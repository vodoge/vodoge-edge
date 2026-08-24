package ike

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/boa-z/vowifi-go/engine/swu"
	"github.com/boa-z/vowifi-go/engine/swu/ikev2"

	"github.com/yuanshuai1122/vodoge-edge/vowifi/internal/capture"
)

// DefaultNonceLength matches RFC 7296 section 2.10 (at least 16 octets and at
// least half the key size of the negotiated PRF).
const DefaultNonceLength = 32

// Errors reported by the runner.
var (
	ErrInvalidInitResponse = errors.New("vowifi/ike: invalid IKE_SA_INIT response")
	// ErrMissingNATDetectionInputs is deliberately fatal rather than a silent
	// skip. See the comment on InitRunner.AllowMissingNATDetection.
	ErrMissingNATDetectionInputs = errors.New("vowifi/ike: cannot build NAT_DETECTION payloads")
	ErrGroupNegotiationFailed    = errors.New("vowifi/ike: exhausted DH group retries")
)

// The mirror will accept our runner in place of ikev2.RunIKE_SA_INIT
// (ike_tunnel_manager.go:22 and :152-154). Asserted at compile time.
var _ swu.IKEInitRunner = (&InitRunner{}).Run

// NATDetection is packet-level evidence about what we sent and what came back.
//
// This exists because the stock stack cannot produce it. initNATPayloads
// (init.go:371-373) bails out to nil whenever LocalPort is zero, which is the
// normal case for the mirror's own ikev2.UDPTransport since it dials without
// binding. detectNAT (init.go:385-387) then short-circuits on the same
// condition, so InitResult.NATDetected is a constant false. Both failures are
// silent.
type NATDetection struct {
	// Sent reports that we actually put both notifies in the request.
	Sent bool
	// SourceHash and DestinationHash are the values we transmitted.
	SourceHash      []byte
	DestinationHash []byte
	// ResponderSentSource / ResponderSentDestination report what came back.
	// T038 measured AT&T returning both and T-Mobile returning neither, so a
	// missing notify is not by itself an error.
	ResponderSentSource      bool
	ResponderSentDestination bool
	// PeerSourceHash and PeerDestinationHash are the notify bodies exactly as
	// the responder sent them.
	//
	// Keeping them is what makes the egress measurable. The destination hash is
	// SHA-1 over our address as the responder saw it, so it is the only thing on
	// this path that reports which of the box's two UDP egresses the datagram
	// actually took (T038 section 7). Comparing it against our own view, which
	// is all BehindNAT does, throws that away.
	PeerSourceHash      []byte
	PeerDestinationHash []byte
	// BehindNAT is true when the responder's DESTINATION hash disagrees with our
	// own view of our address, i.e. something rewrote our source.
	BehindNAT bool
	// PeerBehindNAT is true when the responder's SOURCE hash disagrees.
	PeerBehindNAT bool
}

// RunDetail is everything the fixed ikev2.InitResult shape cannot carry.
type RunDetail struct {
	Offered      ikev2.SecurityAssociation
	Selection    Selection
	NAT          NATDetection
	GroupsTried  []uint16
	CookieRounds int
	Seed         capture.Seed
}

// InitRunner replaces ikev2.RunIKE_SA_INIT.
//
// Replacing rather than patching is the whole strategy: the group-31 hardcodes
// at init.go:159, init.go:342 and sa.go:81 all live inside that one call chain,
// so swapping the function removes all three without touching a mirror byte.
//
// What this adds over the stock runner:
//   - proposes {14, 2, 19, 31} instead of only 31, which is the set T038 put in
//     front of seven live ePDGs; all seven chose 14 and none chose 31
//   - MODP groups via math/big (RFC 3526), which the mirror has no code for
//   - actually emits NAT_DETECTION, and refuses to run silently without it
//   - retries on INVALID_KE_PAYLOAD using the responder's suggested group; the
//     mirror already exports Notify.InvalidKEPayloadAlternativeGroup
//     (payloads.go:119) and never calls it
//   - COOKIE retry, and a pinnable SPI/nonce/scalar so a capture replays exactly
type InitRunner struct {
	// Groups is the DH group offer, most preferred first.
	Groups []uint16
	// Suites is the algorithm offer. Empty means MainstreamSuites.
	Suites []Suite
	// Random overrides crypto/rand.
	Random io.Reader
	// MaxCookieRounds bounds COOKIE retries. RFC 7296 section 2.6 expects one,
	// but a GSLB pool can bounce us onto a second node mid-flight.
	MaxCookieRounds int
	// MaxGroupRetries bounds INVALID_KE_PAYLOAD switches.
	MaxGroupRetries int
	// AllowMissingNATDetection lets a caller run without NAT_DETECTION.
	//
	// Off by default on purpose. The bug this package exists to fix is not "the
	// notify was wrong", it is "the notify was never sent and nothing said so".
	// Trading that for a loud error is the point.
	AllowMissingNATDetection bool
	// Seed pins the initiator SPI, nonce and DH scalar for byte-exact replay.
	Seed capture.Seed
	// Capture receives the seed so a recording can be replayed later.
	Capture *capture.Writer
	// MOBIKE controls whether MOBIKE_SUPPORTED is offered. The mirror always
	// sends it (init.go:161).
	MOBIKE bool

	detail *RunDetail
}

// NewInitRunner returns a runner configured the way T038 measured.
func NewInitRunner() *InitRunner {
	return &InitRunner{
		Groups:          DefaultProposalGroups(),
		Suites:          MainstreamSuites(),
		MaxCookieRounds: 2,
		MaxGroupRetries: 3,
		MOBIKE:          true,
	}
}

// LastDetail returns diagnostics from the most recent Run.
func (r *InitRunner) LastDetail() (RunDetail, bool) {
	if r == nil || r.detail == nil {
		return RunDetail{}, false
	}
	return *r.detail, true
}

// Run is the swu.IKEInitRunner. It is wired into
// swu.IKEPacketTunnelManagerConfig.InitRunner (ike_tunnel_manager.go:69).
func (r *InitRunner) Run(ctx context.Context, cfg ikev2.InitConfig) (ikev2.InitResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if cfg.Transport == nil {
		return ikev2.InitResult{}, fmt.Errorf("%w: transport is nil", ErrInvalidInitResponse)
	}
	random := r.Random
	if random == nil {
		random = cfg.Random
	}
	if random == nil {
		random = rand.Reader
	}

	// The manager builds InitConfig at ike_tunnel_manager.go:156-164 and passes
	// only Transport/Random/SA/LocalIP/LocalPort/RemoteIP/RemotePort. SPI and
	// nonce are filled inside RunIKE_SA_INIT (init.go:129-143), so replacing
	// that function means we own them now. cfg still wins when it carries them,
	// so a future mirror that starts populating the fields is not overridden.
	spiI := cfg.InitiatorSPI
	if spiI == 0 {
		spiI = r.Seed.InitiatorSPI
	}
	if spiI == 0 {
		var err error
		if spiI, err = randomSPI(random); err != nil {
			return ikev2.InitResult{}, err
		}
	}
	nonceI := append([]byte(nil), cfg.NonceI...)
	if len(nonceI) == 0 {
		nonceI = append([]byte(nil), r.Seed.NonceI...)
	}
	if len(nonceI) == 0 {
		buf := make([]byte, DefaultNonceLength)
		if _, err := io.ReadFull(random, buf); err != nil {
			return ikev2.InitResult{}, err
		}
		nonceI = buf
	}

	groups := r.Groups
	if len(groups) == 0 {
		groups = DefaultProposalGroups()
	}
	offered, err := BuildProposal(r.Suites, groups)
	if err != nil {
		return ikev2.InitResult{}, err
	}
	if len(cfg.SA.Proposals) > 0 {
		offered = cfg.SA
	}

	detail := &RunDetail{Offered: offered}
	r.detail = detail

	group := groups[0]
	if r.Seed.DHGroup != 0 {
		group = r.Seed.DHGroup
	}
	maxRetries := r.MaxGroupRetries
	if maxRetries <= 0 {
		maxRetries = 1
	}
	tried := map[uint16]bool{}

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if tried[group] {
			return ikev2.InitResult{}, fmt.Errorf("%w: responder keeps proposing %s", ErrGroupNegotiationFailed, DHGroupName(group))
		}
		tried[group] = true
		detail.GroupsTried = append(detail.GroupsTried, group)

		keys, err := r.keyPairFor(group, random)
		if err != nil {
			return ikev2.InitResult{}, err
		}
		detail.Seed = capture.Seed{
			InitiatorSPI: spiI,
			NonceI:       append([]byte(nil), nonceI...),
			DHGroup:      group,
			DHPrivate:    keys.PrivateKey(),
		}
		if r.Capture != nil {
			r.Capture.SetSeed(detail.Seed)
		}

		result, next, err := r.attempt(ctx, cfg, offered, detail, spiI, nonceI, keys)
		if err == nil {
			return result, nil
		}
		if next == 0 {
			return ikev2.InitResult{}, err
		}
		if !DHGroupSupported(next) {
			return ikev2.InitResult{}, fmt.Errorf("%w: responder suggested %s which we cannot key: %w",
				ErrGroupNegotiationFailed, DHGroupName(next), err)
		}
		if !containsGroup(OfferedGroups(offered), next) {
			return ikev2.InitResult{}, fmt.Errorf("%w: responder suggested %s which we never offered: %w",
				ErrGroupNegotiationFailed, DHGroupName(next), err)
		}
		group = next
	}
	return ikev2.InitResult{}, fmt.Errorf("%w: after %d attempts", ErrGroupNegotiationFailed, maxRetries+1)
}

func (r *InitRunner) keyPairFor(group uint16, random io.Reader) (*KeyPair, error) {
	if r.Seed.DHGroup == group && len(r.Seed.DHPrivate) > 0 {
		return KeyPairFromPrivate(group, r.Seed.DHPrivate)
	}
	return GenerateKeyPair(group, random)
}

// attempt runs one IKE_SA_INIT with a fixed DH group. The second return value
// is a non-zero group when the responder asked us to switch.
func (r *InitRunner) attempt(
	ctx context.Context,
	cfg ikev2.InitConfig,
	offered ikev2.SecurityAssociation,
	detail *RunDetail,
	spiI uint64,
	nonceI []byte,
	keys *KeyPair,
) (ikev2.InitResult, uint16, error) {
	saPayload, err := ikev2.SecurityAssociationPayload(offered)
	if err != nil {
		return ikev2.InitResult{}, 0, err
	}
	payloads := []ikev2.Payload{
		saPayload,
		ikev2.KeyExchangePayload(keys.Group(), keys.PublicKey()),
		ikev2.NoncePayload(nonceI),
	}
	natPayloads, nat, err := r.natPayloads(cfg, spiI)
	if err != nil {
		return ikev2.InitResult{}, 0, err
	}
	payloads = append(payloads, natPayloads...)
	if r.MOBIKE {
		payloads = append(payloads, ikev2.MOBIKESupportedNotify())
	}

	req, reqBytes, resp, respBytes, rounds, err := r.exchange(ctx, cfg.Transport, spiI, payloads)
	detail.CookieRounds = rounds
	if err != nil {
		if group, ok, groupErr := ikev2.InvalidKEPayloadAlternativeGroupFromError(err); groupErr == nil && ok {
			return ikev2.InitResult{}, group, err
		}
		return ikev2.InitResult{}, 0, err
	}

	parsed, err := parseInitResponse(resp, spiI, keys.Group())
	if err != nil {
		if group, ok, groupErr := ikev2.InvalidKEPayloadAlternativeGroupFromError(err); groupErr == nil && ok {
			return ikev2.InitResult{}, group, err
		}
		return ikev2.InitResult{}, 0, err
	}

	selection, err := ValidateSelection(offered, parsed.sa)
	if err != nil {
		return ikev2.InitResult{}, 0, err
	}
	if selection.DHGroup != keys.Group() {
		// The responder accepted a group we did not key. RFC 7296 section 1.2
		// says it should have answered INVALID_KE_PAYLOAD instead; retry with
		// the group it actually chose rather than deriving garbage keys.
		return ikev2.InitResult{}, selection.DHGroup, fmt.Errorf(
			"%w: selected %s but the KE payload used %s", ErrInvalidInitResponse,
			DHGroupName(selection.DHGroup), DHGroupName(keys.Group()))
	}
	if parsed.keyExchange.DHGroup != keys.Group() {
		return ikev2.InitResult{}, parsed.keyExchange.DHGroup, fmt.Errorf(
			"%w: responder KE is %s but the SA selected %s", ErrInvalidInitResponse,
			DHGroupName(parsed.keyExchange.DHGroup), DHGroupName(keys.Group()))
	}
	detail.Selection = selection

	shared, err := keys.ComputeSharedSecret(parsed.keyExchange.KeyData)
	if err != nil {
		return ikev2.InitResult{}, 0, err
	}

	profile, err := ikev2.KeyMaterialProfileFromSA(parsed.sa)
	if err != nil {
		return ikev2.InitResult{}, 0, err
	}
	skeyseed, err := ikev2.SKEYSEED(profile.PRF, nonceI, parsed.nonceR, shared)
	if err != nil {
		return ikev2.InitResult{}, 0, err
	}
	keyMaterialLength := cfg.KeyMaterialLength
	if keyMaterialLength <= 0 {
		keyMaterialLength = profile.RequiredLength()
	}
	keyMaterial, err := ikev2.DeriveIKESAKeyMaterial(profile.PRF, skeyseed, nonceI, parsed.nonceR, spiI, resp.Header.ResponderSPI, keyMaterialLength)
	if err != nil {
		return ikev2.InitResult{}, 0, err
	}
	var ikeKeys ikev2.IKEKeys
	if len(keyMaterial) >= profile.RequiredLength() {
		if ikeKeys, err = ikev2.SplitIKEKeys(profile, keyMaterial); err != nil {
			return ikev2.InitResult{}, 0, err
		}
	}

	r.evaluateNAT(cfg, &nat, parsed.notifies, spiI, resp.Header.ResponderSPI)
	detail.NAT = nat

	return ikev2.InitResult{
		RequestBytes:    append([]byte(nil), reqBytes...),
		ResponseBytes:   append([]byte(nil), respBytes...),
		Request:         req,
		Response:        resp,
		SelectedSA:      parsed.sa,
		InitiatorSPI:    spiI,
		ResponderSPI:    resp.Header.ResponderSPI,
		NonceI:          append([]byte(nil), nonceI...),
		NonceR:          parsed.nonceR,
		PublicKeyI:      keys.PublicKey(),
		PublicKeyR:      parsed.keyExchange.KeyData,
		SharedSecret:    shared,
		PRF:             profile.PRF,
		SKEYSEED:        skeyseed,
		KeyMaterial:     keyMaterial,
		Keys:            ikeKeys,
		MOBIKESupported: parsed.mobikeSupported,
		NATDetected:     nat.BehindNAT || nat.PeerBehindNAT,
	}, 0, nil
}

// exchange sends the request and handles COOKIE retries.
func (r *InitRunner) exchange(ctx context.Context, transport ikev2.InitTransport, spiI uint64, payloads []ikev2.Payload) (ikev2.Message, []byte, ikev2.Message, []byte, int, error) {
	maxRounds := r.MaxCookieRounds
	if maxRounds < 0 {
		maxRounds = 0
	}
	var cookie []byte
	for round := 0; ; round++ {
		reqPayloads := payloads
		if len(cookie) > 0 {
			cookiePayload, err := ikev2.CookieNotify(cookie)
			if err != nil {
				return ikev2.Message{}, nil, ikev2.Message{}, nil, round, err
			}
			// RFC 7296 section 2.6: the COOKIE notify must be the first payload.
			reqPayloads = append([]ikev2.Payload{cookiePayload}, payloads...)
		}
		req := ikev2.Message{
			Header: ikev2.Header{
				InitiatorSPI: spiI,
				ExchangeType: ikev2.ExchangeIKE_SA_INIT,
				Flags:        ikev2.FlagInitiator,
			},
			Payloads: reqPayloads,
		}
		reqBytes, err := req.MarshalBinary()
		if err != nil {
			return ikev2.Message{}, nil, ikev2.Message{}, nil, round, err
		}
		respBytes, err := transport.ExchangeIKE(ctx, reqBytes)
		if err != nil {
			return ikev2.Message{}, nil, ikev2.Message{}, nil, round, err
		}
		resp, err := ikev2.ParseMessage(respBytes)
		if err != nil {
			return ikev2.Message{}, nil, ikev2.Message{}, nil, round, err
		}
		if err := validateResponseHeader(resp, spiI); err != nil {
			return ikev2.Message{}, nil, ikev2.Message{}, nil, round, err
		}
		next, ok, err := responseCookie(resp)
		if err != nil {
			return ikev2.Message{}, nil, ikev2.Message{}, nil, round, err
		}
		if !ok {
			return req, reqBytes, resp, respBytes, round, nil
		}
		if round >= maxRounds {
			return ikev2.Message{}, nil, ikev2.Message{}, nil, round,
				fmt.Errorf("%w: responder demanded a COOKIE %d times", ErrInvalidInitResponse, round+1)
		}
		cookie = next
	}
}

func responseCookie(resp ikev2.Message) ([]byte, bool, error) {
	for _, payload := range resp.Payloads {
		if payload.Type != ikev2.PayloadNotify {
			continue
		}
		notify, err := ikev2.ParseNotify(payload.Body)
		if err != nil {
			return nil, false, fmt.Errorf("%w: %w", ErrInvalidInitResponse, err)
		}
		cookie, ok, err := notify.Cookie()
		if err != nil {
			return nil, false, fmt.Errorf("%w: %w", ErrInvalidInitResponse, err)
		}
		if ok {
			return cookie, true, nil
		}
	}
	return nil, false, nil
}

func validateResponseHeader(resp ikev2.Message, spiI uint64) error {
	h := resp.Header
	if h.InitiatorSPI != spiI {
		return fmt.Errorf("%w: initiator SPI mismatch", ErrInvalidInitResponse)
	}
	if h.ExchangeType != ikev2.ExchangeIKE_SA_INIT || h.MessageID != 0 || h.Flags&ikev2.FlagResponse == 0 {
		return fmt.Errorf("%w: unexpected header", ErrInvalidInitResponse)
	}
	// FirstNotifyError wraps INVALID_KE_PAYLOAD in a *NotifyError, which is what
	// InvalidKEPayloadAlternativeGroupFromError unwraps upstack.
	if err := ikev2.FirstNotifyError(resp.Payloads); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidInitResponse, err)
	}
	return nil
}

// natPayloads builds the NAT_DETECTION notifies, or explains why it cannot.
func (r *InitRunner) natPayloads(cfg ikev2.InitConfig, spiI uint64) ([]ikev2.Payload, NATDetection, error) {
	var nat NATDetection
	missing := missingNATInputs(cfg)
	if len(missing) > 0 {
		if r.AllowMissingNATDetection {
			return nil, nat, nil
		}
		return nil, nat, fmt.Errorf("%w: missing %v; the stock stack would have silently sent nothing (init.go:371-373)",
			ErrMissingNATDetectionInputs, missing)
	}
	// RFC 7296 section 2.23: the responder SPI is still zero in the request, and
	// both hashes must be computed over that zero.
	src, err := ikev2.NATDetectionNotify(ikev2.NotifyNATDetectionSourceIP, spiI, 0, cfg.LocalIP, cfg.LocalPort)
	if err != nil {
		return nil, nat, fmt.Errorf("%w: source: %w", ErrMissingNATDetectionInputs, err)
	}
	dst, err := ikev2.NATDetectionNotify(ikev2.NotifyNATDetectionDestinationIP, spiI, 0, cfg.RemoteIP, cfg.RemotePort)
	if err != nil {
		return nil, nat, fmt.Errorf("%w: destination: %w", ErrMissingNATDetectionInputs, err)
	}
	srcHash, err := ikev2.NATDetectionHash(spiI, 0, cfg.LocalIP, cfg.LocalPort)
	if err != nil {
		return nil, nat, err
	}
	dstHash, err := ikev2.NATDetectionHash(spiI, 0, cfg.RemoteIP, cfg.RemotePort)
	if err != nil {
		return nil, nat, err
	}
	nat.Sent = true
	nat.SourceHash = srcHash
	nat.DestinationHash = dstHash
	return []ikev2.Payload{src, dst}, nat, nil
}

func missingNATInputs(cfg ikev2.InitConfig) []string {
	var missing []string
	if cfg.LocalIP == nil || cfg.LocalIP.IsUnspecified() {
		missing = append(missing, "LocalIP")
	}
	if cfg.LocalPort == 0 {
		missing = append(missing, "LocalPort")
	}
	if cfg.RemoteIP == nil || cfg.RemoteIP.IsUnspecified() {
		missing = append(missing, "RemoteIP")
	}
	if cfg.RemotePort == 0 {
		missing = append(missing, "RemotePort")
	}
	return missing
}

// evaluateNAT compares the responder's notifies with our own view.
//
// The responder hashes its own source (which we see as the remote endpoint) into
// NAT_DETECTION_SOURCE_IP, and our apparent address into
// NAT_DETECTION_DESTINATION_IP. A mismatch on the destination hash means our
// source address was rewritten in flight.
func (r *InitRunner) evaluateNAT(cfg ikev2.InitConfig, nat *NATDetection, notifies []ikev2.Notify, spiI, spiR uint64) {
	if len(missingNATInputs(cfg)) > 0 {
		return
	}
	peerHash, peerErr := ikev2.NATDetectionHash(spiI, spiR, cfg.RemoteIP, cfg.RemotePort)
	ourHash, ourErr := ikev2.NATDetectionHash(spiI, spiR, cfg.LocalIP, cfg.LocalPort)
	if peerErr != nil || ourErr != nil {
		return
	}
	for _, n := range notifies {
		switch n.NotifyType {
		case ikev2.NotifyNATDetectionSourceIP:
			nat.ResponderSentSource = true
			nat.PeerSourceHash = append([]byte(nil), n.NotificationData...)
			if !equalBytes(n.NotificationData, peerHash) {
				nat.PeerBehindNAT = true
			}
		case ikev2.NotifyNATDetectionDestinationIP:
			nat.ResponderSentDestination = true
			nat.PeerDestinationHash = append([]byte(nil), n.NotificationData...)
			if !equalBytes(n.NotificationData, ourHash) {
				nat.BehindNAT = true
			}
		}
	}
}

type parsedInitResponse struct {
	sa              ikev2.SecurityAssociation
	keyExchange     ikev2.KeyExchange
	nonceR          []byte
	notifies        []ikev2.Notify
	mobikeSupported bool
}

// parseInitResponse is our own, because the mirror's version rejects every DH
// group except 31 at init.go:342-344 and is unexported anyway.
func parseInitResponse(resp ikev2.Message, spiI uint64, expectGroup uint16) (parsedInitResponse, error) {
	if err := validateResponseHeader(resp, spiI); err != nil {
		return parsedInitResponse{}, err
	}
	if resp.Header.ResponderSPI == 0 {
		return parsedInitResponse{}, fmt.Errorf("%w: responder SPI is zero", ErrInvalidInitResponse)
	}
	var out parsedInitResponse
	for _, p := range resp.Payloads {
		switch p.Type {
		case ikev2.PayloadSA:
			sa, err := ikev2.ParseSecurityAssociation(p.Body)
			if err != nil {
				return parsedInitResponse{}, err
			}
			out.sa = sa
		case ikev2.PayloadKE:
			ke, err := ikev2.ParseKeyExchange(p.Body)
			if err != nil {
				return parsedInitResponse{}, err
			}
			out.keyExchange = ke
		case ikev2.PayloadNonce:
			out.nonceR = append([]byte(nil), p.Body...)
		case ikev2.PayloadNotify:
			n, err := ikev2.ParseNotify(p.Body)
			if err != nil {
				return parsedInitResponse{}, err
			}
			out.notifies = append(out.notifies, n)
			if n.NotifyType == ikev2.NotifyMOBIKESupported {
				out.mobikeSupported = true
			}
		}
	}
	if len(out.sa.Proposals) == 0 {
		return parsedInitResponse{}, fmt.Errorf("%w: missing SA", ErrInvalidInitResponse)
	}
	if len(out.keyExchange.KeyData) == 0 {
		return parsedInitResponse{}, fmt.Errorf("%w: missing KE", ErrInvalidInitResponse)
	}
	// RFC 7296 section 2.10: nonces are 16..256 octets. T038 measured AT&T at 16
	// and T-Mobile at 32, so a fixed expectation here would reject one of them.
	if len(out.nonceR) < 16 || len(out.nonceR) > 256 {
		return parsedInitResponse{}, fmt.Errorf("%w: responder nonce is %d octets", ErrInvalidInitResponse, len(out.nonceR))
	}
	if out.keyExchange.DHGroup != expectGroup {
		return parsedInitResponse{}, fmt.Errorf("%w: responder KE is %s, we sent %s",
			ErrInvalidInitResponse, DHGroupName(out.keyExchange.DHGroup), DHGroupName(expectGroup))
	}
	return out, nil
}

func randomSPI(random io.Reader) (uint64, error) {
	var buf [8]byte
	for attempt := 0; attempt < 16; attempt++ {
		if _, err := io.ReadFull(random, buf[:]); err != nil {
			return 0, err
		}
		if spi := binary.BigEndian.Uint64(buf[:]); spi != 0 {
			return spi, nil
		}
	}
	return 0, fmt.Errorf("%w: could not draw a non-zero initiator SPI", ErrInvalidInitResponse)
}

func containsGroup(groups []uint16, want uint16) bool {
	for _, g := range groups {
		if g == want {
			return true
		}
	}
	return false
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// InitConfigFor builds the InitConfig for a socket, filling the endpoint fields
// the mirror's manager would leave at zero.
func InitConfigFor(s *Socket, sa ikev2.SecurityAssociation) (ikev2.InitConfig, error) {
	if s == nil {
		return ikev2.InitConfig{}, ErrSocketClosed
	}
	remote := s.Remote()
	if remote == nil {
		return ikev2.InitConfig{}, ErrNoRemote
	}
	local := s.LocalIP()
	if local == nil || local.IsUnspecified() {
		return ikev2.InitConfig{}, fmt.Errorf("%w: local IP is unresolved", ErrMissingNATDetectionInputs)
	}
	return ikev2.InitConfig{
		Transport:  s,
		SA:         sa,
		LocalIP:    local,
		LocalPort:  s.LocalPort(),
		RemoteIP:   remote.IP,
		RemotePort: uint16(remote.Port),
	}, nil
}
