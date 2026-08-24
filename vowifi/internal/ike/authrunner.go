package ike

import (
	"context"
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/boa-z/vowifi-go/engine/swu"
	"github.com/boa-z/vowifi-go/engine/swu/eapaka"
	"github.com/boa-z/vowifi-go/engine/swu/ikev2"

	"github.com/yuanshuai1122/vodoge-edge/vowifi/internal/capture"
)

// The mirror accepts our runner in place of ikev2.RunIKE_AUTH_Full
// (ike_tunnel_manager.go:24 and :168-171). Asserted at compile time.
var _ swu.IKEAuthRunner = (&AuthRunner{}).Run

// Errors reported by the IKE_AUTH runner.
var (
	ErrInvalidAuthConfig   = errors.New("vowifi/ike: invalid IKE_AUTH config")
	ErrInvalidAuthResponse = errors.New("vowifi/ike: invalid IKE_AUTH response")
	// ErrPeerAuthFailed means the responder's AUTH payload did not verify. This
	// is the difference between "a tunnel came up" and "a tunnel came up to the
	// carrier we asked for".
	ErrPeerAuthFailed = errors.New("vowifi/ike: responder AUTH did not verify")
	// ErrPeerAuthMissing means the final response carried no AUTH at all.
	ErrPeerAuthMissing = errors.New("vowifi/ike: responder sent no AUTH payload")
	// ErrPeerAuthMethod means the responder used an Auth Method we did not
	// expect, so verifying it with the MSK would be verifying the wrong thing.
	ErrPeerAuthMethod = errors.New("vowifi/ike: responder used an unexpected AUTH method")
	// ErrResponderIgnoredEAPOnly means the responder produced an AUTH payload
	// before EAP finished, i.e. it is authenticating with a certificate and
	// ignored RFC 5998.
	ErrResponderIgnoredEAPOnly = errors.New("vowifi/ike: responder authenticated before EAP completed")
	// ErrEAPSuccessWithChildSA means EAP-Success and the CHILD_SA shared one
	// message. Accepting that would mean accepting a CHILD_SA from a peer we
	// have not authenticated yet.
	ErrEAPSuccessWithChildSA = errors.New("vowifi/ike: EAP-Success arrived together with the CHILD_SA")
	// ErrEAPRoundsExhausted bounds a server that keeps asking.
	ErrEAPRoundsExhausted = errors.New("vowifi/ike: too many EAP rounds")
)

// DefaultMaxEAPRounds bounds the EAP conversation. RFC 4187 full authentication
// is two rounds (Identity, Challenge); the extra headroom covers notifications,
// AKA' KDF renegotiation and one resynchronisation.
const DefaultMaxEAPRounds = 8

// DefaultAKATimeout is the hard stop applied to one CalculateAKA call.
//
// A real card answers an AUTHENTICATE APDU in well under a second. The number
// that matters is not that one, it is the upper bound on the far side of the
// bridge: the Rust arbiter on the edge box can wait 300 seconds or forever
// (T058 is not done). An ePDG has abandoned the exchange long before then, so
// waiting past this point cannot succeed, it can only hide the fault.
const DefaultAKATimeout = 20 * time.Second

// AuthRunner replaces ikev2.RunIKE_AUTH_Full.
//
// The whole loop is replaced rather than reused for two reasons that cannot be
// patched around from outside the mirror:
//
//   - RunIKE_AUTH_EAPIdentity builds its first request with
//     BuildIKEAuthInitialPayloads (auth.go:182 calling auth.go:840-888), which
//     returns {IDi, CP, SA, TSi, TSr}. There is no IDr, and
//     EAP_ONLY_AUTHENTICATION does not appear anywhere under engine/. Without
//     both, an ePDG follows plain RFC 7296 and expects to prove itself with a
//     certificate.
//   - RunIKE_AUTH_Full treats EAP-Success without a CHILD_SA in the same message
//     as an error (auth.go:326). That is what a correct ladder looks like:
//     RFC 7296 section 2.16 puts EAP-Success in its own exchange and the AUTH
//     plus SA/TSi/TSr in the next one.
//
// Nothing here edits the mirror. Payload codecs, ProtectMessage/UnprotectMessage
// (sk.go:16 and :126), PRF (crypto.go:15), the eapaka constructors and
// ParseChildSAResultWithNonces (childsa.go:129) are all used as they ship.
type AuthRunner struct {
	// ResponderID is the IDr we assert. Required: see ErrMissingResponderID.
	// For an ePDG this is the ID_FQDN from the 3GPP TS 23.003 naming scheme;
	// use IdentityFQDN.
	ResponderID ikev2.Identity
	// AllowMissingResponderID sends IKE_AUTH without an IDr. Off by default,
	// for the same reason AllowMissingNATDetection is off by default: the bug
	// worth guarding against is not a wrong payload, it is a missing one that
	// nothing complains about.
	AllowMissingResponderID bool
	// InitiatorID overrides ikev2.FullAuthConfig.InitiatorID.
	InitiatorID ikev2.Identity
	// DisableEAPOnlyAuthentication drops the RFC 5998 notify. Zero value sends
	// it, because sending it is the entire point of this runner.
	DisableEAPOnlyAuthentication bool
	// AuthMethod is the Auth Method octet we put in our AUTH payload.
	// Zero means AuthMethodSharedKeyMIC.
	AuthMethod uint8
	// ExpectedPeerAuthMethod is what we require in the responder's AUTH.
	// Zero means the same value as AuthMethod.
	ExpectedPeerAuthMethod uint8
	// AllowMissingPeerAuth accepts a final response with no AUTH payload.
	// Off by default: an unauthenticated peer is the failure this card exists
	// to make impossible.
	AllowMissingPeerAuth bool
	// AllowUnverifiedResponderAuth tolerates a responder that sends AUTH before
	// EAP completes, i.e. one that ignored EAP_ONLY_AUTHENTICATION and is
	// authenticating with a certificate. Off by default, because this stack
	// cannot validate a certificate chain and pretending otherwise would make
	// "the responder authenticated" a false statement.
	AllowUnverifiedResponderAuth bool
	// ChildSA overrides the ESP offer. Empty means DefaultESPProposal.
	ChildSA ikev2.SecurityAssociation
	// TSi and TSr override the traffic selectors. Empty means IPv4 any.
	TSi ikev2.TrafficSelectors
	TSr ikev2.TrafficSelectors
	// Configuration overrides the CFG_REQUEST.
	Configuration ikev2.Configuration
	// ExtraInitialPayloads are appended to the first request.
	ExtraInitialPayloads []ikev2.Payload
	// MaxEAPRounds bounds the EAP conversation. Zero means
	// DefaultMaxEAPRounds.
	MaxEAPRounds int
	// MaxResyncAttempts bounds AT_AUTS resynchronisation. Zero means one: a
	// card that desynchronises twice in a row is not going to settle.
	MaxResyncAttempts int
	// AKATimeout bounds one CalculateAKA call. Zero means DefaultAKATimeout;
	// negative disables the deadline. See WithAKADeadline for why this exists
	// before the real card bridge does.
	AKATimeout time.Duration
	// Random overrides crypto/rand for the child SPI and the CBC IVs.
	Random io.Reader
	// ChildSPI pins our inbound ESP SPI. Four octets; empty means random.
	ChildSPI []byte
	// PinnedIVs are consumed in order as the IV of each protected request.
	// This is what makes an IKE_AUTH recording replayable byte for byte.
	PinnedIVs [][]byte
	// Capture receives the auth seed so a recording can be replayed later.
	Capture *capture.Writer

	detail *AuthDetail
}

// NewAuthRunner returns a runner with the defaults this project wants: RFC 5998
// EAP-only authentication, an IDr, a verified peer AUTH, and a bounded card
// call.
func NewAuthRunner(responderID ikev2.Identity) *AuthRunner {
	return &AuthRunner{
		ResponderID:       responderID,
		AuthMethod:        AuthMethodSharedKeyMIC,
		MaxEAPRounds:      DefaultMaxEAPRounds,
		MaxResyncAttempts: 1,
		AKATimeout:        DefaultAKATimeout,
	}
}

// AuthRound records one IKE_AUTH exchange.
type AuthRound struct {
	MessageID     uint32
	SentPayloads  []uint8
	GotPayloads   []uint8
	EAPCode       uint8
	EAPSubtype    uint8
	ResponseEAP   uint8
	SentAuth      bool
	GotAuth       bool
	GotChildSA    bool
	RequestBytes  []byte
	ResponseBytes []byte
}

// AuthNotify is one notify the responder put in an IKE_AUTH response.
type AuthNotify struct {
	MessageID uint32
	Type      uint16
	Data      []byte
	// Malformed holds the payload body when it would not parse as a notify at
	// all, because that is also a finding.
	Malformed []byte
}

// AuthDetail is packet-level evidence about what the ladder actually did.
//
// ikev2.FullAuthResult cannot carry it, and reading the source is not evidence:
// the claim being made here is that specific payloads were on specific wires in
// a specific order.
type AuthDetail struct {
	// InitialPayloadTypes is the payload type list of the first request, in
	// wire order.
	InitialPayloadTypes []uint8
	// SentIDr and SentEAPOnlyNotify are the two additions over the mirror.
	SentIDr           bool
	SentEAPOnlyNotify bool
	// PeerSentIDr reports that the responder identified itself.
	PeerSentIDr bool
	// PeerIDBody is the IDr payload body as received, which is what the AUTH
	// verification hashes.
	PeerIDBody []byte
	// Rounds is one entry per IKE_AUTH exchange.
	Rounds []AuthRound
	// ResponseNotifies is every notify the responder sent, in order, error
	// notifies included. This is what names the rejection.
	ResponseNotifies []AuthNotify
	// EAPSuccessMessageID and ChildSAMessageID must differ. That they do is the
	// core claim of this card.
	EAPSuccessMessageID uint32
	ChildSAMessageID    uint32
	// EAPIdentityUsed is the identity the EAP method settled on.
	EAPIdentityUsed string
	// SyncFailures counts AT_AUTS responses actually put on the wire.
	SyncFailures int
	// AuthRejects counts EAP-Response/AKA-Authentication-Reject packets
	// actually put on the wire.
	AuthRejects int
	// ClientErrors counts EAP-Response/AKA-Client-Error packets.
	ClientErrors int
	// LocalAuth is the AUTH payload data we sent, with the method octet.
	LocalAuth       []byte
	LocalAuthMethod uint8
	// PeerAuth is what came back.
	PeerAuth       []byte
	PeerAuthMethod uint8
	// PeerAuthVerified is only true after a constant-time comparison passed.
	PeerAuthVerified bool
	// EarlyPeerAuthMethod is non-zero when the responder produced an AUTH
	// before EAP finished, i.e. ignored EAP_ONLY_AUTHENTICATION.
	EarlyPeerAuthMethod uint8
	// ChildSPI and IVs are the replay seed for this ladder.
	ChildSPI []byte
	IVs      [][]byte
	// AKAVectors is populated when the provider was wrapped in a
	// RecordingAKAProvider.
	AKAVectors []capture.AKAVector
}

// LastDetail returns diagnostics from the most recent Run.
func (r *AuthRunner) LastDetail() (AuthDetail, bool) {
	if r == nil || r.detail == nil {
		return AuthDetail{}, false
	}
	return *r.detail, true
}

// Run is the swu.IKEAuthRunner. It is wired into
// swu.IKEPacketTunnelManagerConfig.AuthRunner (ike_tunnel_manager.go:70).
func (r *AuthRunner) Run(ctx context.Context, cfg ikev2.FullAuthConfig) (ikev2.FullAuthResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	s, err := r.newSession(ctx, cfg)
	if err != nil {
		return ikev2.FullAuthResult{}, err
	}
	r.detail = s.detail
	out, runErr := s.run(ctx)
	// The seed is published even on failure. A ladder that broke halfway is
	// exactly the one worth replaying offline.
	s.publishSeed()
	return out, runErr
}

type authSession struct {
	runner      *AuthRunner
	cfg         ikev2.FullAuthConfig
	keys        ikev2.IKEKeys
	prf         crypto.Hash
	random      io.Reader
	messageID   uint32
	childSPI    []byte
	initiatorID ikev2.Identity
	peerIDBody  []byte
	driver      *EAPDriver
	recorder    *RecordingAKAProvider
	detail      *AuthDetail
	ivQueue     [][]byte
	result      ikev2.FullAuthResult
}

func (r *AuthRunner) newSession(ctx context.Context, cfg ikev2.FullAuthConfig) (*authSession, error) {
	if cfg.Transport == nil {
		return nil, fmt.Errorf("%w: transport is nil", ErrInvalidAuthConfig)
	}
	keys := cfg.Keys
	if keys.Profile.RequiredLength() == 0 {
		keys = cfg.Init.Keys
	}
	if keys.Profile.RequiredLength() == 0 {
		return nil, fmt.Errorf("%w: no IKE SA keys", ErrInvalidAuthConfig)
	}
	if keys.Profile.PRF == 0 || !keys.Profile.PRF.Available() {
		return nil, fmt.Errorf("%w: PRF %v is unavailable", ErrInvalidAuthConfig, keys.Profile.PRF)
	}
	if len(keys.SKPi) == 0 || len(keys.SKPr) == 0 {
		return nil, fmt.Errorf("%w: SK_pi/SK_pr are missing, so no AUTH can be computed", ErrInvalidAuthConfig)
	}
	if cfg.Init.InitiatorSPI == 0 || cfg.Init.ResponderSPI == 0 {
		return nil, fmt.Errorf("%w: missing IKE SPIs", ErrInvalidAuthConfig)
	}
	// RFC 7296 section 2.15 signs the IKE_SA_INIT messages verbatim. If the
	// runner that produced this InitResult threw them away there is no way to
	// recompute them, and an AUTH built without them would be wrong in a way
	// that only the ePDG can see.
	if len(cfg.Init.RequestBytes) == 0 || len(cfg.Init.ResponseBytes) == 0 {
		return nil, fmt.Errorf("%w: InitResult has no RequestBytes/ResponseBytes, "+
			"so InitiatorSignedOctets cannot be built", ErrInvalidAuthConfig)
	}
	if len(cfg.Init.NonceI) == 0 || len(cfg.Init.NonceR) == 0 {
		return nil, fmt.Errorf("%w: InitResult has no nonces", ErrInvalidAuthConfig)
	}

	random := r.Random
	if random == nil {
		random = cfg.Random
	}
	if random == nil {
		random = rand.Reader
	}

	initiatorID := r.InitiatorID
	if initiatorID.Type == 0 || len(initiatorID.Data) == 0 {
		initiatorID = cfg.InitiatorID
	}
	if initiatorID.Type == 0 || len(initiatorID.Data) == 0 {
		derived, err := IdentityFromString(cfg.EAPIdentity)
		if err != nil {
			return nil, fmt.Errorf("%w: no IDi and no EAP identity to derive one from", ErrMissingInitiatorID)
		}
		initiatorID = derived
	}

	childSPI, err := r.pickChildSPI(cfg, random)
	if err != nil {
		return nil, err
	}

	provider := cfg.SIM
	var recorder *RecordingAKAProvider
	if provider != nil {
		recorder = &RecordingAKAProvider{Inner: provider}
		timeout := r.AKATimeout
		if timeout == 0 {
			timeout = DefaultAKATimeout
		}
		if timeout < 0 {
			timeout = 0
		}
		provider = WithAKADeadline(ctx, recorder, timeout)
	}

	s := &authSession{
		runner:      r,
		cfg:         cfg,
		keys:        keys,
		prf:         keys.Profile.PRF,
		random:      random,
		messageID:   firstAuthMessageID(cfg.InitialMessageID),
		childSPI:    childSPI,
		initiatorID: initiatorID,
		recorder:    recorder,
		detail:      &AuthDetail{ChildSPI: append([]byte(nil), childSPI...)},
		driver: &EAPDriver{
			PermanentIdentity: authIdentity(cfg, initiatorID),
			Pseudonym:         cfg.EAPPseudonym,
			ReauthIdentity:    cfg.EAPReauthIdentity,
			Provider:          provider,
		},
	}
	for _, iv := range r.PinnedIVs {
		s.ivQueue = append(s.ivQueue, append([]byte(nil), iv...))
	}
	s.result.EAPKeys = cfg.EAPKeys
	return s, nil
}

func (r *AuthRunner) pickChildSPI(cfg ikev2.FullAuthConfig, random io.Reader) ([]byte, error) {
	for _, candidate := range [][]byte{r.ChildSPI, cfg.ChildSPI} {
		if len(candidate) == 0 {
			continue
		}
		if len(candidate) != 4 {
			return nil, fmt.Errorf("%w: child SPI is %d octets, want 4", ErrInvalidAuthConfig, len(candidate))
		}
		return append([]byte(nil), candidate...), nil
	}
	if len(cfg.ChildSA.Proposals) > 0 && len(cfg.ChildSA.Proposals[0].SPI) == 4 {
		return append([]byte(nil), cfg.ChildSA.Proposals[0].SPI...), nil
	}
	spi := make([]byte, 4)
	if _, err := io.ReadFull(random, spi); err != nil {
		return nil, err
	}
	return spi, nil
}

func firstAuthMessageID(configured uint32) uint32 {
	if configured == 0 {
		return 1
	}
	return configured
}

func authIdentity(cfg ikev2.FullAuthConfig, initiatorID ikev2.Identity) string {
	if trimmed := trimSpace(cfg.EAPIdentity); trimmed != "" {
		return trimmed
	}
	return trimSpace(string(initiatorID.Data))
}

func trimSpace(value string) string {
	start, end := 0, len(value)
	for start < end && (value[start] == ' ' || value[start] == '\t' || value[start] == '\n' || value[start] == '\r') {
		start++
	}
	for end > start && (value[end-1] == ' ' || value[end-1] == '\t' || value[end-1] == '\n' || value[end-1] == '\r') {
		end--
	}
	return value[start:end]
}

func (s *authSession) run(ctx context.Context) (ikev2.FullAuthResult, error) {
	initial, err := BuildAuthInitialPayloads(AuthInitialPayloads{
		InitiatorID:             s.initiatorID,
		ResponderID:             s.runner.ResponderID,
		AllowMissingResponderID: s.runner.AllowMissingResponderID,
		ChildSA:                 s.offeredChildSA(),
		ChildSPI:                s.childSPI,
		TSi:                     s.offeredTSi(),
		TSr:                     s.offeredTSr(),
		Configuration:           s.offeredConfiguration(),
		EAPOnlyAuthentication:   !s.runner.DisableEAPOnlyAuthentication,
		Extra:                   s.runner.ExtraInitialPayloads,
	})
	if err != nil {
		return s.result, err
	}
	s.detail.InitialPayloadTypes = payloadTypes(initial)
	s.detail.SentIDr = containsPayload(initial, ikev2.PayloadIDr)
	s.detail.SentEAPOnlyNotify = containsNotify(initial, NotifyEAPOnlyAuthentication)

	reqBytes, respBytes, inner, err := s.exchange(ctx, initial)
	if err != nil {
		return s.result, err
	}
	s.result.Auth.InitialRequestBytes = reqBytes
	s.result.Auth.InitialResponseBytes = respBytes
	s.result.Auth.InitialResponseInner = clonePayloads(inner)
	s.result.FinalResponseBytes = respBytes
	s.result.FinalResponseInner = clonePayloads(inner)

	maxRounds := s.runner.MaxEAPRounds
	if maxRounds <= 0 {
		maxRounds = DefaultMaxEAPRounds
	}
	maxResync := s.runner.MaxResyncAttempts
	if maxResync <= 0 {
		maxResync = 1
	}

	eapDone := false
	for round := 0; !eapDone; round++ {
		if round >= maxRounds {
			return s.result, fmt.Errorf("%w: %d rounds", ErrEAPRoundsExhausted, round)
		}
		parts, err := parseAuthResponse(inner)
		if err != nil {
			return s.result, err
		}
		if len(parts.idrBody) > 0 {
			s.peerIDBody = parts.idrBody
			s.detail.PeerSentIDr = true
			s.detail.PeerIDBody = append([]byte(nil), parts.idrBody...)
		}
		if parts.auth != nil {
			s.detail.EarlyPeerAuthMethod = parts.auth.Method
			if !s.runner.AllowUnverifiedResponderAuth {
				return s.result, fmt.Errorf("%w: AUTH method %d arrived in message %d, before EAP finished; "+
					"the responder ignored EAP_ONLY_AUTHENTICATION and is presenting a certificate this stack "+
					"cannot validate (set AllowUnverifiedResponderAuth to record it and continue)",
					ErrResponderIgnoredEAPOnly, parts.auth.Method, s.lastRoundMessageID())
			}
		}
		if parts.eap == nil {
			return s.result, fmt.Errorf("%w: message %d carried no EAP payload and EAP has not finished",
				ErrInvalidAuthResponse, s.lastRoundMessageID())
		}
		s.result.EAPLast = clonePacketPointer(parts.eap)
		s.noteResponseEAP(parts)

		switch parts.eap.Code {
		case eapaka.CodeSuccess:
			if parts.hasSA {
				return s.result, fmt.Errorf("%w: message %d; accepting it would mean taking a CHILD_SA "+
					"from a peer whose AUTH we have not seen yet", ErrEAPSuccessWithChildSA, s.lastRoundMessageID())
			}
			s.detail.EAPSuccessMessageID = s.lastRoundMessageID()
			eapDone = true
		case eapaka.CodeFailure:
			return s.result, fmt.Errorf("%w: EAP-Failure in message %d", ErrEAPFailure, s.lastRoundMessageID())
		case eapaka.CodeRequest:
			step, err := s.driver.Respond(*parts.eap, parts.eapRaw)
			if err != nil {
				return s.result, err
			}
			s.absorbStep(step)
			reqBytes, respBytes, inner, err = s.exchange(ctx, []ikev2.Payload{ikev2.EAPPayload(step.Raw)})
			if err != nil {
				return s.result, err
			}
			s.recordEAPExchange(parts, step, reqBytes, respBytes, inner)
			if step.AuthFailure {
				// The Authentication-Reject is already on the wire; eapaka built
				// it from sim.ErrAuthFailure without any help from this file.
				// Returning now rather than waiting for EAP-Failure keeps the
				// named error attached to the cause.
				return s.result, fmt.Errorf("%w: the USIM rejected AUTN, EAP-Response/AKA-Authentication-Reject sent "+
					"in message %d", ErrAKAAuthFailure, s.lastRoundMessageID())
			}
			if step.SyncFailure && s.detail.SyncFailures > maxResync {
				return s.result, fmt.Errorf("%w: %d AT_AUTS responses sent, budget is %d",
					ErrAKASyncFailure, s.detail.SyncFailures, maxResync)
			}
		default:
			return s.result, fmt.Errorf("%w: EAP code %d", ErrEAPUnexpected, parts.eap.Code)
		}
	}

	return s.finish(ctx)
}

// finish sends the last IKE_AUTH request, the one carrying AUTH, and consumes
// the CHILD_SA that comes back.
func (s *authSession) finish(ctx context.Context) (ikev2.FullAuthResult, error) {
	msk := s.driver.Keys().MSK
	if len(msk) == 0 {
		msk = s.cfg.EAPKeys.MSK
	}
	if len(msk) == 0 {
		return s.result, fmt.Errorf("%w: EAP-Success arrived but no MSK was derived", ErrNoEAPKeys)
	}

	macedIDi, err := MACedIdentity(s.prf, s.keys.SKPi, s.initiatorID)
	if err != nil {
		return s.result, err
	}
	signed := InitiatorSignedOctets(s.cfg.Init.RequestBytes, s.cfg.Init.NonceR, macedIDi)
	method := s.runner.AuthMethod
	if method == 0 {
		method = AuthMethodSharedKeyMIC
	}
	authData, err := SharedKeyAuth(s.prf, msk, signed)
	if err != nil {
		return s.result, err
	}
	authPayload, err := AuthPayload(method, authData)
	if err != nil {
		return s.result, err
	}
	s.detail.LocalAuth = append([]byte(nil), authData...)
	s.detail.LocalAuthMethod = method

	_, respBytes, inner, err := s.exchange(ctx, []ikev2.Payload{authPayload})
	if err != nil {
		return s.result, err
	}
	s.result.FinalResponseBytes = respBytes
	s.result.FinalResponseInner = clonePayloads(inner)

	parts, err := parseAuthResponse(inner)
	if err != nil {
		return s.result, err
	}
	if len(parts.idrBody) > 0 {
		s.peerIDBody = parts.idrBody
		s.detail.PeerSentIDr = true
		s.detail.PeerIDBody = append([]byte(nil), parts.idrBody...)
	}
	if err := s.verifyPeerAuth(parts, msk, method); err != nil {
		return s.result, err
	}

	if !parts.hasSA {
		return s.result, fmt.Errorf("%w: the AUTH response carried no CHILD_SA", ErrInvalidAuthResponse)
	}
	child, err := ikev2.ParseChildSAResultWithNonces(s.cfg.Init, inner, s.childSPI, s.cfg.Init.NonceI, s.cfg.Init.NonceR)
	if err != nil {
		return s.result, err
	}
	child.NextMessageID = s.messageID
	// ChildSAResult.EAPSuccess is set by the parser only when an EAP payload
	// rides in the same message as the SA. On a correct ladder it never does,
	// so leaving it false would report "EAP did not succeed" about an exchange
	// that just succeeded. The field means the method completed, and it did.
	child.EAPSuccess = true
	s.result.ChildSA = &child
	s.detail.ChildSAMessageID = s.lastRoundMessageID()
	s.result.NextMessageID = s.messageID
	s.result.Auth.NextMessageID = s.messageID
	s.detail.EAPIdentityUsed = s.driver.Identity()
	s.result.Auth.EAPIdentityUsed = s.driver.Identity()
	s.result.Auth.IdentityTranscript = s.driver.Transcript()
	if keys := s.driver.Keys(); len(keys.KAut) > 0 {
		s.result.EAPKeys = keys
	}
	if s.recorder != nil {
		s.detail.AKAVectors = s.recorder.Vectors()
	}
	return s.result, nil
}

func (s *authSession) verifyPeerAuth(parts authResponseParts, msk []byte, ourMethod uint8) error {
	if parts.auth == nil {
		if s.runner.AllowMissingPeerAuth {
			return nil
		}
		return fmt.Errorf("%w: message %d", ErrPeerAuthMissing, s.lastRoundMessageID())
	}
	s.detail.PeerAuth = append([]byte(nil), parts.auth.Data...)
	s.detail.PeerAuthMethod = parts.auth.Method

	expectMethod := s.runner.ExpectedPeerAuthMethod
	if expectMethod == 0 {
		expectMethod = ourMethod
	}
	if parts.auth.Method != expectMethod {
		return fmt.Errorf("%w: got %d, expected %d; RFC 5998 EAP-only authentication has the responder "+
			"use the same shared-secret syntax we do", ErrPeerAuthMethod, parts.auth.Method, expectMethod)
	}

	idBody := s.peerIDBody
	if len(idBody) == 0 {
		encoded, err := s.runner.ResponderID.MarshalBinary()
		if err != nil {
			return fmt.Errorf("%w: the responder sent no IDr and we have none to fall back on: %w",
				ErrPeerAuthFailed, err)
		}
		idBody = encoded
	}
	macedIDr, err := MACedIdentityBody(s.prf, s.keys.SKPr, idBody)
	if err != nil {
		return err
	}
	signed := ResponderSignedOctets(s.cfg.Init.ResponseBytes, s.cfg.Init.NonceI, macedIDr)
	expected, err := SharedKeyAuth(s.prf, msk, signed)
	if err != nil {
		return err
	}
	if !EqualAuth(expected, parts.auth.Data) {
		return fmt.Errorf("%w: %d octets received, method %d, over IDr of %d octets",
			ErrPeerAuthFailed, len(parts.auth.Data), parts.auth.Method, len(idBody))
	}
	s.detail.PeerAuthVerified = true
	return nil
}

// exchange protects one request, sends it, and unprotects the response.
func (s *authSession) exchange(ctx context.Context, payloads []ikev2.Payload) ([]byte, []byte, []ikev2.Payload, error) {
	messageID := s.messageID
	iv, err := s.nextIV()
	if err != nil {
		return nil, nil, nil, err
	}
	_, reqBytes, err := ikev2.ProtectMessage(s.header(messageID), s.keys, true, payloads, iv)
	if err != nil {
		return nil, nil, nil, err
	}
	respBytes, err := s.cfg.Transport.ExchangeIKE(ctx, reqBytes)
	if err != nil {
		return nil, nil, nil, err
	}
	msg, inner, err := ikev2.UnprotectMessage(respBytes, s.keys, false)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: message %d: %w", ErrInvalidAuthResponse, messageID, err)
	}
	h := msg.Header
	if h.InitiatorSPI != s.cfg.Init.InitiatorSPI || h.ResponderSPI != s.cfg.Init.ResponderSPI ||
		h.ExchangeType != ikev2.ExchangeIKE_AUTH || h.MessageID != messageID || h.Flags&ikev2.FlagResponse == 0 {
		return nil, nil, nil, fmt.Errorf("%w: unexpected header on message %d", ErrInvalidAuthResponse, messageID)
	}
	// Both of these happen before FirstNotifyError, on purpose. A rejection is
	// carried by a notify, so the exchange that gets rejected is precisely the
	// one whose record must survive - and until T041d the only rejections this
	// package had ever seen were the ones its own fixture produced.
	s.detail.Rounds = append(s.detail.Rounds, AuthRound{
		MessageID:     messageID,
		SentPayloads:  payloadTypes(payloads),
		GotPayloads:   payloadTypes(inner),
		SentAuth:      containsPayload(payloads, ikev2.PayloadAUTH),
		GotAuth:       containsPayload(inner, ikev2.PayloadAUTH),
		GotChildSA:    containsPayload(inner, ikev2.PayloadSA),
		RequestBytes:  append([]byte(nil), reqBytes...),
		ResponseBytes: append([]byte(nil), respBytes...),
	})
	s.noteNotifies(messageID, inner)
	if err := ikev2.FirstNotifyError(inner); err != nil {
		return nil, nil, nil, fmt.Errorf("%w: message %d: %w", ErrInvalidAuthResponse, messageID, err)
	}
	s.messageID = messageID + 1
	return append([]byte(nil), reqBytes...), append([]byte(nil), respBytes...), inner, nil
}

// noteNotifies keeps every notify the responder sent, error or not.
//
// ikev2.FirstNotifyError turns an error notify into a Go error and the type
// number ends up inside the message text. That is fine to read and useless to
// assert on, and "which notify did the ePDG reject us with" is the single most
// load-bearing fact in a failed first contact.
func (s *authSession) noteNotifies(messageID uint32, inner []ikev2.Payload) {
	for _, p := range inner {
		if p.Type != ikev2.PayloadNotify {
			continue
		}
		n, err := ikev2.ParseNotify(p.Body)
		if err != nil {
			s.detail.ResponseNotifies = append(s.detail.ResponseNotifies, AuthNotify{
				MessageID: messageID,
				Malformed: p.Body,
			})
			continue
		}
		s.detail.ResponseNotifies = append(s.detail.ResponseNotifies, AuthNotify{
			MessageID: messageID,
			Type:      n.NotifyType,
			Data:      append([]byte(nil), n.NotificationData...),
		})
	}
}

func (s *authSession) header(messageID uint32) ikev2.Header {
	return ikev2.Header{
		InitiatorSPI: s.cfg.Init.InitiatorSPI,
		ResponderSPI: s.cfg.Init.ResponderSPI,
		ExchangeType: ikev2.ExchangeIKE_AUTH,
		Flags:        ikev2.FlagInitiator,
		MessageID:    messageID,
	}
}

func (s *authSession) lastRoundMessageID() uint32 {
	if len(s.detail.Rounds) == 0 {
		return s.messageID
	}
	return s.detail.Rounds[len(s.detail.Rounds)-1].MessageID
}

// nextIV consumes a pinned IV when one is left, otherwise draws a fresh one and
// remembers it. Every IV used is recorded, which is what lets an IKE_AUTH
// recording be replayed byte for byte: AES-CBC ciphertext is a function of the
// IV, so a replay that regenerated one would stop matching immediately.
func (s *authSession) nextIV() ([]byte, error) {
	var iv []byte
	if len(s.ivQueue) > 0 {
		iv = s.ivQueue[0]
		s.ivQueue = s.ivQueue[1:]
		if len(iv) != s.keys.Profile.EncryptionBlockSize {
			return nil, fmt.Errorf("%w: pinned IV is %d octets, profile wants %d",
				ErrInvalidAuthConfig, len(iv), s.keys.Profile.EncryptionBlockSize)
		}
	} else {
		fresh, err := ikev2.RandomIV(s.random, s.keys.Profile)
		if err != nil {
			return nil, err
		}
		iv = fresh
	}
	s.detail.IVs = append(s.detail.IVs, append([]byte(nil), iv...))
	return iv, nil
}

func (s *authSession) publishSeed() {
	if s.recorder != nil {
		s.detail.AKAVectors = s.recorder.Vectors()
	}
	if s.runner.Capture == nil {
		return
	}
	s.runner.Capture.SetAuthSeed(capture.AuthSeed{
		ChildSPI:        s.detail.ChildSPI,
		IVs:             s.detail.IVs,
		EAPIdentity:     s.driver.Identity(),
		InitiatorIDType: s.initiatorID.Type,
		InitiatorID:     s.initiatorID.Data,
		ResponderIDType: s.runner.ResponderID.Type,
		ResponderID:     s.runner.ResponderID.Data,
		AKA:             s.detail.AKAVectors,
	})
}

func (s *authSession) offeredChildSA() ikev2.SecurityAssociation {
	if len(s.runner.ChildSA.Proposals) > 0 {
		return s.runner.ChildSA
	}
	return s.cfg.ChildSA
}

func (s *authSession) offeredTSi() ikev2.TrafficSelectors {
	if len(s.runner.TSi.Selectors) > 0 {
		return s.runner.TSi
	}
	return s.cfg.TSi
}

func (s *authSession) offeredTSr() ikev2.TrafficSelectors {
	if len(s.runner.TSr.Selectors) > 0 {
		return s.runner.TSr
	}
	return s.cfg.TSr
}

func (s *authSession) offeredConfiguration() ikev2.Configuration {
	if s.runner.Configuration.Type != 0 || len(s.runner.Configuration.Attributes) > 0 {
		return s.runner.Configuration
	}
	return s.cfg.Configuration
}

func (s *authSession) noteResponseEAP(parts authResponseParts) {
	if len(s.detail.Rounds) == 0 || parts.eap == nil {
		return
	}
	round := &s.detail.Rounds[len(s.detail.Rounds)-1]
	round.EAPCode = parts.eap.Code
	round.EAPSubtype = parts.eap.Subtype
}

func (s *authSession) absorbStep(step EAPStep) {
	if step.HaveKeys {
		s.result.EAPKeys = step.Keys
	}
	if step.SyncFailure {
		s.detail.SyncFailures++
		s.result.SyncFailure = true
	}
	if step.AuthFailure {
		s.detail.AuthRejects++
		s.result.AuthFailure = true
	}
	if step.ClientError {
		s.detail.ClientErrors++
		s.result.EAPClientError = true
	}
	if step.KDFNegotiated {
		s.result.KDFNegotiations++
	}
	if step.IdentityState.NextPseudonym != "" {
		s.result.EAPNextPseudonym = step.IdentityState.NextPseudonym
	}
	if step.IdentityState.NextReauthID != "" {
		s.result.EAPNextReauthID = step.IdentityState.NextReauthID
	}
	if step.Identity != "" {
		s.detail.EAPIdentityUsed = step.Identity
		s.result.Auth.EAPIdentityUsed = step.Identity
	}
}

func (s *authSession) recordEAPExchange(request authResponseParts, step EAPStep, reqBytes, respBytes []byte, inner []ikev2.Payload) {
	if len(s.detail.Rounds) > 0 {
		s.detail.Rounds[len(s.detail.Rounds)-1].ResponseEAP = step.Response.Subtype
	}
	s.result.FinalResponseBytes = respBytes
	s.result.FinalResponseInner = clonePayloads(inner)
	switch {
	case request.eap != nil && request.eap.Subtype == eapaka.SubtypeIdentity:
		s.result.Auth.IdentityRequestBytes = reqBytes
		s.result.Auth.IdentityResponseBytes = respBytes
		s.result.Auth.IdentityResponseInner = clonePayloads(inner)
		s.result.Auth.IdentityTranscript = s.driver.Transcript()
		s.result.IdentityExchanges = append(s.result.IdentityExchanges, ikev2.EAPIdentityExchange{
			Request:       *request.eap,
			Response:      step.Response,
			Identity:      step.Identity,
			RequestBytes:  reqBytes,
			ResponseBytes: respBytes,
			ResponseInner: clonePayloads(inner),
			Transcript:    s.driver.Transcript(),
			NextMessageID: s.messageID,
		})
	case step.Challenge:
		s.result.AKAChallenges = append(s.result.AKAChallenges, ikev2.AKAChallengeResult{
			RequestBytes:       reqBytes,
			ResponseBytes:      respBytes,
			ResponseInner:      clonePayloads(inner),
			EAPResponse:        step.Response,
			EAPKeys:            step.Keys,
			EAPNextPseudonym:   step.IdentityState.NextPseudonym,
			EAPNextReauthID:    step.IdentityState.NextReauthID,
			SyncFailure:        step.SyncFailure,
			AuthFailure:        step.AuthFailure,
			NextMessageID:      s.messageID,
			FinalResponseBytes: respBytes,
			FinalResponseInner: clonePayloads(inner),
		})
	case step.Notification:
		s.result.EAPNotifications = append(s.result.EAPNotifications, *request.eap)
	}
	if s.result.Auth.EAPRequest == nil && request.eap != nil {
		first := *request.eap
		s.result.Auth.EAPRequest = &first
	}
}

// authResponseParts is what one IKE_AUTH response carried.
type authResponseParts struct {
	idrBody []byte
	auth    *AuthValue
	eap     *eapaka.Packet
	eapRaw  []byte
	hasSA   bool
}

func parseAuthResponse(inner []ikev2.Payload) (authResponseParts, error) {
	var out authResponseParts
	for _, p := range inner {
		switch p.Type {
		case ikev2.PayloadIDr:
			// Validate the shape, but keep the raw body: RFC 7296 section 2.15
			// MACs the octets that were sent, not a re-encoding of them.
			if _, err := ikev2.ParseIdentity(p.Body); err != nil {
				return authResponseParts{}, fmt.Errorf("%w: IDr: %w", ErrInvalidAuthResponse, err)
			}
			out.idrBody = append([]byte(nil), p.Body...)
		case ikev2.PayloadAUTH:
			value, err := ParseAuthPayload(p.Body)
			if err != nil {
				return authResponseParts{}, err
			}
			out.auth = &value
		case ikev2.PayloadEAP:
			packet, err := eapaka.ParsePacket(p.Body)
			if err != nil {
				return authResponseParts{}, fmt.Errorf("%w: EAP: %w", ErrInvalidAuthResponse, err)
			}
			out.eap = &packet
			out.eapRaw = append([]byte(nil), p.Body...)
		case ikev2.PayloadSA:
			out.hasSA = true
		}
	}
	return out, nil
}

func payloadTypes(payloads []ikev2.Payload) []uint8 {
	out := make([]uint8, 0, len(payloads))
	for _, p := range payloads {
		out = append(out, p.Type)
	}
	return out
}

func containsPayload(payloads []ikev2.Payload, payloadType uint8) bool {
	for _, p := range payloads {
		if p.Type == payloadType {
			return true
		}
	}
	return false
}

func containsNotify(payloads []ikev2.Payload, notifyType uint16) bool {
	_, found, err := ikev2.FirstNotify(payloads, notifyType)
	return err == nil && found
}

func clonePayloads(in []ikev2.Payload) []ikev2.Payload {
	out := make([]ikev2.Payload, len(in))
	for i, p := range in {
		out[i] = ikev2.Payload{
			Type:        p.Type,
			NextPayload: p.NextPayload,
			Critical:    p.Critical,
			Body:        append([]byte(nil), p.Body...),
		}
	}
	return out
}

func clonePacketPointer(packet *eapaka.Packet) *eapaka.Packet {
	if packet == nil {
		return nil
	}
	out := *packet
	return &out
}
