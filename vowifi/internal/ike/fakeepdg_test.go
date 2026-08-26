package ike

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/boa-z/vowifi-go/engine/sim"
	"github.com/boa-z/vowifi-go/engine/swu/eapaka"
	"github.com/boa-z/vowifi-go/engine/swu/ikev2"
)

// fakeEPDG is a loopback stand-in for an ePDG. It speaks real IKE_SA_INIT with
// real MODP/ECP arithmetic, so a passing test means our wire format and our key
// derivation both agree with an independent implementation of the same RFC.
//
// It also models the message *sequencing* of IKE_AUTH. That matters because the
// rest of this repo has been assuming EAP-Success and the CHILD_SA arrive in one
// message. Real ePDGs do not do that: EAP-Success closes the EAP method in its
// own IKE_AUTH response, and the AUTH payload plus SA/TSi/TSr come in the next
// exchange. The ladder below sends them in different messages on purpose so
// T041b inherits a fixture that cannot re-learn the wrong lesson.
type fakeEPDG struct {
	t    *testing.T
	conn *net.UDPConn

	mu sync.Mutex

	// behaviour knobs
	requireCookie   bool
	cookieValue     []byte
	demandGroup     uint16 // when non-zero, answer INVALID_KE_PAYLOAD for anything else
	echoNATDetect   bool
	dropFirst       int
	suite           Suite
	responderNonce  int
	authLadder      bool
	unsolicitedJunk bool

	// epdg, when non-nil, replaces the plaintext authLadder with a real
	// encrypted IKE_AUTH responder built below.
	epdg *epdgAuth

	// observed state
	requests        []ikev2.Message
	rawRequests     [][]byte
	cookiesSeen     int
	kePayloads      []ikev2.KeyExchange
	responderSPI    uint64
	authMessageLog  []authStage
	dropsRemaining  int
	closed          bool
	wg              sync.WaitGroup
	lastInitiatorIP *net.UDPAddr

	// IKE SA state, derived once IKE_SA_INIT completes. Everything the
	// encrypted IKE_AUTH ladder needs lives here: without SK_ei/SK_ai the fake
	// cannot decrypt us, and without the verbatim IKE_SA_INIT messages and the
	// nonces it cannot check an AUTH payload.
	ikeKeys         ikev2.IKEKeys
	haveIKEKeys     bool
	nonceI          []byte
	nonceR          []byte
	initRequestRaw  []byte
	initResponseRaw []byte
}

// authStage names what an IKE_AUTH response carried.
type authStage struct {
	MessageID    uint32
	EAPRequest   bool
	EAPSuccess   bool
	CarriesAuth  bool
	CarriesChild bool
}

func newFakeEPDG(t *testing.T) *fakeEPDG {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("fake ePDG listen: %v", err)
	}
	spi := make([]byte, 8)
	if _, err := rand.Read(spi); err != nil {
		t.Fatalf("fake ePDG spi: %v", err)
	}
	f := &fakeEPDG{
		t:              t,
		conn:           conn,
		suite:          MainstreamSuites()[0],
		demandGroup:    GroupMODP2048,
		echoNATDetect:  true,
		responderNonce: 32,
		responderSPI:   binary.BigEndian.Uint64(spi) | 1,
	}
	t.Cleanup(f.Close)
	return f
}

func (f *fakeEPDG) Addr() *net.UDPAddr { return f.conn.LocalAddr().(*net.UDPAddr) }

func (f *fakeEPDG) Close() {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	f.closed = true
	f.mu.Unlock()
	f.conn.Close()
	f.wg.Wait()
}

func (f *fakeEPDG) Start() {
	f.mu.Lock()
	f.dropsRemaining = f.dropFirst
	f.mu.Unlock()
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		buf := make([]byte, 64*1024)
		for {
			n, from, err := f.conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			wire := append([]byte(nil), buf[:n]...)
			f.mu.Lock()
			f.lastInitiatorIP = from
			drop := f.dropsRemaining > 0
			if drop {
				f.dropsRemaining--
			}
			f.mu.Unlock()
			if drop {
				continue
			}
			if len(wire) == 1 && wire[0] == 0xff {
				continue // NAT-T keepalive
			}
			if len(wire) < 4 || wire[0] != 0 || wire[1] != 0 || wire[2] != 0 || wire[3] != 0 {
				continue // ESP; nothing to do in T041a
			}
			resp, err := f.handle(wire[4:])
			if err != nil {
				f.t.Errorf("fake ePDG: %v", err)
				continue
			}
			if resp == nil {
				continue
			}
			out := append([]byte{0, 0, 0, 0}, resp...)
			if _, err := f.conn.WriteToUDP(out, from); err != nil {
				return
			}
			if f.unsolicitedJunk {
				// A late duplicate of a *previous* exchange, to prove the
				// transport matches responses by header instead of taking
				// whatever shows up next.
				junk := append([]byte(nil), out...)
				binary.BigEndian.PutUint32(junk[4+20:4+24], 0xdead)
				_, _ = f.conn.WriteToUDP(junk, from)
			}
		}
	}()
}

func (f *fakeEPDG) handle(raw []byte) ([]byte, error) {
	msg, err := ikev2.ParseMessage(raw)
	if err != nil {
		return nil, fmt.Errorf("parse request: %w", err)
	}
	f.mu.Lock()
	f.requests = append(f.requests, msg)
	f.rawRequests = append(f.rawRequests, append([]byte(nil), raw...))
	f.mu.Unlock()

	switch msg.Header.ExchangeType {
	case ikev2.ExchangeIKE_SA_INIT:
		return f.handleInit(msg, raw)
	case ikev2.ExchangeIKE_AUTH:
		return f.handleAuth(msg, raw)
	default:
		return nil, fmt.Errorf("unexpected exchange type %d", msg.Header.ExchangeType)
	}
}

func (f *fakeEPDG) respond(req ikev2.Message, payloads []ikev2.Payload) ([]byte, error) {
	resp := ikev2.Message{
		Header: ikev2.Header{
			InitiatorSPI: req.Header.InitiatorSPI,
			ResponderSPI: f.responderSPI,
			ExchangeType: req.Header.ExchangeType,
			Flags:        ikev2.FlagResponse,
			MessageID:    req.Header.MessageID,
		},
		Payloads: payloads,
	}
	return resp.MarshalBinary()
}

func (f *fakeEPDG) handleInit(msg ikev2.Message, raw []byte) ([]byte, error) {
	var (
		sa     ikev2.SecurityAssociation
		ke     ikev2.KeyExchange
		nonceI []byte
		cookie []byte
		natSrc bool
		natDst bool
	)
	for _, p := range msg.Payloads {
		switch p.Type {
		case ikev2.PayloadSA:
			parsed, err := ikev2.ParseSecurityAssociation(p.Body)
			if err != nil {
				return nil, err
			}
			sa = parsed
		case ikev2.PayloadKE:
			parsed, err := ikev2.ParseKeyExchange(p.Body)
			if err != nil {
				return nil, err
			}
			ke = parsed
		case ikev2.PayloadNonce:
			nonceI = append([]byte(nil), p.Body...)
		case ikev2.PayloadNotify:
			n, err := ikev2.ParseNotify(p.Body)
			if err != nil {
				return nil, err
			}
			if got, ok, err := n.Cookie(); err == nil && ok {
				cookie = got
			}
			switch n.NotifyType {
			case ikev2.NotifyNATDetectionSourceIP:
				natSrc = true
			case ikev2.NotifyNATDetectionDestinationIP:
				natDst = true
			}
		}
	}
	f.mu.Lock()
	f.kePayloads = append(f.kePayloads, ke)
	requireCookie := f.requireCookie
	demand := f.demandGroup
	f.mu.Unlock()

	if len(sa.Proposals) == 0 {
		// A bare reachability probe with no SA payload. Transport-level tests
		// use these to drive retransmission and header matching without pulling
		// in the whole negotiation, so answer minimally instead of failing.
		return f.respond(msg, []ikev2.Payload{ikev2.NoncePayload(nonceI)})
	}
	if len(nonceI) < 16 {
		return nil, fmt.Errorf("initiator nonce is %d octets", len(nonceI))
	}

	if requireCookie {
		if len(cookie) == 0 {
			value := []byte("vodoge-test-cookie")
			f.mu.Lock()
			f.cookieValue = value
			f.mu.Unlock()
			payload, err := ikev2.CookieNotify(value)
			if err != nil {
				return nil, err
			}
			return f.respond(msg, []ikev2.Payload{payload})
		}
		f.mu.Lock()
		f.cookiesSeen++
		expected := string(f.cookieValue)
		f.mu.Unlock()
		if string(cookie) != expected {
			return nil, fmt.Errorf("cookie echo mismatch")
		}
		if msg.Payloads[0].Type != ikev2.PayloadNotify {
			return nil, fmt.Errorf("RFC 7296 2.6 requires the COOKIE notify first, got payload type %d", msg.Payloads[0].Type)
		}
	}

	if demand != 0 && ke.DHGroup != demand {
		var body [2]byte
		binary.BigEndian.PutUint16(body[:], demand)
		payload, err := ikev2.NotifyPayload(ikev2.Notify{
			NotifyType:       ikev2.NotifyInvalidKEPayload,
			NotificationData: body[:],
		})
		if err != nil {
			return nil, err
		}
		return f.respond(msg, []ikev2.Payload{payload})
	}

	group := ke.DHGroup
	peer, err := GenerateKeyPair(group, rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := peer.ComputeSharedSecret(ke.KeyData)
	if err != nil {
		return nil, fmt.Errorf("initiator KE rejected: %w", err)
	}

	f.mu.Lock()
	suite := f.suite
	nonceLen := f.responderNonce
	echoNAT := f.echoNATDetect
	f.mu.Unlock()

	selected := ikev2.SecurityAssociation{Proposals: []ikev2.Proposal{{
		Number:     1,
		ProtocolID: ikev2.ProtocolIKE,
		Transforms: []ikev2.Transform{
			{Type: ikev2.TransformENCR, ID: suite.Encryption, Attributes: []ikev2.TransformAttribute{ikev2.KeyLengthAttribute(suite.EncryptionKey)}},
			{Type: ikev2.TransformPRF, ID: suite.PRF},
			{Type: ikev2.TransformINTEG, ID: suite.Integrity},
			{Type: ikev2.TransformDHRGroup, ID: group},
		},
	}}}
	saPayload, err := ikev2.SecurityAssociationPayload(selected)
	if err != nil {
		return nil, err
	}
	nonceR := make([]byte, nonceLen)
	if _, err := rand.Read(nonceR); err != nil {
		return nil, err
	}
	payloads := []ikev2.Payload{
		saPayload,
		ikev2.KeyExchangePayload(group, peer.PublicKey()),
		ikev2.NoncePayload(nonceR),
	}
	if echoNAT && natSrc && natDst {
		f.mu.Lock()
		from := f.lastInitiatorIP
		f.mu.Unlock()
		local := f.Addr()
		// The responder hashes its own address into SOURCE and the peer address
		// it observes into DESTINATION (RFC 7296 section 2.23).
		src, err := ikev2.NATDetectionNotify(ikev2.NotifyNATDetectionSourceIP,
			msg.Header.InitiatorSPI, f.responderSPI, local.IP, uint16(local.Port))
		if err != nil {
			return nil, err
		}
		dst, err := ikev2.NATDetectionNotify(ikev2.NotifyNATDetectionDestinationIP,
			msg.Header.InitiatorSPI, f.responderSPI, from.IP, uint16(from.Port))
		if err != nil {
			return nil, err
		}
		payloads = append(payloads, src, dst)
	}
	payloads = append(payloads, ikev2.MOBIKESupportedNotify())
	respBytes, err := f.respond(msg, payloads)
	if err != nil {
		return nil, err
	}
	if err := f.deriveIKEKeys(msg, selected, shared, nonceI, nonceR, raw, respBytes); err != nil {
		return nil, err
	}
	return respBytes, nil
}

// deriveIKEKeys is the responder half of RFC 7296 section 2.14, done with the
// mirror's own primitives.
//
// It runs on the successful IKE_SA_INIT only - a COOKIE round or an
// INVALID_KE_PAYLOAD round returns earlier - so the stored messages are the ones
// RFC 7296 section 2.15 actually signs.
func (f *fakeEPDG) deriveIKEKeys(req ikev2.Message, selected ikev2.SecurityAssociation, shared, nonceI, nonceR, reqRaw, respRaw []byte) error {
	profile, err := ikev2.KeyMaterialProfileFromSA(selected)
	if err != nil {
		return err
	}
	skeyseed, err := ikev2.SKEYSEED(profile.PRF, nonceI, nonceR, shared)
	if err != nil {
		return err
	}
	material, err := ikev2.DeriveIKESAKeyMaterial(profile.PRF, skeyseed, nonceI, nonceR,
		req.Header.InitiatorSPI, f.responderSPI, profile.RequiredLength())
	if err != nil {
		return err
	}
	keys, err := ikev2.SplitIKEKeys(profile, material)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ikeKeys = keys
	f.haveIKEKeys = true
	f.nonceI = append([]byte(nil), nonceI...)
	f.nonceR = append([]byte(nil), nonceR...)
	f.initRequestRaw = append([]byte(nil), reqRaw...)
	f.initResponseRaw = append([]byte(nil), respRaw...)
	return nil
}

// handleAuth models the IKE_AUTH ladder at the message-sequencing level only.
//
// T041a has no SK encryption yet (that is T041b), so these payloads travel in
// clear. What is being asserted here is not cryptography, it is the shape of the
// conversation: EAP-Request rounds, then an IKE_AUTH response whose only EAP
// payload is EAP-Success, and then a *separate* exchange carrying AUTH plus the
// CHILD_SA. Any code that assumes the last two share a message fails against
// this fixture.
func (f *fakeEPDG) handleAuth(msg ikev2.Message, raw []byte) ([]byte, error) {
	f.mu.Lock()
	ladder := f.authLadder
	encrypted := f.epdg != nil
	f.mu.Unlock()
	if encrypted {
		return f.handleEncryptedAuth(msg, raw)
	}
	if !ladder {
		return nil, nil
	}
	id := msg.Header.MessageID
	var stage authStage
	stage.MessageID = id
	var payloads []ikev2.Payload
	switch id {
	case 1:
		// EAP-AKA Challenge: EAP payload only, no AUTH, no SA.
		stage.EAPRequest = true
		payloads = append(payloads, ikev2.EAPPayload([]byte{1, byte(id), 0, 8, 23, 1, 0, 0}))
	case 2:
		// EAP-Success closes the method. It travels alone.
		stage.EAPSuccess = true
		payloads = append(payloads, ikev2.EAPPayload([]byte{3, byte(id), 0, 4}))
	default:
		// Only now do AUTH and the CHILD_SA appear, in a later exchange.
		stage.CarriesAuth = true
		stage.CarriesChild = true
		childSA, err := ikev2.SecurityAssociationPayload(ikev2.DefaultESPProposal([]byte{1, 2, 3, 4}))
		if err != nil {
			return nil, err
		}
		payloads = append(payloads,
			ikev2.Payload{Type: ikev2.PayloadAUTH, Body: []byte{2, 0, 0, 0, 9, 9, 9, 9}},
			childSA,
			ikev2.Payload{Type: ikev2.PayloadTSi, Body: tsPayloadBody()},
			ikev2.Payload{Type: ikev2.PayloadTSr, Body: tsPayloadBody()},
		)
	}
	f.mu.Lock()
	f.authMessageLog = append(f.authMessageLog, stage)
	f.mu.Unlock()
	return f.respond(msg, payloads)
}

// tsPayloadBody is a single IPv4 traffic selector covering everything.
func tsPayloadBody() []byte {
	body := []byte{1, 0, 0, 0}
	sel := []byte{7, 0, 0, 16, 0, 0, 0xff, 0xff, 0, 0, 0, 0, 255, 255, 255, 255}
	return append(body, sel...)
}

func (f *fakeEPDG) requestCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

func (f *fakeEPDG) offeredGroups() []uint16 {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []uint16
	for _, ke := range f.kePayloads {
		out = append(out, ke.DHGroup)
	}
	return out
}

func (f *fakeEPDG) authStages() []authStage {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]authStage, len(f.authMessageLog))
	copy(out, f.authMessageLog)
	return out
}

// testPolicy keeps unit tests fast while still exercising the retransmit path.
func testPolicy(attempts int) RetransmitPolicy {
	return RetransmitPolicy{
		Initial:    150 * time.Millisecond,
		Multiplier: 1.5,
		Max:        600 * time.Millisecond,
		Attempts:   attempts,
	}
}

// dialFake opens our production socket against the fake ePDG. The local port is
// zero here rather than 4500 so parallel tests do not collide; the pinned-4500
// behaviour is covered separately by TestSocketBindsNATTPort.
func dialFake(t *testing.T, f *fakeEPDG, cfg SocketConfig) *Socket {
	t.Helper()
	cfg.Remote = f.Addr()
	cfg.EphemeralLocalPort = true
	if cfg.LocalIP == nil {
		cfg.LocalIP = net.IPv4(127, 0, 0, 1)
	}
	if cfg.Retransmit == (RetransmitPolicy{}) {
		cfg.Retransmit = testPolicy(4)
	}
	marker := true
	cfg.UseNonESPMarker = &marker
	s, err := Listen(cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = s.Close(nil) })
	return s
}

// ---------------------------------------------------------------------------
// Encrypted IKE_AUTH responder (T041b)
// ---------------------------------------------------------------------------

// testUSIMKey is the secret shared by the stand-in card and the stand-in AuC.
var testUSIMKey = []byte("vodoge-t041b-usim-key-not-a-real-K")

// usimDerive is the stand-in for Milenage.
//
// It is not Milenage and does not claim to be. Writing a Milenage vector from
// memory is exactly the anti-pattern this project keeps getting burnt by, so
// instead the card and the operator's AuC share one deterministic function whose
// only property that matters is that both sides compute the same RES/CK/IK from
// the same RAND/AUTN - which is precisely the property a real K provides.
//
// Everything downstream of it is real: eapaka.DeriveKeys performs the RFC 4187
// section 7 derivation, AT_MAC is a real HMAC over the real packet bytes, and
// the IKEv2 AUTH is computed by two independent pieces of code (production via
// ike.SharedKeyAuth, fixture via epdgSharedKeyAuth below) that only agree if the
// RFC 7296 section 2.15 composition is right.
func usimDerive(k []byte, label string, rand16, autn16 []byte) []byte {
	mac := hmac.New(sha256.New, k)
	_, _ = mac.Write([]byte(label))
	_, _ = mac.Write(rand16)
	_, _ = mac.Write(autn16)
	return mac.Sum(nil)
}

func usimVector(k, rand16, autn16 []byte) sim.AKAResult {
	return sim.AKAResult{
		RES: usimDerive(k, "res", rand16, autn16)[:8],
		CK:  usimDerive(k, "ck", rand16, autn16)[:16],
		IK:  usimDerive(k, "ik", rand16, autn16)[:16],
	}
}

// testAKAProvider is the injected sim.AKAProvider. T041b must not touch
// hardware; the real card bridge is T041c and needs the modem window.
type testAKAProvider struct {
	mu sync.Mutex

	k []byte
	// syncFailOn and authFailOn are 1-based call indexes that should fail.
	syncFailOn map[int]bool
	authFailOn map[int]bool
	// auts is the 14-octet resynchronisation token handed back on a sync
	// failure, the way a real card returns one.
	auts []byte
	// delay stalls the call, to exercise the deadline seam.
	delay time.Duration

	calls int
	seen  [][2][]byte
}

func newTestAKAProvider() *testAKAProvider {
	auts := make([]byte, eapaka.AUTSLength)
	for i := range auts {
		auts[i] = byte(0xa0 + i)
	}
	return &testAKAProvider{
		k:          testUSIMKey,
		syncFailOn: map[int]bool{},
		authFailOn: map[int]bool{},
		auts:       auts,
	}
}

func (p *testAKAProvider) CalculateAKA(rand16, autn16 []byte) (sim.AKAResult, error) {
	p.mu.Lock()
	p.calls++
	call := p.calls
	delay := p.delay
	syncFail := p.syncFailOn[call]
	authFail := p.authFailOn[call]
	auts := append([]byte(nil), p.auts...)
	p.seen = append(p.seen, [2][]byte{append([]byte(nil), rand16...), append([]byte(nil), autn16...)})
	p.mu.Unlock()

	if delay > 0 {
		time.Sleep(delay)
	}
	switch {
	case syncFail:
		// AUTS travels on the error, not in the result, so the eapaka
		// syncFailureAUTS carrier path gets exercised too.
		return sim.AKAResult{}, sim.NewSyncFailureError(auts)
	case authFail:
		return sim.AKAResult{}, sim.NewMACFailureError()
	default:
		return usimVector(p.k, rand16, autn16), nil
	}
}

func (p *testAKAProvider) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

// epdgAuth is the state of one encrypted IKE_AUTH conversation.
type epdgAuth struct {
	// --- behaviour knobs ---
	k                        []byte
	responderID              ikev2.Identity
	skipIdentityRound        bool
	requireIDr               bool
	requireEAPOnly           bool
	authMethod               uint8
	espSPI                   []byte
	maxChallenges            int
	corruptOwnAuth           bool
	omitOwnAuth              bool
	certAuthInFirstResponse  bool
	eapSuccessCarriesChildSA bool
	// addressFailure answers the final exchange with notify 36 instead of a
	// CHILD_SA, unconditionally. This is the T072 rejection, reproduced.
	addressFailure bool
	// requirePCSCF answers notify 36 unless the CFG_REQUEST asked for a P-CSCF
	// address. It models the hypothesis T046 named, so that "adding the P-CSCF
	// attribute is what fixes it" is a statement some responder actually
	// enforces rather than a comment in our own encoder.
	requirePCSCF bool
	// requireSingleFamily answers notify 36 when the CFG_REQUEST asks for both
	// an IPv4 and an IPv6 internal address. It models the other candidate cause
	// of notify 36, so the two can be told apart offline.
	requireSingleFamily bool
	// requireCP answers FAILED_CP_REQUIRED (notify 37) when the first IKE_AUTH
	// request carried no CP payload at all. It is the responder T088's live run
	// is hoping to have been talking to: one that reads the configuration
	// payload closely enough to mind its absence.
	//
	// It is a separate knob from requirePCSCF because the two are answers to
	// different questions, and a fixture that conflated them would let a run
	// with no CP be "explained" by the P-CSCF rule it cannot possibly have
	// broken.
	requireCP bool
	// pcscfIPv4 and pcscfIPv6 are what the CFG_REPLY hands back when the
	// request asked for them.
	pcscfIPv4 net.IP
	pcscfIPv6 net.IP

	// --- observed ---
	initialPayloadTypes []uint8
	observedIDi         []byte
	observedIDr         []byte
	sawEAPOnlyNotify    bool
	sawChildSAOffer     bool
	sawTSi              bool
	sawTSr              bool
	sawCP               bool
	observedConfig      ikev2.Configuration
	observedTSi         ikev2.TrafficSelectors
	refusalReason       string
	eapIdentity         string
	eapResponses        []uint8
	challenges          int
	currentRAND         []byte
	currentAUTN         []byte
	eapKeys             eapaka.Keys
	sentIDrBody         []byte
	clientAuth          []byte
	clientAuthMethod    uint8
	clientAuthVerified  bool
	syncFailures        int
	observedAUTS        []byte
	authRejects         int
	clientErrors        int
	identifier          uint8
}

func newEPDGAuth() *epdgAuth {
	return &epdgAuth{
		k:              testUSIMKey,
		responderID:    IdentityFQDN("epdg.epc.mnc260.mcc310.pub.3gppnetwork.org"),
		requireIDr:     true,
		requireEAPOnly: true,
		authMethod:     AuthMethodSharedKeyMIC,
		espSPI:         []byte{0xde, 0xad, 0xbe, 0xef},
		maxChallenges:  3,
		identifier:     40,
		pcscfIPv4:      net.IPv4(10, 64, 0, 33).To4(),
		pcscfIPv6:      net.ParseIP("2607:fc20:1:100::33"),
	}
}

// enableEPDGAuth switches the fixture from the T041a plaintext ladder to a real
// encrypted responder.
func (f *fakeEPDG) enableEPDGAuth(a *epdgAuth) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.epdg = a
}

func (f *fakeEPDG) auth() *epdgAuth {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.epdg
}

// handleEncryptedAuth is the whole IKE_AUTH ladder, encrypted.
//
// Every request is decrypted with the mirror's own UnprotectMessage. That is the
// upgrade over T041a: its ladder travelled in clear and could only pin message
// sequencing. Here a request that is not really protected fails at
// "expected single SK payload", and the AUTH payload is computed over key
// material that only exists because both sides ran the same key derivation.
func (f *fakeEPDG) handleEncryptedAuth(msg ikev2.Message, raw []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a := f.epdg
	if !f.haveIKEKeys {
		return nil, fmt.Errorf("IKE_AUTH message %d arrived before IKE_SA_INIT completed", msg.Header.MessageID)
	}
	_, inner, err := ikev2.UnprotectMessage(raw, f.ikeKeys, true)
	if err != nil {
		return nil, fmt.Errorf("decrypting IKE_AUTH message %d: %w", msg.Header.MessageID, err)
	}

	var (
		eapRaw   []byte
		authBody []byte
	)
	for _, p := range inner {
		switch p.Type {
		case ikev2.PayloadIDi:
			a.observedIDi = append([]byte(nil), p.Body...)
		case ikev2.PayloadIDr:
			a.observedIDr = append([]byte(nil), p.Body...)
		case ikev2.PayloadEAP:
			eapRaw = append([]byte(nil), p.Body...)
		case ikev2.PayloadAUTH:
			authBody = append([]byte(nil), p.Body...)
		case ikev2.PayloadSA:
			a.sawChildSAOffer = true
		case ikev2.PayloadTSi:
			a.sawTSi = true
			selectors, err := ikev2.ParseTrafficSelectors(p.Body)
			if err != nil {
				return nil, fmt.Errorf("decoding TSi: %w", err)
			}
			a.observedTSi = selectors
		case ikev2.PayloadTSr:
			a.sawTSr = true
		case ikev2.PayloadCP:
			a.sawCP = true
			// Decoded rather than remembered as bytes: the responder's whole
			// job in this file is to judge the request, and it cannot judge
			// what it has not parsed.
			config, err := ikev2.ParseConfiguration(p.Body)
			if err != nil {
				return nil, fmt.Errorf("decoding CP: %w", err)
			}
			a.observedConfig = config
		case ikev2.PayloadNotify:
			notify, err := ikev2.ParseNotify(p.Body)
			if err != nil {
				return nil, err
			}
			if notify.NotifyType == NotifyEAPOnlyAuthentication {
				a.sawEAPOnlyNotify = true
			}
		}
	}

	switch {
	case authBody != nil:
		return f.epdgFinalRound(msg, a, authBody)
	case eapRaw != nil:
		return f.epdgEAPRound(msg, a, eapRaw)
	default:
		return f.epdgFirstRound(msg, a, inner)
	}
}

func (f *fakeEPDG) epdgFirstRound(msg ikev2.Message, a *epdgAuth, inner []ikev2.Payload) ([]byte, error) {
	for _, p := range inner {
		a.initialPayloadTypes = append(a.initialPayloadTypes, p.Type)
	}
	if a.requireIDr && len(a.observedIDr) == 0 {
		return nil, fmt.Errorf("first IKE_AUTH request has no IDr; that is the shape "+
			"BuildIKEAuthInitialPayloads produces (auth.go:840-888) and it is what this card replaces. types=%v",
			a.initialPayloadTypes)
	}
	if a.requireEAPOnly && !a.sawEAPOnlyNotify {
		return nil, fmt.Errorf("first IKE_AUTH request has no EAP_ONLY_AUTHENTICATION notify (%d); "+
			"without it an ePDG expects certificate authentication. types=%v",
			NotifyEAPOnlyAuthentication, a.initialPayloadTypes)
	}
	if !a.sawChildSAOffer || !a.sawTSi || !a.sawTSr {
		return nil, fmt.Errorf("first IKE_AUTH request is missing SA/TSi/TSr: types=%v", a.initialPayloadTypes)
	}

	idr, err := ikev2.IdentityPayload(ikev2.PayloadIDr, a.responderID)
	if err != nil {
		return nil, err
	}
	a.sentIDrBody = append([]byte(nil), idr.Body...)
	payloads := []ikev2.Payload{idr}

	if a.certAuthInFirstResponse {
		// A responder that ignored RFC 5998 and is proving itself with a
		// certificate. The data is deliberately not verifiable.
		payloads = append(payloads, ikev2.Payload{
			Type: ikev2.PayloadAUTH,
			Body: append([]byte{1, 0, 0, 0}, bytes.Repeat([]byte{0x5a}, 32)...),
		})
	}

	var eap eapaka.Packet
	if a.skipIdentityRound {
		eap, err = a.buildChallenge()
		if err != nil {
			return nil, err
		}
	} else {
		a.identifier++
		eap = eapaka.Packet{
			Code:       eapaka.CodeRequest,
			Identifier: a.identifier,
			Type:       eapaka.TypeAKA,
			Subtype:    eapaka.SubtypeIdentity,
			Attributes: []eapaka.Attribute{eapaka.PermanentIDReqAttribute()},
		}
	}
	eapBytes, err := eap.MarshalBinary()
	if err != nil {
		return nil, err
	}
	payloads = append(payloads, ikev2.EAPPayload(eapBytes))
	f.logStage(msg.Header.MessageID, authStage{
		EAPRequest:  true,
		CarriesAuth: a.certAuthInFirstResponse,
	})
	return f.protectLocked(msg, payloads)
}

func (f *fakeEPDG) epdgEAPRound(msg ikev2.Message, a *epdgAuth, eapRaw []byte) ([]byte, error) {
	packet, err := eapaka.ParsePacket(eapRaw)
	if err != nil {
		return nil, err
	}
	if packet.Code != eapaka.CodeResponse {
		return nil, fmt.Errorf("EAP code %d is not a response", packet.Code)
	}
	a.eapResponses = append(a.eapResponses, packet.Subtype)

	switch packet.Subtype {
	case eapaka.SubtypeIdentity:
		attr, ok := eapaka.FindAttribute(packet.Attributes, eapaka.AttributeIdentity)
		if !ok {
			return nil, fmt.Errorf("EAP-Response/AKA-Identity has no AT_IDENTITY")
		}
		identity, err := attr.IdentityValue()
		if err != nil {
			return nil, err
		}
		a.eapIdentity = identity
		challenge, err := a.buildChallenge()
		if err != nil {
			return nil, err
		}
		return f.epdgSendEAP(msg, challenge, authStage{EAPRequest: true})

	case eapaka.SubtypeChallenge:
		if err := a.verifyChallengeResponse(packet, eapRaw); err != nil {
			return nil, err
		}
		success := eapaka.Packet{Code: eapaka.CodeSuccess, Identifier: packet.Identifier}
		stage := authStage{EAPSuccess: true}
		if a.eapSuccessCarriesChildSA {
			// The assumption T041a's fixture exists to break, made real so the
			// runner can be shown rejecting it.
			eapBytes, err := success.MarshalBinary()
			if err != nil {
				return nil, err
			}
			child, err := a.childPayloads()
			if err != nil {
				return nil, err
			}
			stage.CarriesChild = true
			f.logStage(msg.Header.MessageID, stage)
			return f.protectLocked(msg, append([]ikev2.Payload{ikev2.EAPPayload(eapBytes)}, child...))
		}
		return f.epdgSendEAP(msg, success, stage)

	case eapaka.SubtypeSynchronizationFailure:
		attr, ok := eapaka.FindAttribute(packet.Attributes, eapaka.AttributeAUTS)
		if !ok {
			return nil, fmt.Errorf("EAP-Response/AKA-Synchronization-Failure has no AT_AUTS")
		}
		auts, err := attr.AUTSValue()
		if err != nil {
			return nil, err
		}
		a.syncFailures++
		a.observedAUTS = append([]byte(nil), auts...)
		if a.challenges >= a.maxChallenges {
			return f.epdgSendEAP(msg, eapaka.Packet{Code: eapaka.CodeFailure, Identifier: packet.Identifier},
				authStage{})
		}
		// A real HSS resynchronises SQN from AUTS and issues a fresh challenge.
		challenge, err := a.buildChallenge()
		if err != nil {
			return nil, err
		}
		return f.epdgSendEAP(msg, challenge, authStage{EAPRequest: true})

	case eapaka.SubtypeAuthenticationReject:
		a.authRejects++
		return f.epdgSendEAP(msg, eapaka.Packet{Code: eapaka.CodeFailure, Identifier: packet.Identifier},
			authStage{})

	case eapaka.SubtypeClientError:
		a.clientErrors++
		return f.epdgSendEAP(msg, eapaka.Packet{Code: eapaka.CodeFailure, Identifier: packet.Identifier},
			authStage{})

	default:
		return nil, fmt.Errorf("unexpected EAP-Response subtype %d", packet.Subtype)
	}
}

func (f *fakeEPDG) epdgSendEAP(msg ikev2.Message, packet eapaka.Packet, stage authStage) ([]byte, error) {
	raw, err := packet.MarshalBinary()
	if err != nil {
		return nil, err
	}
	f.logStage(msg.Header.MessageID, stage)
	return f.protectLocked(msg, []ikev2.Payload{ikev2.EAPPayload(raw)})
}

func (f *fakeEPDG) epdgFinalRound(msg ikev2.Message, a *epdgAuth, authBody []byte) ([]byte, error) {
	if len(authBody) <= 4 {
		return nil, fmt.Errorf("AUTH payload body is %d octets", len(authBody))
	}
	a.clientAuthMethod = authBody[0]
	a.clientAuth = append([]byte(nil), authBody[4:]...)
	if reserved := authBody[1:4]; !bytes.Equal(reserved, []byte{0, 0, 0}) {
		return nil, fmt.Errorf("AUTH payload RESERVED octets are %v, RFC 7296 3.8 says senders zero them", reserved)
	}
	if len(a.eapKeys.MSK) == 0 {
		return nil, fmt.Errorf("AUTH arrived before the EAP method produced an MSK")
	}

	prf := f.ikeKeys.Profile.PRF
	macedIDi := epdgHMAC(prf, f.ikeKeys.SKPi, a.observedIDi)
	signed := concatBytes(f.initRequestRaw, f.nonceR, macedIDi)
	expected := epdgSharedKeyAuth(prf, a.eapKeys.MSK, signed)
	if !hmac.Equal(expected, a.clientAuth) {
		return nil, fmt.Errorf("initiator AUTH does not verify: got %d octets, expected %d",
			len(a.clientAuth), len(expected))
	}
	a.clientAuthVerified = true

	// A responder that needs a CP payload complains before it tries to satisfy
	// one, because there is nothing to satisfy. RFC 7296 section 3.10.1 puts
	// FAILED_CP_REQUIRED and INTERNAL_ADDRESS_FAILURE in the same place in the
	// exchange, and this fixture sends exactly one of them.
	if a.requireCP && !a.sawCP {
		a.refusalReason = "the first IKE_AUTH request carried no CP payload"
		notify, err := ikev2.NotifyPayload(ikev2.Notify{NotifyType: ikev2.NotifyFailedCPRequired})
		if err != nil {
			return nil, err
		}
		f.logStage(msg.Header.MessageID, authStage{})
		return f.protectLocked(msg, []ikev2.Payload{notify})
	}

	// The address decision happens here and not earlier, which is exactly where
	// T-Mobile made it: the initiator's AUTH is verified first, and only then
	// does the responder try to satisfy the CFG_REQUEST. That ordering is why
	// notify 36 is not an authentication verdict.
	if reason := a.addressFailureReason(); reason != "" {
		// The reason is kept here and not put on the wire. T-Mobile's notify 36
		// carried zero octets of notification data, so a fixture that shipped
		// an explanation would be teaching our parser about a field real ePDGs
		// leave empty.
		a.refusalReason = reason
		notify, err := ikev2.NotifyPayload(ikev2.Notify{NotifyType: ikev2.NotifyInternalAddressFailure})
		if err != nil {
			return nil, err
		}
		f.logStage(msg.Header.MessageID, authStage{})
		return f.protectLocked(msg, []ikev2.Payload{notify})
	}

	payloads := []ikev2.Payload{}
	if !a.omitOwnAuth {
		macedIDr := epdgHMAC(prf, f.ikeKeys.SKPr, a.sentIDrBody)
		ourSigned := concatBytes(f.initResponseRaw, f.nonceI, macedIDr)
		ourAuth := epdgSharedKeyAuth(prf, a.eapKeys.MSK, ourSigned)
		if a.corruptOwnAuth {
			ourAuth[0] ^= 0x01
		}
		body := append([]byte{a.authMethod, 0, 0, 0}, ourAuth...)
		payloads = append(payloads, ikev2.Payload{Type: ikev2.PayloadAUTH, Body: body})
	}
	child, err := a.childPayloads()
	if err != nil {
		return nil, err
	}
	payloads = append(payloads, child...)
	f.logStage(msg.Header.MessageID, authStage{
		CarriesAuth:  !a.omitOwnAuth,
		CarriesChild: true,
	})
	return f.protectLocked(msg, payloads)
}

// addressFailureReason decides whether this responder can satisfy the
// CFG_REQUEST it received, and says why not.
//
// The two conditional refusals are the two competing explanations for what
// T-Mobile did on 2026-08-24. Modelling both means the offline tests can tell
// them apart before a live run spends an SQN step finding out.
func (a *epdgAuth) addressFailureReason() string {
	if a.addressFailure {
		return "this responder refuses every CFG_REQUEST"
	}
	if a.requirePCSCF && !configAsksFor(a.observedConfig, ConfigPCSCFIPv4Address, ConfigPCSCFIPv6Address) {
		return "the CFG_REQUEST carries no P_CSCF_IP4_ADDRESS or P_CSCF_IP6_ADDRESS"
	}
	if a.requireSingleFamily &&
		configAsksFor(a.observedConfig, ikev2.ConfigInternalIPv4Address) &&
		configAsksFor(a.observedConfig, ikev2.ConfigInternalIPv6Address) {
		return "the CFG_REQUEST asks for both an IPv4 and an IPv6 internal address"
	}
	return ""
}

func configAsksFor(cfg ikev2.Configuration, wanted ...uint16) bool {
	for _, attr := range cfg.Attributes {
		for _, w := range wanted {
			if attr.Type == w {
				return true
			}
		}
	}
	return false
}

// childPayloads builds the CFG_REPLY, SA and traffic selectors of a successful
// final response.
//
// The reply answers what was asked for rather than returning a fixed list. A
// fixture that always handed back an IPv4 address would let an IPv6-only
// request "succeed" with an address of the wrong family, which is the shape of
// bug this card is trying to find, not one it should be able to hide.
func (a *epdgAuth) childPayloads() ([]ikev2.Payload, error) {
	sa, err := ikev2.SecurityAssociationPayload(ikev2.DefaultESPProposal(a.espSPI))
	if err != nil {
		return nil, err
	}
	selectors := ikev2.IPv4AnyTrafficSelectors()
	if len(a.observedTSi.Selectors) > 0 && a.observedTSi.Selectors[0].Type == ikev2.TSIPv6AddressRange {
		selectors = IPv6AnyTrafficSelectors()
	}
	tsi, err := ikev2.TrafficSelectorsPayload(ikev2.PayloadTSi, selectors)
	if err != nil {
		return nil, err
	}
	tsr, err := ikev2.TrafficSelectorsPayload(ikev2.PayloadTSr, selectors)
	if err != nil {
		return nil, err
	}
	// No CFG_REPLY when nothing was asked for. RFC 7296 section 2.19 has the
	// reply answer a request, and a fixture that volunteered an address anyway
	// would make the "CHILD_SA came up without a CP" branch of T088's
	// experiment untestable: the tunnel would appear to have an internal
	// address it was never granted, and LiveResult.TunnelIsUp - the one
	// predicate criterion 4 is measured with - would go true on it.
	payloads := make([]ikev2.Payload, 0, 4)
	if a.sawCP {
		cfg, err := ikev2.ConfigurationPayload(a.configReply())
		if err != nil {
			return nil, err
		}
		payloads = append(payloads, cfg)
	}
	return append(payloads, sa, tsi, tsr), nil
}

func (a *epdgAuth) configReply() ikev2.Configuration {
	out := ikev2.Configuration{Type: ikev2.CFGReply}
	if configAsksFor(a.observedConfig, ikev2.ConfigInternalIPv4Address) {
		out.Attributes = append(out.Attributes,
			ikev2.ConfigurationAttribute{Type: ikev2.ConfigInternalIPv4Address, Value: []byte{10, 64, 0, 7}},
			ikev2.ConfigurationAttribute{Type: ikev2.ConfigInternalIPv4DNS, Value: []byte{10, 64, 0, 1}},
		)
	}
	if configAsksFor(a.observedConfig, ikev2.ConfigInternalIPv6Address) {
		value := append(append([]byte(nil), net.ParseIP("2607:fc20:1:100::7").To16()...), 64)
		out.Attributes = append(out.Attributes,
			ikev2.ConfigurationAttribute{Type: ikev2.ConfigInternalIPv6Address, Value: value},
			ikev2.ConfigurationAttribute{
				Type:  ikev2.ConfigInternalIPv6DNS,
				Value: append([]byte(nil), net.ParseIP("2607:fc20:1:100::1").To16()...),
			},
		)
	}
	if configAsksFor(a.observedConfig, ConfigPCSCFIPv4Address) {
		out.Attributes = append(out.Attributes, ikev2.ConfigurationAttribute{
			Type: ConfigPCSCFIPv4Address, Value: append([]byte(nil), a.pcscfIPv4.To4()...),
		})
	}
	if configAsksFor(a.observedConfig, ConfigPCSCFIPv6Address) {
		out.Attributes = append(out.Attributes, ikev2.ConfigurationAttribute{
			Type: ConfigPCSCFIPv6Address, Value: append([]byte(nil), a.pcscfIPv6.To16()...),
		})
	}
	return out
}

// buildChallenge issues an EAP-Request/AKA-Challenge with a real AT_MAC.
func (a *epdgAuth) buildChallenge() (eapaka.Packet, error) {
	randValue := make([]byte, eapaka.RANDLength)
	autn := make([]byte, eapaka.AUTNLength)
	if _, err := rand.Read(randValue); err != nil {
		return eapaka.Packet{}, err
	}
	if _, err := rand.Read(autn); err != nil {
		return eapaka.Packet{}, err
	}
	a.challenges++
	a.currentRAND = randValue
	a.currentAUTN = autn
	a.identifier++

	identity := a.eapIdentity
	if identity == "" {
		return eapaka.Packet{}, fmt.Errorf("no EAP identity known, cannot derive K_aut for AT_MAC")
	}
	keys, err := eapaka.DeriveKeys(identity, usimVector(a.k, randValue, autn))
	if err != nil {
		return eapaka.Packet{}, err
	}
	packet := eapaka.Packet{
		Code:       eapaka.CodeRequest,
		Identifier: a.identifier,
		Type:       eapaka.TypeAKA,
		Subtype:    eapaka.SubtypeChallenge,
		Attributes: []eapaka.Attribute{
			eapaka.RANDAttribute(randValue),
			eapaka.AUTNAttribute(autn),
			eapaka.MACAttribute(nil),
		},
	}
	raw, err := packet.MarshalBinary()
	if err != nil {
		return eapaka.Packet{}, err
	}
	mac, err := eapaka.CalculateMAC(keys.KAut, raw, nil)
	if err != nil {
		return eapaka.Packet{}, err
	}
	packet.Attributes[len(packet.Attributes)-1] = eapaka.MACAttribute(mac)
	return packet, nil
}

// verifyChallengeResponse checks AT_RES against what the AuC expects and AT_MAC
// against K_aut, then keeps the MSK for the AUTH round.
func (a *epdgAuth) verifyChallengeResponse(packet eapaka.Packet, raw []byte) error {
	if a.eapIdentity == "" {
		return fmt.Errorf("challenge response arrived with no identity on record")
	}
	vector := usimVector(a.k, a.currentRAND, a.currentAUTN)
	keys, err := eapaka.DeriveKeys(a.eapIdentity, vector)
	if err != nil {
		return err
	}
	if err := eapaka.VerifyMAC(keys.KAut, raw, nil); err != nil {
		return fmt.Errorf("AT_MAC on the challenge response: %w", err)
	}
	attr, ok := eapaka.FindAttribute(packet.Attributes, eapaka.AttributeRES)
	if !ok {
		return fmt.Errorf("EAP-Response/AKA-Challenge has no AT_RES")
	}
	res, bits, err := attr.RESValue()
	if err != nil {
		return err
	}
	if int(bits) != len(vector.RES)*8 {
		return fmt.Errorf("AT_RES claims %d bits over %d octets", bits, len(res))
	}
	if !hmac.Equal(res, vector.RES) {
		return fmt.Errorf("AT_RES does not match the expected RES")
	}
	a.eapKeys = keys
	return nil
}

func (f *fakeEPDG) logStage(messageID uint32, stage authStage) {
	stage.MessageID = messageID
	f.authMessageLog = append(f.authMessageLog, stage)
}

// protectLocked encrypts one response. The caller holds f.mu.
func (f *fakeEPDG) protectLocked(req ikev2.Message, payloads []ikev2.Payload) ([]byte, error) {
	header := ikev2.Header{
		InitiatorSPI: req.Header.InitiatorSPI,
		ResponderSPI: f.responderSPI,
		ExchangeType: ikev2.ExchangeIKE_AUTH,
		Flags:        ikev2.FlagResponse,
		MessageID:    req.Header.MessageID,
	}
	_, raw, err := ikev2.ProtectMessage(header, f.ikeKeys, false, payloads, nil)
	return raw, err
}

// epdgHMAC and epdgSharedKeyAuth are the fixture's own implementation of
// RFC 7296 section 2.15.
//
// They deliberately do not call ikev2.PRF or ike.SharedKeyAuth. There is only
// one HMAC in the standard library so the primitive is necessarily shared, but
// the composition - which is where a wrong AUTH actually comes from: the order
// of the three concatenated pieces, the key-pad step, whether the ID payload
// header is included - is written out separately here. The two only agree if
// that composition is right on both sides. auth_payloads_test.go goes one step
// further and re-derives HMAC itself from RFC 2104.
func epdgHMAC(h crypto.Hash, key, data []byte) []byte {
	mac := hmac.New(h.New, key)
	_, _ = mac.Write(data)
	return mac.Sum(nil)
}

func epdgSharedKeyAuth(h crypto.Hash, secret, signedOctets []byte) []byte {
	return epdgHMAC(h, epdgHMAC(h, secret, []byte("Key Pad for IKEv2")), signedOctets)
}

func concatBytes(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
