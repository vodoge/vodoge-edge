package ike

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

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
		return f.handleInit(msg)
	case ikev2.ExchangeIKE_AUTH:
		return f.handleAuth(msg)
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

func (f *fakeEPDG) handleInit(msg ikev2.Message) ([]byte, error) {
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
	if _, err := peer.ComputeSharedSecret(ke.KeyData); err != nil {
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
	return f.respond(msg, payloads)
}

// handleAuth models the IKE_AUTH ladder at the message-sequencing level only.
//
// T041a has no SK encryption yet (that is T041b), so these payloads travel in
// clear. What is being asserted here is not cryptography, it is the shape of the
// conversation: EAP-Request rounds, then an IKE_AUTH response whose only EAP
// payload is EAP-Success, and then a *separate* exchange carrying AUTH plus the
// CHILD_SA. Any code that assumes the last two share a message fails against
// this fixture.
func (f *fakeEPDG) handleAuth(msg ikev2.Message) ([]byte, error) {
	f.mu.Lock()
	ladder := f.authLadder
	f.mu.Unlock()
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
