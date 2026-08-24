package ike

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/boa-z/vowifi-go/engine/sim"
	"github.com/boa-z/vowifi-go/engine/swu/eapaka"

	"github.com/yuanshuai1122/vodoge-edge/vowifi/internal/aka"
	"github.com/yuanshuai1122/vodoge-edge/vowifi/internal/capture"
)

// TestAKADeadlineStopsWaiting is the seam T041c needs.
//
// sim.AKAProvider.CalculateAKA has no context (engine/sim/sim.go:116-118), so
// without this wrapper an IKE exchange blocks for as long as the card bridge
// takes - and the Rust arbiter behind that bridge is bounded at 300 seconds or
// not at all until T058 lands. The ePDG has given up long before then.
func TestAKADeadlineStopsWaiting(t *testing.T) {
	slow := newTestAKAProvider()
	slow.delay = 3 * time.Second

	guarded := WithAKADeadline(context.Background(), slow, 100*time.Millisecond)
	started := time.Now()
	_, err := guarded.CalculateAKA(make([]byte, 16), make([]byte, 16))
	elapsed := time.Since(started)

	if !errors.Is(err, ErrAKADeadlineExceeded) {
		t.Fatalf("err = %v, want ErrAKADeadlineExceeded", err)
	}
	if elapsed > time.Second {
		t.Fatalf("the deadline took %s to fire", elapsed)
	}
	// A timeout is not a synchronisation failure and must not become one:
	// eapaka.BuildChallengeResponseFromProvider only manufactures AT_AUTS for
	// sim.ErrSyncFailure, and a stalled card answering AT_AUTS would be a lie
	// to the network.
	if errors.Is(err, sim.ErrSyncFailure) || errors.Is(err, sim.ErrAuthFailure) {
		t.Fatalf("a deadline was misclassified as an AKA failure: %v", err)
	}
}

// TestAKADeadlineHonoursContextCancellation covers the other way out.
func TestAKADeadlineHonoursContextCancellation(t *testing.T) {
	slow := newTestAKAProvider()
	slow.delay = 3 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	guarded := WithAKADeadline(ctx, slow, time.Minute)
	started := time.Now()
	if _, err := guarded.CalculateAKA(make([]byte, 16), make([]byte, 16)); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("cancellation took %s", elapsed)
	}
}

// TestAKADeadlinePassesResultsThrough keeps the wrapper honest on the happy
// path, including the two error classes it must not swallow.
func TestAKADeadlinePassesResultsThrough(t *testing.T) {
	provider := newTestAKAProvider()
	guarded := WithAKADeadline(context.Background(), provider, time.Second)

	randValue := bytes.Repeat([]byte{7}, 16)
	autn := bytes.Repeat([]byte{9}, 16)
	got, err := guarded.CalculateAKA(randValue, autn)
	if err != nil {
		t.Fatalf("CalculateAKA: %v", err)
	}
	want := usimVector(testUSIMKey, randValue, autn)
	if !bytes.Equal(got.RES, want.RES) || !bytes.Equal(got.CK, want.CK) || !bytes.Equal(got.IK, want.IK) {
		t.Fatalf("the wrapper altered the card's answer")
	}

	provider.syncFailOn[2] = true
	if _, err := guarded.CalculateAKA(randValue, autn); !errors.Is(err, sim.ErrSyncFailure) {
		t.Fatalf("sync failure did not survive the wrapper: %v", err)
	}
	provider.authFailOn[3] = true
	if _, err := guarded.CalculateAKA(randValue, autn); !errors.Is(err, sim.ErrAuthFailure) {
		t.Fatalf("auth failure did not survive the wrapper: %v", err)
	}
}

// TestWithAKADeadlineIsInertWhenNotAsked keeps the zero configuration cheap.
func TestWithAKADeadlineIsInertWhenNotAsked(t *testing.T) {
	provider := newTestAKAProvider()
	if got := WithAKADeadline(nil, provider, 0); got != sim.AKAProvider(provider) {
		t.Fatalf("WithAKADeadline wrapped a provider with no deadline and no context")
	}
	if got := WithAKADeadline(context.Background(), nil, time.Second); got != nil {
		t.Fatalf("WithAKADeadline wrapped a nil provider")
	}
}

// TestEAPIdentitySelectionFollowsRFC4187 pins the identity choice. Getting it
// wrong means deriving the master key from a different string than the network
// used, which shows up only as an AT_MAC mismatch at the far end.
func TestEAPIdentitySelectionFollowsRFC4187(t *testing.T) {
	const permanent = "0perm@nai"
	const pseudonym = "pseudo@nai"
	const reauth = "reauth@nai"

	request := func(attrs ...eapaka.Attribute) eapaka.Packet {
		return eapaka.Packet{
			Code:       eapaka.CodeRequest,
			Identifier: 1,
			Type:       eapaka.TypeAKA,
			Subtype:    eapaka.SubtypeIdentity,
			Attributes: attrs,
		}
	}
	cases := map[string]struct {
		packet eapaka.Packet
		want   string
	}{
		"AT_PERMANENT_ID_REQ": {request(eapaka.PermanentIDReqAttribute()), permanent},
		"AT_FULLAUTH_ID_REQ":  {request(eapaka.FullAuthIDReqAttribute()), pseudonym},
		"AT_ANY_ID_REQ":       {request(eapaka.AnyIDReqAttribute()), reauth},
		"no hint":             {request(), permanent},
	}
	for name, tc := range cases {
		if got := eapIdentityFor(tc.packet, permanent, pseudonym, reauth); got != tc.want {
			t.Errorf("%s: identity = %q, want %q", name, got, tc.want)
		}
	}
	// With nothing else configured every hint falls back to the permanent NAI.
	if got := eapIdentityFor(request(eapaka.AnyIDReqAttribute()), permanent, "", ""); got != permanent {
		t.Errorf("fallback identity = %q, want %q", got, permanent)
	}
}

// TestEAPDriverAnswersAnIdentityRequestAndBuildsTheTranscript covers the
// checkcode input, which is the identity round trip in wire order
// (RFC 4187 section 10.13).
func TestEAPDriverAnswersAnIdentityRequestAndBuildsTheTranscript(t *testing.T) {
	driver := &EAPDriver{PermanentIdentity: testEAPIdentity, Provider: newTestAKAProvider()}
	request := eapaka.Packet{
		Code:       eapaka.CodeRequest,
		Identifier: 17,
		Type:       eapaka.TypeAKA,
		Subtype:    eapaka.SubtypeIdentity,
		Attributes: []eapaka.Attribute{eapaka.PermanentIDReqAttribute()},
	}
	raw, err := request.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	step, err := driver.Respond(request, raw)
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}
	if step.Response.Code != eapaka.CodeResponse || step.Response.Subtype != eapaka.SubtypeIdentity {
		t.Fatalf("response is code %d subtype %d", step.Response.Code, step.Response.Subtype)
	}
	if step.Response.Identifier != request.Identifier {
		t.Fatalf("EAP identifier %d does not echo the request's %d", step.Response.Identifier, request.Identifier)
	}
	if step.Identity != testEAPIdentity || driver.Identity() != testEAPIdentity {
		t.Fatalf("identity = %q", step.Identity)
	}
	transcript := driver.Transcript()
	if len(transcript) != 2 || !bytes.Equal(transcript[0], raw) || !bytes.Equal(transcript[1], step.Raw) {
		t.Fatalf("transcript is not [request, response]: %d entries", len(transcript))
	}
}

// TestEAPDriverRefusesAnEAPResponse guards the state machine against being fed
// its own output.
func TestEAPDriverRefusesAnEAPResponse(t *testing.T) {
	driver := &EAPDriver{PermanentIdentity: testEAPIdentity}
	_, err := driver.Respond(eapaka.Packet{Code: eapaka.CodeResponse, Subtype: eapaka.SubtypeIdentity}, nil)
	if !errors.Is(err, ErrEAPUnexpected) {
		t.Fatalf("err = %v, want ErrEAPUnexpected", err)
	}
}

// TestEAPDriverNeedsAProviderForAChallenge: a challenge with nothing to answer
// it must be a named error, not a nil dereference at 3am.
func TestEAPDriverNeedsAProviderForAChallenge(t *testing.T) {
	driver := &EAPDriver{PermanentIdentity: testEAPIdentity}
	challenge := eapaka.Packet{
		Code:       eapaka.CodeRequest,
		Identifier: 3,
		Type:       eapaka.TypeAKA,
		Subtype:    eapaka.SubtypeChallenge,
		Attributes: []eapaka.Attribute{
			eapaka.RANDAttribute(bytes.Repeat([]byte{1}, 16)),
			eapaka.AUTNAttribute(bytes.Repeat([]byte{2}, 16)),
			eapaka.MACAttribute(nil),
		},
	}
	if _, err := driver.Respond(challenge, nil); !errors.Is(err, ErrNoAKAProvider) {
		t.Fatalf("err = %v, want ErrNoAKAProvider", err)
	}
}

// TestRecordedAKAProviderReproducesBothOutcomes is what makes an offline replay
// of a failed ladder possible. A recording that turned AT_AUTS into a success
// would erase the behaviour being debugged.
func TestRecordedAKAProviderReproducesBothOutcomes(t *testing.T) {
	randA := bytes.Repeat([]byte{0x11}, 16)
	autnA := bytes.Repeat([]byte{0x22}, 16)
	randB := bytes.Repeat([]byte{0x33}, 16)
	autnB := bytes.Repeat([]byte{0x44}, 16)
	randC := bytes.Repeat([]byte{0x55}, 16)
	autnC := bytes.Repeat([]byte{0x66}, 16)
	auts := bytes.Repeat([]byte{0x77}, 14)

	provider := NewRecordedAKAProvider([]capture.AKAVector{
		{RAND: randA, AUTN: autnA, RES: []byte("12345678"), CK: bytes.Repeat([]byte{1}, 16), IK: bytes.Repeat([]byte{2}, 16)},
		{RAND: randB, AUTN: autnB, AUTS: auts, Failure: capture.AKAFailureSync},
		{RAND: randC, AUTN: autnC, Failure: capture.AKAFailureAuth},
	})

	if got, err := provider.CalculateAKA(randA, autnA); err != nil || string(got.RES) != "12345678" {
		t.Fatalf("success vector: %v %q", err, got.RES)
	}
	got, err := provider.CalculateAKA(randB, autnB)
	if !errors.Is(err, sim.ErrSyncFailure) {
		t.Fatalf("sync vector: err = %v", err)
	}
	if !bytes.Equal(got.AUTS, auts) {
		t.Fatalf("sync vector lost AUTS")
	}
	var carrier interface{ AUTS() []byte }
	if !errors.As(err, &carrier) || !bytes.Equal(carrier.AUTS(), auts) {
		t.Fatalf("the replayed sync failure does not carry AUTS on the error")
	}
	if _, err := provider.CalculateAKA(randC, autnC); !errors.Is(err, sim.ErrAuthFailure) {
		t.Fatalf("auth vector: err = %v", err)
	}
	// Order must not matter: a resynchronised challenge repeats the exchange.
	if _, err := provider.CalculateAKA(randA, autnA); err != nil {
		t.Fatalf("re-reading a vector failed: %v", err)
	}
	if _, err := provider.CalculateAKA(bytes.Repeat([]byte{0xff}, 16), autnA); !errors.Is(err, ErrRecordedAKAMiss) {
		t.Fatalf("an unrecorded challenge was answered")
	}
}

// TestRecordingAKAProviderClassifiesFailures checks the recorder writes down
// enough to replay a failure, including AUTS carried only on the error.
func TestRecordingAKAProviderClassifiesFailures(t *testing.T) {
	inner := newTestAKAProvider()
	inner.syncFailOn[2] = true
	inner.authFailOn[3] = true
	recorder := &RecordingAKAProvider{Inner: inner}

	randValue := bytes.Repeat([]byte{5}, 16)
	autn := bytes.Repeat([]byte{6}, 16)
	for i := 0; i < 3; i++ {
		_, _ = recorder.CalculateAKA(randValue, autn)
	}
	vectors := recorder.Vectors()
	if len(vectors) != 3 {
		t.Fatalf("%d vectors recorded", len(vectors))
	}
	if vectors[0].Failure != "" || len(vectors[0].RES) == 0 {
		t.Fatalf("the successful call was not recorded properly: %+v", vectors[0])
	}
	if vectors[1].Failure != capture.AKAFailureSync {
		t.Fatalf("sync failure recorded as %q", vectors[1].Failure)
	}
	if !bytes.Equal(vectors[1].AUTS, inner.auts) {
		t.Fatalf("AUTS was not lifted off the error: %x", vectors[1].AUTS)
	}
	if vectors[2].Failure != capture.AKAFailureAuth {
		t.Fatalf("auth failure recorded as %q", vectors[2].Failure)
	}
}

// startFakeLeaseDaemon serves the AT lease protocol over a real unix socket.
//
// It is the daemon's side of the wire, not the bridge's: one JSON request per
// line, one JSON answer per line, the answer shapes at.rs outcome_json produces.
// Using a real socket rather than an in-memory pipe means the transport under
// test here is the transport the edge box uses.
//
// The stand-in card secret is the fixture's testUSIMKey, the same one the fake
// ePDG holds, so a success really does have to travel RAND/AUTN out and
// RES/CK/IK back across the socket for the ladder to complete.
func startFakeLeaseDaemon(t *testing.T, refuse bool) (*aka.Provider, func() int) {
	t.Helper()
	dir, err := os.MkdirTemp("", "lease")
	if err != nil {
		t.Skipf("no temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "at-lease.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("unix sockets unavailable here: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	var mu sync.Mutex
	calls := 0
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				reader := bufio.NewReader(conn)
				line, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				var request struct {
					Op   string `json:"op"`
					RAND string `json:"rand"`
					AUTN string `json:"autn"`
				}
				if err := json.Unmarshal([]byte(line), &request); err != nil {
					return
				}
				mu.Lock()
				calls++
				mu.Unlock()
				// The daemon only ever gets asked to authenticate.
				if request.Op != "authenticate" {
					_, _ = conn.Write([]byte(`{"ok":false,"error":"bad_request","message":"unexpected op"}` + "\n"))
					return
				}
				if refuse {
					_, _ = conn.Write([]byte(`{"ok":true,"op":"authenticate",` +
						`"outcome":"authentication_failure","sw":"9862",` +
						`"detail":"card rejected the challenge: incorrect MAC (SW 9862)"}` + "\n"))
					return
				}
				randBytes, err1 := hex.DecodeString(request.RAND)
				autnBytes, err2 := hex.DecodeString(request.AUTN)
				if err1 != nil || err2 != nil {
					_, _ = conn.Write([]byte(`{"ok":false,"error":"bad_request","message":"not hex"}` + "\n"))
					return
				}
				vector := usimVector(testUSIMKey, randBytes, autnBytes)
				answer, _ := json.Marshal(map[string]any{
					"ok": true, "op": "authenticate", "outcome": "success",
					"res": strings.ToUpper(hex.EncodeToString(vector.RES)),
					"ck":  strings.ToUpper(hex.EncodeToString(vector.CK)),
					"ik":  strings.ToUpper(hex.EncodeToString(vector.IK)),
				})
				_, _ = conn.Write(append(answer, '\n'))
			}()
		}
	}()

	provider := &aka.Provider{SocketPath: path, IMEI: "867018069514820", Timeout: 10 * time.Second}
	return provider, func() int {
		mu.Lock()
		defer mu.Unlock()
		return calls
	}
}

// TestLadderRunsWithTheCardBehindTheLeaseSocket is the T041c acceptance test
// that does not need hardware: the whole IKE_AUTH ladder completes with the only
// source of RES/CK/IK being a socket, exactly as it will be on the edge box.
//
// It is not a substitute for the bench evidence and is not meant to be. What it
// pins is the part the bench cannot show cheaply - that the bridge is
// wire-compatible with the ladder, that the challenge really crosses the socket,
// and that the keys the AUTH payload is built from came back through it.
func TestLadderRunsWithTheCardBehindTheLeaseSocket(t *testing.T) {
	l := startLadder(t, nil, nil, nil)
	bridge, calls := startFakeLeaseDaemon(t, false)

	cfg := l.authConfig()
	cfg.SIM = bridge
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, err := l.runner.Run(ctx, cfg)
	if err != nil {
		t.Fatalf("IKE_AUTH over the lease bridge: %v", err)
	}
	if result.ChildSA == nil {
		t.Fatalf("no CHILD_SA")
	}
	if calls() != 1 {
		t.Fatalf("the lease socket was asked %d times, want 1", calls())
	}
	if l.provider.callCount() != 0 {
		t.Fatalf("the in-process test provider answered %d challenges; the socket was supposed to",
			l.provider.callCount())
	}
	if !l.epdg.clientAuthVerified {
		t.Fatalf("the ePDG did not verify the AUTH built from keys that came off the socket")
	}
}

// TestLeaseRefusalBecomesAnAuthenticationRejectOnTheWire is the bench outcome,
// end to end.
//
// 9862 is what both eUICCs on the bench answer to a synthetic AUTN (T033, T047).
// This drives that exact daemon answer through the bridge and asserts what
// reaches the network: an EAP-Response/AKA-Authentication-Reject, observed by
// the responder after decrypting it, and a named error rather than a retry.
func TestLeaseRefusalBecomesAnAuthenticationRejectOnTheWire(t *testing.T) {
	l := startLadder(t, nil, nil, nil)
	bridge, calls := startFakeLeaseDaemon(t, true)

	cfg := l.authConfig()
	cfg.SIM = bridge
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, err := l.runner.Run(ctx, cfg)
	if !errors.Is(err, ErrAKAAuthFailure) {
		t.Fatalf("err = %v, want ErrAKAAuthFailure", err)
	}
	if result.ChildSA != nil {
		t.Fatalf("a CHILD_SA came out of a card refusal")
	}
	if l.epdg.authRejects != 1 {
		t.Fatalf("the ePDG saw %d Authentication-Reject packets, want 1", l.epdg.authRejects)
	}
	if l.epdg.syncFailures != 0 {
		t.Fatalf("9862 was misclassified as a resynchronisation")
	}
	if calls() != 1 {
		t.Fatalf("the lease socket was asked %d times; a refusal must not be retried", calls())
	}
}

// TestLeaseBridgeTimeoutIsNotACardVerdict closes the loop on the deadline.
//
// A stalled bridge must not look like either card answer, because eapaka turns
// those into packets: sim.ErrSyncFailure into an AT_AUTS resynchronisation and
// sim.ErrAuthFailure into a reject. Neither would be true, and both would be
// MAC-correct and therefore believed.
func TestLeaseBridgeTimeoutIsNotACardVerdict(t *testing.T) {
	dir, err := os.MkdirTemp("", "lease")
	if err != nil {
		t.Skipf("no temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "at-lease.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("unix sockets unavailable here: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			// Accept and never answer: the module is busy elsewhere.
			t.Cleanup(func() { _ = conn.Close() })
		}
	}()

	bridge := &aka.Provider{
		SocketPath: path,
		Timeout:    200 * time.Millisecond,
		Grace:      200 * time.Millisecond,
	}
	started := time.Now()
	_, err = bridge.CalculateAKA(bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 16))
	if !errors.Is(err, aka.ErrTimeout) {
		t.Fatalf("err = %v, want aka.ErrTimeout", err)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("the bound did not hold: %s", elapsed)
	}
	if errors.Is(err, sim.ErrAuthFailure) || errors.Is(err, sim.ErrSyncFailure) {
		t.Fatalf("a stall was reported as a card verdict: %v", err)
	}
	// And the wrapper above it keeps that property.
	if errors.Is(err, ErrAKADeadlineExceeded) {
		t.Fatalf("the bridge error was confused with the wrapper's: %v", err)
	}
}
