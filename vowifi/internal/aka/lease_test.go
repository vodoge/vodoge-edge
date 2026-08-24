package aka

import (
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
)

// The synthetic pair T047 used on the bench, so the fixtures and the hardware
// evidence in the receipt are talking about the same challenge.
var (
	testRAND = mustHex("000102030405060708090A0B0C0D0E0F")
	testAUTN = mustHex("101112131415161718191A1B1C1D1E1F")
)

func mustHex(s string) []byte {
	raw, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return raw
}

// fakeLease is the daemon side of the lease protocol: one JSON request per
// line, one JSON answer per line, one connection per call.
//
// It records the raw request lines rather than a parsed summary, because one of
// the things being asserted is that a forbidden operation never appears on the
// wire, and a parsed summary could quietly normalise it away.
type fakeLease struct {
	t *testing.T

	mu       sync.Mutex
	raw      []string
	handler  func(call int, request map[string]any) (answer string, stall time.Duration)
	calls    int
	shutdown chan struct{}
}

func newFakeLease(t *testing.T, handler func(int, map[string]any) (string, time.Duration)) *fakeLease {
	t.Helper()
	f := &fakeLease{t: t, handler: handler, shutdown: make(chan struct{})}
	t.Cleanup(func() { close(f.shutdown) })
	return f
}

func (f *fakeLease) dial(context.Context, string) (net.Conn, error) {
	client, server := net.Pipe()
	go f.serve(server)
	return client, nil
}

func (f *fakeLease) serve(conn net.Conn) {
	defer conn.Close()
	line, err := readLine(conn)
	if err != nil {
		return
	}
	var request map[string]any
	_ = json.Unmarshal([]byte(line), &request)
	f.mu.Lock()
	f.raw = append(f.raw, line)
	f.calls++
	call := f.calls
	f.mu.Unlock()

	answer, stall := f.handler(call, request)
	if stall > 0 {
		select {
		case <-time.After(stall):
		case <-f.shutdown:
			return
		}
	}
	_, _ = conn.Write([]byte(answer + "\n"))
}

func (f *fakeLease) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.raw...)
}

func (f *fakeLease) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// answers the daemon really produces, byte for byte in shape with at.rs
// outcome_json and failure_json.
const (
	answerSuccess = `{"ok":true,"op":"authenticate","outcome":"success",` +
		`"res":"1122334455667788","ck":"000102030405060708090A0B0C0D0E0F",` +
		`"ik":"F0E0D0C0B0A090807060504030201000","kc":"0011223344556677"}`
	answerAuthFailure = `{"ok":true,"op":"authenticate","outcome":"authentication_failure",` +
		`"sw":"9862","detail":"card rejected the challenge: incorrect MAC (SW 9862)"}`
	answerSyncFailure = `{"ok":true,"op":"authenticate","outcome":"sync_failure",` +
		`"auts":"A0A1A2A3A4A5A6A7A8A9AAABACAD"}`
	answerTransportFailure = `{"ok":false,"error":"at_transport_failed",` +
		`"message":"AT transport: timed out after 10s"}`
	answerStatusRefused = `{"ok":false,"error":"status_refused",` +
		`"message":"card refused STATUS with SW 6E00, so the selected application is unknown"}`
)

func staticLease(t *testing.T, answer string) *fakeLease {
	return newFakeLease(t, func(int, map[string]any) (string, time.Duration) {
		return answer, 0
	})
}

func TestProviderMapsSuccessToRESCKIK(t *testing.T) {
	f := staticLease(t, answerSuccess)
	p := &Provider{IMEI: "867018069514820", Dial: f.dial, Timeout: 2 * time.Second}

	result, err := p.CalculateAKA(testRAND, testAUTN)
	if err != nil {
		t.Fatalf("CalculateAKA: %v", err)
	}
	if got := hex.EncodeToString(result.RES); got != "1122334455667788" {
		t.Fatalf("RES = %s", got)
	}
	if len(result.CK) != 16 || len(result.IK) != 16 {
		t.Fatalf("CK %d octets, IK %d octets", len(result.CK), len(result.IK))
	}
	if len(result.AUTS) != 0 {
		t.Fatalf("a success carried AUTS: %x", result.AUTS)
	}
}

// TestProviderMapsTheBenchRefusalToErrAuthFailure is the mapping the whole card
// turns on: 9862 from a real USIM has to become the error eapaka converts into
// an EAP-Response/AKA-Authentication-Reject, and it has to keep the raw status
// word so a receipt can quote it.
func TestProviderMapsTheBenchRefusalToErrAuthFailure(t *testing.T) {
	f := staticLease(t, answerAuthFailure)
	var seen []Observation
	p := &Provider{
		IMEI:    "867018069514820",
		Dial:    f.dial,
		Timeout: 2 * time.Second,
		Observe: func(o Observation) { seen = append(seen, o) },
	}

	_, err := p.CalculateAKA(testRAND, testAUTN)
	if !errors.Is(err, sim.ErrAuthFailure) {
		t.Fatalf("error = %v, want sim.ErrAuthFailure", err)
	}
	if errors.Is(err, sim.ErrSyncFailure) {
		t.Fatalf("a refusal must not also look like a resynchronisation: %v", err)
	}
	if !strings.Contains(err.Error(), "9862") {
		t.Fatalf("the raw status word is missing from %q", err)
	}
	if len(seen) != 1 || seen[0].StatusWord != "9862" || seen[0].Outcome != "authentication_failure" {
		t.Fatalf("observations = %+v", seen)
	}

	// The point of that mapping: eapaka builds the reject without further help.
	response, handled, buildErr := eapaka.BuildAKAFailureResponse(challengeRequest(), sim.AKAResult{}, err)
	if buildErr != nil || !handled {
		t.Fatalf("BuildAKAFailureResponse handled=%v err=%v", handled, buildErr)
	}
	if response.Subtype != eapaka.SubtypeAuthenticationReject {
		t.Fatalf("subtype = %d, want AuthenticationReject", response.Subtype)
	}
}

func TestProviderMapsSyncFailureOntoTheAUTSCarrier(t *testing.T) {
	f := staticLease(t, answerSyncFailure)
	p := &Provider{Dial: f.dial, Timeout: 2 * time.Second}

	result, err := p.CalculateAKA(testRAND, testAUTN)
	if !errors.Is(err, sim.ErrSyncFailure) {
		t.Fatalf("error = %v, want sim.ErrSyncFailure", err)
	}
	if len(result.AUTS) != 0 {
		t.Fatalf("AUTS must ride on the error, not the result: %x", result.AUTS)
	}
	response, handled, buildErr := eapaka.BuildAKAFailureResponse(challengeRequest(), result, err)
	if buildErr != nil || !handled {
		t.Fatalf("BuildAKAFailureResponse handled=%v err=%v", handled, buildErr)
	}
	if response.Subtype != eapaka.SubtypeSynchronizationFailure {
		t.Fatalf("subtype = %d, want SynchronizationFailure", response.Subtype)
	}
	attr, ok := eapaka.FindAttribute(response.Attributes, eapaka.AttributeAUTS)
	if !ok {
		t.Fatalf("no AT_AUTS in the response")
	}
	want := mustHex("A0A1A2A3A4A5A6A7A8A9AAABACAD")
	if !strings.Contains(hex.EncodeToString(attr.Data), hex.EncodeToString(want)) {
		t.Fatalf("AT_AUTS = %x, want it to carry %x", attr.Data, want)
	}
}

// TestProviderNeverForgesACardRefusal is the safety half of the mapping. A
// broken pipe, a refused STATUS, an unknown status word: none of those is the
// card rejecting a challenge, and turning any of them into sim.ErrAuthFailure
// would put an EAP-Response on the wire that the card never authorised.
func TestProviderNeverForgesACardRefusal(t *testing.T) {
	for _, answer := range []string{answerTransportFailure, answerStatusRefused} {
		f := staticLease(t, answer)
		p := &Provider{Dial: f.dial, Timeout: 2 * time.Second}
		_, err := p.CalculateAKA(testRAND, testAUTN)
		if !errors.Is(err, ErrLeaseRefused) {
			t.Fatalf("%s -> %v, want ErrLeaseRefused", answer, err)
		}
		if errors.Is(err, sim.ErrAuthFailure) || errors.Is(err, sim.ErrSyncFailure) {
			t.Fatalf("%s was turned into a card verdict: %v", answer, err)
		}
		_, handled, buildErr := eapaka.BuildAKAFailureResponse(challengeRequest(), sim.AKAResult{}, err)
		if handled {
			t.Fatalf("eapaka built an EAP response out of %q", answer)
		}
		if !errors.Is(buildErr, ErrLeaseRefused) {
			t.Fatalf("the cause did not survive: %v", buildErr)
		}
	}
}

func TestProviderRefusesAnUnknownOutcome(t *testing.T) {
	f := staticLease(t, `{"ok":true,"op":"authenticate","outcome":"probably_fine"}`)
	p := &Provider{Dial: f.dial, Timeout: 2 * time.Second}
	if _, err := p.CalculateAKA(testRAND, testAUTN); !errors.Is(err, ErrLeaseProtocol) {
		t.Fatalf("error = %v, want ErrLeaseProtocol", err)
	}
}

func TestProviderRejectsAMalformedChallengeBeforeDialling(t *testing.T) {
	f := staticLease(t, answerSuccess)
	p := &Provider{Dial: f.dial, Timeout: 2 * time.Second}
	if _, err := p.CalculateAKA(testRAND[:15], testAUTN); !errors.Is(err, ErrBadChallenge) {
		t.Fatalf("error = %v, want ErrBadChallenge", err)
	}
	if f.count() != 0 {
		t.Fatalf("a malformed challenge reached the daemon %d time(s)", f.count())
	}
}

// TestProviderStopsWaitingAtItsDeadline is the core of T041c: the interface
// being implemented cannot be cancelled, so the bound has to come from here.
//
// It also pins "no silent retry": one call, one request line. A retry would
// pile a second AUTHENTICATE onto a port that is already stuck, and an
// AUTHENTICATE the card accepts advances SQN.
func TestProviderStopsWaitingAtItsDeadline(t *testing.T) {
	f := newFakeLease(t, func(int, map[string]any) (string, time.Duration) {
		return answerSuccess, time.Hour
	})
	late := make(chan Observation, 4)
	p := &Provider{
		Dial:    f.dial,
		Timeout: 150 * time.Millisecond,
		Grace:   150 * time.Millisecond,
		Observe: func(o Observation) {
			if o.Late {
				late <- o
			}
		},
	}

	started := time.Now()
	_, err := p.CalculateAKA(testRAND, testAUTN)
	elapsed := time.Since(started)
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("error = %v, want ErrTimeout", err)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("the bound did not hold: %s", elapsed)
	}
	if f.count() != 1 {
		t.Fatalf("%d request(s) sent; a timeout must not retry", f.count())
	}
	// The reaper gives up too, rather than leaking.
	select {
	case o := <-late:
		if !errors.Is(o.Err, ErrTimeout) {
			t.Fatalf("late observation = %+v", o)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("the reaper never reported")
	}
}

// TestProviderCannotAnswerOneChallengeWithAnother is the ghost-fault test.
//
// A connection reused across calls would put the abandoned answer at the head of
// the stream, and the next challenge would be answered with the previous
// challenge's result - a tunnel that comes up on the wrong keys and looks like a
// carrier problem. One connection per call makes that physically impossible, and
// this asserts it end to end: the abandoned call really does get answered late,
// and the next call still gets its own answer.
func TestProviderCannotAnswerOneChallengeWithAnother(t *testing.T) {
	f := newFakeLease(t, func(call int, _ map[string]any) (string, time.Duration) {
		if call == 1 {
			return answerSuccess, 300 * time.Millisecond
		}
		return answerAuthFailure, 0
	})
	late := make(chan Observation, 4)
	p := &Provider{
		Dial:    f.dial,
		Timeout: 100 * time.Millisecond,
		Grace:   5 * time.Second,
		Observe: func(o Observation) {
			if o.Late {
				late <- o
			}
		},
	}

	if _, err := p.CalculateAKA(testRAND, testAUTN); !errors.Is(err, ErrTimeout) {
		t.Fatalf("first call = %v, want ErrTimeout", err)
	}
	result, err := p.CalculateAKA(testRAND, testAUTN)
	if !errors.Is(err, sim.ErrAuthFailure) {
		t.Fatalf("second call = %v (result %+v), want the refusal that belongs to it", err, result)
	}
	if len(result.RES) != 0 {
		t.Fatalf("the second call inherited the first call's keys: %x", result.RES)
	}
	select {
	case o := <-late:
		if o.Outcome != "success" || o.Err != nil {
			t.Fatalf("late observation = %+v", o)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("the abandoned answer was never collected")
	}
}

// TestProviderRefusesToOversubscribeTheLease covers the second half of "what
// does the next challenge meet". The daemon accepts MAX_LEASE_CLIENTS = 8
// connections and its acquire() has no timeout, so abandoned challenges hold
// their slot until the module frees up. Piling on would exhaust the daemon for
// the console too, and the symptom - too_many_clients - reads like the daemon is
// broken rather than like the port is stuck.
func TestProviderRefusesToOversubscribeTheLease(t *testing.T) {
	f := newFakeLease(t, func(int, map[string]any) (string, time.Duration) {
		return answerSuccess, time.Hour
	})
	p := &Provider{
		Dial:        f.dial,
		Timeout:     120 * time.Millisecond,
		Grace:       10 * time.Second,
		MaxInFlight: 1,
	}

	if _, err := p.CalculateAKA(testRAND, testAUTN); !errors.Is(err, ErrTimeout) {
		t.Fatalf("first call = %v, want ErrTimeout", err)
	}
	started := time.Now()
	_, err := p.CalculateAKA(testRAND, testAUTN)
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("second call = %v, want ErrBusy", err)
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("ErrBusy took %s; it is supposed to be bounded too", elapsed)
	}
	if errors.Is(err, sim.ErrAuthFailure) || errors.Is(err, sim.ErrSyncFailure) {
		t.Fatalf("a busy lease was reported as a card verdict: %v", err)
	}
	if f.count() != 1 {
		t.Fatalf("%d request(s) reached the daemon, want 1", f.count())
	}
}

// TestProviderOnlyEverSendsAuthenticate is the security boundary as a test.
//
// The lease also speaks execute_at, which runs any AT command and is therefore
// full control of the module - USB composition, messaging, profile switching.
// This package must never reach for it, and "must never" is worth an assertion
// rather than a comment, because the day somebody adds a convenience helper the
// grep that would have caught it is not going to be run.
func TestProviderOnlyEverSendsAuthenticate(t *testing.T) {
	f := newFakeLease(t, func(call int, _ map[string]any) (string, time.Duration) {
		switch call {
		case 1:
			return answerSuccess, 0
		case 2:
			return answerAuthFailure, 0
		case 3:
			return answerSyncFailure, 0
		default:
			return answerTransportFailure, 0
		}
	})
	p := &Provider{IMEI: "867018069514820", Dial: f.dial, Timeout: 2 * time.Second}
	for i := 0; i < 4; i++ {
		_, _ = p.CalculateAKA(testRAND, testAUTN)
	}

	lines := f.requests()
	if len(lines) != 4 {
		t.Fatalf("%d request lines, want 4", len(lines))
	}
	for _, line := range lines {
		if strings.Contains(line, "execute_at") || strings.Contains(line, "command") {
			t.Fatalf("a forbidden operation appeared on the wire: %s", line)
		}
		var request map[string]any
		if err := json.Unmarshal([]byte(line), &request); err != nil {
			t.Fatalf("request %q: %v", line, err)
		}
		if request["op"] != opAuthenticate {
			t.Fatalf("op = %v in %s", request["op"], line)
		}
		if request["imei"] != "867018069514820" {
			t.Fatalf("imei = %v in %s", request["imei"], line)
		}
		for key := range request {
			switch key {
			case "op", "imei", "rand", "autn":
			default:
				t.Fatalf("unexpected field %q in %s", key, line)
			}
		}
	}
}

func TestProviderOmitsAnEmptyIMEI(t *testing.T) {
	f := staticLease(t, answerSuccess)
	p := &Provider{Dial: f.dial, Timeout: 2 * time.Second}
	if _, err := p.CalculateAKA(testRAND, testAUTN); err != nil {
		t.Fatalf("CalculateAKA: %v", err)
	}
	if line := f.requests()[0]; strings.Contains(line, "imei") {
		t.Fatalf("an empty IMEI was sent anyway: %s", line)
	}
}

func TestSocketPathFallsBackThroughTheEnvironment(t *testing.T) {
	p := &Provider{}
	t.Setenv(SocketPathEnv, "")
	if got := p.SocketPathOrDefault(); got != DefaultSocketPath {
		t.Fatalf("default = %q", got)
	}
	t.Setenv(SocketPathEnv, "/tmp/other.sock")
	if got := p.SocketPathOrDefault(); got != "/tmp/other.sock" {
		t.Fatalf("env override = %q", got)
	}
	p.SocketPath = "/tmp/explicit.sock"
	if got := p.SocketPathOrDefault(); got != "/tmp/explicit.sock" {
		t.Fatalf("field override = %q", got)
	}
}

// TestProviderTalksOverARealUnixSocket exercises the path the edge box actually
// uses, rather than the in-memory pipe the other tests use. Skipped where the
// platform has no unix sockets; the authoritative run for this one is the edge
// machine, recorded in the receipt.
func TestProviderTalksOverARealUnixSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "aka")
	if err != nil {
		t.Skipf("no temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "s")
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
			go func() {
				defer conn.Close()
				if _, err := readLine(conn); err != nil {
					return
				}
				_, _ = conn.Write([]byte(answerAuthFailure + "\n"))
			}()
		}
	}()

	p := &Provider{SocketPath: path, Timeout: 5 * time.Second}
	if _, err := p.CalculateAKA(testRAND, testAUTN); !errors.Is(err, sim.ErrAuthFailure) {
		t.Fatalf("over a real socket: %v", err)
	}
}

func TestProviderReportsAnUnreachableSocket(t *testing.T) {
	p := &Provider{SocketPath: filepath.Join(t.TempDir(), "absent.sock"), Timeout: time.Second}
	_, err := p.CalculateAKA(testRAND, testAUTN)
	if !errors.Is(err, ErrDial) {
		t.Fatalf("error = %v, want ErrDial", err)
	}
	if errors.Is(err, sim.ErrAuthFailure) {
		t.Fatalf("an unreachable socket was reported as a card refusal: %v", err)
	}
}

func challengeRequest() eapaka.Packet {
	return eapaka.Packet{
		Code:       eapaka.CodeRequest,
		Identifier: 1,
		Type:       eapaka.TypeAKA,
		Subtype:    eapaka.SubtypeChallenge,
	}
}
