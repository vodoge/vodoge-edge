// Package aka answers EAP-AKA challenges with a real USIM.
//
// It implements the mirror's sim.AKAProvider (engine/sim/sim.go:116-118) on top
// of the edge daemon's AT lease socket, a 0600 unix socket under /run speaking
// one JSON object per line (edge-modem/src/at.rs:806-820).
//
// # This is the small half on purpose
//
// Everything that is a statement about smart cards already lives on the Rust
// side, in edge-modem/src/aka.rs, and was measured on the bench by T047: the
// FCP tag-84 gate that refuses to AUTHENTICATE against whatever else might be
// selected, the basic-channel command APDU 00 88 00 81 22 10<RAND>10<AUTN> 00,
// the 61xx/6Cxx recovery, and the classification of the answer into success, a
// synchronisation failure or a refusal.
//
// This file therefore builds no APDU and classifies no status word. It moves
// two 16-octet challenges across a socket and translates three labels into the
// three shapes sim already has. Re-deriving either here would create a second
// source of truth for the one thing on this path that cannot be checked by
// reading code - what the card actually said - and the two copies would drift
// silently, because only one of them is ever exercised by hardware.
//
// # Only authenticate, never execute_at
//
// The lease exposes two operations (AtLease, edge-modem/src/at.rs:726-740).
// execute_at runs an arbitrary AT command: that is total control of the module,
// including USB re-enumeration, messaging and profile switching. authenticate
// is the narrow one, and it is all this package ever sends. There is a test,
// TestProviderOnlyEverSendsAuthenticate, that reads back every request line this
// package produced and fails if any of them is anything else.
//
// The transport is a unix socket on this machine. There is no network listener
// here and there must never be one: the lease is a local capability, not an API.
package aka

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/boa-z/vowifi-go/engine/sim"
)

// Provider satisfies sim.AKAProvider.
var _ sim.AKAProvider = (*Provider)(nil)

// Errors this bridge raises. None of them is a card refusal: a refusal is
// sim.ErrAuthFailure and a resynchronisation is sim.ErrSyncFailure, and both of
// those are produced only when the daemon reported that specific outcome.
// Turning a broken pipe into either one would forge an EAP-Response the card
// never authorised, so every failure below stays outside that family and stops
// the exchange instead.
var (
	// ErrBadChallenge means RAND or AUTN was not 16 octets.
	ErrBadChallenge = errors.New("vowifi/aka: malformed AKA challenge")
	// ErrDial means the lease socket could not be reached. On the edge box the
	// socket is mode 0600 owned by root, so a non-root caller lands here.
	ErrDial = errors.New("vowifi/aka: cannot reach the AT lease socket")
	// ErrTimeout is the hard upper bound described on Provider.Timeout.
	ErrTimeout = errors.New("vowifi/aka: AT lease did not answer within the deadline")
	// ErrBusy means too many earlier challenges are still unfinished on the
	// daemon side, so this one was refused rather than queued behind them.
	ErrBusy = errors.New("vowifi/aka: AT lease has too many unfinished challenges")
	// ErrLeaseRefused is an {"ok":false} answer: the daemon or the card is in a
	// state that is not a challenge result at all.
	ErrLeaseRefused = errors.New("vowifi/aka: AT lease refused the challenge")
	// ErrLeaseProtocol is an answer this bridge cannot read.
	ErrLeaseProtocol = errors.New("vowifi/aka: malformed AT lease answer")
)

// Wire constants. Defaults match the Rust side so a caller can leave them zero.
const (
	// DefaultSocketPath mirrors at.rs DEFAULT_LEASE_SOCKET.
	DefaultSocketPath = "/run/vodoge-edge/at-lease.sock"
	// SocketPathEnv mirrors at.rs LEASE_SOCKET_ENV.
	SocketPathEnv = "VODOGE_AT_LEASE_SOCKET"

	opAuthenticate = "authenticate"

	// Outcome labels, verbatim from AkaOutcome::label() (aka.rs:118-125).
	outcomeSuccess     = "success"
	outcomeSyncFailure = "sync_failure"
	outcomeAuthFailure = "authentication_failure"
)

// DefaultTimeout bounds one CalculateAKA call end to end.
//
// It is deliberately below ike.DefaultAKATimeout (20s) so that when a call does
// stall, the error reaching the IKE state machine is this package's, naming the
// socket and the phase, rather than the generic ErrAKADeadlineExceeded that can
// only say "something below me is slow". The outer bound stays as a backstop for
// a bridge that has itself wedged.
//
// Why there has to be a bound at all: a healthy AUTHENTICATE is 0.0-0.8s (T047
// measured it), but the Rust arbiter's acquire() has no timeout whatsoever
// (at.rs:646-666), its per-command ceiling is MAX_LEASE_TIMEOUT = 300s, and a
// wedged holder is unbounded. T047 watched a real AKA wait 41.5s behind a slow
// poll. The ePDG has abandoned the IKE_AUTH exchange long before any of those
// numbers, so waiting past this point cannot succeed - it can only hide the
// fault.
const DefaultTimeout = 15 * time.Second

// DefaultGrace is how long the reaper keeps an abandoned connection open waiting
// for the answer the daemon is still going to write. See CalculateAKA.
const DefaultGrace = 5 * time.Minute

// DefaultMaxInFlight bounds how many challenges this process may have
// outstanding on the daemon, abandoned ones included. The daemon accepts
// MAX_LEASE_CLIENTS = 8 connections in total (at.rs) and the console shares that
// budget, so this stays well under it.
const DefaultMaxInFlight = 4

// Observation is one completed - or abandoned, or late - bridge call.
//
// It exists because the interesting evidence on this path is what the card said
// verbatim, and sim.AKAResult has nowhere to put a status word. Outcome,
// StatusWord, Detail and ErrorCode are copied through from the daemon without
// interpretation, so a receipt can quote them.
type Observation struct {
	IMEI       string
	RAND       string
	AUTN       string
	Outcome    string
	StatusWord string
	Detail     string
	ErrorCode  string
	Message    string
	Elapsed    time.Duration
	// Late marks an answer that arrived after the caller had given up.
	Late bool
	Err  error
}

// Provider answers AKA challenges over the AT lease socket.
//
// The zero value works on the edge box: default socket path, default deadline,
// and the daemon picks the module.
type Provider struct {
	// SocketPath overrides the default. Empty means $VODOGE_AT_LEASE_SOCKET and
	// then DefaultSocketPath.
	SocketPath string
	// IMEI selects the module. Empty lets the daemon choose, which is only
	// sensible on a one-module box; the bench has three.
	IMEI string
	// Timeout bounds the whole call: slot, dial, write and read. Zero means
	// DefaultTimeout. Negative disables the bound and is only for tests.
	Timeout time.Duration
	// Grace bounds the reaper. Zero means DefaultGrace.
	Grace time.Duration
	// MaxInFlight bounds outstanding challenges. Zero means DefaultMaxInFlight.
	MaxInFlight int
	// Dial is for tests. Nil means a real unix socket.
	Dial func(ctx context.Context, path string) (net.Conn, error)
	// Observe, if set, is called once per answer, late ones included. It runs on
	// the caller's goroutine for a normal answer and on the reaper's goroutine
	// for a late one, so it must be safe to call concurrently.
	Observe func(Observation)

	once  sync.Once
	slots chan struct{}
}

// SocketPathOrDefault reports the socket this provider will use.
func (p *Provider) SocketPathOrDefault() string {
	if strings.TrimSpace(p.SocketPath) != "" {
		return p.SocketPath
	}
	if fromEnv := strings.TrimSpace(os.Getenv(SocketPathEnv)); fromEnv != "" {
		return fromEnv
	}
	return DefaultSocketPath
}

func (p *Provider) timeout() time.Duration {
	if p.Timeout == 0 {
		return DefaultTimeout
	}
	return p.Timeout
}

func (p *Provider) grace() time.Duration {
	if p.Grace <= 0 {
		return DefaultGrace
	}
	return p.Grace
}

func (p *Provider) gate() chan struct{} {
	p.once.Do(func() {
		size := p.MaxInFlight
		if size <= 0 {
			size = DefaultMaxInFlight
		}
		p.slots = make(chan struct{}, size)
	})
	return p.slots
}

func (p *Provider) observe(obs Observation) {
	if p.Observe != nil {
		p.Observe(obs)
	}
}

// CalculateAKA sends one challenge to the card and maps the answer.
//
// # What happens when this times out, which is the part that bites
//
// sim.AKAProvider has no context and no cancellation, so nothing upstream can
// call this off; the bound has to be enforced from inside. It is, with a socket
// deadline and giving up on the connection. Three consequences follow. None is
// hypothetical and all three are chosen rather than inherited:
//
//  1. The AT exchange keeps running. The daemon is blocked in
//     ModemArbiter::acquire or inside the AUTHENTICATE and has no idea we left.
//     It still holds the serial port. The next challenge will queue behind it
//     and, unless the holder finished meanwhile, will time out too - which is
//     correct: the card is genuinely unavailable, and a bridge that hid that by
//     waiting longer would turn a five-second fault into a five-minute one.
//
//  2. There is no silent retry. One call sends exactly one request line. A retry
//     would double the load on a port that is already stuck, and worse, an
//     AUTHENTICATE is not side-effect free: a challenge the card accepts
//     advances SQN. Retrying on a timeout can therefore desynchronise the card
//     against the network, and that failure surfaces much later as an AT_AUTS
//     storm with nothing pointing back here.
//
//  3. A late answer can never be read as somebody else's. Each call gets its own
//     connection, so the answer to an abandoned challenge is physically not on
//     the socket the next challenge reads from. This is the whole reason
//     connections are not pooled: on one shared connection a request that timed
//     out and a reply that arrived a millisecond later would leave the stream
//     one message out of step, and every later challenge would be answered with
//     the previous challenge's RES. That is a tunnel that comes up on the wrong
//     keys, and it would look like a carrier problem.
//
// The abandoned connection is handed to a reaper instead of being closed at
// once. Closing would be simpler but blind: the daemon's connection slot stays
// occupied until its thread unblocks either way, and reading the late answer is
// how this side learns that it did. The reaper reports it through Observe -
// which is how a receipt can say what the abandoned challenge eventually
// returned - and only then releases the in-flight slot. After Grace it gives up
// and closes anyway, so a permanently wedged holder costs one slot rather than a
// leaked goroutine.
func (p *Provider) CalculateAKA(rand16, autn16 []byte) (sim.AKAResult, error) {
	started := time.Now()
	// The length rule is the mirror's own, borrowed rather than restated.
	if _, err := sim.NewAKAAuthRequest(sim.AKAApplicationUSIM, rand16, autn16); err != nil {
		return sim.AKAResult{}, fmt.Errorf("%w: %w", ErrBadChallenge, err)
	}

	obs := Observation{
		IMEI: p.IMEI,
		RAND: strings.ToUpper(hex.EncodeToString(rand16)),
		AUTN: strings.ToUpper(hex.EncodeToString(autn16)),
	}
	fail := func(err error) (sim.AKAResult, error) {
		obs.Elapsed = time.Since(started)
		obs.Err = err
		p.observe(obs)
		return sim.AKAResult{}, err
	}

	timeout := p.timeout()
	var deadline time.Time
	if timeout > 0 {
		deadline = started.Add(timeout)
	}

	release, ok := p.reserve(deadline)
	if !ok {
		return fail(fmt.Errorf("%w: %d outstanding, gave up after %s", ErrBusy,
			cap(p.gate()), time.Since(started).Round(time.Millisecond)))
	}
	// handedOff means the reaper has taken over both the connection and the
	// in-flight slot. Until it does, both belong to this call.
	handedOff := false
	defer func() {
		if !handedOff {
			release()
		}
	}()

	path := p.SocketPathOrDefault()
	conn, err := p.dial(deadline, path)
	if err != nil {
		return fail(fmt.Errorf("%w %s: %w", ErrDial, path, err))
	}
	defer func() {
		if !handedOff {
			_ = conn.Close()
		}
	}()
	if !deadline.IsZero() {
		if err := conn.SetDeadline(deadline); err != nil {
			return fail(fmt.Errorf("%w %s: %w", ErrDial, path, err))
		}
	}

	if _, err := conn.Write(append(p.requestLine(obs), '\n')); err != nil {
		if isTimeout(err) {
			handedOff = p.reap(conn, obs, started, release)
			return fail(timeoutError(timeout, "writing the challenge"))
		}
		return fail(fmt.Errorf("%w: writing the challenge: %w", ErrLeaseProtocol, err))
	}

	line, err := readLine(conn)
	if err != nil {
		if isTimeout(err) {
			handedOff = p.reap(conn, obs, started, release)
			return fail(timeoutError(timeout, "waiting for the card"))
		}
		return fail(fmt.Errorf("%w: reading the answer: %w", ErrLeaseProtocol, err))
	}

	result, obs, err := decode(line, obs)
	obs.Elapsed = time.Since(started)
	obs.Err = err
	p.observe(obs)
	return result, err
}

// requestLine builds the one request shape this package is allowed to send.
//
// An absent IMEI is left out rather than sent empty: at.rs filters blank strings
// anyway, and omitting the key says what is meant.
func (p *Provider) requestLine(obs Observation) []byte {
	fields := map[string]string{
		"op":   opAuthenticate,
		"rand": obs.RAND,
		"autn": obs.AUTN,
	}
	if strings.TrimSpace(p.IMEI) != "" {
		fields["imei"] = p.IMEI
	}
	// map[string]string with fixed keys cannot fail to marshal.
	line, _ := json.Marshal(fields)
	return line
}

// reserve takes an in-flight slot, or reports that the budget is spent.
func (p *Provider) reserve(deadline time.Time) (func(), bool) {
	gate := p.gate()
	select {
	case gate <- struct{}{}:
		return func() { <-gate }, true
	default:
	}
	if deadline.IsZero() {
		gate <- struct{}{}
		return func() { <-gate }, true
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case gate <- struct{}{}:
		return func() { <-gate }, true
	case <-timer.C:
		return nil, false
	}
}

// reap waits out the answer to a challenge the caller has already abandoned.
func (p *Provider) reap(conn net.Conn, obs Observation, started time.Time, release func()) bool {
	grace := p.grace()
	if err := conn.SetDeadline(time.Now().Add(grace)); err != nil {
		_ = conn.Close()
		release()
		return false
	}
	go func() {
		defer release()
		defer conn.Close()
		late := obs
		late.Late = true
		line, err := readLine(conn)
		if err != nil {
			late.Elapsed = time.Since(started)
			late.Err = fmt.Errorf("%w: the abandoned challenge produced no answer within %s: %w",
				ErrTimeout, grace, err)
			p.observe(late)
			return
		}
		_, late, err = decode(line, late)
		late.Elapsed = time.Since(started)
		late.Err = err
		p.observe(late)
	}()
	return true
}

func (p *Provider) dial(deadline time.Time, path string) (net.Conn, error) {
	ctx := context.Background()
	if !deadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}
	if p.Dial != nil {
		return p.Dial(ctx, path)
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, "unix", path)
}

// maxAnswerLine caps one answer. A success body is a few hundred octets, so this
// is ample headroom and still refuses to buffer a runaway peer.
const maxAnswerLine = 64 << 10

func readLine(conn net.Conn) (string, error) {
	reader := bufio.NewReader(io.LimitReader(conn, maxAnswerLine))
	line, err := reader.ReadString('\n')
	if err != nil && (!errors.Is(err, io.EOF) || strings.TrimSpace(line) == "") {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// leaseAnswer is the response object built by at.rs outcome_json/failure_json.
type leaseAnswer struct {
	OK      *bool  `json:"ok"`
	Op      string `json:"op"`
	Outcome string `json:"outcome"`
	RES     string `json:"res"`
	CK      string `json:"ck"`
	IK      string `json:"ik"`
	AUTS    string `json:"auts"`
	SW      string `json:"sw"`
	Detail  string `json:"detail"`
	Error   string `json:"error"`
	Message string `json:"message"`
}

// decode turns one answer line into the sim shapes.
//
// The three outcome labels are the daemon's, copied not recomputed. Anything
// else - including an outcome label this build has never heard of - is an error,
// because guessing at an unknown card state is exactly how a wrong protocol
// decision gets made confidently.
func decode(line string, obs Observation) (sim.AKAResult, Observation, error) {
	var answer leaseAnswer
	if err := json.Unmarshal([]byte(line), &answer); err != nil {
		return sim.AKAResult{}, obs, fmt.Errorf("%w: %q: %w", ErrLeaseProtocol, clip(line), err)
	}
	obs.Outcome = answer.Outcome
	obs.StatusWord = answer.SW
	obs.Detail = answer.Detail
	obs.ErrorCode = answer.Error
	obs.Message = answer.Message

	if answer.OK == nil {
		return sim.AKAResult{}, obs, fmt.Errorf("%w: no ok field in %q", ErrLeaseProtocol, clip(line))
	}
	if !*answer.OK {
		return sim.AKAResult{}, obs, fmt.Errorf("%w: %s: %s", ErrLeaseRefused,
			orUnset(answer.Error), orUnset(answer.Message))
	}
	if answer.Op != "" && answer.Op != opAuthenticate {
		return sim.AKAResult{}, obs, fmt.Errorf("%w: answer is for op %q, not %q",
			ErrLeaseProtocol, answer.Op, opAuthenticate)
	}

	switch answer.Outcome {
	case outcomeSuccess:
		res, err := decodeHex(answer.RES, "res")
		if err != nil {
			return sim.AKAResult{}, obs, err
		}
		ck, err := decodeHex(answer.CK, "ck")
		if err != nil {
			return sim.AKAResult{}, obs, err
		}
		ik, err := decodeHex(answer.IK, "ik")
		if err != nil {
			return sim.AKAResult{}, obs, err
		}
		// Kc is dropped: sim.AKAResult has no field for it and EAP-AKA does not
		// use it. The daemon keeps it for a GSM interworking caller.
		return sim.AKAResult{RES: res, CK: ck, IK: ik}, obs, nil

	case outcomeSyncFailure:
		auts, err := decodeHex(answer.AUTS, "auts")
		if err != nil {
			return sim.AKAResult{}, obs, err
		}
		// AUTS rides on the error, not in the result, so eapaka's carrier path
		// (syncFailureAUTS, crypto.go:444) is the one exercised - the same
		// convention T041b's recorded provider uses.
		return sim.AKAResult{}, obs, sim.NewSyncFailureError(auts)

	case outcomeAuthFailure:
		// The card rejected the challenge. Which refusal it was stays in the
		// message verbatim; the classification behind it is aka.rs's.
		return sim.AKAResult{}, obs, fmt.Errorf("%w (card SW %s: %s)",
			sim.NewMACFailureError(), orUnset(answer.SW), orUnset(answer.Detail))

	default:
		return sim.AKAResult{}, obs, fmt.Errorf("%w: unknown outcome %q in %q",
			ErrLeaseProtocol, answer.Outcome, clip(line))
	}
}

func decodeHex(value, field string) ([]byte, error) {
	if value == "" {
		return nil, fmt.Errorf("%w: the answer has no %s", ErrLeaseProtocol, field)
	}
	raw, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%w: %s is not hex: %w", ErrLeaseProtocol, field, err)
	}
	return raw, nil
}

func timeoutError(timeout time.Duration, phase string) error {
	return fmt.Errorf("%w after %s, %s; the exchange is still running on the daemon because "+
		"sim.AKAProvider cannot be cancelled, so the next challenge may queue behind it",
		ErrTimeout, timeout, phase)
}

func isTimeout(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func orUnset(value string) string {
	if strings.TrimSpace(value) == "" {
		return "(unset)"
	}
	return value
}

func clip(line string) string {
	const limit = 200
	if len(line) <= limit {
		return line
	}
	return line[:limit] + "..."
}
