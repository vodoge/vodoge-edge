package ike

import (
	"context"
	"testing"
	"time"

	"github.com/boa-z/vowifi-go/engine/swu"
)

// TestOpenPacketSessionConstructsFromEstablishedTunnel is the first moment
// swu.PacketSession exists in non-test code in this repository.
//
// The judgment is "tunnel established → PacketSession obtainable → liveness
// fires → keepalive on the wire". All three are needed: construction alone
// proves nothing, and AdvanceIKELiveness returning a decision without a
// packet on the wire would mean the transport cast silently failed.
//
// The socket's KeepalivesSent counter tracks actual UDP datagrams. That is the
// packet-level evidence the receipt requires.
func TestOpenPacketSessionConstructsFromEstablishedTunnel(t *testing.T) {
	sub := benchSubscription(t)
	f, _ := startLiveFake(t, sub, nil)
	cfg, socket := liveConfigFor(t, f, sub, newTestAKAProvider())
	// Disable the RunLiveTunnel keepalive so the counter starts at zero and
	// the only increment we see is the one AdvanceIKELiveness sends.
	cfg.KeepalivePeriod = -1

	result, err := RunLiveTunnel(context.Background(), cfg)
	if err != nil {
		t.Fatalf("RunLiveTunnel: %v", err)
	}
	if result.Outcome != OutcomeEstablished {
		t.Fatalf("outcome = %s, want %s; test requires a CHILD_SA", result.Outcome, OutcomeEstablished)
	}
	if result.Auth.ChildSA == nil {
		t.Fatal("Auth.ChildSA is nil despite OutcomeEstablished")
	}

	session, err := OpenPacketSession(result, socket)
	if err != nil {
		t.Fatalf("OpenPacketSession: %v", err)
	}
	defer func() { _ = session.Close(context.Background()) }()

	// Sanity: liveness state was created with 10 s interval.
	snap := session.IKELivenessSnapshot()
	if !snap.KeepaliveEnabled {
		t.Fatal("keepalive must be enabled; DPD-only liveness does not satisfy T016")
	}

	// Advance time past DefaultKeepalivePeriod so AdvanceIKELiveness triggers
	// a keepalive. The liveness state was initialised to time.Now() at Open;
	// adding 11 s puts us one second past the 10 s interval.
	now := time.Now().Add(DefaultKeepalivePeriod + time.Second)
	before := socket.Stats().KeepalivesSent

	decision, err := session.AdvanceIKELiveness(context.Background(), now)
	if err != nil {
		t.Fatalf("AdvanceIKELiveness: %v", err)
	}
	if decision.Action != swu.IKELivenessSendKeepalive {
		t.Fatalf("action = %s, want IKELivenessSendKeepalive (reason: %s)",
			decision.Action, decision.Reason)
	}

	after := socket.Stats().KeepalivesSent
	if after <= before {
		t.Fatalf("keepalives sent: before=%d after=%d; "+
			"AdvanceIKELiveness must write a packet, not just return a decision",
			before, after)
	}
}

// TestOpenPacketSessionRequiresChildSA guards the precondition.
//
// Calling OpenPacketSession on a result that has no CHILD_SA (any outcome
// other than OutcomeEstablished) must return an error, not a nil session. A
// nil session with a nil error would be silently accepted by a caller that only
// checks the error, and a subsequent AdvanceIKELiveness call on nil would panic.
func TestOpenPacketSessionRequiresChildSA(t *testing.T) {
	sub := benchSubscription(t)
	f, _ := startLiveFake(t, sub, func(a *epdgAuth) { a.addressFailure = true })
	cfg, socket := liveConfigFor(t, f, sub, newTestAKAProvider())
	cfg.KeepalivePeriod = -1

	result, _ := RunLiveTunnel(context.Background(), cfg)
	if result.Auth.ChildSA != nil {
		t.Skip("precondition: fixture must not produce a CHILD_SA for this test to make sense")
	}

	session, err := OpenPacketSession(result, socket)
	if err == nil {
		t.Fatal("OpenPacketSession succeeded on a result with no CHILD_SA")
	}
	if session != nil {
		t.Fatal("OpenPacketSession returned a non-nil session alongside an error")
	}
}
