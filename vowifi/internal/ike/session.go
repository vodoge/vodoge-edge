package ike

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/boa-z/vowifi-go/engine/swu"
)

// OpenPacketSession constructs a swu.PacketSession from a completed live tunnel.
//
// The result must carry a CHILD_SA (Outcome == OutcomeEstablished). The session
// is wired to the same socket that carried the IKE exchange so that
// AdvanceIKELiveness can send NAT-T keepalives on the five-tuple the NAT
// mapping already knows about.
//
// The keepalive interval is set explicitly to DefaultKeepalivePeriod (10 s).
// The upstream default (swu/ike_liveness.go:12-16) is 20 s, which violates
// T016: T062 measured this path losing an idle UDP mapping somewhere in
// (20 s, 40 s], so a 20 s keepalive is indistinguishable from silence from
// the NAT's point of view. Inheriting the default here would silently reopen
// the gap that startKeepalive in tunnel.go was created to close.
//
// DPD is disabled at this layer. T042 will add a supervisor that owns the
// ticker, the DPD handler, and the reconnect loop; this function only assembles
// the PacketSession that supervisor will drive.
func OpenPacketSession(result LiveResult, socket *Socket) (*swu.PacketSession, error) {
	if result.Auth.ChildSA == nil {
		return nil, fmt.Errorf("no CHILD_SA in LiveResult (outcome=%s): "+
			"the tunnel must be established before a PacketSession can be opened", result.Outcome)
	}
	liveness, err := swu.NewIKELivenessState(swu.IKELivenessConfig{
		KeepaliveInterval: DefaultKeepalivePeriod, // 10 s; explicit, not inherited from the upstream 20 s default
		DisableDPD:        true,                   // T042 will wire the DPD handler; not this function's job
	}, time.Now())
	if err != nil {
		return nil, fmt.Errorf("IKELivenessState: %w", err)
	}
	return swu.NewPacketSession(swu.PacketSessionConfig{
		ChildSA:   *result.Auth.ChildSA,
		Transport: socket,
		Random:    rand.Reader,
		Liveness:  liveness,
	})
}
