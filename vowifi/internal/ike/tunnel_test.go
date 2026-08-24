package ike

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/boa-z/vowifi-go/engine/sim"
	"github.com/boa-z/vowifi-go/engine/swu/ikev2"
)

// benchSubscription is the card readout put through the real derivation, so the
// identities these tests assert on are produced the same way the live run
// produces them. Writing the FQDN out by hand here would test nothing.
func benchSubscription(t *testing.T) Subscription {
	t.Helper()
	sub, err := DeriveSubscription("867018069514820", benchIMSI, benchHomePLMN, "test")
	if err != nil {
		t.Fatalf("DeriveSubscription: %v", err)
	}
	return sub
}

// startLiveFake brings up the encrypted fake ePDG expecting the identities this
// subscription derives.
func startLiveFake(t *testing.T, sub Subscription, tune func(*epdgAuth)) (*fakeEPDG, *epdgAuth) {
	t.Helper()
	f := newFakeEPDG(t)
	a := newEPDGAuth()
	a.responderID = sub.ResponderIdentity()
	if tune != nil {
		tune(a)
	}
	f.enableEPDGAuth(a)
	f.Start()
	return f, a
}

func liveConfigFor(t *testing.T, f *fakeEPDG, sub Subscription, provider sim.AKAProvider) (LiveConfig, *Socket) {
	t.Helper()
	socket := dialFake(t, f, SocketConfig{})
	return LiveConfig{
		Socket:       socket,
		Subscription: sub,
		AKA:          provider,
		// The fake ePDG requires an IDr by default, which is what T041b built
		// for. The live default is now the opposite, so these tests have to ask
		// for the IDr explicitly - and one test below pins the new default.
		ResponderID: sub.ResponderIdentity(),
		InitTimeout: 20 * time.Second,
		AuthTimeout: 30 * time.Second,
	}, socket
}

// TestLiveTunnelPutsTheCardDerivedIdentitiesOnTheWire is the confluence test.
//
// It is not "the ladder still works" - authrunner_test.go already covers that.
// What is new in T041d is that nothing chooses the identities: the responder
// checks that the IDr it received is the name derived from the IMSI, and that
// the EAP identity it received is the IMPI derived from the same IMSI. If a
// constant ever creeps back into the path, those two stop matching.
func TestLiveTunnelPutsTheCardDerivedIdentitiesOnTheWire(t *testing.T) {
	sub := benchSubscription(t)
	f, a := startLiveFake(t, sub, nil)
	cfg, _ := liveConfigFor(t, f, sub, newTestAKAProvider())

	result, err := RunLiveTunnel(context.Background(), cfg)
	if err != nil {
		t.Fatalf("RunLiveTunnel: %v", err)
	}
	if result.Outcome != OutcomeEstablished {
		t.Fatalf("outcome = %s, want %s", result.Outcome, OutcomeEstablished)
	}

	gotIDr := string(a.observedIDr[4:])
	if gotIDr != sub.EPDGFQDN() {
		t.Fatalf("IDr on the wire = %q, want the name derived from IMSI %s: %q",
			gotIDr, sub.IMSI, sub.EPDGFQDN())
	}
	gotIDi := string(a.observedIDi[4:])
	if gotIDi != sub.IMPI() {
		t.Fatalf("IDi on the wire = %q, want the IMPI derived from IMSI %s: %q",
			gotIDi, sub.IMSI, sub.IMPI())
	}
	if a.eapIdentity != sub.IMPI() {
		t.Fatalf("EAP identity = %q, want %q", a.eapIdentity, sub.IMPI())
	}
	// The IMEI selects hardware and must not appear in anything the responder
	// saw. Criterion 2b names a self-supplied IMEI as inadmissible evidence.
	for name, value := range map[string]string{"IDi": gotIDi, "IDr": gotIDr, "EAP identity": a.eapIdentity} {
		if strings.Contains(value, sub.IMEI) {
			t.Fatalf("%s %q leaked the IMEI", name, value)
		}
	}
	if !result.SawCarrierChallenge() || !result.CardAnsweredChallenge() {
		t.Fatalf("challenge=%v answered=%v", result.SawCarrierChallenge(), result.CardAnsweredChallenge())
	}
}

// slowAKAProvider answers eventually. It stands in for a card behind a busy AT
// arbiter, which T047 measured at 41.5 seconds in the worst case observed.
type slowAKAProvider struct {
	inner sim.AKAProvider
	delay time.Duration
}

func (p *slowAKAProvider) CalculateAKA(rand16, autn16 []byte) (sim.AKAResult, error) {
	time.Sleep(p.delay)
	return p.inner.CalculateAKA(rand16, autn16)
}

// TestKeepalivesRunWhileTheCardIsThinking is the reason RunLiveTunnel exists.
//
// The NAT mapping is created by IKE_SA_INIT and then has to survive an IKE_AUTH
// ladder that blocks on a USIM. T062 measured this box losing an idle UDP
// mapping somewhere after 20 seconds; a straight-line script sends nothing at
// all during the card round trip, so the gap it leaves is exactly the gap that
// kills the exchange. The assertion is on datagrams actually written, not on a
// ticker having been constructed.
func TestKeepalivesRunWhileTheCardIsThinking(t *testing.T) {
	sub := benchSubscription(t)
	f, _ := startLiveFake(t, sub, nil)
	provider := &slowAKAProvider{inner: newTestAKAProvider(), delay: 400 * time.Millisecond}
	cfg, socket := liveConfigFor(t, f, sub, provider)
	cfg.KeepalivePeriod = 50 * time.Millisecond

	result, err := RunLiveTunnel(context.Background(), cfg)
	if err != nil {
		t.Fatalf("RunLiveTunnel: %v", err)
	}
	if result.Keepalives < 3 {
		t.Fatalf("keepalives = %d; the card took %s and the interval was %s, so the mapping "+
			"went unfed across the phase seam", result.Keepalives, provider.delay, cfg.KeepalivePeriod)
	}
	if got := socket.Stats().KeepalivesSent; got != result.Keepalives {
		t.Fatalf("result says %d keepalives, the socket counted %d", result.Keepalives, got)
	}
}

// TestKeepalivesStopWhenTheLadderDoes guards against a goroutine that outlives
// its socket and starts logging write errors into a run that already finished.
func TestKeepalivesStopWhenTheLadderDoes(t *testing.T) {
	sub := benchSubscription(t)
	f, _ := startLiveFake(t, sub, nil)
	cfg, socket := liveConfigFor(t, f, sub, newTestAKAProvider())
	cfg.KeepalivePeriod = 20 * time.Millisecond

	result, err := RunLiveTunnel(context.Background(), cfg)
	if err != nil {
		t.Fatalf("RunLiveTunnel: %v", err)
	}
	settled := socket.Stats().KeepalivesSent
	if settled != result.Keepalives {
		t.Fatalf("counter moved between the run returning and the check: %d then %d",
			result.Keepalives, settled)
	}
	time.Sleep(120 * time.Millisecond)
	if got := socket.Stats().KeepalivesSent; got != settled {
		t.Fatalf("keepalives kept going after the ladder finished: %d then %d", settled, got)
	}
}

// TestKeepalivesCanBeTurnedOff keeps the disable path honest: a negative period
// must mean none, not "the default".
func TestKeepalivesCanBeTurnedOff(t *testing.T) {
	sub := benchSubscription(t)
	f, _ := startLiveFake(t, sub, nil)
	cfg, _ := liveConfigFor(t, f, sub, newTestAKAProvider())
	cfg.KeepalivePeriod = -1

	result, err := RunLiveTunnel(context.Background(), cfg)
	if err != nil {
		t.Fatalf("RunLiveTunnel: %v", err)
	}
	if result.Keepalives != 0 {
		t.Fatalf("keepalives = %d, want 0", result.Keepalives)
	}
}

// refusingAKAProvider is a card that rejects the challenge, i.e. the 9862 path
// T069 measured on this bench for every AUTN it could construct.
type refusingAKAProvider struct{ calls int }

func (p *refusingAKAProvider) CalculateAKA(_, _ []byte) (sim.AKAResult, error) {
	p.calls++
	return sim.AKAResult{}, sim.NewMACFailureError()
}

// TestCardRefusalIsClassifiedAsClassThreeNotAsAFailedExchange is the
// classification that matters most to the receipt.
//
// A carrier challenge that the card refuses is the largest step this project
// can take short of a tunnel: it proves an operator's AuC put a real RAND/AUTN
// in front of this eUICC. Reporting it as "IKE_AUTH failed" would bury that,
// and reporting it as success would be a lie. Both halves are asserted.
func TestCardRefusalIsClassifiedAsClassThreeNotAsAFailedExchange(t *testing.T) {
	sub := benchSubscription(t)
	f, _ := startLiveFake(t, sub, nil)
	provider := &refusingAKAProvider{}
	cfg, _ := liveConfigFor(t, f, sub, provider)

	result, err := RunLiveTunnel(context.Background(), cfg)
	if err == nil {
		t.Fatalf("a refused challenge must not come back as success")
	}
	if !errors.Is(err, ErrAKAAuthFailure) {
		t.Fatalf("err = %v, want ErrAKAAuthFailure", err)
	}
	if result.Outcome != OutcomeCardRefused {
		t.Fatalf("outcome = %s, want %s", result.Outcome, OutcomeCardRefused)
	}
	if !result.SawCarrierChallenge() {
		t.Fatalf("the challenge reached the card %d time(s) but SawCarrierChallenge is false",
			provider.calls)
	}
	if result.CardAnsweredChallenge() {
		t.Fatalf("a refusal was reported as an answer")
	}
	vectors := result.Challenges()
	if len(vectors) == 0 || vectors[0].Failure != "auth" {
		t.Fatalf("vectors = %+v; the RAND/AUTN of a refused challenge is still evidence", vectors)
	}
	if len(vectors[0].RAND) != 16 || len(vectors[0].AUTN) != 16 {
		t.Fatalf("RAND/AUTN = %d/%d octets", len(vectors[0].RAND), len(vectors[0].AUTN))
	}
	if !strings.Contains(result.Outcome.Explain(), "first half") {
		t.Fatalf("the explanation must say which half of 2b holds: %q", result.Outcome.Explain())
	}
}

// TestUnreachableEPDGIsClassifiedAsClassOne pins the network verdict. Class 1
// is a fact about the path and no edit to our payloads can change it, so
// confusing it with class 2 sends the next round of work in the wrong
// direction.
func TestUnreachableEPDGIsClassifiedAsClassOne(t *testing.T) {
	// A socket that nothing is listening on. Loopback with a port we close
	// immediately: the OS may answer with ICMP unreachable, which a UDP
	// connection does not surface here, so this behaves as a black hole.
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	dead := conn.LocalAddr().(*net.UDPAddr)
	_ = conn.Close()

	socket, err := Listen(SocketConfig{
		LocalIP:            net.IPv4(127, 0, 0, 1),
		EphemeralLocalPort: true,
		Remote:             dead,
		Retransmit:         RetransmitPolicy{Initial: 30 * time.Millisecond, Multiplier: 1.2, Max: 60 * time.Millisecond, Attempts: 2},
	})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = socket.Close(nil) }()

	result, err := RunLiveTunnel(context.Background(), LiveConfig{
		Socket:       socket,
		Subscription: benchSubscription(t),
		AKA:          newTestAKAProvider(),
		InitTimeout:  2 * time.Second,
	})
	if err == nil {
		t.Fatalf("a black hole must not report success")
	}
	if result.Outcome != OutcomeUnreachable {
		t.Fatalf("outcome = %s, want %s (err %v)", result.Outcome, OutcomeUnreachable, err)
	}
	if result.AuthAttempted {
		t.Fatalf("IKE_AUTH was attempted without an IKE SA")
	}
	if !strings.Contains(result.Outcome.Explain(), "network") {
		t.Fatalf("class 1 must be explained as a network result: %q", result.Outcome.Explain())
	}
}

// TestIKEAuthWithoutAChallengeIsClassTwo covers the second bucket.
//
// The fixture is told to authenticate with a certificate, i.e. to ignore
// RFC 5998, which is one of the three things T041b flagged as reasoned but
// unmeasured. The point of the assertion is not the specific error: it is that
// an ePDG which answered IKE_AUTH and never issued a challenge must land in
// class 2 and must not be confused with either the unreachable case or the card
// case.
func TestIKEAuthWithoutAChallengeIsClassTwo(t *testing.T) {
	sub := benchSubscription(t)
	f, _ := startLiveFake(t, sub, func(a *epdgAuth) { a.certAuthInFirstResponse = true })
	cfg, _ := liveConfigFor(t, f, sub, newTestAKAProvider())

	result, err := RunLiveTunnel(context.Background(), cfg)
	if err == nil {
		t.Fatalf("a responder that ignored EAP-only must not report success")
	}
	if !errors.Is(err, ErrResponderIgnoredEAPOnly) {
		t.Fatalf("err = %v, want ErrResponderIgnoredEAPOnly", err)
	}
	if result.Outcome != OutcomeAuthRejected {
		t.Fatalf("outcome = %s, want %s", result.Outcome, OutcomeAuthRejected)
	}
	if result.SawCarrierChallenge() {
		t.Fatalf("no challenge was issued, but one was reported")
	}
	if len(result.AuthDetail.Rounds) == 0 {
		t.Fatalf("the rejected exchange was not recorded, so there is nothing to replay")
	}
	if !strings.Contains(result.Outcome.Explain(), "AUTH encoding") {
		t.Fatalf("class 2 must point at the three unmeasured payload decisions: %q",
			result.Outcome.Explain())
	}
}

// notifyOnlyTransport answers one IKE_AUTH request with a single error notify,
// protected with the real IKE SA keys.
//
// This is what an ePDG rejection looks like, and it is the one shape the fake
// responder cannot be asked for without editing it. The transport is injected
// into AuthRunner rather than into RunLiveTunnel on purpose: RunLiveTunnel
// takes the concrete Socket because sharing one five-tuple with ESP is the
// reason that type exists, and loosening it to an interface for a test would
// trade a real invariant for a convenience.
type notifyOnlyTransport struct {
	notifyType uint16
	build      func(request []byte, notifyType uint16) ([]byte, error)
}

func (t *notifyOnlyTransport) ExchangeIKE(_ context.Context, request []byte) ([]byte, error) {
	return t.build(request, t.notifyType)
}

// TestResponderNotifyIsKeptForTheDiagnosis is about evidence, not control flow.
//
// ikev2.FirstNotifyError turns an error notify into a Go error and the type
// number survives only inside a message string. On the first live contact the
// notify type is the entire diagnosis, so it has to come back as data.
func TestResponderNotifyIsKeptForTheDiagnosis(t *testing.T) {
	sub := benchSubscription(t)
	f, _ := startLiveFake(t, sub, nil)
	socket := dialFake(t, f, SocketConfig{})

	initRunner := NewInitRunner()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	init, err := initRunner.Run(ctx, initConfig(t, socket))
	if err != nil {
		t.Fatalf("IKE_SA_INIT: %v", err)
	}

	const authenticationFailed = uint16(24)
	transport := &notifyOnlyTransport{
		notifyType: authenticationFailed,
		build: func(request []byte, notifyType uint16) ([]byte, error) {
			header, err := ikev2.ParseHeader(request)
			if err != nil {
				return nil, err
			}
			notify, err := ikev2.NotifyPayload(ikev2.Notify{NotifyType: notifyType})
			if err != nil {
				return nil, err
			}
			header.Flags = ikev2.FlagResponse
			_, raw, err := ikev2.ProtectMessage(header, init.Keys, false, []ikev2.Payload{notify}, nil)
			return raw, err
		},
	}

	runner := NewAuthRunner(sub.ResponderIdentity())
	runner.InitiatorID = sub.InitiatorIdentity()
	_, err = runner.Run(ctx, ikev2.FullAuthConfig{
		Transport:   transport,
		Init:        init,
		Keys:        init.Keys,
		SIM:         newTestAKAProvider(),
		InitiatorID: sub.InitiatorIdentity(),
		EAPIdentity: sub.IMPI(),
	})
	if err == nil {
		t.Fatalf("an AUTHENTICATION_FAILED notify must not come back as success")
	}
	detail, ok := runner.LastDetail()
	if !ok {
		t.Fatalf("no detail")
	}
	var found bool
	for _, n := range detail.ResponseNotifies {
		if n.Type == authenticationFailed {
			found = true
		}
	}
	if !found {
		t.Fatalf("AUTHENTICATION_FAILED was not recorded as data; notifies = %+v", detail.ResponseNotifies)
	}
	if len(detail.Rounds) == 0 {
		t.Fatalf("the rejected exchange was not recorded, so there is nothing to replay offline")
	}
	if len(detail.Rounds[0].ResponseBytes) == 0 {
		t.Fatalf("the rejecting response was not kept")
	}
}

// TestLiveTunnelRefusesToRunWithoutACardReadout closes the last door: no
// readout, no exchange. An empty Subscription would otherwise derive
// epdg.epc.mnc000.mcc..., which is a name, and a name is enough to send a
// packet with.
func TestLiveTunnelRefusesToRunWithoutACardReadout(t *testing.T) {
	sub := benchSubscription(t)
	f, _ := startLiveFake(t, sub, nil)
	cfg, _ := liveConfigFor(t, f, sub, newTestAKAProvider())
	cfg.Subscription = Subscription{}

	result, err := RunLiveTunnel(context.Background(), cfg)
	if !errors.Is(err, ErrCardReadout) {
		t.Fatalf("err = %v, want ErrCardReadout", err)
	}
	if result.InitDone || result.AuthAttempted {
		t.Fatalf("something was sent: init=%v auth=%v", result.InitDone, result.AuthAttempted)
	}
}

// TestTheLiveDefaultSendsNoIDr pins the measurement T041d came back with.
//
// This is the one place in the package where the fake ePDG is asked to accept
// something the RFC-shaped fixture would reject by default, and that is the
// point: T-Mobile US answered AUTHENTICATION_FAILED to every IKE_AUTH carrying
// an IDr and issued a Challenge to every one without, across five GSLB nodes on
// 2026-08-24. A future refactor that quietly restores the IDr would reproduce a
// failure that took a live carrier and a switched profile to find.
func TestTheLiveDefaultSendsNoIDr(t *testing.T) {
	sub := benchSubscription(t)
	f, a := startLiveFake(t, sub, func(a *epdgAuth) { a.requireIDr = false })
	socket := dialFake(t, f, SocketConfig{})

	result, err := RunLiveTunnel(context.Background(), LiveConfig{
		Socket:       socket,
		Subscription: sub,
		AKA:          newTestAKAProvider(),
		InitTimeout:  20 * time.Second,
		AuthTimeout:  30 * time.Second,
	})
	if err != nil {
		t.Fatalf("RunLiveTunnel: %v", err)
	}
	if result.AuthDetail.SentIDr {
		t.Fatalf("the default put an IDr on the wire; T-Mobile US rejects those")
	}
	if result.ResponderIDUsed != "(omitted)" {
		t.Fatalf("ResponderIDUsed = %q, want (omitted)", result.ResponderIDUsed)
	}
	if len(a.observedIDr) != 0 {
		t.Fatalf("the responder saw an IDr: %x", a.observedIDr)
	}
	// The IDi is unaffected: the subscriber identity still has to be asserted,
	// and it still has to come from the card.
	if string(a.observedIDi[4:]) != sub.IMPI() {
		t.Fatalf("IDi = %q, want %q", a.observedIDi[4:], sub.IMPI())
	}
	if !result.AuthDetail.SentEAPOnlyNotify {
		t.Fatalf("EAP_ONLY_AUTHENTICATION was dropped; T041d's successful run carried it")
	}
}
