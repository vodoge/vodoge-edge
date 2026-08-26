package ike

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/boa-z/vowifi-go/engine/swu"
	"github.com/boa-z/vowifi-go/engine/swu/eapaka"
	"github.com/boa-z/vowifi-go/engine/swu/ikev2"

	"github.com/yuanshuai1122/vodoge-edge/vowifi/internal/capture"
)

const testEAPIdentity = "0310260000000001@nai.epc.mnc260.mcc310.3gppnetwork.org"

// ladder is one loopback IKE_SA_INIT plus everything IKE_AUTH needs.
type ladder struct {
	fake     *fakeEPDG
	epdg     *epdgAuth
	socket   *Socket
	init     ikev2.InitResult
	provider *testAKAProvider
	runner   *AuthRunner
}

// startLadder brings up a real IKE SA against the encrypted fake ePDG.
//
// IKE_SA_INIT runs for real first, because IKE_AUTH cannot be tested without it:
// SK_ei/SK_ai protect the messages, SK_pi/SK_pr key the identity MACs, and the
// verbatim IKE_SA_INIT request and response are two thirds of the signed octets.
func startLadder(t *testing.T, tuneEPDG func(*epdgAuth), tuneRunner func(*AuthRunner), writer *capture.Writer) *ladder {
	t.Helper()
	f := newFakeEPDG(t)
	a := newEPDGAuth()
	if tuneEPDG != nil {
		tuneEPDG(a)
	}
	f.enableEPDGAuth(a)
	f.Start()
	s := dialFake(t, f, SocketConfig{Capture: writer})

	initRunner := NewInitRunner()
	initRunner.Capture = writer
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	init, err := initRunner.Run(ctx, initConfig(t, s))
	if err != nil {
		t.Fatalf("IKE_SA_INIT: %v", err)
	}

	provider := newTestAKAProvider()
	runner := NewAuthRunner(a.responderID)
	runner.Capture = writer
	if tuneRunner != nil {
		tuneRunner(runner)
	}
	return &ladder{fake: f, epdg: a, socket: s, init: init, provider: provider, runner: runner}
}

func (l *ladder) authConfig() ikev2.FullAuthConfig {
	return ikev2.FullAuthConfig{
		Transport:   l.socket,
		Init:        l.init,
		Keys:        l.init.Keys,
		SIM:         l.provider,
		InitiatorID: ikev2.Identity{Type: ikev2.IDRFC822Addr, Data: []byte(testEAPIdentity)},
		EAPIdentity: testEAPIdentity,
	}
}

func (l *ladder) run(t *testing.T) (ikev2.FullAuthResult, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return l.runner.Run(ctx, l.authConfig())
}

// TestAuthRunnerWalksTheWholeLadder is the acceptance test for T041b:
// EAP-Identity, AKA-Challenge, EAP-Success, AUTH, CHILD_SA - encrypted
// throughout, with the CHILD_SA in its own exchange.
func TestAuthRunnerWalksTheWholeLadder(t *testing.T) {
	l := startLadder(t, nil, nil, nil)
	result, err := l.run(t)
	if err != nil {
		t.Fatalf("IKE_AUTH: %v", err)
	}
	detail, ok := l.runner.LastDetail()
	if !ok {
		t.Fatalf("LastDetail is empty")
	}

	if result.ChildSA == nil {
		t.Fatalf("no CHILD_SA")
	}
	if !bytes.Equal(result.ChildSA.RemoteSPI, l.epdg.espSPI) {
		t.Fatalf("responder ESP SPI = %x, want %x", result.ChildSA.RemoteSPI, l.epdg.espSPI)
	}
	if !bytes.Equal(result.ChildSA.LocalSPI, detail.ChildSPI) {
		t.Fatalf("local ESP SPI = %x, want %x", result.ChildSA.LocalSPI, detail.ChildSPI)
	}
	if len(result.ChildSA.Keys.Outbound.EncryptionKey) == 0 || len(result.ChildSA.Keys.Inbound.EncryptionKey) == 0 {
		t.Fatalf("CHILD_SA keys were not derived")
	}
	if result.ChildSA.Configuration == nil {
		t.Fatalf("the CFG_REPLY was dropped")
	}

	// The core claim: EAP-Success and the CHILD_SA are in different exchanges.
	if detail.EAPSuccessMessageID == 0 || detail.ChildSAMessageID == 0 {
		t.Fatalf("EAP-Success in message %d, CHILD_SA in message %d; both must have happened",
			detail.EAPSuccessMessageID, detail.ChildSAMessageID)
	}
	if detail.EAPSuccessMessageID == detail.ChildSAMessageID {
		t.Fatalf("EAP-Success and the CHILD_SA shared message %d", detail.ChildSAMessageID)
	}
	if detail.ChildSAMessageID != detail.EAPSuccessMessageID+1 {
		t.Fatalf("CHILD_SA in message %d, expected the exchange right after EAP-Success (%d)",
			detail.ChildSAMessageID, detail.EAPSuccessMessageID)
	}

	// Four exchanges: initial, identity, challenge, AUTH.
	if len(detail.Rounds) != 4 {
		t.Fatalf("%d IKE_AUTH exchanges, want 4: %+v", len(detail.Rounds), detail.Rounds)
	}
	if got := l.epdg.eapResponses; len(got) != 2 ||
		got[0] != eapaka.SubtypeIdentity || got[1] != eapaka.SubtypeChallenge {
		t.Fatalf("the ePDG saw EAP-Response subtypes %v, want [Identity Challenge]", got)
	}
	if l.provider.callCount() != 1 {
		t.Fatalf("the card was asked %d times, want 1", l.provider.callCount())
	}
	if l.epdg.eapIdentity != testEAPIdentity {
		t.Fatalf("the ePDG recorded identity %q, want %q", l.epdg.eapIdentity, testEAPIdentity)
	}

	// Both AUTH payloads verified, each by the other side's independent code.
	if !l.epdg.clientAuthVerified {
		t.Fatalf("the ePDG did not verify our AUTH")
	}
	if l.epdg.clientAuthMethod != AuthMethodSharedKeyMIC {
		t.Fatalf("we sent auth method %d, want %d", l.epdg.clientAuthMethod, AuthMethodSharedKeyMIC)
	}
	if !detail.PeerAuthVerified {
		t.Fatalf("we did not verify the responder AUTH")
	}
	if !detail.PeerSentIDr || len(detail.PeerIDBody) == 0 {
		t.Fatalf("the responder IDr was not captured, so its AUTH was verified against a guess")
	}
	if len(result.EAPKeys.MSK) != eapaka.KeyLengthMSK {
		t.Fatalf("MSK is %d octets, want %d", len(result.EAPKeys.MSK), eapaka.KeyLengthMSK)
	}
	if result.NextMessageID != detail.ChildSAMessageID+1 {
		t.Fatalf("NextMessageID = %d, want %d", result.NextMessageID, detail.ChildSAMessageID+1)
	}
}

// TestInitialIKEAuthRequestCarriesIDrAndEAPOnlyOnTheWire is packet-level
// evidence, not a claim about the code.
//
// It takes the bytes we actually transmitted, decrypts them with the negotiated
// IKE keys and re-parses them. Reading BuildAuthInitialPayloads would prove
// nothing: the question is what left the socket.
func TestInitialIKEAuthRequestCarriesIDrAndEAPOnlyOnTheWire(t *testing.T) {
	l := startLadder(t, nil, nil, nil)
	if _, err := l.run(t); err != nil {
		t.Fatalf("IKE_AUTH: %v", err)
	}
	detail, _ := l.runner.LastDetail()
	if len(detail.Rounds) == 0 {
		t.Fatalf("no rounds recorded")
	}
	wire := detail.Rounds[0].RequestBytes

	// It really is encrypted: the outer message is one SK payload and nothing
	// else, so nothing below can have been read in clear.
	outer, err := ikev2.ParseMessage(wire)
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	if len(outer.Payloads) != 1 || outer.Payloads[0].Type != ikev2.PayloadSK {
		t.Fatalf("the first IKE_AUTH request is not a single SK payload: %v", payloadTypes(outer.Payloads))
	}
	if bytes.Contains(wire, []byte(testEAPIdentity)) {
		t.Fatalf("the NAI appears in clear inside a supposedly encrypted request")
	}

	_, inner, err := ikev2.UnprotectMessage(wire, l.init.Keys, true)
	if err != nil {
		t.Fatalf("UnprotectMessage: %v", err)
	}

	var (
		idi, idr    *ikev2.Identity
		sawEAPOnly  bool
		notifyTypes []uint16
	)
	for _, p := range inner {
		switch p.Type {
		case ikev2.PayloadIDi:
			id, err := ikev2.ParseIdentity(p.Body)
			if err != nil {
				t.Fatalf("ParseIdentity(IDi): %v", err)
			}
			idi = &id
		case ikev2.PayloadIDr:
			id, err := ikev2.ParseIdentity(p.Body)
			if err != nil {
				t.Fatalf("ParseIdentity(IDr): %v", err)
			}
			idr = &id
		case ikev2.PayloadNotify:
			n, err := ikev2.ParseNotify(p.Body)
			if err != nil {
				t.Fatalf("ParseNotify: %v", err)
			}
			notifyTypes = append(notifyTypes, n.NotifyType)
			if n.NotifyType == 16417 {
				sawEAPOnly = true
			}
		}
	}
	if idr == nil {
		t.Fatalf("no IDr on the wire; payload types were %v", payloadTypes(inner))
	}
	if idr.Type != ikev2.IDFQDN || string(idr.Data) != "epdg.epc.mnc260.mcc310.pub.3gppnetwork.org" {
		t.Fatalf("IDr on the wire = type %d %q", idr.Type, idr.Data)
	}
	if idi == nil || string(idi.Data) != testEAPIdentity {
		t.Fatalf("IDi on the wire = %+v", idi)
	}
	if !sawEAPOnly {
		t.Fatalf("no EAP_ONLY_AUTHENTICATION (16417) on the wire; notifies were %v", notifyTypes)
	}

	// And the responder agrees, having decrypted the same datagram itself.
	if !l.epdg.sawEAPOnlyNotify || len(l.epdg.observedIDr) == 0 {
		t.Fatalf("the ePDG did not see IDr / EAP_ONLY_AUTHENTICATION: idr=%d bytes eapOnly=%v",
			len(l.epdg.observedIDr), l.epdg.sawEAPOnlyNotify)
	}
	if !bytes.Equal(l.epdg.observedIDi, mustMarshalIdentity(t, ikev2.Identity{
		Type: ikev2.IDRFC822Addr, Data: []byte(testEAPIdentity),
	})) {
		t.Fatalf("the IDi the ePDG decrypted is not the one we encoded")
	}
}

func mustMarshalIdentity(t *testing.T, id ikev2.Identity) []byte {
	t.Helper()
	body, err := id.MarshalBinary()
	if err != nil {
		t.Fatalf("Identity.MarshalBinary: %v", err)
	}
	return body
}

// TestEveryIKEAuthMessageIsEncrypted checks the datagrams on both sides, not
// just the ones we built.
func TestEveryIKEAuthMessageIsEncrypted(t *testing.T) {
	l := startLadder(t, nil, nil, nil)
	if _, err := l.run(t); err != nil {
		t.Fatalf("IKE_AUTH: %v", err)
	}
	detail, _ := l.runner.LastDetail()
	if len(detail.Rounds) != 4 {
		t.Fatalf("%d rounds", len(detail.Rounds))
	}
	for i, round := range detail.Rounds {
		for label, raw := range map[string][]byte{"request": round.RequestBytes, "response": round.ResponseBytes} {
			msg, err := ikev2.ParseMessage(raw)
			if err != nil {
				t.Fatalf("round %d %s: ParseMessage: %v", i, label, err)
			}
			if len(msg.Payloads) != 1 || msg.Payloads[0].Type != ikev2.PayloadSK {
				t.Fatalf("round %d %s carries %v, want a single SK payload", i, label, payloadTypes(msg.Payloads))
			}
			if msg.Header.ExchangeType != ikev2.ExchangeIKE_AUTH {
				t.Fatalf("round %d %s exchange type %d", i, label, msg.Header.ExchangeType)
			}
		}
		if round.MessageID != uint32(i+1) {
			t.Fatalf("round %d has message id %d", i, round.MessageID)
		}
	}
	// The final response is the only one with an SA, and it also has the AUTH.
	last := detail.Rounds[len(detail.Rounds)-1]
	if !last.SentAuth || !last.GotAuth || !last.GotChildSA {
		t.Fatalf("the last exchange should carry AUTH both ways plus the CHILD_SA: %+v", last)
	}
	for _, round := range detail.Rounds[:len(detail.Rounds)-1] {
		if round.GotChildSA {
			t.Fatalf("message %d carried an SA before the AUTH exchange", round.MessageID)
		}
	}
}

// TestAuthRunnerRejectsAForgedResponderAuth is the negative half of "the peer
// AUTH is really verified". The ePDG flips one bit of its own AUTH; everything
// else about the exchange stays valid.
func TestAuthRunnerRejectsAForgedResponderAuth(t *testing.T) {
	l := startLadder(t, func(a *epdgAuth) { a.corruptOwnAuth = true }, nil, nil)
	result, err := l.run(t)
	if !errors.Is(err, ErrPeerAuthFailed) {
		t.Fatalf("err = %v, want ErrPeerAuthFailed", err)
	}
	if result.ChildSA != nil {
		t.Fatalf("a CHILD_SA was accepted from a peer whose AUTH did not verify")
	}
	detail, _ := l.runner.LastDetail()
	if detail.PeerAuthVerified {
		t.Fatalf("PeerAuthVerified is set after a rejection")
	}
	if len(detail.PeerAuth) == 0 {
		t.Fatalf("the rejected AUTH was not recorded, so a live failure could not be diagnosed")
	}
	// The forgery has to be one bit away from correct, otherwise the test would
	// pass for the wrong reason - e.g. a length or method mismatch.
	if !l.epdg.clientAuthVerified {
		t.Fatalf("the ePDG rejected our AUTH too; this test is no longer isolating the responder side")
	}
}

// TestAuthRunnerRejectsAMissingResponderAuth covers the other way to end up
// unauthenticated: nothing at all in the AUTH slot.
func TestAuthRunnerRejectsAMissingResponderAuth(t *testing.T) {
	l := startLadder(t, func(a *epdgAuth) { a.omitOwnAuth = true }, nil, nil)
	_, err := l.run(t)
	if !errors.Is(err, ErrPeerAuthMissing) {
		t.Fatalf("err = %v, want ErrPeerAuthMissing", err)
	}

	// And it is opt-out-able, on purpose and loudly.
	l2 := startLadder(t, func(a *epdgAuth) { a.omitOwnAuth = true },
		func(r *AuthRunner) { r.AllowMissingPeerAuth = true }, nil)
	result, err := l2.run(t)
	if err != nil {
		t.Fatalf("AllowMissingPeerAuth still failed: %v", err)
	}
	if result.ChildSA == nil {
		t.Fatalf("no CHILD_SA on the opt-out path")
	}
	detail, _ := l2.runner.LastDetail()
	if detail.PeerAuthVerified {
		t.Fatalf("PeerAuthVerified must stay false when there was no AUTH to verify")
	}
}

// TestAuthRunnerRejectsAnUnexpectedAuthMethod guards the byte the card calls the
// most likely thing to be wrong. A responder answering with a different Auth
// Method is not a peer we can verify with the MSK.
func TestAuthRunnerRejectsAnUnexpectedAuthMethod(t *testing.T) {
	l := startLadder(t, func(a *epdgAuth) { a.authMethod = 1 }, nil, nil) // 1 = RSA digital signature
	_, err := l.run(t)
	if !errors.Is(err, ErrPeerAuthMethod) {
		t.Fatalf("err = %v, want ErrPeerAuthMethod", err)
	}
}

// TestAuthRunnerRefusesCertificateAuthenticationAfterAskingForEAPOnly covers a
// responder that ignored RFC 5998 and authenticated itself in the first
// response. We cannot validate a certificate chain, so continuing would make
// "the responder authenticated" a false statement.
func TestAuthRunnerRefusesCertificateAuthenticationAfterAskingForEAPOnly(t *testing.T) {
	l := startLadder(t, func(a *epdgAuth) { a.certAuthInFirstResponse = true }, nil, nil)
	_, err := l.run(t)
	if !errors.Is(err, ErrResponderIgnoredEAPOnly) {
		t.Fatalf("err = %v, want ErrResponderIgnoredEAPOnly", err)
	}
	detail, _ := l.runner.LastDetail()
	if detail.EarlyPeerAuthMethod != 1 {
		t.Fatalf("EarlyPeerAuthMethod = %d, want the method the responder actually used", detail.EarlyPeerAuthMethod)
	}
}

// TestAuthRunnerRejectsEAPSuccessSharingTheChildSA makes the wrong ladder real
// and checks that we refuse it.
//
// T041a's fixture could only assert that its own fake kept the two apart. This
// one has the fake do the wrong thing on purpose, so the refusal is the
// runner's, not the fixture's.
func TestAuthRunnerRejectsEAPSuccessSharingTheChildSA(t *testing.T) {
	l := startLadder(t, func(a *epdgAuth) { a.eapSuccessCarriesChildSA = true }, nil, nil)
	result, err := l.run(t)
	if !errors.Is(err, ErrEAPSuccessWithChildSA) {
		t.Fatalf("err = %v, want ErrEAPSuccessWithChildSA", err)
	}
	if result.ChildSA != nil {
		t.Fatalf("a CHILD_SA was taken before any AUTH was exchanged")
	}
}

// TestAuthRunnerRefusesToRunWithoutAnIDr is the same decision T041a made about
// NAT_DETECTION: a missing payload must be an error, not a quieter request.
func TestAuthRunnerRefusesToRunWithoutAnIDr(t *testing.T) {
	l := startLadder(t, nil, func(r *AuthRunner) { r.ResponderID = ikev2.Identity{} }, nil)
	_, err := l.run(t)
	if !errors.Is(err, ErrMissingResponderID) {
		t.Fatalf("err = %v, want ErrMissingResponderID", err)
	}
	if len(l.epdg.initialPayloadTypes) != 0 {
		t.Fatalf("a request went out anyway: %v", l.epdg.initialPayloadTypes)
	}
}

// TestAuthRunnerRejectsAnInitResultWithoutTheSignedMessages: RFC 7296 2.15
// signs the IKE_SA_INIT messages verbatim, so an InitResult that dropped them
// cannot produce a correct AUTH. Failing loudly beats signing the wrong thing.
func TestAuthRunnerRejectsAnInitResultWithoutTheSignedMessages(t *testing.T) {
	l := startLadder(t, nil, nil, nil)
	cfg := l.authConfig()
	cfg.Init.RequestBytes = nil
	if _, err := l.runner.Run(context.Background(), cfg); !errors.Is(err, ErrInvalidAuthConfig) {
		t.Fatalf("err = %v, want ErrInvalidAuthConfig", err)
	}
}

// TestAuthRunnerSatisfiesTheMirrorSeam is the compile-time claim made explicit.
func TestAuthRunnerSatisfiesTheMirrorSeam(t *testing.T) {
	var runner swu.IKEAuthRunner = NewAuthRunner(IdentityFQDN("epdg.example")).Run
	if runner == nil {
		t.Fatalf("AuthRunner.Run does not fit swu.IKEAuthRunner")
	}
}

// TestSyncFailureSendsATAUTSAndResynchronises covers the first of the two
// failure paths eapaka hands us for free.
//
// The card reports SQN desynchronisation, eapaka.BuildChallengeResponseFromProvider
// turns sim.ErrSyncFailure into an EAP-Response/AKA-Synchronization-Failure
// carrying AT_AUTS, and the ePDG resynchronises and challenges again. The proof
// that the conversion really happened is on the responder's side: it decrypted
// the packet and read the AUTS out of it.
func TestSyncFailureSendsATAUTSAndResynchronises(t *testing.T) {
	l := startLadder(t, nil, nil, nil)
	l.provider.syncFailOn[1] = true

	result, err := l.run(t)
	if err != nil {
		t.Fatalf("IKE_AUTH should have recovered after resynchronisation: %v", err)
	}
	if l.epdg.syncFailures != 1 {
		t.Fatalf("the ePDG saw %d synchronisation failures, want 1", l.epdg.syncFailures)
	}
	if !bytes.Equal(l.epdg.observedAUTS, l.provider.auts) {
		t.Fatalf("AT_AUTS on the wire = %x, card returned %x", l.epdg.observedAUTS, l.provider.auts)
	}
	if len(l.epdg.observedAUTS) != eapaka.AUTSLength {
		t.Fatalf("AT_AUTS is %d octets, RFC 4187 says %d", len(l.epdg.observedAUTS), eapaka.AUTSLength)
	}
	want := []uint8{eapaka.SubtypeIdentity, eapaka.SubtypeSynchronizationFailure, eapaka.SubtypeChallenge}
	if got := l.epdg.eapResponses; len(got) != len(want) {
		t.Fatalf("EAP-Response subtypes = %v, want %v", got, want)
	} else {
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("EAP-Response subtypes = %v, want %v", got, want)
			}
		}
	}
	if l.epdg.challenges != 2 {
		t.Fatalf("the ePDG issued %d challenges, want 2 (original plus resynchronised)", l.epdg.challenges)
	}
	if l.provider.callCount() != 2 {
		t.Fatalf("the card was asked %d times, want 2", l.provider.callCount())
	}
	detail, _ := l.runner.LastDetail()
	if detail.SyncFailures != 1 {
		t.Fatalf("detail.SyncFailures = %d", detail.SyncFailures)
	}
	if !result.SyncFailure {
		t.Fatalf("FullAuthResult.SyncFailure was not reported upstack")
	}
	if result.ChildSA == nil {
		t.Fatalf("the tunnel did not come up after resynchronisation")
	}
}

// TestSyncFailureGivesUpWhenItKeepsHappening bounds the resynchronisation loop.
func TestSyncFailureGivesUpWhenItKeepsHappening(t *testing.T) {
	l := startLadder(t, nil, nil, nil)
	for i := 1; i <= 4; i++ {
		l.provider.syncFailOn[i] = true
	}
	_, err := l.run(t)
	if !errors.Is(err, ErrAKASyncFailure) {
		t.Fatalf("err = %v, want ErrAKASyncFailure", err)
	}
	if l.epdg.syncFailures < 2 {
		t.Fatalf("only %d AT_AUTS reached the ePDG; the budget should allow at least one retry",
			l.epdg.syncFailures)
	}
}

// TestAuthFailureSendsAuthenticationReject covers the second free failure path.
//
// The card rejects AUTN, eapaka turns sim.ErrAuthFailure into an
// EAP-Response/AKA-Authentication-Reject, and we stop with a named error rather
// than retrying against a network we just decided is not ours.
func TestAuthFailureSendsAuthenticationReject(t *testing.T) {
	l := startLadder(t, nil, nil, nil)
	l.provider.authFailOn[1] = true

	result, err := l.run(t)
	if !errors.Is(err, ErrAKAAuthFailure) {
		t.Fatalf("err = %v, want ErrAKAAuthFailure", err)
	}
	if result.ChildSA != nil {
		t.Fatalf("a CHILD_SA came out of a rejected authentication")
	}
	if l.epdg.authRejects != 1 {
		t.Fatalf("the ePDG saw %d Authentication-Reject packets, want 1", l.epdg.authRejects)
	}
	want := []uint8{eapaka.SubtypeIdentity, eapaka.SubtypeAuthenticationReject}
	got := l.epdg.eapResponses
	if len(got) != len(want) || got[1] != eapaka.SubtypeAuthenticationReject {
		t.Fatalf("EAP-Response subtypes = %v, want %v", got, want)
	}
	if l.epdg.syncFailures != 0 {
		t.Fatalf("an authentication reject was misclassified as a synchronisation failure")
	}
	detail, _ := l.runner.LastDetail()
	if detail.AuthRejects != 1 {
		t.Fatalf("detail.AuthRejects = %d", detail.AuthRejects)
	}
	if !result.AuthFailure {
		t.Fatalf("FullAuthResult.AuthFailure was not reported upstack")
	}
}

// TestAuthLadderRecordsAndReplaysByteForByte is the cross-phase deliverable:
// record the whole encrypted IKE_AUTH ladder, then reproduce every outgoing
// datagram offline, with no socket and no card.
//
// IKE_SA_INIT needed three pinned values (SPI, nonce, DH scalar). IKE_AUTH adds
// three more sources of fresh randomness - the child SPI, one CBC IV per
// protected message, and the card's answers - and every one of them changes the
// ciphertext. capture.AuthSeed carries all three; without it a "replay" would
// only be a re-run that happens to reach the same conclusion.
func TestAuthLadderRecordsAndReplaysByteForByte(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ike-auth.pcap")
	writer, err := capture.NewWriter(capture.WriterOptions{
		Path:          path,
		RecordSecrets: true,
		Note:          "T041b loopback fake ePDG, encrypted IKE_AUTH ladder",
	})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	l := startLadder(t, nil, nil, writer)
	live, err := l.run(t)
	if err != nil {
		t.Fatalf("live IKE_AUTH: %v", err)
	}
	liveDetail, _ := l.runner.LastDetail()
	if err := writer.Close(); err != nil {
		t.Fatalf("writer Close: %v", err)
	}

	recording, err := capture.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	authSeed := recording.Session.AuthSeed
	if !authSeed.Valid() {
		t.Fatalf("the sidecar has no usable auth seed: %+v", authSeed)
	}
	if len(authSeed.IVs) != len(liveDetail.IVs) || len(authSeed.IVs) != 4 {
		t.Fatalf("recorded %d IVs, the ladder used %d and should have used 4",
			len(authSeed.IVs), len(liveDetail.IVs))
	}
	if len(authSeed.AKA) != 1 || len(authSeed.AKA[0].RES) == 0 {
		t.Fatalf("the card's answer was not recorded: %+v", authSeed.AKA)
	}
	if authSeed.EAPIdentity != testEAPIdentity {
		t.Fatalf("recorded identity %q", authSeed.EAPIdentity)
	}

	replay, seed, err := capture.OpenReplay(path, capture.ReplayOptions{
		UseNonESPMarker:      true,
		RequireExactRequests: true,
	})
	if err != nil {
		t.Fatalf("OpenReplay: %v", err)
	}
	if !seed.Valid() {
		t.Fatalf("the IKE_SA_INIT seed is unusable")
	}

	offlineInit := NewInitRunner()
	offlineInit.Seed = seed
	replayedInit, err := offlineInit.Run(context.Background(), ikev2.InitConfig{
		Transport:  replay,
		LocalIP:    l.socket.LocalIP(),
		LocalPort:  l.socket.LocalPort(),
		RemoteIP:   l.fake.Addr().IP,
		RemotePort: uint16(l.fake.Addr().Port),
	})
	if err != nil {
		t.Fatalf("offline IKE_SA_INIT: %v", err)
	}

	// Everything the replay needs comes out of the sidecar, not out of the live
	// fixture: a recording that still needed the test to remember the IDr would
	// not be replayable at 3am from a pcap alone.
	if authSeed.ResponderIDType == 0 || len(authSeed.ResponderID) == 0 ||
		authSeed.InitiatorIDType == 0 || len(authSeed.InitiatorID) == 0 {
		t.Fatalf("the sidecar does not carry both identities: %+v", authSeed)
	}
	offlineAuth := NewAuthRunner(ikev2.Identity{Type: authSeed.ResponderIDType, Data: authSeed.ResponderID})
	offlineAuth.ChildSPI = authSeed.ChildSPI
	offlineAuth.PinnedIVs = authSeed.IVs
	replayed, err := offlineAuth.Run(context.Background(), ikev2.FullAuthConfig{
		Transport:   replay,
		Init:        replayedInit,
		Keys:        replayedInit.Keys,
		SIM:         NewRecordedAKAProvider(authSeed.AKA),
		InitiatorID: ikev2.Identity{Type: authSeed.InitiatorIDType, Data: authSeed.InitiatorID},
		EAPIdentity: authSeed.EAPIdentity,
	})
	if err != nil {
		t.Fatalf("offline IKE_AUTH: %v", err)
	}
	replayedDetail, _ := offlineAuth.LastDetail()

	if len(replayedDetail.Rounds) != len(liveDetail.Rounds) {
		t.Fatalf("replay took %d exchanges, the recording has %d",
			len(replayedDetail.Rounds), len(liveDetail.Rounds))
	}
	for i := range liveDetail.Rounds {
		if !bytes.Equal(replayedDetail.Rounds[i].RequestBytes, liveDetail.Rounds[i].RequestBytes) {
			t.Fatalf("replayed request %d differs from the recording (%d vs %d octets)",
				i, len(replayedDetail.Rounds[i].RequestBytes), len(liveDetail.Rounds[i].RequestBytes))
		}
		if !bytes.Equal(replayedDetail.Rounds[i].ResponseBytes, liveDetail.Rounds[i].ResponseBytes) {
			t.Fatalf("replayed response %d differs from the recording", i)
		}
	}
	if !bytes.Equal(replayedDetail.LocalAuth, liveDetail.LocalAuth) {
		t.Fatalf("the replay computed a different AUTH")
	}
	if !replayedDetail.PeerAuthVerified {
		t.Fatalf("the replay did not verify the recorded responder AUTH")
	}
	if replayed.ChildSA == nil || !bytes.Equal(replayed.ChildSA.RemoteSPI, live.ChildSA.RemoteSPI) {
		t.Fatalf("the replay produced a different CHILD_SA")
	}

	assertAuthPayloadsAreExportable(t, recording, replayedInit.Keys, liveDetail)
	exportCapture(t, path)
}

// TestTheCFGVariantSurvivesIntoTheSidecarAndBackOut is what keeps every older
// recording replayable while T081 keeps moving the default.
//
// The CFG_REQUEST is inside the first protected message, so changing it changes
// that message's ciphertext. Without the variant in the sidecar, the day
// DefaultConfigVariant moves is the day /root/t072/epdg-challenge.pcap - the
// only recording of a real carrier accepting this card - stops reproducing its
// own bytes, and nothing would say why.
//
// The second half is the part that makes this a test rather than a
// demonstration: a replay that ignores the recorded variant and uses the
// default must fail the byte comparison. If it passed, the field would be
// decoration.
func TestTheCFGVariantSurvivesIntoTheSidecarAndBackOut(t *testing.T) {
	const recorded = ConfigVariantIPv6
	if recorded == DefaultConfigVariant {
		t.Fatalf("this test needs a variant that is not the default, or it proves nothing")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "ike-auth-ipv6.pcap")
	writer, err := capture.NewWriter(capture.WriterOptions{
		Path:          path,
		RecordSecrets: true,
		Note:          "T081 loopback fake ePDG, CFG_REQUEST variant " + string(recorded),
	})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	l := startLadder(t, nil, func(r *AuthRunner) { r.ConfigVariant = recorded }, writer)
	if _, err := l.run(t); err != nil {
		t.Fatalf("live IKE_AUTH: %v", err)
	}
	liveDetail, _ := l.runner.LastDetail()
	if err := writer.Close(); err != nil {
		t.Fatalf("writer Close: %v", err)
	}
	if liveDetail.ConfigVariant != recorded {
		t.Fatalf("the runner recorded variant %q", liveDetail.ConfigVariant)
	}
	if !configurationHasAttribute(liveDetail.SentConfiguration, ConfigPCSCFIPv6Address) {
		t.Fatalf("SentConfiguration does not describe what went out: %s",
			DescribeConfiguration(liveDetail.SentConfiguration))
	}

	recording, err := capture.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	seed := recording.Session.AuthSeed
	if seed == nil || seed.ConfigVariant != string(recorded) {
		t.Fatalf("the sidecar does not carry the variant: %+v", seed)
	}

	replayFrom := func(variant ConfigVariant) ([]byte, error) {
		transport, initSeed, err := capture.OpenReplay(path, capture.ReplayOptions{
			UseNonESPMarker:      true,
			RequireExactRequests: true,
		})
		if err != nil {
			return nil, err
		}
		offlineInit := NewInitRunner()
		offlineInit.Seed = initSeed
		replayedInit, err := offlineInit.Run(context.Background(), ikev2.InitConfig{
			Transport:  transport,
			LocalIP:    l.socket.LocalIP(),
			LocalPort:  l.socket.LocalPort(),
			RemoteIP:   l.fake.Addr().IP,
			RemotePort: uint16(l.fake.Addr().Port),
		})
		if err != nil {
			return nil, err
		}
		offlineAuth := NewAuthRunner(ikev2.Identity{Type: seed.ResponderIDType, Data: seed.ResponderID})
		offlineAuth.ChildSPI = seed.ChildSPI
		offlineAuth.PinnedIVs = seed.IVs
		offlineAuth.ConfigVariant = variant
		_, err = offlineAuth.Run(context.Background(), ikev2.FullAuthConfig{
			Transport:   transport,
			Init:        replayedInit,
			Keys:        replayedInit.Keys,
			SIM:         NewRecordedAKAProvider(seed.AKA),
			InitiatorID: ikev2.Identity{Type: seed.InitiatorIDType, Data: seed.InitiatorID},
			EAPIdentity: seed.EAPIdentity,
		})
		detail, _ := offlineAuth.LastDetail()
		if len(detail.Rounds) == 0 {
			return nil, err
		}
		return detail.Rounds[0].RequestBytes, err
	}

	fromSeed, err := replayFrom(ConfigVariant(seed.ConfigVariant))
	if err != nil {
		t.Fatalf("replaying with the recorded variant: %v", err)
	}
	if !bytes.Equal(fromSeed, liveDetail.Rounds[0].RequestBytes) {
		t.Fatalf("the recorded variant did not reproduce the first request")
	}

	fromDefault, err := replayFrom(DefaultConfigVariant)
	if err == nil && bytes.Equal(fromDefault, liveDetail.Rounds[0].RequestBytes) {
		t.Fatalf("replaying with the wrong variant still matched, so the sidecar field guards nothing")
	}
}

// assertAuthPayloadsAreExportable is the "pull the AUTH payload out on its own"
// requirement. When the first live contact fails, this is the tool that answers
// "what exactly did we put in AUTH" without a Wireshark session that has keys.
func assertAuthPayloadsAreExportable(t *testing.T, c *capture.Capture, keys ikev2.IKEKeys, detail AuthDetail) {
	t.Helper()
	records, err := c.AuthPayloads(keys)
	if err != nil {
		t.Fatalf("AuthPayloads: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("found %d AUTH payloads in the recording, want 2 (ours and theirs)", len(records))
	}
	var sent, received *capture.AuthRecord
	for i := range records {
		switch records[i].Dir {
		case capture.DirTx:
			sent = &records[i]
		case capture.DirRx:
			received = &records[i]
		}
	}
	if sent == nil || received == nil {
		t.Fatalf("AUTH payloads were not found in both directions: %+v", records)
	}
	for _, rec := range records {
		if !rec.Encrypted {
			t.Fatalf("an AUTH payload was found outside an SK payload; the ladder was not encrypted")
		}
		// Raw octets, checked here rather than through our own decoder: this is
		// the four-byte header the card flags as most likely to be wrong.
		if len(rec.Body) != 4+32 {
			t.Fatalf("AUTH body is %d octets, want 4 header + 32 of HMAC-SHA-256", len(rec.Body))
		}
		if rec.Body[0] != 2 {
			t.Fatalf("AUTH method octet is %d, want 2", rec.Body[0])
		}
		if !bytes.Equal(rec.Body[1:4], []byte{0, 0, 0}) {
			t.Fatalf("AUTH RESERVED octets are %v", rec.Body[1:4])
		}
	}
	if !bytes.Equal(sent.Body[4:], detail.LocalAuth) {
		t.Fatalf("the exported outbound AUTH is not the one the runner computed")
	}
	if !bytes.Equal(received.Body[4:], detail.PeerAuth) {
		t.Fatalf("the exported inbound AUTH is not the one the runner verified")
	}
	if sent.MessageID != detail.ChildSAMessageID || received.MessageID != detail.ChildSAMessageID {
		t.Fatalf("AUTH payloads are in messages %d/%d, expected %d",
			sent.MessageID, received.MessageID, detail.ChildSAMessageID)
	}
}

// TestANoneVariantRecordingReplaysAsARequestWithNoCP is the same guarantee for
// the one variant whose request is defined by a payload that is not there.
//
// It is a separate test rather than another value in the one above because the
// failure mode is different in kind. Every other variant differs from its
// neighbours by attribute bytes inside a payload that is always present; this
// one differs by the payload's existence, and the code paths that could get it
// wrong - the emptiness test in BuildAuthInitialPayloads, the opt-out
// derivation in the session, configFromPayloads with nothing to read - are all
// paths the other variants never take. A recording of the live run is the only
// artefact T088 produces, so it has to reproduce its own bytes offline before
// anyone spends an SQN step making one.
func TestANoneVariantRecordingReplaysAsARequestWithNoCP(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ike-auth-none.pcap")
	writer, err := capture.NewWriter(capture.WriterOptions{
		Path:          path,
		RecordSecrets: true,
		Note:          "T088 loopback fake ePDG, no CFG_REQUEST at all",
	})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	l := startLadder(t, nil, func(r *AuthRunner) { r.ConfigVariant = ConfigVariantNone }, writer)
	if _, err := l.run(t); err != nil {
		t.Fatalf("live IKE_AUTH: %v", err)
	}
	liveDetail, _ := l.runner.LastDetail()
	if err := writer.Close(); err != nil {
		t.Fatalf("writer Close: %v", err)
	}
	if liveDetail.SentCP {
		t.Fatalf("the recorded run sent a CP payload")
	}
	if DescribeConfiguration(liveDetail.SentConfiguration) != "(no CP payload)" {
		t.Fatalf("SentConfiguration does not describe an absent payload: %s",
			DescribeConfiguration(liveDetail.SentConfiguration))
	}
	// The responder is the only witness that the payload was absent on the wire
	// rather than merely absent from our own bookkeeping.
	if l.epdg.sawCP {
		t.Fatalf("the responder decoded a CP payload on a run that sent none")
	}

	recording, err := capture.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	seed := recording.Session.AuthSeed
	if seed == nil || seed.ConfigVariant != string(ConfigVariantNone) {
		t.Fatalf("the sidecar does not carry the variant: %+v", seed)
	}

	transport, initSeed, err := capture.OpenReplay(path, capture.ReplayOptions{
		UseNonESPMarker:      true,
		RequireExactRequests: true,
	})
	if err != nil {
		t.Fatalf("OpenReplay: %v", err)
	}
	offlineInit := NewInitRunner()
	offlineInit.Seed = initSeed
	replayedInit, err := offlineInit.Run(context.Background(), ikev2.InitConfig{
		Transport:  transport,
		LocalIP:    l.socket.LocalIP(),
		LocalPort:  l.socket.LocalPort(),
		RemoteIP:   l.fake.Addr().IP,
		RemotePort: uint16(l.fake.Addr().Port),
	})
	if err != nil {
		t.Fatalf("replaying IKE_SA_INIT: %v", err)
	}
	offlineAuth := NewAuthRunner(ikev2.Identity{Type: seed.ResponderIDType, Data: seed.ResponderID})
	offlineAuth.ChildSPI = seed.ChildSPI
	offlineAuth.PinnedIVs = seed.IVs
	offlineAuth.ConfigVariant = ConfigVariant(seed.ConfigVariant)
	if _, err := offlineAuth.Run(context.Background(), ikev2.FullAuthConfig{
		Transport:   transport,
		Init:        replayedInit,
		Keys:        replayedInit.Keys,
		SIM:         NewRecordedAKAProvider(seed.AKA),
		InitiatorID: ikev2.Identity{Type: seed.InitiatorIDType, Data: seed.InitiatorID},
		EAPIdentity: seed.EAPIdentity,
	}); err != nil {
		t.Fatalf("replaying IKE_AUTH from the recorded variant: %v", err)
	}
	offlineDetail, _ := offlineAuth.LastDetail()
	if len(offlineDetail.Rounds) == 0 || len(liveDetail.Rounds) == 0 {
		t.Fatalf("no rounds to compare")
	}
	if !bytes.Equal(offlineDetail.Rounds[0].RequestBytes, liveDetail.Rounds[0].RequestBytes) {
		t.Fatalf("the recorded variant did not reproduce the first request byte for byte")
	}
	if offlineDetail.SentCP {
		t.Fatalf("the replay put a CP payload back into a request that had none")
	}
}
