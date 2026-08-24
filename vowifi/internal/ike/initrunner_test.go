package ike

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/boa-z/vowifi-go/engine/swu/ikev2"

	"github.com/yuanshuai1122/vodoge-edge/vowifi/internal/capture"
)

// TestInitRunnerCompletesAgainstFakeEPDG is the acceptance test for T041a: a
// full IKE_SA_INIT over the real socket against a loopback ePDG that selects
// group 14, with a fully populated ikev2.InitResult at the end.
func TestInitRunnerCompletesAgainstFakeEPDG(t *testing.T) {
	f := newFakeEPDG(t)
	f.Start()
	s := dialFake(t, f, SocketConfig{})

	runner := NewInitRunner()
	cfg := initConfig(t, s)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	result, err := runner.Run(ctx, cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	detail, ok := runner.LastDetail()
	if !ok {
		t.Fatalf("LastDetail is empty")
	}
	if detail.Selection.DHGroup != GroupMODP2048 {
		t.Fatalf("negotiated %s, want MODP-2048; T038 measured 7/7 ePDGs choosing group 14",
			DHGroupName(detail.Selection.DHGroup))
	}
	if got := OfferedGroups(detail.Offered); len(got) != 4 {
		t.Fatalf("offered groups = %v, want the four T038 measured", got)
	}

	// Every field the downstream IKE_AUTH stage (T041b) will read.
	if result.InitiatorSPI == 0 || result.ResponderSPI == 0 {
		t.Errorf("SPIs = %#x/%#x, both must be non-zero", result.InitiatorSPI, result.ResponderSPI)
	}
	if len(result.NonceI) != DefaultNonceLength {
		t.Errorf("NonceI = %d octets, want %d", len(result.NonceI), DefaultNonceLength)
	}
	if len(result.NonceR) < 16 {
		t.Errorf("NonceR = %d octets, want at least 16 (RFC 7296 2.10)", len(result.NonceR))
	}
	if len(result.SharedSecret) != 256 {
		t.Errorf("SharedSecret = %d octets, want 256 for MODP-2048", len(result.SharedSecret))
	}
	if len(result.PublicKeyI) != 256 || len(result.PublicKeyR) != 256 {
		t.Errorf("KE values = %d/%d octets, want 256 each", len(result.PublicKeyI), len(result.PublicKeyR))
	}
	if len(result.SKEYSEED) == 0 || len(result.KeyMaterial) == 0 {
		t.Errorf("SKEYSEED/KeyMaterial were not derived")
	}
	for name, key := range map[string][]byte{
		"SK_d": result.Keys.SKD, "SK_ai": result.Keys.SKAi, "SK_ar": result.Keys.SKAr,
		"SK_ei": result.Keys.SKEi, "SK_er": result.Keys.SKEr,
		"SK_pi": result.Keys.SKPi, "SK_pr": result.Keys.SKPr,
	} {
		if len(key) == 0 {
			t.Errorf("%s is empty; IKE_AUTH cannot proceed without it", name)
		}
	}
	if !result.MOBIKESupported {
		t.Errorf("MOBIKESupported = false, the fake advertised it")
	}
	if len(result.RequestBytes) == 0 || len(result.ResponseBytes) == 0 {
		t.Errorf("raw bytes were not retained, so no capture is possible")
	}
	if !detail.Seed.Valid() {
		t.Errorf("replay seed is incomplete: %+v", detail.Seed)
	}
}

// TestInitRunnerActuallySendsNATDetection is packet-level evidence.
//
// The stock stack sends nothing here: initNATPayloads (init.go:371-373) returns
// nil whenever LocalPort is zero, which is the normal case because the mirror's
// own ikev2.UDPTransport dials without binding. This test parses the bytes that
// went on the wire and recomputes both hashes independently.
func TestInitRunnerActuallySendsNATDetection(t *testing.T) {
	f := newFakeEPDG(t)
	f.Start()
	s := dialFake(t, f, SocketConfig{})

	runner := NewInitRunner()
	cfg := initConfig(t, s)
	result, err := runner.Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	sent, err := ikev2.ParseMessage(result.RequestBytes)
	if err != nil {
		t.Fatalf("re-parsing our own request: %v", err)
	}
	var src, dst *ikev2.Notify
	for _, p := range sent.Payloads {
		if p.Type != ikev2.PayloadNotify {
			continue
		}
		n, err := ikev2.ParseNotify(p.Body)
		if err != nil {
			t.Fatalf("ParseNotify: %v", err)
		}
		switch n.NotifyType {
		case ikev2.NotifyNATDetectionSourceIP:
			copied := n
			src = &copied
		case ikev2.NotifyNATDetectionDestinationIP:
			copied := n
			dst = &copied
		}
	}
	if src == nil || dst == nil {
		t.Fatalf("NAT_DETECTION_SOURCE_IP present=%v DESTINATION_IP present=%v; we sent neither, which is the exact stock-stack bug",
			src != nil, dst != nil)
	}

	// RFC 7296 section 2.23: SHA-1 over SPIi || SPIr || IP || port, with the
	// responder SPI still zero in the request.
	wantSrc, err := ikev2.NATDetectionHash(result.InitiatorSPI, 0, cfg.LocalIP, cfg.LocalPort)
	if err != nil {
		t.Fatalf("NATDetectionHash: %v", err)
	}
	wantDst, err := ikev2.NATDetectionHash(result.InitiatorSPI, 0, cfg.RemoteIP, cfg.RemotePort)
	if err != nil {
		t.Fatalf("NATDetectionHash: %v", err)
	}
	if len(wantSrc) != 20 {
		t.Fatalf("hash length = %d, want 20 (SHA-1)", len(wantSrc))
	}
	if !bytes.Equal(src.NotificationData, wantSrc) {
		t.Errorf("SOURCE_IP hash mismatch:\n got %x\nwant %x", src.NotificationData, wantSrc)
	}
	if !bytes.Equal(dst.NotificationData, wantDst) {
		t.Errorf("DESTINATION_IP hash mismatch:\n got %x\nwant %x", dst.NotificationData, wantDst)
	}

	detail, _ := runner.LastDetail()
	if !detail.NAT.Sent {
		t.Errorf("NATDetection.Sent = false despite both notifies being on the wire")
	}
	if !detail.NAT.ResponderSentSource || !detail.NAT.ResponderSentDestination {
		t.Errorf("the fake echoed NAT-D but we did not record it: %+v", detail.NAT)
	}
	// Loopback has no NAT, so neither side should look rewritten. If this ever
	// flips on the real edge machine, that is the Dallas egress rewriting our
	// source port, which T038 already measured (local 4500 -> apparent 37343).
	if detail.NAT.BehindNAT || detail.NAT.PeerBehindNAT {
		t.Errorf("NAT detected on loopback: %+v", detail.NAT)
	}
	if result.NATDetected {
		t.Errorf("InitResult.NATDetected = true on loopback")
	}
}

// TestInitRunnerRefusesToSilentlySkipNATDetection locks in the design choice.
func TestInitRunnerRefusesToSilentlySkipNATDetection(t *testing.T) {
	f := newFakeEPDG(t)
	f.Start()
	s := dialFake(t, f, SocketConfig{})

	cfg := initConfig(t, s)
	cfg.LocalPort = 0 // exactly the condition that makes init.go:371-373 return nil

	runner := NewInitRunner()
	_, err := runner.Run(context.Background(), cfg)
	if !errors.Is(err, ErrMissingNATDetectionInputs) {
		t.Fatalf("Run error = %v, want ErrMissingNATDetectionInputs", err)
	}

	// The escape hatch must exist, but it has to be asked for.
	runner.AllowMissingNATDetection = true
	result, err := runner.Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run with AllowMissingNATDetection: %v", err)
	}
	detail, _ := runner.LastDetail()
	if detail.NAT.Sent {
		t.Errorf("NAT-D reported as sent when it was skipped")
	}
	if result.NATDetected {
		t.Errorf("NATDetected = true without any NAT-D payloads")
	}
}

// TestInitRunnerSwitchesGroupOnInvalidKE wires up
// Notify.InvalidKEPayloadAlternativeGroup (payloads.go:119), which the mirror
// exports and never calls.
func TestInitRunnerSwitchesGroupOnInvalidKE(t *testing.T) {
	f := newFakeEPDG(t)
	f.demandGroup = GroupMODP2048
	f.Start()
	s := dialFake(t, f, SocketConfig{})

	runner := NewInitRunner()
	// Start on group 31, the group the stock stack hardcodes at init.go:159 and
	// the one no ePDG in T038 chose.
	runner.Groups = []uint16{GroupX25519, GroupMODP2048, GroupMODP1024, GroupECP256}

	result, err := runner.Run(context.Background(), initConfig(t, s))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	detail, _ := runner.LastDetail()
	if len(detail.GroupsTried) != 2 {
		t.Fatalf("GroupsTried = %v, want two entries", detail.GroupsTried)
	}
	if detail.GroupsTried[0] != GroupX25519 || detail.GroupsTried[1] != GroupMODP2048 {
		t.Fatalf("GroupsTried = %v, want [31 14]", detail.GroupsTried)
	}
	if detail.Selection.DHGroup != GroupMODP2048 {
		t.Fatalf("settled on %s, want MODP-2048", DHGroupName(detail.Selection.DHGroup))
	}
	if len(result.SharedSecret) != 256 {
		t.Fatalf("shared secret is %d octets, so the retry did not re-key for the new group", len(result.SharedSecret))
	}
	if got := f.offeredGroups(); len(got) != 2 || got[0] != GroupX25519 || got[1] != GroupMODP2048 {
		t.Fatalf("fake ePDG saw KE groups %v, want [31 14]", got)
	}
}

func TestInitRunnerRejectsUnofferedAlternativeGroup(t *testing.T) {
	f := newFakeEPDG(t)
	f.demandGroup = GroupECP384 // never in DefaultProposalGroups
	f.Start()
	s := dialFake(t, f, SocketConfig{})

	runner := NewInitRunner()
	_, err := runner.Run(context.Background(), initConfig(t, s))
	if !errors.Is(err, ErrGroupNegotiationFailed) {
		t.Fatalf("Run error = %v, want ErrGroupNegotiationFailed", err)
	}
}

// TestInitRunnerHandlesCookie covers RFC 7296 section 2.6.
func TestInitRunnerHandlesCookie(t *testing.T) {
	f := newFakeEPDG(t)
	f.requireCookie = true
	f.Start()
	s := dialFake(t, f, SocketConfig{})

	runner := NewInitRunner()
	result, err := runner.Run(context.Background(), initConfig(t, s))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	detail, _ := runner.LastDetail()
	if detail.CookieRounds != 1 {
		t.Fatalf("CookieRounds = %d, want 1", detail.CookieRounds)
	}
	if result.ResponderSPI == 0 {
		t.Fatalf("no SA established after the cookie round trip")
	}
	f.mu.Lock()
	seen := f.cookiesSeen
	f.mu.Unlock()
	if seen != 1 {
		t.Fatalf("fake ePDG saw %d cookie echoes, want 1", seen)
	}
}

// TestInitRunnerUsesConfigSPIAndNonce is the forward-compatibility clause: if a
// later mirror starts filling InitiatorSPI/NonceI in InitConfig
// (ike_tunnel_manager.go:156-164 does not today), we must not overwrite it.
func TestInitRunnerUsesConfigSPIAndNonce(t *testing.T) {
	f := newFakeEPDG(t)
	f.Start()
	s := dialFake(t, f, SocketConfig{})

	cfg := initConfig(t, s)
	cfg.InitiatorSPI = 0x0badc0ffee0ddf00
	cfg.NonceI = bytes.Repeat([]byte{0x5a}, 24)

	runner := NewInitRunner()
	result, err := runner.Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.InitiatorSPI != cfg.InitiatorSPI {
		t.Errorf("InitiatorSPI = %#x, want the configured %#x", result.InitiatorSPI, cfg.InitiatorSPI)
	}
	if !bytes.Equal(result.NonceI, cfg.NonceI) {
		t.Errorf("NonceI was regenerated instead of taken from the config")
	}
}

// TestInitRunnerRecordsAndReplays is the cross-phase deliverable: record a live
// exchange, then reproduce it offline byte for byte with no socket at all.
func TestInitRunnerRecordsAndReplays(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sa-init.pcap")

	writer, err := capture.NewWriter(capture.WriterOptions{
		Path:          path,
		RecordSecrets: true,
		Note:          "T041a loopback fake ePDG, group 14",
	})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	f := newFakeEPDG(t)
	f.requireCookie = true // force more than one round trip into the recording
	f.Start()
	s := dialFake(t, f, SocketConfig{Capture: writer})

	runner := NewInitRunner()
	runner.Capture = writer
	live, err := runner.Run(context.Background(), initConfig(t, s))
	if err != nil {
		t.Fatalf("live Run: %v", err)
	}
	liveDetail, _ := runner.LastDetail()
	if err := writer.Close(); err != nil {
		t.Fatalf("writer Close: %v", err)
	}
	if writer.Count() < 4 {
		t.Fatalf("recorded %d datagrams, want at least 4 (cookie round plus real round)", writer.Count())
	}

	replay, seed, err := capture.OpenReplay(path, capture.ReplayOptions{
		UseNonESPMarker:      true,
		RequireExactRequests: true,
	})
	if err != nil {
		t.Fatalf("OpenReplay: %v", err)
	}
	if !seed.Valid() {
		t.Fatalf("seed from the sidecar is unusable: %+v", seed)
	}
	if seed.InitiatorSPI != live.InitiatorSPI || seed.DHGroup != liveDetail.Seed.DHGroup {
		t.Fatalf("sidecar seed does not describe the recorded run")
	}

	offline := NewInitRunner()
	offline.Seed = seed
	replayed, err := offline.Run(context.Background(), ikev2.InitConfig{
		Transport:  replay,
		LocalIP:    s.LocalIP(),
		LocalPort:  s.LocalPort(),
		RemoteIP:   f.Addr().IP,
		RemotePort: uint16(f.Addr().Port),
	})
	if err != nil {
		t.Fatalf("offline Run: %v", err)
	}

	// Byte-exact is the whole claim. Anything weaker is "the replay produced
	// something plausible", which is worth nothing at 3am.
	if !bytes.Equal(replayed.RequestBytes, live.RequestBytes) {
		t.Fatalf("replayed request differs from the recorded request")
	}
	if !bytes.Equal(replayed.ResponseBytes, live.ResponseBytes) {
		t.Fatalf("replayed response differs from the recorded response")
	}
	if !bytes.Equal(replayed.SKEYSEED, live.SKEYSEED) {
		t.Fatalf("replay derived a different SKEYSEED")
	}
	if !bytes.Equal(replayed.KeyMaterial, live.KeyMaterial) {
		t.Fatalf("replay derived different key material")
	}
	if replayed.ResponderSPI != live.ResponderSPI {
		t.Fatalf("replay responder SPI %#x, want %#x", replayed.ResponderSPI, live.ResponderSPI)
	}
	if !bytes.Equal(replayed.SharedSecret, live.SharedSecret) {
		t.Fatalf("replay computed a different shared secret")
	}

	exportCapture(t, path)
}

// exportCapture copies the recording out of the temp dir when
// VODOGE_CAPTURE_OUT is set. That is how a sample gets attached to a bug report,
// and how the shipped vodoge-ike-probe binary is exercised in -replay mode on
// the edge machine without needing a carrier.
func exportCapture(t *testing.T, path string) {
	t.Helper()
	outDir := os.Getenv("VODOGE_CAPTURE_OUT")
	if outDir == "" {
		return
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatalf("VODOGE_CAPTURE_OUT: %v", err)
	}
	for _, suffix := range []string{"", ".session.json"} {
		blob, err := os.ReadFile(path + suffix)
		if err != nil {
			t.Fatalf("reading %s: %v", path+suffix, err)
		}
		dst := filepath.Join(outDir, filepath.Base(path)+suffix)
		if err := os.WriteFile(dst, blob, 0o600); err != nil {
			t.Fatalf("writing %s: %v", dst, err)
		}
		t.Logf("exported %s (%d bytes)", dst, len(blob))
	}
}

// TestFakeEPDGSeparatesEAPSuccessFromChildSA is the first fixture in this repo
// that refuses the "EAP-Success and CHILD_SA share a message" assumption.
//
// The payloads here are unencrypted because SK handling is T041b. What is being
// pinned is the message sequencing, which is the part that has been assumed
// wrong so far, and it is exercised over the real socket and the real
// retransmission path rather than asserted about a data structure.
func TestFakeEPDGSeparatesEAPSuccessFromChildSA(t *testing.T) {
	f := newFakeEPDG(t)
	f.authLadder = true
	f.Start()
	s := dialFake(t, f, SocketConfig{})

	// Establish the SA first so the exchange is a realistic continuation.
	runner := NewInitRunner()
	init, err := runner.Run(context.Background(), initConfig(t, s))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var sawEAPSuccess, sawChildSA int
	for id := uint32(1); id <= 3; id++ {
		req := ikev2.Message{
			Header: ikev2.Header{
				InitiatorSPI: init.InitiatorSPI,
				ResponderSPI: init.ResponderSPI,
				ExchangeType: ikev2.ExchangeIKE_AUTH,
				Flags:        ikev2.FlagInitiator,
				MessageID:    id,
			},
			Payloads: []ikev2.Payload{ikev2.EAPPayload([]byte{2, byte(id), 0, 4})},
		}
		raw, err := req.MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary: %v", err)
		}
		respBytes, err := s.ExchangeIKE(ctx, raw)
		if err != nil {
			t.Fatalf("IKE_AUTH %d: %v", id, err)
		}
		resp, err := ikev2.ParseMessage(respBytes)
		if err != nil {
			t.Fatalf("ParseMessage: %v", err)
		}
		var hasEAPSuccess, hasSA, hasAuth bool
		for _, p := range resp.Payloads {
			switch p.Type {
			case ikev2.PayloadEAP:
				if len(p.Body) >= 1 && p.Body[0] == 3 { // EAP code 3 = Success
					hasEAPSuccess = true
				}
			case ikev2.PayloadSA:
				hasSA = true
			case ikev2.PayloadAUTH:
				hasAuth = true
			}
		}
		if hasEAPSuccess {
			sawEAPSuccess++
			if hasSA || hasAuth {
				t.Fatalf("message %d carried EAP-Success together with SA=%v AUTH=%v; that is the assumption this fixture exists to break",
					id, hasSA, hasAuth)
			}
		}
		if hasSA {
			sawChildSA++
			if hasEAPSuccess {
				t.Fatalf("message %d carried the CHILD_SA alongside EAP-Success", id)
			}
		}
	}
	if sawEAPSuccess != 1 {
		t.Fatalf("saw EAP-Success %d times, want exactly 1", sawEAPSuccess)
	}
	if sawChildSA != 1 {
		t.Fatalf("saw a CHILD_SA %d times, want exactly 1", sawChildSA)
	}

	stages := f.authStages()
	if len(stages) != 3 {
		t.Fatalf("fake logged %d IKE_AUTH stages, want 3", len(stages))
	}
	var successID, childID uint32
	for _, st := range stages {
		if st.EAPSuccess {
			successID = st.MessageID
		}
		if st.CarriesChild {
			childID = st.MessageID
		}
	}
	if successID == 0 || childID == 0 || successID == childID {
		t.Fatalf("EAP-Success in message %d and CHILD_SA in message %d must differ and both be present", successID, childID)
	}
}

func initConfig(t *testing.T, s *Socket) ikev2.InitConfig {
	t.Helper()
	cfg, err := InitConfigFor(s, ikev2.SecurityAssociation{})
	if err != nil {
		t.Fatalf("InitConfigFor: %v", err)
	}
	return cfg
}
