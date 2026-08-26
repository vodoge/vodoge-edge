package ike

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/boa-z/vowifi-go/engine/swu/ikev2"
)

// rfc2104HMAC is HMAC written out from RFC 2104, using only crypto/sha256.
//
// This is the T041a move applied to a different primitive. T041a cross-checked
// its DH groups with a second standard library package (crypto/elliptic against
// crypto/ecdh) rather than pasting a vector it could not source. There is only
// one HMAC implementation in the standard library, so the equivalent here is to
// build the construction from the RFC text: K zero-padded to the block size,
// XOR with 0x36 and 0x5c, hash twice. If ike.SharedKeyAuth and this agree, the
// key-pad step and the PRF nesting are both right, and nothing was copied from
// memory.
func rfc2104HMAC(key, data []byte) []byte {
	const blockSize = 64 // SHA-256 block size, RFC 4868
	k := key
	if len(k) > blockSize {
		sum := sha256.Sum256(k)
		k = sum[:]
	}
	padded := make([]byte, blockSize)
	copy(padded, k)
	ipad := make([]byte, blockSize)
	opad := make([]byte, blockSize)
	for i := 0; i < blockSize; i++ {
		ipad[i] = padded[i] ^ 0x36
		opad[i] = padded[i] ^ 0x5c
	}
	inner := sha256.Sum256(append(append([]byte(nil), ipad...), data...))
	outer := sha256.Sum256(append(append([]byte(nil), opad...), inner[:]...))
	return outer[:]
}

// TestSharedKeyAuthMatchesAnIndependentHMAC checks the RFC 7296 section 2.15
// shared-secret AUTH against an HMAC built from RFC 2104 rather than from
// crypto/hmac.
func TestSharedKeyAuthMatchesAnIndependentHMAC(t *testing.T) {
	secret := []byte("an MSK stand-in that is 64 octets long once padded out......")
	signed := []byte("RealMessage1|NonceRData|MACedIDForI")

	got, err := SharedKeyAuth(crypto.SHA256, secret, signed)
	if err != nil {
		t.Fatalf("SharedKeyAuth: %v", err)
	}
	want := rfc2104HMAC(rfc2104HMAC(secret, []byte("Key Pad for IKEv2")), signed)
	if !bytes.Equal(got, want) {
		t.Fatalf("SharedKeyAuth disagrees with an independently written HMAC:\n got  %x\n want %x", got, want)
	}
	if len(got) != sha256.Size {
		t.Fatalf("AUTH data is %d octets, want %d for PRF_HMAC_SHA2_256", len(got), sha256.Size)
	}
}

// TestAuthKeyPadIsExactlySeventeenASCIIOctets pins the constant that everything
// else hangs off. A trailing NUL or a case slip here produces an AUTH that is
// wrong in a way only the ePDG can see.
func TestAuthKeyPadIsExactlySeventeenASCIIOctets(t *testing.T) {
	if len(AuthKeyPad) != 17 {
		t.Fatalf("AuthKeyPad is %d octets, RFC 7296 2.15 spells 17", len(AuthKeyPad))
	}
	for i := 0; i < len(AuthKeyPad); i++ {
		if AuthKeyPad[i] == 0 || AuthKeyPad[i] > 0x7e {
			t.Fatalf("AuthKeyPad[%d] = %#x is not printable ASCII", i, AuthKeyPad[i])
		}
	}
	if AuthKeyPad != "Key Pad for IKEv2" {
		t.Fatalf("AuthKeyPad = %q", AuthKeyPad)
	}
}

// TestAuthPayloadEncoding pins the four-octet header. The card calls this the
// single byte most likely to be wrong, so the assertions are on raw octets and
// not on a round trip through our own parser.
func TestAuthPayloadEncoding(t *testing.T) {
	data := bytes.Repeat([]byte{0xab}, 32)
	payload, err := AuthPayload(AuthMethodSharedKeyMIC, data)
	if err != nil {
		t.Fatalf("AuthPayload: %v", err)
	}
	if payload.Type != ikev2.PayloadAUTH {
		t.Fatalf("payload type %d, want %d", payload.Type, ikev2.PayloadAUTH)
	}
	if len(payload.Body) != 4+len(data) {
		t.Fatalf("body is %d octets, want %d (1 method + 3 RESERVED + %d data)",
			len(payload.Body), 4+len(data), len(data))
	}
	if payload.Body[0] != 2 {
		t.Fatalf("auth method octet is %d, want 2 (Shared Key Message Integrity Code)", payload.Body[0])
	}
	if !bytes.Equal(payload.Body[1:4], []byte{0, 0, 0}) {
		t.Fatalf("RESERVED octets are %v, RFC 7296 3.8 requires zeros", payload.Body[1:4])
	}
	if !bytes.Equal(payload.Body[4:], data) {
		t.Fatalf("authentication data was altered")
	}

	value, err := ParseAuthPayload(payload.Body)
	if err != nil {
		t.Fatalf("ParseAuthPayload: %v", err)
	}
	if value.Method != AuthMethodSharedKeyMIC || !bytes.Equal(value.Data, data) {
		t.Fatalf("round trip lost data: method=%d len=%d", value.Method, len(value.Data))
	}
	if !bytes.Equal(AuthPayloadReserved(payload.Body), []byte{0, 0, 0}) {
		t.Fatalf("AuthPayloadReserved did not report the RESERVED octets")
	}

	for name, body := range map[string][]byte{
		"empty":        {},
		"header only":  {2, 0, 0, 0},
		"zero method":  {0, 0, 0, 0, 1},
		"short header": {2, 0},
	} {
		if _, err := ParseAuthPayload(body); !errors.Is(err, ErrInvalidAuthPayload) {
			t.Errorf("%s: ParseAuthPayload err = %v, want ErrInvalidAuthPayload", name, err)
		}
	}
}

// TestSignedOctetsConcatenationOrder pins RFC 7296 section 2.15. Getting the
// order wrong is not detectable locally: both peers produce a well-formed AUTH
// and only the far end notices they disagree.
func TestSignedOctetsConcatenationOrder(t *testing.T) {
	realMessage1 := []byte("REQ")
	realMessage2 := []byte("RESP")
	nonceI := []byte("NI")
	nonceR := []byte("NR")
	macedI := []byte("MI")
	macedR := []byte("MR")

	if got, want := InitiatorSignedOctets(realMessage1, nonceR, macedI), []byte("REQNRMI"); !bytes.Equal(got, want) {
		t.Fatalf("InitiatorSignedOctets = %q, want %q (RealMessage1 | NonceRData | MACedIDForI)", got, want)
	}
	if got, want := ResponderSignedOctets(realMessage2, nonceI, macedR), []byte("RESPNIMR"); !bytes.Equal(got, want) {
		t.Fatalf("ResponderSignedOctets = %q, want %q (RealMessage2 | NonceIData | MACedIDForR)", got, want)
	}
}

// TestMACedIdentityCoversTheIDPayloadBodyOnly checks that the MAC input starts
// at the ID Type octet and excludes the generic payload header.
func TestMACedIdentityCoversTheIDPayloadBodyOnly(t *testing.T) {
	id := ikev2.Identity{Type: ikev2.IDRFC822Addr, Data: []byte("0310260000000001@nai.epc.mnc260.mcc310.3gppnetwork.org")}
	skP := bytes.Repeat([]byte{0x11}, 32)

	got, err := MACedIdentity(crypto.SHA256, skP, id)
	if err != nil {
		t.Fatalf("MACedIdentity: %v", err)
	}
	body, err := id.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if len(body) != 4+len(id.Data) || body[0] != ikev2.IDRFC822Addr {
		t.Fatalf("ID payload body has the wrong shape: %d octets, type %d", len(body), body[0])
	}
	want := rfc2104HMAC(skP, body)
	if !bytes.Equal(got, want) {
		t.Fatalf("MACedIdentity hashed something other than the ID payload body")
	}

	// The payload that goes on the wire must carry exactly those octets, so a
	// peer recomputing the MAC from what it received gets the same answer.
	payload, err := ikev2.IdentityPayload(ikev2.PayloadIDi, id)
	if err != nil {
		t.Fatalf("IdentityPayload: %v", err)
	}
	if !bytes.Equal(payload.Body, body) {
		t.Fatalf("IDi payload body differs from the MAC input")
	}
	fromWire, err := MACedIdentityBody(crypto.SHA256, skP, payload.Body)
	if err != nil {
		t.Fatalf("MACedIdentityBody: %v", err)
	}
	if !bytes.Equal(fromWire, got) {
		t.Fatalf("MACedIdentityBody and MACedIdentity disagree")
	}
}

// TestBuildAuthInitialPayloadsCarriesIDrAndEAPOnly is the structural half of the
// core claim; the packet-level half is in authrunner_test.go, which decodes the
// bytes that actually went out over the socket.
func TestBuildAuthInitialPayloadsCarriesIDrAndEAPOnly(t *testing.T) {
	payloads, err := BuildAuthInitialPayloads(AuthInitialPayloads{
		InitiatorID:           ikev2.Identity{Type: ikev2.IDRFC822Addr, Data: []byte("user@example")},
		ResponderID:           IdentityFQDN("epdg.example"),
		ChildSPI:              []byte{1, 2, 3, 4},
		EAPOnlyAuthentication: true,
	})
	if err != nil {
		t.Fatalf("BuildAuthInitialPayloads: %v", err)
	}
	want := []uint8{
		ikev2.PayloadIDi, ikev2.PayloadIDr, ikev2.PayloadCP,
		ikev2.PayloadSA, ikev2.PayloadTSi, ikev2.PayloadTSr, ikev2.PayloadNotify,
	}
	got := payloadTypes(payloads)
	if len(got) != len(want) {
		t.Fatalf("payload types = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("payload types = %v, want %v", got, want)
		}
	}

	// The mirror's own builder is the thing being replaced. Assert the
	// difference rather than describing it.
	mirror, err := ikev2.BuildIKEAuthInitialPayloads(ikev2.AuthConfig{
		InitiatorID: ikev2.Identity{Type: ikev2.IDRFC822Addr, Data: []byte("user@example")},
		ChildSPI:    []byte{1, 2, 3, 4},
	})
	if err != nil {
		t.Fatalf("BuildIKEAuthInitialPayloads: %v", err)
	}
	for _, p := range mirror {
		if p.Type == ikev2.PayloadIDr {
			t.Fatalf("the mirror grew an IDr; this test and the runner both need rechecking")
		}
		if p.Type == ikev2.PayloadNotify {
			t.Fatalf("the mirror grew a notify in the initial IKE_AUTH payloads")
		}
	}

	notify, err := ikev2.ParseNotify(payloads[len(payloads)-1].Body)
	if err != nil {
		t.Fatalf("ParseNotify: %v", err)
	}
	if notify.NotifyType != 16417 {
		t.Fatalf("notify type = %d, want 16417 (EAP_ONLY_AUTHENTICATION, RFC 5998)", notify.NotifyType)
	}
	if notify.ProtocolID != 0 || len(notify.SPI) != 0 || len(notify.NotificationData) != 0 {
		t.Fatalf("EAP_ONLY_AUTHENTICATION must be protocol 0, no SPI, no data; got %+v", notify)
	}

	idr, err := ikev2.ParseIdentity(payloads[1].Body)
	if err != nil {
		t.Fatalf("ParseIdentity: %v", err)
	}
	if idr.Type != ikev2.IDFQDN || string(idr.Data) != "epdg.example" {
		t.Fatalf("IDr = %d/%q", idr.Type, idr.Data)
	}
}

// TestTheAPNFQDNKeepsItsOperatorHalfOnTheCard covers the one IDr shape
// TS 24.302 section 7.2.2 actually specifies for SWu.
//
// The point of the assertions is provenance, not spelling. Everything except
// the APN network identifier has to be the same derivation EPDGFQDN uses, so
// that offering this IDr does not become a back door for a hand-typed operator
// - which is what goal oracle criterion 2b refuses.
func TestTheAPNFQDNKeepsItsOperatorHalfOnTheCard(t *testing.T) {
	sub, err := DeriveSubscription("867018069514820", "310240529712215", "310-240", "test")
	if err != nil {
		t.Fatalf("DeriveSubscription: %v", err)
	}
	got, err := sub.APNFQDN(WellKnownIMSAPN)
	if err != nil {
		t.Fatalf("APNFQDN: %v", err)
	}
	// The operator half is taken from the ePDG name rather than rewritten, so a
	// change to the MNC padding rule cannot make the two disagree silently.
	operator, ok := strings.CutPrefix(sub.EPDGFQDN(), "epdg.")
	if !ok {
		t.Fatalf("EPDGFQDN no longer starts with epdg.: %q", sub.EPDGFQDN())
	}
	want := WellKnownIMSAPN + ".apn." + operator
	if got != want {
		t.Fatalf("APNFQDN = %q, want %q", got, want)
	}
	if !strings.Contains(got, "mnc240.mcc310") {
		t.Fatalf("the APN-FQDN lost the card's three-digit MNC: %q", got)
	}
	if strings.Contains(got, sub.IMSI) || strings.Contains(got, sub.IMEI) {
		t.Fatalf("the APN-FQDN leaks a subscriber identity: %q", got)
	}

	identity, err := sub.APNIdentity(" IMS ")
	if err != nil {
		t.Fatalf("APNIdentity: %v", err)
	}
	if identity.Type != ikev2.IDFQDN || string(identity.Data) != want {
		t.Fatalf("APNIdentity = %d/%q", identity.Type, identity.Data)
	}
	// An APN that is not a DNS label is refused rather than concatenated into a
	// name that would be silently wrong on the wire.
	for _, bad := range []string{"", "   ", "ims apn", "ims/1", "ims_4g"} {
		if _, err := sub.APNFQDN(bad); !errors.Is(err, ErrCardReadout) {
			t.Fatalf("APNFQDN(%q) err = %v, want ErrCardReadout", bad, err)
		}
	}

	// A two-digit MNC still pads to three, the same way EPDGFQDN does.
	hk, err := DeriveSubscription("867018069514820", "454006395021420", "454-00", "test")
	if err != nil {
		t.Fatalf("DeriveSubscription: %v", err)
	}
	hkAPN, err := hk.APNFQDN(WellKnownIMSAPN)
	if err != nil {
		t.Fatalf("APNFQDN: %v", err)
	}
	if !strings.Contains(hkAPN, "mnc000.mcc454") {
		t.Fatalf("two-digit MNC did not pad: %q", hkAPN)
	}
}

// TestBuildAuthInitialPayloadsRefusesToSilentlyDropIDr mirrors T041a's
// NAT_DETECTION decision: the dangerous failure is the quiet one.
func TestBuildAuthInitialPayloadsRefusesToSilentlyDropIDr(t *testing.T) {
	base := AuthInitialPayloads{
		InitiatorID:           ikev2.Identity{Type: ikev2.IDRFC822Addr, Data: []byte("user@example")},
		ChildSPI:              []byte{1, 2, 3, 4},
		EAPOnlyAuthentication: true,
	}
	if _, err := BuildAuthInitialPayloads(base); !errors.Is(err, ErrMissingResponderID) {
		t.Fatalf("err = %v, want ErrMissingResponderID", err)
	}

	opted := base
	opted.AllowMissingResponderID = true
	payloads, err := BuildAuthInitialPayloads(opted)
	if err != nil {
		t.Fatalf("explicit opt-out still failed: %v", err)
	}
	if containsPayload(payloads, ikev2.PayloadIDr) {
		t.Fatalf("AllowMissingResponderID still emitted an IDr")
	}

	noID := base
	noID.ResponderID = IdentityFQDN("epdg.example")
	noID.InitiatorID = ikev2.Identity{}
	if _, err := BuildAuthInitialPayloads(noID); !errors.Is(err, ErrMissingInitiatorID) {
		t.Fatalf("err = %v, want ErrMissingInitiatorID", err)
	}
}

func TestIdentityFromString(t *testing.T) {
	nai, err := IdentityFromString("0310260000000001@nai.epc.mnc260.mcc310.3gppnetwork.org")
	if err != nil {
		t.Fatalf("IdentityFromString: %v", err)
	}
	if nai.Type != ikev2.IDRFC822Addr {
		t.Fatalf("an NAI became ID type %d, want %d", nai.Type, ikev2.IDRFC822Addr)
	}
	other, err := IdentityFromString("310260000000001")
	if err != nil {
		t.Fatalf("IdentityFromString: %v", err)
	}
	if other.Type != ikev2.IDKeyID {
		t.Fatalf("a bare IMSI became ID type %d, want KEY_ID %d", other.Type, ikev2.IDKeyID)
	}
	if _, err := IdentityFromString(""); err == nil {
		t.Fatalf("an empty identity was accepted")
	}
}

// TestBuildAuthInitialPayloadsOmitsTheCPOnlyWhenAskedTo covers both halves of
// the switch, because only one of them is a change.
//
// The dangerous direction is not "no CP when asked for none", it is "no CP by
// accident". Leaving Configuration at its zero value is how every caller in
// this repository asks for the default request, so if the opt-out ever leaked
// into that path, the live default would quietly become the experiment - and it
// would look identical in a log until an ePDG answered notify 37.
func TestBuildAuthInitialPayloadsOmitsTheCPOnlyWhenAskedTo(t *testing.T) {
	base := AuthInitialPayloads{
		InitiatorID:             ikev2.Identity{Type: ikev2.IDRFC822Addr, Data: []byte("user@example")},
		AllowMissingResponderID: true,
		ChildSPI:                []byte{1, 2, 3, 4},
		EAPOnlyAuthentication:   true,
	}

	withCP, err := BuildAuthInitialPayloads(base)
	if err != nil {
		t.Fatalf("BuildAuthInitialPayloads: %v", err)
	}
	if !containsPayload(withCP, ikev2.PayloadCP) {
		t.Fatalf("the zero Configuration stopped meaning the default: %v", payloadTypes(withCP))
	}

	opted := base
	opted.AllowMissingConfiguration = true
	without, err := BuildAuthInitialPayloads(opted)
	if err != nil {
		t.Fatalf("BuildAuthInitialPayloads: %v", err)
	}
	if containsPayload(without, ikev2.PayloadCP) {
		t.Fatalf("AllowMissingConfiguration still sent a CP: %v", payloadTypes(without))
	}
	// Everything else is unchanged, which is what makes the live run a
	// one-variable experiment against T081's.
	want := []uint8{
		ikev2.PayloadIDi, ikev2.PayloadSA, ikev2.PayloadTSi, ikev2.PayloadTSr, ikev2.PayloadNotify,
	}
	got := payloadTypes(without)
	if len(got) != len(want) {
		t.Fatalf("payload types = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("payload types = %v, want %v", got, want)
		}
	}

	// An explicitly built request wins over the flag. A caller that handed in a
	// payload asked for that payload; silently dropping it would be the same
	// class of bug in the other direction.
	explicit := opted
	explicit.Configuration, err = ConfigVariantMirror.Configuration()
	if err != nil {
		t.Fatalf("Configuration: %v", err)
	}
	kept, err := BuildAuthInitialPayloads(explicit)
	if err != nil {
		t.Fatalf("BuildAuthInitialPayloads: %v", err)
	}
	if !containsPayload(kept, ikev2.PayloadCP) {
		t.Fatalf("an explicit CFG_REQUEST was dropped by the opt-out: %v", payloadTypes(kept))
	}
}
