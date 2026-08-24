package ike

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/boa-z/vowifi-go/engine/swu/ikev2"
)

// The bench card, as the daemon reported it on 2026-08-24 (T031) and again at
// the start of T041d. It is here as *input*, never as an expected output: every
// assertion below re-derives what it checks from these two strings rather than
// comparing them against a second copy of the answer.
const (
	benchIMSI     = "310240529712215"
	benchHomePLMN = "310-240"
)

// TestThreeDigitMNCSurvivesTheWholeDerivation is the T048 regression, moved one
// layer up.
//
// T048 fixed the split; this checks that the three digits survive all the way
// onto the wire. The check does not compare against a hand-written FQDN,
// because a hand-written FQDN is a second copy of the same belief. It pulls the
// mnc label back out of the name and compares it with the IMSI digits it is
// supposed to have come from.
func TestThreeDigitMNCSurvivesTheWholeDerivation(t *testing.T) {
	sub, err := DeriveSubscription("867018069514820", benchIMSI, benchHomePLMN, "test")
	if err != nil {
		t.Fatalf("DeriveSubscription: %v", err)
	}
	if sub.MNC != benchIMSI[3:6] {
		t.Fatalf("MNC = %q, want the IMSI digits %q", sub.MNC, benchIMSI[3:6])
	}

	fqdn := sub.EPDGFQDN()
	label := labelValue(t, fqdn, "mnc")
	if label != benchIMSI[3:6] {
		t.Fatalf("FQDN %q carries mnc%s, want mnc%s", fqdn, label, benchIMSI[3:6])
	}
	if got := labelValue(t, fqdn, "mcc"); got != benchIMSI[:3] {
		t.Fatalf("FQDN %q carries mcc%s, want mcc%s", fqdn, got, benchIMSI[:3])
	}
	// The two directions the padding can go wrong. Neither is caught by an
	// equality check against a golden string that was itself written by hand.
	if len(label) != 3 {
		t.Fatalf("mnc label %q is %d digits; TS 23.003 section 19.4.2.4 pads to exactly 3", label, len(label))
	}

	impi := sub.IMPI()
	if got := labelValue(t, impi, "mnc"); got != benchIMSI[3:6] {
		t.Fatalf("IMPI %q carries mnc%s, want mnc%s", impi, got, benchIMSI[3:6])
	}
	user, realm, ok := strings.Cut(impi, "@")
	if !ok {
		t.Fatalf("IMPI %q has no realm", impi)
	}
	// RFC 4187 section 4.1.1.6: EAP-AKA permanent identities are "0" || IMSI.
	if user != "0"+benchIMSI {
		t.Fatalf("IMPI user part %q, want %q", user, "0"+benchIMSI)
	}
	if !strings.HasPrefix(realm, "nai.epc.") {
		t.Fatalf("IMPI realm %q does not start with nai.epc. - that prefix is what separates the "+
			"NAI realm from the ePDG name", realm)
	}
	if strings.HasPrefix(sub.EPDGFQDN(), "nai.") {
		t.Fatalf("ePDG FQDN %q picked up the NAI realm prefix", sub.EPDGFQDN())
	}
}

// TestTwoDigitMNCIsPaddedToThreeNotFour uses the other card on the bench.
func TestTwoDigitMNCIsPaddedToThreeNotFour(t *testing.T) {
	// CSL, as the daemon reports it for 867018069514820 before the switch.
	const imsi, plmn = "454006395021420", "454-00"
	sub, err := DeriveSubscription("867018069514820", imsi, plmn, "test")
	if err != nil {
		t.Fatalf("DeriveSubscription: %v", err)
	}
	if sub.MNC != imsi[3:5] {
		t.Fatalf("MNC = %q, want %q", sub.MNC, imsi[3:5])
	}
	label := labelValue(t, sub.EPDGFQDN(), "mnc")
	if len(label) != 3 {
		t.Fatalf("mnc label %q is %d digits, want 3", label, len(label))
	}
	if strings.TrimLeft(label, "0") != strings.TrimLeft(imsi[3:5], "0") {
		t.Fatalf("mnc label %q does not carry the card MNC %q", label, imsi[3:5])
	}
}

// TestDerivationRefusesAReadoutThatDoesNotHangTogether is the anti-hardcoding
// guard. An MCC that did not come off this card cannot be smuggled in through
// the home PLMN field, because the IMSI has to agree with it.
func TestDerivationRefusesAReadoutThatDoesNotHangTogether(t *testing.T) {
	cases := []struct {
		name     string
		imsi     string
		plmn     string
		wantKind error
	}{
		{"mcc disagrees", benchIMSI, "311-240", ErrInconsistentReadout},
		{"mnc disagrees", benchIMSI, "310-260", ErrInconsistentReadout},
		{"no imsi", "", benchHomePLMN, ErrCardReadout},
		{"imsi not decimal", "31024052971221x", benchHomePLMN, ErrCardReadout},
		{"plmn not split", benchIMSI, "310240", ErrCardReadout},
		{"mnc too long", benchIMSI, "310-2401", ErrCardReadout},
		{"imsi too short", "31024", benchHomePLMN, ErrCardReadout},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DeriveSubscription("867018069514820", tc.imsi, tc.plmn, "test")
			if !errors.Is(err, tc.wantKind) {
				t.Fatalf("err = %v, want %v", err, tc.wantKind)
			}
		})
	}
}

// TestAmbiguousMNCLengthIsRefusedRatherThanGuessed covers the hole in the
// readout format.
//
// edge-core renders the home PLMN through a u16 with {:02}, so a three-digit
// MNC that begins with a zero comes back looking two digits long. When the IMSI
// admits both readings there is nothing here that can settle it, and guessing
// would produce a plausible wrong operator - the exact failure mode criterion
// 2a exists to rule out.
func TestAmbiguousMNCLengthIsRefusedRatherThanGuessed(t *testing.T) {
	// 310-00 with IMSI 310000...: the MNC is either "00" or "000", both render
	// as 0, and they are different networks with different ePDG names
	// (mnc000 either way here, but the realm and the split are not the same
	// question). This is the only shape where the ambiguity is real: any other
	// third digit changes the number and settles it.
	_, err := DeriveSubscription("867018069514820", "310000123456789", "310-00", "test")
	if !errors.Is(err, ErrAmbiguousMNCLength) {
		t.Fatalf("err = %v, want ErrAmbiguousMNCLength", err)
	}
}

func TestPadMNCNeverProducesFourDigits(t *testing.T) {
	for _, in := range []string{"0", "00", "000", "24", "240", "999"} {
		got := PadMNC(in)
		if len(got) != 3 {
			t.Fatalf("PadMNC(%q) = %q, %d digits", in, got, len(got))
		}
		gotValue, err := strconv.Atoi(got)
		if err != nil {
			t.Fatalf("PadMNC(%q) = %q, not decimal", in, got)
		}
		wantValue, err := strconv.Atoi(in)
		if err != nil {
			t.Fatalf("bad input %q", in)
		}
		if gotValue != wantValue {
			t.Fatalf("PadMNC(%q) = %q, which is a different number", in, got)
		}
	}
}

// TestIdentitiesUseTheRightIKEv2Types pins the two identity payload types. An
// IDr sent as an RFC 822 address, or an IDi sent as an FQDN, is the sort of
// mistake that produces a rejection with no diagnostic attached.
func TestIdentitiesUseTheRightIKEv2Types(t *testing.T) {
	sub, err := DeriveSubscription("867018069514820", benchIMSI, benchHomePLMN, "test")
	if err != nil {
		t.Fatalf("DeriveSubscription: %v", err)
	}
	idi := sub.InitiatorIdentity()
	if idi.Type != ikev2.IDRFC822Addr {
		t.Fatalf("IDi type = %d, want ID_RFC822_ADDR (%d)", idi.Type, ikev2.IDRFC822Addr)
	}
	if string(idi.Data) != sub.IMPI() {
		t.Fatalf("IDi data = %q, want the IMPI", idi.Data)
	}
	idr := sub.ResponderIdentity()
	if idr.Type != ikev2.IDFQDN {
		t.Fatalf("IDr type = %d, want ID_FQDN (%d)", idr.Type, ikev2.IDFQDN)
	}
	if string(idr.Data) != sub.EPDGFQDN() {
		t.Fatalf("IDr data = %q, want the ePDG FQDN", idr.Data)
	}
	// Nothing identity-shaped may carry the IMEI: criterion 2b names a
	// self-supplied IMEI as inadmissible, and the module selector is the only
	// place one appears.
	for name, value := range map[string]string{"IDi": string(idi.Data), "IDr": string(idr.Data)} {
		if strings.Contains(value, sub.IMEI) {
			t.Fatalf("%s %q contains the IMEI", name, value)
		}
	}
}

func TestFetchCardReadoutPicksTheNamedModule(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/status" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"modems":[
		  {"imei":"111","iccid":"a","state":"registered","imsi":"460026303803275","home_numeric":"460-02"},
		  {"imei":"222","iccid":"b","state":"registered","imsi":"`+benchIMSI+`","home_numeric":"`+benchHomePLMN+`"}
		]}`)
	}))
	defer server.Close()

	readout, err := FetchCardReadout(context.Background(), server.URL, "222")
	if err != nil {
		t.Fatalf("FetchCardReadout: %v", err)
	}
	if readout.IMSI != benchIMSI {
		t.Fatalf("IMSI = %q", readout.IMSI)
	}
	sub, err := readout.Subscription()
	if err != nil {
		t.Fatalf("Subscription: %v", err)
	}
	if sub.MNC != benchIMSI[3:6] {
		t.Fatalf("MNC = %q", sub.MNC)
	}
	if sub.Source == "" || !strings.Contains(sub.Source, "/api/status") {
		t.Fatalf("Source = %q, should name where the reading came from", sub.Source)
	}

	if _, err := FetchCardReadout(context.Background(), server.URL, "333"); !errors.Is(err, ErrModemNotFound) {
		t.Fatalf("unknown IMEI: err = %v, want ErrModemNotFound", err)
	}
	// Three modules on the bench: refusing to pick one silently is the point.
	if _, err := FetchCardReadout(context.Background(), server.URL, ""); !errors.Is(err, ErrModemNotFound) {
		t.Fatalf("unnamed module: err = %v, want ErrModemNotFound", err)
	}
}

func TestDoHResolverFollowsTheCNAMEChain(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("name"); got != "epdg.epc.mnc240.mcc310.pub.3gppnetwork.org" {
			t.Errorf("name = %q", got)
		}
		if got := r.URL.Query().Get("type"); got != "A" {
			t.Errorf("type = %q", got)
		}
		fmt.Fprint(w, `{"Status":0,"Answer":[
		  {"name":"epdg.epc.mnc240.mcc310.pub.3gppnetwork.org","type":5,"TTL":60,"data":"epdg.epc.geo.mnc260.mcc310.pub.3gppnetwork.org"},
		  {"name":"epdg.epc.geo.mnc260.mcc310.pub.3gppnetwork.org","type":1,"TTL":60,"data":"208.54.34.3"}
		]}`)
	}))
	defer server.Close()

	resolver := &DoHResolver{Endpoint: server.URL}
	answer, err := resolver.LookupA(context.Background(), "epdg.epc.mnc240.mcc310.pub.3gppnetwork.org")
	if err != nil {
		t.Fatalf("LookupA: %v", err)
	}
	if len(answer.IPs) != 1 || !answer.IPs[0].Equal(net.ParseIP("208.54.34.3")) {
		t.Fatalf("IPs = %v", answer.IPs)
	}
	if len(answer.Chain) != 2 {
		t.Fatalf("chain = %v, the CNAME hop is the thing that explains how a 310-240 card "+
			"ends up on the 310-260 infrastructure T038 measured", answer.Chain)
	}
}

// TestDoHResolverRefusesTheFakeIPRange is the T036 trap.
//
// The edge box answers every name, random ones included, from 198.18.0.0/16. A
// resolver that returned one of those would hand back an address that dials the
// host's TUN proxy, and the resulting failure reads like a carrier problem.
func TestDoHResolverRefusesTheFakeIPRange(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"Status":0,"Answer":[{"name":"x","type":1,"TTL":60,"data":"198.18.0.155"}]}`)
	}))
	defer server.Close()

	_, err := (&DoHResolver{Endpoint: server.URL}).LookupA(context.Background(), "x")
	if !errors.Is(err, ErrFakeIPAnswer) {
		t.Fatalf("err = %v, want ErrFakeIPAnswer", err)
	}
}

func TestDoHResolverReportsNXDOMAIN(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"Status":3}`)
	}))
	defer server.Close()

	_, err := (&DoHResolver{Endpoint: server.URL}).LookupA(context.Background(), "x")
	if !errors.Is(err, ErrNoAddress) {
		t.Fatalf("err = %v, want ErrNoAddress", err)
	}
}

// TestSolveApparentEndpointRecoversTheSourceTheResponderSaw checks the egress
// measurement against a hash built by the mirror, not by this file.
func TestSolveApparentEndpointRecoversTheSourceTheResponderSaw(t *testing.T) {
	const spiI, spiR = uint64(0x0123456789abcdef), uint64(0xfedcba9876543210)
	want := ApparentEndpoint{IP: net.ParseIP("34.174.243.156"), Port: 43140}
	hash, err := ikev2.NATDetectionHash(spiI, spiR, want.IP, want.Port)
	if err != nil {
		t.Fatalf("NATDetectionHash: %v", err)
	}
	got, ok := SolveApparentEndpoint(hash, spiI, spiR, KnownEgressIPs())
	if !ok {
		t.Fatalf("no match against %v", KnownEgressIPs())
	}
	if !got.IP.Equal(want.IP) || got.Port != want.Port {
		t.Fatalf("got %s, want %s", got, want)
	}
	// A hash from an address outside the candidate list must miss rather than
	// land on the nearest plausible answer.
	other, err := ikev2.NATDetectionHash(spiI, spiR, net.ParseIP("203.0.113.7"), 1234)
	if err != nil {
		t.Fatalf("NATDetectionHash: %v", err)
	}
	if _, ok := SolveApparentEndpoint(other, spiI, spiR, KnownEgressIPs()); ok {
		t.Fatalf("a foreign address matched one of the known egresses")
	}
}

// labelValue pulls the digits out of a dotted label such as "mnc240".
func labelValue(t *testing.T, name, prefix string) string {
	t.Helper()
	for _, label := range strings.Split(name, ".") {
		if strings.HasPrefix(label, prefix) {
			return strings.TrimPrefix(label, prefix)
		}
	}
	t.Fatalf("%q has no %s label", name, prefix)
	return ""
}
