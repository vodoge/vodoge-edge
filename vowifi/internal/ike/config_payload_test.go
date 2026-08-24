package ike

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/boa-z/vowifi-go/engine/swu/ikev2"
)

// TestTheDefaultCFGRequestIsNotTheOneTMobileRefused is the regression that this
// whole card exists for.
//
// T072 sent ikev2.SWuConfigurationRequest() and T-Mobile US answered
// INTERNAL_ADDRESS_FAILURE. Comparing our default against the mirror's function
// - rather than against a list retyped here - means a refactor that "restores
// the upstream default" reddens this instead of silently reproducing a measured
// failure.
func TestTheDefaultCFGRequestIsNotTheOneTMobileRefused(t *testing.T) {
	got, err := DefaultConfigVariant.Configuration()
	if err != nil {
		t.Fatalf("Configuration: %v", err)
	}
	mirror := ikev2.SWuConfigurationRequest()

	mirrorBody, err := mirror.MarshalBinary()
	if err != nil {
		t.Fatalf("mirror MarshalBinary: %v", err)
	}
	gotBody, err := got.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if bytes.Equal(mirrorBody, gotBody) {
		t.Fatalf("the default CFG_REQUEST is byte for byte the one T-Mobile US refused on 2026-08-24: %s",
			DescribeConfiguration(got))
	}
	if !DefaultConfigVariant.RequestsPCSCF() {
		t.Fatalf("the default asks for no P-CSCF address, so a tunnel built on it would have "+
			"nowhere to send REGISTER: %s", DescribeConfiguration(got))
	}

	// Everything the mirror asked for is still asked for. The change is
	// additive: dropping an attribute would be a second variable in a
	// measurement that only has room for one.
	for _, attr := range mirror.Attributes {
		if !configurationHasAttribute(got, attr.Type) {
			t.Fatalf("the default dropped %s, which the refused request also carried; "+
				"that is a second change in a one-variable experiment", ConfigAttributeName(attr.Type))
		}
	}
}

// TestTheMirrorVariantReproducesTheRefusedRequestExactly keeps the control
// honest. A control that has drifted is not a control.
func TestTheMirrorVariantReproducesTheRefusedRequestExactly(t *testing.T) {
	got, err := ConfigVariantMirror.Configuration()
	if err != nil {
		t.Fatalf("Configuration: %v", err)
	}
	want, err := ikev2.SWuConfigurationRequest().MarshalBinary()
	if err != nil {
		t.Fatalf("mirror MarshalBinary: %v", err)
	}
	gotBody, err := got.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if !bytes.Equal(want, gotBody) {
		t.Fatalf("ConfigVariantMirror is no longer what T072 sent:\n got %x\nwant %x", gotBody, want)
	}
}

// TestPCSCFAttributeTypesAreTheRFC7651Allocations pins the two numbers the
// mirror does not define.
//
// The numbers are checked against the wire encoding rather than against
// themselves. A constant compared to a copy of the same constant guards
// nothing, which this repository has already been burnt by once.
func TestPCSCFAttributeTypesAreTheRFC7651Allocations(t *testing.T) {
	cfg, err := ConfigVariantDual.Configuration()
	if err != nil {
		t.Fatalf("Configuration: %v", err)
	}
	body, err := cfg.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if body[0] != ikev2.CFGRequest {
		t.Fatalf("CP type octet is %d, want CFG_REQUEST (%d)", body[0], ikev2.CFGRequest)
	}

	var seen []uint16
	for rest := body[4:]; len(rest) >= 4; {
		attrType := binary.BigEndian.Uint16(rest[0:2])
		length := int(binary.BigEndian.Uint16(rest[2:4]))
		if attrType&0x8000 != 0 {
			t.Fatalf("attribute %d has the RFC 7296 3.15.1 R bit set", attrType&0x7fff)
		}
		// A request asks by sending the type with no value. A non-empty value
		// would be us telling the ePDG which address to give us.
		if length != 0 {
			t.Fatalf("attribute %d carries %d octets of value; a CFG_REQUEST asks, it does not tell",
				attrType, length)
		}
		seen = append(seen, attrType)
		rest = rest[4+length:]
	}

	var haveV4, haveV6 bool
	for _, attrType := range seen {
		switch attrType {
		case 20:
			haveV4 = true
		case 21:
			haveV6 = true
		}
	}
	if !haveV4 || !haveV6 {
		t.Fatalf("the dual request put %v on the wire; RFC 7651 allocates 20 for "+
			"P_CSCF_IP4_ADDRESS and 21 for P_CSCF_IP6_ADDRESS", seen)
	}
	if ConfigPCSCFIPv4Address != 20 || ConfigPCSCFIPv6Address != 21 {
		t.Fatalf("the constants moved: %d/%d", ConfigPCSCFIPv4Address, ConfigPCSCFIPv6Address)
	}
}

// TestSingleFamilyVariantsKeepTheirTrafficSelectorsInStep pins the pairing that
// makes a variant a complete description of the request.
func TestSingleFamilyVariantsKeepTheirTrafficSelectorsInStep(t *testing.T) {
	for _, tc := range []struct {
		variant  ConfigVariant
		wantAttr uint16
		bannedAt uint16
		wantTS   uint8
	}{
		{ConfigVariantIPv4, ikev2.ConfigInternalIPv4Address, ikev2.ConfigInternalIPv6Address, ikev2.TSIPv4AddressRange},
		{ConfigVariantIPv6, ikev2.ConfigInternalIPv6Address, ikev2.ConfigInternalIPv4Address, ikev2.TSIPv6AddressRange},
	} {
		t.Run(string(tc.variant), func(t *testing.T) {
			cfg, err := tc.variant.Configuration()
			if err != nil {
				t.Fatalf("Configuration: %v", err)
			}
			if !configurationHasAttribute(cfg, tc.wantAttr) {
				t.Fatalf("%s does not ask for %s", tc.variant, ConfigAttributeName(tc.wantAttr))
			}
			if configurationHasAttribute(cfg, tc.bannedAt) {
				t.Fatalf("%s is meant to be single family and asks for %s",
					tc.variant, ConfigAttributeName(tc.bannedAt))
			}
			ts, err := tc.variant.TrafficSelectors()
			if err != nil {
				t.Fatalf("TrafficSelectors: %v", err)
			}
			if len(ts.Selectors) != 1 || ts.Selectors[0].Type != tc.wantTS {
				t.Fatalf("%s offers selectors %+v, want one of type %d", tc.variant, ts.Selectors, tc.wantTS)
			}
			// A selector the mirror's own encoder refuses is not a selector.
			if _, err := ikev2.TrafficSelectorsPayload(ikev2.PayloadTSi, ts); err != nil {
				t.Fatalf("%s produced selectors the mirror will not encode: %v", tc.variant, err)
			}
		})
	}
}

// TestIPv6AnyTrafficSelectorsSurviveTheMirrorRoundTrip checks the selector this
// package had to write itself, because session_payloads.go only ships the IPv4
// one.
func TestIPv6AnyTrafficSelectorsSurviveTheMirrorRoundTrip(t *testing.T) {
	payload, err := ikev2.TrafficSelectorsPayload(ikev2.PayloadTSi, IPv6AnyTrafficSelectors())
	if err != nil {
		t.Fatalf("TrafficSelectorsPayload: %v", err)
	}
	parsed, err := ikev2.ParseTrafficSelectors(payload.Body)
	if err != nil {
		t.Fatalf("ParseTrafficSelectors: %v", err)
	}
	if len(parsed.Selectors) != 1 {
		t.Fatalf("round trip produced %d selectors", len(parsed.Selectors))
	}
	got := parsed.Selectors[0]
	if got.Type != ikev2.TSIPv6AddressRange {
		t.Fatalf("selector type %d", got.Type)
	}
	if !got.StartAddr.Equal(net.IPv6zero) {
		t.Fatalf("start address %s, want ::", got.StartAddr)
	}
	if got.StartPort != 0 || got.EndPort != 65535 {
		t.Fatalf("port range %d-%d", got.StartPort, got.EndPort)
	}
	for i, b := range got.EndAddr.To16() {
		if b != 0xff {
			t.Fatalf("end address octet %d is %#x, want the all-ones address", i, b)
		}
	}
}

// TestUnknownVariantIsRefusedRatherThanDefaulted guards an SQN step. A -cfg
// typo that quietly sent the default would attribute a live measurement to a
// request that was never made.
func TestUnknownVariantIsRefusedRatherThanDefaulted(t *testing.T) {
	if _, err := ParseConfigVariant("ipv7"); !errors.Is(err, ErrUnknownConfigVariant) {
		t.Fatalf("ParseConfigVariant(ipv7) err = %v, want ErrUnknownConfigVariant", err)
	}
	if _, err := ConfigVariant("nonsense").Configuration(); !errors.Is(err, ErrUnknownConfigVariant) {
		t.Fatalf("Configuration() err = %v, want ErrUnknownConfigVariant", err)
	}
	if _, err := ConfigVariant("nonsense").TrafficSelectors(); !errors.Is(err, ErrUnknownConfigVariant) {
		t.Fatalf("TrafficSelectors() err = %v, want ErrUnknownConfigVariant", err)
	}
	got, err := ParseConfigVariant("  DUAL ")
	if err != nil || got != ConfigVariantDual {
		t.Fatalf("ParseConfigVariant(\"  DUAL \") = %q, %v", got, err)
	}
	if got, err := ParseConfigVariant(""); err != nil || got != DefaultConfigVariant {
		t.Fatalf("the empty name should mean the default, got %q, %v", got, err)
	}
	for _, variant := range AllConfigVariants {
		if _, err := variant.Configuration(); err != nil {
			t.Fatalf("%s is listed in AllConfigVariants and has no shape: %v", variant, err)
		}
	}
}

// TestCFGSetIsReachableAndNotTheDefault covers the CP-type axis T081 listed.
func TestCFGSetIsReachableAndNotTheDefault(t *testing.T) {
	request, err := ConfigVariantDual.Configuration()
	if err != nil {
		t.Fatalf("Configuration: %v", err)
	}
	if request.Type != ikev2.CFGRequest {
		t.Fatalf("the default CP type is %d, want CFG_REQUEST", request.Type)
	}
	set, err := ConfigVariantDual.ConfigurationOfType(ikev2.CFGSet)
	if err != nil {
		t.Fatalf("ConfigurationOfType: %v", err)
	}
	if set.Type != ikev2.CFGSet {
		t.Fatalf("CP type %d, want CFG_SET", set.Type)
	}
	if len(set.Attributes) != len(request.Attributes) {
		t.Fatalf("the CP type changed the attribute list: %d vs %d",
			len(set.Attributes), len(request.Attributes))
	}
	if !strings.HasPrefix(DescribeConfiguration(set), "CFG_SET") {
		t.Fatalf("DescribeConfiguration does not name the type: %s", DescribeConfiguration(set))
	}
}

// TestParseConfigReplyReadsTheAddressesThatMatter is the decoder for the thing
// criterion 4 is measured on.
func TestParseConfigReplyReadsTheAddressesThatMatter(t *testing.T) {
	v6 := net.ParseIP("2607:fc20:1:100::7").To16()
	pcscf6 := net.ParseIP("2607:fc20:1:100::33").To16()
	body, err := ikev2.Configuration{
		Type: ikev2.CFGReply,
		Attributes: []ikev2.ConfigurationAttribute{
			{Type: ikev2.ConfigInternalIPv4Address, Value: []byte{10, 64, 0, 7}},
			{Type: ConfigInternalIPv4Netmask, Value: []byte{255, 255, 255, 0}},
			{Type: ikev2.ConfigInternalIPv4DNS, Value: []byte{10, 64, 0, 1}},
			{Type: ikev2.ConfigInternalIPv4DNS, Value: []byte{10, 64, 0, 2}},
			{Type: ikev2.ConfigInternalIPv6Address, Value: append(append([]byte(nil), v6...), 64)},
			{Type: ConfigPCSCFIPv4Address, Value: []byte{10, 64, 0, 33}},
			{Type: ConfigPCSCFIPv6Address, Value: pcscf6},
			{Type: ikev2.ConfigInternalAddressExpiry, Value: []byte{0, 0, 0x0e, 0x10}},
			{Type: 4242, Value: []byte{0xde, 0xad}},
			{Type: ikev2.ConfigInternalIPv6DNS},
		},
	}.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}

	reply, err := ParseConfigReply(body)
	if err != nil {
		t.Fatalf("ParseConfigReply: %v", err)
	}
	if reply.Type != ikev2.CFGReply {
		t.Fatalf("type %d", reply.Type)
	}
	if len(reply.IPv4Address) != 1 || reply.IPv4Address[0].String() != "10.64.0.7" {
		t.Fatalf("IPv4Address = %v", reply.IPv4Address)
	}
	if reply.IPv4Netmask.String() != "255.255.255.0" {
		t.Fatalf("IPv4Netmask = %v", reply.IPv4Netmask)
	}
	if len(reply.IPv4DNS) != 2 {
		t.Fatalf("IPv4DNS = %v; repeated attributes must all survive", reply.IPv4DNS)
	}
	if len(reply.IPv6Address) != 1 || reply.IPv6Address[0].PrefixLen != 64 ||
		!reply.IPv6Address[0].Address.Equal(net.IP(v6)) {
		t.Fatalf("IPv6Address = %v", reply.IPv6Address)
	}
	if len(reply.PCSCFIPv4) != 1 || reply.PCSCFIPv4[0].String() != "10.64.0.33" {
		t.Fatalf("PCSCFIPv4 = %v", reply.PCSCFIPv4)
	}
	if len(reply.PCSCFIPv6) != 1 || !reply.PCSCFIPv6[0].Equal(net.IP(pcscf6)) {
		t.Fatalf("PCSCFIPv6 = %v", reply.PCSCFIPv6)
	}
	if !reply.HasExpiry || reply.Expiry.Seconds() != 3600 {
		t.Fatalf("expiry = %v (%v)", reply.Expiry, reply.HasExpiry)
	}
	if !reply.HavePCSCF() || !reply.HaveInternalAddress() {
		t.Fatalf("a reply carrying both an address and a P-CSCF says it has neither")
	}
	// The unknown attribute and the empty one are kept, not dropped. A reply
	// with an invisible half is worse than a reply we admit we cannot name.
	if len(reply.Unrecognised) != 2 {
		t.Fatalf("Unrecognised = %+v, want the 4242 attribute and the empty IPv6 DNS", reply.Unrecognised)
	}
	if !bytes.Equal(reply.Raw, body) {
		t.Fatalf("the raw body was not preserved")
	}

	joined := strings.Join(reply.Describe(), "\n")
	for _, want := range []string{"P_CSCF_IP4_ADDRESS", "10.64.0.33", "INTERNAL_IP6_ADDRESS", "/64"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("Describe() does not mention %q:\n%s", want, joined)
		}
	}
}

// TestParseConfigReplyRefusesAnAddressOfTheWrongLength stops a wrong address
// reaching a receipt that claims to be evidence.
func TestParseConfigReplyRefusesAnAddressOfTheWrongLength(t *testing.T) {
	for _, tc := range []struct {
		name string
		attr ikev2.ConfigurationAttribute
	}{
		{"three octet IPv4", ikev2.ConfigurationAttribute{Type: ikev2.ConfigInternalIPv4Address, Value: []byte{10, 0, 0}}},
		{"four octet P-CSCF v6", ikev2.ConfigurationAttribute{Type: ConfigPCSCFIPv6Address, Value: []byte{1, 2, 3, 4}}},
		{"IPv6 address without prefix length", ikev2.ConfigurationAttribute{
			Type: ikev2.ConfigInternalIPv6Address, Value: make([]byte, 16)}},
		{"short expiry", ikev2.ConfigurationAttribute{Type: ikev2.ConfigInternalAddressExpiry, Value: []byte{0, 1}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, err := ikev2.Configuration{
				Type:       ikev2.CFGReply,
				Attributes: []ikev2.ConfigurationAttribute{tc.attr},
			}.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary: %v", err)
			}
			if _, err := ParseConfigReply(body); !errors.Is(err, ErrInvalidConfigReply) {
				t.Fatalf("err = %v, want ErrInvalidConfigReply", err)
			}
		})
	}
	if _, err := ParseConfigReply([]byte{1}); !errors.Is(err, ErrInvalidConfigReply) {
		t.Fatalf("a truncated payload should be ErrInvalidConfigReply, got %v", err)
	}
}

// TestAConfigReplyWithoutPCSCFSaysSo covers the honest-report path: an ePDG may
// hand out an address and no P-CSCF, and that has to read as a partial result
// rather than as a working tunnel.
func TestAConfigReplyWithoutPCSCFSaysSo(t *testing.T) {
	body, err := ikev2.Configuration{
		Type: ikev2.CFGReply,
		Attributes: []ikev2.ConfigurationAttribute{
			{Type: ikev2.ConfigInternalIPv4Address, Value: []byte{10, 64, 0, 7}},
		},
	}.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	reply, err := ParseConfigReply(body)
	if err != nil {
		t.Fatalf("ParseConfigReply: %v", err)
	}
	if reply.HavePCSCF() {
		t.Fatalf("HavePCSCF on a reply with no P-CSCF attribute")
	}
	if !reply.HaveInternalAddress() {
		t.Fatalf("HaveInternalAddress on a reply that assigned 10.64.0.7")
	}
	if !strings.Contains(strings.Join(reply.Describe(), "\n"), "nowhere to send REGISTER") {
		t.Fatalf("Describe() does not flag the missing P-CSCF:\n%s", strings.Join(reply.Describe(), "\n"))
	}
	var zero ConfigReply
	if zero.Present() || zero.HavePCSCF() || zero.HaveInternalAddress() {
		t.Fatalf("the zero ConfigReply claims to carry something")
	}
}

func configurationHasAttribute(cfg ikev2.Configuration, attrType uint16) bool {
	for _, attr := range cfg.Attributes {
		if attr.Type == attrType {
			return true
		}
	}
	return false
}
