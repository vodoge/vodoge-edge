package ike

// The configuration payload, which is where the tunnel actually died.
//
// T072 got EAP-Success out of T-Mobile US and then got
// INTERNAL_ADDRESS_FAILURE (notify 36) on the message carrying AUTH. Notify 36
// is not an authentication verdict and not a traffic-selector verdict: RFC 7296
// section 3.10.1 defines it as "the responder could not assign an internal
// address", i.e. it is a judgement on the CFG_REQUEST we sent in the first
// IKE_AUTH request and on nothing else.
//
// What we sent was ikev2.SWuConfigurationRequest()
// (vendor-mirror/vowifi-go-1e9c6e6/engine/swu/ikev2/session_payloads.go:146-153):
//
//	CFG_REQUEST { INTERNAL_IP4_ADDRESS, INTERNAL_IP4_DNS,
//	              INTERNAL_IP6_ADDRESS, INTERNAL_IP6_DNS }
//
// Two things are wrong with that for an ePDG, and they are independent:
//
//   - No P-CSCF. 3GPP TS 24.302 section 7.2.2 has the UE ask for the proxy
//     CSCF address in the CFG_REQUEST, and RFC 7651 allocated attribute types
//     20 (P_CSCF_IP4_ADDRESS) and 21 (P_CSCF_IP6_ADDRESS) for it. The mirror
//     defines neither constant - the list in session_payloads.go:26-34 stops at
//     15. Without a P-CSCF address a tunnel that came up would have nowhere to
//     send REGISTER, so this is required for criterion 4 whether or not it is
//     what notify 36 is complaining about.
//   - Both address families at once. The request asks for an IPv4 address and
//     an IPv6 address in one PDN. An ePDG that can only allocate one of the two
//     for the IMS APN is entitled to answer notify 36 rather than partially
//     satisfy the request.
//
// Which of those T-Mobile objects to is a measurement, not a deduction, and
// each measurement costs one SQN step on the bench card. So the shapes are
// named, one axis apart from each other where that is possible, and the name
// travels into the capture sidecar so that a recording says which one produced
// it.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/boa-z/vowifi-go/engine/swu/ikev2"
)

// Configuration attribute types the mirror does not define.
//
// The mirror stops at ConfigInternalIPv6Subnet (15). These are the IANA "IKEv2
// Configuration Payload Attribute Types" allocations this package needs; each
// one is written down with its source so a future reader does not have to trust
// that somebody remembered the number correctly.
const (
	// ConfigInternalIPv4Netmask is RFC 7296 section 3.15.1 attribute 2. Only
	// meaningful in a reply.
	ConfigInternalIPv4Netmask uint16 = 2
	// ConfigPCSCFIPv4Address is RFC 7651 section 3, attribute 20. This is the
	// one T046 identified as missing.
	ConfigPCSCFIPv4Address uint16 = 20
	// ConfigPCSCFIPv6Address is RFC 7651 section 3, attribute 21.
	ConfigPCSCFIPv6Address uint16 = 21
	// ConfigInternalDNSDomain is RFC 8598 attribute 25. Never requested here;
	// named so that a reply carrying one is reported instead of dumped as hex.
	ConfigInternalDNSDomain uint16 = 25
)

// Errors raised by this file.
var (
	ErrInvalidConfigReply = errors.New("vowifi/ike: invalid configuration payload")
	// ErrUnknownConfigVariant is returned for a -cfg name nobody defined. It is
	// a hard error rather than a fallback to the default: a typo that silently
	// sent the shape we already know is refused would burn an SQN step and
	// produce a result attributed to the wrong variant.
	ErrUnknownConfigVariant = errors.New("vowifi/ike: unknown CFG_REQUEST variant")
)

// ConfigVariant names one CFG_REQUEST shape.
//
// These exist so that "which request did the ePDG refuse" is a word in a
// receipt and a string in a capture sidecar, not a hex dump somebody has to
// decode a second time.
type ConfigVariant string

const (
	// ConfigVariantMirror is exactly ikev2.SWuConfigurationRequest(): both
	// address families, no P-CSCF. It is the control, because it is byte for
	// byte what T072 sent when T-Mobile answered notify 36. Nothing should make
	// this the default again; it exists to be reproduced.
	ConfigVariantMirror ConfigVariant = "mirror"
	// ConfigVariantDual is ConfigVariantMirror plus P_CSCF_IP4_ADDRESS and
	// P_CSCF_IP6_ADDRESS, and nothing else. One axis away from the control, so
	// a run of it answers "is the missing P-CSCF what notify 36 was about" on
	// its own.
	//
	// T081 ran it at T-Mobile US on 2026-08-24 (capture /root/t081/cfg-dual.pcap)
	// and the answer is no: EAP-Success, then INTERNAL_ADDRESS_FAILURE again.
	// The attributes are still right - TS 24.302 section 7.2.2 asks for them
	// and a tunnel without them has nowhere to register - so this stays the
	// default. It is the correct request, and it is not sufficient.
	ConfigVariantDual ConfigVariant = "dual"
	// ConfigVariantIPv4 is ConfigVariantDual with the IPv6 attributes removed:
	// a single-family request for an IPv4 IMS PDN.
	ConfigVariantIPv4 ConfigVariant = "ipv4"
	// ConfigVariantIPv6 is ConfigVariantDual with the IPv4 attributes removed.
	// It also moves the traffic selectors to IPv6, because a CFG_REQUEST that
	// asks for an IPv6 address while TSi offers 0.0.0.0-255.255.255.255
	// describes a tunnel that cannot carry the address it just asked for.
	//
	// Also measured at T-Mobile US by T081 (/root/t081/cfg-ipv6.pcap):
	// INTERNAL_ADDRESS_FAILURE. So the refusal is not a dual-stack objection
	// either, and ConfigVariantIPv4 is the cell nobody has spent an SQN on yet.
	ConfigVariantIPv6 ConfigVariant = "ipv6"
	// ConfigVariantIPv4NoPCSCF and ConfigVariantIPv6NoPCSCF are the single
	// family shapes without P-CSCF. They complete the two-by-two, so that a
	// P-CSCF result measured on one family can be checked against the other
	// without inventing a shape at 3am.
	ConfigVariantIPv4NoPCSCF ConfigVariant = "ipv4-nopcscf"
	ConfigVariantIPv6NoPCSCF ConfigVariant = "ipv6-nopcscf"
	// ConfigVariantNone sends no CP payload at all. It is not an empty
	// CFG_REQUEST: the payload is absent from the message.
	//
	// Every other variant is a guess about which attribute T-Mobile objected
	// to, and T081 spent two SQN steps finding out that three different guesses
	// are all wrong (mirror, dual and ipv6 were each answered notify 36). This
	// one is not a guess, it is the only shape whose three possible answers each
	// eliminate a different two thirds of the remaining space:
	//
	//   - FAILED_CP_REQUIRED (notify 37) means the ePDG reads the CP payload and
	//     needs it, so the attribute list is worth bisecting after all.
	//   - A CHILD_SA means the ePDG will build a tunnel without being asked for
	//     an address, so the fault is entirely inside the attribute list. Note
	//     that such a tunnel has no internal address and no P-CSCF, so it is not
	//     criterion 4 - see LiveResult.TunnelIsUp.
	//   - Another INTERNAL_ADDRESS_FAILURE means the refusal was never about the
	//     contents of the CP at all, which points at the subscription rather
	//     than at this package. See notes/T081-cfg-request.md section 5.2.
	//
	// It is deliberately one axis from ConfigVariantDual: same IPv4 traffic
	// selectors, same everything else, minus the payload.
	ConfigVariantNone ConfigVariant = "none"
)

// DefaultConfigVariant is what the live path sends when nothing overrides it.
//
// It is ConfigVariantDual because that is the request TS 24.302 section 7.2.2
// and RFC 7651 describe, not because it is known to work. It is not: T081
// measured it being refused by T-Mobile US on 2026-08-24. Saying so here rather
// than quietly defaulting to something is the point - a default that a reader
// assumes has been validated is how "implemented" turns into "works on the
// bench" in a receipt.
//
// Changing this constant is a claim about a live carrier, so it moves only when
// a live run says so, and the note records which run.
const DefaultConfigVariant = ConfigVariantDual

// AllConfigVariants is every shape, in the order a diagnosis should walk them.
var AllConfigVariants = []ConfigVariant{
	ConfigVariantMirror,
	ConfigVariantDual,
	ConfigVariantIPv6,
	ConfigVariantIPv4,
	ConfigVariantIPv4NoPCSCF,
	ConfigVariantIPv6NoPCSCF,
	ConfigVariantNone,
}

// configShape is the definition of one variant.
type configShape struct {
	attributes []uint16
	ipv6TS     bool
	// omitCP means the request carries no configuration payload at all. It is a
	// separate flag rather than an empty attribute list because those two are
	// different messages on the wire, and RFC 7296 section 3.15 gives them
	// different meanings: an empty CFG_REQUEST still asks to be configured.
	omitCP bool
	why    string
}

var configShapes = map[ConfigVariant]configShape{
	ConfigVariantMirror: {
		attributes: []uint16{
			ikev2.ConfigInternalIPv4Address, ikev2.ConfigInternalIPv4DNS,
			ikev2.ConfigInternalIPv6Address, ikev2.ConfigInternalIPv6DNS,
		},
		why: "the mirror's SWuConfigurationRequest, i.e. the exact request T-Mobile US " +
			"answered with INTERNAL_ADDRESS_FAILURE on 2026-08-24",
	},
	ConfigVariantDual: {
		attributes: []uint16{
			ikev2.ConfigInternalIPv4Address, ikev2.ConfigInternalIPv4DNS,
			ikev2.ConfigInternalIPv6Address, ikev2.ConfigInternalIPv6DNS,
			ConfigPCSCFIPv4Address, ConfigPCSCFIPv6Address,
		},
		why: "the mirror's request plus the two P-CSCF attributes RFC 7651 defines and " +
			"TS 24.302 section 7.2.2 asks for; exactly one axis from the control",
	},
	ConfigVariantIPv4: {
		attributes: []uint16{
			ikev2.ConfigInternalIPv4Address, ikev2.ConfigInternalIPv4DNS,
			ConfigPCSCFIPv4Address,
		},
		why: "a single-family IPv4 IMS PDN with P-CSCF",
	},
	ConfigVariantIPv6: {
		attributes: []uint16{
			ikev2.ConfigInternalIPv6Address, ikev2.ConfigInternalIPv6DNS,
			ConfigPCSCFIPv6Address,
		},
		ipv6TS: true,
		why:    "a single-family IPv6 IMS PDN with P-CSCF, traffic selectors moved to match",
	},
	ConfigVariantIPv4NoPCSCF: {
		attributes: []uint16{ikev2.ConfigInternalIPv4Address, ikev2.ConfigInternalIPv4DNS},
		why:        "IPv4 only, no P-CSCF: isolates the family axis from the P-CSCF axis",
	},
	ConfigVariantIPv6NoPCSCF: {
		attributes: []uint16{ikev2.ConfigInternalIPv6Address, ikev2.ConfigInternalIPv6DNS},
		ipv6TS:     true,
		why:        "IPv6 only, no P-CSCF: isolates the family axis from the P-CSCF axis",
	},
	ConfigVariantNone: {
		omitCP: true,
		why: "no CP payload at all: FAILED_CP_REQUIRED means the attribute list is worth " +
			"bisecting, a CHILD_SA means the fault is entirely in it, and a third notify 36 " +
			"means notify 36 was never about the CP",
	},
}

// ParseConfigVariant turns a command line word into a variant.
func ParseConfigVariant(name string) (ConfigVariant, error) {
	trimmed := ConfigVariant(strings.ToLower(strings.TrimSpace(name)))
	if trimmed == "" {
		return DefaultConfigVariant, nil
	}
	if _, ok := configShapes[trimmed]; !ok {
		names := make([]string, 0, len(AllConfigVariants))
		for _, v := range AllConfigVariants {
			names = append(names, string(v))
		}
		return "", fmt.Errorf("%w: %q; want one of %s", ErrUnknownConfigVariant, name, strings.Join(names, ", "))
	}
	return trimmed, nil
}

// Configuration renders the variant as a CFG_REQUEST.
//
// Every attribute goes out with a zero-length value. RFC 7296 section 3.15
// makes that the way an initiator says "give me one of these" as opposed to
// "here is the one I want", and it is what the mirror already did for the four
// attributes it knew about.
func (v ConfigVariant) Configuration() (ikev2.Configuration, error) {
	return v.ConfigurationOfType(ikev2.CFGRequest)
}

// ConfigurationOfType renders the variant with an explicit CP type.
//
// The type is an axis T081 listed, because notify 36 could in principle be a
// complaint about the payload rather than about its contents. A UE sends
// CFG_REQUEST: RFC 7296 section 3.15.1 reserves CFG_SET for the "here is
// configuration, acknowledge it" direction, and nothing in this repository has
// ever seen an ePDG want one from an initiator. It is reachable so the
// experiment can be run and written down, not because it is expected to work.
func (v ConfigVariant) ConfigurationOfType(cfgType uint8) (ikev2.Configuration, error) {
	shape, ok := configShapes[v]
	if !ok {
		return ikev2.Configuration{}, fmt.Errorf("%w: %q", ErrUnknownConfigVariant, string(v))
	}
	// The zero value, and not an empty CFG_REQUEST of the asked-for type. This
	// is what BuildAuthInitialPayloads tests for when deciding whether there is
	// a payload to send, and -cfg-type has nothing to apply itself to when
	// there is no payload.
	if shape.omitCP {
		return ikev2.Configuration{}, nil
	}
	if cfgType == 0 {
		cfgType = ikev2.CFGRequest
	}
	out := ikev2.Configuration{Type: cfgType}
	for _, attr := range shape.attributes {
		out.Attributes = append(out.Attributes, ikev2.ConfigurationAttribute{Type: attr})
	}
	return out, nil
}

// TrafficSelectors returns the TSi/TSr this variant needs.
//
// It is part of the variant rather than a separate knob because the pairing is
// not free: asking for an IPv6 internal address over a tunnel whose selectors
// only cover 0.0.0.0/0 is a self-contradictory request, and an ePDG is within
// its rights to refuse either half of it. Keeping them together means a variant
// name fully describes what went on the wire.
func (v ConfigVariant) TrafficSelectors() (ikev2.TrafficSelectors, error) {
	shape, ok := configShapes[v]
	if !ok {
		return ikev2.TrafficSelectors{}, fmt.Errorf("%w: %q", ErrUnknownConfigVariant, string(v))
	}
	if shape.ipv6TS {
		return IPv6AnyTrafficSelectors(), nil
	}
	return ikev2.IPv4AnyTrafficSelectors(), nil
}

// SendsConfiguration reports whether this variant puts a CP payload in the
// first IKE_AUTH request at all.
//
// An unknown or empty name answers true, because the empty name means
// DefaultConfigVariant and every defined shape except ConfigVariantNone carries
// a request. Callers that need an unknown name rejected use Configuration or
// ConfigurationOfType, which return ErrUnknownConfigVariant; this predicate is
// only ever asked "is the CP payload suppressed", and answering "yes" for a
// typo would silently turn a mistyped -cfg into the one experiment that is
// most expensive to attribute to the wrong request.
func (v ConfigVariant) SendsConfiguration() bool {
	shape, ok := configShapes[v]
	if !ok {
		return true
	}
	return !shape.omitCP
}

// RequestsPCSCF reports whether this shape asks for a P-CSCF address.
func (v ConfigVariant) RequestsPCSCF() bool {
	shape, ok := configShapes[v]
	if !ok {
		return false
	}
	for _, attr := range shape.attributes {
		if attr == ConfigPCSCFIPv4Address || attr == ConfigPCSCFIPv6Address {
			return true
		}
	}
	return false
}

// Why explains what the variant is for, in one line.
func (v ConfigVariant) Why() string {
	shape, ok := configShapes[v]
	if !ok {
		return "undefined variant"
	}
	return shape.why
}

// IPv6AnyTrafficSelectors is the IPv6 counterpart of the mirror's
// ikev2.IPv4AnyTrafficSelectors, which has no IPv6 sibling
// (session_payloads.go:224-232 is the whole of it).
func IPv6AnyTrafficSelectors() ikev2.TrafficSelectors {
	return ikev2.TrafficSelectors{Selectors: []ikev2.TrafficSelector{{
		Type:      ikev2.TSIPv6AddressRange,
		StartPort: 0,
		EndPort:   65535,
		StartAddr: net.IP(make([]byte, net.IPv6len)),
		EndAddr: net.IP([]byte{
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		}),
	}}}
}

// ConfigAttributeName labels a configuration attribute type.
//
// Anything unnamed prints as its number. A guessed name in a diagnosis is worse
// than a number, because the number can still be looked up.
func ConfigAttributeName(value uint16) string {
	switch value {
	case ikev2.ConfigInternalIPv4Address:
		return "INTERNAL_IP4_ADDRESS"
	case ConfigInternalIPv4Netmask:
		return "INTERNAL_IP4_NETMASK"
	case ikev2.ConfigInternalIPv4DNS:
		return "INTERNAL_IP4_DNS"
	case ikev2.ConfigInternalAddressExpiry:
		return "INTERNAL_ADDRESS_EXPIRY"
	case ikev2.ConfigInternalIPv6Address:
		return "INTERNAL_IP6_ADDRESS"
	case ikev2.ConfigInternalIPv6DNS:
		return "INTERNAL_IP6_DNS"
	case ikev2.ConfigInternalIPv4Subnet:
		return "INTERNAL_IP4_SUBNET"
	case ikev2.ConfigSupportedAttributes:
		return "SUPPORTED_ATTRIBUTES"
	case ikev2.ConfigInternalIPv6Subnet:
		return "INTERNAL_IP6_SUBNET"
	case ConfigPCSCFIPv4Address:
		return "P_CSCF_IP4_ADDRESS"
	case ConfigPCSCFIPv6Address:
		return "P_CSCF_IP6_ADDRESS"
	case ConfigInternalDNSDomain:
		return "INTERNAL_DNS_DOMAIN"
	default:
		return fmt.Sprintf("attribute %d", value)
	}
}

// ConfigTypeName labels a CP payload type.
func ConfigTypeName(value uint8) string {
	switch value {
	case ikev2.CFGRequest:
		return "CFG_REQUEST"
	case ikev2.CFGReply:
		return "CFG_REPLY"
	case ikev2.CFGSet:
		return "CFG_SET"
	case ikev2.CFGAck:
		return "CFG_ACK"
	default:
		return fmt.Sprintf("CFG type %d", value)
	}
}

// DescribeConfiguration renders a configuration payload as one readable line.
//
// This is what goes into the INTERNAL_ADDRESS_FAILURE error text. A rejection
// that does not say what was rejected is the failure mode this file exists to
// end: T072's receipt could say "notify 36" and could not say what the ePDG had
// been asked for without decrypting the capture a second time.
func DescribeConfiguration(cfg ikev2.Configuration) string {
	if cfg.Type == 0 && len(cfg.Attributes) == 0 {
		return "(no CP payload)"
	}
	parts := make([]string, 0, len(cfg.Attributes))
	for _, attr := range cfg.Attributes {
		name := ConfigAttributeName(attr.Type)
		if len(attr.Value) > 0 {
			name = fmt.Sprintf("%s=%x", name, attr.Value)
		}
		parts = append(parts, name)
	}
	if len(parts) == 0 {
		return ConfigTypeName(cfg.Type) + " { }"
	}
	return ConfigTypeName(cfg.Type) + " { " + strings.Join(parts, ", ") + " }"
}

// IPv6Prefix is an INTERNAL_IP6_ADDRESS or INTERNAL_IP6_SUBNET value: sixteen
// octets of address followed by one octet of prefix length
// (RFC 7296 section 3.15.1).
type IPv6Prefix struct {
	Address   net.IP
	PrefixLen uint8
}

func (p IPv6Prefix) String() string {
	return fmt.Sprintf("%s/%d", p.Address, p.PrefixLen)
}

// ConfigReply is a decoded CFG_REPLY.
//
// Unknown attributes are kept rather than dropped. The single most likely thing
// to be in a real ePDG's reply is an attribute nobody here has a constant for,
// and silently discarding it would mean the first tunnel came up with part of
// its own configuration invisible.
type ConfigReply struct {
	Type         uint8
	IPv4Address  []net.IP
	IPv4Netmask  net.IP
	IPv4DNS      []net.IP
	IPv6Address  []IPv6Prefix
	IPv6DNS      []net.IP
	PCSCFIPv4    []net.IP
	PCSCFIPv6    []net.IP
	Expiry       time.Duration
	HasExpiry    bool
	Unrecognised []ikev2.ConfigurationAttribute
	// Raw is the payload body exactly as it arrived.
	Raw []byte
}

// Present reports whether anything was parsed at all.
func (r ConfigReply) Present() bool { return r.Type != 0 || len(r.Raw) > 0 }

// HavePCSCF reports the criterion this card is measured against: the ePDG told
// us where the IMS proxy is.
//
// Without it a tunnel is a tunnel to nowhere - SIP REGISTER has no destination,
// and criterion 4 asks for IMS registration and not for an ESP SA.
func (r ConfigReply) HavePCSCF() bool { return len(r.PCSCFIPv4)+len(r.PCSCFIPv6) > 0 }

// HaveInternalAddress reports whether the ePDG assigned us anything to source
// packets from.
func (r ConfigReply) HaveInternalAddress() bool {
	return len(r.IPv4Address)+len(r.IPv6Address) > 0
}

// Describe renders the reply as receipt-ready lines.
func (r ConfigReply) Describe() []string {
	if !r.Present() {
		return []string{"no CP payload in the response"}
	}
	out := []string{fmt.Sprintf("%s, %d octets", ConfigTypeName(r.Type), len(r.Raw))}
	for _, ip := range r.IPv4Address {
		out = append(out, "INTERNAL_IP4_ADDRESS    "+ip.String())
	}
	if r.IPv4Netmask != nil {
		out = append(out, "INTERNAL_IP4_NETMASK    "+r.IPv4Netmask.String())
	}
	for _, ip := range r.IPv4DNS {
		out = append(out, "INTERNAL_IP4_DNS        "+ip.String())
	}
	for _, p := range r.IPv6Address {
		out = append(out, "INTERNAL_IP6_ADDRESS    "+p.String())
	}
	for _, ip := range r.IPv6DNS {
		out = append(out, "INTERNAL_IP6_DNS        "+ip.String())
	}
	for _, ip := range r.PCSCFIPv4 {
		out = append(out, "P_CSCF_IP4_ADDRESS      "+ip.String())
	}
	for _, ip := range r.PCSCFIPv6 {
		out = append(out, "P_CSCF_IP6_ADDRESS      "+ip.String())
	}
	if r.HasExpiry {
		out = append(out, "INTERNAL_ADDRESS_EXPIRY "+r.Expiry.String())
	}
	for _, attr := range r.Unrecognised {
		out = append(out, fmt.Sprintf("%-23s %x", ConfigAttributeName(attr.Type), attr.Value))
	}
	if !r.HavePCSCF() {
		out = append(out, "no P-CSCF address: a tunnel built on this reply has nowhere to send REGISTER")
	}
	return out
}

// ParseConfigReply decodes a CP payload body.
//
// Decoding is delegated to the mirror's ikev2.ParseConfiguration; what is added
// here is meaning. An attribute whose value is the wrong length for its type is
// an error and not a silently skipped field: four octets read as an address
// when the responder meant something else would put a wrong address into a
// receipt that claims to be evidence.
func ParseConfigReply(body []byte) (ConfigReply, error) {
	cfg, err := ikev2.ParseConfiguration(body)
	if err != nil {
		return ConfigReply{}, fmt.Errorf("%w: %w", ErrInvalidConfigReply, err)
	}
	out := ConfigReply{Type: cfg.Type, Raw: append([]byte(nil), body...)}
	for _, attr := range cfg.Attributes {
		// A zero-length attribute in a reply is the responder echoing the ask
		// without answering it. That is information, and it is not an address.
		if len(attr.Value) == 0 {
			out.Unrecognised = append(out.Unrecognised, attr)
			continue
		}
		switch attr.Type {
		case ikev2.ConfigInternalIPv4Address:
			ip, err := configIPv4(attr)
			if err != nil {
				return ConfigReply{}, err
			}
			out.IPv4Address = append(out.IPv4Address, ip)
		case ConfigInternalIPv4Netmask:
			ip, err := configIPv4(attr)
			if err != nil {
				return ConfigReply{}, err
			}
			out.IPv4Netmask = ip
		case ikev2.ConfigInternalIPv4DNS:
			ip, err := configIPv4(attr)
			if err != nil {
				return ConfigReply{}, err
			}
			out.IPv4DNS = append(out.IPv4DNS, ip)
		case ConfigPCSCFIPv4Address:
			ip, err := configIPv4(attr)
			if err != nil {
				return ConfigReply{}, err
			}
			out.PCSCFIPv4 = append(out.PCSCFIPv4, ip)
		case ikev2.ConfigInternalIPv6DNS:
			ip, err := configIPv6(attr)
			if err != nil {
				return ConfigReply{}, err
			}
			out.IPv6DNS = append(out.IPv6DNS, ip)
		case ConfigPCSCFIPv6Address:
			ip, err := configIPv6(attr)
			if err != nil {
				return ConfigReply{}, err
			}
			out.PCSCFIPv6 = append(out.PCSCFIPv6, ip)
		case ikev2.ConfigInternalIPv6Address:
			prefix, err := configIPv6Prefix(attr)
			if err != nil {
				return ConfigReply{}, err
			}
			out.IPv6Address = append(out.IPv6Address, prefix)
		case ikev2.ConfigInternalAddressExpiry:
			if len(attr.Value) != 4 {
				return ConfigReply{}, fmt.Errorf("%w: INTERNAL_ADDRESS_EXPIRY is %d octets, want 4",
					ErrInvalidConfigReply, len(attr.Value))
			}
			out.Expiry = time.Duration(binary.BigEndian.Uint32(attr.Value)) * time.Second
			out.HasExpiry = true
		default:
			out.Unrecognised = append(out.Unrecognised, ikev2.ConfigurationAttribute{
				Type:  attr.Type,
				Value: append([]byte(nil), attr.Value...),
			})
		}
	}
	return out, nil
}

func configIPv4(attr ikev2.ConfigurationAttribute) (net.IP, error) {
	if len(attr.Value) != net.IPv4len {
		return nil, fmt.Errorf("%w: %s is %d octets, want 4",
			ErrInvalidConfigReply, ConfigAttributeName(attr.Type), len(attr.Value))
	}
	return net.IPv4(attr.Value[0], attr.Value[1], attr.Value[2], attr.Value[3]), nil
}

func configIPv6(attr ikev2.ConfigurationAttribute) (net.IP, error) {
	if len(attr.Value) != net.IPv6len {
		return nil, fmt.Errorf("%w: %s is %d octets, want 16",
			ErrInvalidConfigReply, ConfigAttributeName(attr.Type), len(attr.Value))
	}
	return net.IP(append([]byte(nil), attr.Value...)), nil
}

func configIPv6Prefix(attr ikev2.ConfigurationAttribute) (IPv6Prefix, error) {
	if len(attr.Value) != net.IPv6len+1 {
		return IPv6Prefix{}, fmt.Errorf("%w: %s is %d octets, want 17 (16 of address, one of prefix length)",
			ErrInvalidConfigReply, ConfigAttributeName(attr.Type), len(attr.Value))
	}
	return IPv6Prefix{
		Address:   net.IP(append([]byte(nil), attr.Value[:net.IPv6len]...)),
		PrefixLen: attr.Value[net.IPv6len],
	}, nil
}
