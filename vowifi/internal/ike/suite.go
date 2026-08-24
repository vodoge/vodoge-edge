package ike

import (
	"errors"
	"fmt"

	"github.com/boa-z/vowifi-go/engine/swu/ikev2"
)

// Transform ids the mirror does not declare because it cannot key them.
// They exist here so the blocklist can name them; nothing puts them on the wire.
const (
	encr3DES        uint16 = 3 // RFC 7296 ENCR_3DES
	prfAES128XCBC   uint16 = 4 // RFC 4615 PRF_AES128_XCBC
	integAESXCBC96  uint16 = 5 // RFC 3566 AUTH_AES_XCBC_96
	integHMACSHA196 uint16 = 2 // RFC 2404 AUTH_HMAC_SHA1_96
)

var (
	// ErrLegacySuiteUnsupported reports a suite that is blocked by a type wall
	// in the mirror rather than by a missing switch case.
	ErrLegacySuiteUnsupported = errors.New("vowifi/ike: legacy suite blocked by vowifi-go type wall")
	// ErrSuiteRejected reports that a responder selected transforms we never
	// offered, or a combination the mirror cannot key.
	ErrSuiteRejected = errors.New("vowifi/ike: responder selection rejected")
)

// Suite is one encryption/PRF/integrity triple for the IKE SA.
type Suite struct {
	Name          string
	Encryption    uint16
	EncryptionKey uint16 // key length in bits; 0 means "no attribute"
	PRF           uint16
	Integrity     uint16
}

// MainstreamSuites are the IKE SA suites we offer, most preferred first.
//
// T038 measured exactly one suite in use across the mainstream nodes (T-Mobile
// majority plus all of AT&T): AES-CBC-128 / HMAC-SHA2-256-128 / HMAC-SHA2-256
// with DH group 14. It is listed first for that reason. The two stronger
// entries are additive: every one of them is expressible in the mirror's
// ikev2.KeyMaterialProfile, so offering them costs nothing and buys headroom if
// a node prefers SHA2-384/512.
func MainstreamSuites() []Suite {
	return []Suite{
		{
			Name:          "AES-CBC-128/HMAC-SHA2-256-128/PRF-HMAC-SHA2-256",
			Encryption:    ikev2.ENCR_AES_CBC,
			EncryptionKey: 128,
			PRF:           ikev2.PRF_HMAC_SHA2_256,
			Integrity:     ikev2.INTEG_HMAC_SHA2_256_128,
		},
		{
			Name:          "AES-CBC-256/HMAC-SHA2-384-192/PRF-HMAC-SHA2-384",
			Encryption:    ikev2.ENCR_AES_CBC,
			EncryptionKey: 256,
			PRF:           ikev2.PRF_HMAC_SHA2_384,
			Integrity:     ikev2.INTEG_HMAC_SHA2_384_192,
		},
		{
			Name:          "AES-CBC-256/HMAC-SHA2-512-256/PRF-HMAC-SHA2-512",
			Encryption:    ikev2.ENCR_AES_CBC,
			EncryptionKey: 256,
			PRF:           ikev2.PRF_HMAC_SHA2_512,
			Integrity:     ikev2.INTEG_HMAC_SHA2_512_256,
		},
	}
}

// DefaultProposalGroups is the DH group set T038 put on the wire, in the order
// it used. All seven ePDGs that answered picked group 14; not one picked 31.
func DefaultProposalGroups() []uint16 {
	return []uint16{GroupMODP2048, GroupMODP1024, GroupECP256, GroupX25519}
}

// LegacyBlocker names one place in the read-only mirror that refuses a legacy
// T-Mobile transform, so the reason is auditable without re-reading the mirror.
type LegacyBlocker struct {
	Transform string
	ID        uint16
	Location  string
	Reason    string
}

// LegacySuiteBlockers documents why the old T-Mobile suite observed by T038 on
// 208.54.26.131 (3DES / HMAC-SHA1-96 / AES128-XCBC) is not implemented here.
//
// This is not "the switch is missing a case". ikev2.KeyMaterialProfile.PRF is
// declared as crypto.Hash (engine/swu/ikev2/keys.go:13), and AES-XCBC-PRF is a
// CMAC construction: no crypto.Hash value can express it. Changing that field
// type ripples through the whole ikev2 package, which would mean forking the
// mirror. T041 forbids that, so the escape hatch is candidate selection: retry
// against the next ePDG the GSLB hands out.
//
// The GSLB evidence has a limit worth restating: T038 got seven distinct IPs in
// 208.54.0.0/16 from seven queries and .26.131 was one of them. That is a
// sample, not an enumeration - the pool may hold other legacy nodes. So the
// runner retries until something succeeds and records the suite each failing
// node selected, rather than dodging one hardcoded address.
func LegacySuiteBlockers() []LegacyBlocker {
	return []LegacyBlocker{
		{
			Transform: "PRF_AES128_XCBC",
			ID:        prfAES128XCBC,
			Location:  "engine/swu/ikev2/keys.go:13 (KeyMaterialProfile.PRF crypto.Hash) and keys.go:124-137 (PRFHashForTransform)",
			Reason:    "AES-XCBC-PRF is CMAC-family; no crypto.Hash value can represent it, so the blocker is the field type, not the switch",
		},
		{
			Transform: "ENCR_3DES",
			ID:        encr3DES,
			Location:  "engine/swu/ikev2/keys.go:148-170 (encryptionProfile)",
			Reason:    "encryptionProfile only admits ENCR 12 (AES-CBC) and ENCR 20 (AES-GCM-16)",
		},
		{
			Transform: "AUTH_AES_XCBC_96",
			ID:        integAESXCBC96,
			Location:  "engine/swu/ikev2/keys.go:183-196 (integrityProfile) and sk.go:358 (integrityHash)",
			Reason:    "integrityProfile admits INTEG 2/12/13/14 only, and integrityHash dispatches on crypto.Hash",
		},
	}
}

// LegacySuite returns the transform ids T038 saw on the old T-Mobile node,
// together with the error explaining why we will not negotiate them. It exists
// so a probe can label a node as "legacy, skip" instead of reporting a generic
// NO_PROPOSAL_CHOSEN.
func LegacySuite() (Suite, error) {
	return Suite{
			Name:       "3DES/HMAC-SHA1-96/PRF-AES128-XCBC (T-Mobile legacy, not implemented)",
			Encryption: encr3DES,
			PRF:        prfAES128XCBC,
			Integrity:  integAESXCBC96,
		}, fmt.Errorf("%w: %d blockers, see LegacySuiteBlockers", ErrLegacySuiteUnsupported,
			len(LegacySuiteBlockers()))
}

// IsLegacyTransform reports whether an id belongs to the blocked legacy suite.
func IsLegacyTransform(transformType uint8, id uint16) bool {
	switch transformType {
	case ikev2.TransformENCR:
		return id == encr3DES
	case ikev2.TransformPRF:
		return id == prfAES128XCBC
	case ikev2.TransformINTEG:
		return id == integAESXCBC96
	default:
		return false
	}
}

// BuildProposal renders one IKE SA proposal carrying every suite and every DH
// group, letting the responder pick.
//
// One proposal with several transforms of the same type is the RFC 7296 section
// 3.3 way to say "any of these": the responder selects exactly one transform per
// type. T038 used precisely this shape and all seven ePDGs answered.
func BuildProposal(suites []Suite, groups []uint16) (ikev2.SecurityAssociation, error) {
	if len(suites) == 0 {
		suites = MainstreamSuites()
	}
	if len(groups) == 0 {
		groups = DefaultProposalGroups()
	}
	var transforms []ikev2.Transform
	seen := map[string]bool{}
	add := func(t ikev2.Transform) {
		key := fmt.Sprintf("%d/%d/%v", t.Type, t.ID, t.Attributes)
		if seen[key] {
			return
		}
		seen[key] = true
		transforms = append(transforms, t)
	}

	for _, s := range suites {
		if IsLegacyTransform(ikev2.TransformENCR, s.Encryption) ||
			IsLegacyTransform(ikev2.TransformPRF, s.PRF) ||
			IsLegacyTransform(ikev2.TransformINTEG, s.Integrity) {
			return ikev2.SecurityAssociation{}, fmt.Errorf("%w: suite %q", ErrLegacySuiteUnsupported, s.Name)
		}
		encr := ikev2.Transform{Type: ikev2.TransformENCR, ID: s.Encryption}
		if s.EncryptionKey != 0 {
			encr.Attributes = []ikev2.TransformAttribute{ikev2.KeyLengthAttribute(s.EncryptionKey)}
		}
		add(encr)
		add(ikev2.Transform{Type: ikev2.TransformPRF, ID: s.PRF})
		add(ikev2.Transform{Type: ikev2.TransformINTEG, ID: s.Integrity})
	}
	for _, g := range groups {
		if !DHGroupSupported(g) {
			return ikev2.SecurityAssociation{}, fmt.Errorf("%w: cannot key %s", ErrUnsupportedDHGroup, DHGroupName(g))
		}
		add(ikev2.Transform{Type: ikev2.TransformDHRGroup, ID: g})
	}

	sa := ikev2.SecurityAssociation{Proposals: []ikev2.Proposal{{
		Number:     1,
		ProtocolID: ikev2.ProtocolIKE,
		Transforms: transforms,
	}}}
	// Fail here rather than on the wire if the shape is wrong.
	if _, err := sa.MarshalBinary(); err != nil {
		return ikev2.SecurityAssociation{}, err
	}
	return sa, nil
}

// Selection is what the responder chose, resolved against what we offered.
type Selection struct {
	Encryption    uint16
	EncryptionKey uint16
	PRF           uint16
	Integrity     uint16
	DHGroup       uint16
	SuiteName     string
}

// String renders a selection the way T038 tabulated live nodes.
func (s Selection) String() string {
	return fmt.Sprintf("ENCR %d/%d INTEG %d PRF %d DH %d (%s)",
		s.Encryption, s.EncryptionKey, s.Integrity, s.PRF, s.DHGroup, DHGroupName(s.DHGroup))
}

// ValidateSelection checks the responder's chosen proposal against ours.
//
// Deliberately not ikev2.ValidateSelectedSA: that helper compares transform
// attributes for exact equality (sa.go:transformsEqual), so a responder that
// echoes ENCR 12 without the key-length attribute - legal, since 128 is the
// default - would be rejected. The mirror's own KeyMaterialProfileFromSA already
// treats a missing length as 128 (keys.go:150-158), so rejecting it upstream of
// that would be stricter than the code that consumes the result.
func ValidateSelection(offered, selected ikev2.SecurityAssociation) (Selection, error) {
	if len(selected.Proposals) != 1 {
		return Selection{}, fmt.Errorf("%w: %d proposals selected, want exactly 1", ErrSuiteRejected, len(selected.Proposals))
	}
	if len(offered.Proposals) == 0 {
		return Selection{}, fmt.Errorf("%w: nothing was offered", ErrSuiteRejected)
	}
	chosen := selected.Proposals[0]
	if chosen.ProtocolID != ikev2.ProtocolIKE {
		return Selection{}, fmt.Errorf("%w: protocol %d, want IKE", ErrSuiteRejected, chosen.ProtocolID)
	}

	var out Selection
	found := map[uint8]bool{}
	for _, tr := range chosen.Transforms {
		if found[tr.Type] {
			return Selection{}, fmt.Errorf("%w: duplicate transform type %d", ErrSuiteRejected, tr.Type)
		}
		found[tr.Type] = true
		if IsLegacyTransform(tr.Type, tr.ID) {
			suite, legacyErr := LegacySuite()
			return Selection{}, fmt.Errorf("%w: responder chose transform type %d id %d from %s: %w",
				ErrSuiteRejected, tr.Type, tr.ID, suite.Name, legacyErr)
		}
		if !offerContains(offered, tr) {
			return Selection{}, fmt.Errorf("%w: transform type %d id %d was never offered", ErrSuiteRejected, tr.Type, tr.ID)
		}
		switch tr.Type {
		case ikev2.TransformENCR:
			out.Encryption = tr.ID
			out.EncryptionKey = attributeKeyLength(tr)
		case ikev2.TransformPRF:
			out.PRF = tr.ID
		case ikev2.TransformINTEG:
			out.Integrity = tr.ID
		case ikev2.TransformDHRGroup:
			out.DHGroup = tr.ID
		}
	}
	for _, required := range []uint8{ikev2.TransformENCR, ikev2.TransformPRF, ikev2.TransformINTEG, ikev2.TransformDHRGroup} {
		if !found[required] {
			return Selection{}, fmt.Errorf("%w: selection is missing transform type %d", ErrSuiteRejected, required)
		}
	}
	if out.EncryptionKey == 0 && out.Encryption == ikev2.ENCR_AES_CBC {
		out.EncryptionKey = 128 // RFC 7296 default, matching keys.go:150-158
	}
	if !DHGroupSupported(out.DHGroup) {
		return Selection{}, fmt.Errorf("%w: cannot key selected %s", ErrUnsupportedDHGroup, DHGroupName(out.DHGroup))
	}
	if _, err := ikev2.PRFHashForTransform(out.PRF); err != nil {
		return Selection{}, fmt.Errorf("%w: %w", ErrSuiteRejected, err)
	}
	out.SuiteName = suiteNameFor(out)
	return out, nil
}

func suiteNameFor(sel Selection) string {
	for _, s := range MainstreamSuites() {
		if s.Encryption == sel.Encryption && s.PRF == sel.PRF && s.Integrity == sel.Integrity {
			if s.EncryptionKey == sel.EncryptionKey || s.EncryptionKey == 0 {
				return s.Name
			}
		}
	}
	return "non-catalogued suite"
}

// offerContains matches a selected transform against the offer, ignoring a
// missing key-length attribute on the responder side.
func offerContains(offered ikev2.SecurityAssociation, selected ikev2.Transform) bool {
	selectedBits := attributeKeyLength(selected)
	for _, p := range offered.Proposals {
		for _, tr := range p.Transforms {
			if tr.Type != selected.Type || tr.ID != selected.ID {
				continue
			}
			if selectedBits == 0 {
				return true
			}
			if attributeKeyLength(tr) == selectedBits {
				return true
			}
		}
	}
	return false
}

func attributeKeyLength(t ikev2.Transform) uint16 {
	for _, attr := range t.Attributes {
		if attr.Type == ikev2.AttributeKeyLength && len(attr.Value) >= 2 {
			return uint16(attr.Value[0])<<8 | uint16(attr.Value[1])
		}
	}
	return 0
}

// OfferedGroups lists the DH groups present in a proposal, in wire order.
func OfferedGroups(sa ikev2.SecurityAssociation) []uint16 {
	var out []uint16
	for _, p := range sa.Proposals {
		for _, tr := range p.Transforms {
			if tr.Type == ikev2.TransformDHRGroup {
				out = append(out, tr.ID)
			}
		}
	}
	return out
}
