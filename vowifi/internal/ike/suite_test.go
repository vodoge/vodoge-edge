package ike

import (
	"errors"
	"testing"

	"github.com/boa-z/vowifi-go/engine/swu/ikev2"
)

// TestProposalCarriesTheGroupsT038Measured pins the wire offer to the evidence.
func TestProposalCarriesTheGroupsT038Measured(t *testing.T) {
	sa, err := BuildProposal(nil, nil)
	if err != nil {
		t.Fatalf("BuildProposal: %v", err)
	}
	got := OfferedGroups(sa)
	want := []uint16{GroupMODP2048, GroupMODP1024, GroupECP256, GroupX25519}
	if len(got) != len(want) {
		t.Fatalf("offered groups = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("offered groups = %v, want %v (order is the T038 offer)", got, want)
		}
	}
	if got[0] != GroupMODP2048 {
		t.Errorf("group 14 must lead: all seven ePDGs in T038 chose it and none chose 31")
	}

	// The mirror's DefaultIKEProposal (sa.go:73-83) offers only group 31, which
	// is why we never use it. Guard against a future refactor quietly adopting it.
	if stock := OfferedGroups(ikev2.DefaultIKEProposal()); len(stock) != 1 || stock[0] != GroupX25519 {
		t.Logf("note: the mirror default now offers %v", stock)
	} else if len(got) == 1 && got[0] == GroupX25519 {
		t.Fatalf("we regressed onto the mirror's group-31-only proposal")
	}
}

// TestProposalNeverCarriesLegacyTransforms is the T-Mobile legacy guard.
func TestProposalNeverCarriesLegacyTransforms(t *testing.T) {
	sa, err := BuildProposal(nil, nil)
	if err != nil {
		t.Fatalf("BuildProposal: %v", err)
	}
	for _, p := range sa.Proposals {
		for _, tr := range p.Transforms {
			if IsLegacyTransform(tr.Type, tr.ID) {
				t.Errorf("proposal carries blocked legacy transform type %d id %d", tr.Type, tr.ID)
			}
		}
	}

	// Asking for the legacy suite explicitly must fail loudly, not silently
	// negotiate something else.
	legacy, err := LegacySuite()
	if !errors.Is(err, ErrLegacySuiteUnsupported) {
		t.Fatalf("LegacySuite error = %v, want ErrLegacySuiteUnsupported", err)
	}
	if _, err := BuildProposal([]Suite{legacy}, nil); !errors.Is(err, ErrLegacySuiteUnsupported) {
		t.Fatalf("BuildProposal(legacy) error = %v, want ErrLegacySuiteUnsupported", err)
	}

	blockers := LegacySuiteBlockers()
	if len(blockers) != 3 {
		t.Fatalf("expected three documented blockers, got %d", len(blockers))
	}
	for _, b := range blockers {
		if b.Location == "" || b.Reason == "" {
			t.Errorf("blocker %s is undocumented", b.Transform)
		}
	}

	// The claim in the note is that this is a type wall, not a missing case.
	// Verify the mirror really does refuse each id, so the note stays true if
	// the mirror is ever bumped.
	if _, err := ikev2.PRFHashForTransform(prfAES128XCBC); err == nil {
		t.Errorf("the mirror now keys PRF_AES128_XCBC; the blocker list is stale")
	}
	if _, err := ikev2.PRFHashForTransform(ikev2.PRF_HMAC_SHA2_256); err != nil {
		t.Errorf("the mirror stopped keying PRF_HMAC_SHA2_256: %v", err)
	}
}

// TestEveryOfferedSuiteIsKeyable makes sure we never propose something the
// mirror cannot turn into key material. A responder picking it would leave us
// negotiating successfully and then failing at derivation.
func TestEveryOfferedSuiteIsKeyable(t *testing.T) {
	for _, s := range MainstreamSuites() {
		selected := ikev2.SecurityAssociation{Proposals: []ikev2.Proposal{{
			Number:     1,
			ProtocolID: ikev2.ProtocolIKE,
			Transforms: []ikev2.Transform{
				{Type: ikev2.TransformENCR, ID: s.Encryption, Attributes: []ikev2.TransformAttribute{ikev2.KeyLengthAttribute(s.EncryptionKey)}},
				{Type: ikev2.TransformPRF, ID: s.PRF},
				{Type: ikev2.TransformINTEG, ID: s.Integrity},
				{Type: ikev2.TransformDHRGroup, ID: GroupMODP2048},
			},
		}}}
		profile, err := ikev2.KeyMaterialProfileFromSA(selected)
		if err != nil {
			t.Errorf("%s: KeyMaterialProfileFromSA = %v", s.Name, err)
			continue
		}
		if profile.RequiredLength() <= 0 {
			t.Errorf("%s: RequiredLength = %d", s.Name, profile.RequiredLength())
		}
	}
}

func TestValidateSelectionAcceptsMissingKeyLength(t *testing.T) {
	offered, err := BuildProposal(nil, nil)
	if err != nil {
		t.Fatalf("BuildProposal: %v", err)
	}
	// A responder that echoes ENCR 12 with no key-length attribute is legal:
	// 128 is the default. ikev2.ValidateSelectedSA would reject this because
	// transformsEqual compares attributes exactly, so we do our own check.
	selected := ikev2.SecurityAssociation{Proposals: []ikev2.Proposal{{
		Number:     1,
		ProtocolID: ikev2.ProtocolIKE,
		Transforms: []ikev2.Transform{
			{Type: ikev2.TransformENCR, ID: ikev2.ENCR_AES_CBC},
			{Type: ikev2.TransformPRF, ID: ikev2.PRF_HMAC_SHA2_256},
			{Type: ikev2.TransformINTEG, ID: ikev2.INTEG_HMAC_SHA2_256_128},
			{Type: ikev2.TransformDHRGroup, ID: GroupMODP2048},
		},
	}}}
	sel, err := ValidateSelection(offered, selected)
	if err != nil {
		t.Fatalf("ValidateSelection: %v", err)
	}
	if sel.EncryptionKey != 128 {
		t.Errorf("EncryptionKey = %d, want the RFC default of 128", sel.EncryptionKey)
	}
	if err := ikev2.ValidateSelectedSA(offered, selected); err == nil {
		t.Logf("note: the mirror now accepts an attribute-free ENCR echo too")
	}
}

func TestValidateSelectionRejectsUnofferedAndLegacy(t *testing.T) {
	offered, err := BuildProposal(nil, nil)
	if err != nil {
		t.Fatalf("BuildProposal: %v", err)
	}
	base := []ikev2.Transform{
		{Type: ikev2.TransformENCR, ID: ikev2.ENCR_AES_CBC, Attributes: []ikev2.TransformAttribute{ikev2.KeyLengthAttribute(128)}},
		{Type: ikev2.TransformPRF, ID: ikev2.PRF_HMAC_SHA2_256},
		{Type: ikev2.TransformINTEG, ID: ikev2.INTEG_HMAC_SHA2_256_128},
		{Type: ikev2.TransformDHRGroup, ID: GroupMODP2048},
	}

	t.Run("legacy PRF", func(t *testing.T) {
		transforms := append([]ikev2.Transform(nil), base...)
		transforms[1] = ikev2.Transform{Type: ikev2.TransformPRF, ID: prfAES128XCBC}
		_, err := ValidateSelection(offered, wrap(transforms))
		if !errors.Is(err, ErrSuiteRejected) || !errors.Is(err, ErrLegacySuiteUnsupported) {
			t.Fatalf("error = %v, want both ErrSuiteRejected and ErrLegacySuiteUnsupported", err)
		}
	})

	t.Run("unoffered group", func(t *testing.T) {
		transforms := append([]ikev2.Transform(nil), base...)
		transforms[3] = ikev2.Transform{Type: ikev2.TransformDHRGroup, ID: GroupECP384}
		if _, err := ValidateSelection(offered, wrap(transforms)); !errors.Is(err, ErrSuiteRejected) {
			t.Fatalf("error = %v, want ErrSuiteRejected", err)
		}
	})

	t.Run("mismatched key length", func(t *testing.T) {
		transforms := append([]ikev2.Transform(nil), base...)
		transforms[0] = ikev2.Transform{Type: ikev2.TransformENCR, ID: ikev2.ENCR_AES_CBC,
			Attributes: []ikev2.TransformAttribute{ikev2.KeyLengthAttribute(192)}}
		if _, err := ValidateSelection(offered, wrap(transforms)); !errors.Is(err, ErrSuiteRejected) {
			t.Fatalf("error = %v, want ErrSuiteRejected", err)
		}
	})

	t.Run("missing transform type", func(t *testing.T) {
		if _, err := ValidateSelection(offered, wrap(base[:3])); !errors.Is(err, ErrSuiteRejected) {
			t.Fatalf("error = %v, want ErrSuiteRejected", err)
		}
	})

	t.Run("two proposals", func(t *testing.T) {
		sa := ikev2.SecurityAssociation{Proposals: []ikev2.Proposal{
			wrap(base).Proposals[0], wrap(base).Proposals[0],
		}}
		if _, err := ValidateSelection(offered, sa); !errors.Is(err, ErrSuiteRejected) {
			t.Fatalf("error = %v, want ErrSuiteRejected", err)
		}
	})
}

func TestSelectionStringNamesTheSuite(t *testing.T) {
	offered, err := BuildProposal(nil, nil)
	if err != nil {
		t.Fatalf("BuildProposal: %v", err)
	}
	sel, err := ValidateSelection(offered, wrap([]ikev2.Transform{
		{Type: ikev2.TransformENCR, ID: ikev2.ENCR_AES_CBC, Attributes: []ikev2.TransformAttribute{ikev2.KeyLengthAttribute(128)}},
		{Type: ikev2.TransformPRF, ID: ikev2.PRF_HMAC_SHA2_256},
		{Type: ikev2.TransformINTEG, ID: ikev2.INTEG_HMAC_SHA2_256_128},
		{Type: ikev2.TransformDHRGroup, ID: GroupMODP2048},
	}))
	if err != nil {
		t.Fatalf("ValidateSelection: %v", err)
	}
	if sel.SuiteName != MainstreamSuites()[0].Name {
		t.Errorf("SuiteName = %q, want the mainstream suite T038 measured", sel.SuiteName)
	}
	if sel.String() == "" {
		t.Errorf("Selection.String is empty")
	}
}

func wrap(transforms []ikev2.Transform) ikev2.SecurityAssociation {
	return ikev2.SecurityAssociation{Proposals: []ikev2.Proposal{{
		Number:     1,
		ProtocolID: ikev2.ProtocolIKE,
		Transforms: transforms,
	}}}
}
