use edge_core::{arbitrate, Plmn, RegistrationEvidence, RegistrationSourceKind};

#[test]
fn serving_system_searching_with_lte_cell_is_treated_as_camped() {
    let verdict = arbitrate(&[
        RegistrationEvidence::serving_system(false, None),
        RegistrationEvidence::cell_location(
            Some(Plmn::new("460", "11")),
            Some(4_945_521),
        ),
    ]);

    assert!(verdict.registered);
    assert!(!verdict.recovery_allowed);
    assert!(verdict.conflict);
    assert_eq!(verdict.trusted_source, Some(RegistrationSourceKind::CellLocation));
}

#[test]
fn incomplete_cell_info_does_not_override_searching() {
    let verdict = arbitrate(&[
        RegistrationEvidence::serving_system(false, None),
        RegistrationEvidence::cell_location(Some(Plmn::new("460", "11")), None),
    ]);

    assert!(!verdict.registered);
    assert!(verdict.recovery_allowed);
    assert!(!verdict.conflict);
}

#[test]
fn high_confidence_registered_source_blocks_recovery() {
    let verdict = arbitrate(&[
        RegistrationEvidence::cereg(true),
        RegistrationEvidence::serving_system(false, None),
    ]);

    assert!(verdict.registered);
    assert!(!verdict.recovery_allowed);
    assert_eq!(verdict.trusted_source, Some(RegistrationSourceKind::Cereg));
}

#[test]
fn all_sources_unregistered_allows_recovery() {
    let verdict = arbitrate(&[
        RegistrationEvidence::serving_system(false, None),
        RegistrationEvidence::cereg(false),
        RegistrationEvidence::cell_location(None, None),
    ]);

    assert!(!verdict.registered);
    assert!(verdict.recovery_allowed);
}
