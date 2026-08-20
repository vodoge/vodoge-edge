use edge_core::{
    Bearer, Capability, CarrierProfile, DataIntent, DeviceContext, LabFactory, ModemFamily,
    RadioState, RecoveryPreference, ReleaseScope, Vertical, VerticalFactory, builtin_registry,
};

#[test]
fn adding_lab_does_not_require_core_factory_or_sms_changes() {
    let factory_src = include_str!("../src/factory.rs");
    let sms_src = include_str!("../src/sms.rs");
    assert!(
        !factory_src.contains("LabFactory"),
        "factory.rs must stay vertical-agnostic"
    );
    assert!(
        !sms_src.contains("LabFactory"),
        "sms.rs must stay vertical-agnostic"
    );
    assert!(
        !factory_src.contains("\"lab\""),
        "factory.rs must not hard-code the lab vertical"
    );
}

#[test]
fn lab_is_selected_by_registering_one_factory() {
    let registry = builtin_registry();
    let context = DeviceContext::new(
        ModemFamily::EC20,
        CarrierProfile::GENERIC_INTERNATIONAL,
        Vertical::from("lab"),
    );

    let resolved = registry.resolve(&context);
    assert_eq!(resolved.id().as_str(), "lab");
    assert!(LabFactory.matches(&context));
}

#[test]
fn lab_policy_family_is_self_contained_and_distinct() {
    let capability = Capability::probe_all();
    let family = LabFactory.assemble(&capability);
    assert!(family.is_coherent());
    assert_eq!(family.vertical_id.as_str(), "lab");
    assert!(!family.registration.allow_ims());
    assert_eq!(
        family.registration.recovery_preference(),
        RecoveryPreference::ObserveOnly
    );
    assert!(!family.esim.allow_profile_download());
    assert_eq!(
        family.esim.switch_release_scope(),
        ReleaseScope::AllExceptEsimChannel
    );
    assert_eq!(family.egress.data_intent(), DataIntent::Deny);
    assert!(family.notification.surface_capability_unsupported());

    let radio = RadioState::with_available([Bearer::Sgs, Bearer::Ims, Bearer::Cellular]);
    let plan = family.sms.plan(&capability, &radio);
    assert_eq!(plan.primary, Some(Bearer::Sgs));
    assert_eq!(plan.fallback, Some(Bearer::Ims));
}

#[test]
fn unknown_verticals_fall_back_to_intl_without_selecting_lab() {
    let registry = builtin_registry();
    let context = DeviceContext::new(
        ModemFamily::EG25_G,
        CarrierProfile::GENERIC_INTERNATIONAL,
        Vertical::from("oceania"),
    );

    let resolved = registry.resolve(&context);
    assert_eq!(resolved.id().as_str(), "intl");
}
