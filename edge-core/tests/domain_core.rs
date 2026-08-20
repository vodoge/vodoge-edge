use std::sync::Arc;

use edge_core::{
    Bearer, BearerSupport, Capability, CapabilityMatrix, CapabilityOrigin, CarrierProfile,
    DeviceContext, EsimPolicy, EgressPolicy, ModemFamily, NotificationPolicy, OrderedSmsRouter,
    RadioState, RegistrationPolicy, SmsRouter, Vertical, VerticalFactory, VerticalId,
    VerticalRegistry, builtin_registry, CnFactory, DataIntent, IntlFactory, RecoveryPreference,
    ReleaseScope,
};

#[test]
fn ec20_on_cn_telecom_is_rejected_before_a_send_attempt() {
    let matrix = CapabilityMatrix::builtin().expect("built-in matrix is valid TOML");
    let query = matrix.query(&ModemFamily::EC20, &CarrierProfile::CN_TELECOM);

    assert_eq!(query.origin, CapabilityOrigin::Rule);
    assert_eq!(
        query.capability.sms_mo,
        BearerSupport::unsupported("no_cdma_fallback_and_no_ct_volte_mbn")
    );
    assert_eq!(
        query.capability.sms_mt,
        BearerSupport::unsupported("no_cdma_fallback_and_no_ct_volte_mbn")
    );

    let plan = CnFactory
        .sms_router(query.capability)
        .plan(
            query.capability,
            &RadioState::with_available([Bearer::Cellular, Bearer::Ims]),
        );
    assert_eq!(plan.primary, None);
    assert_eq!(plan.fallback, None);
    assert_eq!(plan.reason, "no_cdma_fallback_and_no_ct_volte_mbn");
}

#[test]
fn ec20_on_cn_mobile_has_a_cellular_sms_bearer() {
    let matrix = CapabilityMatrix::builtin().expect("built-in matrix is valid TOML");
    let query = matrix.query(&ModemFamily::EC20, &CarrierProfile::CN_MOBILE);

    assert_eq!(query.origin, CapabilityOrigin::Rule);
    assert_eq!(
        query.capability.sms_mo,
        BearerSupport::Supported(Bearer::Cellular)
    );

    let radio = RadioState::with_available([Bearer::Cellular, Bearer::Ims]);
    let cn_plan = CnFactory.sms_router(query.capability).plan(query.capability, &radio);
    assert_eq!(cn_plan.primary, Some(Bearer::Cellular));
    assert_eq!(cn_plan.fallback, None);

    let intl_plan = IntlFactory
        .sms_router(query.capability)
        .plan(query.capability, &radio);
    assert_eq!(intl_plan.primary, Some(Bearer::Cellular));
    assert_eq!(intl_plan.fallback, Some(Bearer::Ims));
}

#[test]
fn unmatched_matrix_query_has_an_explicit_probe_fallback() {
    let matrix = CapabilityMatrix::from_toml(
        r#"
            version = "test"
            [fallback]
            sms_mo = { kind = "probe" }

            [[rule]]
            modem_family = "EC20"
            carrier = "CN-Mobile"
            sms_mo = { kind = "supported", bearer = "cellular" }
        "#,
    )
    .expect("test matrix is valid");

    let query = matrix.query(&ModemFamily::EC25_CN, &CarrierProfile::CN_MOBILE);
    assert_eq!(matrix.version(), "test");
    assert_eq!(query.origin, CapabilityOrigin::Fallback);
    assert_eq!(query.capability, &Capability::probe_all());
}

#[test]
fn registry_uses_the_first_matching_factory() {
    let registry = VerticalRegistry::new(
        Arc::new(TestFactory::new("fallback", false)),
        vec![
            Arc::new(TestFactory::new("first", true)),
            Arc::new(TestFactory::new("second", true)),
        ],
    );

    let resolved = registry.resolve(&cn_context());
    assert_eq!(resolved.id().as_str(), "first");
}

#[test]
fn registry_uses_fallback_when_no_factory_matches() {
    let registry = VerticalRegistry::new(
        Arc::new(TestFactory::new("fallback", false)),
        vec![Arc::new(TestFactory::new("does-not-match", false))],
    );

    let resolved = registry.resolve(&cn_context());
    assert_eq!(resolved.id().as_str(), "fallback");
}

#[test]
fn cn_probe_uses_ims_only_when_ims_is_registered() {
    let router = CnFactory.sms_router(&Capability::probe_all());
    let plan = router.plan(
        &Capability::probe_all(),
        &RadioState::with_available([Bearer::Cellular, Bearer::Ims]),
    );

    assert_eq!(plan.primary, Some(Bearer::Ims));
    assert_eq!(plan.fallback, None);
}

#[test]
fn international_router_uses_ims_as_the_probe_fallback() {
    let router = IntlFactory.sms_router(&Capability::probe_all());
    let plan = router.plan(
        &Capability::probe_all(),
        &RadioState::with_available([Bearer::Cellular, Bearer::Ims]),
    );

    assert_eq!(plan.primary, Some(Bearer::Cellular));
    assert_eq!(plan.fallback, Some(Bearer::Ims));
}

#[test]
fn cn_and_intl_policy_families_are_not_mixed() {
    let capability = Capability::probe_all();
    let cn = CnFactory.assemble(&capability);
    let intl = IntlFactory.assemble(&capability);

    assert!(cn.is_coherent());
    assert!(intl.is_coherent());
    assert_ne!(cn.vertical_id, intl.vertical_id);
    assert_eq!(cn.registration.recovery_preference(), RecoveryPreference::ImsFirst);
    assert_eq!(
        intl.registration.recovery_preference(),
        RecoveryPreference::CellularFirst
    );

    let radio = RadioState::with_available([Bearer::Cellular, Bearer::Ims]);
    assert_ne!(
        cn.sms.plan(&capability, &radio),
        intl.sms.plan(&capability, &radio)
    );
}

fn cn_context() -> DeviceContext {
    DeviceContext::new(
        ModemFamily::EC20,
        CarrierProfile::CN_MOBILE,
        Vertical::CN,
    )
}

struct TestFactory {
    id: VerticalId,
    matches: bool,
}

impl TestFactory {
    fn new(id: &str, matches: bool) -> Self {
        Self {
            id: VerticalId::from(id),
            matches,
        }
    }
}

impl VerticalFactory for TestFactory {
    fn id(&self) -> VerticalId {
        self.id.clone()
    }

    fn matches(&self, _context: &DeviceContext) -> bool {
        self.matches
    }

    fn sms_router(&self, _capability: &Capability) -> Arc<dyn SmsRouter> {
        Arc::new(OrderedSmsRouter::new([
            Bearer::Cellular,
            Bearer::Ims,
            Bearer::Sgs,
        ]))
    }

    fn registration(&self, _capability: &Capability) -> Arc<dyn RegistrationPolicy> {
        Arc::new(edge_core::StaticRegistrationPolicy::new(
            self.id.as_str().to_owned(),
            false,
            RecoveryPreference::ObserveOnly,
        ))
    }

    fn esim(&self) -> Arc<dyn EsimPolicy> {
        Arc::new(edge_core::StaticEsimPolicy::new(
            self.id.as_str().to_owned(),
            ReleaseScope::AllExceptEsimChannel,
            false,
        ))
    }

    fn egress(&self) -> Arc<dyn EgressPolicy> {
        Arc::new(edge_core::StaticEgressPolicy::new(
            self.id.as_str().to_owned(),
            DataIntent::Deny,
        ))
    }

    fn notification(&self) -> Arc<dyn NotificationPolicy> {
        Arc::new(edge_core::StaticNotificationPolicy::new(
            self.id.as_str().to_owned(),
            true,
            false,
        ))
    }
}

#[test]
fn builtin_registry_is_available_to_callers() {
    let registry = builtin_registry();
    let ids = registry
        .factory_ids()
        .into_iter()
        .map(|id| id.as_str().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(ids, vec!["cn", "intl", "lab"]);
}
