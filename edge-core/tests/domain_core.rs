use std::sync::Arc;

use edge_core::{
    Bearer, BearerSupport, Capability, CapabilityMatrix, CapabilityOrigin, CarrierProfile,
    DeviceContext, ModemFamily, OrderedSmsRouter, RadioState, SmsRouter, Vertical, VerticalFactory,
    VerticalId, VerticalRegistry,
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

    let plan = OrderedSmsRouter::cn().plan(
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

    let plan = OrderedSmsRouter::cn().plan(
        query.capability,
        &RadioState::with_available([Bearer::Cellular, Bearer::Ims]),
    );
    assert_eq!(plan.primary, Some(Bearer::Cellular));
    assert_eq!(plan.fallback, None);
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
fn probe_capability_produces_a_primary_and_backup_bearer_plan() {
    let router = OrderedSmsRouter::cn();
    let plan = router.plan(
        &Capability::probe_all(),
        &RadioState::with_available([Bearer::Cellular, Bearer::Ims]),
    );

    assert_eq!(plan.primary, Some(Bearer::Cellular));
    assert_eq!(plan.fallback, Some(Bearer::Ims));
}

#[test]
fn international_router_uses_ims_as_the_probe_fallback() {
    let router = OrderedSmsRouter::intl();
    let plan = router.plan(
        &Capability::probe_all(),
        &RadioState::with_available([Bearer::Cellular, Bearer::Ims]),
    );

    assert_eq!(plan.primary, Some(Bearer::Cellular));
    assert_eq!(plan.fallback, Some(Bearer::Ims));
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
        Arc::new(OrderedSmsRouter::cn())
    }
}
