use std::sync::Arc;

use crate::{
    Bearer, Capability, DataIntent, DeviceContext, EsimPolicy, EgressPolicy, NotificationPolicy,
    OrderedSmsRouter, RecoveryPreference, RegistrationPolicy, ReleaseScope, SmsRouter,
    StaticEsimPolicy, StaticEgressPolicy, StaticNotificationPolicy, StaticRegistrationPolicy,
    Vertical, VerticalFactory, VerticalId,
};

const ID: &str = "lab";

/// Fictional lab vertical used as the extensibility proof.
///
/// Adding this vertical required this file and one registration line in
/// `builtin_registry`. Core routing, matrix loading, and the factory trait were
/// not modified.
pub struct LabFactory;

impl VerticalFactory for LabFactory {
    fn id(&self) -> VerticalId {
        VerticalId::from(ID)
    }

    fn matches(&self, context: &DeviceContext) -> bool {
        context.vertical == Vertical::from(ID)
    }

    fn sms_router(&self, _capability: &Capability) -> Arc<dyn SmsRouter> {
        Arc::new(OrderedSmsRouter::new([
            Bearer::Sgs,
            Bearer::Ims,
            Bearer::Cellular,
        ]))
    }

    fn registration(&self, _capability: &Capability) -> Arc<dyn RegistrationPolicy> {
        Arc::new(StaticRegistrationPolicy::new(
            ID,
            false,
            RecoveryPreference::ObserveOnly,
        ))
    }

    fn esim(&self) -> Arc<dyn EsimPolicy> {
        Arc::new(StaticEsimPolicy::new(
            ID,
            ReleaseScope::AllExceptEsimChannel,
            false,
        ))
    }

    fn egress(&self) -> Arc<dyn EgressPolicy> {
        Arc::new(StaticEgressPolicy::new(ID, DataIntent::Deny))
    }

    fn notification(&self) -> Arc<dyn NotificationPolicy> {
        Arc::new(StaticNotificationPolicy::new(ID, true, true))
    }
}
