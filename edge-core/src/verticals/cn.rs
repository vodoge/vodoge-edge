use std::sync::Arc;

use crate::{
    authorized_bearer, veto_unsupported, Bearer, Capability, DataIntent, DeviceContext, EsimPolicy,
    EgressPolicy, NotificationPolicy, RadioState, RecoveryPreference, RegistrationPolicy,
    ReleaseScope, SendPlan, SmsRouter, StaticEsimPolicy, StaticEgressPolicy,
    StaticNotificationPolicy, StaticRegistrationPolicy, Vertical, VerticalFactory, VerticalId,
};

const ID: &str = "cn";

/// Domestic line. Known bearers from the matrix are used as-is; unknown
/// combinations follow the existing VoWiFi-or-cellular rule and never mix a
/// fallback bearer into a domestic send.
pub struct CnFactory;

#[derive(Clone, Copy, Debug, Default)]
struct CnSmsRouter;

impl SmsRouter for CnSmsRouter {
    fn plan(&self, capability: &Capability, radio_state: &RadioState) -> SendPlan {
        if let Some(rejected) = veto_unsupported(capability) {
            return rejected;
        }

        if let Some(bearer) = authorized_bearer(capability) {
            return if radio_state.is_available(bearer) {
                SendPlan::with_reason(
                    Some(bearer),
                    None,
                    format!("cn vertical: capability matrix authorizes {bearer}; no fallback"),
                )
            } else {
                SendPlan::unavailable(format!(
                    "cn vertical: capability matrix authorizes {bearer}, but it is not currently registered"
                ))
            };
        }

        if radio_state.ims_registered {
            SendPlan::with_reason(
                Some(Bearer::Ims),
                None,
                "cn vertical: IMS is registered; send over IMS only",
            )
        } else {
            SendPlan::with_reason(
                Some(Bearer::Cellular),
                None,
                "cn vertical: IMS is not registered; send over cellular only",
            )
        }
    }
}

impl VerticalFactory for CnFactory {
    fn id(&self) -> VerticalId {
        VerticalId::from(ID)
    }

    fn matches(&self, context: &DeviceContext) -> bool {
        context.vertical == Vertical::Cn
    }

    fn sms_router(&self, _capability: &Capability) -> Arc<dyn SmsRouter> {
        Arc::new(CnSmsRouter)
    }

    fn registration(&self, _capability: &Capability) -> Arc<dyn RegistrationPolicy> {
        Arc::new(StaticRegistrationPolicy::new(
            ID,
            true,
            RecoveryPreference::ImsFirst,
        ))
    }

    fn esim(&self) -> Arc<dyn EsimPolicy> {
        Arc::new(StaticEsimPolicy::new(
            ID,
            ReleaseScope::AllExceptEsimChannel,
            true,
        ))
    }

    fn egress(&self) -> Arc<dyn EgressPolicy> {
        Arc::new(StaticEgressPolicy::new(ID, DataIntent::AllowCellular))
    }

    fn notification(&self) -> Arc<dyn NotificationPolicy> {
        Arc::new(StaticNotificationPolicy::new(ID, true, true))
    }
}
