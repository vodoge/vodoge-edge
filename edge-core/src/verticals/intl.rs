use std::sync::Arc;

use crate::{
    authorized_bearer, veto_unsupported, Bearer, Capability, DataIntent, DeviceContext, EsimPolicy,
    EgressPolicy, NotificationPolicy, RadioState, RecoveryPreference, RegistrationPolicy,
    ReleaseScope, SendPlan, SmsRouter, StaticEsimPolicy, StaticEgressPolicy,
    StaticNotificationPolicy, StaticRegistrationPolicy, Vertical, VerticalFactory, VerticalId,
};

const ID: &str = "intl";

/// International line. Cellular is the preferred path when registered; IMS is
/// the documented fallback when the cellular path is down or a send fails.
pub struct IntlFactory;

#[derive(Clone, Copy, Debug, Default)]
struct IntlSmsRouter;

impl IntlSmsRouter {
    fn probe(radio_state: &RadioState) -> SendPlan {
        if radio_state.cellular_registered {
            if radio_state.ims_registered {
                SendPlan::with_reason(
                    Some(Bearer::Cellular),
                    Some(Bearer::Ims),
                    "intl vertical: cellular is registered; fall back to IMS on failure",
                )
            } else {
                SendPlan::with_reason(
                    Some(Bearer::Cellular),
                    None,
                    "intl vertical: cellular is registered and IMS is not available",
                )
            }
        } else if radio_state.ims_registered {
            SendPlan::with_reason(
                Some(Bearer::Ims),
                Some(Bearer::Cellular),
                "intl vertical: cellular is down; try IMS then retry cellular",
            )
        } else {
            SendPlan::with_reason(
                Some(Bearer::Cellular),
                None,
                "intl vertical: neither cellular nor IMS is registered; try cellular",
            )
        }
    }
}

impl SmsRouter for IntlSmsRouter {
    fn plan(&self, capability: &Capability, radio_state: &RadioState) -> SendPlan {
        if let Some(rejected) = veto_unsupported(capability) {
            return rejected;
        }

        if let Some(bearer) = authorized_bearer(capability) {
            if radio_state.is_available(bearer) {
                let fallback = match bearer {
                    Bearer::Cellular if radio_state.ims_registered => Some(Bearer::Ims),
                    Bearer::Ims if radio_state.cellular_registered => Some(Bearer::Cellular),
                    _ => None,
                };
                let reason = match fallback {
                    Some(fallback) => format!(
                        "intl vertical: capability matrix authorizes {bearer}; {fallback} is fallback"
                    ),
                    None => format!(
                        "intl vertical: capability matrix authorizes {bearer}; no fallback is registered"
                    ),
                };
                return SendPlan::with_reason(Some(bearer), fallback, reason);
            }

            return Self::probe(radio_state);
        }

        Self::probe(radio_state)
    }
}

impl VerticalFactory for IntlFactory {
    fn id(&self) -> VerticalId {
        VerticalId::from(ID)
    }

    fn matches(&self, context: &DeviceContext) -> bool {
        context.vertical == Vertical::Intl
    }

    fn sms_router(&self, _capability: &Capability) -> Arc<dyn SmsRouter> {
        Arc::new(IntlSmsRouter)
    }

    fn registration(&self, _capability: &Capability) -> Arc<dyn RegistrationPolicy> {
        Arc::new(StaticRegistrationPolicy::new(
            ID,
            true,
            RecoveryPreference::CellularFirst,
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
