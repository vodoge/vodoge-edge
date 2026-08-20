use std::borrow::Cow;

use crate::{Bearer, BearerSupport, Capability};

/// Runtime facts from the registration layer. The router reads this snapshot but
/// never initiates registration or sends a modem command itself.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RadioState {
    pub cellular_registered: bool,
    pub ims_registered: bool,
    pub sgs_available: bool,
}

impl RadioState {
    pub fn with_available(bearers: impl IntoIterator<Item = Bearer>) -> Self {
        let mut state = Self::default();
        for bearer in bearers {
            state.set_available(bearer, true);
        }
        state
    }

    pub fn is_available(&self, bearer: Bearer) -> bool {
        match bearer {
            Bearer::Cellular => self.cellular_registered,
            Bearer::Ims => self.ims_registered,
            Bearer::Sgs => self.sgs_available,
        }
    }

    pub fn set_available(&mut self, bearer: Bearer, available: bool) {
        match bearer {
            Bearer::Cellular => self.cellular_registered = available,
            Bearer::Ims => self.ims_registered = available,
            Bearer::Sgs => self.sgs_available = available,
        }
    }
}

/// The no-I/O result of deciding how to send one MO SMS.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SendPlan {
    pub primary: Option<Bearer>,
    pub fallback: Option<Bearer>,
    pub reason: Cow<'static, str>,
}

impl SendPlan {
    fn unavailable(reason: impl Into<Cow<'static, str>>) -> Self {
        Self {
            primary: None,
            fallback: None,
            reason: reason.into(),
        }
    }
}

/// Decides a main and optional backup bearer without performing I/O.
pub trait SmsRouter: Send + Sync {
    fn plan(&self, capability: &Capability, radio_state: &RadioState) -> SendPlan;
}

/// A deterministic router whose order is supplied by its vertical factory.
#[derive(Clone, Debug)]
pub struct OrderedSmsRouter {
    preferred: [Bearer; 3],
}

impl OrderedSmsRouter {
    /// Domestic lines prefer the circuit-switched/cellular path before IMS.
    pub fn cn() -> Self {
        Self::new([Bearer::Cellular, Bearer::Ims, Bearer::Sgs])
    }

    /// International lines use IMS as the fallback behind the cellular path.
    pub fn intl() -> Self {
        Self::new([Bearer::Cellular, Bearer::Ims, Bearer::Sgs])
    }

    pub fn new(preferred: [Bearer; 3]) -> Self {
        Self { preferred }
    }
}

impl SmsRouter for OrderedSmsRouter {
    fn plan(&self, capability: &Capability, radio_state: &RadioState) -> SendPlan {
        match &capability.sms_mo {
            BearerSupport::Unsupported { reason } => SendPlan::unavailable(reason.clone()),
            BearerSupport::Supported(bearer) if radio_state.is_available(*bearer) => SendPlan {
                primary: Some(*bearer),
                fallback: None,
                reason: Cow::Owned(format!(
                    "capability matrix authorizes {} as the SMS bearer",
                    bearer
                )),
            },
            BearerSupport::Supported(bearer) => SendPlan::unavailable(format!(
                "capability matrix authorizes {bearer}, but it is not currently registered"
            )),
            BearerSupport::Probe => {
                let available = self
                    .preferred
                    .iter()
                    .copied()
                    .filter(|bearer| radio_state.is_available(*bearer))
                    .collect::<Vec<_>>();

                match available.as_slice() {
                    [] => SendPlan::unavailable(
                        "SMS capability requires runtime probing and no bearer is currently available",
                    ),
                    [primary] => SendPlan {
                        primary: Some(*primary),
                        fallback: None,
                        reason: Cow::Owned(format!(
                            "SMS capability requires runtime probing; {} is available",
                            primary
                        )),
                    },
                    [primary, fallback, ..] => SendPlan {
                        primary: Some(*primary),
                        fallback: Some(*fallback),
                        reason: Cow::Owned(format!(
                            "SMS capability requires runtime probing; {} is primary and {} is fallback",
                            primary, fallback
                        )),
                    },
                }
            }
        }
    }
}
