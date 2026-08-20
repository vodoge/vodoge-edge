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
    pub fn unavailable(reason: impl Into<Cow<'static, str>>) -> Self {
        Self {
            primary: None,
            fallback: None,
            reason: reason.into(),
        }
    }

    pub fn with_reason(
        primary: Option<Bearer>,
        fallback: Option<Bearer>,
        reason: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self {
            primary,
            fallback,
            reason: reason.into(),
        }
    }
}

/// Decides a main and optional backup bearer without performing I/O.
pub trait SmsRouter: Send + Sync {
    fn plan(&self, capability: &Capability, radio_state: &RadioState) -> SendPlan;
}

/// A deterministic router whose order is supplied by its vertical factory.
///
/// Built-in verticals use dedicated routers because their fallback rules are not
/// a simple preference list. This helper remains for additional verticals that
/// only need an ordered probe sequence.
#[derive(Clone, Debug)]
pub struct OrderedSmsRouter {
    preferred: [Bearer; 3],
}

impl OrderedSmsRouter {
    pub fn new(preferred: [Bearer; 3]) -> Self {
        Self { preferred }
    }

    pub fn preferred(&self) -> [Bearer; 3] {
        self.preferred
    }
}

impl SmsRouter for OrderedSmsRouter {
    fn plan(&self, capability: &Capability, radio_state: &RadioState) -> SendPlan {
        match &capability.sms_mo {
            BearerSupport::Unsupported { reason } => SendPlan::unavailable(reason.clone()),
            BearerSupport::Supported(bearer) if radio_state.is_available(*bearer) => {
                SendPlan::with_reason(
                    Some(*bearer),
                    None,
                    format!("capability matrix authorizes {bearer} as the SMS bearer"),
                )
            }
            BearerSupport::Supported(bearer) => SendPlan::unavailable(format!(
                "capability matrix authorizes {bearer}, but it is not currently registered"
            )),
            BearerSupport::Probe => probe_in_order(self.preferred, radio_state),
        }
    }
}

pub(crate) fn veto_unsupported(capability: &Capability) -> Option<SendPlan> {
    match &capability.sms_mo {
        BearerSupport::Unsupported { reason } => Some(SendPlan::unavailable(reason.clone())),
        _ => None,
    }
}

pub(crate) fn authorized_bearer(capability: &Capability) -> Option<Bearer> {
    match capability.sms_mo {
        BearerSupport::Supported(bearer) => Some(bearer),
        _ => None,
    }
}

fn probe_in_order(preferred: [Bearer; 3], radio_state: &RadioState) -> SendPlan {
    let available = preferred
        .into_iter()
        .filter(|bearer| radio_state.is_available(*bearer))
        .collect::<Vec<_>>();

    match available.as_slice() {
        [] => SendPlan::unavailable(
            "SMS capability requires runtime probing and no bearer is currently available",
        ),
        [primary] => SendPlan::with_reason(
            Some(*primary),
            None,
            format!("SMS capability requires runtime probing; {primary} is available"),
        ),
        [primary, fallback, ..] => SendPlan::with_reason(
            Some(*primary),
            Some(*fallback),
            format!(
                "SMS capability requires runtime probing; {primary} is primary and {fallback} is fallback"
            ),
        ),
    }
}
