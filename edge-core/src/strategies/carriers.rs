//! Carrier strategies.
//!
//! What a network does with a module attached to it. These deliberately hold
//! very little: almost everything about what works is a *measurement*, and
//! measurements live in the ledger. A carrier strategy is for behaviour that
//! is a property of the network rather than of one pairing — which bearer
//! carries a message, and refusals that apply to every module alike.

use crate::{Bearer, CarrierProfile, CarrierStrategy, Operation};

/// China Mobile.
pub struct CnMobileStrategy;

impl CarrierStrategy for CnMobileStrategy {
    fn id(&self) -> &'static str {
        "cn-mobile"
    }

    fn carriers(&self) -> Vec<CarrierProfile> {
        vec![CarrierProfile::CN_MOBILE]
    }
}

/// China Unicom.
pub struct CnUnicomStrategy;

impl CarrierStrategy for CnUnicomStrategy {
    fn id(&self) -> &'static str {
        "cn-unicom"
    }

    fn carriers(&self) -> Vec<CarrierProfile> {
        vec![CarrierProfile::CN_UNICOM]
    }
}

/// China Telecom.
///
/// Holds no refusal of its own. The EC20's inability to carry Telecom SMS is
/// a property of that *pairing* — no CDMA fallback and no Telecom VoLTE MBN on
/// that module — not of the network, and it is recorded against the pair in
/// the ledger. Putting it here would withhold Telecom SMS from every module
/// ever added, including ones that carry it perfectly well.
pub struct CnTelecomStrategy;

impl CarrierStrategy for CnTelecomStrategy {
    fn id(&self) -> &'static str {
        "cn-telecom"
    }

    fn carriers(&self) -> Vec<CarrierProfile> {
        vec![CarrierProfile::CN_TELECOM]
    }
}

/// Everything outside China, until a network earns its own strategy.
///
/// `Network::carrier_profile()` returns this for every MCC that is not 460, so
/// it covers Hong Kong CSL and T-Mobile US alike today. That is exactly why
/// the ledger is keyed on it and why per-plan differences are not: two cards
/// resolving to this profile in the same module can differ entirely, and the
/// thing that separates them is the subscription layer, not this one.
pub struct InternationalStrategy;

impl CarrierStrategy for InternationalStrategy {
    fn id(&self) -> &'static str {
        "generic-international"
    }

    fn carriers(&self) -> Vec<CarrierProfile> {
        vec![CarrierProfile::GENERIC_INTERNATIONAL]
    }

    fn bearer(&self, operation: Operation, measured: Bearer) -> Option<Bearer> {
        // Leaves the measurement alone. Named rather than defaulted so the
        // next person to add a roaming rule sees where it goes.
        let _ = (operation, measured);
        None
    }
}
