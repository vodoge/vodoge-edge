//! The strategies for hardware and networks that exist on this bench.
//!
//! Every one of these is here because a module or a card was put in front of
//! it. Adding a strategy for hardware nobody has run is how the EC25-E hazard
//! gets re-created: an object that looks like support, backed by nothing.

mod carriers;
mod modems;

pub use carriers::{CnMobileStrategy, CnTelecomStrategy, CnUnicomStrategy, InternationalStrategy};
pub use modems::{Ec200uStrategy, QuectelEcStrategy};

use std::sync::Arc;

use crate::{StrategyError, StrategyRegistry, SupportLedger};

/// The registry as this build ships it.
///
/// The ledger is passed in rather than baked here: what has been tested is a
/// fact about the world that changes without the code changing, and the
/// binary must not be the place it is edited.
pub fn registry(ledger: SupportLedger) -> Result<StrategyRegistry, StrategyError> {
    StrategyRegistry::new(ledger)
        .with_modem(Arc::new(QuectelEcStrategy))?
        .with_modem(Arc::new(Ec200uStrategy))?
        .with_carrier(Arc::new(CnMobileStrategy))?
        .with_carrier(Arc::new(CnUnicomStrategy))?
        .with_carrier(Arc::new(CnTelecomStrategy))?
        .with_carrier(Arc::new(InternationalStrategy))
}
