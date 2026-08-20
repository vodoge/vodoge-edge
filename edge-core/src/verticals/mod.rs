use std::sync::Arc;

use crate::VerticalRegistry;

mod cn;
mod intl;
mod lab;

pub use cn::CnFactory;
pub use intl::IntlFactory;
pub use lab::LabFactory;

/// Built-in factories in priority order. Unknown verticals fall back to `intl`.
///
/// Adding a region means adding a factory module and one line in this vector.
pub fn builtin_registry() -> VerticalRegistry {
    VerticalRegistry::new(
        Arc::new(IntlFactory),
        vec![
            Arc::new(CnFactory),
            Arc::new(IntlFactory),
            Arc::new(LabFactory),
        ],
    )
}
