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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::UsbIdentity;

    fn built() -> StrategyRegistry {
        registry(SupportLedger::default()).expect("the shipped registry must build")
    }

    /// 🔴 The device this gate exists for. Two Qualcomm MSM8916 sticks sat on
    /// the bench hub answering just enough to be enumerated and never enough
    /// to be identified: they re-enumerated every few minutes for hours,
    /// filled the candidate list with rows nobody could adopt, and were
    /// indistinguishable from a real fault in the logs.
    ///
    /// Nothing drives them, so nothing should open them.
    #[test]
    fn hardware_no_strategy_drives_is_not_touched() {
        let registry = built();
        assert!(
            !registry.drives(UsbIdentity::new(0x05c6, 0x90b4)),
            "a module with no strategy must not be probed"
        );
    }

    /// The three the bench actually runs. Named individually rather than
    /// counted, because the point is these exact pairs.
    #[test]
    fn the_bench_hardware_is_driven() {
        let registry = built();
        // EC20, EC25-CN and EG25-G all ship this one composition.
        assert!(registry.drives(UsbIdentity::new(0x2c7c, 0x0125)));
        // The EC200U-CN, which has no cdc-wdm at all.
        assert!(registry.drives(UsbIdentity::new(0x2c7c, 0x0901)));
    }

    /// Same vendor is not enough. A Quectel product nobody has written a
    /// strategy for is as undriveable as another vendor's.
    #[test]
    fn a_familiar_vendor_with_an_unknown_product_is_still_refused() {
        assert!(!built().drives(UsbIdentity::new(0x2c7c, 0x0296)));
    }

    /// What the enumerator will report it is willing to open.
    #[test]
    fn the_driven_set_is_sorted_and_deduplicated() {
        let driven = built().driven_usb_identities();
        assert_eq!(
            driven,
            vec![
                UsbIdentity::new(0x2c7c, 0x0125),
                UsbIdentity::new(0x2c7c, 0x0901),
            ]
        );
    }

    /// sysfs holds these as lowercase hex with no prefix. Parsing is where a
    /// silently wrong answer would turn the gate into a coin toss, so the
    /// failure cases are pinned too.
    #[test]
    fn sysfs_hex_parses_and_rubbish_does_not() {
        assert_eq!(
            UsbIdentity::parse("2c7c", "0125"),
            Some(UsbIdentity::new(0x2c7c, 0x0125))
        );
        // Trailing newline is what a bare `cat` of the sysfs file leaves.
        assert_eq!(
            UsbIdentity::parse("2c7c\n", "0125\n"),
            Some(UsbIdentity::new(0x2c7c, 0x0125))
        );
        assert_eq!(UsbIdentity::parse("", "0125"), None);
        assert_eq!(UsbIdentity::parse("0x2c7c", "0125"), None);
        assert_eq!(UsbIdentity::parse("zzzz", "0125"), None);
    }

    /// The form used in logs and in the ledger, so an operator can match it
    /// against `lsusb` without converting anything.
    #[test]
    fn an_identity_renders_the_way_lsusb_prints_it() {
        assert_eq!(UsbIdentity::new(0x2c7c, 0x0125).to_string(), "2c7c:0125");
        assert_eq!(UsbIdentity::new(0x05c6, 0x90b4).to_string(), "05c6:90b4");
    }
}
