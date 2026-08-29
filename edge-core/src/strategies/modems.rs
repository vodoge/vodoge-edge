//! Module strategies.
//!
//! Sharing one strategy across families is allowed and is the point of the
//! trait — but only where the driving really is the same, and the families
//! stay separate identities in the ledger regardless, so a pair tested on one
//! is never claimed for the other.

use crate::{Bearer, ModemFamily, ModemStrategy, Operation};

/// Quectel's EC-series LTE Cat-4 modules: EC20, EC25-CN, EG25-G.
///
/// One strategy for three families because they are driven identically — the
/// same QMI services, the same AT surface, the same `AT+QCFG="usbnet"` for the
/// USB function. The families stay distinct in the ledger because their radios
/// are not identical: an EC25-CN and an EC25-E differ by band set, which is why
/// only the CN variant is a family at all.
pub struct QuectelEcStrategy;

impl ModemStrategy for QuectelEcStrategy {
    fn id(&self) -> &'static str {
        "quectel-ec"
    }

    fn families(&self) -> Vec<ModemFamily> {
        vec![
            ModemFamily::EC20,
            ModemFamily::EC25_CN,
            ModemFamily::EG25_G,
        ]
    }

    fn preferred_bearer(&self, operation: Operation) -> Option<Bearer> {
        match operation {
            // These are data-first modules; a message goes out over the packet
            // domain unless the carrier layer moves it.
            Operation::SmsSend | Operation::SmsReceive => Some(Bearer::Cellular),
            _ => None,
        }
    }
}

/// Quectel's EC200 series, China variant.
///
/// A different line from the EC20 despite the name, and deliberately its own
/// strategy: on this bench it is reachable over its AT port only — the agent's
/// QMI probe does not find a `cdc-wdm` for it — so everything structured the
/// agent does over QMI is unavailable, and claiming otherwise by folding it in
/// with the EC-series would produce exactly the silent half-working stick this
/// design exists to prevent.
pub struct Ec200uStrategy;

impl ModemStrategy for Ec200uStrategy {
    fn id(&self) -> &'static str {
        "quectel-ec200u"
    }

    fn families(&self) -> Vec<ModemFamily> {
        vec![ModemFamily::EC200U_CN]
    }

    /// What this agent can and cannot ask of an EC200U.
    ///
    /// The module exposes no QMI interface -- its USB composition
    /// (`2c7c:0901`) has no `cdc-wdm` at all, which is a property of the
    /// series rather than of this bench -- so everything the agent drives over
    /// QMI is unavailable on it.
    ///
    /// Submitting a message is no longer among those things: there is now an
    /// AT path for it, and the ceiling narrowed to match rather than being
    /// left as a blanket refusal that would have kept a working capability
    /// switched off. Receiving still has none -- the inbox sweep is a QMI
    /// operation -- and neither has data or voice, so those still say so.
    fn ceiling(&self, operation: Operation) -> Option<String> {
        match operation {
            // Sends go over AT for this family; see `edge_modem::at_sms`.
            Operation::SmsSend => None,
            // The AT sweep exists now, so this ceiling came off with it --
            // narrowed as the capability arrived rather than left standing
            // with a reason that had stopped being true.
            Operation::SmsReceive => None,
            Operation::Data => Some(
                "this agent brings the bearer up over QMI and the EC200U series exposes none"
                    .to_owned(),
            ),
            Operation::Voice => Some("this agent has no voice path at all".to_owned()),
        }
    }

    fn preferred_bearer(&self, operation: Operation) -> Option<Bearer> {
        match operation {
            Operation::SmsSend | Operation::SmsReceive => Some(Bearer::Cellular),
            _ => None,
        }
    }
}
