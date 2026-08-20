use edge_core::{Bearer, SendPlan};

use crate::{ModemPort, PortError};

/// Outcome of executing a `SendPlan` against a modem.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendOutcome {
    pub used: Bearer,
    pub fallback_used: bool,
}

/// Send on the planned primary bearer, then the fallback if the primary fails.
pub fn send_with_plan<P: ModemPort>(
    port: &mut P,
    plan: &SendPlan,
    pdu: &[u8],
) -> Result<SendOutcome, PortError> {
    let Some(primary) = plan.primary else {
        return Err(PortError::PlanUnavailable(plan.reason.to_string()));
    };

    match port.send_on(primary, pdu) {
        Ok(()) => Ok(SendOutcome {
            used: primary,
            fallback_used: false,
        }),
        Err(primary_error) => {
            let Some(fallback) = plan.fallback else {
                return Err(primary_error);
            };
            port.send_on(fallback, pdu)?;
            Ok(SendOutcome {
                used: fallback,
                fallback_used: true,
            })
        }
    }
}
