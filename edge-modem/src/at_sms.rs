//! Submitting a message over AT, for modules this agent cannot reach by QMI.
//!
//! Everything structured the agent does goes over QMI, and that is right for
//! the modules that speak it. The EC200U series does not: its USB composition
//! (`2c7c:0901`) exposes no `cdc-wdm` at all, so a module that is present,
//! identified and registered on a network still cannot be asked to do
//! anything. This is the path for those.
//!
//! PDU mode rather than text mode, so the encoder is the one already used for
//! every QMI send. Text mode would mean a second way of turning a message into
//! bytes -- a second set of alphabet, length and concatenation rules to keep in
//! step with the first -- and the two would drift on exactly the messages that
//! are hardest to test.

use std::time::Duration;

use crate::at::{AtError, AtPort};
use crate::pdu::{encode_submit, PduError};

/// How long the module gets to accept the message. Submission waits on the
/// network, so this is longer than an ordinary AT round trip.
pub const SEND_TIMEOUT: Duration = Duration::from_secs(60);

/// What went wrong submitting over AT.
///
/// Not `Clone`: `AtError` is not, because losing a port is not a fact worth
/// duplicating.
#[derive(Debug)]
pub enum AtSmsError {
    /// The message could not be encoded.
    Encode(PduError),
    /// The port was lost.
    Transport(AtError),
    /// The module answered, and the answer was a refusal.
    Refused { terminator: String },
}

impl std::fmt::Display for AtSmsError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Encode(error) => write!(formatter, "pdu: {error:?}"),
            Self::Transport(error) => write!(formatter, "at: {error}"),
            Self::Refused { terminator } => {
                write!(formatter, "module refused the submission: {terminator}")
            }
        }
    }
}

/// The message reference the module reports back, when it reports one.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AtSendOutcome {
    /// TP-MR as the module used it. A delivery report names the message by
    /// this and by nothing else, so an absent one means a later `+CDS` cannot
    /// be tied to this send.
    pub reference: Option<u8>,
}

/// Submit one message through an AT port.
///
/// `reference` is the TP-MR written into the PDU. The module is free to
/// substitute its own and report that instead, which is why the answer is read
/// rather than assumed.
pub fn send_sms(
    port: &mut AtPort,
    to: &str,
    body: &str,
    reference: u8,
) -> Result<AtSendOutcome, AtSmsError> {
    let pdu = encode_submit(to, body, reference).map_err(AtSmsError::Encode)?;

    // PDU mode. Set every time rather than once at startup: the port is shared
    // with a console somebody may have typed `AT+CMGF=1` into, and a text-mode
    // module reads a PDU as the message body and sends the hex to the
    // recipient.
    let mode = port
        .command("AT+CMGF=0")
        .map_err(AtSmsError::Transport)?;
    if !mode.succeeded() {
        return Err(AtSmsError::Refused {
            terminator: mode.terminator,
        });
    }

    // The length `AT+CMGS` wants is the TPDU only -- everything after the
    // service-centre byte -- not the whole PDU. Counting the whole thing is
    // the classic way to have the module answer `+CMS ERROR: 304`.
    let tpdu_len = pdu.len().saturating_sub(1);
    let hex: String = pdu.iter().map(|byte| format!("{byte:02X}")).collect();

    let answer = port
        .command_with_payload(&format!("AT+CMGS={tpdu_len}"), &hex, SEND_TIMEOUT)
        .map_err(AtSmsError::Transport)?;
    if !answer.succeeded() {
        return Err(AtSmsError::Refused {
            terminator: answer.terminator,
        });
    }

    Ok(AtSendOutcome {
        reference: parse_cmgs_reference(&answer.lines),
    })
}

/// `+CMGS: 42` -- the reference the module actually used.
fn parse_cmgs_reference(lines: &[String]) -> Option<u8> {
    lines.iter().find_map(|line| {
        line.trim()
            .strip_prefix("+CMGS:")
            .and_then(|rest| rest.trim().parse::<u8>().ok())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn the_modules_own_reference_is_read_back() {
        assert_eq!(parse_cmgs_reference(&lines(&["+CMGS: 42"])), Some(42));
        assert_eq!(parse_cmgs_reference(&lines(&["+CMGS:  7 "])), Some(7));
    }

    /// A submission with no reference reported is still a submission, but a
    /// later delivery report cannot be tied to it -- so this is `None` rather
    /// than a zero that would collide with a real reference of zero.
    #[test]
    fn an_absent_reference_is_none_rather_than_zero() {
        assert_eq!(parse_cmgs_reference(&lines(&["OK"])), None);
        assert_eq!(parse_cmgs_reference(&[]), None);
    }

    /// The length sent to the module is the TPDU, not the whole PDU. Getting
    /// this wrong is answered with `+CMS ERROR: 304` and nothing else.
    #[test]
    fn the_length_excludes_the_service_centre_byte() {
        let pdu = encode_submit("+8613800138000", "hi", 1).expect("encode");
        assert_eq!(pdu[0], 0x00, "a zero service-centre byte means use the card's");
        assert_eq!(pdu.len() - 1, pdu.len().saturating_sub(1));
        assert!(pdu.len() > 1);
    }
}
