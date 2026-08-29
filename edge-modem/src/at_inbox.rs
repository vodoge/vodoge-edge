//! Reading and clearing a module's message store over AT.
//!
//! The counterpart to `at_sms`, and for the same modules: the QMI sweep cannot
//! touch an EC200U because the series exposes no `cdc-wdm`, so a message that
//! arrives on one sits in module storage where nothing can see it. That is not
//! a network failure and it is not a card failure -- on this bench the reply
//! from 10001 was delivered, stored, and unreadable.
//!
//! PDU mode throughout, so the decoder is the one every QMI-collected message
//! already goes through. Text mode would hand back a string the module had
//! already decoded with its own idea of the alphabet, and the concatenation
//! header -- which is how a long message is reassembled -- would be gone.

use std::time::Duration;

use crate::at::{AtError, AtPort};

/// How long a listing may take. A full store is a few dozen PDUs on one port.
pub const LIST_TIMEOUT: Duration = Duration::from_secs(30);

/// One stored message as the module reports it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredMessage {
    /// Storage index. What `AT+CMGD` addresses, so it is how the message is
    /// deleted after it has been carried away.
    pub index: u32,
    /// The status word the module used, verbatim: `REC UNREAD`, `REC READ`,
    /// `STO SENT` and so on.
    pub status: String,
    /// The PDU, decoded no further here.
    pub pdu: Vec<u8>,
}

impl StoredMessage {
    /// Whether this is a message that arrived, rather than one this module
    /// sent or holds as a draft.
    ///
    /// Taken from the status the module reported rather than from what the
    /// listing asked for: `AT+CMGL=4` asks for everything, and a store holding
    /// sent messages would otherwise have them read, decoded as deliveries and
    /// carried upstream as if they had arrived.
    ///
    /// 🔴 **Both spellings, because the mode decides which one arrives.** In
    /// text mode the status is a quoted word -- `"REC UNREAD"` -- and in PDU
    /// mode it is the bare number that word stands for. This sweep runs in PDU
    /// mode, so the number is the form it actually meets; the words are kept
    /// because a console leaves the port in text mode and the same parser is
    /// the obvious thing to point at a listing taken by hand.
    ///
    /// Getting this wrong is silent: every row is read, decoded, and then
    /// discarded as "not a delivery", and the sweep reports nothing found on a
    /// module holding unread messages.
    pub fn is_received(&self) -> bool {
        // 0 REC UNREAD, 1 REC READ, 2 STO UNSENT, 3 STO SENT.
        matches!(self.status.as_str(), "0" | "1") || self.status.starts_with("REC")
    }
}

/// List every message the module is holding.
///
/// `AT+CMGL=4` in PDU mode is "all", including read ones. Read state is the
/// module's own bookkeeping and says nothing about whether this agent has
/// carried a message away -- one `AT+CMGR` from a console flips it -- so
/// filtering on it here would lose exactly the messages somebody had already
/// looked at.
pub fn list(port: &mut AtPort) -> Result<Vec<StoredMessage>, AtError> {
    // Set every time. The port is shared with a console, and a module left in
    // text mode answers with strings it has already decoded, which the PDU
    // parser then reads as garbage.
    let mode = port.command("AT+CMGF=0")?;
    if !mode.succeeded() {
        return Ok(Vec::new());
    }
    let listing = port.command_with_timeout("AT+CMGL=4", LIST_TIMEOUT)?;
    if !listing.succeeded() {
        return Ok(Vec::new());
    }
    Ok(parse_listing(&listing.lines))
}

/// Delete one message by index.
///
/// Called only after the message is durably stored elsewhere. The module's
/// store is small and a full one silently stops accepting new messages, so
/// this is not optional housekeeping -- but it is destructive, and a delete
/// that ran before the message was safe would lose it with no trace.
pub fn delete(port: &mut AtPort, index: u32) -> Result<bool, AtError> {
    let answer = port.command(&format!("AT+CMGD={index}"))?;
    Ok(answer.succeeded())
}

/// Parse the `+CMGL:` header/PDU pairs of a PDU-mode listing.
///
/// Each message is two lines: a header naming the index and status, and the
/// PDU on the line after it. A header whose PDU line is missing or unreadable
/// is dropped rather than guessed at -- the index would be right and the
/// content wrong, which is the one combination that could delete a message
/// nobody ever read.
pub fn parse_listing(lines: &[String]) -> Vec<StoredMessage> {
    let mut out = Vec::new();
    let mut pending: Option<(u32, String)> = None;
    for line in lines {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("+CMGL:") {
            pending = parse_header(rest);
            continue;
        }
        let Some((index, status)) = pending.take() else {
            continue;
        };
        let Some(pdu) = decode_hex(trimmed) else {
            continue;
        };
        out.push(StoredMessage { index, status, pdu });
    }
    out
}

/// `0,"REC UNREAD","10001",,"26/08/29,17:35:23+32"` -- index and status.
fn parse_header(rest: &str) -> Option<(u32, String)> {
    let mut fields = rest.split(',');
    let index = fields.next()?.trim().parse::<u32>().ok()?;
    let status = fields.next()?.trim().trim_matches('"').to_owned();
    if status.is_empty() {
        return None;
    }
    Some((index, status))
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    let value = value.trim();
    if value.is_empty() || value.len() % 2 != 0 {
        return None;
    }
    (0..value.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&value[at..at + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    /// The shape the bench's EC200U actually answered with in PDU mode,
    /// holding China Telecom's balance reply: a numeric status, no alpha
    /// field, and the length.
    ///
    /// Written from the real listing after the first version of this parser
    /// was tested against the text-mode spelling instead and silently found
    /// nothing on a module that was holding a message.
    #[test]
    fn the_pdu_mode_listing_this_bench_produces_is_read() {
        let parsed = parse_listing(&lines(&[
            "+CMGL: 0,1,,98",
            "09A164000339341002F00405A10100F1000862809271533223525C0A656C",
        ]));
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].index, 0);
        assert_eq!(parsed[0].status, "1");
        assert!(parsed[0].is_received(), "1 is REC READ, which arrived");
        assert_eq!(parsed[0].pdu[0], 0x09);
    }

    /// Numeric statuses 2 and 3 are this module's own outgoing messages.
    #[test]
    fn a_numeric_stored_status_is_not_a_delivery() {
        let parsed = parse_listing(&lines(&["+CMGL: 4,3,,20", "0001000B915121551532F4"]));
        assert_eq!(parsed.len(), 1);
        assert!(!parsed[0].is_received(), "3 is STO SENT");
        assert!(parse_listing(&lines(&["+CMGL: 5,0,,20", "0001000B915121551532F4"]))[0]
            .is_received(), "0 is REC UNREAD");
    }

    /// The text-mode spelling still reads, for a listing taken by hand.
    #[test]
    fn a_header_and_its_pdu_are_read_as_one_message() {
        let parsed = parse_listing(&lines(&[
            "+CMGL: 0,\"REC UNREAD\",\"10001\",,\"26/08/29,17:35:23+32\"",
            "0891683108200105F0240D91683108200105F000082608921553238004F60D",
        ]));
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].index, 0);
        assert_eq!(parsed[0].status, "REC UNREAD");
        assert!(parsed[0].is_received());
        assert_eq!(parsed[0].pdu[0], 0x08);
    }

    /// A store holding messages this module sent must not have them decoded as
    /// arrivals and carried upstream.
    #[test]
    fn a_sent_message_is_not_a_received_one() {
        let parsed = parse_listing(&lines(&[
            "+CMGL: 3,\"STO SENT\",\"10001\",,",
            "0001000B915121551532F400000431D98C56",
        ]));
        assert_eq!(parsed.len(), 1);
        assert!(!parsed[0].is_received(), "a sent message did not arrive");
    }

    /// A header with no PDU after it is dropped. Keeping it would pair a real
    /// index with no content, and the index is what a delete addresses.
    #[test]
    fn a_header_without_a_pdu_is_dropped() {
        assert!(parse_listing(&lines(&["+CMGL: 1,\"REC READ\",,,"])).is_empty());
        assert!(parse_listing(&lines(&[
            "+CMGL: 1,\"REC READ\",,,",
            "not hex",
        ]))
        .is_empty());
    }

    #[test]
    fn several_messages_are_read_in_order() {
        let parsed = parse_listing(&lines(&[
            "+CMGL: 0,\"REC UNREAD\",,,",
            "07911234",
            "+CMGL: 1,\"REC READ\",,,",
            "07915678",
        ]));
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].index, 0);
        assert_eq!(parsed[1].index, 1);
        assert_eq!(parsed[1].status, "REC READ");
    }

    /// An odd-length hex string is a truncated read, not a message.
    #[test]
    fn a_truncated_pdu_is_not_half_a_message() {
        assert!(parse_listing(&lines(&["+CMGL: 0,\"REC UNREAD\",,,", "0791123"])).is_empty());
    }
}
