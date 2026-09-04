//! USSD sessions over the AT port.
//!
//! `AT+CUSD` is the only way to ask a carrier questions the module cannot
//! answer itself — balance, plan state, activation codes — so a debug terminal
//! without it cannot tell "the SIM has no credit" apart from "the SIM is
//! broken".
//!
//! The exchange is two-stage: the command returns `OK` as soon as the request
//! is accepted, and the network's answer arrives later as a `+CUSD:` report.
//! Reading only the command result returns an empty answer for a session that
//! worked.

/// What the network wants to happen next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UssdStage {
    /// Answer delivered, session closed.
    Complete,
    /// The network is waiting for a reply on the same session.
    NeedsReply,
    /// The network terminated the session.
    Terminated,
    /// Another local client answered first.
    OtherClient,
    /// The module does not support the operation.
    NotSupported,
    /// The network never answered. The module reports this after its own wait
    /// expires, which is why such a request takes tens of seconds to fail.
    NetworkTimeout,
    Other(u8),
}

impl UssdStage {
    pub fn from_code(code: u8) -> Self {
        match code {
            0 => Self::Complete,
            1 => Self::NeedsReply,
            2 => Self::Terminated,
            3 => Self::OtherClient,
            4 => Self::NotSupported,
            5 => Self::NetworkTimeout,
            other => Self::Other(other),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::NeedsReply => "needs_reply",
            Self::Terminated => "terminated",
            Self::OtherClient => "other_client",
            Self::NotSupported => "not_supported",
            Self::NetworkTimeout => "network_timeout",
            Self::Other(_) => "other",
        }
    }

    /// Whether the caller should keep the session open for a follow-up.
    pub fn expects_reply(self) -> bool {
        matches!(self, Self::NeedsReply)
    }

    /// Whether the text field carries the network's answer.
    ///
    /// A timed-out or unsupported session still carries a string, but it is the
    /// module echoing the request back rather than anything the network said.
    /// Showing it presents noise as a reply.
    pub fn carries_answer(self) -> bool {
        matches!(self, Self::Complete | Self::NeedsReply)
    }
}

/// One `+CUSD:` report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UssdReply {
    pub stage: UssdStage,
    pub text: String,
    pub dcs: Option<u8>,
}

/// Build `AT+CUSD=1,"<code>",15`.
///
/// Mode 1 asks the module to report the network's answer, which is what makes
/// the reply arrive at all; mode 0 suppresses it.
pub fn request(code: &str) -> String {
    format!("AT+CUSD=1,\"{}\",15", escape(code))
}

/// Cancel an open session.
pub fn cancel() -> &'static str {
    "AT+CUSD=2"
}

fn escape(code: &str) -> String {
    code.chars().filter(|c| *c != '"' && *c != '\r' && *c != '\n').collect()
}

/// Parse `+CUSD: 0,"Balance 12.30",15`.
pub fn parse_reply(line: &str) -> Option<UssdReply> {
    let rest = line.trim().strip_prefix("+CUSD:")?.trim();
    let mut fields = split_outside_quotes(rest);
    let stage = UssdStage::from_code(fields.first()?.trim().parse::<u8>().ok()?);
    let raw = fields
        .get_mut(1)
        .map(|value| value.trim().trim_matches('"').to_string())
        .unwrap_or_default();
    let dcs = fields.get(2).and_then(|value| value.trim().parse::<u8>().ok());
    Some(UssdReply {
        stage,
        text: if stage.carries_answer() {
            decode(&raw, dcs)
        } else {
            String::new()
        },
        dcs,
    })
}

/// Decode the answer according to its data coding scheme.
///
/// Modules hand this back in whatever encoding the carrier used, and a UCS2
/// answer arrives as hex. Printing it raw shows the operator a wall of digits
/// instead of the message.
pub fn decode(raw: &str, dcs: Option<u8>) -> String {
    if raw.is_empty() {
        return String::new();
    }
    let is_hex = raw.len() % 2 == 0 && raw.chars().all(|c| c.is_ascii_hexdigit());
    // 0x48 selects UCS2 in the CBS coding used by +CUSD.
    //
    // ⚠️ This used to read `Some(0x48) | Some(72)`. Those are the same number
    // written twice — 0x48 *is* 72 — so the second arm was unreachable and
    // rustc said so. Whoever wrote it likely meant "accept the decimal spelling
    // too", which is not a thing a `u8` can distinguish. Do not add it back;
    // if another DCS should be accepted, name it and say which module sends it.
    if is_hex && dcs == Some(0x48) {
        if let Some(text) = decode_ucs2(raw) {
            return text;
        }
    }
    if is_hex && raw.len() >= 4 {
        // Some modules hex-encode an ASCII answer under dcs 15. Accept that
        // only when every decoded character is printable ASCII: "is it
        // alphabetic" is not a guard, because CJK is alphabetic too, so a
        // genuine eight-digit balance decodes into plausible-looking Chinese
        // and the operator is shown an invented answer.
        if let Some(text) = decode_ucs2(raw) {
            if !text.is_empty() && text.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
                return text;
            }
        }
    }
    raw.to_string()
}

fn decode_ucs2(raw: &str) -> Option<String> {
    if raw.len() % 4 != 0 {
        return None;
    }
    let mut units = Vec::with_capacity(raw.len() / 4);
    for chunk in raw.as_bytes().chunks(4) {
        let text = std::str::from_utf8(chunk).ok()?;
        units.push(u16::from_str_radix(text, 16).ok()?);
    }
    String::from_utf16(&units).ok()
}

fn split_outside_quotes(value: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut buffer = String::new();
    let mut quoted = false;
    for character in value.chars() {
        match character {
            '"' => {
                quoted = !quoted;
                buffer.push(character);
            }
            ',' if !quoted => fields.push(std::mem::take(&mut buffer)),
            _ => buffer.push(character),
        }
    }
    fields.push(buffer);
    fields
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_uses_reporting_mode() {
        assert_eq!(request("*100#"), "AT+CUSD=1,\"*100#\",15");
    }

    /// A quote in the code would close the argument early and leave the rest to
    /// be read as further parameters.
    #[test]
    fn request_strips_quotes_from_the_code() {
        assert_eq!(request("*1\"00#"), "AT+CUSD=1,\"*100#\",15");
    }

    #[test]
    fn plain_reply_is_read_as_text() {
        let reply = parse_reply("+CUSD: 0,\"Balance 12.30 CNY\",15").expect("reply");
        assert_eq!(reply.stage, UssdStage::Complete);
        assert_eq!(reply.text, "Balance 12.30 CNY");
        assert!(!reply.stage.expects_reply());
    }

    #[test]
    fn a_menu_reply_expects_a_follow_up() {
        let reply = parse_reply("+CUSD: 1,\"1 Balance 2 Plan\",15").expect("reply");
        assert_eq!(reply.stage, UssdStage::NeedsReply);
        assert!(reply.stage.expects_reply());
    }

    /// A UCS2 answer arrives as hex; printing it raw shows digits, not text.
    #[test]
    fn ucs2_reply_is_decoded() {
        let reply = parse_reply("+CUSD: 0,\"4F59989D\",72").expect("reply");
        assert_eq!(reply.text, "余额");
    }

    /// A balance really is digits. Decoding it as UCS2 would turn a correct
    /// answer into nonsense.
    #[test]
    fn a_numeric_answer_is_left_alone() {
        let reply = parse_reply("+CUSD: 0,\"12345678\",15").expect("reply");
        assert_eq!(reply.text, "12345678");
    }

    #[test]
    fn a_comma_inside_the_answer_stays_together() {
        let reply = parse_reply("+CUSD: 0,\"Balance: 1,234\",15").expect("reply");
        assert_eq!(reply.text, "Balance: 1,234");
    }

    #[test]
    fn a_reply_without_text_still_parses() {
        let reply = parse_reply("+CUSD: 2").expect("reply");
        assert_eq!(reply.stage, UssdStage::Terminated);
        assert_eq!(reply.text, "");
    }

    /// Captured from a live module: the network never answered a code that is
    /// not valid for the roaming card, and after its own wait the module
    /// reported status 5 with the request echoed back. Naming that "other" and
    /// showing the echo presents a clear answer as garbage.
    #[test]
    fn a_network_timeout_is_named_and_carries_no_text() {
        let reply = parse_reply("+CUSD: 5,\"*b@\u{1}3\",15").expect("reply");
        assert_eq!(reply.stage, UssdStage::NetworkTimeout);
        assert_eq!(reply.stage.as_str(), "network_timeout");
        assert_eq!(reply.text, "");
        assert!(!reply.stage.carries_answer());
    }

    #[test]
    fn an_unsupported_operation_is_named() {
        let reply = parse_reply("+CUSD: 4").expect("reply");
        assert_eq!(reply.stage, UssdStage::NotSupported);
    }

    #[test]
    fn a_non_cusd_line_is_not_a_reply() {
        assert_eq!(parse_reply("+CSQ: 24,99"), None);
    }
}
