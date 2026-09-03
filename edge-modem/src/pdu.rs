//! SMS-SUBMIT TPDU encoding for QMI WMS RAW_SEND (format 0x06).
//!
//! Wire shape is `00` (use the network SMSC) plus a 3GPP 23.040 SUBMIT TPDU.
//! GSM-7 is used for a small ASCII subset; everything else is UCS2.

/// 🔴 编码规则住在 `edge-core`，不在这里。
///
/// 面板要在按下发送**之前**告诉操作员这条会走哪种编码、会不会被拒，而这个
/// 编码器不分片 —— 超了就是发不出去。规则有两份的时候，屏幕上说 70 而 daemon
/// 接受 160 是随时会发生的事（面板那份自己留了一句话承认这一点）。现在两边
/// 取的是同一个函数：给 `gsm7_value` 加一个字符，两边同时改变。
use edge_core::{gsm7_value, GSM7_MAX_SEPTETS, UCS2_MAX_CHARS};

/// Encode one SMS-SUBMIT PDU including a zero-length SMSC prefix.
///
/// `reference` becomes TP-MR. It is the caller's because it is the only thing
/// that ties a later SMS-STATUS-REPORT back to this send: the report quotes
/// the reference and nothing else about the original. It used to be a
/// hardcoded zero, which was harmless while nothing read the reports back and
/// would have made every one of them ambiguous the moment something did.
pub fn encode_submit(to: &str, body: &str, reference: u8) -> Result<Vec<u8>, PduError> {
    let tpdu = encode_tpdu(to, body, reference)?;
    let mut pdu = Vec::with_capacity(1 + tpdu.len());
    pdu.push(0x00);
    pdu.extend_from_slice(&tpdu);
    Ok(pdu)
}

/// Errors while building a SUBMIT TPDU.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PduError {
    EmptyDestination,
    InvalidDestination,
    EmptyBody,
    TooLong { encoding: &'static str, limit: usize },
}

impl std::fmt::Display for PduError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyDestination => formatter.write_str("SMS destination is empty"),
            Self::InvalidDestination => formatter.write_str("SMS destination is not a phone number"),
            Self::EmptyBody => formatter.write_str("SMS body is empty"),
            Self::TooLong { encoding, limit } => {
                write!(formatter, "SMS body exceeds {limit} {encoding} units")
            }
        }
    }
}

impl std::error::Error for PduError {}

fn encode_tpdu(to: &str, body: &str, reference: u8) -> Result<Vec<u8>, PduError> {
    if body.is_empty() {
        return Err(PduError::EmptyBody);
    }
    let (digit_count, toa, address) = encode_address(to)?;
    let gsm7 = pack_gsm7(body);
    let mut tpdu = Vec::new();
    // TP-MTI 0b01 (SUBMIT) with TP-SRR set.
    //
    // The status-report-request bit is the whole reason a `+CDS` ever arrives.
    // Nothing in the modem, the SMSC, or any AT setting can conjure a delivery
    // receipt for a message that did not ask for one -- `AT+CSMS=1` and
    // `AT+CNMI` only decide what happens to a report that exists. This octet
    // is where it is decided that one should.
    //
    // Always on rather than per-message: every send goes through one console
    // form with no "confirm delivery" checkbox, and a receipt the operator did
    // not ask for costs nothing while a missing one cannot be recovered after
    // the fact.
    tpdu.push(0x21);
    tpdu.push(reference);
    tpdu.push(digit_count);
    tpdu.push(toa);
    tpdu.extend_from_slice(&address);
    tpdu.push(0x00);
    if let Some(packed) = gsm7 {
        if body.chars().count() > GSM7_MAX_SEPTETS {
            return Err(PduError::TooLong {
                encoding: "gsm7",
                limit: GSM7_MAX_SEPTETS,
            });
        }
        tpdu.push(0x00);
        tpdu.push(body.chars().count() as u8);
        tpdu.extend_from_slice(&packed);
    } else {
        let units: Vec<u16> = body.encode_utf16().collect();
        if units.len() > UCS2_MAX_CHARS {
            return Err(PduError::TooLong {
                encoding: "ucs2",
                limit: UCS2_MAX_CHARS,
            });
        }
        tpdu.push(0x08);
        tpdu.push((units.len() * 2) as u8);
        for unit in units {
            tpdu.extend_from_slice(&unit.to_be_bytes());
        }
    }
    Ok(tpdu)
}

fn encode_address(to: &str) -> Result<(u8, u8, Vec<u8>), PduError> {
    let trimmed = to.trim();
    if trimmed.is_empty() {
        return Err(PduError::EmptyDestination);
    }
    let international = trimmed.starts_with('+');
    let digits: String = trimmed
        .chars()
        .filter(|ch| ch.is_ascii_digit())
        .collect();
    if digits.is_empty() || digits.len() > 20 {
        return Err(PduError::InvalidDestination);
    }
    let toa = if international { 0x91 } else { 0x81 };
    Ok((digits.len() as u8, toa, bcd_digits(&digits)))
}

fn bcd_digits(digits: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut chars = digits.chars();
    while let Some(lo) = chars.next() {
        let hi = chars.next().unwrap_or('F');
        let lo_nibble = nibble(lo);
        let hi_nibble = nibble(hi);
        bytes.push(lo_nibble | (hi_nibble << 4));
    }
    bytes
}

fn nibble(ch: char) -> u8 {
    match ch {
        '0'..='9' => ch as u8 - b'0',
        _ => 0x0f,
    }
}

fn pack_gsm7(body: &str) -> Option<Vec<u8>> {
    let mut septets = Vec::new();
    for ch in body.chars() {
        septets.push(gsm7_value(ch)?);
    }
    let mut packed = Vec::new();
    let mut acc = 0u16;
    let mut bits = 0u32;
    for septet in septets {
        acc |= u16::from(septet) << bits;
        bits += 7;
        if bits >= 8 {
            packed.push(acc as u8);
            acc >>= 8;
            bits -= 8;
        }
    }
    if bits > 0 {
        packed.push(acc as u8);
    }
    Some(packed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_submit_uses_gsm7_and_default_smsc() {
        let pdu = encode_submit("12345", "Hi", 0x00).expect("pdu");
        assert_eq!(
            pdu,
            [
                0x00, 0x21, 0x00, 0x05, 0x81, 0x21, 0x43, 0xf5, 0x00, 0x00, 0x02, 0xc8, 0x34
            ]
        );
    }

    // The bit that asks the network for a delivery receipt. Named in its own
    // test because the byte-exact case above would still pass with it cleared
    // if someone updated the expected array to match the code.
    #[test]
    fn submit_requests_a_status_report() {
        let pdu = encode_submit("12345", "Hi", 0x00).expect("pdu");
        assert_eq!(pdu[1] & 0x20, 0x20, "TP-SRR must be set");
        assert_eq!(pdu[1] & 0x03, 0x01, "TP-MTI must still say SUBMIT");
    }

    // TP-MR is what a status report quotes back. A send that ignored the
    // caller's reference would make every report point at the same message.
    #[test]
    fn the_caller_chooses_the_message_reference() {
        let pdu = encode_submit("12345", "Hi", 0x9c).expect("pdu");
        assert_eq!(pdu[2], 0x9c);
    }

    #[test]
    fn plus_prefix_is_international() {
        let pdu = encode_submit("+8613800138000", "Hi", 0x00).expect("pdu");
        assert_eq!(pdu[4], 0x91);
        assert_eq!(pdu[3], 13);
    }

    #[test]
    fn chinese_body_is_ucs2() {
        // 下标对照 ascii_submit_uses_gsm7_and_default_smsc 里的完整布局：
        // [0]SMSC [1]首字节 [2]MR [3]位数 [4]TOA [5..8]地址 [8]PID [9]DCS [10]UDL [11..]数据
        // PID 那一字节容易漏算——漏了会把 DCS 的断言错位到 PID 上。
        let pdu = encode_submit("10086", "你好", 0x00).expect("pdu");
        assert_eq!(pdu[0], 0x00);
        assert_eq!(pdu[8], 0x00, "PID");
        assert_eq!(pdu[9], 0x08, "DCS 应为 UCS-2");
        assert_eq!(pdu[10], 4, "UDL 以字节计");
        assert_eq!(&pdu[11..], &[0x4f, 0x60, 0x59, 0x7d]);
    }

    #[test]
    fn empty_destination_is_rejected() {
        assert_eq!(
            encode_submit(" ", "Hi", 0x00),
            Err(PduError::EmptyDestination)
        );
    }
}
