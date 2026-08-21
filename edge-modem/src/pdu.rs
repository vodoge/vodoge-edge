//! SMS-SUBMIT TPDU encoding for QMI WMS RAW_SEND (format 0x06).
//!
//! Wire shape is `00` (use the network SMSC) plus a 3GPP 23.040 SUBMIT TPDU.
//! GSM-7 is used for a small ASCII subset; everything else is UCS2.

const GSM7_MAX_SEPTETS: usize = 160;
const UCS2_MAX_CHARS: usize = 70;

/// Encode one SMS-SUBMIT PDU including a zero-length SMSC prefix.
pub fn encode_submit(to: &str, body: &str) -> Result<Vec<u8>, PduError> {
    let tpdu = encode_tpdu(to, body)?;
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

fn encode_tpdu(to: &str, body: &str) -> Result<Vec<u8>, PduError> {
    if body.is_empty() {
        return Err(PduError::EmptyBody);
    }
    let (digit_count, toa, address) = encode_address(to)?;
    let gsm7 = pack_gsm7(body);
    let mut tpdu = Vec::new();
    tpdu.push(0x01);
    tpdu.push(0x00);
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

fn gsm7_value(ch: char) -> Option<u8> {
    match ch {
        'A'..='Z' | 'a'..='z' | '0'..='9' | ' ' | '.' | ',' | '!' | '?' | ':' | '+' | '-' => {
            Some(ch as u8)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_submit_uses_gsm7_and_default_smsc() {
        let pdu = encode_submit("12345", "Hi").expect("pdu");
        assert_eq!(
            pdu,
            [
                0x00, 0x01, 0x00, 0x05, 0x81, 0x21, 0x43, 0xf5, 0x00, 0x00, 0x02, 0xc8, 0x34
            ]
        );
    }

    #[test]
    fn plus_prefix_is_international() {
        let pdu = encode_submit("+8613800138000", "Hi").expect("pdu");
        assert_eq!(pdu[4], 0x91);
        assert_eq!(pdu[3], 13);
    }

    #[test]
    fn chinese_body_is_ucs2() {
        // 下标对照 ascii_submit_uses_gsm7_and_default_smsc 里的完整布局：
        // [0]SMSC [1]首字节 [2]MR [3]位数 [4]TOA [5..8]地址 [8]PID [9]DCS [10]UDL [11..]数据
        // PID 那一字节容易漏算——漏了会把 DCS 的断言错位到 PID 上。
        let pdu = encode_submit("10086", "你好").expect("pdu");
        assert_eq!(pdu[0], 0x00);
        assert_eq!(pdu[8], 0x00, "PID");
        assert_eq!(pdu[9], 0x08, "DCS 应为 UCS-2");
        assert_eq!(pdu[10], 4, "UDL 以字节计");
        assert_eq!(&pdu[11..], &[0x4f, 0x60, 0x59, 0x7d]);
    }

    #[test]
    fn empty_destination_is_rejected() {
        assert_eq!(encode_submit(" ", "Hi"), Err(PduError::EmptyDestination));
    }
}
