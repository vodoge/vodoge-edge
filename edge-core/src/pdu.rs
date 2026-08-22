//! SMS-DELIVER decoding, per 3GPP 23.040.
//!
//! This lived in edge-bin behind `#[cfg(target_os = "linux")]`, which meant it
//! could not be compiled — let alone tested — on any machine anyone develops
//! on. Three decoding faults survived in it for that reason alone, and each was
//! found by reading mangled messages out of the production database rather than
//! by a test. It is here so it can be exercised anywhere.

use crate::gsm7;

/// One decoded SMS-DELIVER: who sent it, what it says, and which part of a
/// longer message it is.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Deliver {
    pub peer: String,
    pub body: String,
    /// `(reference, total, sequence)` when this is one fragment of a longer
    /// message.
    pub concat: Option<(u16, u8, u8)>,
    /// The alphabet the data coding scheme named: `gsm7`, `ucs2`, `8bit`, or
    /// `unknown` for a PDU that could not be walked.
    pub encoding: &'static str,
}

impl Deliver {
    fn undecodable(pdu: &[u8]) -> Self {
        Deliver {
            peer: String::new(),
            body: hex(pdu),
            concat: None,
            encoding: "unknown",
        }
    }
}

/// Decodes one SMS-DELIVER PDU.
///
/// A PDU that cannot be walked is returned as hex rather than as an error. It
/// is a real message that really arrived, and the bytes are the only evidence
/// of what it was; discarding them to signal a parse failure loses the one
/// thing that would explain the failure.
pub fn decode_deliver(pdu: &[u8]) -> Deliver {
    if pdu.is_empty() {
        return Deliver {
            peer: String::new(),
            body: String::new(),
            concat: None,
            encoding: "unknown",
        };
    }

    let mut i = 0usize;
    let smsc_len = pdu[0] as usize;
    if 1 + smsc_len < pdu.len() {
        i = 1 + smsc_len;
    }
    if i + 2 >= pdu.len() {
        return Deliver::undecodable(pdu);
    }

    // The first octet carries TP-UDHI in bit 6. It was skipped unread, which is
    // why every concatenated message arrived with its header decoded as text --
    // the string that started them all, `Ԁϒȁ`, is a six-byte UDH read as UCS-2.
    let has_udh = pdu[i] & 0x40 != 0;
    i += 1;

    let oa_digits = pdu[i] as usize;
    i += 1;
    if i >= pdu.len() {
        return Deliver::undecodable(pdu);
    }
    // The type-of-address octet, which used to be stepped over. Bits 6-4 are
    // the numbering-plan type.
    let toa = pdu[i];
    i += 1;

    let oa_bytes = oa_digits.div_ceil(2);
    // The address, then TP-PID, TP-DCS, the seven-octet timestamp, and TP-UDL:
    // ten octets past the address, and TP-UDL is the last of them, so the
    // whole run must be present before any of it is read. The bound used to
    // stop at nine and then index TP-UDL anyway, so a PDU truncated in the
    // timestamp panicked the agent instead of being reported as undecodable.
    // Nothing on this path validates what the network sends.
    if i + oa_bytes + 10 > pdu.len() {
        return Deliver::undecodable(pdu);
    }
    let peer = decode_address(&pdu[i..i + oa_bytes], oa_digits, toa);
    i += oa_bytes;

    i += 1; // TP-PID
    let dcs = pdu[i];
    i += 1;
    i += 7; // TP-SCTS
    let udl = pdu[i] as usize;
    i += 1;
    let ud = if i <= pdu.len() { &pdu[i..] } else { &[] };

    let (concat, header_octets, payload) = split_user_data_header(has_udh, ud);

    // DCS bits 3 and 2 name the alphabet: 00 seven-bit, 01 eight-bit data, 10
    // UCS-2.
    let (body, encoding) = match dcs & 0x0c {
        0x08 => (decode_ucs2(payload), "ucs2"),
        // Eight-bit data is not text. It carries SIM toolkit and OTA traffic,
        // and rendering it as characters produces line noise that reads like a
        // decoder fault -- which is how it was read for a while. Hex keeps it
        // legible and honest, and `encoding` says why it looks like that.
        0x04 => (hex(payload), "8bit"),
        // Seven-bit packed septets, the default and by far the most common.
        // These were handed to a UTF-8 reader, which is not a lenient reading
        // of GSM-7 but a reading of an unrelated encoding: septets cross octet
        // boundaries, so the bytes never lined up with characters at all.
        //
        // Decoding takes the whole user data rather than the split payload:
        // in this alphabet the header is measured in octets but the text
        // resumes on a septet boundary, so it is skipped in septets.
        _ => (gsm7::decode(ud, header_octets, udl), "gsm7"),
    };

    Deliver {
        peer,
        body,
        concat,
        encoding,
    }
}

/// Decodes a TP-OA into something dialable, or into the sender's name.
///
/// The type-of-address octet is what says which. It was previously skipped, and
/// the leading `+` guessed from whether the digits began with an 8 — which is
/// true of Chinese numbers and of nothing else, so every international number
/// from anywhere but China lost its prefix. US numbers, the ones this product
/// is being pointed at, never got one.
fn decode_address(bytes: &[u8], digits: usize, toa: u8) -> String {
    const TYPE_INTERNATIONAL: u8 = 0b001;
    const TYPE_ALPHANUMERIC: u8 = 0b101;
    let kind = (toa >> 4) & 0b111;

    if kind == TYPE_ALPHANUMERIC {
        // A shortcode sending under a name rather than a number: "VERIZON",
        // "Saily". The address field is packed GSM-7, and the length is in
        // semi-octets, so it is 4 bits per unit rather than 7.
        let septets = (digits * 4) / 7;
        return gsm7::decode_septets(&gsm7::unpack_septets(bytes, 0, septets));
    }

    let mut out = String::new();
    for byte in bytes {
        let lo = byte & 0x0f;
        let hi = byte >> 4;
        if lo <= 9 && out.len() < digits {
            out.push(char::from(b'0' + lo));
        }
        if hi <= 9 && out.len() < digits {
            out.push(char::from(b'0' + hi));
        }
    }
    if kind == TYPE_INTERNATIONAL && !out.is_empty() {
        return format!("+{out}");
    }
    out
}

fn decode_ucs2(payload: &[u8]) -> String {
    String::from_utf16_lossy(
        &payload
            .chunks(2)
            .filter_map(|pair| {
                if pair.len() == 2 {
                    Some(u16::from_be_bytes([pair[0], pair[1]]))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>(),
    )
}

/// Splits the user data header off the payload.
///
/// Returns the concatenation parameters when the header carries them --
/// information element 0x00 is an 8-bit reference, 0x08 a 16-bit one -- the
/// number of octets the header occupies, and the remaining bytes. A header this
/// does not understand is still removed: leaving it in puts binary in the
/// message body, which is the one outcome nobody wants to read.
///
/// The octet count is returned because seven-bit messages cannot use the split
/// payload: there the header is skipped in septets, from the start of the whole
/// user data field.
fn split_user_data_header(has_udh: bool, ud: &[u8]) -> (Option<(u16, u8, u8)>, usize, &[u8]) {
    if !has_udh || ud.is_empty() {
        return (None, 0, ud);
    }
    let header_len = ud[0] as usize;
    let end = 1 + header_len;
    if end > ud.len() {
        return (None, 0, &[]);
    }
    let header = &ud[1..end];
    let payload = &ud[end..];

    let mut concat = None;
    let mut offset = 0usize;
    while offset + 2 <= header.len() {
        let iei = header[offset];
        let length = header[offset + 1] as usize;
        let value_start = offset + 2;
        let value_end = value_start + length;
        if value_end > header.len() {
            break;
        }
        let value = &header[value_start..value_end];
        match (iei, value.len()) {
            (0x00, 3) => concat = Some((u16::from(value[0]), value[1], value[2])),
            (0x08, 4) => {
                concat = Some((
                    u16::from_be_bytes([value[0], value[1]]),
                    value[2],
                    value[3],
                ))
            }
            _ => {}
        }
        offset = value_end;
    }
    (concat, end, payload)
}

pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02X}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
            .collect()
    }

    // A textbook DELIVER: SMSC +447785016005, sender +447785016005, GSM-7,
    // "hellohello". This is the case that used to come back as mojibake.
    #[test]
    fn decodes_a_seven_bit_message() {
        let pdu = from_hex(
            "0791448720003023240C914477581006500000916042113312800AE8329BFD4697D9EC37",
        );
        let decoded = decode_deliver(&pdu);
        assert_eq!(decoded.encoding, "gsm7");
        assert_eq!(decoded.body, "hellohello");
        assert_eq!(decoded.peer, "+447785016005");
        assert_eq!(decoded.concat, None);
    }

    // The old code guessed the '+' from a leading 8, so a US number never got
    // one even though its type-of-address says international.
    #[test]
    fn a_us_number_keeps_its_international_prefix() {
        // TOA 0x91 is international ISDN; 12025550143 as semi-octets.
        let address = from_hex("2120550541F3");
        assert_eq!(decode_address(&address, 11, 0x91), "+12025550143");
    }

    #[test]
    fn a_national_number_gets_no_prefix() {
        // TOA 0x81 is unknown/national -- no '+' belongs on it.
        let address = from_hex("0198765432");
        assert_eq!(decode_address(&address, 10, 0x81), "1089674523");
    }

    // Alphanumeric senders are how most US shortcodes identify themselves. The
    // digit reader turned them into nonsense.
    #[test]
    fn an_alphanumeric_sender_is_read_as_text() {
        // "Saily" packed as GSM-7, address length in semi-octets.
        let packed = gsm7_pack("Saily");
        let digits = packed.len() * 2;
        assert_eq!(decode_address(&packed, digits, 0xd0), "Saily");
    }

    #[test]
    fn decodes_a_ucs2_message() {
        // DCS 0x08. Chinese needs UCS-2, which is why these were the only
        // messages that ever decoded correctly.
        let body: Vec<u8> = "余额"
            .encode_utf16()
            .flat_map(|unit| unit.to_be_bytes())
            .collect();
        let pdu = deliver(0x04, 0x08, &body, body.len());
        let decoded = decode_deliver(&pdu);
        assert_eq!(decoded.encoding, "ucs2");
        assert_eq!(decoded.body, "余额");
    }

    // Eight-bit data is binary. Reading it as text is what produced the line
    // noise -- and the NUL bytes that PostgreSQL then refused.
    #[test]
    fn eight_bit_data_is_reported_as_hex() {
        let pdu = from_hex(
            "0791448720003023240D91447785016005F600049160421133128004DEADBEEF",
        );
        let decoded = decode_deliver(&pdu);
        assert_eq!(decoded.encoding, "8bit");
        assert_eq!(decoded.body, "DEADBEEF");
        assert!(!decoded.body.contains('\u{0}'));
    }

    #[test]
    fn a_concatenated_message_reports_its_fragment_and_drops_the_header() {
        // A six-octet concatenation header for reference 0xD2, fragment 1 of
        // 2, then "Hi" starting on the next septet boundary.
        let header = [0x05u8, 0x00, 0x03, 0xd2, 0x02, 0x01];
        let skip = gsm7::header_septets(header.len());
        let mut septets = vec![0u8; skip];
        septets.extend("Hi".chars().map(|c| c as u8));

        // The header occupies whole octets at the front; the text is packed
        // from the septet boundary after it.
        let mut ud = header.to_vec();
        ud.extend_from_slice(&gsm7_pack_septets(&septets)[header.len()..]);

        let pdu = deliver(0x44, 0x00, &ud, septets.len());
        let decoded = decode_deliver(&pdu);
        assert_eq!(decoded.concat, Some((0xd2, 2, 1)));
        assert_eq!(decoded.encoding, "gsm7");
        assert_eq!(
            decoded.body, "Hi",
            "the header leaked into the body: {:?}",
            decoded.body
        );
    }

    #[test]
    fn an_empty_pdu_is_empty_not_a_panic() {
        let decoded = decode_deliver(&[]);
        assert_eq!(decoded.body, "");
        assert_eq!(decoded.encoding, "unknown");
    }

    // Every truncation must return, not index past the end.
    #[test]
    fn a_truncated_pdu_comes_back_as_hex() {
        let full = from_hex(
            "0791448720003023240C914477581006500000916042113312800AE8329BFD4697D9EC37",
        );
        for cut in 1..full.len() {
            let decoded = decode_deliver(&full[..cut]);
            let _ = decoded.body;
        }
    }

    /// Builds a DELIVER around a user data field: SMSC and sender fixed,
    /// `first` is the TP-MTI octet (0x44 sets UDHI), `dcs` the coding scheme.
    fn deliver(first: u8, dcs: u8, ud: &[u8], udl: usize) -> Vec<u8> {
        // 07 declares seven SMSC octets, so the field ends at index 7 and the
        // TP-MTI octet is index 8.
        let mut pdu = from_hex("0791448720003023");
        pdu.push(first);
        pdu.extend_from_slice(&from_hex("0D91447785016005F6"));
        pdu.push(0x00); // TP-PID
        pdu.push(dcs);
        pdu.extend_from_slice(&from_hex("91604211331280")); // TP-SCTS
        pdu.push(udl as u8);
        pdu.extend_from_slice(ud);
        pdu
    }

    fn gsm7_pack(text: &str) -> Vec<u8> {
        let septets: Vec<u8> = text.chars().map(|c| c as u8).collect();
        gsm7_pack_septets(&septets)
    }

    fn gsm7_pack_septets(septets: &[u8]) -> Vec<u8> {
        let mut packed = Vec::new();
        let mut acc = 0u16;
        let mut bits = 0u32;
        for &septet in septets {
            acc |= u16::from(septet) << bits;
            bits += 7;
            while bits >= 8 {
                packed.push(acc as u8);
                acc >>= 8;
                bits -= 8;
            }
        }
        if bits > 0 {
            packed.push(acc as u8);
        }
        packed
    }
}
