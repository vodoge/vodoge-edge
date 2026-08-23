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
    /// TP-DCS verbatim, and `None` for a PDU that could not be walked.
    ///
    /// Carried so `encoding` can be audited against the byte it was derived
    /// from. The label reaches the console and the database, and until this
    /// existed there was no way to check it after the fact: the modem's copy
    /// of a message is deleted within a poll of being read, so by the time
    /// anyone doubts the label the evidence is gone.
    pub dcs: Option<u8>,
}

impl Deliver {
    fn undecodable(pdu: &[u8]) -> Self {
        Deliver {
            peer: String::new(),
            body: hex(pdu),
            concat: None,
            encoding: "unknown",
            dcs: None,
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
            dcs: None,
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
        dcs: Some(dcs),
    }
}

/// One decoded SMS-STATUS-REPORT: the network's answer to "did it arrive".
///
/// This is a different fact from the command receipt that moves a message from
/// `queued` to `sent`. That one says the modem accepted the PDU. This one says
/// the network handed it to the recipient, and the two can be minutes and one
/// failure apart.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatusReport {
    /// TP-MR, the reference the original SUBMIT carried. This is the only
    /// field that ties a report back to one particular sent message.
    pub reference: u8,
    /// TP-RA: who the original message was addressed to.
    pub peer: String,
    /// `delivered`, `pending`, `failed`, or `unknown`.
    pub status: &'static str,
    /// TP-ST verbatim. The four buckets above throw away the reason, and the
    /// reason is what says whether to retry -- 0x41 is "remote procedure
    /// error" and 0x46 is "SME not equipped", and only one is worth a resend.
    pub status_code: u8,
    /// TP-SCTS, when the service centre took the message, in unix millis.
    pub submitted_at: Option<i64>,
    /// TP-DT, when the service centre discharged it, in unix millis.
    pub delivered_at: Option<i64>,
}

/// Decodes one SMS-STATUS-REPORT PDU, or `None` if these bytes are not one.
///
/// `None` rather than a lossy struct: unlike a DELIVER, whose bytes are the
/// only copy of something a person wrote, a report that cannot be walked
/// carries nothing worth keeping and a guessed reference would settle the
/// wrong message. Callers log the hex and move on.
pub fn decode_status_report(pdu: &[u8]) -> Option<StatusReport> {
    if pdu.is_empty() {
        return None;
    }
    let mut i = 0usize;
    let smsc_len = pdu[0] as usize;
    if 1 + smsc_len < pdu.len() {
        i = 1 + smsc_len;
    }
    if i >= pdu.len() {
        return None;
    }

    // TP-MTI lives in bits 1-0 and is 0b10 for a status report. Checked rather
    // than assumed: the same store can hand back a DELIVER, and reading one as
    // the other yields a plausible reference pointing at an unrelated message.
    if pdu[i] & 0x03 != 0x02 {
        return None;
    }
    i += 1;

    if i >= pdu.len() {
        return None;
    }
    let reference = pdu[i];
    i += 1;

    if i + 1 >= pdu.len() {
        return None;
    }
    let ra_digits = pdu[i] as usize;
    let toa = pdu[i + 1];
    i += 2;

    let ra_bytes = ra_digits.div_ceil(2);
    // The address, then TP-SCTS and TP-DT at seven octets each and TP-ST at
    // one. The whole run must be present before any of it is read; a report
    // truncated inside a timestamp is the case that would index past the end.
    if i + ra_bytes + 15 > pdu.len() {
        return None;
    }
    let peer = decode_address(&pdu[i..i + ra_bytes], ra_digits, toa);
    i += ra_bytes;

    let submitted_at = decode_timestamp(&pdu[i..i + 7]);
    i += 7;
    let delivered_at = decode_timestamp(&pdu[i..i + 7]);
    i += 7;
    let status_code = pdu[i];

    Some(StatusReport {
        reference,
        peer,
        status: delivery_status(status_code),
        status_code,
        submitted_at,
        delivered_at,
    })
}

/// Buckets TP-ST, per 23.040 9.2.3.15.
///
/// The temporary-error range splits on whether the service centre is still
/// trying: 0x20-0x3f means it is, so the message is not finished and calling
/// it failed would be wrong. 0x60-0x7f is the same class of error with the
/// attempts given up on, which is an outcome.
fn delivery_status(status: u8) -> &'static str {
    match status {
        0x00..=0x1f => "delivered",
        0x20..=0x3f => "pending",
        0x40..=0x7f => "failed",
        _ => "unknown",
    }
}

/// Decodes a seven-octet TP-SCTS or TP-DT into unix millis.
///
/// Two traps, both of which produce a date that looks reasonable if missed.
///
/// The digits are semi-octet swapped: the low nibble is the *first* digit, so
/// `0x62` is 26 and not 62. Reading them in octet order gives a timestamp that
/// is wrong but still parses, which is the worst kind.
///
/// The last octet is the timezone in quarter-hours, swapped the same way, and
/// bit 3 of the first semi-octet is a sign bit rather than part of the number.
/// Ignoring it turns UTC-5 into UTC+21, and a `+CDS` from a western network
/// then reads as delivered a day and change into the future.
fn decode_timestamp(field: &[u8]) -> Option<i64> {
    if field.len() < 7 {
        return None;
    }
    let mut parts = [0u8; 6];
    for (slot, byte) in parts.iter_mut().zip(field.iter()) {
        let first = byte & 0x0f;
        let second = byte >> 4;
        if first > 9 || second > 9 {
            return None;
        }
        *slot = first * 10 + second;
    }
    let [year, month, day, hour, minute, second] = parts;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    // 60 seconds is allowed: a leap second is a real reading, not a fault.
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }

    let zone = field[6];
    let negative = zone & 0x08 != 0;
    let tens = zone & 0x07;
    let units = zone >> 4;
    if units > 9 {
        return None;
    }
    let quarters = i64::from(tens) * 10 + i64::from(units);
    let offset_minutes = if negative { -quarters * 15 } else { quarters * 15 };

    // Two digits of year, and the field has no century. 2000 is the only
    // reading that is not absurd for a message being delivered right now.
    let days = days_from_civil(2000 + i64::from(year), month, day);
    let seconds = days * 86_400
        + i64::from(hour) * 3600
        + i64::from(minute) * 60
        + i64::from(second)
        - offset_minutes * 60;
    Some(seconds * 1000)
}

/// Days between 1970-01-01 and a proleptic Gregorian date.
///
/// Hinnant's algorithm, written out rather than pulled in: edge-core owns no
/// dependencies beyond serde, and a calendar is arithmetic.
fn days_from_civil(year: i64, month: u8, day: u8) -> i64 {
    let month = i64::from(month);
    let shifted = if month <= 2 { year - 1 } else { year };
    let era = if shifted >= 0 { shifted } else { shifted - 399 } / 400;
    let year_of_era = shifted - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5
        + i64::from(day)
        - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
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

    /// Builds a STATUS-REPORT around its variable parts.
    ///
    /// SMSC and recipient fixed; `scts` and `dt` are the two seven-octet
    /// timestamps and `st` is TP-ST.
    fn status_report(reference: u8, scts: &str, dt: &str, st: u8) -> Vec<u8> {
        let mut pdu = from_hex("0791448720003023");
        pdu.push(0x06); // TP-MTI 0b10 (STATUS-REPORT), TP-SRQ clear
        pdu.push(reference);
        pdu.extend_from_slice(&from_hex("0C91447758100650")); // TP-RA +447785016005
        pdu.extend_from_slice(&from_hex(scts));
        pdu.extend_from_slice(&from_hex(dt));
        pdu.push(st);
        pdu
    }

    #[test]
    fn decodes_a_delivered_status_report() {
        // 2026-08-23 15:30:30 and :32 at UTC+8. The zone octet 0x23 is 32
        // quarter hours, swapped like every other pair.
        let pdu = status_report(0x2a, "62803251030323", "62803251032323", 0x00);
        let report = decode_status_report(&pdu).expect("status report");
        assert_eq!(report.reference, 0x2a);
        assert_eq!(report.peer, "+447785016005");
        assert_eq!(report.status, "delivered");
        assert_eq!(report.status_code, 0x00);
        assert_eq!(report.submitted_at, Some(1_787_470_230_000));
        assert_eq!(report.delivered_at, Some(1_787_470_232_000));
    }

    // The four TP-ST bands are not two. A service centre still retrying says
    // so with 0x30, and reporting that as failed would tell an operator to
    // resend a message that is still on its way.
    #[test]
    fn tp_st_bands_are_distinguished() {
        for (code, expected) in [
            (0x00u8, "delivered"),
            (0x02, "delivered"),
            (0x30, "pending"),
            (0x41, "failed"),
            (0x60, "failed"),
            (0x80, "unknown"),
        ] {
            let pdu = status_report(1, "62803251030323", "62803251030323", code);
            let report = decode_status_report(&pdu).expect("status report");
            assert_eq!(report.status, expected, "TP-ST {code:#04x}");
            assert_eq!(report.status_code, code);
        }
    }

    // Bit 3 of the first semi-octet is a sign, not a digit. Without it a
    // report from a US network reads as delivered 21 hours in the future,
    // which is a plausible-looking timestamp and so passes unnoticed.
    #[test]
    fn a_negative_timezone_is_not_read_as_a_large_positive_one() {
        // 0x0a: twenty quarter-hours with the sign bit set, i.e. UTC-05:00.
        let west = status_report(1, "6280325103030A", "6280325103030A", 0x00);
        // 0x02: the same twenty quarter-hours without it, UTC+05:00.
        let east = status_report(1, "62803251030302", "62803251030302", 0x00);
        let west = decode_status_report(&west).expect("west").submitted_at;
        let east = decode_status_report(&east).expect("east").submitted_at;
        assert_eq!(
            west.zip(east).map(|(w, e)| w - e),
            Some(10 * 3_600_000),
            "UTC-5 must be ten hours later in absolute time than UTC+5"
        );
    }

    // Semi-octets are swapped. Reading them in octet order gives a date that
    // parses and is wrong, which nothing downstream can detect.
    #[test]
    fn timestamp_digits_are_semi_octet_swapped() {
        let pdu = status_report(1, "62803251030300", "62803251030300", 0x00);
        let report = decode_status_report(&pdu).expect("status report");
        // 0x62 0x80 0x32 -> 26-08-23, not 62-08-23.
        assert_eq!(report.submitted_at, Some(1_787_499_030_000));
    }

    // A DELIVER read out of the same store must not be mistaken for a report:
    // its second octet would become a reference pointing at an unrelated send.
    #[test]
    fn a_deliver_is_not_a_status_report() {
        let pdu = from_hex(
            "0791448720003023240C914477581006500000916042113312800AE8329BFD4697D9EC37",
        );
        assert_eq!(decode_status_report(&pdu), None);
    }

    #[test]
    fn a_truncated_status_report_is_none_not_a_panic() {
        let full = status_report(7, "62803251030323", "62803251030323", 0x00);
        for cut in 0..full.len() {
            let _ = decode_status_report(&full[..cut]);
        }
        assert!(decode_status_report(&full).is_some());
    }

    // A timestamp with non-BCD nibbles is reported as absent rather than as a
    // number: the report itself is still usable, and inventing a discharge
    // time would put a fabricated moment on the operator's screen.
    #[test]
    fn a_nonsense_timestamp_leaves_the_field_empty() {
        let pdu = status_report(1, "FFFFFFFFFFFFFF", "62803251030323", 0x00);
        let report = decode_status_report(&pdu).expect("status report");
        assert_eq!(report.submitted_at, None);
        assert!(report.delivered_at.is_some());
        assert_eq!(report.status, "delivered");
    }

    // Two reports China Mobile actually sent, captured on the bench the day
    // this decoder was written. Every constant in the synthetic cases above
    // was chosen by reading the specification; these were chosen by nobody.
    //
    // Both went to a shortcode, so TP-RA is five digits with a filler nibble
    // and a national type-of-address -- no leading plus, which is the right
    // answer and the one a decoder that guesses the prefix gets wrong. The
    // trailing FF octets after TP-ST are padding the module leaves in place,
    // and reading them as more of the report is how a parser ends up
    // reporting a status code of 255 for a message that arrived.
    #[test]
    fn decodes_the_reports_the_bench_produced() {
        for (text, reference, at) in [
            (
                "00066705810180F6628032610530236280326105302300FFFFFFFFFFFFFF",
                103u8,
                1_787_475_003_000i64,
            ),
            (
                "00066805810180F6628032612524236280326125242300FFFFFFFFFFFFFF",
                104,
                1_787_475_162_000,
            ),
        ] {
            let report = decode_status_report(&from_hex(text)).expect(text);
            assert_eq!(report.reference, reference);
            assert_eq!(report.peer, "10086");
            assert_eq!(report.status, "delivered");
            assert_eq!(report.status_code, 0x00);
            assert_eq!(report.submitted_at, Some(at));
            assert_eq!(report.delivered_at, Some(at));
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
