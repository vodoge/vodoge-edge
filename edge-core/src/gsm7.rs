//! GSM 03.38 seven-bit alphabet, decode side.
//!
//! Inbound messages were being handed to `String::from_utf8_lossy`. That is not
//! a lenient reading of GSM-7, it is a reading of a different encoding
//! entirely: the alphabet packs seven-bit values across octet boundaries, so
//! the bytes on the wire do not line up with characters at all. Every plain
//! ASCII message from a US shortcode arrived as mojibake, and since packed
//! septets routinely produce a zero octet, some arrived carrying a NUL — which
//! PostgreSQL then refused, stalling the entire device uplink.
//!
//! Only the decode direction lives here. Sending already has `pack_gsm7` in
//! edge-modem, which deliberately handles a small ASCII subset and refuses
//! anything else so it can fall back to UCS-2. Receiving has no such luxury:
//! whatever the network sends must be read.

/// The default alphabet, GSM 03.38 table 1.
///
/// Position is the septet value. The entries that are not their ASCII
/// equivalent are the point of the table: 0x00 is '@' rather than NUL, 0x02 is
/// the currency sign, and the run from 0x10 carries Greek capitals that share
/// no code point with anything in ASCII.
const BASIC: [char; 128] = [
    '@', '£', '$', '¥', 'è', 'é', 'ù', 'ì', 'ò', 'Ç', '\n', 'Ø', 'ø', '\r', 'Å', 'å',
    'Δ', '_', 'Φ', 'Γ', 'Λ', 'Ω', 'Π', 'Ψ', 'Σ', 'Θ', 'Ξ', '\u{1b}', 'Æ', 'æ', 'ß', 'É',
    ' ', '!', '"', '#', '¤', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?',
    '¡', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
    'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'Ä', 'Ö', 'Ñ', 'Ü', '§',
    '¿', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
    'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'ä', 'ö', 'ñ', 'ü', 'à',
];

/// The escape value. A septet of 0x1b means the next septet is read from the
/// extension table instead of the basic one.
const ESCAPE: u8 = 0x1b;

/// Extension table, GSM 03.38 table 2. Everything absent from it is defined to
/// read as the basic-table character for the same value, so only the handful
/// that differ are listed.
fn extension(value: u8) -> Option<char> {
    Some(match value {
        0x0a => '\u{0c}', // form feed
        0x14 => '^',
        0x28 => '{',
        0x29 => '}',
        0x2f => '\\',
        0x3c => '[',
        0x3d => '~',
        0x3e => ']',
        0x40 => '|',
        0x65 => '€',
        _ => return None,
    })
}

/// Unpacks `count` septets from `packed`, skipping the first `skip`.
///
/// `skip` exists for the user data header. In a seven-bit message the header is
/// measured in octets but the text that follows must start on a septet
/// boundary, so the network inserts fill bits and the first whole septets are
/// header, not text. Unpacking from after the header instead of skipping over
/// it reads every septet shifted by those fill bits, which yields plausible but
/// entirely wrong characters — the failure mode that looks like a decoder bug
/// long after the real cause.
pub fn unpack_septets(packed: &[u8], skip: usize, count: usize) -> Vec<u8> {
    let mut septets = Vec::with_capacity(count);
    let mut acc = 0u16;
    let mut bits = 0u32;
    let mut taken = 0usize;
    let wanted = skip + count;

    for &byte in packed {
        acc |= u16::from(byte) << bits;
        bits += 8;
        while bits >= 7 {
            if taken == wanted {
                return septets;
            }
            let septet = (acc & 0x7f) as u8;
            acc >>= 7;
            bits -= 7;
            if taken >= skip {
                septets.push(septet);
            }
            taken += 1;
        }
    }
    septets
}

/// Number of septets the user data header occupies, including its length byte.
///
/// The header is `header_octets` bytes of user data; the text resumes at the
/// next septet boundary at or after it.
pub fn header_septets(header_octets: usize) -> usize {
    (header_octets * 8).div_ceil(7)
}

/// Maps unpacked septets through the default alphabet.
pub fn decode_septets(septets: &[u8]) -> String {
    let mut out = String::with_capacity(septets.len());
    let mut iter = septets.iter().copied();
    while let Some(value) = iter.next() {
        if value == ESCAPE {
            match iter.next() {
                // An escape followed by a value the extension table does not
                // define is specified to read as the basic character for that
                // value, not as an error and not as nothing.
                Some(next) => out.push(
                    extension(next).unwrap_or_else(|| BASIC[usize::from(next & 0x7f)]),
                ),
                // A trailing escape is the padding at the end of a full
                // message, and means nothing.
                None => break,
            }
            continue;
        }
        out.push(BASIC[usize::from(value & 0x7f)]);
    }
    out
}

/// Decodes GSM-7 user data straight from the wire.
///
/// `user_data` is the whole UD field including any header, `header_octets` is
/// what the header occupies (zero when there is none), and `udl` is the
/// TP-UDL, which for this alphabet counts septets across the whole field —
/// header included.
pub fn decode(user_data: &[u8], header_octets: usize, udl: usize) -> String {
    let skip = header_septets(header_octets);
    let count = udl.saturating_sub(skip);
    decode_septets(&unpack_septets(user_data, skip, count))
}

#[cfg(test)]
mod tests {
    use super::*;

    // The canonical example from 3GPP 23.038: "hellohello" packed into eight
    // octets. If the bit order is wrong this is the test that says so.
    #[test]
    fn unpacks_the_specification_example() {
        let packed = [0xe8, 0x32, 0x9b, 0xfd, 0x46, 0x97, 0xd9, 0xec, 0x37];
        assert_eq!(decode(&packed, 0, 10), "hellohello");
    }

    #[test]
    fn reads_plain_ascii() {
        // "Your code is 123456" -- the shape of every one-time passcode.
        let text = "Your code is 123456";
        let packed = pack_for_test(text);
        assert_eq!(decode(&packed, 0, text.chars().count()), text);
    }

    #[test]
    fn zero_is_at_sign_not_nul() {
        // The septet zero decodes to '@'. Read as UTF-8 it is a NUL, which
        // jsonb cannot store -- this is the byte that stalled the uplink.
        let packed = pack_for_test("@@@");
        let body = decode(&packed, 0, 3);
        assert_eq!(body, "@@@");
        assert!(!body.contains('\u{0}'), "decoder produced a NUL");
    }

    #[test]
    fn reads_the_extension_table() {
        let septets = [ESCAPE, 0x65, ESCAPE, 0x28, 0x41, ESCAPE, 0x29];
        assert_eq!(decode_septets(&septets), "€{A}");
    }

    #[test]
    fn an_undefined_escape_falls_back_to_the_basic_table() {
        // 0x1b 0x41 is not in the extension table; 0x41 is 'A' in the basic one.
        assert_eq!(decode_septets(&[ESCAPE, 0x41]), "A");
    }

    #[test]
    fn a_trailing_escape_is_padding() {
        assert_eq!(decode_septets(&[0x41, ESCAPE]), "A");
    }

    // A six-octet concatenation header occupies seven septets, and the text
    // starts at the next boundary. Decoding from the octet after the header
    // instead shifts every character.
    #[test]
    fn skips_the_septets_a_header_occupies() {
        let text = "Hi";
        let mut user_data = vec![0x05, 0x00, 0x03, 0xd2, 0x02, 0x01];
        let header_octets = user_data.len();
        let skip = header_septets(header_octets);
        assert_eq!(skip, 7);

        // Repack: seven septets of filler standing in for the header, then the
        // text, exactly as the network lays it out.
        let mut septets = vec![0u8; skip];
        septets.extend(text.chars().map(|c| c as u8));
        user_data = pack_septets(&septets);

        let udl = skip + text.chars().count();
        assert_eq!(decode(&user_data, header_octets, udl), text);
    }

    #[test]
    fn stops_at_the_declared_length() {
        // Packing leaves spare bits in the final octet. Without honouring UDL
        // those decode as a trailing '@'.
        let packed = pack_for_test("AAAAAAA");
        assert_eq!(decode(&packed, 0, 7), "AAAAAAA");
    }

    fn pack_for_test(text: &str) -> Vec<u8> {
        let septets: Vec<u8> = text
            .chars()
            .map(|c| {
                BASIC
                    .iter()
                    .position(|&b| b == c)
                    .expect("test text must be in the basic alphabet") as u8
            })
            .collect();
        pack_septets(&septets)
    }

    fn pack_septets(septets: &[u8]) -> Vec<u8> {
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
