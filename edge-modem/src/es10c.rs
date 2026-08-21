//! ES10c: the local profile management interface of an eUICC.
//!
//! Commands travel to the ISD-R as BER-TLV inside a `STORE DATA` APDU, and the
//! eUICC answers with BER-TLV. The channel number is carried by QMI as its own
//! field, so the APDU class byte stays `0x80` here and does not encode it.
//!
//! Length fields use the definite BER forms, and real cards use both: a
//! single-profile eUICC answered with a short length while one carrying policy
//! rules answered with `81 B0`. Reading only the short form silently truncates
//! the second card's profile list.

use crate::uim::decode_iccid;

/// `STORE DATA`, last block, block zero.
const STORE_DATA_HEADER: [u8; 4] = [0x80, 0xe2, 0x91, 0x00];

const TAG_GET_PROFILES_INFO: &[u8] = &[0xbf, 0x2d];
const TAG_ENABLE_PROFILE: &[u8] = &[0xbf, 0x31];
const TAG_DISABLE_PROFILE: &[u8] = &[0xbf, 0x32];

const TAG_PROFILE_LIST: u8 = 0xa0;
const TAG_PROFILE: u8 = 0xe3;
const TAG_ICCID: u8 = 0x5a;
const TAG_ISDP_AID: u8 = 0x4f;
const TAG_NICKNAME: u8 = 0x90;
const TAG_PROVIDER: u8 = 0x91;
const TAG_PROFILE_NAME: u8 = 0x92;
const TAG_PROFILE_CLASS: u8 = 0x95;
const TAG_PROFILE_STATE: &[u8] = &[0x9f, 0x70];
const TAG_RESULT: u8 = 0x80;

/// Failures decoding an eUICC answer or building a request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Es10cError {
    Truncated,
    UnexpectedTag { expected: Vec<u8>, actual: Vec<u8> },
    MissingProfileList,
    InvalidIccid,
    /// The eUICC understood the command and refused it.
    Refused { code: u8, reason: &'static str },
}

impl std::fmt::Display for Es10cError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => formatter.write_str("eUICC response is truncated"),
            Self::UnexpectedTag { expected, actual } => write!(
                formatter,
                "expected tag {}, got {}",
                hex(expected),
                hex(actual)
            ),
            Self::MissingProfileList => formatter.write_str("response has no profile list"),
            Self::InvalidIccid => formatter.write_str("ICCID is not a digit string"),
            Self::Refused { code, reason } => {
                write!(formatter, "eUICC refused the request: {reason} ({code})")
            }
        }
    }
}

impl std::error::Error for Es10cError {}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// One profile as the eUICC reports it.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Profile {
    pub iccid: String,
    pub isdp_aid: Option<String>,
    /// `true` when `profileState` is 1. Exactly one profile can be enabled.
    pub enabled: bool,
    pub nickname: Option<String>,
    pub provider: Option<String>,
    pub name: Option<String>,
    /// 0 test, 1 provisioning, 2 operational.
    pub class: Option<u8>,
}

impl Profile {
    /// The most useful human label the card offers, falling back to the ICCID.
    pub fn label(&self) -> String {
        self.nickname
            .clone()
            .or_else(|| self.name.clone())
            .or_else(|| self.provider.clone())
            .unwrap_or_else(|| self.iccid.clone())
    }
}

/// `GetProfilesInfo` with no search criteria, so the card returns every profile.
pub fn get_profiles_apdu() -> Vec<u8> {
    store_data(&[TAG_GET_PROFILES_INFO, &[0x00]].concat())
}

/// `EnableProfile` by ICCID.
///
/// `refresh` asks the card to trigger a REFRESH so the modem re-reads the new
/// profile. Without it the switch does not take effect until the module is
/// restarted, which looks to an operator like the command silently failed.
pub fn enable_profile_apdu(iccid: &str, refresh: bool) -> Result<Vec<u8>, Es10cError> {
    profile_command(TAG_ENABLE_PROFILE, iccid, refresh)
}

/// `DisableProfile` by ICCID.
pub fn disable_profile_apdu(iccid: &str, refresh: bool) -> Result<Vec<u8>, Es10cError> {
    profile_command(TAG_DISABLE_PROFILE, iccid, refresh)
}

fn profile_command(tag: &[u8], iccid: &str, refresh: bool) -> Result<Vec<u8>, Es10cError> {
    let iccid = encode_iccid(iccid)?;
    // SGP.22 uses AUTOMATIC TAGS, so the profileIdentifier CHOICE becomes
    // context [0] (constructed) and refreshFlag becomes context [1].
    let mut identifier = vec![TAG_ICCID, iccid.len() as u8];
    identifier.extend_from_slice(&iccid);
    let mut body = vec![TAG_PROFILE_LIST, identifier.len() as u8];
    body.extend_from_slice(&identifier);
    body.extend_from_slice(&[0x81, 0x01, if refresh { 0xff } else { 0x00 }]);

    let mut request = tag.to_vec();
    request.push(body.len() as u8);
    request.extend_from_slice(&body);
    Ok(store_data(&request))
}

fn store_data(payload: &[u8]) -> Vec<u8> {
    let mut apdu = STORE_DATA_HEADER.to_vec();
    apdu.push(payload.len() as u8);
    apdu.extend_from_slice(payload);
    apdu
}

/// Parse a `GetProfilesInfo` response.
pub fn parse_profiles(response: &[u8]) -> Result<Vec<Profile>, Es10cError> {
    let body = expect_tag(response, TAG_GET_PROFILES_INFO)?;
    let (tag, list, _) = read_tlv(body)?;
    if tag != [TAG_PROFILE_LIST] {
        // A card with no profiles answers with an error tag instead of an
        // empty list, so this is a refusal rather than "none installed".
        return Err(Es10cError::MissingProfileList);
    }
    let mut profiles = Vec::new();
    let mut rest = list;
    while !rest.is_empty() {
        let (tag, value, tail) = read_tlv(rest)?;
        rest = tail;
        if tag != [TAG_PROFILE] {
            continue;
        }
        profiles.push(parse_profile(value)?);
    }
    Ok(profiles)
}

fn parse_profile(mut body: &[u8]) -> Result<Profile, Es10cError> {
    let mut profile = Profile::default();
    while !body.is_empty() {
        let (tag, value, tail) = read_tlv(body)?;
        body = tail;
        match tag.as_slice() {
            [TAG_ICCID] => profile.iccid = decode_iccid(value).map_err(|_| Es10cError::InvalidIccid)?,
            [TAG_ISDP_AID] => profile.isdp_aid = Some(hex(value).to_uppercase()),
            [TAG_NICKNAME] => profile.nickname = text(value),
            [TAG_PROVIDER] => profile.provider = text(value),
            [TAG_PROFILE_NAME] => profile.name = text(value),
            [TAG_PROFILE_CLASS] => profile.class = value.first().copied(),
            _ if tag == TAG_PROFILE_STATE => profile.enabled = value.first() == Some(&1),
            _ => {}
        }
    }
    Ok(profile)
}

/// Parse an `EnableProfile` or `DisableProfile` response.
pub fn parse_profile_result(response: &[u8], enable: bool) -> Result<(), Es10cError> {
    let tag = if enable {
        TAG_ENABLE_PROFILE
    } else {
        TAG_DISABLE_PROFILE
    };
    let body = expect_tag(response, tag)?;
    let (result_tag, value, _) = read_tlv(body)?;
    if result_tag != [TAG_RESULT] {
        return Err(Es10cError::UnexpectedTag {
            expected: vec![TAG_RESULT],
            actual: result_tag,
        });
    }
    match value.first().copied().ok_or(Es10cError::Truncated)? {
        0 => Ok(()),
        code => Err(Es10cError::Refused {
            code,
            reason: refusal(code, enable),
        }),
    }
}

/// SGP.22 enable/disable result codes.
fn refusal(code: u8, enable: bool) -> &'static str {
    match (code, enable) {
        (1, _) => "ICCID or AID not found",
        (2, true) => "profile is not in the disabled state",
        (2, false) => "profile is not in the enabled state",
        (3, _) => "disallowed by policy",
        (4, true) => "wrong profile reenabled",
        (4, false) => "catBusy",
        (5, _) => "catBusy",
        _ => "undefined error",
    }
}

fn text(value: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(value).trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

/// ICCID as nibble-swapped BCD, padded to 10 bytes with `f`.
fn encode_iccid(iccid: &str) -> Result<Vec<u8>, Es10cError> {
    let digits: Vec<char> = iccid.trim().chars().collect();
    if digits.is_empty() || digits.iter().any(|c| !c.is_ascii_digit()) {
        return Err(Es10cError::InvalidIccid);
    }
    let mut bytes = Vec::with_capacity(10);
    let mut index = 0;
    while index < digits.len() {
        let low = digits[index].to_digit(16).ok_or(Es10cError::InvalidIccid)? as u8;
        let high = match digits.get(index + 1) {
            Some(value) => value.to_digit(16).ok_or(Es10cError::InvalidIccid)? as u8,
            None => 0x0f,
        };
        bytes.push(low | (high << 4));
        index += 2;
    }
    while bytes.len() < 10 {
        bytes.push(0xff);
    }
    Ok(bytes)
}

fn expect_tag<'a>(bytes: &'a [u8], expected: &[u8]) -> Result<&'a [u8], Es10cError> {
    let (tag, value, _) = read_tlv(bytes)?;
    if tag != expected {
        return Err(Es10cError::UnexpectedTag {
            expected: expected.to_vec(),
            actual: tag,
        });
    }
    Ok(value)
}

/// Read one BER-TLV, returning its tag, value, and the bytes after it.
fn read_tlv(bytes: &[u8]) -> Result<(Vec<u8>, &[u8], &[u8]), Es10cError> {
    let first = *bytes.first().ok_or(Es10cError::Truncated)?;
    let mut cursor = 1;
    let mut tag = vec![first];
    // A low-order nibble of all ones means the tag continues into further
    // bytes, each of which sets bit 8 while more follow.
    if first & 0x1f == 0x1f {
        loop {
            let next = *bytes.get(cursor).ok_or(Es10cError::Truncated)?;
            cursor += 1;
            tag.push(next);
            if next & 0x80 == 0 {
                break;
            }
        }
    }

    let length_byte = *bytes.get(cursor).ok_or(Es10cError::Truncated)?;
    cursor += 1;
    let length = if length_byte & 0x80 == 0 {
        usize::from(length_byte)
    } else {
        let count = usize::from(length_byte & 0x7f);
        if count == 0 || count > 4 {
            return Err(Es10cError::Truncated);
        }
        let mut value = 0usize;
        for _ in 0..count {
            let byte = *bytes.get(cursor).ok_or(Es10cError::Truncated)?;
            cursor += 1;
            value = (value << 8) | usize::from(byte);
        }
        value
    };

    let end = cursor.checked_add(length).ok_or(Es10cError::Truncated)?;
    if end > bytes.len() {
        return Err(Es10cError::Truncated);
    }
    Ok((tag, &bytes[cursor..end], &bytes[end..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(hex: &str) -> Vec<u8> {
        let hex: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
        let hex = hex.as_str();
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect()
    }

    /// Captured from a ClubSIM eUICC. Short-form lengths throughout.
    const CLUBSIM: &str = "BF2D35A033E3315A0A985802004136129775F14F10A0000005591010FFFFFFFF8900\
                           0012009F7001019104436C75629204436C756295010 2";

    /// Captured from a Saily eUICC: long-form lengths and policy rules.
    const SAILY: &str = "BF2D81B0A081ADE381AA5A0A9858321522052412241 04F10A0000005591010FFFFFFFF89\
                         000012009F70010191055361696C79920757454242494E47950102BF7672E224E116C114\
                         9880246500BFD50F1415AF56C705A94E2BB2015AE30ADB080000000000000001E224E116\
                         C114A8F000988F2C44FA897427E1A740FDE2FF545C19E30ADB080000000000000001E224\
                         E116C1148204F3D96D0061D88FBD97FC8CE041E9494D6B9BE30ADB0800000000000000 01";

    fn clean(value: &str) -> String {
        value.chars().filter(|c| !c.is_whitespace()).collect()
    }

    #[test]
    fn parses_a_short_form_profile_list() {
        let profiles = parse_profiles(&bytes(&clean(CLUBSIM))).expect("profiles");
        assert_eq!(profiles.len(), 1);
        let profile = &profiles[0];
        assert_eq!(profile.iccid, "8985200014632179571");
        assert!(profile.enabled);
        assert_eq!(profile.provider.as_deref(), Some("Club"));
        assert_eq!(profile.name.as_deref(), Some("Club"));
        assert_eq!(profile.class, Some(2));
    }

    /// The second card answers with `81 B0`. Reading only the short length
    /// form truncates its list to nothing.
    #[test]
    fn parses_a_long_form_profile_list() {
        let profiles = parse_profiles(&bytes(&clean(SAILY))).expect("profiles");
        assert_eq!(profiles.len(), 1);
        let profile = &profiles[0];
        assert_eq!(profile.iccid, "89852351225042214201");
        assert!(profile.enabled);
        assert_eq!(profile.provider.as_deref(), Some("Saily"));
        assert_eq!(profile.name.as_deref(), Some("WEBBING"));
    }

    #[test]
    fn label_prefers_a_human_name_over_the_iccid() {
        let profiles = parse_profiles(&bytes(&clean(SAILY))).expect("profiles");
        assert_eq!(profiles[0].label(), "WEBBING");
    }

    #[test]
    fn get_profiles_apdu_is_store_data() {
        assert_eq!(get_profiles_apdu(), bytes("80E2910003BF2D00"));
    }

    #[test]
    fn enable_wraps_the_iccid_and_refresh_flag() {
        let apdu = enable_profile_apdu("89852351225042214201", true).expect("apdu");
        // STORE DATA Lc 0x14, BF31 body 0x11: A0 0C (5A 0A <10 bytes>) 81 01 FF.
        assert_eq!(
            apdu,
            bytes("80E2910014 BF3111 A00C 5A0A 98583215220524122410 8101FF")
        );
    }

    #[test]
    fn disable_uses_its_own_tag() {
        let apdu = disable_profile_apdu("89852351225042214201", false).expect("apdu");
        assert_eq!(&apdu[5..7], &[0xbf, 0x32]);
        assert_eq!(apdu[apdu.len() - 1], 0x00);
    }

    /// A 19-digit ICCID is padded, not truncated: the card matches on the full
    /// ten-byte field, and the odd digit leaves an `f` in the high nibble.
    #[test]
    fn odd_length_iccid_is_padded() {
        let apdu = enable_profile_apdu("8985200014632179571", true).expect("apdu");
        // header 5 + BF31 tag/len 3 + A0 len 2 + 5A len 2 = 12.
        let iccid = &apdu[12..22];
        assert_eq!(iccid.len(), 10);
        assert_eq!(iccid[9], 0xf1);
    }

    #[test]
    fn non_numeric_iccid_is_rejected() {
        assert_eq!(
            enable_profile_apdu("89ab", true),
            Err(Es10cError::InvalidIccid)
        );
    }

    #[test]
    fn success_result_is_ok() {
        assert_eq!(parse_profile_result(&bytes("BF31038001 00"), true), Ok(()));
    }

    #[test]
    fn refusal_is_reported_with_its_reason() {
        assert_eq!(
            parse_profile_result(&bytes("BF31038001 02"), true),
            Err(Es10cError::Refused {
                code: 2,
                reason: "profile is not in the disabled state",
            })
        );
    }

    #[test]
    fn truncated_response_is_rejected() {
        assert_eq!(parse_profiles(&bytes("BF2D35A0")), Err(Es10cError::Truncated));
    }
}
