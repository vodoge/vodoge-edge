//! ES10b and ES10c: the local information and profile management interfaces
//! of an eUICC.
//!
//! Commands travel to the ISD-R as BER-TLV inside a `STORE DATA` APDU, and the
//! eUICC answers with BER-TLV. The channel number is carried by QMI as its own
//! field, so the APDU class byte stays `0x80` here and does not encode it.
//!
//! Length fields use the definite BER forms, and real cards use both: a
//! single-profile eUICC answered with a short length while one carrying policy
//! rules answered with `81 B0`. Reading only the short form silently truncates
//! the second card's profile list.
//!
//! ES10b lives here rather than in a file of its own because the two share the
//! transport, the TLV reader and the error type, and splitting them would have
//! meant duplicating all three.

use crate::uim::decode_iccid;

/// `STORE DATA` for a block that is not the last one (SGP.22 §5.7.2).
const P1_MORE_BLOCKS: u8 = 0x11;
/// `STORE DATA` for the last block.
const P1_LAST_BLOCK: u8 = 0x91;
const CLA_GLOBALPLATFORM: u8 = 0x80;
const INS_STORE_DATA: u8 = 0xe2;

/// The largest command data field one `STORE DATA` can carry.
///
/// `Lc` is a single byte in the short APDU form the ISD-R accepts, so anything
/// longer has to be split. It used to be cast with `as u8`: a 300-byte payload
/// became `Lc = 44` and the card was handed 44 bytes of a request it could not
/// parse, with no error anywhere.
pub const STORE_DATA_BLOCK_BYTES: usize = 255;

/// `P2` carries the block number in one byte, so a chain is at most 256 blocks.
pub const MAX_STORE_DATA_BLOCKS: usize = 256;

/// The largest payload a `STORE DATA` chain can carry at all.
pub const MAX_STORE_DATA_BYTES: usize = STORE_DATA_BLOCK_BYTES * MAX_STORE_DATA_BLOCKS;

const TAG_GET_PROFILES_INFO: &[u8] = &[0xbf, 0x2d];
const TAG_ENABLE_PROFILE: &[u8] = &[0xbf, 0x31];
const TAG_DISABLE_PROFILE: &[u8] = &[0xbf, 0x32];
/// ES10c `GetEUICCData`, which is how the EID is read.
const TAG_GET_EUICC_DATA: &[u8] = &[0xbf, 0x3e];
/// ES10b `GetEUICCInfo2`.
const TAG_EUICC_INFO2: &[u8] = &[0xbf, 0x22];
/// ES10b `GetEUICCInfo1`, the short form ES9+ carries.
const TAG_EUICC_INFO1: &[u8] = &[0xbf, 0x20];
/// ES10b `GetEUICCChallenge`.
const TAG_EUICC_CHALLENGE: &[u8] = &[0xbf, 0x2e];
/// ES10a `GetEuiccConfiguredAddresses`.
const TAG_CONFIGURED_ADDRESSES: &[u8] = &[0xbf, 0x3c];
/// ES10b `ListNotification`.
const TAG_LIST_NOTIFICATION: &[u8] = &[0xbf, 0x28];
/// ES10b `RetrieveNotificationsList`.
const TAG_RETRIEVE_NOTIFICATIONS: &[u8] = &[0xbf, 0x2b];
/// One notification's metadata, in both responses above.
const TAG_NOTIFICATION_METADATA: &[u8] = &[0xbf, 0x2f];
/// A pending notification that is a `ProfileInstallationResult`.
const TAG_INSTALLATION_RESULT: &[u8] = &[0xbf, 0x37];
const TAG_INSTALLATION_RESULT_DATA: &[u8] = &[0xbf, 0x27];

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

/// `[0]` in both notification responses: the list.
const TAG_NOTIFICATION_LIST: u8 = 0xa0;
/// `[1]` in both notification responses: an error instead of a list.
const TAG_NOTIFICATION_ERROR: u8 = 0x81;
/// An `OtherSignedNotification` is a plain SEQUENCE, unlike the tagged
/// `ProfileInstallationResult` it shares the list with.
const TAG_SEQUENCE: u8 = 0x30;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_UTF8_STRING: u8 = 0x0c;

/// SGP.22 `NotificationEvent`, a BIT STRING.
const NOTIFICATION_EVENTS: &[&str] = &["install", "enable", "disable", "delete"];

/// SGP.22 `RspCapability`, a BIT STRING.
const RSP_CAPABILITIES: &[&str] = &[
    "additionalProfile",
    "crlSupport",
    "rpmSupport",
    "testProfileSupport",
    "deviceInfoExtensibilitySupport",
    "serviceSpecificDataSupport",
    "hriServerAddressSupport",
    "serviceProviderMessageSupport",
];

/// SGP.22 `UICCCapability`, a BIT STRING.
const UICC_CAPABILITIES: &[&str] = &[
    "contactlessSupport",
    "usimSupport",
    "isimSupport",
    "csimSupport",
    "akaMilenage",
    "akaCave",
    "akaTuak128",
    "akaTuak256",
    "usimTestAlgorithm",
    "rfu2",
    "gbaAuthenUsim",
    "gbaAuthenISim",
    "mbmsAuthenUsim",
    "eapClient",
    "javacard",
    "multos",
    "multipleUsimSupport",
    "multipleIsimSupport",
    "multipleCsimSupport",
    "berTlvFileSupport",
    "dfLinkSupport",
    "catTp",
    "getIdentity",
    "profile-a-x25519",
    "profile-b-p256",
    "suciCalculatorApi",
];

/// SGP.22 `PprIds`, a BIT STRING.
const PPR_IDS: &[&str] = &["pprUpdateControl", "ppr1", "ppr2"];

/// Failures decoding an eUICC answer or building a request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Es10cError {
    Truncated,
    UnexpectedTag { expected: Vec<u8>, actual: Vec<u8> },
    MissingProfileList,
    InvalidIccid,
    /// The eUICC understood the command and refused it.
    Refused { code: u8, reason: &'static str },
    /// A `STORE DATA` chain cannot carry this much.
    ///
    /// A hard error rather than a truncation: the block number is one byte, so
    /// past this point there is no correct APDU to send, and sending a wrong
    /// one is how a half-written request reaches a card.
    PayloadTooLarge { actual: usize, max: usize },
    /// `STORE DATA` with no command data is not a request the ISD-R answers.
    EmptyPayload,
    /// The card returned an error code instead of a notification list.
    NotificationsUnavailable { code: u64 },
    /// A field SGP.22 makes mandatory was absent.
    MissingField { name: &'static str },
    /// `GetEUICCChallenge` returned something other than sixteen bytes.
    ///
    /// Its own error rather than `Truncated`: the challenge is what binds an
    /// ES9+ session to this chip, and a short one would be handed to an
    /// SM-DP+ and echoed back looking perfectly valid.
    ChallengeLength { actual: usize },
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
            Self::PayloadTooLarge { actual, max } => write!(
                formatter,
                "ES10 payload is {actual} bytes, above the {max} a STORE DATA chain can carry"
            ),
            Self::EmptyPayload => formatter.write_str("ES10 payload is empty"),
            Self::NotificationsUnavailable { code } => write!(
                formatter,
                "eUICC returned notification list error {code}{}",
                if *code == 127 { " (undefined error)" } else { "" }
            ),
            Self::MissingField { name } => write!(formatter, "response has no {name}"),
            Self::ChallengeLength { actual } => write!(
                formatter,
                "eUICC challenge is {actual} bytes, SGP.22 requires {EUICC_CHALLENGE_BYTES}"
            ),
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

/// What `GetEUICCInfo2` says about the chip.
///
/// Decoded in full rather than checked for a success tag. The interesting
/// numbers for anyone about to download a profile are the free non-volatile
/// memory and the CI public keys the chip will verify against, and neither is
/// visible from "the command did not fail".
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EuiccInfo2 {
    pub profile_version: Option<String>,
    /// SGP.22 version the chip implements.
    pub svn: Option<String>,
    pub firmware_version: Option<String>,
    pub installed_applications: Option<u64>,
    pub free_non_volatile_memory: Option<u64>,
    pub free_volatile_memory: Option<u64>,
    pub uicc_capabilities: Vec<String>,
    pub ts102241_version: Option<String>,
    pub global_platform_version: Option<String>,
    pub rsp_capabilities: Vec<String>,
    /// GSMA CI public key identifiers the chip verifies signatures against.
    pub ci_key_ids_for_verification: Vec<String>,
    /// CI public key identifiers the chip can sign with.
    pub ci_key_ids_for_signing: Vec<String>,
    pub category: Option<u64>,
    pub forbidden_profile_policy_rules: Vec<String>,
    pub pp_version: Option<String>,
    pub sas_accreditation_number: Option<String>,
}

impl EuiccInfo2 {
    /// How many of the sixteen fields the card actually populated.
    ///
    /// The point of a count is that a test can insist the decoder read the
    /// whole answer. Asserting only "no error" passes just as happily when a
    /// truncated response yielded one field out of sixteen, which is exactly
    /// what a single-round GET RESPONSE produces.
    pub fn populated_fields(&self) -> usize {
        [
            self.profile_version.is_some(),
            self.svn.is_some(),
            self.firmware_version.is_some(),
            self.installed_applications.is_some(),
            self.free_non_volatile_memory.is_some(),
            self.free_volatile_memory.is_some(),
            !self.uicc_capabilities.is_empty(),
            self.ts102241_version.is_some(),
            self.global_platform_version.is_some(),
            !self.rsp_capabilities.is_empty(),
            !self.ci_key_ids_for_verification.is_empty(),
            !self.ci_key_ids_for_signing.is_empty(),
            self.category.is_some(),
            !self.forbidden_profile_policy_rules.is_empty(),
            self.pp_version.is_some(),
            self.sas_accreditation_number.is_some(),
        ]
        .into_iter()
        .filter(|present| *present)
        .count()
    }
}

/// How many bytes `GetEUICCChallenge` returns (SGP.22 `Octet16`).
pub const EUICC_CHALLENGE_BYTES: usize = 16;

/// `GetEUICCInfo1`: the short chip description ES9+ carries verbatim.
///
/// The raw bytes are kept alongside the decoded fields because
/// `InitiateAuthentication` transports the whole `BF20` structure base64
/// encoded, and an SM-DP+ reads it as the chip emitted it. Re-encoding the
/// decoded fields would produce something that means the same and is not the
/// same, which is exactly the class of bug that only shows up at the far end.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EuiccInfo1 {
    /// SGP.22 version the chip implements.
    pub svn: Option<String>,
    /// GSMA CI public key identifiers the chip verifies an SM-DP+ against.
    pub ci_key_ids_for_verification: Vec<String>,
    pub ci_key_ids_for_signing: Vec<String>,
    /// The `BF20` TLV exactly as the card produced it.
    pub raw: Vec<u8>,
}

/// The addresses ES10a `GetEuiccConfiguredAddresses` reports.
///
/// Both are optional and on the bench both chips answer with only the second:
/// no default SM-DP+ is configured, and the root SM-DS is GSMA's *test* one.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ConfiguredAddresses {
    /// The SM-DP+ the chip should talk to when nothing else names one.
    pub default_dp_address: Option<String>,
    /// The root discovery server.
    pub root_ds_address: Option<String>,
}

/// One entry of the eUICC pending notification list.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NotificationMetadata {
    pub sequence_number: u64,
    /// `install`, `enable`, `disable` or `delete`.
    pub operations: Vec<String>,
    /// The SM-DP+ that has to be told, as a host name.
    pub address: String,
    pub iccid: Option<String>,
}

/// A pending notification with the signed bytes the SM-DP+ has to receive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingNotification {
    pub metadata: NotificationMetadata,
    /// `true` for a `ProfileInstallationResult`, `false` for an
    /// `OtherSignedNotification`. The two are carried in the same list under
    /// different tags and go to the same ES9+ function.
    pub installation_result: bool,
    /// The whole signed notification, verbatim.
    ///
    /// Kept as bytes rather than re-encoded: what ES9+ `handleNotification`
    /// carries is the signed structure the eUICC produced, and anything this
    /// code rebuilt would no longer match the signature over it.
    pub payload: Vec<u8>,
}

/// Split an ES10 request into a `STORE DATA` chain.
///
/// Blocks before the last carry `P1 = 0x11`, the last carries `0x91`, and `P2`
/// counts them from zero (SGP.22 section 5.7.2). A payload that does not fit
/// is an error: the alternative is the `as u8` truncation this replaced, which
/// handed a card a prefix of a request and called it a success.
pub fn store_data_chain(payload: &[u8]) -> Result<Vec<Vec<u8>>, Es10cError> {
    if payload.is_empty() {
        return Err(Es10cError::EmptyPayload);
    }
    if payload.len() > MAX_STORE_DATA_BYTES {
        return Err(Es10cError::PayloadTooLarge {
            actual: payload.len(),
            max: MAX_STORE_DATA_BYTES,
        });
    }
    let blocks: Vec<&[u8]> = payload.chunks(STORE_DATA_BLOCK_BYTES).collect();
    let last = blocks.len() - 1;
    Ok(blocks
        .into_iter()
        .enumerate()
        .map(|(index, block)| {
            let p1 = if index == last {
                P1_LAST_BLOCK
            } else {
                P1_MORE_BLOCKS
            };
            // Both casts are bounded by the checks above: at most 256 blocks,
            // at most 255 bytes each.
            let mut apdu = vec![
                CLA_GLOBALPLATFORM,
                INS_STORE_DATA,
                p1,
                index as u8,
                block.len() as u8,
            ];
            apdu.extend_from_slice(block);
            apdu
        })
        .collect())
}

/// `GetProfilesInfo` with no search criteria, so the card returns every profile.
pub fn get_profiles_payload() -> Vec<u8> {
    [TAG_GET_PROFILES_INFO, &[0x00]].concat()
}

/// ES10c `GetEUICCData` asking for tag `5A`, the EID.
///
/// Preferred over the GlobalPlatform `GET DATA` form the first version used:
/// both eUICCs on the bench answer `6D00` to `80 CA 00 5A 00` and answer this
/// one, so the GlobalPlatform form is only a fallback now.
pub fn get_eid_payload() -> Vec<u8> {
    [TAG_GET_EUICC_DATA, &[0x03, 0x5c, 0x01, 0x5a]].concat()
}

/// ES10b `GetEUICCInfo2`.
pub fn euicc_info2_payload() -> Vec<u8> {
    [TAG_EUICC_INFO2, &[0x00]].concat()
}

/// ES10b `GetEUICCInfo1`.
///
/// Not the same thing as `GetEUICCInfo2` with fewer fields read out of it:
/// ES9+ `InitiateAuthentication` carries `euiccInfo1`, and an SM-DP+ handed
/// the `BF22` structure instead rejects the request.
pub fn euicc_info1_payload() -> Vec<u8> {
    [TAG_EUICC_INFO1, &[0x00]].concat()
}

/// ES10b `GetEUICCChallenge`.
///
/// Read-only, and fresh every time: the chip generates a new random challenge
/// per call rather than returning a stored one. That is what makes it usable
/// as proof that an ES9+ session reached this chip and not a cache.
pub fn euicc_challenge_payload() -> Vec<u8> {
    [TAG_EUICC_CHALLENGE, &[0x00]].concat()
}

/// ES10a `GetEuiccConfiguredAddresses`.
pub fn configured_addresses_payload() -> Vec<u8> {
    [TAG_CONFIGURED_ADDRESSES, &[0x00]].concat()
}

/// ES10b `ListNotification` with no filter.
pub fn list_notification_payload() -> Vec<u8> {
    [TAG_LIST_NOTIFICATION, &[0x00]].concat()
}

/// ES10b `RetrieveNotificationsList` with no search criteria.
///
/// No criteria on purpose. Both bench eUICCs answer the `seqNumber` search
/// form (`BF2B 03 80 01 <seq>`) with `BF2B 03 81 01 7F`, undefined error, even
/// for a sequence number their own `ListNotification` had just reported. So
/// retrieving one notification means retrieving all of them and picking.
pub fn retrieve_notifications_payload() -> Vec<u8> {
    [TAG_RETRIEVE_NOTIFICATIONS, &[0x00]].concat()
}

/// `EnableProfile` by ICCID.
///
/// `refresh` asks the card to trigger a REFRESH so the modem re-reads the new
/// profile. Without it the switch does not take effect until the module is
/// restarted, which looks to an operator like the command silently failed.
pub fn enable_profile_payload(iccid: &str, refresh: bool) -> Result<Vec<u8>, Es10cError> {
    profile_command(TAG_ENABLE_PROFILE, iccid, refresh)
}

/// `DisableProfile` by ICCID.
pub fn disable_profile_payload(iccid: &str, refresh: bool) -> Result<Vec<u8>, Es10cError> {
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
    Ok(request)
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

/// Parse an ES10c `GetEUICCData` response into the 32 EID digits.
pub fn parse_eid_response(response: &[u8]) -> Result<String, Es10cError> {
    let body = expect_tag(response, TAG_GET_EUICC_DATA)?;
    let (tag, value, _) = read_tlv(body)?;
    if tag != [TAG_ICCID] {
        // The EID reuses tag 5A. Same tag, different meaning: sixteen BCD
        // bytes in reading order rather than a nibble-swapped ICCID.
        return Err(Es10cError::UnexpectedTag {
            expected: vec![TAG_ICCID],
            actual: tag,
        });
    }
    if value.len() != 16 {
        return Err(Es10cError::Truncated);
    }
    Ok(value
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 0x0f])
        .map(|nibble| char::from_digit(u32::from(nibble), 16).unwrap_or('f'))
        .collect())
}

/// Parse a `GetEUICCInfo2` response.
pub fn parse_euicc_info2(response: &[u8]) -> Result<EuiccInfo2, Es10cError> {
    let mut body = expect_tag(response, TAG_EUICC_INFO2)?;
    let mut info = EuiccInfo2::default();
    while !body.is_empty() {
        let (tag, value, tail) = read_tlv(body)?;
        body = tail;
        match tag.as_slice() {
            [0x81] => info.profile_version = Some(version(value)),
            [0x82] => info.svn = Some(version(value)),
            [0x83] => info.firmware_version = Some(version(value)),
            [0x84] => read_card_resource(value, &mut info)?,
            [0x85] => info.uicc_capabilities = named_bits(value, UICC_CAPABILITIES),
            [0x86] => info.ts102241_version = Some(version(value)),
            [0x87] => info.global_platform_version = Some(version(value)),
            [0x88] => info.rsp_capabilities = named_bits(value, RSP_CAPABILITIES),
            [0xa9] => info.ci_key_ids_for_verification = key_identifiers(value)?,
            [0xaa] => info.ci_key_ids_for_signing = key_identifiers(value)?,
            [0x8b] => info.category = Some(integer(value)?),
            [0x99] => info.forbidden_profile_policy_rules = named_bits(value, PPR_IDS),
            // ppVersion and sasAcreditationNumber carry no context tag: they
            // are the two fields SGP.22 leaves universally tagged.
            [TAG_OCTET_STRING] => info.pp_version = Some(version(value)),
            [TAG_UTF8_STRING] => info.sas_accreditation_number = text(value),
            _ => {}
        }
    }
    if info.svn.is_none() {
        return Err(Es10cError::MissingField { name: "svn" });
    }
    Ok(info)
}

/// Parse a `GetEUICCChallenge` response into the sixteen random bytes.
pub fn parse_euicc_challenge(response: &[u8]) -> Result<[u8; EUICC_CHALLENGE_BYTES], Es10cError> {
    let body = expect_tag(response, TAG_EUICC_CHALLENGE)?;
    let (tag, value, _) = read_tlv(body)?;
    if tag != [0x80] {
        return Err(Es10cError::UnexpectedTag {
            expected: vec![0x80],
            actual: tag,
        });
    }
    value
        .try_into()
        .map_err(|_| Es10cError::ChallengeLength {
            actual: value.len(),
        })
}

/// Parse a `GetEUICCInfo1` response, keeping the encoded form.
///
/// The response is trimmed to exactly the length the `BF20` header declares.
/// A modem that pads its answer would otherwise put those pad bytes into the
/// base64 an SM-DP+ receives, and a server that parses strict DER answers
/// that with a function execution error rather than with anything that names
/// the padding.
pub fn parse_euicc_info1(response: &[u8]) -> Result<EuiccInfo1, Es10cError> {
    let (tag, body, tail) = read_tlv(response)?;
    if tag != TAG_EUICC_INFO1 {
        return Err(Es10cError::UnexpectedTag {
            expected: TAG_EUICC_INFO1.to_vec(),
            actual: tag,
        });
    }
    let mut info = EuiccInfo1 {
        raw: response[..response.len() - tail.len()].to_vec(),
        ..EuiccInfo1::default()
    };
    let mut rest = body;
    while !rest.is_empty() {
        let (tag, value, next) = read_tlv(rest)?;
        rest = next;
        match tag.as_slice() {
            [0x82] => info.svn = Some(version(value)),
            [0xa9] => info.ci_key_ids_for_verification = key_identifiers(value)?,
            [0xaa] => info.ci_key_ids_for_signing = key_identifiers(value)?,
            _ => {}
        }
    }
    if info.svn.is_none() {
        return Err(Es10cError::MissingField { name: "svn" });
    }
    if info.ci_key_ids_for_verification.is_empty() {
        // A chip that lists no CI it will verify against cannot complete a
        // download at all, so this is a refusal rather than a blank field.
        return Err(Es10cError::MissingField {
            name: "euiccCiPKIdListForVerification",
        });
    }
    Ok(info)
}

/// Parse a `GetEuiccConfiguredAddresses` response.
pub fn parse_configured_addresses(response: &[u8]) -> Result<ConfiguredAddresses, Es10cError> {
    let mut body = expect_tag(response, TAG_CONFIGURED_ADDRESSES)?;
    let mut addresses = ConfiguredAddresses::default();
    while !body.is_empty() {
        let (tag, value, tail) = read_tlv(body)?;
        body = tail;
        match tag.as_slice() {
            [0x80] => addresses.default_dp_address = text(value),
            [0x81] => addresses.root_ds_address = text(value),
            _ => {}
        }
    }
    Ok(addresses)
}

/// Parse a `ListNotification` response.
pub fn parse_notification_metadata_list(
    response: &[u8],
) -> Result<Vec<NotificationMetadata>, Es10cError> {
    let body = expect_tag(response, TAG_LIST_NOTIFICATION)?;
    let mut list = notification_list(body)?;
    let mut out = Vec::new();
    while !list.is_empty() {
        let (tag, value, tail) = read_tlv(list)?;
        list = tail;
        if tag != TAG_NOTIFICATION_METADATA {
            continue;
        }
        out.push(parse_notification_metadata(value)?);
    }
    Ok(out)
}

/// Parse a `RetrieveNotificationsList` response.
pub fn parse_pending_notifications(
    response: &[u8],
) -> Result<Vec<PendingNotification>, Es10cError> {
    let body = expect_tag(response, TAG_RETRIEVE_NOTIFICATIONS)?;
    let mut list = notification_list(body)?;
    let mut out = Vec::new();
    while !list.is_empty() {
        let (tag, value, tail) = read_tlv(list)?;
        let entry = &list[..list.len() - tail.len()];
        list = tail;
        let (metadata, installation_result) = if tag == TAG_INSTALLATION_RESULT {
            let data = expect_tag(value, TAG_INSTALLATION_RESULT_DATA)?;
            (find_notification_metadata(data)?, true)
        } else if tag == [TAG_SEQUENCE] {
            (find_notification_metadata(value)?, false)
        } else {
            continue;
        };
        out.push(PendingNotification {
            metadata,
            installation_result,
            payload: entry.to_vec(),
        });
    }
    Ok(out)
}

/// The `[0]` list, or the `[1]` error code the card sends instead of one.
fn notification_list(body: &[u8]) -> Result<&[u8], Es10cError> {
    let (tag, value, _) = read_tlv(body)?;
    match tag.as_slice() {
        [TAG_NOTIFICATION_LIST] => Ok(value),
        [TAG_NOTIFICATION_ERROR] => Err(Es10cError::NotificationsUnavailable {
            code: integer(value)?,
        }),
        _ => Err(Es10cError::UnexpectedTag {
            expected: vec![TAG_NOTIFICATION_LIST],
            actual: tag,
        }),
    }
}

fn find_notification_metadata(mut body: &[u8]) -> Result<NotificationMetadata, Es10cError> {
    while !body.is_empty() {
        let (tag, value, tail) = read_tlv(body)?;
        body = tail;
        if tag == TAG_NOTIFICATION_METADATA {
            return parse_notification_metadata(value);
        }
    }
    Err(Es10cError::MissingField {
        name: "notificationMetadata",
    })
}

fn parse_notification_metadata(mut body: &[u8]) -> Result<NotificationMetadata, Es10cError> {
    let mut metadata = NotificationMetadata::default();
    let mut has_sequence = false;
    while !body.is_empty() {
        let (tag, value, tail) = read_tlv(body)?;
        body = tail;
        match tag.as_slice() {
            [0x80] => {
                metadata.sequence_number = integer(value)?;
                has_sequence = true;
            }
            [0x81] => metadata.operations = named_bits(value, NOTIFICATION_EVENTS),
            [TAG_UTF8_STRING] => {
                metadata.address = String::from_utf8_lossy(value).trim().to_string();
            }
            [TAG_ICCID] => metadata.iccid = decode_iccid(value).ok(),
            _ => {}
        }
    }
    if !has_sequence {
        return Err(Es10cError::MissingField { name: "seqNumber" });
    }
    if metadata.address.is_empty() {
        return Err(Es10cError::MissingField {
            name: "notificationAddress",
        });
    }
    Ok(metadata)
}

/// ETSI TS 102 226 `extendedCardResource`, carried as an OCTET STRING.
fn read_card_resource(value: &[u8], info: &mut EuiccInfo2) -> Result<(), Es10cError> {
    let mut rest = value;
    while !rest.is_empty() {
        let (tag, inner, tail) = read_tlv(rest)?;
        rest = tail;
        match tag.as_slice() {
            [0x81] => info.installed_applications = Some(integer(inner)?),
            [0x82] => info.free_non_volatile_memory = Some(integer(inner)?),
            [0x83] => info.free_volatile_memory = Some(integer(inner)?),
            _ => {}
        }
    }
    Ok(())
}

fn key_identifiers(value: &[u8]) -> Result<Vec<String>, Es10cError> {
    let mut out = Vec::new();
    let mut rest = value;
    while !rest.is_empty() {
        let (tag, inner, tail) = read_tlv(rest)?;
        rest = tail;
        if tag == [TAG_OCTET_STRING] {
            out.push(hex(inner).to_uppercase());
        }
    }
    Ok(out)
}

/// Decode a BER BIT STRING into the names of the bits that are set.
///
/// The first byte counts the unused trailing bits, and bit zero is the most
/// significant bit of the byte after it. Reading it the other way round turns
/// `install` into `delete`, which is the difference between a notification
/// saying a profile arrived and one saying it was removed.
fn named_bits(value: &[u8], names: &[&str]) -> Vec<String> {
    let Some((unused, bytes)) = value.split_first() else {
        return Vec::new();
    };
    let significant = (bytes.len() * 8).saturating_sub(usize::from(*unused));
    (0..significant)
        .filter(|bit| bytes[bit / 8] & (0x80 >> (bit % 8)) != 0)
        .map(|bit| match names.get(bit) {
            Some(name) => (*name).to_string(),
            None => format!("bit{bit}"),
        })
        .collect()
}

/// `VersionType` is three bytes of major, minor and patch.
fn version(value: &[u8]) -> String {
    value
        .iter()
        .map(|byte| byte.to_string())
        .collect::<Vec<_>>()
        .join(".")
}

fn integer(value: &[u8]) -> Result<u64, Es10cError> {
    if value.is_empty() || value.len() > 8 {
        return Err(Es10cError::Truncated);
    }
    Ok(value
        .iter()
        .fold(0u64, |accumulator, byte| (accumulator << 8) | u64::from(*byte)))
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
    fn get_profiles_is_one_store_data_block() {
        let chain = store_data_chain(&get_profiles_payload()).expect("chain");
        assert_eq!(chain, vec![bytes("80E2910003BF2D00")]);
    }

    #[test]
    fn enable_wraps_the_iccid_and_refresh_flag() {
        let payload = enable_profile_payload("89852351225042214201", true).expect("payload");
        let chain = store_data_chain(&payload).expect("chain");
        // STORE DATA Lc 0x14, BF31 body 0x11: A0 0C (5A 0A <10 bytes>) 81 01 FF.
        assert_eq!(
            chain,
            vec![bytes("80E2910014 BF3111 A00C 5A0A 98583215220524122410 8101FF")]
        );
    }

    #[test]
    fn disable_uses_its_own_tag() {
        let payload = disable_profile_payload("89852351225042214201", false).expect("payload");
        assert_eq!(&payload[..2], &[0xbf, 0x32]);
        assert_eq!(payload[payload.len() - 1], 0x00);
    }

    /// A 19-digit ICCID is padded, not truncated: the card matches on the full
    /// ten-byte field, and the odd digit leaves an `f` in the high nibble.
    #[test]
    fn odd_length_iccid_is_padded() {
        let payload = enable_profile_payload("8985200014632179571", true).expect("payload");
        // BF31 tag/len 3 + A0 len 2 + 5A len 2 = 7.
        let iccid = &payload[7..17];
        assert_eq!(iccid.len(), 10);
        assert_eq!(iccid[9], 0xf1);
    }

    #[test]
    fn non_numeric_iccid_is_rejected() {
        assert_eq!(
            enable_profile_payload("89ab", true),
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

    // ---- STORE DATA chaining -------------------------------------------
    //
    // The three cases below are the ones the old `payload.len() as u8` got
    // wrong. It produced a single APDU whatever the length was, so at 256
    // bytes Lc wrapped to 0 and at 300 bytes it wrapped to 44 while all 300
    // bytes were still appended. The card then read 44 bytes of BER-TLV and
    // the rest as the next command.

    fn filler(length: usize) -> Vec<u8> {
        (0..length).map(|index| (index % 251) as u8).collect()
    }

    #[test]
    fn a_full_block_is_still_one_apdu() {
        let chain = store_data_chain(&filler(STORE_DATA_BLOCK_BYTES)).expect("chain");
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0][..5], [0x80, 0xe2, 0x91, 0x00, 0xff]);
        assert_eq!(chain[0].len(), 5 + 255);
    }

    /// One byte past a block is where the cast used to wrap Lc to zero.
    #[test]
    fn two_hundred_and_fifty_six_bytes_become_two_blocks() {
        let payload = filler(256);
        let chain = store_data_chain(&payload).expect("chain");
        assert_eq!(chain.len(), 2);
        // First block: not last, block zero, full length.
        assert_eq!(chain[0][..5], [0x80, 0xe2, P1_MORE_BLOCKS, 0x00, 0xff]);
        // Last block: one byte, block one.
        assert_eq!(chain[1][..5], [0x80, 0xe2, P1_LAST_BLOCK, 0x01, 0x01]);
        assert_eq!(chain[1][5], payload[255]);
    }

    /// Every byte handed in has to reach the card exactly once, and every
    /// block has to declare the length it actually carries.
    #[test]
    fn a_three_hundred_byte_payload_survives_the_chain() {
        let payload = filler(300);
        let chain = store_data_chain(&payload).expect("chain");
        let mut rebuilt = Vec::new();
        for (index, apdu) in chain.iter().enumerate() {
            assert_eq!(apdu[3], index as u8, "block number");
            assert_eq!(
                usize::from(apdu[4]),
                apdu.len() - 5,
                "Lc must match the block it carries"
            );
            rebuilt.extend_from_slice(&apdu[5..]);
        }
        assert_eq!(rebuilt, payload);
        assert_eq!(chain[chain.len() - 1][2], P1_LAST_BLOCK);
    }

    #[test]
    fn the_longest_chain_is_two_hundred_and_fifty_six_blocks() {
        let chain = store_data_chain(&filler(MAX_STORE_DATA_BYTES)).expect("chain");
        assert_eq!(chain.len(), MAX_STORE_DATA_BLOCKS);
        assert_eq!(chain[MAX_STORE_DATA_BLOCKS - 1][3], 0xff);
        assert_eq!(chain[MAX_STORE_DATA_BLOCKS - 1][2], P1_LAST_BLOCK);
    }

    /// Past the chain limit there is no correct APDU, so this is an error and
    /// not a wrap. A silently wrapped block number sends the card the same
    /// block twice.
    #[test]
    fn a_payload_too_long_to_chain_is_refused() {
        assert_eq!(
            store_data_chain(&filler(MAX_STORE_DATA_BYTES + 1)),
            Err(Es10cError::PayloadTooLarge {
                actual: MAX_STORE_DATA_BYTES + 1,
                max: MAX_STORE_DATA_BYTES,
            })
        );
    }

    #[test]
    fn an_empty_payload_is_refused() {
        assert_eq!(store_data_chain(&[]), Err(Es10cError::EmptyPayload));
    }

    // ---- ES10b, from the two eUICCs on the bench -----------------------
    //
    // Every constant below was read off a card with AT+CGLA on the ISD-R
    // channel before any of this was written. Guessing the layout from the
    // specification is how five earlier parsers in this project ended up
    // wrong.

    /// 867018069514820, the Saily/WEBBING chip.
    const EID_RESPONSE_SAILY: &str = "BF3E125A1089086030202200000026000178339240";
    /// 862547055142811, the CSL chip.
    const EID_RESPONSE_CSL: &str = "BF3E125A1089086030202200000026000178340695";

    const INFO2_SAILY: &str = "BF227E81030203018203020202830304020084 0D 8101008204000279D083020B\
                               89 8505077F3E1F808603090200870302030088020490A916041481370F5125D0B1\
                               D408D4C3B232E6D25E795BEBFBAA16041481370F5125D0B1D408D4C3B232E6D25E79\
                               5BEBFB8B01009902064004030100000C0D45442D5A492D55502D30383236";

    const INFO2_CSL: &str = "BF227E81030203018203020202830304020084 0D 8101008204000253C983020F\
                             FA 8505077F3E1F808603090200870302030088020490A916041481370F5125D0B1\
                             D408D4C3B232E6D25E795BEBFBAA16041481370F5125D0B1D408D4C3B232E6D25E79\
                             5BEBFB8B01009902064004030100000C0D45442D5A492D55502D30383236";

    /// Four pending notifications: install, delete, install, enable.
    const NOTIFICATIONS_SAILY: &str = "BF2881E7A081E4\
        BF2F36800100810207800C217762672E70726F642E6F6E64656D616E64636F6E6E65637469766974792E636F6D\
        5A0A98583215220524122410\
        BF2F36800101810204100C217762672E70726F642E6F6E64656D616E64636F6E6E65637469766974792E636F6D\
        5A0A98583215220524122410\
        BF2F36800102810207800C217762672E70726F642E6F6E64656D616E64636F6E6E65637469766974792E636F6D\
        5A0A98583215220524122410\
        BF2F36800103810206400C217762672E70726F642E6F6E64656D616E64636F6E6E65637469766974792E636F6D\
        5A0A98583215220524122410";

    /// One pending notification on the CSL chip.
    const NOTIFICATIONS_CSL: &str = "BF283BA039BF2F36800100810207800C2163736C2E70726F642E6F6E6465\
                                     6D616E64636F6E6E65637469766974792E636F6D5A0A985802004136129775F1";

    /// What both chips answer to a `seqNumber` search, for a sequence number
    /// they had just listed.
    const RETRIEVE_REFUSED: &str = "BF2B0381017F";

    #[test]
    fn the_eid_comes_back_as_thirty_two_digits() {
        assert_eq!(
            parse_eid_response(&bytes(EID_RESPONSE_SAILY)).expect("eid"),
            "89086030202200000026000178339240"
        );
        assert_eq!(
            parse_eid_response(&bytes(EID_RESPONSE_CSL)).expect("eid"),
            "89086030202200000026000178340695"
        );
    }

    /// The whole answer, field by field. This is the response a single-round
    /// GET RESPONSE truncates, and a test that only asserted "no error" would
    /// pass on the truncated half of it.
    #[test]
    fn euicc_info2_decodes_every_field() {
        let info = parse_euicc_info2(&bytes(&clean(INFO2_SAILY))).expect("info2");
        assert_eq!(info.profile_version.as_deref(), Some("2.3.1"));
        assert_eq!(info.svn.as_deref(), Some("2.2.2"));
        assert_eq!(info.firmware_version.as_deref(), Some("4.2.0"));
        assert_eq!(info.installed_applications, Some(0));
        assert_eq!(info.free_non_volatile_memory, Some(162_256));
        assert_eq!(info.free_volatile_memory, Some(2_953));
        assert_eq!(info.ts102241_version.as_deref(), Some("9.2.0"));
        assert_eq!(info.global_platform_version.as_deref(), Some("2.3.0"));
        assert_eq!(info.category, Some(0));
        assert_eq!(info.pp_version.as_deref(), Some("1.0.0"));
        assert_eq!(
            info.sas_accreditation_number.as_deref(),
            Some("ED-ZI-UP-0826")
        );
        assert_eq!(
            info.rsp_capabilities,
            vec!["additionalProfile", "testProfileSupport"]
        );
        assert_eq!(info.forbidden_profile_policy_rules, vec!["ppr1"]);
        assert_eq!(
            info.ci_key_ids_for_verification,
            vec!["81370F5125D0B1D408D4C3B232E6D25E795BEBFB"]
        );
        assert_eq!(
            info.ci_key_ids_for_signing,
            vec!["81370F5125D0B1D408D4C3B232E6D25E795BEBFB"]
        );
        assert_eq!(
            info.uicc_capabilities,
            vec![
                "usimSupport",
                "isimSupport",
                "csimSupport",
                "akaMilenage",
                "akaCave",
                "akaTuak128",
                "akaTuak256",
                "gbaAuthenUsim",
                "gbaAuthenISim",
                "mbmsAuthenUsim",
                "eapClient",
                "javacard",
                "berTlvFileSupport",
                "dfLinkSupport",
                "catTp",
                "getIdentity",
                "profile-a-x25519",
                "profile-b-p256",
            ]
        );
        assert_eq!(info.populated_fields(), 16);
    }

    /// The second chip differs only in how much memory is left, which is the
    /// field an operator about to download a profile is looking for.
    #[test]
    fn the_other_chip_reports_its_own_free_memory() {
        let info = parse_euicc_info2(&bytes(&clean(INFO2_CSL))).expect("info2");
        assert_eq!(info.free_non_volatile_memory, Some(152_521));
        assert_eq!(info.free_volatile_memory, Some(4_090));
        assert_eq!(info.populated_fields(), 16);
    }

    /// Half a response is not a small answer, it is a wrong one.
    #[test]
    fn a_truncated_euicc_info2_is_an_error_not_a_thin_result() {
        let full = bytes(&clean(INFO2_SAILY));
        assert!(parse_euicc_info2(&full[..60]).is_err());
    }

    #[test]
    fn the_notification_list_decodes_with_its_operations() {
        let list =
            parse_notification_metadata_list(&bytes(&clean(NOTIFICATIONS_SAILY))).expect("list");
        assert_eq!(list.len(), 4);
        assert_eq!(
            list.iter().map(|row| row.sequence_number).collect::<Vec<_>>(),
            vec![0, 1, 2, 3]
        );
        assert_eq!(
            list.iter()
                .map(|row| row.operations.join("+"))
                .collect::<Vec<_>>(),
            vec!["install", "delete", "install", "enable"]
        );
        assert!(list
            .iter()
            .all(|row| row.address == "wbg.prod.ondemandconnectivity.com"));
        assert_eq!(list[0].iccid.as_deref(), Some("89852351225042214201"));
    }

    #[test]
    fn the_other_chip_has_one_notification_of_its_own() {
        let list =
            parse_notification_metadata_list(&bytes(&clean(NOTIFICATIONS_CSL))).expect("list");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].sequence_number, 0);
        assert_eq!(list[0].address, "csl.prod.ondemandconnectivity.com");
        assert_eq!(list[0].iccid.as_deref(), Some("8985200014632179571"));
    }

    /// The card refusing a search is a reported error, not an empty list. An
    /// empty list would read as "nothing pending" and be wrong.
    #[test]
    fn a_refused_search_is_not_an_empty_list() {
        assert_eq!(
            parse_pending_notifications(&bytes(RETRIEVE_REFUSED)),
            Err(Es10cError::NotificationsUnavailable { code: 127 })
        );
    }

    /// The whole pending notification list off 867018069514820: 3333 bytes,
    /// which the card hands over in fifteen `61xx` rounds. Captured verbatim.
    const PENDING_SAILY: &str = "BF2B820D00A0820CFCBF3781C2BF277C8010F2E53202F2314318B9D0EBD1D11EF87EBF2F36800100810207800C217762\
        672E70726F642E6F6E64656D616E64636F6E6E65637469766974792E636F6D5A0A98583215220524122410060E2B0601\
        040181F80201815C646502A21FA01D4F10A0000005591010FFFFFFFF890000120004093007A00530038001005F37402F\
        1D7FC2943917ECBD4C49E10161AB3E9490E53A6D247231BE974AF2E12068F25A9EDDEE897A744635BD27D1E195932C92\
        10669BB4E179706A0E3F0B4636DA94308205B4BF2F36800101810204100C217762672E70726F642E6F6E64656D616E64\
        636F6E6E65637469766974792E636F6D5A0A985832152205241224105F3740A0622EE3E090975C91D0B3A5F2605350B2\
        448B375A5B0F4D3476689C28F6D38D065B1113FC6759C4A9DC8CBC22F357496BF2C89BB7FEC6208BF2BF2C13C1E4FF30\
        820239308201E0A00302010202110089086030202200000026000178339201300A06082A8648CE3D0403023079310B30\
        0906035504061302434E31283026060355040A131F45617374636F6D706561636520546563686E6F6C6F677920436F2E\
        2C4C746431153013060355040B130C45617374636F6D7065616365312930270603550403132045617374636F6D706561\
        63652E45554D2E436F6E73756D65722E5A68756861693020170D3236303631333032353835305A180F39393939313233\
        313233353935395A305531283026060355040A131F45617374636F6D706561636520546563686E6F6C6F677920436F2E\
        2C4C74643129302706035504051320383930383630333032303232303030303030323630303031373833333932343030\
        59301306072A8648CE3D020106082A8648CE3D030107034200049D9BFE5A4A1E21F2EFE6525C7B36217C81F38216AD51\
        8B96584FFCB6940E0E461B15668B04363C8C4ECBD470D7FA283BC3A22EE1715969F9348D029946DA2958A36B3069301F\
        0603551D230418301680143A6B2CA4585D9C95C5947ABDD3BB1B0169ACEF72301D0603551D0E0416041499B0EB0F926C\
        0835A94EA4F7987D989DD3611617300E0603551D0F0101FF04040302078030170603551D200101FF040D300B30090607\
        67811201020101300A06082A8648CE3D04030203470030440220170673F6215275E7F1D2829B72567D3607D427B651BF\
        CE6D718F84D8725C247A02204A6DEA07F07F346D3972ADEB730268F2C01DBF2984BE8DAD1CC47682064C468C308202F7\
        3082029EA00302010202105986939CF376FDD1013E8F1529307748300A06082A8648CE3D040302304431183016060355\
        040A130F47534D204173736F63696174696F6E312830260603550403131F47534D204173736F63696174696F6E202D20\
        5253503220526F6F7420434931301E170D3139313132313030303030305A170D3439313132303233353935395A307931\
        0B300906035504061302434E31283026060355040A131F45617374636F6D706561636520546563686E6F6C6F67792043\
        6F2E2C4C746431153013060355040B130C45617374636F6D7065616365312930270603550403132045617374636F6D70\
        656163652E45554D2E436F6E73756D65722E5A68756861693059301306072A8648CE3D020106082A8648CE3D03010703\
        4200042FB0E6C5292E90321B0F1C69E88D5C3CF8C0E5F79E5C6F2C588552A74AB894AA0B4414B349F4616CDDE9629DCA\
        F955B7C39712EEAF46101AF686D44F8B2DFC07A382013B30820137301D0603551D0E041604143A6B2CA4585D9C95C594\
        7ABDD3BB1B0169ACEF7230120603551D130101FF040830060101FF02010030170603551D200101FF040D300B30090607\
        67811201020102304D0603551D1F044630443042A040A03E863C687474703A2F2F67736D612D63726C2E73796D617574\
        682E636F6D2F6F66666C696E6563612F67736D612D727370322D726F6F742D6369312E63726C300E0603551D0F0101FF\
        04040302010630510603551D1E0101FF04473045A0433041A43F303D31283026060355040A131F45617374636F6D7065\
        61636520546563686E6F6C6F677920436F2E2C4C74643111300F06035504051308383930383630333030160603551D11\
        040F300D880B2B06010401838A1D010202301F0603551D2304183016801481370F5125D0B1D408D4C3B232E6D25E795B\
        EBFB300A06082A8648CE3D040302034700304402203C5FD987D7CABB5172489647A8563016BE05DE44B06CE285A2D679\
        0BCDF408CA02202272886D929FC9434153068C8BE3521BC371E9101A18A56E9BAA7DD936592A1EBF3781C2BF277C8010\
        7F8AEDA1660948A98CCD5E819455C192BF2F36800102810207800C217762672E70726F642E6F6E64656D616E64636F6E\
        6E65637469766974792E636F6D5A0A98583215220524122410060E2B0601040181F80201815C646502A21FA01D4F10A0\
        000005591010FFFFFFFF890000120004093007A00530038001005F37408FF2164785CEB8FE92AAAB080FECE43ECA9A21\
        2C862CD6F943527CDBB7322BC6C04107FB78E21B7823D6DFD94CFAC61865899E169CCBAFD8D49D237C13CA266D308205\
        B4BF2F36800103810206400C217762672E70726F642E6F6E64656D616E64636F6E6E65637469766974792E636F6D5A0A\
        985832152205241224105F3740DD508DB2942F3340ED121BD3B3AF4FE28303A56CBE40B19D8BB5453E9991CB56E7A12C\
        D6BC48677BF25C05B9051010E70F19D8B2B0E3077B1B55D47A749B8D0830820239308201E0A003020102021100890860\
        30202200000026000178339201300A06082A8648CE3D0403023079310B300906035504061302434E3128302606035504\
        0A131F45617374636F6D706561636520546563686E6F6C6F677920436F2E2C4C746431153013060355040B130C456173\
        74636F6D7065616365312930270603550403132045617374636F6D70656163652E45554D2E436F6E73756D65722E5A68\
        756861693020170D3236303631333032353835305A180F39393939313233313233353935395A30553128302606035504\
        0A131F45617374636F6D706561636520546563686E6F6C6F677920436F2E2C4C74643129302706035504051320383930\
        38363033303230323230303030303032363030303137383333393234303059301306072A8648CE3D020106082A8648CE\
        3D030107034200049D9BFE5A4A1E21F2EFE6525C7B36217C81F38216AD518B96584FFCB6940E0E461B15668B04363C8C\
        4ECBD470D7FA283BC3A22EE1715969F9348D029946DA2958A36B3069301F0603551D230418301680143A6B2CA4585D9C\
        95C5947ABDD3BB1B0169ACEF72301D0603551D0E0416041499B0EB0F926C0835A94EA4F7987D989DD3611617300E0603\
        551D0F0101FF04040302078030170603551D200101FF040D300B3009060767811201020101300A06082A8648CE3D0403\
        0203470030440220170673F6215275E7F1D2829B72567D3607D427B651BFCE6D718F84D8725C247A02204A6DEA07F07F\
        346D3972ADEB730268F2C01DBF2984BE8DAD1CC47682064C468C308202F73082029EA00302010202105986939CF376FD\
        D1013E8F1529307748300A06082A8648CE3D040302304431183016060355040A130F47534D204173736F63696174696F\
        6E312830260603550403131F47534D204173736F63696174696F6E202D205253503220526F6F7420434931301E170D31\
        39313132313030303030305A170D3439313132303233353935395A3079310B300906035504061302434E312830260603\
        55040A131F45617374636F6D706561636520546563686E6F6C6F677920436F2E2C4C746431153013060355040B130C45\
        617374636F6D7065616365312930270603550403132045617374636F6D70656163652E45554D2E436F6E73756D65722E\
        5A68756861693059301306072A8648CE3D020106082A8648CE3D030107034200042FB0E6C5292E90321B0F1C69E88D5C\
        3CF8C0E5F79E5C6F2C588552A74AB894AA0B4414B349F4616CDDE9629DCAF955B7C39712EEAF46101AF686D44F8B2DFC\
        07A382013B30820137301D0603551D0E041604143A6B2CA4585D9C95C5947ABDD3BB1B0169ACEF7230120603551D1301\
        01FF040830060101FF02010030170603551D200101FF040D300B3009060767811201020102304D0603551D1F04463044\
        3042A040A03E863C687474703A2F2F67736D612D63726C2E73796D617574682E636F6D2F6F66666C696E6563612F6773\
        6D612D727370322D726F6F742D6369312E63726C300E0603551D0F0101FF04040302010630510603551D1E0101FF0447\
        3045A0433041A43F303D31283026060355040A131F45617374636F6D706561636520546563686E6F6C6F677920436F2E\
        2C4C74643111300F06035504051308383930383630333030160603551D11040F300D880B2B06010401838A1D01020230\
        1F0603551D2304183016801481370F5125D0B1D408D4C3B232E6D25E795BEBFB300A06082A8648CE3D04030203470030\
        4402203C5FD987D7CABB5172489647A8563016BE05DE44B06CE285A2D6790BCDF408CA02202272886D929FC943415306\
        8C8BE3521BC371E9101A18A56E9BAA7DD936592A1E";

    /// Both shapes in one list: two `ProfileInstallationResult` entries and
    /// two `OtherSignedNotification` entries, which are a tagged structure and
    /// a plain SEQUENCE respectively.
    #[test]
    fn pending_notifications_carry_their_signed_payloads() {
        let raw = bytes(PENDING_SAILY);
        let pending = parse_pending_notifications(&raw).expect("pending");
        assert_eq!(pending.len(), 4);
        assert_eq!(
            pending
                .iter()
                .map(|entry| entry.metadata.sequence_number)
                .collect::<Vec<_>>(),
            vec![0, 1, 2, 3]
        );
        assert_eq!(
            pending
                .iter()
                .map(|entry| entry.installation_result)
                .collect::<Vec<_>>(),
            vec![true, false, true, false]
        );
        assert_eq!(
            pending
                .iter()
                .map(|entry| entry.metadata.operations.join("+"))
                .collect::<Vec<_>>(),
            vec!["install", "delete", "install", "enable"]
        );
        // The payload is what ES9+ has to receive, so it has to be the entry
        // verbatim, tag included, and not a re-encoding of the parts.
        for entry in &pending {
            assert!(entry.payload.len() > 100, "payload is the signed structure");
            let needle: Vec<u8> = entry.payload.clone();
            assert!(
                raw.windows(needle.len()).any(|window| window == needle),
                "payload must be a slice of what the card sent"
            );
        }
        assert!(pending[0].payload.starts_with(&[0xbf, 0x37]));
        assert!(pending[1].payload.starts_with(&[0x30]));
    }
}
