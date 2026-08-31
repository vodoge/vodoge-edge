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
/// `SetNicknameRequest ::= [41]`, SGP.22 5.7.21.
const TAG_SET_NICKNAME: &[u8] = &[0xbf, 0x29];
/// `DeleteProfileRequest ::= [51]`, SGP.22 5.7.18.
const TAG_DELETE_PROFILE: &[u8] = &[0xbf, 0x33];
/// The longest nickname SGP.22 admits.
const NICKNAME_MAX_BYTES: usize = 64;
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
    /// SGP.22 caps `profileNickname` at 64 bytes. Refused here rather than
    /// truncated: a name silently cut in half is one nobody can search for.
    NicknameTooLong { bytes: usize },
    /// `GetEUICCChallenge` returned something other than sixteen bytes.
    ///
    /// Its own error rather than `Truncated`: the challenge is what binds an
    /// ES9+ session to this chip, and a short one would be handed to an
    /// SM-DP+ and echoed back looking perfectly valid.
    ChallengeLength { actual: usize },
    /// The eUICC would not authenticate the SM-DP+.
    ///
    /// Separate from `Refused` because this is the card judging a *server*,
    /// not the card judging a request, and the two failures need different
    /// answers: one means retry somewhere else, the other means fix the LPA.
    AuthenticationRefused { code: u64, reason: &'static str },
    /// The eUICC would not prepare the download.
    DownloadRefused { code: u64, reason: &'static str },
    /// `CancelSession` came back as an error, so an RSP session is still open
    /// on the chip. Reported rather than swallowed: the next download will
    /// fail with something that does not mention this one.
    SessionNotCancelled,
    /// An IMEI that is not fifteen or sixteen digits has no type allocation
    /// code to take, and inventing one would put a false device identity in
    /// front of an operator.
    InvalidImei,
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
            Self::NicknameTooLong { bytes } => write!(
                formatter,
                "nickname is {bytes} bytes; SGP.22 allows {NICKNAME_MAX_BYTES}"
            ),
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
            Self::AuthenticationRefused { code, reason } => write!(
                formatter,
                "eUICC refused to authenticate the SM-DP+: {reason} ({code})"
            ),
            Self::DownloadRefused { code, reason } => write!(
                formatter,
                "eUICC refused to prepare the download: {reason} ({code})"
            ),
            Self::SessionNotCancelled => {
                formatter.write_str("eUICC refused to cancel the RSP session")
            }
            Self::InvalidImei => {
                formatter.write_str("IMEI is not a digit string long enough to carry a TAC")
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

/// `SetNickname` by ICCID.
///
/// 🔴 **The field is always sent, even empty, and that is a measurement rather
/// than a reading of the specification.** SGP.22 makes `profileNickname`
/// OPTIONAL, so omitting it is the obvious way to clear a name, and this
/// function did that until 2026-08-31 -- when the bench eUICC
/// (EID 89086030202200000026000178339240) answered a request with no
/// `profileNickname` with `undefined error (127)`. A zero-length UTF8String is
/// what it accepts.
///
/// The concern that led to the first shape still stands in principle: a card
/// is free to store an empty name and report it back as one that renders as
/// nothing. It is a smaller problem than a clear that does not work at all,
/// and the one card that has spoken on the subject has settled it.
pub fn set_nickname_payload(iccid: &str, nickname: &str) -> Result<Vec<u8>, Es10cError> {
    let iccid = encode_iccid(iccid)?;
    let nickname = nickname.trim();
    if nickname.len() > NICKNAME_MAX_BYTES {
        return Err(Es10cError::NicknameTooLong {
            bytes: nickname.len(),
        });
    }
    let mut body = vec![TAG_ICCID, iccid.len() as u8];
    body.extend_from_slice(&iccid);
    body.push(TAG_NICKNAME);
    body.push(nickname.len() as u8);
    body.extend_from_slice(nickname.as_bytes());
    let mut request = TAG_SET_NICKNAME.to_vec();
    request.push(body.len() as u8);
    request.extend_from_slice(&body);
    Ok(request)
}

/// `DeleteProfile` by ICCID.
///
/// 🔴 The body is the ICCID directly, NOT wrapped in the `a0` list that
/// `EnableProfile` and `DisableProfile` use. `DeleteProfileRequest` is a
/// CHOICE rather than a SEQUENCE in SGP.22, and a request built like its two
/// neighbours is rejected by the card -- or worse, understood as something
/// else. This asymmetry is the whole reason this is not `profile_command`.
///
/// Irreversible: a deleted profile cannot be restored from the card, and a
/// paid one generally cannot be re-downloaded without the operator issuing a
/// new activation code.
pub fn delete_profile_payload(iccid: &str) -> Result<Vec<u8>, Es10cError> {
    let iccid = encode_iccid(iccid)?;
    let mut body = vec![TAG_ICCID, iccid.len() as u8];
    body.extend_from_slice(&iccid);
    let mut request = TAG_DELETE_PROFILE.to_vec();
    request.push(body.len() as u8);
    request.extend_from_slice(&body);
    Ok(request)
}

/// Parse a `SetNickname` response.
pub fn parse_set_nickname_result(response: &[u8]) -> Result<(), Es10cError> {
    parse_simple_result(response, TAG_SET_NICKNAME, nickname_refusal)
}

/// Parse a `DeleteProfile` response.
pub fn parse_delete_result(response: &[u8]) -> Result<(), Es10cError> {
    parse_simple_result(response, TAG_DELETE_PROFILE, delete_refusal)
}

fn parse_simple_result(
    response: &[u8],
    tag: &[u8],
    reason: fn(u8) -> &'static str,
) -> Result<(), Es10cError> {
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
            reason: reason(code),
        }),
    }
}

fn nickname_refusal(code: u8) -> &'static str {
    match code {
        1 => "ICCID or AID not found",
        _ => "undefined error",
    }
}

fn delete_refusal(code: u8) -> &'static str {
    match code {
        1 => "ICCID or AID not found",
        // The common one, and the one worth naming: a card refuses to delete
        // the profile it is currently running on.
        2 => "profile is not in the disabled state",
        3 => "disallowed by policy",
        _ => "undefined error",
    }
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

// ---------------------------------------------------------------------------
// The download half of ES10b, plus the ES8+ metadata that decides whether a
// download is allowed to happen at all.
//
// Everything above this line reads a card. Everything below it is what a
// profile installation needs, and one of those steps is irreversible: once a
// Bound Profile Package is loaded the profile is on the chip, and a Profile
// Policy Rule that came with it is on the chip permanently. So the metadata is
// decoded *before* anything is loaded, and `ppr1`/`ppr2` are named rather than
// counted.
// ---------------------------------------------------------------------------

/// ES10b `AuthenticateServer`.
const TAG_AUTHENTICATE_SERVER: &[u8] = &[0xbf, 0x38];
/// ES10b `PrepareDownload`.
const TAG_PREPARE_DOWNLOAD: &[u8] = &[0xbf, 0x21];
/// ES10b `LoadBoundProfilePackage` carries a `BoundProfilePackage`.
const TAG_BOUND_PROFILE_PACKAGE: &[u8] = &[0xbf, 0x36];
/// `InitialiseSecureChannelRequest`, the first element inside a BPP.
const TAG_INITIALISE_SECURE_CHANNEL: &[u8] = &[0xbf, 0x23];
/// ES10b `RemoveNotificationFromList`.
const TAG_NOTIFICATION_SENT: &[u8] = &[0xbf, 0x30];
/// ES10b `CancelSession`.
const TAG_CANCEL_SESSION: &[u8] = &[0xbf, 0x41];
/// ES8+ `StoreMetadataRequest`, which an SM-DP+ hands over as `profileMetadata`
/// before any of the profile itself is released.
const TAG_STORE_METADATA: &[u8] = &[0xbf, 0x25];
/// `profilePolicyRules` inside `StoreMetadataRequest`.
const TAG_PROFILE_POLICY_RULES: u8 = 0x99;
/// The `[0]` alternative of a CHOICE: the success case in every ES10b response
/// below.
const TAG_CHOICE_OK: u8 = 0xa0;
/// The `[1]` alternative: the error case.
const TAG_CHOICE_ERROR: u8 = 0xa1;
/// `finalResult` inside `ProfileInstallationResultData`.
const TAG_FINAL_RESULT: u8 = 0xa2;

/// SGP.22 `CancelSessionReason`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancelSessionReason {
    EndUserRejection = 0,
    Postponed = 1,
    Timeout = 2,
    /// The profile arrived carrying a Profile Policy Rule this device will not
    /// install. The one reason code that exists so an LPA can walk away
    /// *before* the package is released.
    PprNotAllowed = 3,
    MetadataMismatch = 4,
    LoadBppExecutionError = 5,
    UndefinedReason = 16,
}

impl CancelSessionReason {
    pub fn label(self) -> &'static str {
        match self {
            Self::EndUserRejection => "endUserRejection",
            Self::Postponed => "postponed",
            Self::Timeout => "timeout",
            Self::PprNotAllowed => "pprNotAllowed",
            Self::MetadataMismatch => "metadataMismatch",
            Self::LoadBppExecutionError => "loadBppExecutionError",
            Self::UndefinedReason => "undefinedReason",
        }
    }
}

/// What an SM-DP+ says a profile is, before the profile itself is released.
///
/// This is the whole reason `AuthenticateClient` and `PrepareDownload` are two
/// steps rather than one: between them the LPA holds the metadata and nothing
/// has been installed yet.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProfileMetadata {
    pub iccid: Option<String>,
    pub service_provider_name: Option<String>,
    pub profile_name: Option<String>,
    /// 0 test, 1 provisioning, 2 operational.
    pub class: Option<u8>,
    /// The policy rules that would be installed with the profile:
    /// `pprUpdateControl`, `ppr1`, `ppr2`.
    pub policy_rules: Vec<String>,
    /// The raw `BF25` bytes, so what was decided on can be shown verbatim.
    pub raw: Vec<u8>,
}

impl ProfileMetadata {
    /// `ppr1` forbids disabling the profile, `ppr2` forbids deleting it.
    ///
    /// Either one is permanent once the profile is installed, and on hardware
    /// nobody can physically reach, a profile that cannot be disabled or
    /// deleted is a slot that is gone. Returned as a list rather than a
    /// boolean so a refusal can say which rule it refused.
    pub fn irreversible_policy_rules(&self) -> Vec<String> {
        self.policy_rules
            .iter()
            .filter(|rule| rule.as_str() == "ppr1" || rule.as_str() == "ppr2")
            .cloned()
            .collect()
    }
}

/// One piece of a Bound Profile Package as it has to reach the eUICC.
///
/// A BPP is not sent as one blob. SGP.22 section 5.7.5 splits it at fixed
/// points — the header plus the secure channel request, then each sequence
/// header, then each encrypted element on its own — and each piece is its own
/// `STORE DATA` chain with its own block counter. A correctly formed BPP cut
/// in the wrong places fails inside the secure channel, and the card reports
/// that as a security error rather than as a framing one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BppSegment {
    /// What this piece is, for a log that has to be read after the fact.
    pub label: String,
    pub bytes: Vec<u8>,
}

/// What the eUICC reports after the last BPP segment.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InstallationResult {
    pub success: bool,
    /// The notification the card now owes the SM-DP+.
    pub sequence_number: Option<u64>,
    pub iccid: Option<String>,
    /// Which BPP command failed, when one did.
    pub bpp_command: Option<String>,
    pub error_reason: Option<String>,
    /// The whole `BF37` structure, which is also the notification to deliver.
    pub notification: Vec<u8>,
}

/// Encode a DER length.
fn der_length(length: usize) -> Vec<u8> {
    if length < 0x80 {
        vec![length as u8]
    } else if length <= 0xff {
        vec![0x81, length as u8]
    } else if length <= 0xffff {
        vec![0x82, (length >> 8) as u8, length as u8]
    } else {
        vec![0x83, (length >> 16) as u8, (length >> 8) as u8, length as u8]
    }
}

/// Wrap `value` in one BER-TLV.
fn tlv(tag: &[u8], value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(tag.len() + 4 + value.len());
    out.extend_from_slice(tag);
    out.extend_from_slice(&der_length(value.len()));
    out.extend_from_slice(value);
    out
}

/// The first complete TLV in `bytes`, tag and length included.
///
/// A modem is free to pad its answer, and a trailing zero byte handed to an
/// SM-DP+ inside base64 is rejected by a strict DER parser with a message that
/// says nothing about padding.
pub fn first_tlv(bytes: &[u8]) -> Result<&[u8], Es10cError> {
    let (_, _, tail) = read_tlv(bytes)?;
    Ok(&bytes[..bytes.len() - tail.len()])
}

/// The value of the first child carrying `tag`, one level down.
fn find_tag<'a>(mut body: &'a [u8], tag: &[u8]) -> Option<&'a [u8]> {
    while !body.is_empty() {
        let (found, value, tail) = read_tlv(body).ok()?;
        body = tail;
        if found == tag {
            return Some(value);
        }
    }
    None
}

/// The shortest big-endian encoding of `value`, at least one byte.
fn minimal_integer(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first = bytes.iter().position(|byte| *byte != 0).unwrap_or(7);
    bytes[first..].to_vec()
}

/// Build ES10b `AuthenticateServer`.
///
/// The four credentials go in exactly as the SM-DP+ sent them. They are signed
/// structures: anything re-encoded here, even into something that means the
/// same, no longer matches the signature the eUICC is about to check.
pub fn authenticate_server_payload(
    server_signed1: &[u8],
    server_signature1: &[u8],
    euicc_ci_pkid: &[u8],
    server_certificate: &[u8],
    matching_id: Option<&str>,
    tac: [u8; 4],
) -> Result<Vec<u8>, Es10cError> {
    let mut context = Vec::new();
    if let Some(matching_id) = matching_id {
        context.extend_from_slice(&tlv(&[0x80], matching_id.as_bytes()));
    }
    // DeviceInfo: the type allocation code, then an empty DeviceCapabilities.
    //
    // No `imei` field. It is optional in SGP.22 and an LPA that omits it is
    // ordinary; the TAC is taken from the module's own IMEI rather than from
    // a borrowed handset one, because a type allocation code is how an
    // operator decides what this device is and answering that with someone
    // else's is a lie with consequences for whoever owns the real one.
    let device_info = tlv(&[0xa1], &[tlv(&[0x80], &tac), tlv(&[0xa1], &[])].concat());
    context.extend_from_slice(&device_info);

    let body = [
        first_tlv(server_signed1)?,
        first_tlv(server_signature1)?,
        first_tlv(euicc_ci_pkid)?,
        first_tlv(server_certificate)?,
        &tlv(&[TAG_CHOICE_OK], &context),
    ]
    .concat();
    Ok(tlv(TAG_AUTHENTICATE_SERVER, &body))
}

/// The type allocation code of an IMEI: its first eight digits, packed BCD.
pub fn tac_from_imei(imei: &str) -> Result<[u8; 4], Es10cError> {
    let digits: Vec<u8> = imei
        .chars()
        .filter(|character| !character.is_whitespace())
        .map(|character| character.to_digit(10).map(|digit| digit as u8))
        .collect::<Option<Vec<u8>>>()
        .ok_or(Es10cError::InvalidImei)?;
    if digits.len() < 8 {
        return Err(Es10cError::InvalidImei);
    }
    let mut tac = [0u8; 4];
    for (index, pair) in digits[..8].chunks(2).enumerate() {
        tac[index] = (pair[0] << 4) | pair[1];
    }
    Ok(tac)
}

/// SGP.22 `AuthenticateErrorCode`.
fn authenticate_error(code: u64) -> &'static str {
    match code {
        1 => "invalidCertificate",
        2 => "invalidSignature",
        3 => "unsupportedCurve",
        4 => "noSessionContext",
        5 => "invalidOid",
        6 => "euiccChallengeMismatch",
        7 => "ciPKUnknown",
        127 => "undefinedError",
        _ => "unknown error code",
    }
}

/// SGP.22 `DownloadErrorCode`.
fn download_error(code: u64) -> &'static str {
    match code {
        1 => "invalidCertificate",
        2 => "invalidSignature",
        3 => "unsupportedCurve",
        4 => "noSessionContext",
        5 => "invalidTransactionId",
        127 => "undefinedError",
        _ => "unknown error code",
    }
}

/// SGP.22 `BppCommandId`.
fn bpp_command(code: u64) -> &'static str {
    match code {
        0 => "initialiseSecureChannel",
        1 => "configureISDP",
        2 => "storeMetadata",
        3 => "storeMetadata2",
        4 => "replaceSessionKeys",
        5 => "loadProfileElements",
        _ => "unknown BPP command",
    }
}

/// SGP.22 `ErrorReason` from a `ProfileInstallationResult`.
fn installation_error(code: u64) -> &'static str {
    match code {
        1 => "incorrectInputValues",
        2 => "invalidSignature",
        3 => "invalidTransactionId",
        4 => "unsupportedCrtValues",
        5 => "unsupportedRemoteOperationType",
        6 => "unsupportedProfileClass",
        7 => "scp03tStructureError",
        8 => "scp03tSecurityError",
        9 => "installFailedDueToIccidAlreadyExistsOnEuicc",
        10 => "installFailedDueToInsufficientMemoryForProfile",
        11 => "installFailedDueToInterruption",
        12 => "installFailedDueToPEProcessingError",
        13 => "installFailedDueToDataMismatch",
        14 => "testProfileInstallFailedDueToInvalidNaaKey",
        15 => "pprNotAllowed",
        127 => "installFailedDueToUnknownError",
        _ => "unknown error reason",
    }
}

/// Read an `AuthenticateServer` response and return it verbatim.
///
/// The bytes are what `AuthenticateClient` carries to the SM-DP+, so they are
/// returned rather than rebuilt. The parse exists to notice a refusal: an
/// error response is a well formed answer that would otherwise be base64'd and
/// posted, and the server would then reject it with a message about *its*
/// input rather than about this card.
pub fn parse_authenticate_server_response(response: &[u8]) -> Result<Vec<u8>, Es10cError> {
    let whole = first_tlv(response)?;
    let body = expect_tag(whole, TAG_AUTHENTICATE_SERVER)?;
    let (tag, value, _) = read_tlv(body)?;
    match tag.as_slice() {
        [TAG_CHOICE_OK] => Ok(whole.to_vec()),
        [TAG_CHOICE_ERROR] => {
            let code = find_tag(value, &[0x81])
                .map(integer)
                .transpose()?
                .unwrap_or(127);
            Err(Es10cError::AuthenticationRefused {
                code,
                reason: authenticate_error(code),
            })
        }
        _ => Err(Es10cError::UnexpectedTag {
            expected: vec![TAG_CHOICE_OK],
            actual: tag,
        }),
    }
}

/// `ccRequiredFlag` inside `SmdpSigned2`.
///
/// A confirmation code the operator did not supply turns into a
/// `PrepareDownload` the card refuses, so the question is asked before the
/// card is involved.
pub fn confirmation_code_required(smdp_signed2: &[u8]) -> Result<bool, Es10cError> {
    let whole = first_tlv(smdp_signed2)?;
    let (_, body, _) = read_tlv(whole)?;
    match find_tag(body, &[0x01]) {
        Some(value) => Ok(value.first().copied().unwrap_or(0) != 0),
        None => Ok(false),
    }
}

/// The `transactionId` an SM-DP+ signed into `SmdpSigned2`.
pub fn smdp_signed2_transaction_id(smdp_signed2: &[u8]) -> Result<Vec<u8>, Es10cError> {
    let whole = first_tlv(smdp_signed2)?;
    let (_, body, _) = read_tlv(whole)?;
    find_tag(body, &[0x80])
        .map(<[u8]>::to_vec)
        .ok_or(Es10cError::MissingField {
            name: "smdpSigned2.transactionId",
        })
}

/// Build ES10b `PrepareDownload`.
pub fn prepare_download_payload(
    smdp_signed2: &[u8],
    smdp_signature2: &[u8],
    smdp_certificate: &[u8],
    hash_cc: Option<&[u8]>,
) -> Result<Vec<u8>, Es10cError> {
    let mut body = Vec::new();
    body.extend_from_slice(first_tlv(smdp_signed2)?);
    body.extend_from_slice(first_tlv(smdp_signature2)?);
    if let Some(hash) = hash_cc {
        body.extend_from_slice(&tlv(&[TAG_OCTET_STRING], hash));
    }
    body.extend_from_slice(first_tlv(smdp_certificate)?);
    Ok(tlv(TAG_PREPARE_DOWNLOAD, &body))
}

/// Read a `PrepareDownload` response and return it verbatim.
pub fn parse_prepare_download_response(response: &[u8]) -> Result<Vec<u8>, Es10cError> {
    let whole = first_tlv(response)?;
    let body = expect_tag(whole, TAG_PREPARE_DOWNLOAD)?;
    let (tag, value, _) = read_tlv(body)?;
    match tag.as_slice() {
        [TAG_CHOICE_OK] => Ok(whole.to_vec()),
        [TAG_CHOICE_ERROR] => {
            let code = find_tag(value, &[0x81])
                .map(integer)
                .transpose()?
                .unwrap_or(127);
            Err(Es10cError::DownloadRefused {
                code,
                reason: download_error(code),
            })
        }
        _ => Err(Es10cError::UnexpectedTag {
            expected: vec![TAG_CHOICE_OK],
            actual: tag,
        }),
    }
}

/// Decode the `profileMetadata` an SM-DP+ returns from `AuthenticateClient`.
pub fn parse_profile_metadata(bytes: &[u8]) -> Result<ProfileMetadata, Es10cError> {
    let whole = first_tlv(bytes)?;
    let mut body = expect_tag(whole, TAG_STORE_METADATA)?;
    let mut metadata = ProfileMetadata {
        raw: whole.to_vec(),
        ..ProfileMetadata::default()
    };
    while !body.is_empty() {
        let (tag, value, tail) = read_tlv(body)?;
        body = tail;
        match tag.as_slice() {
            [TAG_ICCID] => metadata.iccid = decode_iccid(value).ok(),
            [TAG_PROVIDER] => metadata.service_provider_name = text(value),
            [TAG_PROFILE_NAME] => metadata.profile_name = text(value),
            [TAG_PROFILE_CLASS] => metadata.class = value.first().copied(),
            [TAG_PROFILE_POLICY_RULES] => metadata.policy_rules = named_bits(value, PPR_IDS),
            _ => {}
        }
    }
    Ok(metadata)
}

/// Split a Bound Profile Package the way SGP.22 section 5.7.5 requires.
///
/// The order is fixed by the specification and by what the eUICC's secure
/// channel expects next, so this walks the structure rather than searching it:
/// the header and `BF23`, then the whole `A0`, then `A1`'s header followed by
/// each `88` on its own, then `A2` whole if it is there, then `A3`'s header
/// followed by each `86` on its own.
pub fn bound_profile_package_segments(bpp: &[u8]) -> Result<Vec<BppSegment>, Es10cError> {
    let whole = first_tlv(bpp)?;
    let (tag, body, _) = read_tlv(whole)?;
    if tag != TAG_BOUND_PROFILE_PACKAGE {
        return Err(Es10cError::UnexpectedTag {
            expected: TAG_BOUND_PROFILE_PACKAGE.to_vec(),
            actual: tag,
        });
    }
    let header_length = whole.len() - body.len();

    let mut segments = Vec::new();
    let mut rest = body;

    // The header plus the complete InitialiseSecureChannelRequest. The eUICC
    // needs the outer length before it will accept anything else.
    let (tag, _, tail) = read_tlv(rest)?;
    if tag != TAG_INITIALISE_SECURE_CHANNEL {
        return Err(Es10cError::UnexpectedTag {
            expected: TAG_INITIALISE_SECURE_CHANNEL.to_vec(),
            actual: tag,
        });
    }
    let secure_channel = &rest[..rest.len() - tail.len()];
    segments.push(BppSegment {
        label: "header+initialiseSecureChannelRequest".into(),
        bytes: [&whole[..header_length], secure_channel].concat(),
    });
    rest = tail;

    let mut seen_first_87 = false;
    let mut seen_88 = false;
    let mut seen_86 = false;
    while !rest.is_empty() {
        let (tag, value, tail) = read_tlv(rest)?;
        let element = &rest[..rest.len() - tail.len()];
        let element_header = element.len() - value.len();
        rest = tail;
        match tag.as_slice() {
            // firstSequenceOf87 and secondSequenceOf87 travel whole.
            [0xa0] | [0xa2] => {
                let label = if seen_first_87 {
                    "secondSequenceOf87"
                } else {
                    seen_first_87 = true;
                    "firstSequenceOf87"
                };
                segments.push(BppSegment {
                    label: label.into(),
                    bytes: element.to_vec(),
                });
            }
            // sequenceOf88 and sequenceOf86 travel as a header followed by one
            // segment per element: each element is separately encrypted and
            // the card processes them one at a time.
            [0xa1] | [0xa3] => {
                let (name, member) = if tag == [0xa1] {
                    seen_88 = true;
                    ("sequenceOf88", "88")
                } else {
                    seen_86 = true;
                    ("sequenceOf86", "86")
                };
                segments.push(BppSegment {
                    label: format!("{name} header"),
                    bytes: element[..element_header].to_vec(),
                });
                let mut inner = value;
                let mut index = 0;
                while !inner.is_empty() {
                    let (_, _, next) = read_tlv(inner)?;
                    let child = &inner[..inner.len() - next.len()];
                    segments.push(BppSegment {
                        label: format!("{member}[{index}]"),
                        bytes: child.to_vec(),
                    });
                    inner = next;
                    index += 1;
                }
            }
            _ => {
                return Err(Es10cError::UnexpectedTag {
                    expected: vec![0xa0, 0xa1, 0xa2, 0xa3],
                    actual: tag,
                })
            }
        }
    }
    if !seen_first_87 || !seen_88 || !seen_86 {
        return Err(Es10cError::MissingField {
            name: "boundProfilePackage element",
        });
    }
    Ok(segments)
}

/// Decode the `ProfileInstallationResult` the last BPP segment returns.
pub fn parse_installation_result(response: &[u8]) -> Result<InstallationResult, Es10cError> {
    let whole = first_tlv(response)?;
    let body = expect_tag(whole, TAG_INSTALLATION_RESULT)?;
    let data = expect_tag(body, TAG_INSTALLATION_RESULT_DATA)?;
    let metadata = find_tag(data, TAG_NOTIFICATION_METADATA).ok_or(Es10cError::MissingField {
        name: "notificationMetadata",
    })?;
    let final_result =
        find_tag(data, &[TAG_FINAL_RESULT]).ok_or(Es10cError::MissingField {
            name: "finalResult",
        })?;

    let mut result = InstallationResult {
        sequence_number: find_tag(metadata, &[0x80]).map(integer).transpose()?,
        iccid: find_tag(metadata, &[TAG_ICCID]).and_then(|value| decode_iccid(value).ok()),
        notification: whole.to_vec(),
        ..InstallationResult::default()
    };

    let (tag, value, _) = read_tlv(final_result)?;
    match tag.as_slice() {
        [TAG_CHOICE_OK] => result.success = true,
        [TAG_CHOICE_ERROR] => {
            result.bpp_command = find_tag(value, &[0x80])
                .map(integer)
                .transpose()?
                .map(|code| bpp_command(code).to_string());
            result.error_reason = find_tag(value, &[0x81])
                .map(integer)
                .transpose()?
                .map(|code| installation_error(code).to_string());
        }
        _ => {
            return Err(Es10cError::UnexpectedTag {
                expected: vec![TAG_CHOICE_OK],
                actual: tag,
            })
        }
    }
    Ok(result)
}

/// ES10b `RemoveNotificationFromList` by sequence number.
pub fn remove_notification_payload(sequence_number: u64) -> Vec<u8> {
    tlv(
        TAG_NOTIFICATION_SENT,
        &tlv(&[0x80], &minimal_integer(sequence_number)),
    )
}

/// Read a `RemoveNotificationFromList` response: 0 means it is gone.
pub fn parse_remove_notification_response(response: &[u8]) -> Result<u64, Es10cError> {
    let body = expect_tag(first_tlv(response)?, TAG_NOTIFICATION_SENT)?;
    let (tag, value, _) = read_tlv(body)?;
    if tag != [0x80] {
        return Err(Es10cError::UnexpectedTag {
            expected: vec![0x80],
            actual: tag,
        });
    }
    integer(value)
}

/// ES10b `CancelSession`.
///
/// The way out of a session that has been started and must not be finished.
/// Without it a refused download leaves the SM-DP+ holding a profile in a
/// state it will not hand out again for hours.
pub fn cancel_session_payload(transaction_id: &[u8], reason: CancelSessionReason) -> Vec<u8> {
    let body = [tlv(&[0x80], transaction_id), tlv(&[0x81], &[reason as u8])].concat();
    tlv(TAG_CANCEL_SESSION, &body)
}

/// Read a `CancelSession` response and return it verbatim for ES9+.
pub fn parse_cancel_session_response(response: &[u8]) -> Result<Vec<u8>, Es10cError> {
    let whole = first_tlv(response)?;
    let body = expect_tag(whole, TAG_CANCEL_SESSION)?;
    let (tag, _, _) = read_tlv(body)?;
    match tag.as_slice() {
        [TAG_CHOICE_OK] => Ok(whole.to_vec()),
        [TAG_CHOICE_ERROR] => Err(Es10cError::SessionNotCancelled),
        _ => Err(Es10cError::UnexpectedTag {
            expected: vec![TAG_CHOICE_OK],
            actual: tag,
        }),
    }
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

    // ---- the download half ---------------------------------------------
    //
    // Nothing here can be captured off the bench beforehand: a real
    // BoundProfilePackage only exists once an SM-DP+ has released one, and
    // releasing one is the irreversible act these tests exist to make safe.
    // So the fixtures are built to the SGP.22 structure, and the assertions
    // are about the shape the eUICC is entitled to expect.

    /// A `StoreMetadataRequest` whose `profilePolicyRules` asserts ppr1.
    ///
    /// BIT STRING `03 02 06 40` — two bytes, six unused bits, and `0100 0000`
    /// sets bit 1, which is `ppr1`: "disabling of this profile is not
    /// allowed". On hardware nobody can reach, that bit costs a slot forever.
    const METADATA_WITH_PPR1: &str = "BF252A \
                                      5A0A 98882119002200140268 \
                                      910B 542D4D6F62696C65205553 \
                                      9208 545F4D6F62696C65 \
                                      950102 \
                                      99020640";

    #[test]
    fn metadata_names_the_policy_rules_that_would_be_installed() {
        let metadata =
            parse_profile_metadata(&bytes(&clean(METADATA_WITH_PPR1))).expect("metadata");
        assert_eq!(metadata.policy_rules, vec!["ppr1".to_string()]);
        assert_eq!(metadata.irreversible_policy_rules(), vec!["ppr1".to_string()]);
        assert_eq!(metadata.service_provider_name.as_deref(), Some("T-Mobile US"));
        assert_eq!(metadata.profile_name.as_deref(), Some("T_Mobile"));
        assert_eq!(metadata.class, Some(2));
    }

    /// Metadata with no `99` at all is the ordinary case, and it has to read
    /// as "no rules" rather than as a decode failure. A parser that errored
    /// here would refuse every profile that is safe to install.
    #[test]
    fn metadata_without_policy_rules_is_not_an_error() {
        let raw = clean(METADATA_WITH_PPR1)
            .replace("99020640", "")
            .replacen("BF252A", "BF2526", 1);
        let metadata = parse_profile_metadata(&bytes(&raw)).expect("metadata");
        assert!(metadata.policy_rules.is_empty());
        assert!(metadata.irreversible_policy_rules().is_empty());
    }

    /// `pprUpdateControl` is bit 0 and is not one of the two that pin a
    /// profile permanently, so it must not trip the refusal.
    #[test]
    fn ppr_update_control_alone_is_not_irreversible() {
        let raw = clean(METADATA_WITH_PPR1).replace("99020640", "99020680");
        let metadata = parse_profile_metadata(&bytes(&raw)).expect("metadata");
        assert_eq!(metadata.policy_rules, vec!["pprUpdateControl".to_string()]);
        assert!(metadata.irreversible_policy_rules().is_empty());
    }

    /// Five unused bits rather than six: bit 2 only counts as set when the
    /// BIT STRING says three of its bits are significant.
    #[test]
    fn ppr2_is_refused_as_well() {
        let raw = clean(METADATA_WITH_PPR1).replace("99020640", "99020520");
        let metadata = parse_profile_metadata(&bytes(&raw)).expect("metadata");
        assert_eq!(metadata.irreversible_policy_rules(), vec!["ppr2".to_string()]);
    }

    /// A Bound Profile Package with two `88` elements and three `86` ones,
    /// which is the shape of every real one: a secure channel request, the
    /// ISD-P configuration, the metadata, then the profile itself.
    fn bound_profile_package(second_87: bool) -> Vec<u8> {
        fn wrap(tag: &[u8], value: &[u8]) -> Vec<u8> {
            let mut out = tag.to_vec();
            out.extend_from_slice(&der_length(value.len()));
            out.extend_from_slice(value);
            out
        }
        let secure_channel = wrap(&[0xbf, 0x23], &filler(90));
        let first_87 = wrap(&[0xa0], &wrap(&[0x87], &filler(16)));
        let sequence_88 = wrap(
            &[0xa1],
            &[wrap(&[0x88], &filler(40)), wrap(&[0x88], &filler(300))].concat(),
        );
        let second = if second_87 {
            wrap(&[0xa2], &wrap(&[0x87], &filler(16)))
        } else {
            Vec::new()
        };
        let sequence_86 = wrap(
            &[0xa3],
            &[
                wrap(&[0x86], &filler(700)),
                wrap(&[0x86], &filler(1024)),
                wrap(&[0x86], &filler(33)),
            ]
            .concat(),
        );
        wrap(
            &[0xbf, 0x36],
            &[secure_channel, first_87, sequence_88, second, sequence_86].concat(),
        )
    }

    #[test]
    fn a_bound_profile_package_splits_the_way_the_card_expects() {
        let bpp = bound_profile_package(false);
        let segments = bound_profile_package_segments(&bpp).expect("segments");
        let labels: Vec<&str> = segments.iter().map(|s| s.label.as_str()).collect();
        assert_eq!(
            labels,
            vec![
                "header+initialiseSecureChannelRequest",
                "firstSequenceOf87",
                "sequenceOf88 header",
                "88[0]",
                "88[1]",
                "sequenceOf86 header",
                "86[0]",
                "86[1]",
                "86[2]",
            ]
        );
        // Concatenating the segments back has to reproduce the package byte
        // for byte. Anything else means a byte was dropped or sent twice, and
        // inside a secure channel either one reads as a security error.
        let rebuilt: Vec<u8> = segments.iter().flat_map(|s| s.bytes.clone()).collect();
        assert_eq!(rebuilt, bpp);
    }

    #[test]
    fn the_optional_second_sequence_of_87_is_carried_when_present() {
        let bpp = bound_profile_package(true);
        let segments = bound_profile_package_segments(&bpp).expect("segments");
        assert!(segments.iter().any(|s| s.label == "secondSequenceOf87"));
        let rebuilt: Vec<u8> = segments.iter().flat_map(|s| s.bytes.clone()).collect();
        assert_eq!(rebuilt, bpp);
    }

    /// Every segment then goes through the `STORE DATA` chain, and this is the
    /// first thing in the project that produces one longer than a block. The
    /// big `86` elements are what make it a chain rather than a single APDU.
    #[test]
    fn the_segments_of_a_package_need_a_multi_block_store_data_chain() {
        let bpp = bound_profile_package(false);
        let segments = bound_profile_package_segments(&bpp).expect("segments");
        let chains: Vec<usize> = segments
            .iter()
            .map(|segment| store_data_chain(&segment.bytes).expect("chain").len())
            .collect();
        let blocks: usize = chains.iter().sum();
        assert!(blocks > segments.len(), "at least one segment spans blocks");
        let longest = chains.iter().copied().max().unwrap_or(0);
        assert!(
            longest >= 5,
            "the 1024-byte element needs five blocks, got {longest}"
        );
    }

    /// A package missing the mandatory `sequenceOf86` is refused before a
    /// single byte reaches the card. Half a package installs nothing and
    /// leaves the chip holding an open secure channel.
    #[test]
    fn an_incomplete_package_is_refused_before_anything_is_sent() {
        let bpp = bound_profile_package(false);
        let truncated = &bpp[..bpp.len() - 1800];
        assert!(bound_profile_package_segments(truncated).is_err());
    }

    #[test]
    fn authenticate_server_carries_the_credentials_verbatim() {
        let signed1 = bytes("300C 8004 AABBCCDD 8104 11223344");
        let signature1 = bytes("5F3708 0102030405060708");
        let ci_pkid = bytes("0403 AABBCC");
        let certificate = bytes("3006 0201 07 0201 08");
        let payload = authenticate_server_payload(
            &signed1,
            &signature1,
            &ci_pkid,
            &certificate,
            Some("QQ111-22222"),
            [0x86, 0x94, 0x27, 0x04],
        )
        .expect("payload");
        assert_eq!(&payload[..2], &[0xbf, 0x38]);
        for part in [&signed1, &signature1, &ci_pkid, &certificate] {
            assert!(
                payload.windows(part.len()).any(|window| window == &part[..]),
                "credential must travel byte for byte"
            );
        }
        // ctxParams1: A0 { 80 matchingId, A1 { 80 tac, A1 (empty) } }
        let expected_context =
            bytes("A017 800B 51513131312D3232323232 A108 800486942704 A100");
        assert!(payload
            .windows(expected_context.len())
            .any(|window| window == expected_context.as_slice()));
    }

    #[test]
    fn a_matching_id_is_optional_in_the_context() {
        let payload = authenticate_server_payload(
            &bytes("3003 800100"),
            &bytes("5F3701 00"),
            &bytes("040100"),
            &bytes("3003 020100"),
            None,
            [0x86, 0x94, 0x27, 0x04],
        )
        .expect("payload");
        let expected_context = bytes("A00A A108 800486942704 A100");
        assert!(payload
            .windows(expected_context.len())
            .any(|window| window == expected_context.as_slice()));
    }

    #[test]
    fn the_tac_is_the_first_eight_digits_of_the_modules_own_imei() {
        assert_eq!(
            tac_from_imei("867018069514820").expect("tac"),
            [0x86, 0x70, 0x18, 0x06]
        );
        assert_eq!(tac_from_imei("86701"), Err(Es10cError::InvalidImei));
        assert_eq!(tac_from_imei("86701806951482x"), Err(Es10cError::InvalidImei));
    }

    /// A refusal by the card is a well formed response. Left unread it would
    /// be base64'd and posted, and the SM-DP+ would answer with a complaint
    /// about its own input rather than about this chip.
    #[test]
    fn an_authenticate_server_refusal_is_read_as_a_refusal() {
        assert_eq!(
            parse_authenticate_server_response(&bytes("BF3805 A103 810101")),
            Err(Es10cError::AuthenticationRefused {
                code: 1,
                reason: "invalidCertificate",
            })
        );
    }

    #[test]
    fn an_authenticate_server_success_is_returned_byte_for_byte() {
        let response = bytes("BF3806 A004 80020102 FFFF");
        let carried = parse_authenticate_server_response(&response).expect("ok");
        // Trailing padding a modem added is not part of the answer.
        assert_eq!(carried, bytes("BF3806 A004 80020102"));
    }

    #[test]
    fn a_prepare_download_refusal_names_its_code() {
        assert_eq!(
            parse_prepare_download_response(&bytes("BF2105 A103 810105")),
            Err(Es10cError::DownloadRefused {
                code: 5,
                reason: "invalidTransactionId",
            })
        );
    }

    #[test]
    fn a_confirmation_code_is_only_required_when_the_server_says_so() {
        // SmdpSigned2 ::= SEQUENCE { transactionId [0], ccRequiredFlag BOOLEAN }
        assert_eq!(
            confirmation_code_required(&bytes("3009 8004 AABBCCDD 0101FF")),
            Ok(true)
        );
        assert_eq!(
            confirmation_code_required(&bytes("3009 8004 AABBCCDD 010100")),
            Ok(false)
        );
        assert_eq!(
            smdp_signed2_transaction_id(&bytes("3009 8004 AABBCCDD 010100")),
            Ok(vec![0xaa, 0xbb, 0xcc, 0xdd])
        );
    }

    #[test]
    fn prepare_download_carries_the_hash_only_when_there_is_one() {
        let without = prepare_download_payload(
            &bytes("3003 800100"),
            &bytes("5F3701 00"),
            &bytes("3003 020100"),
            None,
        )
        .expect("payload");
        let with = prepare_download_payload(
            &bytes("3003 800100"),
            &bytes("5F3701 00"),
            &bytes("3003 020100"),
            Some(&[0x11; 32]),
        )
        .expect("payload");
        assert_eq!(with.len(), without.len() + 34);
        assert!(with
            .windows(34)
            .any(|window| window[0] == 0x04 && window[1] == 0x20));
    }

    /// The success case. `finalResult` is `A2 { A0 ... }`, and the whole
    /// `BF37` is also the notification the SM-DP+ has to be told about.
    #[test]
    fn an_installation_result_reports_success_and_the_notification_to_deliver() {
        let response = bytes(
            "BF372B BF2728 \
             8004AABBCCDD \
             BF2F19 800103 81020780 0C10 736D64702E6578616D706C652E636F6D \
             A204 A0020500",
        );
        let result = parse_installation_result(&response).expect("result");
        assert!(result.success);
        assert_eq!(result.sequence_number, Some(3));
        assert_eq!(result.notification, response);
        assert!(result.error_reason.is_none());
    }

    #[test]
    fn a_failed_installation_names_the_command_and_the_reason() {
        let response = bytes(
            "BF372F BF272C \
             8004AABBCCDD \
             BF2F19 800104 81020780 0C10 736D64702E6578616D706C652E636F6D \
             A208 A106 800105 81010A",
        );
        let result = parse_installation_result(&response).expect("result");
        assert!(!result.success);
        assert_eq!(result.bpp_command.as_deref(), Some("loadProfileElements"));
        assert_eq!(
            result.error_reason.as_deref(),
            Some("installFailedDueToInsufficientMemoryForProfile")
        );
    }

    #[test]
    fn removing_a_notification_asks_for_it_by_sequence_number() {
        assert_eq!(remove_notification_payload(3), bytes("BF3003 800103"));
        assert_eq!(remove_notification_payload(300), bytes("BF3004 8002012C"));
        assert_eq!(
            parse_remove_notification_response(&bytes("BF3003 800100")),
            Ok(0)
        );
        // 1 is "nothing to delete", which is not the same as removed.
        assert_eq!(
            parse_remove_notification_response(&bytes("BF3003 800101")),
            Ok(1)
        );
    }

    #[test]
    fn cancelling_a_session_states_why() {
        let payload =
            cancel_session_payload(&[0xaa, 0xbb, 0xcc, 0xdd], CancelSessionReason::PprNotAllowed);
        assert_eq!(payload, bytes("BF4109 8004AABBCCDD 810103"));
        assert_eq!(CancelSessionReason::PprNotAllowed.label(), "pprNotAllowed");
        assert_eq!(
            parse_cancel_session_response(&bytes("BF410B A009 8004AABBCCDD 810100")),
            Ok(bytes("BF410B A009 8004AABBCCDD 810100"))
        );
    }

    /// 🔴 `DeleteProfileRequest` is a CHOICE, not a SEQUENCE: the ICCID sits
    /// directly in the body, with no `a0` list around it. Enable and disable
    /// next door DO use the list, so a delete built by copying one of them is
    /// wrong in a way that only a real card reports.
    #[test]
    fn a_delete_carries_the_iccid_without_the_list_wrapper() {
        let request = delete_profile_payload("8985200014632179571").expect("payload");
        assert_eq!(&request[..2], &[0xbf, 0x33], "DeleteProfileRequest is [51]");
        // Body starts at index 3 (two tag bytes and one length byte).
        assert_eq!(request[3], 0x5a, "the ICCID follows the length directly");
        let enable = enable_profile_payload("8985200014632179571", true).expect("payload");
        assert_eq!(enable[3], 0xa0, "enable really does wrap it, which is the trap");
    }

    #[test]
    fn a_nickname_is_carried_as_utf8_under_its_own_tag() {
        let request = set_nickname_payload("8985200014632179571", "bench").expect("payload");
        assert_eq!(&request[..2], &[0xbf, 0x29], "SetNicknameRequest is [41]");
        assert!(
            request.windows(5).any(|window| window == b"bench"),
            "the nickname is not in the request"
        );
        let tag_at = request.iter().position(|byte| *byte == 0x90).expect("nickname tag");
        assert_eq!(request[tag_at + 1], 5, "length precedes the text");
    }

    /// 🔴 Clearing a name sends an empty field, not no field. Measured
    /// 2026-08-31: the bench eUICC answers `undefined error (127)` to a
    /// SetNickname carrying no `profileNickname` at all, so the obvious
    /// reading of SGP.22's OPTIONAL is the one that does not work here.
    #[test]
    fn clearing_a_nickname_sends_an_empty_field_rather_than_none() {
        let request = set_nickname_payload("8985200014632179571", "  ").expect("payload");
        let tag_at = request
            .iter()
            .position(|byte| *byte == TAG_NICKNAME)
            .expect("the nickname field must be present even when empty");
        assert_eq!(request[tag_at + 1], 0, "a cleared nickname has length zero");
    }

    #[test]
    fn a_nickname_past_the_limit_is_refused_rather_than_cut() {
        let long = "x".repeat(65);
        assert!(matches!(
            set_nickname_payload("8985200014632179571", &long),
            Err(Es10cError::NicknameTooLong { bytes: 65 })
        ));
    }

    /// The refusal an operator will actually meet: a card will not delete the
    /// profile it is running on.
    #[test]
    fn deleting_the_running_profile_is_refused_by_name() {
        let response = [0xbf, 0x33, 0x03, 0x80, 0x01, 0x02];
        match parse_delete_result(&response) {
            Err(Es10cError::Refused { code: 2, reason }) => {
                assert!(reason.contains("disabled state"), "reason = {reason}");
            }
            other => panic!("expected a named refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_successful_delete_and_rename_read_as_success() {
        assert!(parse_delete_result(&[0xbf, 0x33, 0x03, 0x80, 0x01, 0x00]).is_ok());
        assert!(parse_set_nickname_result(&[0xbf, 0x29, 0x03, 0x80, 0x01, 0x00]).is_ok());
    }

    #[test]
    fn a_rename_against_a_missing_iccid_is_reported() {
        match parse_set_nickname_result(&[0xbf, 0x29, 0x03, 0x80, 0x01, 0x01]) {
            Err(Es10cError::Refused { code: 1, reason }) => {
                assert!(reason.contains("not found"), "reason = {reason}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }
}
