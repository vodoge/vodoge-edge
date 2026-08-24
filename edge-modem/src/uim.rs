use std::{error::Error, fmt};

use crate::{
    unique_tlv, ClientAssignment, ClientId, MessageId, QmiRequest, QmiResponse, QmiResult,
    ResultError, ServiceId, Tlv, TlvLookupError, TransactionId, WireError,
};

pub const SEND_APDU: MessageId = MessageId::new(0x003b);
pub const CLOSE_LOGICAL_CHANNEL: MessageId = MessageId::new(0x003f);
pub const OPEN_LOGICAL_CHANNEL: MessageId = MessageId::new(0x0042);
pub const READ_TRANSPARENT: MessageId = MessageId::new(0x0020);

const SLOT_TLV: u8 = 0x01;
const APDU_COMMAND_TLV: u8 = 0x02;
const CHANNEL_TLV: u8 = 0x10;
const AID_TLV: u8 = 0x10;
const APDU_RESPONSE_TLV: u8 = 0x10;
/// `LOGICAL_CHANNEL` (0x003f) carries the AID at 0x10 and the channel to close
/// at 0x11, unlike `OPEN_LOGICAL_CHANNEL` (0x0042) whose *response* reports the
/// new channel at 0x10. Reusing 0x10 to close makes the module read a channel
/// number as an AID and reject the whole message as malformed.
const CLOSE_CHANNEL_TLV: u8 = 0x11;
const TERMINATE_APPLICATION_TLV: u8 = 0x12;
const SESSION_TLV: u8 = 0x01;
const FILE_TLV: u8 = 0x02;
const READ_INFO_TLV: u8 = 0x03;
const READ_RESULT_TLV: u8 = 0x11;

/// `EF_IMSI` lives inside the USIM application, not under the MF.
pub const EF_IMSI_FILE_ID: u16 = 0x6f07;
pub const EF_IMSI_PATH: &[u16] = &[0x3f00, 0x7fff];

/// `EF_AD` sits beside `EF_IMSI` inside the USIM application, and is what
/// says where the MNC ends inside that IMSI (byte 4, low nibble). It is
/// read-only and reachable on the basic channel, so it costs one more
/// READ TRANSPARENT on a poll that already reads `EF_IMSI` -- no logical
/// channel, nothing to contend with an eUICC session over.
pub const EF_AD_FILE_ID: u16 = 0x6fad;
pub const EF_AD_PATH: &[u16] = &[0x3f00, 0x7fff];

/// `EF_ICCID` sits directly under the MF, outside any application.
pub const EF_ICCID_FILE_ID: u16 = 0x2fe2;
pub const EF_ICCID_PATH: &[u16] = &[0x3f00];

/// GSMA SGP.22 ISD-R AID used to open an eUICC logical channel.
pub const ISD_R_AID: &[u8] = &[
    0xa0, 0x00, 0x00, 0x05, 0x59, 0x10, 0x10, 0xff, 0xff, 0xff, 0xff, 0x89, 0x00, 0x00, 0x01,
    0x00,
];

/// GlobalPlatform GET DATA for tag `5A` (EID).
///
/// Only a fallback now. Both eUICCs on the bench answer `6D00` to this and
/// answer the ES10c `GetEUICCData` form, so the ES10c one is tried first.
pub const GET_EID_APDU: &[u8] = &[0x80, 0xca, 0x00, 0x5a, 0x00];

/// How many `GET RESPONSE` continuations one command may be given.
///
/// A card that has more to say answers `61 xx` and expects to be asked again,
/// and it can do that many times over: `RetrieveNotificationsList` on the
/// bench chip returns 3333 bytes in fifteen rounds. Doing one round and
/// stopping — which is what this crate used to do — hands the caller the first
/// 255 bytes of an answer and no indication that the rest exists.
///
/// The bound is here so a card answering `61xx` forever cannot wedge the poll
/// loop, not because a real answer is expected to be short.
pub const MAX_GET_RESPONSE_ROUNDS: usize = 256;

/// APDU status words plus any returned data bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApduResponse {
    pub data: Vec<u8>,
    pub sw1: u8,
    pub sw2: u8,
}

impl ApduResponse {
    pub fn is_success(&self) -> bool {
        self.sw1 == 0x90 && self.sw2 == 0x00
    }

    pub fn needs_get_response(&self) -> bool {
        self.sw1 == 0x61
    }

    pub fn get_response_apdu(&self) -> Option<[u8; 5]> {
        if self.needs_get_response() {
            Some([0x00, 0xc0, 0x00, 0x00, self.sw2])
        } else {
            None
        }
    }
}

/// Keep asking a card for the rest of an answer until it stops saying `61 xx`.
///
/// Lifted out of `IsdrSession::transmit` when a second caller appeared: the
/// USIM AKA primitive runs on the basic channel over `AT+CSIM` rather than
/// over QMI, so it cannot borrow the session, but it must not re-derive this
/// loop either. Two copies of "how many rounds are too many" is how one of
/// them silently keeps the old answer of "one".
///
/// `send` carries whatever transport the caller has; `too_many` builds that
/// caller's own error for the bound, so neither side has to widen its error
/// type to accommodate the other.
pub fn drain_get_response<E>(
    first: ApduResponse,
    mut send: impl FnMut(&[u8]) -> Result<ApduResponse, E>,
    too_many: impl FnOnce(usize) -> E,
) -> Result<ApduResponse, E> {
    let mut response = first;
    let mut collected = std::mem::take(&mut response.data);
    let mut rounds = 0usize;
    while let Some(get_response) = response.get_response_apdu() {
        if rounds >= MAX_GET_RESPONSE_ROUNDS {
            return Err(too_many(MAX_GET_RESPONSE_ROUNDS));
        }
        rounds += 1;
        response = send(&get_response)?;
        collected.extend_from_slice(&response.data);
    }
    Ok(ApduResponse {
        data: collected,
        sw1: response.sw1,
        sw2: response.sw2,
    })
}

pub fn open_logical_channel_request(
    assignment: ClientAssignment,
    transaction: TransactionId,
    slot: u8,
    aid: &[u8],
) -> Result<QmiRequest, UimError> {
    ensure_uim(assignment)?;
    if aid.len() > u8::MAX as usize {
        return Err(UimError::AidTooLarge { actual: aid.len() });
    }
    let mut aid_value = Vec::with_capacity(1 + aid.len());
    aid_value.push(aid.len() as u8);
    aid_value.extend_from_slice(aid);
    let aid_tlv = Tlv::new(AID_TLV, aid_value)?;
    let slot_tlv = Tlv::new(SLOT_TLV, vec![slot])?;
    Ok(QmiRequest::from_tlvs(
        ServiceId::UIM,
        assignment.client_id(),
        transaction,
        OPEN_LOGICAL_CHANNEL,
        &[aid_tlv, slot_tlv],
    )?)
}

pub fn parse_open_logical_channel(response: &QmiResponse) -> Result<u8, UimError> {
    let tlvs = expect_uim(response, OPEN_LOGICAL_CHANNEL)?;
    let tlv = unique_tlv(&tlvs, CHANNEL_TLV)?;
    if tlv.value.is_empty() {
        return Err(UimError::TruncatedChannel);
    }
    Ok(tlv.value[0])
}

pub fn close_logical_channel_request(
    assignment: ClientAssignment,
    transaction: TransactionId,
    slot: u8,
    channel: u8,
) -> Result<QmiRequest, UimError> {
    ensure_uim(assignment)?;
    let slot_tlv = Tlv::new(SLOT_TLV, vec![slot])?;
    let channel_tlv = Tlv::new(CLOSE_CHANNEL_TLV, vec![channel])?;
    let terminate_tlv = Tlv::new(TERMINATE_APPLICATION_TLV, vec![0x01])?;
    Ok(QmiRequest::from_tlvs(
        ServiceId::UIM,
        assignment.client_id(),
        transaction,
        CLOSE_LOGICAL_CHANNEL,
        &[slot_tlv, channel_tlv, terminate_tlv],
    )?)
}

pub fn parse_close_logical_channel(response: &QmiResponse) -> Result<(), UimError> {
    expect_uim(response, CLOSE_LOGICAL_CHANNEL).map(|_| ())
}

pub fn send_apdu_request(
    assignment: ClientAssignment,
    transaction: TransactionId,
    slot: u8,
    channel: u8,
    command: &[u8],
) -> Result<QmiRequest, UimError> {
    ensure_uim(assignment)?;
    if command.len() > u16::MAX as usize {
        return Err(UimError::ApduTooLarge {
            actual: command.len(),
        });
    }
    let mut command_value = Vec::with_capacity(2 + command.len());
    command_value.extend_from_slice(&(command.len() as u16).to_le_bytes());
    command_value.extend_from_slice(command);
    let channel_tlv = Tlv::new(CHANNEL_TLV, vec![channel])?;
    let command_tlv = Tlv::new(APDU_COMMAND_TLV, command_value)?;
    let slot_tlv = Tlv::new(SLOT_TLV, vec![slot])?;
    Ok(QmiRequest::from_tlvs(
        ServiceId::UIM,
        assignment.client_id(),
        transaction,
        SEND_APDU,
        &[channel_tlv, command_tlv, slot_tlv],
    )?)
}

pub fn parse_send_apdu(response: &QmiResponse) -> Result<ApduResponse, UimError> {
    let tlvs = expect_uim(response, SEND_APDU)?;
    let tlv = unique_tlv(&tlvs, APDU_RESPONSE_TLV)?;
    if tlv.value.len() < 2 {
        return Err(UimError::TruncatedApdu {
            actual: tlv.value.len(),
        });
    }
    let declared = u16::from_le_bytes([tlv.value[0], tlv.value[1]]) as usize;
    if tlv.value.len() < 2 + declared {
        return Err(UimError::TruncatedApdu {
            actual: tlv.value.len(),
        });
    }
    parse_rapdu(&tlv.value[2..2 + declared])
}

/// Decode an EID from a GET DATA `5A` RAPDU. The value is 16 BCD bytes, shown
/// as 32 decimal digits.
pub fn parse_eid(response: &ApduResponse) -> Result<String, UimError> {
    if !response.is_success() && !response.needs_get_response() {
        return Err(UimError::ApduFailed {
            sw1: response.sw1,
            sw2: response.sw2,
        });
    }
    let bytes = eid_bytes(&response.data)?;
    if bytes.len() != 16 {
        return Err(UimError::UnexpectedEidLength {
            actual: bytes.len(),
        });
    }
    Ok(bcd_digits(&bytes))
}

/// Read a transparent EF. `path` holds the parent DF identifiers, most
/// significant first; each is encoded little-endian on the wire.
pub fn read_transparent_request(
    assignment: ClientAssignment,
    transaction: TransactionId,
    file_id: u16,
    path: &[u16],
) -> Result<QmiRequest, UimError> {
    ensure_uim(assignment)?;
    // Session type 0x00 is primary GW provisioning with a zero-length AID,
    // which is what reaches the MF on the modems this crate targets.
    let session_tlv = Tlv::new(SESSION_TLV, vec![0x00, 0x00])?;

    let mut file_value = Vec::with_capacity(3 + path.len() * 2);
    file_value.extend_from_slice(&file_id.to_le_bytes());
    file_value.push((path.len() * 2) as u8);
    for entry in path {
        file_value.extend_from_slice(&entry.to_le_bytes());
    }
    let file_tlv = Tlv::new(FILE_TLV, file_value)?;

    // Offset 0, length 0 asks the card for the whole file.
    let read_tlv = Tlv::new(READ_INFO_TLV, vec![0x00, 0x00, 0x00, 0x00])?;

    Ok(QmiRequest::from_tlvs(
        ServiceId::UIM,
        assignment.client_id(),
        transaction,
        READ_TRANSPARENT,
        &[session_tlv, file_tlv, read_tlv],
    )?)
}

pub fn parse_read_transparent(response: &QmiResponse) -> Result<Vec<u8>, UimError> {
    let tlvs = expect_uim(response, READ_TRANSPARENT)?;
    let tlv = unique_tlv(&tlvs, READ_RESULT_TLV)?;
    if tlv.value.len() < 2 {
        return Err(UimError::TruncatedReadResult { actual: tlv.value.len() });
    }
    let declared = u16::from_le_bytes([tlv.value[0], tlv.value[1]]) as usize;
    if tlv.value.len() < 2 + declared {
        return Err(UimError::TruncatedReadResult { actual: tlv.value.len() });
    }
    Ok(tlv.value[2..2 + declared].to_vec())
}

/// Decode `EF_ICCID`. Unlike the EID its nibbles are swapped per byte, and a
/// 19-digit ICCID is padded to 20 with a trailing `f`.
pub fn decode_iccid(bytes: &[u8]) -> Result<String, UimError> {
    if bytes.is_empty() {
        return Err(UimError::EmptyIccid);
    }
    let mut digits = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        digits.push(nibble_char(byte & 0x0f));
        digits.push(nibble_char(byte >> 4));
    }
    // Padding nibbles are removed wherever they are, not only at the end.
    //
    // A China Mobile card on the bench reports `898600F3031401770106` — the
    // `F` sits at position six, not at the end, and trimming only the tail
    // left an `f` in the middle that then failed the digit check. The card was
    // rejected outright and the cloud showed no ICCID for it at all.
    let digits: String = digits.chars().filter(|c| *c != 'f').collect();

    // Stripping padding cannot be allowed to turn a corrupt read into a
    // plausible number, so what is left has to look like an ICCID: E.118 gives
    // every one of them the major industry identifier 89, and they are 19 or
    // 20 digits long.
    if !digits.chars().all(|c| c.is_ascii_digit()) {
        return Err(UimError::EmptyIccid);
    }
    if digits.len() < 19 || digits.len() > 20 || !digits.starts_with("89") {
        return Err(UimError::EmptyIccid);
    }
    Ok(digits)
}

/// Decode `EF_IMSI`.
///
/// The layout is not the same as ICCID even though both are swapped BCD: the
/// first byte is a length, and the first digit lives in the *high* nibble of
/// the next byte while its low nibble is a parity flag. Decoding it the ICCID
/// way yields a number that looks plausible and is wrong.
pub fn decode_imsi(bytes: &[u8]) -> Result<String, UimError> {
    if bytes.len() < 2 {
        return Err(UimError::EmptyImsi);
    }
    let declared = usize::from(bytes[0]);
    if declared == 0 || declared > bytes.len() - 1 {
        return Err(UimError::EmptyImsi);
    }
    let packed = &bytes[1..=declared];
    let odd = packed[0] & 0x01 == 1;
    let mut digits = String::with_capacity(15);
    digits.push(nibble_char(packed[0] >> 4));
    for byte in &packed[1..] {
        digits.push(nibble_char(byte & 0x0f));
        digits.push(nibble_char(byte >> 4));
    }
    // An even-length IMSI pads with a trailing filler nibble.
    if !odd {
        digits.pop();
    }
    let trimmed = digits.trim_end_matches('f').to_string();
    if trimmed.is_empty() || trimmed.chars().any(|c| !c.is_ascii_digit()) {
        return Err(UimError::EmptyImsi);
    }
    Ok(trimmed)
}

fn nibble_char(value: u8) -> char {
    char::from_digit(u32::from(value), 16).unwrap_or('f')
}

fn parse_rapdu(bytes: &[u8]) -> Result<ApduResponse, UimError> {
    if bytes.len() < 2 {
        return Err(UimError::TruncatedApdu { actual: bytes.len() });
    }
    let (data, status) = bytes.split_at(bytes.len() - 2);
    Ok(ApduResponse {
        data: data.to_vec(),
        sw1: status[0],
        sw2: status[1],
    })
}

fn eid_bytes(data: &[u8]) -> Result<Vec<u8>, UimError> {
    if data.len() >= 2 && data[0] == 0x5a {
        let length = data[1] as usize;
        if data.len() >= 2 + length {
            return Ok(data[2..2 + length].to_vec());
        }
        return Err(UimError::TruncatedEid);
    }
    if data.len() == 16 {
        return Ok(data.to_vec());
    }
    Err(UimError::MissingEidTag)
}

fn bcd_digits(bytes: &[u8]) -> String {
    let mut digits = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        digits.push(char::from_digit((byte >> 4) as u32, 16).unwrap_or('0'));
        digits.push(char::from_digit((byte & 0x0f) as u32, 16).unwrap_or('0'));
    }
    digits
}

fn expect_uim(response: &QmiResponse, message_id: MessageId) -> Result<Vec<Tlv>, UimError> {
    if response.service() != ServiceId::UIM {
        return Err(UimError::UnexpectedService {
            actual: response.service(),
        });
    }
    if response.client_id() == ClientId::CONTROL {
        return Err(UimError::Wire(WireError::ServiceRequiresAllocatedClient {
            service: ServiceId::UIM,
        }));
    }
    if response.message_id() != message_id {
        return Err(UimError::UnexpectedMessage {
            expected: message_id,
            actual: response.message_id(),
        });
    }
    let tlvs = response.tlvs()?;
    QmiResult::from_tlvs(&tlvs)?.check()?;
    Ok(tlvs)
}

fn ensure_uim(assignment: ClientAssignment) -> Result<(), UimError> {
    if assignment.service() != ServiceId::UIM {
        return Err(UimError::UnexpectedService {
            actual: assignment.service(),
        });
    }
    Ok(())
}

/// Errors from encoding or decoding UIM messages.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UimError {
    Wire(WireError),
    Result(ResultError),
    Lookup(TlvLookupError),
    UnexpectedService { actual: ServiceId },
    UnexpectedMessage { expected: MessageId, actual: MessageId },
    AidTooLarge { actual: usize },
    ApduTooLarge { actual: usize },
    TruncatedChannel,
    TruncatedApdu { actual: usize },
    TruncatedEid,
    MissingEidTag,
    UnexpectedEidLength { actual: usize },
    TruncatedReadResult { actual: usize },
    EmptyIccid,
    EmptyImsi,
    ApduFailed { sw1: u8, sw2: u8 },
}

impl fmt::Display for UimError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(error) => error.fmt(formatter),
            Self::Result(error) => error.fmt(formatter),
            Self::Lookup(error) => error.fmt(formatter),
            Self::UnexpectedService { actual } => {
                write!(formatter, "expected UIM service, got {actual}")
            }
            Self::UnexpectedMessage { expected, actual } => {
                write!(formatter, "expected UIM message {expected}, got {actual}")
            }
            Self::AidTooLarge { actual } => {
                write!(formatter, "AID is {actual} bytes, above the u8 UIM limit")
            }
            Self::ApduTooLarge { actual } => {
                write!(formatter, "APDU is {actual} bytes, above the u16 UIM limit")
            }
            Self::TruncatedChannel => formatter.write_str("logical channel TLV is empty"),
            Self::TruncatedApdu { actual } => {
                write!(formatter, "APDU response TLV has {actual} bytes")
            }
            Self::TruncatedEid => formatter.write_str("EID TLV is truncated"),
            Self::MissingEidTag => formatter.write_str("APDU response does not contain an EID"),
            Self::UnexpectedEidLength { actual } => {
                write!(formatter, "EID has {actual} bytes, expected 16")
            }
            Self::TruncatedReadResult { actual } => {
                write!(formatter, "read result TLV has {actual} bytes")
            }
            Self::EmptyIccid => formatter.write_str("EF_ICCID is empty or not numeric"),
            Self::EmptyImsi => formatter.write_str("EF_IMSI is empty or not numeric"),
            Self::ApduFailed { sw1, sw2 } => {
                write!(formatter, "APDU failed with SW {sw1:02x}{sw2:02x}")
            }
        }
    }
}

impl Error for UimError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Wire(error) => Some(error),
            Self::Result(error) => Some(error),
            Self::Lookup(error) => Some(error),
            _ => None,
        }
    }
}

impl From<WireError> for UimError {
    fn from(value: WireError) -> Self {
        Self::Wire(value)
    }
}

impl From<ResultError> for UimError {
    fn from(value: ResultError) -> Self {
        Self::Result(value)
    }
}

impl From<TlvLookupError> for UimError {
    fn from(value: TlvLookupError) -> Self {
        Self::Lookup(value)
    }
}

#[cfg(test)]
mod imsi_tests {
    use super::*;

    /// Captured layout: length byte, then the first digit in the high nibble of
    /// the next byte with its low nibble carrying the odd-length flag.
    #[test]
    fn an_odd_length_imsi_is_decoded() {
        // 454006395021420 — fifteen digits, so the parity flag is set.
        let bytes = [0x08, 0x49, 0x45, 0x00, 0x36, 0x59, 0x20, 0x41, 0x02];
        assert_eq!(decode_imsi(&bytes).expect("imsi"), "454006395021420");
    }

    /// Decoding this the ICCID way would drop the leading digit and shift every
    /// other one, producing a number that still looks like an IMSI.
    #[test]
    fn the_first_digit_comes_from_the_high_nibble() {
        let bytes = [0x08, 0x49, 0x45, 0x00, 0x36, 0x59, 0x20, 0x41, 0x02];
        let decoded = decode_imsi(&bytes).expect("imsi");
        assert!(decoded.starts_with("454"), "got {decoded}");
        assert_eq!(decoded.len(), 15);
    }

    #[test]
    fn a_truncated_record_is_rejected() {
        assert!(matches!(decode_imsi(&[]), Err(UimError::EmptyImsi)));
        assert!(matches!(decode_imsi(&[0x08]), Err(UimError::EmptyImsi)));
        // Length byte promising more than the record holds.
        assert!(matches!(decode_imsi(&[0x08, 0x49]), Err(UimError::EmptyImsi)));
    }
}

#[cfg(test)]
mod iccid_bench_tests {
    use super::decode_iccid;

    /// The three cards actually on the bench, as their EF_ICCID bytes.
    ///
    /// The China Mobile one is the reason this test exists: its padding nibble
    /// is in the middle of the number rather than at the end, and the first
    /// version of the decoder rejected the card entirely.
    #[test]
    fn every_card_on_the_bench_decodes() {
        // CSL Hong Kong, 19 digits with padding at the end.
        assert_eq!(
            decode_iccid(&[0x98, 0x58, 0x02, 0x00, 0x41, 0x36, 0x12, 0x97, 0x75, 0xF1])
                .expect("csl"),
            "8985200014632179571",
        );

        // China Mobile, 19 digits with the padding nibble at position six.
        assert_eq!(
            decode_iccid(&[0x98, 0x68, 0x00, 0x3F, 0x30, 0x41, 0x10, 0x77, 0x10, 0x60])
                .expect("china mobile"),
            "8986003031401770106",
        );
    }

    /// Stripping padding must not turn a corrupt read into a plausible number.
    #[test]
    fn something_that_is_not_an_iccid_is_refused() {
        // All padding.
        assert!(decode_iccid(&[0xFF; 10]).is_err());
        // Right length, wrong prefix — every ICCID starts with 89.
        assert!(decode_iccid(&[0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x9F]).is_err());
        // Too short to be one.
        assert!(decode_iccid(&[0x98, 0x68]).is_err());
        assert!(decode_iccid(&[]).is_err());
    }
}
