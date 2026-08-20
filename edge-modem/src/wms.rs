use std::{error::Error, fmt};

use crate::{
    unique_tlv, ClientAssignment, ClientId, MessageId, QmiRequest, QmiResponse, QmiResult,
    ResultError, ServiceId, Tlv, TlvLookupError, TransactionId, WireError,
};

pub const RAW_SEND: MessageId = MessageId::new(0x0020);
pub const RAW_READ: MessageId = MessageId::new(0x0022);
pub const DELETE: MessageId = MessageId::new(0x0024);
pub const LIST_MESSAGES: MessageId = MessageId::new(0x0031);

const STORAGE_TLV: u8 = 0x01;
const LIST_RESULT_TLV: u8 = 0x01;
const RAW_MESSAGE_TLV: u8 = 0x01;
const MESSAGE_MODE_TLV: u8 = 0x10;
const MESSAGE_TAG_TLV: u8 = 0x11;
const DELETE_INDEX_TLV: u8 = 0x10;
const DELETE_MODE_TLV: u8 = 0x12;
const SEND_MESSAGE_ID_TLV: u8 = 0x01;

/// WMS storage type. UIM is the SIM/USIM store used for received SMS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageType {
    Uim,
    Nv,
}

impl StorageType {
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Uim => 0,
            Self::Nv => 1,
        }
    }
}

/// GSM/WCDMA vs CDMA transfer mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageMode {
    Cdma,
    Gw,
}

impl MessageMode {
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Cdma => 0,
            Self::Gw => 1,
        }
    }
}

/// Tag returned in a list or read. The request tag is never trusted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageTag {
    MtRead,
    MtUnread,
    MoSent,
    MoUnsent,
    Unknown(u8),
}

impl MessageTag {
    pub fn from_wire(value: u8) -> Self {
        match value {
            0 => Self::MtRead,
            1 => Self::MtUnread,
            2 => Self::MoSent,
            3 => Self::MoUnsent,
            other => Self::Unknown(other),
        }
    }

    pub fn as_u8(self) -> u8 {
        match self {
            Self::MtRead => 0,
            Self::MtUnread => 1,
            Self::MoSent => 2,
            Self::MoUnsent => 3,
            Self::Unknown(value) => value,
        }
    }

    pub fn is_mobile_terminated(self) -> bool {
        matches!(self, Self::MtRead | Self::MtUnread)
    }
}

/// One storage entry as returned by `QMI_WMS_LIST_MESSAGES`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ListedMessage {
    pub index: u32,
    pub tag: MessageTag,
}

/// Raw PDU plus the tag when the modem includes one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawMessage {
    pub tag: Option<MessageTag>,
    pub format: u8,
    pub pdu: Vec<u8>,
}

pub fn list_messages_request(
    assignment: ClientAssignment,
    transaction: TransactionId,
    storage: StorageType,
    tag: MessageTag,
    mode: MessageMode,
) -> Result<QmiRequest, WmsError> {
    ensure_wms(assignment)?;
    let storage_tlv = Tlv::new(STORAGE_TLV, vec![storage.as_u8()])?;
    let tag_tlv = Tlv::new(MESSAGE_TAG_TLV, vec![tag.as_u8()])?;
    let mode_tlv = Tlv::new(MESSAGE_MODE_TLV, vec![mode.as_u8()])?;
    Ok(QmiRequest::from_tlvs(
        ServiceId::WMS,
        assignment.client_id(),
        transaction,
        LIST_MESSAGES,
        &[storage_tlv, tag_tlv, mode_tlv],
    )?)
}

pub fn parse_list_messages(response: &QmiResponse) -> Result<Vec<ListedMessage>, WmsError> {
    let tlvs = expect_wms(response, LIST_MESSAGES)?;
    match unique_tlv(&tlvs, LIST_RESULT_TLV) {
        Err(TlvLookupError::Missing { .. }) => Ok(Vec::new()),
        Err(error) => Err(error.into()),
        Ok(tlv) => parse_list_payload(&tlv.value),
    }
}

/// Keep only MT entries. EC20 ignores the list-tag request argument and mixes
/// in sent/draft rows; callers must filter on the returned tag.
pub fn retain_mobile_terminated(messages: &[ListedMessage]) -> Vec<ListedMessage> {
    messages
        .iter()
        .copied()
        .filter(|message| message.tag.is_mobile_terminated())
        .collect()
}

pub fn raw_read_request(
    assignment: ClientAssignment,
    transaction: TransactionId,
    storage: StorageType,
    index: u32,
    mode: MessageMode,
) -> Result<QmiRequest, WmsError> {
    ensure_wms(assignment)?;
    let mut storage_value = Vec::with_capacity(5);
    storage_value.push(storage.as_u8());
    storage_value.extend_from_slice(&index.to_le_bytes());
    let storage_tlv = Tlv::new(STORAGE_TLV, storage_value)?;
    let mode_tlv = Tlv::new(MESSAGE_MODE_TLV, vec![mode.as_u8()])?;
    Ok(QmiRequest::from_tlvs(
        ServiceId::WMS,
        assignment.client_id(),
        transaction,
        RAW_READ,
        &[storage_tlv, mode_tlv],
    )?)
}

pub fn parse_raw_read(response: &QmiResponse) -> Result<RawMessage, WmsError> {
    let tlvs = expect_wms(response, RAW_READ)?;
    let tlv = unique_tlv(&tlvs, RAW_MESSAGE_TLV)?;
    parse_raw_message_value(&tlv.value)
}

pub fn raw_send_request(
    assignment: ClientAssignment,
    transaction: TransactionId,
    format: u8,
    pdu: &[u8],
) -> Result<QmiRequest, WmsError> {
    ensure_wms(assignment)?;
    if pdu.len() > u16::MAX as usize {
        return Err(WmsError::PduTooLarge { actual: pdu.len() });
    }
    let mut value = Vec::with_capacity(3 + pdu.len());
    value.push(format);
    value.extend_from_slice(&(pdu.len() as u16).to_le_bytes());
    value.extend_from_slice(pdu);
    let tlv = Tlv::new(RAW_MESSAGE_TLV, value)?;
    Ok(QmiRequest::from_tlvs(
        ServiceId::WMS,
        assignment.client_id(),
        transaction,
        RAW_SEND,
        &[tlv],
    )?)
}

pub fn parse_raw_send(response: &QmiResponse) -> Result<Option<u16>, WmsError> {
    let tlvs = expect_wms(response, RAW_SEND)?;
    match unique_tlv(&tlvs, SEND_MESSAGE_ID_TLV) {
        Err(TlvLookupError::Missing { .. }) => Ok(None),
        Err(error) => Err(error.into()),
        Ok(tlv) if tlv.value.len() >= 2 => {
            Ok(Some(u16::from_le_bytes([tlv.value[0], tlv.value[1]])))
        }
        Ok(tlv) => Err(WmsError::TruncatedMessageId {
            actual: tlv.value.len(),
        }),
    }
}

pub fn delete_by_index_request(
    assignment: ClientAssignment,
    transaction: TransactionId,
    storage: StorageType,
    index: u32,
    mode: MessageMode,
) -> Result<QmiRequest, WmsError> {
    ensure_wms(assignment)?;
    let storage_tlv = Tlv::new(STORAGE_TLV, vec![storage.as_u8()])?;
    let index_tlv = Tlv::new(DELETE_INDEX_TLV, index.to_le_bytes().to_vec())?;
    let mode_tlv = Tlv::new(DELETE_MODE_TLV, vec![mode.as_u8()])?;
    Ok(QmiRequest::from_tlvs(
        ServiceId::WMS,
        assignment.client_id(),
        transaction,
        DELETE,
        &[storage_tlv, index_tlv, mode_tlv],
    )?)
}

pub fn parse_delete(response: &QmiResponse) -> Result<(), WmsError> {
    expect_wms(response, DELETE).map(|_| ())
}

fn parse_list_payload(value: &[u8]) -> Result<Vec<ListedMessage>, WmsError> {
    if value.len() < 4 {
        return Err(WmsError::TruncatedList { actual: value.len() });
    }
    let count = u32::from_le_bytes([value[0], value[1], value[2], value[3]]) as usize;
    let mut messages = Vec::with_capacity(count);
    let mut offset = 4;
    for _ in 0..count {
        if offset + 5 > value.len() {
            return Err(WmsError::TruncatedList { actual: value.len() });
        }
        let index = u32::from_le_bytes([
            value[offset],
            value[offset + 1],
            value[offset + 2],
            value[offset + 3],
        ]);
        let tag = MessageTag::from_wire(value[offset + 4]);
        messages.push(ListedMessage { index, tag });
        offset += 5;
    }
    Ok(messages)
}

fn parse_raw_message_value(value: &[u8]) -> Result<RawMessage, WmsError> {
    if value.len() < 3 {
        return Err(WmsError::TruncatedRawMessage { actual: value.len() });
    }

    let untagged_length = u16::from_le_bytes([value[1], value[2]]) as usize;
    if untagged_length <= value.len().saturating_sub(3) {
        return Ok(RawMessage {
            tag: None,
            format: value[0],
            pdu: value[3..3 + untagged_length].to_vec(),
        });
    }

    if value.len() >= 4 {
        let tagged_length = u16::from_le_bytes([value[2], value[3]]) as usize;
        if MessageTag::from_wire(value[0]).is_known() && tagged_length <= value.len() - 4 {
            return Ok(RawMessage {
                tag: Some(MessageTag::from_wire(value[0])),
                format: value[1],
                pdu: value[4..4 + tagged_length].to_vec(),
            });
        }
    }

    Ok(RawMessage {
        tag: None,
        format: value[0],
        pdu: value[3..].to_vec(),
    })
}

impl MessageTag {
    fn is_known(self) -> bool {
        !matches!(self, Self::Unknown(_))
    }
}

fn expect_wms(response: &QmiResponse, message_id: MessageId) -> Result<Vec<Tlv>, WmsError> {
    if response.service() != ServiceId::WMS {
        return Err(WmsError::UnexpectedService {
            actual: response.service(),
        });
    }
    if response.client_id() == ClientId::CONTROL {
        return Err(WmsError::Wire(WireError::ServiceRequiresAllocatedClient {
            service: ServiceId::WMS,
        }));
    }
    if response.message_id() != message_id {
        return Err(WmsError::UnexpectedMessage {
            expected: message_id,
            actual: response.message_id(),
        });
    }
    let tlvs = response.tlvs()?;
    QmiResult::from_tlvs(&tlvs)?.check()?;
    Ok(tlvs)
}

fn ensure_wms(assignment: ClientAssignment) -> Result<(), WmsError> {
    if assignment.service() != ServiceId::WMS {
        return Err(WmsError::UnexpectedService {
            actual: assignment.service(),
        });
    }
    Ok(())
}

/// Errors from encoding or decoding WMS messages.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WmsError {
    Wire(WireError),
    Result(ResultError),
    Lookup(TlvLookupError),
    UnexpectedService { actual: ServiceId },
    UnexpectedMessage { expected: MessageId, actual: MessageId },
    TruncatedList { actual: usize },
    TruncatedRawMessage { actual: usize },
    TruncatedMessageId { actual: usize },
    PduTooLarge { actual: usize },
}

impl fmt::Display for WmsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(error) => error.fmt(formatter),
            Self::Result(error) => error.fmt(formatter),
            Self::Lookup(error) => error.fmt(formatter),
            Self::UnexpectedService { actual } => {
                write!(formatter, "expected WMS service, got {actual}")
            }
            Self::UnexpectedMessage { expected, actual } => {
                write!(formatter, "expected WMS message {expected}, got {actual}")
            }
            Self::TruncatedList { actual } => {
                write!(formatter, "WMS message list TLV has {actual} bytes")
            }
            Self::TruncatedRawMessage { actual } => {
                write!(formatter, "WMS raw message TLV has {actual} bytes")
            }
            Self::TruncatedMessageId { actual } => {
                write!(formatter, "WMS send message ID has {actual} bytes")
            }
            Self::PduTooLarge { actual } => {
                write!(formatter, "SMS PDU is {actual} bytes, above the u16 WMS limit")
            }
        }
    }
}

impl Error for WmsError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Wire(error) => Some(error),
            Self::Result(error) => Some(error),
            Self::Lookup(error) => Some(error),
            _ => None,
        }
    }
}

impl From<WireError> for WmsError {
    fn from(value: WireError) -> Self {
        Self::Wire(value)
    }
}

impl From<ResultError> for WmsError {
    fn from(value: ResultError) -> Self {
        Self::Result(value)
    }
}

impl From<TlvLookupError> for WmsError {
    fn from(value: TlvLookupError) -> Self {
        Self::Lookup(value)
    }
}
