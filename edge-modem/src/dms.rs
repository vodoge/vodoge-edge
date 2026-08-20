use std::{error::Error, fmt, str};

use crate::{
    unique_tlv, ClientAssignment, ClientId, MessageId, QmiRequest, QmiResponse, QmiResult,
    ResultError, ServiceId, Tlv, TlvLookupError, TransactionId, WireError,
};

pub const GET_MANUFACTURER: MessageId = MessageId::new(0x0021);
pub const GET_MODEL_ID: MessageId = MessageId::new(0x0022);
pub const GET_DEVICE_REV_ID: MessageId = MessageId::new(0x0023);
pub const GET_DEVICE_SERIAL_NUMBERS: MessageId = MessageId::new(0x0025);
pub const GET_OPERATING_MODE: MessageId = MessageId::new(0x002d);
pub const SET_OPERATING_MODE: MessageId = MessageId::new(0x002e);

const STRING_MANUFACTURER: u8 = 0x01;
const STRING_MODEL: u8 = 0x01;
const STRING_DEVICE_REV: u8 = 0x01;
const STRING_IMEI: u8 = 0x11;
const STRING_ESN: u8 = 0x10;
const STRING_MEID: u8 = 0x12;
const OPERATING_MODE: u8 = 0x01;

/// Identifiers returned by `QMI_DMS_GET_DEVICE_SERIAL_NUMBERS`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceSerialNumbers {
    pub imei: Option<String>,
    pub esn: Option<String>,
    pub meid: Option<String>,
}

/// Firmware identity returned by `QMI_DMS_GET_DEVICE_REV_ID`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceRevision {
    pub device_rev_id: String,
}

/// QMI DMS operating mode values used by radio on/off and reset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperatingMode {
    Online,
    LowPower,
    FactoryTest,
    Offline,
    Resetting,
    ShuttingDown,
    PersistentLowPower,
    ModeOnlyLowPower,
    Unknown(u8),
}

impl OperatingMode {
    pub fn from_wire(value: u8) -> Self {
        match value {
            0 => Self::Online,
            1 => Self::LowPower,
            2 => Self::FactoryTest,
            3 => Self::Offline,
            4 => Self::Resetting,
            5 => Self::ShuttingDown,
            6 => Self::PersistentLowPower,
            7 => Self::ModeOnlyLowPower,
            other => Self::Unknown(other),
        }
    }

    pub fn as_u8(self) -> u8 {
        match self {
            Self::Online => 0,
            Self::LowPower => 1,
            Self::FactoryTest => 2,
            Self::Offline => 3,
            Self::Resetting => 4,
            Self::ShuttingDown => 5,
            Self::PersistentLowPower => 6,
            Self::ModeOnlyLowPower => 7,
            Self::Unknown(value) => value,
        }
    }
}

/// Builds an empty DMS request for the allocated client.
pub fn empty_request(
    assignment: ClientAssignment,
    transaction: TransactionId,
    message_id: MessageId,
) -> Result<QmiRequest, DmsError> {
    ensure_dms(assignment)?;
    Ok(QmiRequest::new(
        ServiceId::DMS,
        assignment.client_id(),
        transaction,
        message_id,
        Vec::new(),
    )?)
}

pub fn get_serial_numbers_request(
    assignment: ClientAssignment,
    transaction: TransactionId,
) -> Result<QmiRequest, DmsError> {
    empty_request(assignment, transaction, GET_DEVICE_SERIAL_NUMBERS)
}

pub fn get_revision_request(
    assignment: ClientAssignment,
    transaction: TransactionId,
) -> Result<QmiRequest, DmsError> {
    empty_request(assignment, transaction, GET_DEVICE_REV_ID)
}

pub fn get_model_request(
    assignment: ClientAssignment,
    transaction: TransactionId,
) -> Result<QmiRequest, DmsError> {
    empty_request(assignment, transaction, GET_MODEL_ID)
}

pub fn get_manufacturer_request(
    assignment: ClientAssignment,
    transaction: TransactionId,
) -> Result<QmiRequest, DmsError> {
    empty_request(assignment, transaction, GET_MANUFACTURER)
}

pub fn get_operating_mode_request(
    assignment: ClientAssignment,
    transaction: TransactionId,
) -> Result<QmiRequest, DmsError> {
    empty_request(assignment, transaction, GET_OPERATING_MODE)
}

pub fn set_operating_mode_request(
    assignment: ClientAssignment,
    transaction: TransactionId,
    mode: OperatingMode,
) -> Result<QmiRequest, DmsError> {
    ensure_dms(assignment)?;
    let mode_tlv = Tlv::new(OPERATING_MODE, vec![mode.as_u8()])?;
    Ok(QmiRequest::from_tlvs(
        ServiceId::DMS,
        assignment.client_id(),
        transaction,
        SET_OPERATING_MODE,
        &[mode_tlv],
    )?)
}

pub fn parse_serial_numbers(response: &QmiResponse) -> Result<DeviceSerialNumbers, DmsError> {
    let tlvs = expect_dms(response, GET_DEVICE_SERIAL_NUMBERS)?;
    Ok(DeviceSerialNumbers {
        imei: optional_string(&tlvs, STRING_IMEI)?,
        esn: optional_string(&tlvs, STRING_ESN)?,
        meid: optional_string(&tlvs, STRING_MEID)?,
    })
}

pub fn parse_revision(response: &QmiResponse) -> Result<DeviceRevision, DmsError> {
    let tlvs = expect_dms(response, GET_DEVICE_REV_ID)?;
    Ok(DeviceRevision {
        device_rev_id: required_string(&tlvs, STRING_DEVICE_REV)?,
    })
}

pub fn parse_model(response: &QmiResponse) -> Result<String, DmsError> {
    let tlvs = expect_dms(response, GET_MODEL_ID)?;
    required_string(&tlvs, STRING_MODEL)
}

pub fn parse_manufacturer(response: &QmiResponse) -> Result<String, DmsError> {
    let tlvs = expect_dms(response, GET_MANUFACTURER)?;
    required_string(&tlvs, STRING_MANUFACTURER)
}

pub fn parse_operating_mode(response: &QmiResponse) -> Result<OperatingMode, DmsError> {
    let tlvs = expect_dms(response, GET_OPERATING_MODE)?;
    let tlv = unique_tlv(&tlvs, OPERATING_MODE)?;
    if tlv.value.len() != 1 {
        return Err(DmsError::MalformedOperatingMode {
            actual: tlv.value.len(),
        });
    }
    Ok(OperatingMode::from_wire(tlv.value[0]))
}

pub fn parse_set_operating_mode(response: &QmiResponse) -> Result<(), DmsError> {
    expect_dms(response, SET_OPERATING_MODE).map(|_| ())
}

fn expect_dms(response: &QmiResponse, message_id: MessageId) -> Result<Vec<Tlv>, DmsError> {
    if response.service() != ServiceId::DMS {
        return Err(DmsError::UnexpectedService {
            actual: response.service(),
        });
    }
    if response.client_id() == ClientId::CONTROL {
        return Err(DmsError::Wire(WireError::ServiceRequiresAllocatedClient {
            service: ServiceId::DMS,
        }));
    }
    if response.message_id() != message_id {
        return Err(DmsError::UnexpectedMessage {
            expected: message_id,
            actual: response.message_id(),
        });
    }

    let tlvs = response.tlvs()?;
    QmiResult::from_tlvs(&tlvs)?.check()?;
    Ok(tlvs)
}

fn ensure_dms(assignment: ClientAssignment) -> Result<(), DmsError> {
    if assignment.service() != ServiceId::DMS {
        return Err(DmsError::UnexpectedService {
            actual: assignment.service(),
        });
    }
    Ok(())
}

fn required_string(tlvs: &[Tlv], kind: u8) -> Result<String, DmsError> {
    optional_string(tlvs, kind)?.ok_or(DmsError::Lookup(TlvLookupError::Missing { kind }))
}

fn optional_string(tlvs: &[Tlv], kind: u8) -> Result<Option<String>, DmsError> {
    match unique_tlv(tlvs, kind) {
        Ok(tlv) => Ok(Some(decode_string(&tlv.value, kind)?)),
        Err(TlvLookupError::Missing { .. }) => Ok(None),
        Err(error) => Err(DmsError::Lookup(error)),
    }
}

fn decode_string(bytes: &[u8], kind: u8) -> Result<String, DmsError> {
    let end = bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len());
    str::from_utf8(&bytes[..end])
        .map(|value| value.to_owned())
        .map_err(|_| DmsError::InvalidUtf8 { kind })
}

/// Errors from encoding or decoding DMS messages.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DmsError {
    Wire(WireError),
    Result(ResultError),
    Lookup(TlvLookupError),
    UnexpectedService { actual: ServiceId },
    UnexpectedMessage { expected: MessageId, actual: MessageId },
    InvalidUtf8 { kind: u8 },
    MalformedOperatingMode { actual: usize },
}

impl fmt::Display for DmsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(error) => error.fmt(formatter),
            Self::Result(error) => error.fmt(formatter),
            Self::Lookup(error) => error.fmt(formatter),
            Self::UnexpectedService { actual } => {
                write!(formatter, "expected DMS service, got {actual}")
            }
            Self::UnexpectedMessage { expected, actual } => {
                write!(formatter, "expected DMS message {expected}, got {actual}")
            }
            Self::InvalidUtf8 { kind } => {
                write!(formatter, "DMS TLV 0x{kind:02x} is not valid UTF-8")
            }
            Self::MalformedOperatingMode { actual } => {
                write!(formatter, "operating mode TLV has {actual} bytes, expected one")
            }
        }
    }
}

impl Error for DmsError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Wire(error) => Some(error),
            Self::Result(error) => Some(error),
            Self::Lookup(error) => Some(error),
            _ => None,
        }
    }
}

impl From<WireError> for DmsError {
    fn from(value: WireError) -> Self {
        Self::Wire(value)
    }
}

impl From<ResultError> for DmsError {
    fn from(value: ResultError) -> Self {
        Self::Result(value)
    }
}

impl From<TlvLookupError> for DmsError {
    fn from(value: TlvLookupError) -> Self {
        Self::Lookup(value)
    }
}
