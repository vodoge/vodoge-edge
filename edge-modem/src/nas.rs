use std::{error::Error, fmt};

use crate::{
    unique_tlv, ClientAssignment, ClientId, MessageId, QmiRequest, QmiResponse, QmiResult,
    ResultError, ServiceId, Tlv, TlvLookupError, TransactionId, WireError,
};

pub const GET_SERVING_SYSTEM: MessageId = MessageId::new(0x0024);
pub const GET_CELL_LOCATION_INFO: MessageId = MessageId::new(0x0043);

const SERVING_SYSTEM: u8 = 0x01;
const CURRENT_PLMN: u8 = 0x12;
const LTE_INTRAFREQUENCY: u8 = 0x13;

/// QMI NAS registration_state values from the serving-system TLV.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NasRegistrationState {
    NotRegistered,
    Registered,
    Searching,
    Denied,
    Unknown(u8),
}

impl NasRegistrationState {
    pub fn from_wire(value: u8) -> Self {
        match value {
            0 => Self::NotRegistered,
            1 => Self::Registered,
            2 => Self::Searching,
            3 => Self::Denied,
            other => Self::Unknown(other),
        }
    }

    pub fn as_u8(self) -> u8 {
        match self {
            Self::NotRegistered => 0,
            Self::Registered => 1,
            Self::Searching => 2,
            Self::Denied => 3,
            Self::Unknown(value) => value,
        }
    }

    pub fn is_registered(self) -> bool {
        matches!(self, Self::Registered)
    }
}

/// Parsed `QMI_NAS_GET_SERVING_SYSTEM` body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServingSystem {
    pub registration_state: NasRegistrationState,
    pub ps_attached: bool,
    pub radio_interface: Option<u8>,
    pub mcc: Option<u16>,
    pub mnc: Option<u16>,
}

/// Parsed LTE intra-frequency cell from `QMI_NAS_GET_CELL_LOCATION_INFO`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LteCellLocation {
    pub mcc: String,
    pub mnc: String,
    pub tac: u16,
    pub global_cell_id: u32,
    pub earfcn: u16,
}

impl LteCellLocation {
    pub fn is_complete(&self) -> bool {
        !self.mcc.is_empty() && !self.mnc.is_empty() && self.global_cell_id != 0
    }
}

/// Parsed cell-location response. Other RATs can be added without changing
/// the arbitration contract.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CellLocationInfo {
    pub lte: Option<LteCellLocation>,
}

pub fn empty_request(
    assignment: ClientAssignment,
    transaction: TransactionId,
    message_id: MessageId,
) -> Result<QmiRequest, NasError> {
    ensure_nas(assignment)?;
    Ok(QmiRequest::new(
        ServiceId::NAS,
        assignment.client_id(),
        transaction,
        message_id,
        Vec::new(),
    )?)
}

pub fn parse_serving_system(response: &QmiResponse) -> Result<ServingSystem, NasError> {
    let tlvs = expect_nas(response, GET_SERVING_SYSTEM)?;
    let serving = unique_tlv(&tlvs, SERVING_SYSTEM)?;
    if serving.value.len() < 3 {
        return Err(NasError::TruncatedServingSystem {
            actual: serving.value.len(),
        });
    }

    let radio_interface = if serving.value.len() >= 6 {
        let count = serving.value[4] as usize;
        if count > 0 && serving.value.len() >= 5 + count {
            Some(serving.value[5])
        } else {
            None
        }
    } else {
        None
    };

    let mut mcc = None;
    let mut mnc = None;
    if let Ok(plmn) = unique_tlv(&tlvs, CURRENT_PLMN) {
        if plmn.value.len() >= 4 {
            mcc = Some(u16::from_le_bytes([plmn.value[0], plmn.value[1]]));
            mnc = Some(u16::from_le_bytes([plmn.value[2], plmn.value[3]]));
        }
    }

    Ok(ServingSystem {
        registration_state: NasRegistrationState::from_wire(serving.value[0]),
        ps_attached: serving.value[2] == 1,
        radio_interface,
        mcc,
        mnc,
    })
}

pub fn parse_cell_location(response: &QmiResponse) -> Result<CellLocationInfo, NasError> {
    let tlvs = expect_nas(response, GET_CELL_LOCATION_INFO)?;
    let mut info = CellLocationInfo::default();

    match unique_tlv(&tlvs, LTE_INTRAFREQUENCY) {
        Ok(lte) if lte.value.len() >= 18 => {
            let (mcc, mnc) = decode_bcd_plmn(&lte.value[1..4])?;
            info.lte = Some(LteCellLocation {
                mcc,
                mnc,
                tac: u16::from_le_bytes([lte.value[4], lte.value[5]]),
                global_cell_id: u32::from_le_bytes([
                    lte.value[6],
                    lte.value[7],
                    lte.value[8],
                    lte.value[9],
                ]),
                earfcn: u16::from_le_bytes([lte.value[10], lte.value[11]]),
            });
        }
        Ok(_) | Err(TlvLookupError::Missing { .. }) => {}
        Err(error) => return Err(error.into()),
    }

    if info.lte.is_none() {
        return Err(NasError::NoCellLocation);
    }
    Ok(info)
}

fn expect_nas(response: &QmiResponse, message_id: MessageId) -> Result<Vec<Tlv>, NasError> {
    if response.service() != ServiceId::NAS {
        return Err(NasError::UnexpectedService {
            actual: response.service(),
        });
    }
    if response.client_id() == ClientId::CONTROL {
        return Err(NasError::Wire(WireError::ServiceRequiresAllocatedClient {
            service: ServiceId::NAS,
        }));
    }
    if response.message_id() != message_id {
        return Err(NasError::UnexpectedMessage {
            expected: message_id,
            actual: response.message_id(),
        });
    }
    let tlvs = response.tlvs()?;
    QmiResult::from_tlvs(&tlvs)?.check()?;
    Ok(tlvs)
}

fn ensure_nas(assignment: ClientAssignment) -> Result<(), NasError> {
    if assignment.service() != ServiceId::NAS {
        return Err(NasError::UnexpectedService {
            actual: assignment.service(),
        });
    }
    Ok(())
}

fn decode_bcd_plmn(plmn: &[u8]) -> Result<(String, String), NasError> {
    if plmn.len() < 3 {
        return Err(NasError::TruncatedPlmn { actual: plmn.len() });
    }
    let mcc1 = plmn[0] & 0x0f;
    let mcc2 = (plmn[0] >> 4) & 0x0f;
    let mcc3 = plmn[1] & 0x0f;
    let mnc3 = (plmn[1] >> 4) & 0x0f;
    let mnc1 = plmn[2] & 0x0f;
    let mnc2 = (plmn[2] >> 4) & 0x0f;
    let mcc = format!("{mcc1}{mcc2}{mcc3}");
    let mnc = if mnc3 == 0x0f {
        format!("{mnc1}{mnc2}")
    } else {
        format!("{mnc1}{mnc2}{mnc3}")
    };
    Ok((mcc, mnc))
}

/// Errors from encoding or decoding NAS messages.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NasError {
    Wire(WireError),
    Result(ResultError),
    Lookup(TlvLookupError),
    UnexpectedService { actual: ServiceId },
    UnexpectedMessage { expected: MessageId, actual: MessageId },
    TruncatedServingSystem { actual: usize },
    TruncatedPlmn { actual: usize },
    NoCellLocation,
}

impl fmt::Display for NasError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(error) => error.fmt(formatter),
            Self::Result(error) => error.fmt(formatter),
            Self::Lookup(error) => error.fmt(formatter),
            Self::UnexpectedService { actual } => {
                write!(formatter, "expected NAS service, got {actual}")
            }
            Self::UnexpectedMessage { expected, actual } => {
                write!(formatter, "expected NAS message {expected}, got {actual}")
            }
            Self::TruncatedServingSystem { actual } => {
                write!(formatter, "serving system TLV has {actual} bytes, expected at least 3")
            }
            Self::TruncatedPlmn { actual } => {
                write!(formatter, "PLMN encoding has {actual} bytes, expected 3")
            }
            Self::NoCellLocation => formatter.write_str("cell location response has no usable RAT TLV"),
        }
    }
}

impl Error for NasError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Wire(error) => Some(error),
            Self::Result(error) => Some(error),
            Self::Lookup(error) => Some(error),
            _ => None,
        }
    }
}

impl From<WireError> for NasError {
    fn from(value: WireError) -> Self {
        Self::Wire(value)
    }
}

impl From<ResultError> for NasError {
    fn from(value: ResultError) -> Self {
        Self::Result(value)
    }
}

impl From<TlvLookupError> for NasError {
    fn from(value: TlvLookupError) -> Self {
        Self::Lookup(value)
    }
}
