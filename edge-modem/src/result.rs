use std::{error::Error, fmt};

use crate::{unique_tlv, Tlv, TlvLookupError};

/// Standard QMI result TLV (`0x02`): two little-endian `u16` values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QmiResult {
    pub result: u16,
    pub error: u16,
}

impl QmiResult {
    pub const TLV_KIND: u8 = 0x02;
    pub const SUCCESS: u16 = 0;

    pub fn from_tlvs(tlvs: &[Tlv]) -> Result<Self, ResultError> {
        let tlv = unique_tlv(tlvs, Self::TLV_KIND)?;
        if tlv.value.len() != 4 {
            return Err(ResultError::Malformed {
                actual: tlv.value.len(),
            });
        }

        Ok(Self {
            result: u16::from_le_bytes([tlv.value[0], tlv.value[1]]),
            error: u16::from_le_bytes([tlv.value[2], tlv.value[3]]),
        })
    }

    pub fn is_success(self) -> bool {
        self.result == Self::SUCCESS && self.error == 0
    }

    pub fn check(self) -> Result<(), ResultError> {
        if self.result != Self::SUCCESS {
            return Err(ResultError::ModemRejected {
                result: self.result,
                error: self.error,
            });
        }
        if self.error != 0 {
            return Err(ResultError::SuccessWithErrorCode { error: self.error });
        }
        Ok(())
    }
}

/// Errors from the standard QMI result TLV.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResultError {
    Lookup(TlvLookupError),
    Malformed { actual: usize },
    ModemRejected { result: u16, error: u16 },
    SuccessWithErrorCode { error: u16 },
}

impl fmt::Display for ResultError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lookup(error) => error.fmt(formatter),
            Self::Malformed { actual } => {
                write!(formatter, "QMI result TLV has {actual} bytes, expected four")
            }
            Self::ModemRejected { result, error } => {
                write!(formatter, "QMI request rejected with result {result} error {error}")
            }
            Self::SuccessWithErrorCode { error } => {
                write!(formatter, "QMI result reports success with error code {error}")
            }
        }
    }
}

impl Error for ResultError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Lookup(error) => Some(error),
            _ => None,
        }
    }
}

impl From<TlvLookupError> for ResultError {
    fn from(value: TlvLookupError) -> Self {
        Self::Lookup(value)
    }
}
