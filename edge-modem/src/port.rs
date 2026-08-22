use edge_core::{Bearer, RegistrationEvidence};

use crate::wms::StorageType;
use crate::{ListedMessage, RawMessage, SessionError};

/// How a modem control channel is reached. Implementations must not share a
/// channel across devices.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportKind {
    Qmi,
    At,
    Mbim,
    Pcsc,
}

impl TransportKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Qmi => "qmi",
            Self::At => "at",
            Self::Mbim => "mbim",
            Self::Pcsc => "pcsc",
        }
    }
}

/// One physical modem. Tests inject a fake; production uses QMI first.
pub trait ModemPort {
    fn transport_kind(&self) -> TransportKind;
    fn imei(&mut self) -> Result<String, PortError>;
    fn firmware(&mut self) -> Result<String, PortError>;
    fn registration_evidence(&mut self) -> Result<Vec<RegistrationEvidence>, PortError>;
    /// Every stored message, from every store the modem keeps them in.
    ///
    /// Both stores, not just the SIM. A modem decides for itself where a
    /// received message goes, and these EC20s put them in their own memory —
    /// so a reader that only looked at the SIM saw an empty inbox while five
    /// messages sat on the device.
    fn list_sms(&mut self) -> Result<Vec<ListedMessage>, PortError>;
    /// Reads one message from the store it was listed in. Indexes are per
    /// store, so the same number means a different message in the other one.
    fn read_sms(&mut self, storage: StorageType, index: u32) -> Result<RawMessage, PortError>;
    fn delete_sms(&mut self, storage: StorageType, index: u32) -> Result<(), PortError>;
    fn send_pdu(&mut self, pdu: &[u8]) -> Result<(), PortError> {
        self.send_on(Bearer::Cellular, pdu)
    }
    fn send_on(&mut self, bearer: Bearer, pdu: &[u8]) -> Result<(), PortError>;
}

/// A transport that exists in the discovery chain but is not implemented yet.
pub struct UnsupportedPort {
    kind: TransportKind,
}

impl UnsupportedPort {
    pub fn at() -> Self {
        Self {
            kind: TransportKind::At,
        }
    }

    pub fn mbim() -> Self {
        Self {
            kind: TransportKind::Mbim,
        }
    }

    pub fn pcsc() -> Self {
        Self {
            kind: TransportKind::Pcsc,
        }
    }
}

impl ModemPort for UnsupportedPort {
    fn transport_kind(&self) -> TransportKind {
        self.kind
    }

    fn imei(&mut self) -> Result<String, PortError> {
        Err(PortError::Unsupported(self.kind))
    }

    fn firmware(&mut self) -> Result<String, PortError> {
        Err(PortError::Unsupported(self.kind))
    }

    fn registration_evidence(&mut self) -> Result<Vec<RegistrationEvidence>, PortError> {
        Err(PortError::Unsupported(self.kind))
    }

    fn list_sms(&mut self) -> Result<Vec<ListedMessage>, PortError> {
        Err(PortError::Unsupported(self.kind))
    }

    fn read_sms(&mut self, _storage: StorageType, _index: u32) -> Result<RawMessage, PortError> {
        Err(PortError::Unsupported(self.kind))
    }

    fn delete_sms(&mut self, _storage: StorageType, _index: u32) -> Result<(), PortError> {
        Err(PortError::Unsupported(self.kind))
    }

    fn send_on(&mut self, _bearer: Bearer, _pdu: &[u8]) -> Result<(), PortError> {
        Err(PortError::Unsupported(self.kind))
    }
}

/// Port-level errors. Unsupported variants keep the discovery chain moving.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PortError {
    Unsupported(TransportKind),
    Session(String),
    MissingImei,
    PlanUnavailable(String),
}

impl std::fmt::Display for PortError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported(kind) => write!(formatter, "{} transport is not implemented", kind.as_str()),
            Self::Session(message) => formatter.write_str(message),
            Self::MissingImei => formatter.write_str("modem did not return an IMEI"),
            Self::PlanUnavailable(reason) => write!(formatter, "no SMS bearer: {reason}"),
        }
    }
}

impl std::error::Error for PortError {}

impl From<SessionError> for PortError {
    fn from(value: SessionError) -> Self {
        Self::Session(value.to_string())
    }
}
