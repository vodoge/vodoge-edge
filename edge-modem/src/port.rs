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
    /// A SIM reached through an external smart-card reader instead of through
    /// the modem. Named here and nowhere else -- see [`UnsupportedPort::pcsc`]
    /// for why nothing implements it and nothing is going to.
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
    /// Reads a window of storage slots directly, reporting the inbound
    /// messages found in them.
    ///
    /// A listing is not always complete. On the bench EC20s
    /// `QMI_WMS_LIST_MESSAGES` accepts exactly one tag -- unread -- and
    /// refuses every other, so a message anyone has marked read cannot be
    /// named by any listing the firmware offers, and the old collector lost
    /// such messages permanently while they went on occupying storage.
    /// Reading the slot finds them.
    ///
    /// A window rather than the whole store because a read costs real time on
    /// a serial-speed control channel: the caller decides how much of a pass
    /// to spend on the slow path and how far it walks between passes.
    ///
    /// The default finds nothing, which is the right answer for a transport
    /// whose listing is already complete.
    fn sweep_slots(&mut self, _first: u32, _count: u32) -> Result<Vec<ListedMessage>, PortError> {
        Ok(Vec::new())
    }
    /// Reads one message from the store it was listed in. Indexes are per
    /// store, so the same number means a different message in the other one.
    fn read_sms(&mut self, storage: StorageType, index: u32) -> Result<RawMessage, PortError>;
    fn delete_sms(&mut self, storage: StorageType, index: u32) -> Result<(), PortError>;
    fn send_pdu(&mut self, pdu: &[u8]) -> Result<(), PortError> {
        self.send_on(Bearer::Cellular, pdu)
    }
    fn send_on(&mut self, bearer: Bearer, pdu: &[u8]) -> Result<(), PortError>;
}

/// A transport this build names but does not implement.
///
/// Every call fails, and the failure means *this build has no code for that
/// transport* -- not *no device was found*, not *the device refused*. The port
/// opens nothing, sends nothing, and never looks for hardware, so none of what
/// it returns is evidence about any device. Keeping those apart is most of the
/// value of the type: "no device found" sends someone off to check cables, and
/// on this deployment there is nobody who can go check them (`goal.md:161`).
///
/// So no method here may report success -- including the ones whose natural
/// empty answer would pass for one. [`ModemPort::sweep_slots`] defaults to
/// `Ok(vec![])`, which is right for a transport whose listing is already
/// complete and wrong here, because a caller cannot tell "swept, nothing in
/// those slots" from "there is no transport". It is overridden below.
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

    /// PC/SC: the SIM reached through an external smart-card reader.
    ///
    /// This is not "not implemented yet". It is not implementable on this
    /// deployment, and it is left a stub deliberately (T052, decided
    /// 2026-08-25).
    ///
    /// PC/SC needs a reader physically plugged into the edge machine, and
    /// `docs/goals/vodoge-vowifi-call/goal.md:161` records the constraint that
    /// kills it: **nobody can physically touch that hardware.** The modems
    /// reach the VM over USB/IP and there is no one at the far end to plug
    /// anything in. Code written against that could never be run, never be
    /// tested against a card, never be falsified -- and a PC/SC path that has
    /// never met a reader is worse than none, because it would read as
    /// implemented.
    ///
    /// Two further gaps, both cheap and neither sufficient: no `pcsc` crate in
    /// any manifest in this workspace, and no PC/SC step in
    /// [`crate::DeviceEnumerator`], whose steps are QMI, then MBIM, then
    /// VID/AT -- so a finished `PcscPort` would still have nothing routing to
    /// it.
    ///
    /// If a reader is ever attached, the first move is not this file: it is
    /// teaching `DeviceEnumerator` to enumerate readers, since that decides
    /// what a `PcscPort` is handed at all. And `tests/hardware_layer.rs` goes
    /// red the moment this stops being a stub -- that red is the correct
    /// signal. Claim it and rewrite those assertions; do not route around it.
    ///
    /// Full account:
    /// `docs/goals/vodoge-vowifi-call/notes/T052-pcsc-reader.md`.
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

    /// Overridden away from the trait default, which answers `Ok(vec![])`. An
    /// empty success out of here is a lie the caller cannot detect.
    fn sweep_slots(&mut self, _first: u32, _count: u32) -> Result<Vec<ListedMessage>, PortError> {
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
            Self::Unsupported(kind) => write!(
                formatter,
                "{} transport is not implemented in this build; no device was contacted",
                kind.as_str()
            ),
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
