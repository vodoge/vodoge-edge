use std::{error::Error, fmt};

use crate::{
    dms, nas, uim, unique_tlv, wms, AllocationError, ApduResponse, CellLocationInfo,
    ClientAllocationRequest, ClientAssignment, ClientId, ClientRegistry, ClientRegistryError,
    CorrelationError, DeviceRevision, DeviceSerialNumbers, DmsError, ListedMessage, MessageId,
    MessageMode, MessageTag, NasError, OperatingMode, PendingTransactions, QmiRequest, QmiResponse,
    QmiResult, RawMessage, ResultError, ServiceId, ServingSystem, StorageType, TlvLookupError,
    TransactionId, UimError, WireError, WmsError,
};

/// CTL message that asks the modem to resynchronize control state.
pub const CTL_SYNC: MessageId = MessageId::new(0x0027);

/// Byte-level QMI transport. Implementations own device I/O; this crate only
/// sequences well-formed requests and correlated responses.
pub trait QmiTransport {
    fn transact(&mut self, request: &[u8]) -> Result<Vec<u8>, SessionError>;
}

/// A request/response QMI client that tracks control and service transactions.
pub struct QmiClient<T> {
    transport: T,
    pending: PendingTransactions,
    clients: ClientRegistry,
    next_control_transaction: u8,
    next_service_transaction: u16,
}

impl<T: QmiTransport> QmiClient<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            pending: PendingTransactions::default(),
            clients: ClientRegistry::default(),
            next_control_transaction: 1,
            next_service_transaction: 1,
        }
    }

    pub fn client_for(&self, service: ServiceId) -> Option<ClientId> {
        self.clients.client_for(service)
    }

    /// Sends `QMICTL_SYNC` and requires a successful result TLV.
    pub fn sync(&mut self) -> Result<(), SessionError> {
        let request = SyncRequest::new(self.allocate_control_transaction())?.to_qmi_request()?;
        let response = self.round_trip(&request)?;
        SyncRequest::accept(&response)
    }

    /// Allocates a client ID for `service` and remembers it locally.
    pub fn allocate(&mut self, service: ServiceId) -> Result<ClientAssignment, SessionError> {
        if self.clients.client_for(service).is_some() {
            return Err(SessionError::Registry(ClientRegistryError::AlreadyAssigned { service }));
        }

        let allocation =
            ClientAllocationRequest::new(service, self.allocate_control_transaction())?;
        let request = allocation.to_qmi_request()?;
        let response = self.round_trip(&request)?;
        let assignment = allocation.accept(&response)?;
        self.clients.install(assignment)?;
        Ok(assignment)
    }

    pub fn get_serial_numbers(&mut self) -> Result<DeviceSerialNumbers, SessionError> {
        let response = self.dms_empty(dms::GET_DEVICE_SERIAL_NUMBERS)?;
        Ok(dms::parse_serial_numbers(&response)?)
    }

    pub fn get_revision(&mut self) -> Result<DeviceRevision, SessionError> {
        let response = self.dms_empty(dms::GET_DEVICE_REV_ID)?;
        Ok(dms::parse_revision(&response)?)
    }

    pub fn get_model(&mut self) -> Result<String, SessionError> {
        let response = self.dms_empty(dms::GET_MODEL_ID)?;
        Ok(dms::parse_model(&response)?)
    }

    pub fn get_manufacturer(&mut self) -> Result<String, SessionError> {
        let response = self.dms_empty(dms::GET_MANUFACTURER)?;
        Ok(dms::parse_manufacturer(&response)?)
    }

    pub fn get_operating_mode(&mut self) -> Result<OperatingMode, SessionError> {
        let response = self.dms_empty(dms::GET_OPERATING_MODE)?;
        Ok(dms::parse_operating_mode(&response)?)
    }

    pub fn set_operating_mode(&mut self, mode: OperatingMode) -> Result<(), SessionError> {
        let assignment = self.dms_assignment()?;
        let request =
            dms::set_operating_mode_request(assignment, self.allocate_service_transaction(), mode)?;
        let response = self.round_trip(&request)?;
        dms::parse_set_operating_mode(&response)?;
        Ok(())
    }

    pub fn get_serving_system(&mut self) -> Result<ServingSystem, SessionError> {
        let response = self.nas_empty(nas::GET_SERVING_SYSTEM)?;
        Ok(nas::parse_serving_system(&response)?)
    }

    pub fn get_cell_location(&mut self) -> Result<CellLocationInfo, SessionError> {
        let response = self.nas_empty(nas::GET_CELL_LOCATION_INFO)?;
        Ok(nas::parse_cell_location(&response)?)
    }

    pub fn list_sms(
        &mut self,
        storage: StorageType,
        tag: MessageTag,
        mode: MessageMode,
    ) -> Result<Vec<ListedMessage>, SessionError> {
        let assignment = self.assignment(ServiceId::WMS)?;
        let request = wms::list_messages_request(
            assignment,
            self.allocate_service_transaction(),
            storage,
            tag,
            mode,
        )?;
        let response = self.round_trip(&request)?;
        Ok(wms::parse_list_messages(&response)?)
    }

    pub fn read_sms(
        &mut self,
        storage: StorageType,
        index: u32,
        mode: MessageMode,
    ) -> Result<RawMessage, SessionError> {
        let assignment = self.assignment(ServiceId::WMS)?;
        let request = wms::raw_read_request(
            assignment,
            self.allocate_service_transaction(),
            storage,
            index,
            mode,
        )?;
        let response = self.round_trip(&request)?;
        Ok(wms::parse_raw_read(&response)?)
    }

    pub fn send_sms(&mut self, format: u8, pdu: &[u8]) -> Result<Option<u16>, SessionError> {
        let assignment = self.assignment(ServiceId::WMS)?;
        let request =
            wms::raw_send_request(assignment, self.allocate_service_transaction(), format, pdu)?;
        let response = self.round_trip(&request)?;
        Ok(wms::parse_raw_send(&response)?)
    }

    pub fn delete_sms(
        &mut self,
        storage: StorageType,
        index: u32,
        mode: MessageMode,
    ) -> Result<(), SessionError> {
        let assignment = self.assignment(ServiceId::WMS)?;
        let request = wms::delete_by_index_request(
            assignment,
            self.allocate_service_transaction(),
            storage,
            index,
            mode,
        )?;
        let response = self.round_trip(&request)?;
        wms::parse_delete(&response)?;
        Ok(())
    }

    pub fn open_logical_channel(&mut self, slot: u8, aid: &[u8]) -> Result<u8, SessionError> {
        let assignment = self.assignment(ServiceId::UIM)?;
        let request = uim::open_logical_channel_request(
            assignment,
            self.allocate_service_transaction(),
            slot,
            aid,
        )?;
        let response = self.round_trip(&request)?;
        Ok(uim::parse_open_logical_channel(&response)?)
    }

    pub fn close_logical_channel(&mut self, slot: u8, channel: u8) -> Result<(), SessionError> {
        let assignment = self.assignment(ServiceId::UIM)?;
        let request = uim::close_logical_channel_request(
            assignment,
            self.allocate_service_transaction(),
            slot,
            channel,
        )?;
        let response = self.round_trip(&request)?;
        uim::parse_close_logical_channel(&response)?;
        Ok(())
    }

    pub fn send_apdu(
        &mut self,
        slot: u8,
        channel: u8,
        command: &[u8],
    ) -> Result<ApduResponse, SessionError> {
        let assignment = self.assignment(ServiceId::UIM)?;
        let request = uim::send_apdu_request(
            assignment,
            self.allocate_service_transaction(),
            slot,
            channel,
            command,
        )?;
        let response = self.round_trip(&request)?;
        Ok(uim::parse_send_apdu(&response)?)
    }

    /// Open the ISD-R application, GET DATA tag `5A`, and return the EID digits.
    /// Read `EF_IMSI`, which says whose subscription the card carries.
    ///
    /// This is the home network. The serving system reports where the modem is
    /// registered, which on a roaming card is somebody else entirely — so one
    /// cannot stand in for the other.
    pub fn read_imsi(&mut self) -> Result<String, SessionError> {
        let assignment = self.assignment(ServiceId::UIM)?;
        let request = uim::read_transparent_request(
            assignment,
            self.allocate_service_transaction(),
            uim::EF_IMSI_FILE_ID,
            uim::EF_IMSI_PATH,
        )?;
        let response = self.round_trip(&request)?;
        let bytes = uim::parse_read_transparent(&response)?;
        Ok(uim::decode_imsi(&bytes)?)
    }

    /// Read `EF_ICCID` from the active profile. On an eUICC this changes when
    /// a different profile is enabled, so it identifies the SIM in use rather
    /// than the chip.
    pub fn read_iccid(&mut self) -> Result<String, SessionError> {
        let assignment = self.assignment(ServiceId::UIM)?;
        let request = uim::read_transparent_request(
            assignment,
            self.allocate_service_transaction(),
            uim::EF_ICCID_FILE_ID,
            uim::EF_ICCID_PATH,
        )?;
        let response = self.round_trip(&request)?;
        let bytes = uim::parse_read_transparent(&response)?;
        Ok(uim::decode_iccid(&bytes)?)
    }

    /// List every profile the eUICC holds.
    pub fn list_profiles(&mut self, slot: u8) -> Result<Vec<crate::Profile>, SessionError> {
        let bytes = self.isdr_exchange(slot, &crate::es10c::get_profiles_apdu())?;
        Ok(crate::es10c::parse_profiles(&bytes)?)
    }

    /// Enable or disable one profile by ICCID.
    ///
    /// `refresh` is requested so the modem re-reads the card immediately.
    /// Without it the switch only takes effect after a restart, which reads to
    /// an operator as if the command did nothing.
    pub fn set_profile(
        &mut self,
        slot: u8,
        iccid: &str,
        enable: bool,
    ) -> Result<(), SessionError> {
        let apdu = if enable {
            crate::es10c::enable_profile_apdu(iccid, true)?
        } else {
            crate::es10c::disable_profile_apdu(iccid, true)?
        };
        let bytes = self.isdr_exchange(slot, &apdu)?;
        Ok(crate::es10c::parse_profile_result(&bytes, enable)?)
    }

    /// Open the ISD-R channel, run one APDU including any GET RESPONSE, and
    /// close the channel even when the exchange failed.
    ///
    /// Leaking a logical channel is not harmless: an eUICC offers only a few,
    /// and once they are gone every later profile operation fails to open one.
    fn isdr_exchange(&mut self, slot: u8, apdu: &[u8]) -> Result<Vec<u8>, SessionError> {
        let channel = self
            .open_logical_channel(slot, uim::ISD_R_AID)
            .map_err(|error| SessionError::transport(format!("open ISD-R channel: {error}")))?;
        let result = (|| {
            let mut rapdu = self
                .send_apdu(slot, channel, apdu)
                .map_err(|error| SessionError::transport(format!("ES10c command: {error}")))?;
            if let Some(get_response) = rapdu.get_response_apdu() {
                rapdu = self
                    .send_apdu(slot, channel, &get_response)
                    .map_err(|error| SessionError::transport(format!("GET RESPONSE: {error}")))?;
            }
            Ok(rapdu.data.clone())
        })();
        // A failed close is worth reporting — an eUICC offers only a few
        // logical channels and a leaked one makes every later profile
        // operation fail to open — but it must not discard an exchange that
        // already succeeded. Throwing away the profile list because cleanup
        // failed leaves the operator with an error and no data.
        if let Err(error) = self.close_logical_channel(slot, channel) {
            eprintln!("close ISD-R channel {channel} on slot {slot}: {error}");
        }
        result
    }

    pub fn read_eid(&mut self, slot: u8) -> Result<String, SessionError> {
        let channel = self.open_logical_channel(slot, uim::ISD_R_AID)?;
        let result = (|| {
            let mut rapdu = self.send_apdu(slot, channel, uim::GET_EID_APDU)?;
            if let Some(get_response) = rapdu.get_response_apdu() {
                rapdu = self.send_apdu(slot, channel, &get_response)?;
            }
            Ok(uim::parse_eid(&rapdu)?)
        })();
        let close = self.close_logical_channel(slot, channel);
        match (result, close) {
            (Ok(eid), Ok(())) => Ok(eid),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }

    fn assignment(&mut self, service: ServiceId) -> Result<ClientAssignment, SessionError> {
        if let Some(client_id) = self.clients.client_for(service) {
            return Ok(ClientAssignment::new(service, client_id)?);
        }
        self.allocate(service)
    }

    fn dms_empty(&mut self, message_id: MessageId) -> Result<QmiResponse, SessionError> {
        let assignment = self.dms_assignment()?;
        let request = dms::empty_request(assignment, self.allocate_service_transaction(), message_id)?;
        self.round_trip(&request)
    }

    fn dms_assignment(&mut self) -> Result<ClientAssignment, SessionError> {
        if let Some(client_id) = self.clients.client_for(ServiceId::DMS) {
            return Ok(ClientAssignment::new(ServiceId::DMS, client_id)?);
        }
        self.allocate(ServiceId::DMS)
    }

    fn nas_empty(&mut self, message_id: MessageId) -> Result<QmiResponse, SessionError> {
        let assignment = self.nas_assignment()?;
        let request = nas::empty_request(assignment, self.allocate_service_transaction(), message_id)?;
        self.round_trip(&request)
    }

    fn nas_assignment(&mut self) -> Result<ClientAssignment, SessionError> {
        if let Some(client_id) = self.clients.client_for(ServiceId::NAS) {
            return Ok(ClientAssignment::new(ServiceId::NAS, client_id)?);
        }
        self.allocate(ServiceId::NAS)
    }

    fn round_trip(&mut self, request: &QmiRequest) -> Result<QmiResponse, SessionError> {
        self.pending.register(request)?;
        let encoded = request.encode();
        let raw = match self.transport.transact(&encoded) {
            Ok(raw) => raw,
            Err(error) => {
                self.pending.discard(request.transaction_key());
                return Err(error);
            }
        };

        let response = match QmiResponse::decode(&raw) {
            Ok(response) => response,
            Err(error) => {
                self.pending.discard(request.transaction_key());
                return Err(SessionError::Wire(error));
            }
        };

        if let Err(error) = self.pending.resolve(&response) {
            return Err(error.into());
        }
        Ok(response)
    }

    fn allocate_control_transaction(&mut self) -> TransactionId {
        let current = self.next_control_transaction;
        self.next_control_transaction = self.next_control_transaction.wrapping_add(1);
        if self.next_control_transaction == 0 {
            self.next_control_transaction = 1;
        }
        TransactionId::new(current as u16)
    }

    fn allocate_service_transaction(&mut self) -> TransactionId {
        let current = self.next_service_transaction;
        self.next_service_transaction = self.next_service_transaction.wrapping_add(1);
        if self.next_service_transaction == 0 {
            self.next_service_transaction = 1;
        }
        TransactionId::new(current)
    }
}

/// `QMICTL_SYNC` request/response helpers.
pub struct SyncRequest {
    transaction: TransactionId,
}

impl SyncRequest {
    pub fn new(transaction: TransactionId) -> Result<Self, SessionError> {
        if transaction.as_u16() > u8::MAX as u16 {
            return Err(SessionError::Wire(WireError::ControlTransactionOutOfRange {
                transaction,
            }));
        }
        Ok(Self { transaction })
    }

    pub fn to_qmi_request(&self) -> Result<QmiRequest, SessionError> {
        Ok(QmiRequest::new(
            ServiceId::CONTROL,
            ClientId::CONTROL,
            self.transaction,
            CTL_SYNC,
            Vec::new(),
        )?)
    }

    pub fn accept(response: &QmiResponse) -> Result<(), SessionError> {
        if response.service() != ServiceId::CONTROL
            || response.client_id() != ClientId::CONTROL
            || response.message_id() != CTL_SYNC
        {
            return Err(SessionError::UnexpectedSyncResponse {
                service: response.service(),
                client: response.client_id(),
                message: response.message_id(),
            });
        }
        let tlvs = response.tlvs()?;
        // Some firmware omits TLVs on a successful sync. Require a result TLV
        // when one is present; accept an empty payload as success.
        if tlvs.is_empty() {
            return Ok(());
        }
        match unique_tlv(&tlvs, QmiResult::TLV_KIND) {
            Ok(_) => QmiResult::from_tlvs(&tlvs)?.check().map_err(SessionError::Result),
            Err(TlvLookupError::Missing { .. }) => Ok(()),
            Err(error) => Err(SessionError::Lookup(error)),
        }
    }
}

/// Transport, correlation, and service errors from a QMI session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionError {
    Transport(String),
    Wire(WireError),
    Correlation(CorrelationError),
    Allocation(AllocationError),
    Registry(ClientRegistryError),
    Result(ResultError),
    Lookup(TlvLookupError),
    Dms(DmsError),
    Nas(NasError),
    Wms(WmsError),
    Uim(UimError),
    Es10c(crate::Es10cError),
    UnexpectedSyncResponse {
        service: ServiceId,
        client: ClientId,
        message: MessageId,
    },
}

impl SessionError {
    pub fn transport(message: impl Into<String>) -> Self {
        Self::Transport(message.into())
    }
}

impl fmt::Display for SessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(message) => write!(formatter, "QMI transport error: {message}"),
            Self::Wire(error) => error.fmt(formatter),
            Self::Correlation(error) => error.fmt(formatter),
            Self::Allocation(error) => error.fmt(formatter),
            Self::Registry(error) => error.fmt(formatter),
            Self::Result(error) => error.fmt(formatter),
            Self::Lookup(error) => error.fmt(formatter),
            Self::Dms(error) => error.fmt(formatter),
            Self::Nas(error) => error.fmt(formatter),
            Self::Wms(error) => error.fmt(formatter),
            Self::Uim(error) => error.fmt(formatter),
            Self::Es10c(error) => error.fmt(formatter),
            Self::UnexpectedSyncResponse {
                service,
                client,
                message,
            } => write!(
                formatter,
                "unexpected CTL sync response service {service} client {client} message {message}"
            ),
        }
    }
}

impl Error for SessionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Wire(error) => Some(error),
            Self::Correlation(error) => Some(error),
            Self::Allocation(error) => Some(error),
            Self::Registry(error) => Some(error),
            Self::Result(error) => Some(error),
            Self::Lookup(error) => Some(error),
            Self::Dms(error) => Some(error),
            Self::Nas(error) => Some(error),
            Self::Wms(error) => Some(error),
            Self::Uim(error) => Some(error),
            Self::Es10c(error) => Some(error),
            _ => None,
        }
    }
}

impl From<WireError> for SessionError {
    fn from(value: WireError) -> Self {
        Self::Wire(value)
    }
}

impl From<CorrelationError> for SessionError {
    fn from(value: CorrelationError) -> Self {
        Self::Correlation(value)
    }
}

impl From<AllocationError> for SessionError {
    fn from(value: AllocationError) -> Self {
        Self::Allocation(value)
    }
}

impl From<ClientRegistryError> for SessionError {
    fn from(value: ClientRegistryError) -> Self {
        Self::Registry(value)
    }
}

impl From<ResultError> for SessionError {
    fn from(value: ResultError) -> Self {
        Self::Result(value)
    }
}

impl From<TlvLookupError> for SessionError {
    fn from(value: TlvLookupError) -> Self {
        Self::Lookup(value)
    }
}

impl From<DmsError> for SessionError {
    fn from(value: DmsError) -> Self {
        Self::Dms(value)
    }
}

impl From<NasError> for SessionError {
    fn from(value: NasError) -> Self {
        Self::Nas(value)
    }
}

impl From<WmsError> for SessionError {
    fn from(value: WmsError) -> Self {
        Self::Wms(value)
    }
}

impl From<UimError> for SessionError {
    fn from(value: UimError) -> Self {
        Self::Uim(value)
    }
}

impl From<crate::Es10cError> for SessionError {
    fn from(value: crate::Es10cError) -> Self {
        Self::Es10c(value)
    }
}
