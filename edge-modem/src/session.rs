use std::{error::Error, fmt};

use crate::{
    dms, nas, unique_tlv, AllocationError, CellLocationInfo, ClientAllocationRequest,
    ClientAssignment, ClientId, ClientRegistry, ClientRegistryError, CorrelationError,
    DeviceRevision, DeviceSerialNumbers, DmsError, MessageId, NasError, OperatingMode,
    PendingTransactions, QmiRequest, QmiResponse, QmiResult, ResultError, ServiceId, ServingSystem,
    TlvLookupError, TransactionId, WireError,
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
