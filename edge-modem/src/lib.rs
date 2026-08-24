//! Pure QMUX/QMI framing and correlation primitives.
//!
//! This crate deliberately has no OS device dependency. A later cdc-wdm or
//! QMI-over-MBIM adapter owns byte I/O, while this crate owns the binary
//! invariants needed before a frame can be sent or accepted.

mod aka;
mod at;
#[cfg(target_os = "linux")]
mod cdc_wdm;
mod channels;
mod discovery;
mod dms;
mod es10c;
mod es9p;
mod fake;
mod inbox;
mod nas;
mod pdu;
mod port;
mod qmi_port;
mod report;
mod restore;
mod result;
mod send;
mod session;
mod uim;
mod usb;
mod ussd;
mod wms;

use std::{
    collections::HashMap,
    error::Error,
    fmt,
};

pub use aka::{
    authenticate_apdu, classify_authenticate, csim_command, decode_hex, hex_upper,
    parse_csim_answer, selected_aid, usim_authenticate, verify_usim_selected, AkaError, AkaOutcome,
    BasicChannel, CsimChannel, AKA_TIMEOUT, AUTN_BYTES, AUTS_BYTES, CK_BYTES, IK_BYTES, KC_BYTES,
    RAND_BYTES, RES_MAX_BYTES, RES_MIN_BYTES, STATUS_FCP_APDU, SW_INCORRECT_MAC,
    USIM_ADF_AID_PREFIX,
};
pub use at::{
    at_control_ports, at_port_for_qmi, first_bare_digits, handle_lease_request, lease_socket_path,
    usb_device_of_at, ArbiterWaiting, AtError, AtExchange, AtLease, AtPort, LeaseFailure,
    ModemArbiter, ModemLease, ModemPriority, AT_CONTROL_INTERFACE, DEFAULT_LEASE_SOCKET,
    DEFAULT_LEASE_TIMEOUT, LEASE_SOCKET_ENV, MAX_LEASE_CLIENTS, MAX_LEASE_TIMEOUT,
};
#[cfg(unix)]
pub use at::{bind_lease_socket, serve_connection, serve_lease};
pub use usb::{
    recover_usb_device, reset_for_qmi, usb_device_of_qmi, usb_devnum, usb_identity, UsbError,
    UsbIdentity, UsbRecovery, UsbReset,
};
pub use ussd::{
    cancel as ussd_cancel, parse_reply as parse_ussd_reply, request as ussd_request, UssdReply,
    UssdStage,
};
pub use report::{
    collect as collect_report, parse_cops_scan, parse_creg, parse_csq, ModemReport, Registration,
    ScannedOperator, Signal,
};
pub use es10c::{
    authenticate_server_payload, bound_profile_package_segments, cancel_session_payload,
    configured_addresses_payload, confirmation_code_required, euicc_challenge_payload,
    euicc_info1_payload, euicc_info2_payload, get_eid_payload, get_profiles_payload,
    list_notification_payload, parse_authenticate_server_response, parse_cancel_session_response,
    parse_configured_addresses, parse_eid_response, parse_euicc_challenge, parse_euicc_info1,
    parse_euicc_info2, parse_installation_result, parse_notification_metadata_list,
    parse_pending_notifications, parse_prepare_download_response, parse_profile_metadata,
    parse_remove_notification_response, prepare_download_payload, remove_notification_payload,
    retrieve_notifications_payload, smdp_signed2_transaction_id, store_data_chain, tac_from_imei,
    BppSegment, CancelSessionReason, ConfiguredAddresses, Es10cError, EuiccInfo1, EuiccInfo2,
    InstallationResult, NotificationMetadata, PendingNotification, Profile, ProfileMetadata,
    EUICC_CHALLENGE_BYTES, MAX_STORE_DATA_BLOCKS, MAX_STORE_DATA_BYTES, STORE_DATA_BLOCK_BYTES,
};
pub use es9p::{
    hash_confirmation_code, initiate_authentication_request, load_trust_anchors,
    parse_activation_code, parse_initiate_authentication, trust_dir, verify_server_credentials,
    ActivationCode, Acknowledgement, AuthenticationStart, BoundProfile, ClientAuthentication,
    Es9pClient, Es9pError, HttpResponse, TrustAnchor, Verification, ADMIN_PROTOCOL,
    AUTHENTICATE_CLIENT_PATH, CANCEL_SESSION_PATH, DEFAULT_TRUST_DIR,
    GET_BOUND_PROFILE_PACKAGE_PATH, HANDLE_NOTIFICATION_PATH, INITIATE_AUTHENTICATION_PATH,
    TRUST_DIR_ENV, USER_AGENT,
};
#[cfg(target_os = "linux")]
pub use cdc_wdm::CdcWdmDevice;
pub use channels::LogicalChannels;
pub use discovery::{discover, DeviceEnumerator, DiscoveredModem, FakeEnumerator};
pub use fake::FakeModem;
pub use inbox::{
    collect_inbound, collect_inbound_sweeping, delete_inbound, fragment_fingerprint, seen_before,
    CollectedMessage, InboxPass,
};
pub use port::{ModemPort, PortError, TransportKind, UnsupportedPort};
pub use restore::with_restore;
pub use pdu::{encode_submit, PduError};
pub use send::{send_with_plan, SendOutcome};
pub use dms::{
    empty_request, get_manufacturer_request, get_model_request, get_operating_mode_request,
    get_revision_request, get_serial_numbers_request, parse_manufacturer, parse_model,
    parse_operating_mode, parse_revision, parse_serial_numbers, parse_set_operating_mode,
    set_operating_mode_request, DeviceRevision, DeviceSerialNumbers, DmsError, OperatingMode,
    GET_DEVICE_REV_ID, GET_DEVICE_SERIAL_NUMBERS, GET_MANUFACTURER, GET_MODEL_ID,
    GET_OPERATING_MODE, SET_OPERATING_MODE,
};
pub use nas::{
    parse_cell_location, parse_serving_system, CellLocationInfo, LteCellLocation, NasError,
    NasRegistrationState, ServingSystem, GET_CELL_LOCATION_INFO, GET_SERVING_SYSTEM,
};
pub use result::{QmiResult, ResultError};
pub use session::{
    parse_cfun, parse_cpin, parse_qinistat, parse_qsimstat, restart_radio, CardEvidence, CardState,
    DownloadOutcome, DownloadRequest, EsimAuthenticationInputs, EsimLocalInfo, EuiccSnapshot,
    HttpStep, IsdrSession, ModuleRadio, QmiClient, QmiTransport, RestartError, RestartReport,
    SegmentTransfer, SessionError, SyncRequest, CARD_RECOVERY_NOTE, CFUN_DISABLE_RF, CFUN_FULL,
    CFUN_MINIMUM, CFUN_OFFLINE, CFUN_RESET_NOTE, CTL_SYNC,
};
pub use uim::{
    decode_imsi, EF_IMSI_FILE_ID, EF_IMSI_PATH,
    drain_get_response, parse_eid, parse_open_logical_channel, parse_send_apdu, ApduResponse,
    UimError,
    CLOSE_LOGICAL_CHANNEL, GET_EID_APDU, ISD_R_AID, MAX_GET_RESPONSE_ROUNDS,
    OPEN_LOGICAL_CHANNEL, SEND_APDU,
};
pub use wms::{
    parse_list_messages, parse_raw_read, retain_mobile_terminated, ListedMessage, MessageMode,
    MessageTag, RawMessage, StorageType, WmsError, LIST_MESSAGES, RAW_READ, RAW_SEND,
};

const QMUX_INTERFACE_TYPE: u8 = 0x01;
const QMUX_HEADER_LENGTH: usize = 6;
const QMUX_REQUEST_FLAG: u8 = 0x00;
const QMUX_RESPONSE_FLAG: u8 = 0x80;
const CONTROL_QMI_HEADER_LENGTH: usize = 6;
const SERVICE_QMI_HEADER_LENGTH: usize = 7;
const CONTROL_REQUEST_KIND: u8 = 0x00;
const CONTROL_RESPONSE_KIND: u8 = 0x01;
const SERVICE_REQUEST_KIND: u8 = 0x00;
const SERVICE_RESPONSE_KIND: u8 = 0x02;
const TLV_HEADER_LENGTH: usize = 3;

/// A QMI service identifier carried in the QMUX header.
///
/// Service IDs remain open-ended because vendor-specific services are valid on
/// real modem firmware. Only service `0x00` has special wire semantics.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ServiceId(u8);

impl ServiceId {
    pub const CONTROL: Self = Self(0x00);
    pub const DMS: Self = Self(0x02);
    pub const NAS: Self = Self(0x03);
    pub const WMS: Self = Self(0x05);
    pub const UIM: Self = Self(0x0b);

    pub const fn new(value: u8) -> Self {
        Self(value)
    }

    pub const fn as_u8(self) -> u8 {
        self.0
    }

    pub const fn is_control(self) -> bool {
        self.0 == Self::CONTROL.0
    }
}

impl fmt::Display for ServiceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "0x{:02x}", self.0)
    }
}

/// A QMI client identifier. Client zero is reserved for the control service.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ClientId(u8);

impl ClientId {
    pub const CONTROL: Self = Self(0x00);

    /// Returns a client ID that can be used with a non-control QMI service.
    pub fn allocated(value: u8) -> Result<Self, WireError> {
        if value == Self::CONTROL.0 {
            return Err(WireError::ZeroClientId);
        }

        Ok(Self(value))
    }

    pub const fn as_u8(self) -> u8 {
        self.0
    }

    const fn from_wire(value: u8) -> Self {
        Self(value)
    }

    const fn is_control(self) -> bool {
        self.0 == Self::CONTROL.0
    }
}

impl fmt::Display for ClientId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "0x{:02x}", self.0)
    }
}

/// A QMI transaction ID. The control service uses only its low byte.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TransactionId(u16);

impl TransactionId {
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    pub const fn as_u16(self) -> u16 {
        self.0
    }
}

impl fmt::Display for TransactionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "0x{:04x}", self.0)
    }
}

/// A QMI message identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct MessageId(u16);

impl MessageId {
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    pub const fn as_u16(self) -> u16 {
        self.0
    }
}

impl fmt::Display for MessageId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "0x{:04x}", self.0)
    }
}

/// A single QMI type-length-value field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Tlv {
    pub kind: u8,
    pub value: Vec<u8>,
}

impl Tlv {
    pub fn new(kind: u8, value: impl Into<Vec<u8>>) -> Result<Self, WireError> {
        let value = value.into();
        if value.len() > u16::MAX as usize {
            return Err(WireError::TlvValueTooLarge {
                kind,
                actual: value.len(),
            });
        }

        Ok(Self { kind, value })
    }
}

/// Encodes QMI TLVs with their three-byte wire headers.
pub fn encode_tlvs(tlvs: &[Tlv]) -> Result<Vec<u8>, WireError> {
    let encoded_length = tlvs.iter().try_fold(0usize, |length, tlv| {
        if tlv.value.len() > u16::MAX as usize {
            return Err(WireError::TlvValueTooLarge {
                kind: tlv.kind,
                actual: tlv.value.len(),
            });
        }

        length
            .checked_add(TLV_HEADER_LENGTH + tlv.value.len())
            .ok_or(WireError::EncodedPayloadTooLarge)
    })?;

    let mut encoded = Vec::with_capacity(encoded_length);
    for tlv in tlvs {
        encoded.push(tlv.kind);
        encoded.extend_from_slice(&(tlv.value.len() as u16).to_le_bytes());
        encoded.extend_from_slice(&tlv.value);
    }

    Ok(encoded)
}

/// Decodes a QMI TLV sequence and rejects truncated headers and values.
pub fn decode_tlvs(mut payload: &[u8]) -> Result<Vec<Tlv>, WireError> {
    let mut tlvs = Vec::new();

    while !payload.is_empty() {
        if payload.len() < TLV_HEADER_LENGTH {
            return Err(WireError::TruncatedTlvHeader {
                actual: payload.len(),
            });
        }

        let kind = payload[0];
        let value_length = u16::from_le_bytes([payload[1], payload[2]]) as usize;
        let available = payload.len() - TLV_HEADER_LENGTH;
        if available < value_length {
            return Err(WireError::TruncatedTlvValue {
                kind,
                declared: value_length,
                actual: available,
            });
        }

        let value_end = TLV_HEADER_LENGTH + value_length;
        tlvs.push(Tlv {
            kind,
            value: payload[TLV_HEADER_LENGTH..value_end].to_vec(),
        });
        payload = &payload[value_end..];
    }

    Ok(tlvs)
}

/// A fully formed request, ready for a transport to write as one QMUX frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QmiRequest {
    service: ServiceId,
    client_id: ClientId,
    transaction: TransactionId,
    message_id: MessageId,
    payload: Vec<u8>,
}

impl QmiRequest {
    pub fn new(
        service: ServiceId,
        client_id: ClientId,
        transaction: TransactionId,
        message_id: MessageId,
        payload: impl Into<Vec<u8>>,
    ) -> Result<Self, WireError> {
        validate_address(service, client_id)?;
        validate_transaction(service, transaction)?;

        let payload = payload.into();
        validate_payload_length(service, payload.len())?;
        decode_tlvs(&payload)?;

        Ok(Self {
            service,
            client_id,
            transaction,
            message_id,
            payload,
        })
    }

    pub fn from_tlvs(
        service: ServiceId,
        client_id: ClientId,
        transaction: TransactionId,
        message_id: MessageId,
        tlvs: &[Tlv],
    ) -> Result<Self, WireError> {
        Self::new(
            service,
            client_id,
            transaction,
            message_id,
            encode_tlvs(tlvs)?,
        )
    }

    pub const fn service(&self) -> ServiceId {
        self.service
    }

    pub const fn client_id(&self) -> ClientId {
        self.client_id
    }

    pub const fn transaction(&self) -> TransactionId {
        self.transaction
    }

    pub const fn message_id(&self) -> MessageId {
        self.message_id
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn tlvs(&self) -> Result<Vec<Tlv>, WireError> {
        decode_tlvs(&self.payload)
    }

    pub fn transaction_key(&self) -> TransactionKey {
        TransactionKey {
            service: self.service,
            client_id: self.client_id,
            transaction: self.transaction,
        }
    }

    /// Serializes this request into one complete QMUX frame.
    pub fn encode(&self) -> Vec<u8> {
        let qmi_header_length = qmi_header_length(self.service);
        let qmux_length = 5 + qmi_header_length + self.payload.len();
        let mut frame = Vec::with_capacity(qmux_length + 1);

        frame.push(QMUX_INTERFACE_TYPE);
        frame.extend_from_slice(&(qmux_length as u16).to_le_bytes());
        frame.push(QMUX_REQUEST_FLAG);
        frame.push(self.service.as_u8());
        frame.push(self.client_id.as_u8());

        frame.push(request_kind(self.service));
        if self.service.is_control() {
            frame.push(self.transaction.as_u16() as u8);
        } else {
            frame.extend_from_slice(&self.transaction.as_u16().to_le_bytes());
        }
        frame.extend_from_slice(&self.message_id.as_u16().to_le_bytes());
        frame.extend_from_slice(&(self.payload.len() as u16).to_le_bytes());
        frame.extend_from_slice(&self.payload);

        frame
    }
}

/// A decoded QMI response. The constructor has already checked all wire sizes,
/// message directions, address rules, and TLV boundaries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QmiResponse {
    service: ServiceId,
    client_id: ClientId,
    transaction: TransactionId,
    message_id: MessageId,
    payload: Vec<u8>,
}

impl QmiResponse {
    /// Decodes exactly one QMUX response frame. Concatenated and trailing data
    /// are rejected so a transport cannot accidentally correlate bytes from a
    /// later frame.
    pub fn decode(frame: &[u8]) -> Result<Self, WireError> {
        let (service, client_id, sdu) = decode_qmux_response(frame)?;
        let (transaction, message_id, payload) = decode_response_sdu(service, sdu)?;

        // QMI payloads are TLV sequences. Parse once at the boundary so a
        // malformed frame never reaches service-specific code as raw bytes.
        decode_tlvs(payload)?;

        Ok(Self {
            service,
            client_id,
            transaction,
            message_id,
            payload: payload.to_vec(),
        })
    }

    pub const fn service(&self) -> ServiceId {
        self.service
    }

    pub const fn client_id(&self) -> ClientId {
        self.client_id
    }

    pub const fn transaction(&self) -> TransactionId {
        self.transaction
    }

    pub const fn message_id(&self) -> MessageId {
        self.message_id
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn tlvs(&self) -> Result<Vec<Tlv>, WireError> {
        decode_tlvs(&self.payload)
    }

    pub fn transaction_key(&self) -> TransactionKey {
        TransactionKey {
            service: self.service,
            client_id: self.client_id,
            transaction: self.transaction,
        }
    }
}

/// The fields that identify one in-flight QMI transaction.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TransactionKey {
    pub service: ServiceId,
    pub client_id: ClientId,
    pub transaction: TransactionId,
}

impl fmt::Display for TransactionKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "service {} client {} transaction {}",
            self.service, self.client_id, self.transaction
        )
    }
}

/// The result of matching one response to a registered request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MatchedTransaction {
    pub key: TransactionKey,
    pub message_id: MessageId,
}

/// Tracks in-flight requests without selecting a transport or timeout policy.
#[derive(Default)]
pub struct PendingTransactions {
    pending: HashMap<TransactionKey, MessageId>,
}

impl PendingTransactions {
    /// Registers a request. A QMI transaction ID cannot be reused for the same
    /// service/client pair until its prior request is resolved or discarded.
    pub fn register(&mut self, request: &QmiRequest) -> Result<TransactionKey, CorrelationError> {
        let key = request.transaction_key();
        if self.pending.contains_key(&key) {
            return Err(CorrelationError::DuplicateTransaction(key));
        }
        self.pending.insert(key, request.message_id());

        Ok(key)
    }

    /// Matches a response by service, client, and transaction, then verifies
    /// that its message ID is the one registered for that transaction.
    pub fn resolve(
        &mut self,
        response: &QmiResponse,
    ) -> Result<MatchedTransaction, CorrelationError> {
        let key = response.transaction_key();
        let expected_message = self
            .pending
            .get(&key)
            .copied()
            .ok_or(CorrelationError::UnmatchedResponse(key))?;

        if expected_message != response.message_id() {
            return Err(CorrelationError::MessageMismatch {
                key,
                expected: expected_message,
                actual: response.message_id(),
            });
        }

        self.pending.remove(&key);
        Ok(MatchedTransaction {
            key,
            message_id: expected_message,
        })
    }

    pub fn discard(&mut self, key: TransactionKey) -> Option<MessageId> {
        self.pending.remove(&key)
    }

    pub fn len(&self) -> usize {
        self.pending.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

/// The CTL message that asks a modem to allocate a service client ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientAllocationRequest {
    service: ServiceId,
    transaction: TransactionId,
}

impl ClientAllocationRequest {
    pub const MESSAGE_ID: MessageId = MessageId(0x0022);

    pub fn new(service: ServiceId, transaction: TransactionId) -> Result<Self, AllocationError> {
        if service.is_control() {
            return Err(AllocationError::ControlServiceCannotBeAllocated);
        }
        validate_transaction(ServiceId::CONTROL, transaction)?;

        Ok(Self {
            service,
            transaction,
        })
    }

    pub const fn service(&self) -> ServiceId {
        self.service
    }

    pub const fn transaction(&self) -> TransactionId {
        self.transaction
    }

    /// Produces `QMICTL_GET_CLIENT_ID` with TLV `0x01 = requested service`.
    pub fn to_qmi_request(&self) -> Result<QmiRequest, AllocationError> {
        let service_tlv = Tlv::new(0x01, vec![self.service.as_u8()])?;
        Ok(QmiRequest::from_tlvs(
            ServiceId::CONTROL,
            ClientId::CONTROL,
            self.transaction,
            Self::MESSAGE_ID,
            &[service_tlv],
        )?)
    }

    /// Validates the correlated CTL response and extracts the allocated client.
    pub fn accept(&self, response: &QmiResponse) -> Result<ClientAssignment, AllocationError> {
        if response.service() != ServiceId::CONTROL
            || response.client_id() != ClientId::CONTROL
            || response.transaction() != self.transaction
            || response.message_id() != Self::MESSAGE_ID
        {
            return Err(AllocationError::UnexpectedResponse {
                expected_transaction: self.transaction,
                actual_service: response.service(),
                actual_client: response.client_id(),
                actual_transaction: response.transaction(),
                actual_message: response.message_id(),
            });
        }

        let tlvs = response.tlvs()?;
        let result = required_tlv(&tlvs, 0x02)?;
        if result.value.len() != 4 {
            return Err(AllocationError::MalformedResultCode {
                actual: result.value.len(),
            });
        }

        let result_code = u16::from_le_bytes([result.value[0], result.value[1]]);
        let error_code = u16::from_le_bytes([result.value[2], result.value[3]]);
        if result_code != 0 {
            return Err(AllocationError::ModemRejected {
                result: result_code,
                error: error_code,
            });
        }
        if error_code != 0 {
            return Err(AllocationError::SuccessWithErrorCode { error: error_code });
        }

        let allocation = required_tlv(&tlvs, 0x01)?;
        if allocation.value.len() != 2 {
            return Err(AllocationError::MalformedAllocation {
                actual: allocation.value.len(),
            });
        }

        let actual_service = ServiceId::new(allocation.value[0]);
        if actual_service != self.service {
            return Err(AllocationError::ServiceMismatch {
                expected: self.service,
                actual: actual_service,
            });
        }

        let client_id = ClientId::allocated(allocation.value[1])?;
        Ok(ClientAssignment {
            service: self.service,
            client_id,
        })
    }
}

/// A modem-issued service/client pair that can be used for service requests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientAssignment {
    service: ServiceId,
    client_id: ClientId,
}

impl ClientAssignment {
    pub fn new(service: ServiceId, client_id: ClientId) -> Result<Self, WireError> {
        if service.is_control() {
            return Err(WireError::ControlServiceCannotHaveAssignment);
        }
        validate_address(service, client_id)?;
        Ok(Self { service, client_id })
    }

    pub const fn service(&self) -> ServiceId {
        self.service
    }

    pub const fn client_id(&self) -> ClientId {
        self.client_id
    }

    /// Produces `QMICTL_RELEASE_CLIENT_ID` for this assignment.
    pub fn release_request(
        &self,
        transaction: TransactionId,
    ) -> Result<QmiRequest, WireError> {
        validate_transaction(ServiceId::CONTROL, transaction)?;
        let service_client_tlv = Tlv::new(
            0x01,
            vec![self.service.as_u8(), self.client_id.as_u8()],
        )?;
        QmiRequest::from_tlvs(
            ServiceId::CONTROL,
            ClientId::CONTROL,
            transaction,
            MessageId::new(0x0023),
            &[service_client_tlv],
        )
    }
}

/// A local registry of modem-issued clients, keyed by service.
#[derive(Default)]
pub struct ClientRegistry {
    clients: HashMap<ServiceId, ClientId>,
}

impl ClientRegistry {
    pub fn install(&mut self, assignment: ClientAssignment) -> Result<(), ClientRegistryError> {
        if self.clients.contains_key(&assignment.service) {
            return Err(ClientRegistryError::AlreadyAssigned {
                service: assignment.service,
            });
        }

        self.clients.insert(assignment.service, assignment.client_id);
        Ok(())
    }

    pub fn client_for(&self, service: ServiceId) -> Option<ClientId> {
        self.clients.get(&service).copied()
    }

    pub fn release(&mut self, service: ServiceId) -> Option<ClientAssignment> {
        self.clients.remove(&service).map(|client_id| ClientAssignment {
            service,
            client_id,
        })
    }

    pub fn len(&self) -> usize {
        self.clients.len()
    }

    pub fn is_empty(&self) -> bool {
        self.clients.is_empty()
    }
}

/// Errors emitted while encoding or decoding a QMUX/QMI frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WireError {
    FrameTooShort { actual: usize, minimum: usize },
    InvalidInterfaceType { actual: u8 },
    QmuxLengthMismatch { declared: usize, actual: usize },
    UnexpectedQmuxControlFlag { actual: u8, expected: u8 },
    ControlServiceRequiresControlClient { actual: ClientId },
    ControlServiceCannotHaveAssignment,
    ServiceRequiresAllocatedClient { service: ServiceId },
    ZeroClientId,
    ControlTransactionOutOfRange { transaction: TransactionId },
    PayloadTooLarge { service: ServiceId, actual: usize, maximum: usize },
    EncodedPayloadTooLarge,
    UnexpectedMessageKind {
        service: ServiceId,
        actual: u8,
        expected: u8,
    },
    PayloadLengthMismatch { declared: usize, actual: usize },
    TlvValueTooLarge { kind: u8, actual: usize },
    TruncatedTlvHeader { actual: usize },
    TruncatedTlvValue {
        kind: u8,
        declared: usize,
        actual: usize,
    },
}

impl fmt::Display for WireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameTooShort { actual, minimum } => {
                write!(formatter, "QMUX frame is {actual} bytes, need at least {minimum}")
            }
            Self::InvalidInterfaceType { actual } => {
                write!(formatter, "invalid QMUX interface type 0x{actual:02x}")
            }
            Self::QmuxLengthMismatch { declared, actual } => write!(
                formatter,
                "QMUX length declares {declared} total bytes, received {actual}"
            ),
            Self::UnexpectedQmuxControlFlag { actual, expected } => write!(
                formatter,
                "QMUX control flag 0x{actual:02x}, expected 0x{expected:02x}"
            ),
            Self::ControlServiceRequiresControlClient { actual } => write!(
                formatter,
                "control service requires client 0x00, received {actual}"
            ),
            Self::ControlServiceCannotHaveAssignment => {
                formatter.write_str("the control service cannot have an allocated client assignment")
            }
            Self::ServiceRequiresAllocatedClient { service } => {
                write!(formatter, "service {service} requires a nonzero allocated client")
            }
            Self::ZeroClientId => formatter.write_str("client ID 0x00 is not allocatable"),
            Self::ControlTransactionOutOfRange { transaction } => write!(
                formatter,
                "control transaction {transaction} exceeds the one-byte wire field"
            ),
            Self::PayloadTooLarge {
                service,
                actual,
                maximum,
            } => write!(
                formatter,
                "payload for service {service} is {actual} bytes, maximum is {maximum}"
            ),
            Self::EncodedPayloadTooLarge => {
                formatter.write_str("encoded QMI payload exceeds addressable memory")
            }
            Self::UnexpectedMessageKind {
                service,
                actual,
                expected,
            } => write!(
                formatter,
                "service {service} message kind 0x{actual:02x}, expected 0x{expected:02x}"
            ),
            Self::PayloadLengthMismatch { declared, actual } => write!(
                formatter,
                "QMI payload declares {declared} bytes, received {actual}"
            ),
            Self::TlvValueTooLarge { kind, actual } => write!(
                formatter,
                "TLV 0x{kind:02x} has {actual} bytes, above the u16 wire limit"
            ),
            Self::TruncatedTlvHeader { actual } => {
                write!(formatter, "truncated QMI TLV header with {actual} bytes remaining")
            }
            Self::TruncatedTlvValue {
                kind,
                declared,
                actual,
            } => write!(
                formatter,
                "TLV 0x{kind:02x} declares {declared} bytes, only {actual} remain"
            ),
        }
    }
}

impl Error for WireError {}

/// Errors specific to a CTL client-ID allocation exchange.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AllocationError {
    Wire(WireError),
    ControlServiceCannotBeAllocated,
    UnexpectedResponse {
        expected_transaction: TransactionId,
        actual_service: ServiceId,
        actual_client: ClientId,
        actual_transaction: TransactionId,
        actual_message: MessageId,
    },
    MissingTlv { kind: u8 },
    DuplicateTlv { kind: u8 },
    MalformedResultCode { actual: usize },
    ModemRejected { result: u16, error: u16 },
    SuccessWithErrorCode { error: u16 },
    MalformedAllocation { actual: usize },
    ServiceMismatch { expected: ServiceId, actual: ServiceId },
}

impl fmt::Display for AllocationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(error) => error.fmt(formatter),
            Self::ControlServiceCannotBeAllocated => {
                formatter.write_str("the control service does not have an allocatable client ID")
            }
            Self::UnexpectedResponse {
                expected_transaction,
                actual_service,
                actual_client,
                actual_transaction,
                actual_message,
            } => write!(
                formatter,
                "unexpected client allocation response: expected control transaction {expected_transaction}, got service {actual_service} client {actual_client} transaction {actual_transaction} message {actual_message}"
            ),
            Self::MissingTlv { kind } => write!(formatter, "client allocation response lacks TLV 0x{kind:02x}"),
            Self::DuplicateTlv { kind } => write!(formatter, "client allocation response repeats TLV 0x{kind:02x}"),
            Self::MalformedResultCode { actual } => write!(
                formatter,
                "client allocation result code has {actual} bytes, expected four"
            ),
            Self::ModemRejected { result, error } => write!(
                formatter,
                "modem rejected client allocation with result {result} and error {error}"
            ),
            Self::SuccessWithErrorCode { error } => write!(
                formatter,
                "client allocation reports success with nonzero error code {error}"
            ),
            Self::MalformedAllocation { actual } => write!(
                formatter,
                "client allocation TLV has {actual} bytes, expected service and client"
            ),
            Self::ServiceMismatch { expected, actual } => write!(
                formatter,
                "client allocation returned service {actual}, expected {expected}"
            ),
        }
    }
}

impl Error for AllocationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Wire(error) => Some(error),
            _ => None,
        }
    }
}

impl From<WireError> for AllocationError {
    fn from(value: WireError) -> Self {
        Self::Wire(value)
    }
}

/// Errors from local transaction matching.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CorrelationError {
    DuplicateTransaction(TransactionKey),
    UnmatchedResponse(TransactionKey),
    MessageMismatch {
        key: TransactionKey,
        expected: MessageId,
        actual: MessageId,
    },
}

impl fmt::Display for CorrelationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateTransaction(key) => {
                write!(formatter, "transaction already registered for {key}")
            }
            Self::UnmatchedResponse(key) => write!(formatter, "response has no pending {key}"),
            Self::MessageMismatch {
                key,
                expected,
                actual,
            } => write!(
                formatter,
                "response for {key} has message {actual}, expected {expected}"
            ),
        }
    }
}

impl Error for CorrelationError {}

/// Errors from managing locally installed client assignments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClientRegistryError {
    AlreadyAssigned { service: ServiceId },
}

impl fmt::Display for ClientRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyAssigned { service } => {
                write!(formatter, "service {service} already has an installed client")
            }
        }
    }
}

impl Error for ClientRegistryError {}

fn decode_qmux_response(frame: &[u8]) -> Result<(ServiceId, ClientId, &[u8]), WireError> {
    if frame.len() < QMUX_HEADER_LENGTH {
        return Err(WireError::FrameTooShort {
            actual: frame.len(),
            minimum: QMUX_HEADER_LENGTH,
        });
    }
    if frame[0] != QMUX_INTERFACE_TYPE {
        return Err(WireError::InvalidInterfaceType { actual: frame[0] });
    }

    let declared_length = u16::from_le_bytes([frame[1], frame[2]]) as usize + 1;
    if declared_length != frame.len() {
        return Err(WireError::QmuxLengthMismatch {
            declared: declared_length,
            actual: frame.len(),
        });
    }
    if frame[3] != QMUX_RESPONSE_FLAG {
        return Err(WireError::UnexpectedQmuxControlFlag {
            actual: frame[3],
            expected: QMUX_RESPONSE_FLAG,
        });
    }

    let service = ServiceId::new(frame[4]);
    let client_id = ClientId::from_wire(frame[5]);
    validate_address(service, client_id)?;
    Ok((service, client_id, &frame[QMUX_HEADER_LENGTH..]))
}

fn decode_response_sdu(
    service: ServiceId,
    sdu: &[u8],
) -> Result<(TransactionId, MessageId, &[u8]), WireError> {
    let header_length = qmi_header_length(service);
    if sdu.len() < header_length {
        return Err(WireError::FrameTooShort {
            actual: sdu.len(),
            minimum: header_length,
        });
    }

    let expected_kind = response_kind(service);
    if sdu[0] != expected_kind {
        return Err(WireError::UnexpectedMessageKind {
            service,
            actual: sdu[0],
            expected: expected_kind,
        });
    }

    let (transaction, message_offset, payload_length_offset) = if service.is_control() {
        (TransactionId::new(sdu[1] as u16), 2, 4)
    } else {
        (
            TransactionId::new(u16::from_le_bytes([sdu[1], sdu[2]])),
            3,
            5,
        )
    };
    let message_id = MessageId::new(u16::from_le_bytes([
        sdu[message_offset],
        sdu[message_offset + 1],
    ]));
    let declared_payload_length = u16::from_le_bytes([
        sdu[payload_length_offset],
        sdu[payload_length_offset + 1],
    ]) as usize;
    let payload = &sdu[header_length..];
    if declared_payload_length != payload.len() {
        return Err(WireError::PayloadLengthMismatch {
            declared: declared_payload_length,
            actual: payload.len(),
        });
    }

    Ok((transaction, message_id, payload))
}

/// Looks up a TLV kind and rejects both absence and duplicates.
pub fn unique_tlv(tlvs: &[Tlv], kind: u8) -> Result<&Tlv, TlvLookupError> {
    let mut matches = tlvs.iter().filter(|tlv| tlv.kind == kind);
    let value = matches
        .next()
        .ok_or(TlvLookupError::Missing { kind })?;
    if matches.next().is_some() {
        return Err(TlvLookupError::Duplicate { kind });
    }
    Ok(value)
}

fn required_tlv<'a>(tlvs: &'a [Tlv], kind: u8) -> Result<&'a Tlv, AllocationError> {
    unique_tlv(tlvs, kind).map_err(|error| match error {
        TlvLookupError::Missing { kind } => AllocationError::MissingTlv { kind },
        TlvLookupError::Duplicate { kind } => AllocationError::DuplicateTlv { kind },
    })
}

/// Errors from locating a unique TLV in a decoded payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TlvLookupError {
    Missing { kind: u8 },
    Duplicate { kind: u8 },
}

impl fmt::Display for TlvLookupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing { kind } => write!(formatter, "missing TLV 0x{kind:02x}"),
            Self::Duplicate { kind } => write!(formatter, "duplicate TLV 0x{kind:02x}"),
        }
    }
}

impl Error for TlvLookupError {}

fn validate_address(service: ServiceId, client_id: ClientId) -> Result<(), WireError> {
    if service.is_control() && !client_id.is_control() {
        return Err(WireError::ControlServiceRequiresControlClient { actual: client_id });
    }
    if !service.is_control() && client_id.is_control() {
        return Err(WireError::ServiceRequiresAllocatedClient { service });
    }

    Ok(())
}

fn validate_transaction(service: ServiceId, transaction: TransactionId) -> Result<(), WireError> {
    if service.is_control() && transaction.as_u16() > u8::MAX as u16 {
        return Err(WireError::ControlTransactionOutOfRange { transaction });
    }

    Ok(())
}

fn validate_payload_length(service: ServiceId, length: usize) -> Result<(), WireError> {
    let maximum = u16::MAX as usize - 5 - qmi_header_length(service);
    if length > maximum {
        return Err(WireError::PayloadTooLarge {
            service,
            actual: length,
            maximum,
        });
    }

    Ok(())
}

const fn qmi_header_length(service: ServiceId) -> usize {
    if service.is_control() {
        CONTROL_QMI_HEADER_LENGTH
    } else {
        SERVICE_QMI_HEADER_LENGTH
    }
}

const fn request_kind(service: ServiceId) -> u8 {
    if service.is_control() {
        CONTROL_REQUEST_KIND
    } else {
        SERVICE_REQUEST_KIND
    }
}

const fn response_kind(service: ServiceId) -> u8 {
    if service.is_control() {
        CONTROL_RESPONSE_KIND
    } else {
        SERVICE_RESPONSE_KIND
    }
}
