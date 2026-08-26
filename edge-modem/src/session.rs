use std::{error::Error, fmt, time::Duration};

use crate::{
    dms, es10c, es9p, nas, uim, unique_tlv, wms, ActivationCode, AllocationError, ApduResponse,
    AuthenticationStart, CellLocationInfo, ClientAllocationRequest, ClientAssignment,
    ClientAuthentication, ClientId, ClientRegistry, ClientRegistryError, ConfiguredAddresses,
    CorrelationError, DeviceRevision, DeviceSerialNumbers, DmsError, Es9pClient, Es9pError,
    EuiccInfo1, EuiccInfo2, InstallationResult, ListedMessage,
    MessageId, MessageMode, MessageTag, NasError, NotificationMetadata, OperatingMode,
    PendingNotification, PendingTransactions, Profile, ProfileMetadata, QmiRequest, QmiResponse,
    QmiResult, RawMessage, ResultError, ServiceId, ServingSystem, StorageType, TlvLookupError,
    TransactionId, UimError, Verification, WireError, WmsError,
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
        Ok(wms::parse_list_messages(&response, storage)?)
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

    /// Read `EF_AD`, whose fourth byte says how many digits of the IMSI are
    /// the MNC.
    ///
    /// Returned raw rather than decoded: the AT-only probe reads the same
    /// file over `AT+CRSM` and both hand the bytes to the one decoder in
    /// `edge-core`, so there is a single statement of what byte 4 means. A
    /// second copy of that rule is how the two operator tables in this
    /// product came to disagree.
    ///
    /// Basic channel, like `read_imsi`: session type 0x00 with an empty AID.
    /// Opening a logical channel for a read-only file would put this poll in
    /// contention with the eUICC's ISD-R session for nothing.
    pub fn read_ef_ad(&mut self) -> Result<Vec<u8>, SessionError> {
        let assignment = self.assignment(ServiceId::UIM)?;
        let request = uim::read_transparent_request(
            assignment,
            self.allocate_service_transaction(),
            uim::EF_AD_FILE_ID,
            uim::EF_AD_PATH,
        )?;
        let response = self.round_trip(&request)?;
        Ok(uim::parse_read_transparent(&response)?)
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

    /// Open the ISD-R application on `slot` for as long as the returned value
    /// lives.
    ///
    /// The channel closes when the session is dropped, which covers the paths
    /// a caller forgets: an early `?`, a panic, a command that failed halfway
    /// through a sequence. Leaking one is not harmless — an eUICC offers only
    /// a few logical channels, and once they are gone every later profile
    /// operation fails to open one — and the previous design defended against
    /// that by opening and closing around every single APDU, which cannot
    /// carry a stateful sequence at all.
    pub fn isdr_session(&mut self, slot: u8) -> Result<IsdrSession<'_, T>, SessionError> {
        let channel = self
            .open_logical_channel(slot, uim::ISD_R_AID)
            .map_err(|error| SessionError::transport(format!("open ISD-R channel: {error}")))?;
        Ok(IsdrSession {
            client: self,
            slot,
            channel,
            closed: false,
        })
    }

    /// List every profile the eUICC holds.
    pub fn list_profiles(&mut self, slot: u8) -> Result<Vec<Profile>, SessionError> {
        let mut session = self.isdr_session(slot)?;
        let profiles = session.list_profiles()?;
        session.close()?;
        Ok(profiles)
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
        let payload = if enable {
            es10c::enable_profile_payload(iccid, true)?
        } else {
            es10c::disable_profile_payload(iccid, true)?
        };
        let mut session = self.isdr_session(slot)?;
        let bytes = session.execute(&payload)?;
        let outcome = es10c::parse_profile_result(&bytes, enable);
        session.close()?;
        Ok(outcome?)
    }

    pub fn read_eid(&mut self, slot: u8) -> Result<String, SessionError> {
        let mut session = self.isdr_session(slot)?;
        let eid = session.read_eid()?;
        session.close()?;
        Ok(eid)
    }

    /// Everything ES10b will say about a chip without changing anything on it.
    ///
    /// One channel for the whole read. The four commands are a sequence, not
    /// four unrelated errands, and opening a channel per command is both four
    /// times the round trips and four chances to leak one.
    pub fn read_esim_local_info(&mut self, slot: u8) -> Result<EsimLocalInfo, SessionError> {
        let mut session = self.isdr_session(slot)?;
        let outcome = (|| {
            let eid = session.read_eid()?;
            let info = session.euicc_info2()?;
            // A card with nothing pending and a card that refused the query
            // both produce an empty list, so the refusal is kept rather than
            // flattened into "no notifications".
            let (notifications, notifications_error) = match session.list_notifications() {
                Ok(list) => (list, None),
                Err(error) => (Vec::new(), Some(error.to_string())),
            };
            let (profiles, profiles_error) = match session.list_profiles() {
                Ok(list) => (list, None),
                Err(error) => (Vec::new(), Some(error.to_string())),
            };
            Ok(EsimLocalInfo {
                eid,
                info,
                notifications,
                notifications_error,
                profiles,
                profiles_error,
            })
        })();
        session.close()?;
        outcome
    }

    /// Everything ES9+ `InitiateAuthentication` needs from the chip.
    ///
    /// One channel again, and for a stronger reason than tidiness: the
    /// challenge is only meaningful next to the `GetEUICCInfo1` that names the
    /// CI keys the same chip will verify with, and reading them through two
    /// sessions leaves room for them to come from two different cards.
    ///
    /// Read-only. `GetEUICCChallenge` generates a fresh random each call and
    /// stores nothing an operator can see; the profile inventory, the enabled
    /// profile and the pending notifications are all untouched.
    pub fn read_esim_authentication_inputs(
        &mut self,
        slot: u8,
    ) -> Result<EsimAuthenticationInputs, SessionError> {
        let mut session = self.isdr_session(slot)?;
        let outcome = (|| {
            let eid = session.read_eid()?;
            let challenge = session.euicc_challenge()?;
            let info1 = session.euicc_info1()?;
            // Both of these name where to go next, and a chip that refuses
            // one can still be reachable through the other, so neither is
            // allowed to fail the read.
            let (addresses, addresses_error) = match session.configured_addresses() {
                Ok(addresses) => (addresses, None),
                Err(error) => (ConfiguredAddresses::default(), Some(error.to_string())),
            };
            let (notification_addresses, notification_addresses_error) =
                match session.list_notifications() {
                    Ok(list) => {
                        let mut addresses: Vec<String> = Vec::new();
                        for entry in list {
                            if !addresses.contains(&entry.address) {
                                addresses.push(entry.address);
                            }
                        }
                        (addresses, None)
                    }
                    Err(error) => (Vec::new(), Some(error.to_string())),
                };
            Ok(EsimAuthenticationInputs {
                eid,
                challenge,
                info1,
                addresses,
                addresses_error,
                notification_addresses,
                notification_addresses_error,
            })
        })();
        session.close()?;
        outcome
    }

    /// Pull one pending notification off the chip, signature and all.
    ///
    /// This is the first of the three steps in an ES9+ notification retry.
    /// The other two — handing it to the SM-DP+ over HTTPS and then removing
    /// it from the card — need an HTTP client and a write respectively, and
    /// neither belongs to a read-only slice.
    pub fn retrieve_esim_notification(
        &mut self,
        slot: u8,
        sequence_number: u64,
    ) -> Result<PendingNotification, SessionError> {
        let mut session = self.isdr_session(slot)?;
        let outcome = session.retrieve_notification(sequence_number);
        session.close()?;
        outcome
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

/// Everything ES10b reports about one eUICC, read in a single channel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EsimLocalInfo {
    /// 32 digits identifying the chip itself, unchanged by profile switches.
    pub eid: String,
    pub info: EuiccInfo2,
    pub notifications: Vec<NotificationMetadata>,
    /// Why the notification list is empty, when the card refused rather than
    /// having nothing pending.
    pub notifications_error: Option<String>,
    pub profiles: Vec<Profile>,
    pub profiles_error: Option<String>,
}

/// Digits an EID has, and the only length the cloud will store one at.
///
/// A chip that answers `GetEID` with anything else has not been read: the
/// number is fixed by SGP.22 and is not a local formatting choice.
const EID_DIGITS: usize = 32;

/// The widest inventory the uplink contract will carry in one payload.
const MAX_INVENTORY_PROFILES: usize = 64;

/// Shortest and longest ICCID the cloud accepts.
const ICCID_DIGITS: std::ops::RangeInclusive<usize> = 19..=20;

/// Largest `collected_at` the cloud will store, in epoch milliseconds.
const MAX_EPOCH_MILLIS: i64 = 253_402_300_799_999;

impl EsimLocalInfo {
    /// This read as an `EsimInventory` payload, or `None` when it cannot
    /// honestly stand for one.
    ///
    /// The cloud treats an inventory as *the complete contents of one chip*:
    /// every ICCID it has on record for this EID and does not find in the
    /// payload is marked deleted. That makes a partial answer worse than no
    /// answer, so this is deliberately all-or-nothing. A list the card refused
    /// (`profiles_error`), a profile whose ICCID came back the wrong shape, or
    /// more profiles than one payload can carry each produce `None` rather
    /// than a shorter inventory that would erase what it left out.
    ///
    /// `None` is also the answer for a card that is not an eUICC. Such a card
    /// has no EID, the payload requires one, and so it cannot be represented
    /// here at all — the projection is not where that card gets reported.
    ///
    /// JSON rather than a type of its own: this crate speaks to modems and
    /// carries no dependency on the wire contract. The caller that does have
    /// one parses this back into the generated type, and that parse is what
    /// checks it.
    pub fn inventory_json(
        &self,
        modem_imei: &str,
        collected_at: i64,
    ) -> Option<serde_json::Value> {
        if self.profiles_error.is_some() {
            return None;
        }
        if !is_eid(&self.eid) {
            return None;
        }
        if !(0..=MAX_EPOCH_MILLIS).contains(&collected_at) {
            return None;
        }
        if self.profiles.len() > MAX_INVENTORY_PROFILES {
            return None;
        }

        let mut profiles = Vec::with_capacity(self.profiles.len());
        for profile in &self.profiles {
            if !is_iccid(&profile.iccid) {
                return None;
            }
            let mut entry = serde_json::Map::new();
            entry.insert("iccid".into(), profile.iccid.clone().into());
            // Only two of the contract's four states can come from a card that
            // answered: it lists what it holds, and the enabled flag is the
            // whole of what it says about each one. `deleted` is the cloud's
            // own inference from an ICCID going missing, and `unknown` would be
            // this code declining to report a boolean it has in hand.
            entry.insert(
                "state".into(),
                if profile.enabled { "enabled" } else { "disabled" }.into(),
            );
            if let Some(nickname) = profile.nickname.as_deref() {
                let nickname = nickname.trim();
                // An empty nickname is not a nickname. Upstream would keep the
                // one it already had either way, but sending it would still be
                // claiming the operator had named this profile something.
                if !nickname.is_empty() {
                    entry.insert("nickname".into(), nickname.to_string().into());
                }
            }
            profiles.push(serde_json::Value::Object(entry));
        }

        Some(serde_json::json!({
            "modem_imei": modem_imei,
            "eid": self.eid,
            "collected_at": collected_at,
            "profiles": profiles,
        }))
    }
}

/// True for the 32 decimal digits an eUICC reports as its EID.
///
/// What separates an eUICC from a card that is not one, once the chip has
/// answered at all. It lives here rather than at the caller because the caller
/// cannot see what the difference is for.
fn is_eid(value: &str) -> bool {
    value.len() == EID_DIGITS && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn is_iccid(value: &str) -> bool {
    ICCID_DIGITS.contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_digit())
}

/// What an ES9+ session needs from the chip before it can start.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EsimAuthenticationInputs {
    pub eid: String,
    /// Sixteen random bytes, fresh from this read.
    pub challenge: [u8; es10c::EUICC_CHALLENGE_BYTES],
    pub info1: EuiccInfo1,
    pub addresses: ConfiguredAddresses,
    pub addresses_error: Option<String>,
    /// The SM-DP+ addresses the chip's pending notifications name, in the
    /// order it reported them and without repeats.
    ///
    /// A fallback with a real basis: a notification carries the address of the
    /// server that has to hear about it, so a chip with anything pending knows
    /// an SM-DP+ that has already dealt with this card even when no default
    /// one is configured. Both bench chips are in exactly that state.
    pub notification_addresses: Vec<String>,
    pub notification_addresses_error: Option<String>,
}

/// An open ISD-R logical channel.
///
/// Every exit path closes it, including the ones a caller does not write: the
/// `Drop` implementation is the guarantee, and `close` only exists so a caller
/// that wants to know whether the close failed can find out. Relying on the
/// caller to remember is what the earlier open-and-close-per-APDU design was
/// avoiding, at the cost of not being able to run a sequence at all.
pub struct IsdrSession<'a, T: QmiTransport> {
    client: &'a mut QmiClient<T>,
    slot: u8,
    channel: u8,
    closed: bool,
}

impl<T: QmiTransport> IsdrSession<'_, T> {
    pub fn channel(&self) -> u8 {
        self.channel
    }

    pub fn slot(&self) -> u8 {
        self.slot
    }

    /// Send one APDU and keep asking for the rest until the card stops saying
    /// `61 xx`.
    ///
    /// One round was enough for a profile list and is not enough for anything
    /// in ES10b: `GetEUICCInfo2` needs two exchanges and the pending
    /// notification list needs sixteen. Stopping after the first returned a
    /// prefix that still parsed as valid BER-TLV, so the truncation showed up
    /// as missing fields rather than as an error.
    pub fn transmit(&mut self, apdu: &[u8]) -> Result<ApduResponse, SessionError> {
        let first = self
            .client
            .send_apdu(self.slot, self.channel, apdu)
            .map_err(|error| SessionError::transport(format!("ES10 command: {error}")))?;
        let slot = self.slot;
        let channel = self.channel;
        let client = &mut *self.client;
        uim::drain_get_response(
            first,
            |get_response| {
                client
                    .send_apdu(slot, channel, get_response)
                    .map_err(|error| SessionError::transport(format!("GET RESPONSE: {error}")))
            },
            |rounds| {
                SessionError::transport(format!(
                    "eUICC on slot {slot} asked for more than {rounds} GET RESPONSE rounds"
                ))
            },
        )
    }

    /// Run one ES10 request, splitting it across `STORE DATA` blocks if it
    /// does not fit in one, and return the card's answer.
    pub fn execute(&mut self, payload: &[u8]) -> Result<Vec<u8>, SessionError> {
        let chain = es10c::store_data_chain(payload)?;
        let last = chain.len() - 1;
        let mut answer = Vec::new();
        for (index, apdu) in chain.iter().enumerate() {
            let response = self.transmit(apdu)?;
            if !response.is_success() {
                return Err(SessionError::Uim(UimError::ApduFailed {
                    sw1: response.sw1,
                    sw2: response.sw2,
                }));
            }
            // Only the last block carries the answer. An intermediate block
            // that returns data is a card doing something unusual rather than
            // a failure, so it is dropped rather than concatenated: appending
            // it would corrupt the BER-TLV the caller then tries to parse.
            if index == last {
                answer = response.data;
            }
        }
        Ok(answer)
    }

    /// The EID, 32 digits.
    pub fn read_eid(&mut self) -> Result<String, SessionError> {
        // ES10c GetEUICCData first: both bench eUICCs answer `6D00` to the
        // GlobalPlatform GET DATA form this used to send, so the fallback is
        // the form that does not work here rather than the other way round.
        let first = match self.execute(&es10c::get_eid_payload()) {
            Ok(bytes) => match es10c::parse_eid_response(&bytes) {
                Ok(eid) => return Ok(eid),
                Err(error) => SessionError::from(error),
            },
            Err(error) => error,
        };
        match self.transmit(uim::GET_EID_APDU) {
            Ok(response) if response.is_success() => Ok(uim::parse_eid(&response)?),
            _ => Err(first),
        }
    }

    /// `GetEUICCInfo2`, decoded in full.
    pub fn euicc_info2(&mut self) -> Result<EuiccInfo2, SessionError> {
        let bytes = self.execute(&es10c::euicc_info2_payload())?;
        Ok(es10c::parse_euicc_info2(&bytes)?)
    }

    /// `GetEUICCChallenge`: sixteen random bytes, generated now.
    ///
    /// Never cached. Two calls returning the same value would mean the chip
    /// was not consulted, and an ES9+ exchange built on a stale challenge
    /// proves nothing about which card is on the other end.
    pub fn euicc_challenge(
        &mut self,
    ) -> Result<[u8; es10c::EUICC_CHALLENGE_BYTES], SessionError> {
        let bytes = self.execute(&es10c::euicc_challenge_payload())?;
        Ok(es10c::parse_euicc_challenge(&bytes)?)
    }

    /// `GetEUICCInfo1`, decoded and kept in its encoded form.
    pub fn euicc_info1(&mut self) -> Result<EuiccInfo1, SessionError> {
        let bytes = self.execute(&es10c::euicc_info1_payload())?;
        Ok(es10c::parse_euicc_info1(&bytes)?)
    }

    /// ES10a `GetEuiccConfiguredAddresses`.
    pub fn configured_addresses(&mut self) -> Result<ConfiguredAddresses, SessionError> {
        let bytes = self.execute(&es10c::configured_addresses_payload())?;
        Ok(es10c::parse_configured_addresses(&bytes)?)
    }

    /// `ListNotification` with no filter.
    pub fn list_notifications(&mut self) -> Result<Vec<NotificationMetadata>, SessionError> {
        let bytes = self.execute(&es10c::list_notification_payload())?;
        Ok(es10c::parse_notification_metadata_list(&bytes)?)
    }

    /// Every profile the chip holds.
    pub fn list_profiles(&mut self) -> Result<Vec<Profile>, SessionError> {
        let bytes = self.execute(&es10c::get_profiles_payload())?;
        Ok(es10c::parse_profiles(&bytes)?)
    }

    /// Every pending notification, with the signed bytes ES9+ would carry.
    pub fn retrieve_notifications(&mut self) -> Result<Vec<PendingNotification>, SessionError> {
        let bytes = self.execute(&es10c::retrieve_notifications_payload())?;
        Ok(es10c::parse_pending_notifications(&bytes)?)
    }

    /// One pending notification by sequence number.
    ///
    /// Selected here rather than on the card: both bench eUICCs refuse the
    /// `seqNumber` search form with `BF2B 03 81 01 7F` even for a sequence
    /// number their own `ListNotification` had just reported, so the whole
    /// list comes back and the wanted entry is picked out of it.
    pub fn retrieve_notification(
        &mut self,
        sequence_number: u64,
    ) -> Result<PendingNotification, SessionError> {
        let pending = self.retrieve_notifications()?;
        pending
            .into_iter()
            .find(|entry| entry.metadata.sequence_number == sequence_number)
            .ok_or_else(|| {
                SessionError::transport(format!(
                    "eUICC has no pending notification with sequence number {sequence_number}"
                ))
            })
    }

    /// Close the channel and say whether that worked.
    pub fn close(mut self) -> Result<(), SessionError> {
        self.closed = true;
        self.client.close_logical_channel(self.slot, self.channel)
    }
}

impl<T: QmiTransport> Drop for IsdrSession<'_, T> {
    fn drop(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        // A failed close is reported rather than raised: `Drop` has nowhere to
        // return it, and this path exists precisely for the cases where an
        // error is already on its way to the caller.
        if let Err(error) = self.client.close_logical_channel(self.slot, self.channel) {
            eprintln!(
                "close ISD-R channel {} on slot {}: {error}",
                self.channel, self.slot
            );
        }
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
    /// The character device stopped having a modem behind it.
    ///
    /// Separate from `Transport` because the caller has to act differently:
    /// a transfer that failed can be retried, while a module that left the
    /// bus after the request was written may already have carried it out.
    /// `awaiting_response` is what says which of those two happened.
    Disconnected {
        device: String,
        awaiting_response: bool,
    },
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
    /// An ES9+ exchange with an SM-DP+ failed.
    ///
    /// Carried through rather than flattened into `Transport`: a download runs
    /// over two very different links, and "the server refused the matching
    /// id" and "the modem stopped answering" need different next steps.
    Es9p(Es9pError),
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

    /// True when the module went away with a request already in its hands.
    ///
    /// The only caller that must branch on this is the one that sends SMS.
    /// Everything else here is a read and can simply be tried again; a
    /// submit cannot, because repeating it is how one message becomes two.
    pub fn left_the_bus_after_the_request(&self) -> bool {
        matches!(
            self,
            Self::Disconnected {
                awaiting_response: true,
                ..
            }
        )
    }
}

impl fmt::Display for SessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(message) => write!(formatter, "QMI transport error: {message}"),
            Self::Disconnected {
                device,
                awaiting_response,
            } => {
                if *awaiting_response {
                    write!(
                        formatter,
                        "{device} left the bus while the modem was answering; \
                         the request had already been handed over"
                    )
                } else {
                    write!(formatter, "{device} left the bus before the request was written")
                }
            }
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
            Self::Es9p(error) => error.fmt(formatter),
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

impl From<Es9pError> for SessionError {
    fn from(error: Es9pError) -> Self {
        Self::Es9p(error)
    }
}

impl From<crate::Es10cError> for SessionError {
    fn from(value: crate::Es10cError) -> Self {
        Self::Es10c(value)
    }
}

/// What one eUICC held at a moment in time.
///
/// Taken twice, before and after a download, because the evidence that a
/// profile arrived is not the command saying so. It is a second profile in the
/// list, a smaller free memory figure, and one more notification the card owes
/// its SM-DP+.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EuiccSnapshot {
    pub free_non_volatile_memory: Option<u64>,
    pub profiles: Vec<Profile>,
    pub notifications: Vec<NotificationMetadata>,
}

/// One `STORE DATA` chain that carried a piece of a Bound Profile Package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SegmentTransfer {
    pub label: String,
    pub bytes: usize,
    pub blocks: usize,
}

/// One ES9+ round trip, for a record that can be read after the fact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpStep {
    pub step: &'static str,
    pub http_status: u16,
    pub elapsed_ms: u64,
}

/// What the operator asked for.
///
/// The activation code is borrowed rather than owned and is never copied into
/// the outcome: it is a one-time credential, and a value that ends up in a
/// command result ends up in a database, a log and a receipt.
pub struct DownloadRequest<'a> {
    pub activation_code: &'a ActivationCode,
    pub confirmation_code: Option<&'a str>,
    /// The module's own IMEI. Only its first eight digits travel, as the type
    /// allocation code inside `DeviceInfo`.
    pub imei: &'a str,
}

/// Everything that happened, in enough detail to tell a download that worked
/// from one that merely returned.
#[derive(Clone, Debug, Default)]
pub struct DownloadOutcome {
    pub eid: String,
    pub smdp_address: String,
    pub transaction_id: String,
    /// True when the activation code named a matching id. The id itself is
    /// deliberately absent.
    pub matching_id_present: bool,
    pub before: EuiccSnapshot,
    pub after: Option<EuiccSnapshot>,

    // The ES9+ session, from `InitiateAuthentication`.
    pub euicc_challenge: [u8; es10c::EUICC_CHALLENGE_BYTES],
    pub echoed_euicc_challenge: String,
    pub server_challenge: String,
    pub euicc_ci_pkid_to_be_used: String,
    pub chip_ci_key_ids: Vec<String>,
    pub ci_key_accepted_by_chip: bool,
    pub verification: Verification,
    pub negotiated_tls: Option<String>,
    pub admin_protocol: Option<String>,
    pub http: Vec<HttpStep>,

    /// What the SM-DP+ said the profile is, read before anything was written.
    pub metadata: Option<ProfileMetadata>,
    /// The policy rules that stopped this download, when they did.
    pub refused_policy_rules: Vec<String>,
    /// Whether the server asked for a confirmation code.
    pub confirmation_code_required: bool,

    /// Blocks in the `STORE DATA` chain each card-side step needed. These are
    /// the numbers that say the chain works on real hardware: every one of
    /// them above 1 is a payload the old single-APDU code would have wrapped.
    pub authenticate_server_blocks: usize,
    pub prepare_download_blocks: usize,
    pub bpp_bytes: usize,
    pub bpp_segments: Vec<SegmentTransfer>,
    pub bpp_blocks: usize,

    pub installed: bool,
    pub installation: Option<InstallationResult>,
    /// The notification produced by *this* download, and only that one.
    pub notification_delivered: bool,
    pub notification_bytes: usize,
    pub notification_delivery_error: Option<String>,
    /// 0 when the card confirmed the notification is gone.
    pub notification_removed: Option<u64>,
    /// Set when the RSP session was deliberately cancelled instead of
    /// finished, with the SGP.22 reason.
    pub session_cancelled: Option<&'static str>,
    pub cancel_error: Option<String>,
    /// Where this stopped, when it stopped short of installing.
    pub stopped_after: Option<String>,
}

impl<T: QmiTransport> QmiClient<T> {
    /// Download one profile onto the eUICC and tell its SM-DP+ it arrived.
    ///
    /// One ISD-R channel for the whole thing, and it has to be: an RSP session
    /// is state the card holds between `AuthenticateServer` and the last block
    /// of the profile package, and a channel that closed in the middle would
    /// take the session with it.
    ///
    /// Installs. Does not enable. SGP.22 keeps those apart and so does this:
    /// the module on the bench has exactly one working profile and enabling a
    /// new one would take the network away from whoever is using it.
    pub fn download_esim_profile(
        &mut self,
        slot: u8,
        client: &Es9pClient,
        request: &DownloadRequest<'_>,
    ) -> Result<DownloadOutcome, SessionError> {
        let mut session = self.isdr_session(slot)?;
        let outcome = session.run_download(client, request);
        session.close()?;
        outcome
    }
}

impl<T: QmiTransport> IsdrSession<'_, T> {
    /// Run one ES10 request and say how many `STORE DATA` blocks it took.
    pub fn execute_counted(&mut self, payload: &[u8]) -> Result<(Vec<u8>, usize), SessionError> {
        let chain = es10c::store_data_chain(payload)?;
        let blocks = chain.len();
        let last = blocks - 1;
        let mut answer = Vec::new();
        for (index, apdu) in chain.iter().enumerate() {
            let response = self.transmit(apdu)?;
            if !response.is_success() {
                return Err(SessionError::Uim(UimError::ApduFailed {
                    sw1: response.sw1,
                    sw2: response.sw2,
                }));
            }
            if index == last {
                answer = response.data;
            }
        }
        Ok((answer, blocks))
    }

    /// ES10b `AuthenticateServer`: the card judges the SM-DP+.
    ///
    /// The first request in this project large enough to need more than one
    /// `STORE DATA` block against a real card. A server certificate alone is
    /// six hundred bytes.
    pub fn authenticate_server(
        &mut self,
        start: &AuthenticationStart,
        matching_id: Option<&str>,
        imei: &str,
    ) -> Result<(Vec<u8>, usize), SessionError> {
        let payload = es10c::authenticate_server_payload(
            &start.server_signed1,
            &start.server_signature1,
            &start.euicc_ci_pkid_der,
            &start.server_certificate,
            matching_id,
            es10c::tac_from_imei(imei)?,
        )?;
        let (bytes, blocks) = self.execute_counted(&payload)?;
        Ok((es10c::parse_authenticate_server_response(&bytes)?, blocks))
    }

    /// ES10b `PrepareDownload`: the card accepts the profile's key material.
    pub fn prepare_download(
        &mut self,
        authentication: &ClientAuthentication,
        confirmation_code: Option<&str>,
    ) -> Result<(Vec<u8>, usize), SessionError> {
        let required = es10c::confirmation_code_required(&authentication.smdp_signed2)?;
        let hash = if required {
            let code = confirmation_code.ok_or_else(|| {
                SessionError::transport(
                    "the SM-DP+ requires a confirmation code and none was supplied",
                )
            })?;
            let transaction_id = es10c::smdp_signed2_transaction_id(&authentication.smdp_signed2)?;
            Some(es9p::hash_confirmation_code(code, &transaction_id))
        } else {
            None
        };
        let payload = es10c::prepare_download_payload(
            &authentication.smdp_signed2,
            &authentication.smdp_signature2,
            &authentication.smdp_certificate,
            hash.as_ref().map(|value| &value[..]),
        )?;
        let (bytes, blocks) = self.execute_counted(&payload)?;
        Ok((es10c::parse_prepare_download_response(&bytes)?, blocks))
    }

    /// Feed a Bound Profile Package to the eUICC, segment by segment.
    ///
    /// The card answers most segments with nothing at all. The moment it
    /// answers with bytes, that is a `ProfileInstallationResult` and the
    /// transfer is over — successfully if it is the last segment, and as a
    /// named failure if it is not. Carrying on after that would push the rest
    /// of a profile at a card that has already closed the channel.
    pub fn load_bound_profile_package(
        &mut self,
        package: &[u8],
    ) -> Result<(InstallationResult, Vec<SegmentTransfer>), SessionError> {
        let segments = es10c::bound_profile_package_segments(package)?;
        let mut transfers = Vec::with_capacity(segments.len());
        let mut result = None;
        for segment in &segments {
            let (answer, blocks) = self.execute_counted(&segment.bytes)?;
            transfers.push(SegmentTransfer {
                label: segment.label.clone(),
                bytes: segment.bytes.len(),
                blocks,
            });
            if !answer.is_empty() {
                result = Some(es10c::parse_installation_result(&answer)?);
                break;
            }
        }
        match result {
            Some(result) => Ok((result, transfers)),
            None => Err(SessionError::transport(
                "the eUICC accepted every segment of the profile package without \
                 returning a ProfileInstallationResult",
            )),
        }
    }

    /// ES10b `RemoveNotificationFromList`. Returns the card's own code: 0 is
    /// removed, 1 is "there was nothing there".
    pub fn remove_notification(&mut self, sequence_number: u64) -> Result<u64, SessionError> {
        let bytes = self.execute(&es10c::remove_notification_payload(sequence_number))?;
        Ok(es10c::parse_remove_notification_response(&bytes)?)
    }

    /// ES10b `CancelSession`, returning the signed answer ES9+ has to relay.
    pub fn cancel_session(
        &mut self,
        transaction_id: &[u8],
        reason: es10c::CancelSessionReason,
    ) -> Result<Vec<u8>, SessionError> {
        let bytes = self.execute(&es10c::cancel_session_payload(transaction_id, reason))?;
        Ok(es10c::parse_cancel_session_response(&bytes)?)
    }

    /// Read what the chip holds right now.
    fn snapshot(&mut self) -> Result<EuiccSnapshot, SessionError> {
        Ok(EuiccSnapshot {
            free_non_volatile_memory: self.euicc_info2()?.free_non_volatile_memory,
            profiles: self.list_profiles()?,
            notifications: self.list_notifications()?,
        })
    }

    /// The whole download, on one channel.
    fn run_download(
        &mut self,
        client: &Es9pClient,
        request: &DownloadRequest<'_>,
    ) -> Result<DownloadOutcome, SessionError> {
        let mut outcome = DownloadOutcome {
            eid: self.read_eid()?,
            smdp_address: request.activation_code.smdp_address.clone(),
            matching_id_present: request.activation_code.matching_id.is_some(),
            before: self.snapshot()?,
            ..DownloadOutcome::default()
        };

        let challenge = self.euicc_challenge()?;
        let info1 = self.euicc_info1()?;
        outcome.euicc_challenge = challenge;
        outcome.chip_ci_key_ids = info1.ci_key_ids_for_verification.clone();

        let start = client
            .initiate_authentication(&outcome.smdp_address, &challenge, &info1.raw)
            .map_err(SessionError::from)?;
        outcome.transaction_id = start.transaction_id.clone();
        outcome.echoed_euicc_challenge = start.echoed_euicc_challenge.clone();
        outcome.server_challenge = start.server_challenge.clone();
        outcome.euicc_ci_pkid_to_be_used = start.euicc_ci_pkid_to_be_used.clone();
        outcome.ci_key_accepted_by_chip = outcome
            .chip_ci_key_ids
            .iter()
            .any(|key| key == &start.euicc_ci_pkid_to_be_used);
        outcome.verification = start.verification.clone();
        outcome.negotiated_tls = start.negotiated_tls.clone();
        outcome.admin_protocol = start.admin_protocol.clone();
        outcome.http.push(HttpStep {
            step: "initiateAuthentication",
            http_status: start.http_status,
            elapsed_ms: start.elapsed_ms,
        });

        // The card is asked to judge the server before the server is told
        // anything about the order. A chip that will not authenticate this
        // SM-DP+ ends the session here, with the activation code untouched.
        let (server_response, blocks) = self.authenticate_server(
            &start,
            request.activation_code.matching_id.as_deref(),
            request.imei,
        )?;
        outcome.authenticate_server_blocks = blocks;

        // From here the SM-DP+ knows which order this is, so every exit runs
        // `cancelSession` rather than walking away.
        let transaction_bytes = hex_bytes(&start.transaction_id_raw);
        let authentication = match client.authenticate_client(
            &outcome.smdp_address,
            &start.transaction_id_raw,
            &server_response,
        ) {
            Ok(authentication) => authentication,
            Err(error) => {
                // The card is holding an RSP session that will now never be
                // finished, so it is closed here even though the server has
                // nothing to give back: a refused matching id is a thing an
                // operator retypes and tries again, and the retry has to find
                // the chip in the state it started in. Best effort, and the
                // ES9+ half is deliberately skipped — the server dropped the
                // transaction when it refused, and a cancel for a transaction
                // it has never heard of answers with an error that would
                // replace the one worth reading.
                let _ = self.cancel_session(
                    &transaction_bytes,
                    es10c::CancelSessionReason::UndefinedReason,
                );
                return Err(SessionError::from(error));
            }
        };
        outcome.http.push(HttpStep {
            step: "authenticateClient",
            http_status: authentication.http_status,
            elapsed_ms: authentication.elapsed_ms,
        });

        let metadata = es10c::parse_profile_metadata(&authentication.profile_metadata)?;
        outcome.confirmation_code_required =
            es10c::confirmation_code_required(&authentication.smdp_signed2)?;
        let refused = metadata.irreversible_policy_rules();
        outcome.metadata = Some(metadata);

        // The gate. `ppr1` forbids ever disabling this profile and `ppr2`
        // forbids ever deleting it, and both are permanent from the moment the
        // package is installed. There are two eUICCs on this bench and nobody
        // can physically reach either one, so a profile that cannot be removed
        // is a slot that is gone. The profile is handed back rather than
        // installed.
        if !refused.is_empty() {
            outcome.refused_policy_rules = refused.clone();
            outcome.stopped_after = Some(format!(
                "the profile carries {}, which cannot be removed once installed",
                refused.join(" and ")
            ));
            self.give_back_session(
                client,
                &mut outcome,
                &transaction_bytes,
                &start.transaction_id_raw,
                es10c::CancelSessionReason::PprNotAllowed,
            );
            outcome.after = Some(self.snapshot()?);
            return Ok(outcome);
        }

        let (prepared, blocks) = self.prepare_download(&authentication, request.confirmation_code)?;
        outcome.prepare_download_blocks = blocks;

        // The point of no return at the server.
        let bound = client
            .get_bound_profile_package(
                &outcome.smdp_address,
                &start.transaction_id_raw,
                &prepared,
            )
            .map_err(SessionError::from)?;
        outcome.http.push(HttpStep {
            step: "getBoundProfilePackage",
            http_status: bound.http_status,
            elapsed_ms: bound.elapsed_ms,
        });
        outcome.bpp_bytes = bound.package.len();

        let (installation, transfers) = self.load_bound_profile_package(&bound.package)?;
        outcome.bpp_blocks = transfers.iter().map(|transfer| transfer.blocks).sum();
        outcome.bpp_segments = transfers;
        outcome.installed = installation.success;
        let notification = installation.notification.clone();
        let sequence_number = installation.sequence_number;
        outcome.notification_bytes = notification.len();
        outcome.installation = Some(installation);

        // The notification is delivered whether the installation succeeded or
        // failed: SGP.22 requires the SM-DP+ to be told either way, and a
        // failure it never hears about leaves the profile stuck at its end.
        // Only this one notification goes. The chip is also holding older ones
        // from a previous life, and delivering those would tell an operator to
        // act on profiles nobody asked about.
        match client.handle_notification(&outcome.smdp_address, &notification) {
            Ok(acknowledgement) => {
                outcome.notification_delivered = true;
                outcome.http.push(HttpStep {
                    step: "handleNotification",
                    http_status: acknowledgement.http_status,
                    elapsed_ms: acknowledgement.elapsed_ms,
                });
                // Removed only once the server has it. The other order loses
                // the notification if the delivery fails, and the card will
                // not produce it again.
                if let Some(sequence_number) = sequence_number {
                    match self.remove_notification(sequence_number) {
                        Ok(code) => outcome.notification_removed = Some(code),
                        Err(error) => {
                            outcome.notification_delivery_error = Some(format!(
                                "delivered, but the card would not remove it: {error}"
                            ))
                        }
                    }
                }
            }
            Err(error) => outcome.notification_delivery_error = Some(error.to_string()),
        }

        outcome.after = Some(self.snapshot()?);
        if !outcome.installed {
            outcome.stopped_after = Some("the eUICC refused the profile package".into());
        }
        Ok(outcome)
    }

    /// Hand a claimed profile back to its SM-DP+.
    ///
    /// Best effort and recorded rather than raised: this runs on a path that
    /// already has a reason to report, and replacing that reason with "the
    /// cancel failed" would hide why the download was abandoned.
    fn give_back_session(
        &mut self,
        client: &Es9pClient,
        outcome: &mut DownloadOutcome,
        transaction_bytes: &[u8],
        transaction_id: &str,
        reason: es10c::CancelSessionReason,
    ) {
        outcome.session_cancelled = Some(reason.label());
        match self.cancel_session(transaction_bytes, reason) {
            Ok(response) => {
                match client.cancel_session(&outcome.smdp_address, transaction_id, &response) {
                    Ok(acknowledgement) => outcome.http.push(HttpStep {
                        step: "cancelSession",
                        http_status: acknowledgement.http_status,
                        elapsed_ms: acknowledgement.elapsed_ms,
                    }),
                    Err(error) => outcome.cancel_error = Some(error.to_string()),
                }
            }
            Err(error) => outcome.cancel_error = Some(error.to_string()),
        }
    }
}

/// Decode an even-length hex string, ignoring anything that is not hex.
///
/// The transaction id arrives as text and the card wants the bytes. A
/// permissive reader is right here: the string came from a server that has
/// already been authenticated, and the alternative is a download that fails at
/// the cancel step because of a separator.
fn hex_bytes(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text
        .chars()
        .filter_map(|character| character.to_digit(16).map(|digit| digit as u8))
        .collect();
    digits.chunks(2).map(|pair| match pair {
        [high, low] => (high << 4) | low,
        [high] => high << 4,
        _ => 0,
    }).collect()
}

// ───────────────────────────────────────────────────────────────────────────
// Restarting a module's radio without stranding it
// ───────────────────────────────────────────────────────────────────────────
//
// # What happened on 2026-08-25
//
// The Restart button ran `set_operating_mode(Offline)` and then
// `set_operating_mode(Online)`. On the bench the first request was accepted
// and the second came back `QMI request rejected with result 1 error 60`.
// The module stopped there, and it could not be got out again:
//
// * `AT+CFUN?` answered `+CFUN: 7` — Quectel's offline mode — while
//   `AT+CPIN?` still answered `READY`, so the AT port and the card were fine
//   and only the radio was down;
// * further QMI mode changes were refused with `error 60` in **both**
//   directions;
// * `AT+CFUN=0`, `AT+CFUN=1` and `AT+CFUN=4` all answered `+CME ERROR: 4`.
//
// The one thing that worked was `AT+CFUN=1,1`. Nobody can reach this hardware
// to pull a stick, so a button that can land a module there is a button that
// can take a module away for good.
//
// # What this code does about it, and what it deliberately does not do
//
// 1. **`OperatingMode::Offline` is never requested.** It was measured to be a
//    one-way door on this firmware, and nothing the Restart button is for
//    needs it. `LowPower` is the mode the radio toggle and the address
//    rotation already use many times a day, in both directions, on these same
//    three sticks.
// 2. **`+CFUN?` is read before and after, and the two readings decide the
//    result** — not the return codes of the mode requests. A restart that
//    reports success while the module sits at `+CFUN: 4` is the failure this
//    project keeps rediscovering, most recently as a profile switch that
//    answered `{"status":"ok"}` and changed nothing on the card.
// 3. **A refusal is followed by a recovery ladder** of cheap, non-resetting
//    rungs, and if the module is still not back the call **fails, loudly, and
//    says where the module was left**.
// 4. **A module found already at `+CFUN: 7` is not touched at all**, because
//    from that state every QMI mode request was measured to be refused.
//
// # The contradiction, written down so nobody has to derive it again
//
// `AT+CFUN=1,1` is at once **the only measured cure for this wedge** and the
// **forbidden form** named in `edge-panel`'s `set_radio` documentation
// ("this goes through QMI rather than `AT+CFUN`, whose reset form wedges a
// module often enough that it is not worth exposing on a button") and in the
// note on the panel's raw AT endpoint, which is LAN-only precisely so that
// `AT+CFUN=1,1` cannot be fired from the cloud.
//
// Both statements are true, and they are about different situations:
//
// * `set_radio` refuses the reset form as the **ordinary** way to do something
//   a plain QMI `LowPower` round trip already does cleanly. Trading a working
//   cheap mechanism for a full re-enumeration buys nothing and risks a stick
//   that does not come back — over USB/IP, with nobody able to replug it.
// * Here the module is **already unusable**, and every cheap mechanism has
//   been measured to fail from this exact state. The trade is no longer
//   "cheap and safe versus expensive and risky".
//
// So why is it still not automatic here? Because a stranded module is not a
// dead one. At `+CFUN: 7` the AT port answers, the card is `READY`, and the
// eUICC can still be read and driven — the radio is what is lost. A reset that
// fails to re-enumerate loses all of that as well, and this bench has exactly
// **one** observation of `AT+CFUN=1,1` clearing this state cleanly (about
// forty seconds, without the module leaving the USB bus). One sample is enough
// to name the cure in an error message. It is not enough to fire it,
// unprompted, at hardware nobody can reach. The escalation is left to a human
// at the LAN-only `/api/at` endpoint, which is where destructive AT already
// lives and where the blast radius is already bounded to the site.
//
// `OperatingMode::Resetting` (4) was considered as a middle path and rejected
// for the same reason: it re-enumerates too, and it has never been tried on
// these modules at all — zero samples is worse than one.

/// `+CFUN` values as an EC20 reports them.
///
/// 27.007 defines 0, 1 and 4. 7 is Quectel's own offline mode, and it is what
/// the module shows after QMI has been asked for `OperatingMode::Offline`.
pub const CFUN_MINIMUM: u8 = 0;
/// Full functionality — the only value a finished restart may leave behind.
pub const CFUN_FULL: u8 = 1;
/// Radio off, card still initialised.
pub const CFUN_DISABLE_RF: u8 = 4;
/// The stranded value. Getting in is easy; every documented way out fails.
pub const CFUN_OFFLINE: u8 = 7;

/// Said in every error where the module is, or is left, stranded.
///
/// A constant rather than prose at each site, so the one dangerous thing an
/// operator may be about to type is described the same way every time —
/// including the part about why the software will not type it for them.
pub const CFUN_RESET_NOTE: &str = "the only measured way out of +CFUN: 7 is AT+CFUN=1,1 over \
     the LAN-only /api/at endpoint; this agent will not issue it by itself, because a stranded \
     module still has a working AT port, a READY card and a reachable eUICC, and a reset that \
     fails to re-enumerate over USB/IP loses those too";

/// How long the module is given to act on a mode change before a read-back is
/// believed.
///
/// `AT+CFUN=1` answers `OK` before the radio is actually up, and a QMI mode
/// change is applied asynchronously by the same firmware. Reading `+CFUN?` the
/// instant a request returns therefore measures the request, not the module.
const SETTLE_STEP: Duration = Duration::from_millis(1_500);

/// How many times the read-back is retried before the module is called stuck.
///
/// Twelve seconds, against a bench measurement of about fifteen for a full
/// `AT+CFUN=0` / `AT+CFUN=1` cycle to reach `+CPIN: READY` — the `+CFUN?`
/// value flips well before registration does.
const SETTLE_ATTEMPTS: usize = 8;

/// The gap between `AT+CFUN=0` and `AT+CFUN=1` on the last rung.
///
/// Three seconds because that is the only interval this pair has ever been
/// measured with on this bench (T085, `867018069509705`, 2026-08-25). The
/// ladder used to reuse `SETTLE_STEP` here, which is 1.5s and has never been
/// tried — and "3s works" does not imply "1.5s works" for a firmware that is
/// powering the card down and back up. The rung is only reached when a restart
/// has already gone wrong, so the extra second and a half buys removal of an
/// untested assumption at no cost anybody will notice.
const CFUN_CYCLE_GAP: Duration = Duration::from_millis(3_000);

/// How many times `AT+CPIN?` is read before the card is called "not ready
/// yet".
///
/// An upper bound on patience, **not** a prediction of how long the card
/// takes. There is no honest number for that: the same `AT+CFUN=0` /
/// `AT+CFUN=1` pair reached `+CPIN: READY` in about 15s on `867018069514820`
/// (T079) and in 2.3s on `867018069509705` (T085) — a factor of three between
/// two sticks of the same model. Anything hard-coded as "the" duration is
/// therefore wrong on one of them, which is why the success criterion below is
/// a state and this constant only decides when to stop asking.
///
/// 20 attempts × `SETTLE_STEP` is a little under thirty seconds, roughly twice
/// the slowest reading anyone has taken, so a card that is merely slow is not
/// reported as a card that is missing.
const CARD_ATTEMPTS: usize = 20;

/// Said whenever a restart ends with the radio up and the card not there.
///
/// It names the one thing that has cleared this state on this bench, and in
/// the same breath says why the agent does not do it: the symptom has been
/// seen twice and the same pair of commands cleared it twice, and n=2 is an
/// empirical regularity, not a mechanism. Nobody has established *why* the
/// card falls off, so nothing here is allowed to fire it automatically at
/// hardware the operator cannot unplug.
pub const CARD_RECOVERY_NOTE: &str = "on this bench a card in this state has been brought back \
     twice by AT+CFUN=0, a few seconds, then AT+CFUN=1 over the LAN-only /api/at endpoint \
     (about 15s on 867018069514820, 2.3s on 867018069509705, neither left the USB bus); this \
     agent will not issue it by itself, because two successes are an empirical regularity and \
     not an established mechanism, and the failure it treats is not understood";

/// What the card says about itself, as read from `AT+CPIN?`.
///
/// Three separate things come back at three separate times after the radio is
/// told to come up — the radio, then the card, then the network — and this
/// type exists because the middle one used to be invisible to this module.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CardState {
    /// `+CPIN: READY`. The card has finished initialising.
    Ready,
    /// `+CME ERROR: 14`, SIM busy. The card is initialising right now; this is
    /// the good intermediate state, and waiting is exactly the right response
    /// to it.
    Initialising,
    /// `+CME ERROR: 10` (not inserted) or `13` (SIM failure). Read literally
    /// this says there is no card, but on this bench a card answering 13 has
    /// twice gone 13 → 14 → `READY` on its own after a functionality cycle, so
    /// it is not treated as final either.
    Absent(u16),
    /// `+CPIN: SIM PIN` and its relatives. Someone has to type something; no
    /// amount of waiting turns this into `READY`, so the wait stops here.
    Locked(String),
    /// Anything else the module said.
    Unknown(String),
}

impl CardState {
    /// The only state in which the module is usable by anything that touches
    /// the card — AKA, eUICC sessions, IMSI reads, messaging.
    pub fn is_ready(&self) -> bool {
        matches!(self, Self::Ready)
    }

    /// Whether polling again could plausibly change the answer.
    ///
    /// `false` only for a card that is waiting on a human. Everything else is
    /// worth re-reading until the bound runs out, including `Unknown`: an
    /// unrecognised answer is a reason to keep looking, not a reason to
    /// conclude.
    pub fn waiting_can_help(&self) -> bool {
        !matches!(self, Self::Ready | Self::Locked(_))
    }
}

impl fmt::Display for CardState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ready => write!(formatter, "+CPIN: READY"),
            Self::Initialising => write!(formatter, "+CME ERROR: 14 (SIM busy, initialising)"),
            Self::Absent(code) => write!(formatter, "+CME ERROR: {code} (no usable card)"),
            Self::Locked(code) => write!(formatter, "+CPIN: {code} (waiting for a code)"),
            Self::Unknown(text) => write!(formatter, "unrecognised +CPIN answer: {text}"),
        }
    }
}

/// The Quectel-specific readings taken alongside `AT+CPIN?`.
///
/// Recorded, never a gate. `AT+CPIN?` is the criterion because it is the one
/// reading whose transition has been measured on two different sticks; these
/// two are corroboration for whoever reads the report afterwards. `+QINISTAT`
/// in particular reaches 7 only once SMS and phonebook initialisation are also
/// finished, and nobody has established that every card here gets there —
/// gating on it would risk calling a perfectly usable module broken.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CardEvidence {
    /// The second field of `+QSIMSTAT: <urc>,<inserted>`.
    pub inserted: Option<bool>,
    /// `+QINISTAT` as a bitmask: 1 CPIN done, 2 SMS done, 4 phonebook done,
    /// so 7 is everything and 0 is a card that has not started.
    pub init_status: Option<u8>,
}

impl fmt::Display for CardEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "+QSIMSTAT {}, +QINISTAT {}",
            match self.inserted {
                Some(true) => "inserted".to_string(),
                Some(false) => "no card".to_string(),
                None => "unread".to_string(),
            },
            match self.init_status {
                Some(value) => value.to_string(),
                None => "unread".to_string(),
            }
        )
    }
}

/// Read an `AT+CPIN?` exchange the way the module actually answers it.
///
/// Both halves matter: a ready card answers on a `+CPIN:` line and terminates
/// `OK`, while a card that is missing or busy produces **no lines at all** and
/// puts everything in the terminator. Passing only the lines would make the
/// two most important states — busy and absent — indistinguishable from each
/// other and from silence.
pub fn parse_cpin(lines: &[String], terminator: &str) -> CardState {
    if let Some(state) = lines.iter().find_map(|line| {
        let rest = line.trim().strip_prefix("+CPIN:")?;
        let value = rest.trim();
        Some(if value.eq_ignore_ascii_case("READY") {
            CardState::Ready
        } else {
            CardState::Locked(value.to_string())
        })
    }) {
        return state;
    }
    let terminator = terminator.trim();
    if let Some(code) = terminator
        .strip_prefix("+CME ERROR:")
        .and_then(|rest| rest.trim().parse::<u16>().ok())
    {
        return match code {
            // 14 is the one worth telling apart: it means the card is busy
            // initialising, which is the difference between "wait" and
            // "something is wrong".
            14 => CardState::Initialising,
            other => CardState::Absent(other),
        };
    }
    CardState::Unknown(if terminator.is_empty() {
        "no answer".to_string()
    } else {
        terminator.to_string()
    })
}

/// The insertion flag out of `+QSIMSTAT: <urc>,<inserted>`.
pub fn parse_qsimstat(lines: &[String]) -> Option<bool> {
    lines.iter().find_map(|line| {
        let rest = line.trim().strip_prefix("+QSIMSTAT:")?;
        let inserted = rest.split(',').nth(1)?.trim();
        Some(inserted == "1")
    })
}

/// The bitmask out of `+QINISTAT: <mask>`.
pub fn parse_qinistat(lines: &[String]) -> Option<u8> {
    lines.iter().find_map(|line| {
        let rest = line.trim().strip_prefix("+QINISTAT:")?;
        rest.split(',').next()?.trim().parse::<u8>().ok()
    })
}

/// The two control paths a radio restart needs on one module.
///
/// QMI and AT reach the same firmware over different USB interfaces of the
/// same stick, and a restart has to interleave them: the mode change is a QMI
/// request and the only trustworthy read-back is an AT one. Both sit behind
/// this trait so that the ladder above them can be exercised without hardware
/// — which matters more than usual here, because the failure being defended
/// against is one nobody is willing to reproduce on the bench.
pub trait ModuleRadio {
    /// `QMI_DMS_GET_OPERATING_MODE`.
    fn operating_mode(&mut self) -> Result<OperatingMode, String>;
    /// `QMI_DMS_SET_OPERATING_MODE`.
    fn set_operating_mode(&mut self, mode: OperatingMode) -> Result<(), String>;
    /// `AT+CFUN?`. `Ok(None)` means the module answered without a `+CFUN:`
    /// line; `Err` means the port itself could not be used.
    fn read_functionality(&mut self) -> Result<Option<u8>, String>;
    /// `AT+CFUN=<value>`. `Ok(false)` means the module answered with an error
    /// result code, which is still an answer; `Err` is for losing the port.
    fn write_functionality(&mut self, value: u8) -> Result<bool, String>;
    /// `AT+CPIN?`.
    ///
    /// Every answer, including `+CME ERROR`, is a reading and comes back as
    /// `Ok`; `Err` is only for losing the port. That is the opposite of
    /// `read_functionality`, on purpose — there, an error result code means
    /// the module will not say where its radio is and the restart must not
    /// proceed; here, the error codes *are* the interesting states.
    fn read_card_state(&mut self) -> Result<CardState, String>;
    /// `AT+QSIMSTAT?` and `AT+QINISTAT`, for the report only.
    ///
    /// Defaulted to nothing so that an implementation which cannot ask
    /// Quectel-specific questions is not forced to lie about them; the
    /// criterion never depends on this.
    fn read_card_evidence(&mut self) -> CardEvidence {
        CardEvidence::default()
    }
    /// Wait for the module to act on what it was just told.
    ///
    /// A hook rather than a `thread::sleep` inside the ladder, so the ladder
    /// runs at full speed under test and patiently on hardware, without either
    /// side having to know about the other.
    fn pause(&mut self, duration: Duration);
}

/// What a restart did, and where it left the module.
///
/// Carried on success as well as on failure: "it worked" is not a useful
/// receipt for an operation whose whole problem was reporting a success it had
/// not earned.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RestartReport {
    pub cfun_before: Option<u8>,
    pub cfun_after: Option<u8>,
    pub mode_after: Option<OperatingMode>,
    /// Where the card was when the wait for it ended. `None` means the radio
    /// never came back, so the card was never reached.
    pub card_after: Option<CardState>,
    /// The corroborating card readings, where they could be taken.
    pub card_evidence: CardEvidence,
    /// Every rung that was attempted, in order.
    pub steps: Vec<String>,
}

impl fmt::Display for RestartReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "before {}, after {}, QMI {}, card {} ({}); tried: {}",
            describe_cfun(self.cfun_before),
            describe_cfun(self.cfun_after),
            match self.mode_after {
                Some(mode) => format!("{mode:?}"),
                None => "unreadable".to_string(),
            },
            match &self.card_after {
                Some(state) => state.to_string(),
                None => "not reached".to_string(),
            },
            self.card_evidence,
            if self.steps.is_empty() {
                "nothing".to_string()
            } else {
                self.steps.join(" | ")
            }
        )
    }
}

/// Why a restart did not finish cleanly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RestartError {
    /// `AT+CFUN?` could not be read, so nothing was done to the radio.
    Unverifiable { reason: String },
    /// A control port stopped answering. `step` says what was in flight,
    /// because "we never started" and "we are half way" are different states
    /// for the next operator to inherit.
    Port {
        step: String,
        reason: String,
        report: RestartReport,
    },
    /// The module was already at `+CFUN: 7` when the restart was asked for.
    /// Nothing was sent to it.
    AlreadyStranded(RestartReport),
    /// The module went down and would not come back, and every non-resetting
    /// rung has been tried.
    Stranded(RestartReport),
    /// The module answered, but not where it was asked to be — including the
    /// case where QMI and `+CFUN?` disagree about where that is.
    NotRestored(RestartReport),
    /// The radio came back and the card did not. **This is not a failed
    /// restart** — see `radio_restored` and the comment on the wait itself.
    CardNotReady(RestartReport),
}

impl fmt::Display for RestartError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unverifiable { reason } => write!(
                formatter,
                "refusing to restart: AT+CFUN? could not be read ({reason}), so there would be \
                 no way to tell whether the radio came back"
            ),
            Self::Port {
                step,
                reason,
                report,
            } => write!(formatter, "restart lost the module at {step}: {reason}; {report}"),
            Self::AlreadyStranded(report) => write!(
                formatter,
                "this module is already stranded offline and a restart cannot help it: every QMI \
                 mode change from here was measured to be refused with error 60 ({report}); \
                 {CFUN_RESET_NOTE}"
            ),
            Self::Stranded(report) => write!(
                formatter,
                "the module did not come back online ({report}); {CFUN_RESET_NOTE}"
            ),
            Self::NotRestored(report) => write!(
                formatter,
                "restart did not leave the module online ({report}); the radio is down but not \
                 stranded, so bringing it up with the radio control or asking for another \
                 restart is the next thing to try"
            ),
            Self::CardNotReady(report) => write!(
                formatter,
                "the radio came back but the card did not: AT+CPIN? never reached READY \
                 ({report}); the module is online and answering, so this is not a failed \
                 restart and asking for another one is not the fix — {CARD_RECOVERY_NOTE}"
            ),
        }
    }
}

impl Error for RestartError {}

impl RestartError {
    /// The report, where there is one. For a caller that wants to log what was
    /// tried even though the call failed.
    pub fn report(&self) -> Option<&RestartReport> {
        match self {
            Self::Unverifiable { .. } => None,
            Self::Port { report, .. }
            | Self::AlreadyStranded(report)
            | Self::Stranded(report)
            | Self::NotRestored(report)
            | Self::CardNotReady(report) => Some(report),
        }
    }

    /// Whether the radio is up despite this not being an `Ok`.
    ///
    /// There are two different things a caller can be told here and it must be
    /// able to tell them apart without reading prose: "the restart did not
    /// work, the module's radio is down" and "the restart worked, the radio is
    /// online, and the card on it is not usable". The second one is not an
    /// argument for restarting again, and it does not mean the module is lost
    /// — it means the next step is about the card, not about the radio.
    pub fn radio_restored(&self) -> bool {
        matches!(self, Self::CardNotReady(_))
    }

    /// A short, stable code for the command result, so the console can tell
    /// these apart without parsing prose.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unverifiable { .. } => "restart_unverifiable",
            Self::Port { .. } => "restart_port_lost",
            Self::AlreadyStranded(_) => "modem_already_stranded",
            Self::Stranded(_) => "modem_stranded_offline",
            Self::NotRestored(_) => "restart_not_restored",
            Self::CardNotReady(_) => "restart_card_not_ready",
        }
    }
}

/// Take one module's radio down and bring it back, or say why it is not back.
///
/// The contract is the point: this returns `Ok` only when the module has been
/// read to be online again by two independent means **and** the card on it has
/// been read to be initialised. Everything else is an error naming the state
/// the module is actually in.
///
/// # Where the line is drawn, and why
///
/// Coming back is three events, not one, and on 2026-08-25 they were measured
/// on `867018069509705` at three different times after `AT+CFUN=1`:
///
/// | reading | when |
/// | --- | --- |
/// | `AT+CFUN=1` answers `OK` | 294ms |
/// | `AT+CPIN?` still `+CME ERROR: 14` | 0.3s |
/// | `AT+CPIN?` reads `READY` | 2.3s |
/// | `AT+CREG?` reads `0,1` | 5.4s |
///
/// This function guarantees the **first two** layers: radio online, card
/// initialised. It deliberately does **not** wait for registration.
///
/// Registration is the only one of the three that depends on something outside
/// this box. A module sitting where its operator has no coverage never
/// registers, and it is still a perfectly working module — `867018069509705`
/// spent days at `+COPS: 2` for exactly that reason. Waiting for `+CREG` would
/// turn "no signal here" into "your restart failed", which is a worse lie than
/// the one this change is fixing. The card, by contrast, is entirely local:
/// nothing outside the stick decides whether it initialises, and everything a
/// caller does after a restart — AKA, eUICC sessions, IMSI reads, messaging —
/// fails with `+CME ERROR: 13`/`14` until it has.
///
/// So: `Ok` means "usable". Registration is the caller's own business, and the
/// poll loop that watches for it is already elsewhere.
pub fn restart_radio<R: ModuleRadio>(radio: &mut R) -> Result<RestartReport, RestartError> {
    let mut report = RestartReport::default();

    // Read first. A restart that cannot be checked is not offered at all: the
    // whole reason this function exists is a mode change whose failure was
    // invisible until somebody went looking with `AT+CFUN?`.
    let before = radio
        .read_functionality()
        .map_err(|reason| RestartError::Unverifiable { reason })?;
    report.cfun_before = before;
    report.steps.push(format!("before {}", describe_cfun(before)));

    if before == Some(CFUN_OFFLINE) {
        // Send nothing. From here both directions of the QMI mode change were
        // measured to answer error 60, so a request now would add nothing but
        // a second failure to explain.
        report.cfun_after = before;
        report.steps.push("already offline, QMI left alone".to_string());
        return Err(RestartError::AlreadyStranded(report));
    }

    // Down. `LowPower`, never `Offline` — see the note at the top of this
    // section for what `Offline` did to a module nobody can go and touch.
    if let Err(reason) = radio.set_operating_mode(OperatingMode::LowPower) {
        report.steps.push(format!("QMI low power refused: {reason}"));
        report.cfun_after = radio.read_functionality().ok().flatten();
        return Err(RestartError::Port {
            step: "low_power".to_string(),
            reason,
            report,
        });
    }
    report.steps.push("QMI low power accepted".to_string());

    // Up.
    let refused = radio.set_operating_mode(OperatingMode::Online).err();
    match &refused {
        None => report.steps.push("QMI online accepted".to_string()),
        Some(reason) => report.steps.push(format!("QMI online refused: {reason}")),
    }

    // Believe the module, not the request. An accepted request that did not
    // take gets the same ladder a refused one gets; the only difference is
    // that there is no point waiting on a module that has already said no.
    if !(refused.is_none() && wait_for_full(radio, &mut report)) {
        climb_back(radio, &mut report);
    }

    let after = match radio.read_functionality() {
        Ok(value) => value,
        Err(reason) => {
            return Err(RestartError::Port {
                step: "read_back".to_string(),
                reason,
                report,
            })
        }
    };
    report.cfun_after = after;
    match radio.operating_mode() {
        Ok(mode) => report.mode_after = Some(mode),
        Err(reason) => report.steps.push(format!("QMI mode unreadable: {reason}")),
    }
    report.steps.push(format!("after {}", describe_cfun(after)));

    if after == Some(CFUN_OFFLINE) {
        return Err(RestartError::Stranded(report));
    }
    if after != Some(CFUN_FULL) {
        return Err(RestartError::NotRestored(report));
    }
    // Two readings, and both have to agree. `+CFUN: 1` while QMI still reports
    // anything else is the exact shape of a success that is not one, and this
    // section exists because that shape was reported as `ok` once already.
    if report.mode_after != Some(OperatingMode::Online) {
        return Err(RestartError::NotRestored(report));
    }

    // The radio is back. Now find out whether the module is usable, which is a
    // different question and used to be an unasked one.
    //
    // Nothing below sends anything to the module except reads. In particular
    // this does **not** run `AT+CFUN=0` / `AT+CFUN=1` at a card that will not
    // initialise, even though that pair has cleared this state twice: two
    // successes are a regularity, not a mechanism, and firing an unexplained
    // remedy at hardware nobody can unplug is a different decision from the
    // one this function is allowed to make. It reports, and names the remedy
    // for whoever is reading.
    let card = match wait_for_card(radio, &mut report) {
        Ok(state) => state,
        Err(reason) => {
            return Err(RestartError::Port {
                step: "card_read_back".to_string(),
                reason,
                report,
            })
        }
    };
    report.card_evidence = radio.read_card_evidence();
    report.card_after = Some(card.clone());

    if card.is_ready() {
        Ok(report)
    } else {
        Err(RestartError::CardNotReady(report))
    }
}

/// Everything that can be tried to bring a module back **without resetting
/// it**. Deliberately stops one rung short of the thing that is known to work;
/// see the contradiction note at the top of this section.
fn climb_back<R: ModuleRadio>(radio: &mut R, report: &mut RestartReport) {
    // Rung 1: ask QMI again. A mode change refused while the firmware was
    // still acting on the previous one is the cheapest explanation there is,
    // and the retry costs a single request.
    radio.pause(SETTLE_STEP);
    match radio.set_operating_mode(OperatingMode::Online) {
        Ok(()) => {
            report.steps.push("QMI online accepted on retry".to_string());
            if wait_for_full(radio, report) {
                return;
            }
        }
        Err(reason) => report
            .steps
            .push(format!("QMI online refused again: {reason}")),
    }

    // Rung 2: `AT+CFUN=1`. The plain form, which does not reset the module and
    // does not take it off the USB bus. Measured to answer `+CME ERROR: 4` on
    // a module already at `+CFUN: 7`, so it is a candidate and not a cure —
    // but it is free, and the state this ladder usually runs from is low power
    // rather than offline.
    match radio.write_functionality(CFUN_FULL) {
        Ok(true) => {
            report.steps.push("AT+CFUN=1 accepted".to_string());
            if wait_for_full(radio, report) {
                return;
            }
        }
        Ok(false) => report.steps.push("AT+CFUN=1 rejected".to_string()),
        Err(reason) => {
            report.steps.push(format!("AT+CFUN=1 unusable: {reason}"));
            return;
        }
    }

    // Rung 3: `AT+CFUN=0` then `AT+CFUN=1`. On this bench that pair cleared a
    // SIM fault in about fifteen seconds without the module leaving the USB
    // bus. It has never been tried against `+CFUN: 7`, so it is listed here as
    // the last cheap thing rather than as an answer. It is only reached when
    // the single-step form was answered and refused, which means the port is
    // alive and the firmware is taking commands.
    match radio.write_functionality(CFUN_MINIMUM) {
        Ok(true) => report.steps.push("AT+CFUN=0 accepted".to_string()),
        Ok(false) => {
            report.steps.push("AT+CFUN=0 rejected".to_string());
            return;
        }
        Err(reason) => {
            report.steps.push(format!("AT+CFUN=0 unusable: {reason}"));
            return;
        }
    }
    // `CFUN_CYCLE_GAP`, not `SETTLE_STEP`: this is the one pause in the ladder
    // whose length has actually been observed to work on hardware.
    radio.pause(CFUN_CYCLE_GAP);
    match radio.write_functionality(CFUN_FULL) {
        Ok(true) => {
            report
                .steps
                .push("AT+CFUN=1 accepted after AT+CFUN=0".to_string());
            wait_for_full(radio, report);
        }
        Ok(false) => report
            .steps
            .push("AT+CFUN=1 rejected after AT+CFUN=0".to_string()),
        Err(reason) => report
            .steps
            .push(format!("AT+CFUN=1 unusable after AT+CFUN=0: {reason}")),
    }
}

/// Poll `AT+CFUN?` until it reads full functionality, or give up.
///
/// Returns `false` for an unreadable port as well as for a module that stayed
/// down: both mean the caller may not treat the radio as back.
fn wait_for_full<R: ModuleRadio>(radio: &mut R, report: &mut RestartReport) -> bool {
    for attempt in 0..SETTLE_ATTEMPTS {
        match radio.read_functionality() {
            Ok(Some(CFUN_FULL)) => return true,
            Ok(_) => {}
            Err(reason) => {
                report.steps.push(format!("AT+CFUN? unreadable: {reason}"));
                return false;
            }
        }
        if attempt + 1 < SETTLE_ATTEMPTS {
            radio.pause(SETTLE_STEP);
        }
    }
    false
}

/// Poll `AT+CPIN?` until the card is initialised, or until patience runs out.
///
/// The stopping condition is a **state**, never a duration. That is not a
/// stylistic preference: the same functionality cycle reached `READY` in about
/// 15s on one stick and in 2.3s on another, so any sleep long enough for the
/// first is six times too long for the second, and any sleep short enough for
/// the second reports the first as broken. `CARD_ATTEMPTS` bounds how long
/// this is willing to keep asking; it is not a claim about how long the card
/// takes.
///
/// Returns the last state read. `Err` means the AT port was lost, which is a
/// different thing from the card not being ready and is reported as such.
fn wait_for_card<R: ModuleRadio>(
    radio: &mut R,
    report: &mut RestartReport,
) -> Result<CardState, String> {
    let mut last: Option<CardState> = None;
    for attempt in 0..CARD_ATTEMPTS {
        let state = radio.read_card_state()?;
        // Transitions only. The interesting thing about `13 → 14 → READY` is
        // that it happened, not that it was sampled twenty times, and a report
        // nobody can read is not a report.
        if last.as_ref() != Some(&state) {
            report.steps.push(format!("card {state}"));
        }
        let done = state.is_ready() || !state.waiting_can_help();
        last = Some(state);
        if done {
            break;
        }
        if attempt + 1 < CARD_ATTEMPTS {
            radio.pause(SETTLE_STEP);
        }
    }
    Ok(last.unwrap_or_else(|| CardState::Unknown("never read".to_string())))
}

fn describe_cfun(value: Option<u8>) -> String {
    match value {
        Some(CFUN_MINIMUM) => "+CFUN: 0 (minimum)".to_string(),
        Some(CFUN_FULL) => "+CFUN: 1 (full)".to_string(),
        Some(CFUN_DISABLE_RF) => "+CFUN: 4 (radio off)".to_string(),
        Some(CFUN_OFFLINE) => "+CFUN: 7 (offline, stranded)".to_string(),
        Some(other) => format!("+CFUN: {other}"),
        None => "no +CFUN line".to_string(),
    }
}

/// Read a `+CFUN:` value out of the lines of an `AT+CFUN?` exchange.
///
/// Tolerant of the second parameter some firmware appends and of leading
/// whitespace, because the answer is only ever compared against a small set of
/// known values.
pub fn parse_cfun(lines: &[String]) -> Option<u8> {
    lines.iter().find_map(|line| {
        let rest = line.trim().strip_prefix("+CFUN:")?;
        let first = rest.split(',').next()?.trim();
        first.parse::<u8>().ok()
    })
}
