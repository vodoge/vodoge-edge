use std::{error::Error, fmt};

use crate::{
    dms, es10c, nas, uim, unique_tlv, wms, AllocationError, ApduResponse, CellLocationInfo,
    ClientAllocationRequest, ClientAssignment, ClientId, ClientRegistry, ClientRegistryError,
    ConfiguredAddresses, CorrelationError, DeviceRevision, DeviceSerialNumbers, DmsError,
    EuiccInfo1, EuiccInfo2, ListedMessage,
    MessageId, MessageMode, MessageTag, NasError, NotificationMetadata, OperatingMode,
    PendingNotification, PendingTransactions, Profile, QmiRequest, QmiResponse, QmiResult,
    RawMessage, ResultError, ServiceId, ServingSystem, StorageType, TlvLookupError, TransactionId,
    UimError, WireError, WmsError,
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
        let mut response = self
            .client
            .send_apdu(self.slot, self.channel, apdu)
            .map_err(|error| SessionError::transport(format!("ES10 command: {error}")))?;
        let mut collected = std::mem::take(&mut response.data);
        let mut rounds = 0usize;
        while let Some(get_response) = response.get_response_apdu() {
            if rounds >= uim::MAX_GET_RESPONSE_ROUNDS {
                return Err(SessionError::transport(format!(
                    "eUICC on slot {} asked for more than {} GET RESPONSE rounds",
                    self.slot,
                    uim::MAX_GET_RESPONSE_ROUNDS
                )));
            }
            rounds += 1;
            response = self
                .client
                .send_apdu(self.slot, self.channel, &get_response)
                .map_err(|error| SessionError::transport(format!("GET RESPONSE: {error}")))?;
            collected.extend_from_slice(&response.data);
        }
        Ok(ApduResponse {
            data: collected,
            sw1: response.sw1,
            sw2: response.sw2,
        })
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
