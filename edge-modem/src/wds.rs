//! QMI Wireless Data Service: starting a packet session and reading what the
//! network granted.
//!
//! The missing half of "this module has data". `AT+CGACT` activates a PDP
//! context on the module, and that is where this product stopped: all four
//! `wwan` interfaces on the bench have been DOWN throughout, because an
//! activated context is not an interface. What turns one into the other is a
//! WDS session -- the network hands back an address, a gateway, a netmask and
//! DNS, and something has to put those on the `wwan` device and add a route.
//!
//! This module is the wire half of that: build the requests, read the
//! answers. Configuring the interface is the caller's, because it is Linux
//! netlink work and has nothing to do with QMI.
//!
//! # 🔴 Not yet measured against hardware
//!
//! Every message and TLV number here comes from the published QMI definitions
//! (libqmi's `wds.json` is the usual reference), **not from a modem on this
//! bench**. Under this product's own rule that is untested, and the capability
//! ledger must not gain a `data` verdict on the strength of this file alone.
//! The tests below prove the encoder and the parser agree with those published
//! shapes; they cannot prove a Quectel EC20 answers in them.
//!
//! # The handle is the session
//!
//! `StartNetworkInterface` returns a packet data handle, and the session lives
//! exactly as long as the QMI client that holds it. Releasing the client tears
//! the session down -- which is why a data session cannot be started by a
//! short-lived probe that closes its client afterwards, and why the handle has
//! to be carried by whatever keeps the client open.

use std::{error::Error, fmt};

use crate::{
    encode_tlvs, unique_tlv, ClientAssignment, ClientId, MessageId, QmiRequest, QmiResponse,
    QmiResult, ResultError, ServiceId, Tlv, TlvLookupError, TransactionId, WireError,
};

pub const START_NETWORK_INTERFACE: MessageId = MessageId::new(0x0020);
pub const STOP_NETWORK_INTERFACE: MessageId = MessageId::new(0x0021);
pub const GET_CURRENT_SETTINGS: MessageId = MessageId::new(0x002d);

// Request TLVs for StartNetworkInterface.
const REQ_APN: u8 = 0x14;
const REQ_AUTH_PREFERENCE: u8 = 0x16;
const REQ_USERNAME: u8 = 0x17;
const REQ_PASSWORD: u8 = 0x18;
const REQ_IP_FAMILY: u8 = 0x19;

// Response TLVs.
const PACKET_DATA_HANDLE: u8 = 0x01;
const CALL_END_REASON: u8 = 0x10;
const REQUESTED_SETTINGS: u8 = 0x10;
const DNS_PRIMARY: u8 = 0x15;
const DNS_SECONDARY: u8 = 0x16;
const IPV4_ADDRESS: u8 = 0x1e;
const IPV4_GATEWAY: u8 = 0x20;
const IPV4_NETMASK: u8 = 0x21;
const MTU: u8 = 0x29;

/// Ask for every setting rather than naming the ones we want.
///
/// The requested-settings mask is a hint: modems differ in which bits they
/// honour and several ignore it entirely. Asking for everything and reading
/// defensively is what works across firmware, and costs one extra TLV in a
/// response that is already small.
const ALL_SETTINGS: u32 = u32::MAX;

/// The handle a started session is addressed by.
///
/// 🔴 It is only valid while the QMI client that obtained it is open. A caller
/// that releases the client has ended the session, whether or not it ever
/// sends `StopNetworkInterface`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketDataHandle(u32);

impl PacketDataHandle {
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

impl fmt::Display for PacketDataHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "0x{:08x}", self.0)
    }
}

/// How the session authenticates, matching QMI's bitmask.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthPreference {
    None,
    Pap,
    Chap,
    /// Both bits set: let the network choose.
    PapOrChap,
}

impl AuthPreference {
    pub const fn bits(self) -> u8 {
        match self {
            Self::None => 0x00,
            Self::Pap => 0x01,
            Self::Chap => 0x02,
            Self::PapOrChap => 0x03,
        }
    }
}

/// What the network granted, as far as it said.
///
/// Every field is optional because a modem answers with the TLVs it has: a
/// session can come up with an address and no DNS, and reading that as a
/// failure would refuse a working link. The caller decides which absences it
/// can live with -- an address it cannot, DNS it can.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Ipv4Settings {
    pub address: Option<u32>,
    pub gateway: Option<u32>,
    pub netmask: Option<u32>,
    pub dns_primary: Option<u32>,
    pub dns_secondary: Option<u32>,
    pub mtu: Option<u32>,
}

impl Ipv4Settings {
    /// Netmask as a prefix length, for the `ip addr` form of the same fact.
    pub fn prefix_length(&self) -> Option<u8> {
        let mask = self.netmask?;
        // A netmask is contiguous ones followed by contiguous zeroes. Anything
        // else is not a netmask, and turning it into a prefix length would
        // invent one -- so it reads as absent rather than as a guess.
        let ones = mask.leading_ones();
        if mask.checked_shl(ones).unwrap_or(0) != 0 {
            return None;
        }
        Some(ones as u8)
    }
}

/// Build `StartNetworkInterface`.
///
/// The APN is required by every network this product has met; username and
/// password are sent only when there is one, because an empty credential TLV
/// is not the same as no credential and some firmware treats it as a request
/// to authenticate with nothing.
pub fn start_request(
    assignment: ClientAssignment,
    transaction: TransactionId,
    apn: &str,
    username: Option<&str>,
    password: Option<&str>,
    auth: AuthPreference,
) -> Result<QmiRequest, WdsError> {
    ensure_wds(assignment)?;
    let mut tlvs = vec![
        Tlv::new(REQ_APN, apn.as_bytes().to_vec())?,
        // IPv4 only. The bench has never had an IPv6 data session to measure,
        // and asking for a family nobody has seen work here would put an
        // untested path in front of the tested one.
        Tlv::new(REQ_IP_FAMILY, vec![4])?,
    ];
    if auth != AuthPreference::None {
        tlvs.push(Tlv::new(REQ_AUTH_PREFERENCE, vec![auth.bits()])?);
    }
    if let Some(username) = username.filter(|value| !value.is_empty()) {
        tlvs.push(Tlv::new(REQ_USERNAME, username.as_bytes().to_vec())?);
    }
    if let Some(password) = password.filter(|value| !value.is_empty()) {
        tlvs.push(Tlv::new(REQ_PASSWORD, password.as_bytes().to_vec())?);
    }
    Ok(QmiRequest::new(
        ServiceId::WDS,
        assignment.client_id(),
        transaction,
        START_NETWORK_INTERFACE,
        encode_tlvs(&tlvs)?,
    )?)
}

/// Build `StopNetworkInterface` for a handle.
pub fn stop_request(
    assignment: ClientAssignment,
    transaction: TransactionId,
    handle: PacketDataHandle,
) -> Result<QmiRequest, WdsError> {
    ensure_wds(assignment)?;
    let tlvs = vec![Tlv::new(
        PACKET_DATA_HANDLE,
        handle.as_u32().to_le_bytes().to_vec(),
    )?];
    Ok(QmiRequest::new(
        ServiceId::WDS,
        assignment.client_id(),
        transaction,
        STOP_NETWORK_INTERFACE,
        encode_tlvs(&tlvs)?,
    )?)
}

/// Build `GetCurrentSettings`.
pub fn current_settings_request(
    assignment: ClientAssignment,
    transaction: TransactionId,
) -> Result<QmiRequest, WdsError> {
    ensure_wds(assignment)?;
    let tlvs = vec![Tlv::new(
        REQUESTED_SETTINGS,
        ALL_SETTINGS.to_le_bytes().to_vec(),
    )?];
    Ok(QmiRequest::new(
        ServiceId::WDS,
        assignment.client_id(),
        transaction,
        GET_CURRENT_SETTINGS,
        encode_tlvs(&tlvs)?,
    )?)
}

/// Read the handle out of a successful `StartNetworkInterface`.
pub fn parse_start(response: &QmiResponse) -> Result<PacketDataHandle, WdsError> {
    let tlvs = expect_wds(response, START_NETWORK_INTERFACE)?;
    let handle = unique_tlv(&tlvs, PACKET_DATA_HANDLE)?;
    Ok(PacketDataHandle::new(read_u32(&handle.value, "packet data handle")?))
}

/// Why the network refused, when it said.
///
/// Read from the failure response rather than from the result code: the result
/// says "call failed" and this says which of forty reasons it was, which is
/// the difference between an operator retrying and an operator reading a
/// tariff. Absent when the modem did not include it.
pub fn parse_call_end_reason(response: &QmiResponse) -> Option<u16> {
    let tlvs = response.tlvs().ok()?;
    let reason = unique_tlv(&tlvs, CALL_END_REASON).ok()?;
    if reason.value.len() < 2 {
        return None;
    }
    Some(u16::from_le_bytes([reason.value[0], reason.value[1]]))
}

/// Read whatever the network granted.
pub fn parse_current_settings(response: &QmiResponse) -> Result<Ipv4Settings, WdsError> {
    let tlvs = expect_wds(response, GET_CURRENT_SETTINGS)?;
    let read = |kind: u8| -> Option<u32> {
        let tlv = tlvs.iter().find(|tlv| tlv.kind == kind)?;
        read_u32(&tlv.value, "setting").ok()
    };
    Ok(Ipv4Settings {
        address: read(IPV4_ADDRESS),
        gateway: read(IPV4_GATEWAY),
        netmask: read(IPV4_NETMASK),
        dns_primary: read(DNS_PRIMARY),
        dns_secondary: read(DNS_SECONDARY),
        mtu: read(MTU),
    })
}

fn read_u32(value: &[u8], field: &'static str) -> Result<u32, WdsError> {
    if value.len() < 4 {
        return Err(WdsError::Truncated {
            field,
            actual: value.len(),
        });
    }
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn expect_wds(response: &QmiResponse, message_id: MessageId) -> Result<Vec<Tlv>, WdsError> {
    if response.service() != ServiceId::WDS {
        return Err(WdsError::UnexpectedService {
            actual: response.service(),
        });
    }
    if response.client_id() == ClientId::CONTROL {
        return Err(WdsError::Wire(WireError::ServiceRequiresAllocatedClient {
            service: ServiceId::WDS,
        }));
    }
    if response.message_id() != message_id {
        return Err(WdsError::UnexpectedMessage {
            expected: message_id,
            actual: response.message_id(),
        });
    }
    let tlvs = response.tlvs()?;
    QmiResult::from_tlvs(&tlvs)?.check()?;
    Ok(tlvs)
}

fn ensure_wds(assignment: ClientAssignment) -> Result<(), WdsError> {
    if assignment.service() != ServiceId::WDS {
        return Err(WdsError::UnexpectedService {
            actual: assignment.service(),
        });
    }
    Ok(())
}

#[derive(Debug)]
pub enum WdsError {
    Wire(WireError),
    Result(ResultError),
    Lookup(TlvLookupError),
    UnexpectedService { actual: ServiceId },
    UnexpectedMessage { expected: MessageId, actual: MessageId },
    Truncated { field: &'static str, actual: usize },
}

impl fmt::Display for WdsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(error) => error.fmt(formatter),
            Self::Result(error) => error.fmt(formatter),
            Self::Lookup(error) => error.fmt(formatter),
            Self::UnexpectedService { actual } => {
                write!(formatter, "expected WDS service, got {actual}")
            }
            Self::UnexpectedMessage { expected, actual } => {
                write!(formatter, "expected WDS message {expected}, got {actual}")
            }
            Self::Truncated { field, actual } => {
                write!(formatter, "{field} is {actual} bytes, expected at least 4")
            }
        }
    }
}

impl Error for WdsError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Wire(error) => Some(error),
            Self::Result(error) => Some(error),
            Self::Lookup(error) => Some(error),
            _ => None,
        }
    }
}

impl From<WireError> for WdsError {
    fn from(value: WireError) -> Self {
        Self::Wire(value)
    }
}

impl From<ResultError> for WdsError {
    fn from(value: ResultError) -> Self {
        Self::Result(value)
    }
}

impl From<TlvLookupError> for WdsError {
    fn from(value: TlvLookupError) -> Self {
        Self::Lookup(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ClientAssignment;

    const CLIENT: u8 = 7;

    fn assignment() -> ClientAssignment {
        ClientAssignment::new(ServiceId::WDS, ClientId::allocated(CLIENT).expect("client"))
            .expect("assignment")
    }

    fn transaction() -> TransactionId {
        TransactionId::new(1)
    }

    /// A QMUX response frame, built the way the wire tests build one, so the
    /// parsers are read against bytes rather than against a struct this file
    /// also constructed.
    fn response_for(service: u8, message_id: MessageId, tlvs: &[Tlv]) -> QmiResponse {
        let mut all = vec![Tlv::new(0x02, vec![0, 0, 0, 0]).expect("result ok")];
        all.extend_from_slice(tlvs);
        let payload = encode_tlvs(&all).expect("tlvs");
        let qmux_length = 5 + 7 + payload.len();
        let mut frame = Vec::with_capacity(qmux_length + 1);
        frame.push(0x01);
        frame.extend_from_slice(&(qmux_length as u16).to_le_bytes());
        frame.push(0x80);
        frame.push(service);
        frame.push(CLIENT);
        frame.push(0x02);
        frame.extend_from_slice(&1u16.to_le_bytes());
        frame.extend_from_slice(&message_id.as_u16().to_le_bytes());
        frame.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        frame.extend_from_slice(&payload);
        QmiResponse::decode(&frame).expect("decode")
    }

    fn response(message_id: MessageId, tlvs: &[Tlv]) -> QmiResponse {
        response_for(ServiceId::WDS.as_u8(), message_id, tlvs)
    }

    /// 🔴 A credential that was never given must not be sent as an empty one.
    /// Some firmware reads an empty username TLV as "authenticate with
    /// nothing" rather than as "no username", which fails a session that would
    /// have come up unauthenticated.
    #[test]
    fn absent_credentials_are_absent_rather_than_empty() {
        let request =
            start_request(assignment(), transaction(), "cmnet", None, None, AuthPreference::None)
                .expect("request");
        let payload = request.payload();
        assert!(!payload.contains(&REQ_USERNAME), "an empty username was sent");
        assert!(!payload.contains(&REQ_PASSWORD), "an empty password was sent");
        assert!(
            !payload.contains(&REQ_AUTH_PREFERENCE),
            "an auth preference was sent for a session that asked for none"
        );
    }

    #[test]
    fn a_named_credential_travels_with_its_method() {
        let request = start_request(
            assignment(),
            transaction(),
            "cmnet",
            Some("user"),
            Some("pass"),
            AuthPreference::Chap,
        )
        .expect("request");
        let payload = request.payload();
        assert!(payload.windows(4).any(|window| window == b"user"));
        assert!(payload.windows(4).any(|window| window == b"pass"));
        assert!(payload.contains(&AuthPreference::Chap.bits()));
    }

    /// The empty-string case is the same as the absent one. A form that
    /// submits a blank box must not turn into an empty credential on the wire.
    #[test]
    fn an_empty_string_credential_is_treated_as_absent() {
        let request = start_request(
            assignment(),
            transaction(),
            "cmnet",
            Some(""),
            Some(""),
            AuthPreference::None,
        )
        .expect("request");
        assert!(!request.payload().contains(&REQ_USERNAME));
    }

    #[test]
    fn a_started_session_yields_its_handle() {
        let handle = Tlv::new(PACKET_DATA_HANDLE, 0x1234_5678u32.to_le_bytes().to_vec())
            .expect("tlv");
        let parsed = parse_start(&response(START_NETWORK_INTERFACE, &[handle])).expect("handle");
        assert_eq!(parsed, PacketDataHandle::new(0x1234_5678));
    }

    /// A session can come up with an address and no DNS. Reading that as a
    /// failure would refuse a link that works, so every field is optional and
    /// the caller decides which absence it can live with.
    #[test]
    fn settings_are_read_field_by_field_and_absence_is_not_failure() {
        let address = Tlv::new(IPV4_ADDRESS, 0x0a00_0002u32.to_le_bytes().to_vec()).expect("tlv");
        let gateway = Tlv::new(IPV4_GATEWAY, 0x0a00_0001u32.to_le_bytes().to_vec()).expect("tlv");
        let parsed = parse_current_settings(&response(GET_CURRENT_SETTINGS, &[address, gateway]))
            .expect("settings");
        assert_eq!(parsed.address, Some(0x0a00_0002));
        assert_eq!(parsed.gateway, Some(0x0a00_0001));
        assert_eq!(parsed.dns_primary, None, "absent DNS is absent, not an error");
        assert_eq!(parsed.mtu, None);
    }

    #[test]
    fn a_netmask_becomes_a_prefix_length() {
        let settings = Ipv4Settings {
            netmask: Some(0xffff_ff00),
            ..Ipv4Settings::default()
        };
        assert_eq!(settings.prefix_length(), Some(24));
        let all = Ipv4Settings {
            netmask: Some(0xffff_ffff),
            ..Ipv4Settings::default()
        };
        assert_eq!(all.prefix_length(), Some(32));
    }

    /// 🔴 A mask with a hole in it is not a netmask. Turning it into a prefix
    /// length would invent one and put a wrong route on the interface, so it
    /// reads as absent and the caller falls back to something it chose.
    #[test]
    fn a_discontiguous_mask_has_no_prefix_length() {
        let settings = Ipv4Settings {
            netmask: Some(0xff00_ff00),
            ..Ipv4Settings::default()
        };
        assert_eq!(settings.prefix_length(), None);
    }

    #[test]
    fn a_truncated_handle_is_reported_rather_than_read_short() {
        let handle = Tlv::new(PACKET_DATA_HANDLE, vec![1, 2]).expect("tlv");
        assert!(matches!(
            parse_start(&response(START_NETWORK_INTERFACE, &[handle])),
            Err(WdsError::Truncated { .. })
        ));
    }

    /// The refusal reason is what an operator acts on: the result code says
    /// "call failed" and this says which of forty reasons it was.
    #[test]
    fn a_call_end_reason_is_read_when_the_modem_gives_one() {
        let reason = Tlv::new(CALL_END_REASON, 29u16.to_le_bytes().to_vec()).expect("tlv");
        assert_eq!(
            parse_call_end_reason(&response(START_NETWORK_INTERFACE, &[reason])),
            Some(29)
        );
        assert_eq!(
            parse_call_end_reason(&response(START_NETWORK_INTERFACE, &[])),
            None
        );
    }

    /// A response from another service must not be read as ours: the TLV
    /// numbers overlap between QMI services, so a NAS frame parsed here would
    /// produce plausible nonsense rather than an error.
    #[test]
    fn a_response_from_another_service_is_refused() {
        let foreign = response_for(ServiceId::NAS.as_u8(), START_NETWORK_INTERFACE, &[]);
        assert!(matches!(
            parse_start(&foreign),
            Err(WdsError::UnexpectedService { .. })
        ));
    }
}
