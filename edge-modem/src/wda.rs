//! Telling the *modem* which framing the data path uses.
//!
//! 🔴 **This is the step whose absence looks like a subscription problem.**
//! `/sys/class/net/wwanX/qmi/raw_ip` sets the framing on the **host** side
//! only. The modem has its own idea, and its default is 802.3. With the two
//! disagreeing, every packet is dropped in both directions while everything
//! else looks perfect.
//!
//! Measured on this bench, 2026-08-31, with the sysfs toggle set and this
//! message not sent:
//!
//! * `AT+CGACT?` said the context was active, `AT+CGPADDR` returned the same
//!   address the host had configured, `AT+CGREG?` said registered on the home
//!   network, and `AT+CSQ` reported 31 -- full signal.
//! * `ip link` said `link/none`, so the host was in raw-ip.
//! * The host sent 2196 bytes over 36 packets.
//! * The modem's own counter, `AT+QGDCNT?`, did not move by one byte.
//!
//! Everything a person would think to check said the data path was up. The
//! packets were being thrown away at the boundary between the two, because one
//! side was framing them one way and the other was reading them another.
//!
//! `qmicli` spells this `--wda-set-data-format=raw-ip`, and it is why the
//! documented recipes work when a hand-written client does not.

use crate::{
    encode_tlvs, ClientAssignment, ClientId, MessageId, QmiRequest, QmiResponse, ServiceId, Tlv,
    TransactionId, WireError,
};

const SET_DATA_FORMAT: MessageId = MessageId::new(0x0020);

/// Link layer protocol, TLV 0x11 of the request and of the response.
const LINK_LAYER_PROTOCOL: u8 = 0x11;

/// The framings a modem will agree to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkLayer {
    /// The default, and the one that does not work with `raw_ip=Y`.
    Ethernet,
    RawIp,
}

impl LinkLayer {
    /// The wire value. A u32, little endian, which is the shape this TLV
    /// takes -- a single byte here is accepted by some firmware and silently
    /// ignored by the rest.
    fn bits(self) -> u32 {
        match self {
            Self::Ethernet => 1,
            Self::RawIp => 2,
        }
    }

    fn from_bits(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::Ethernet),
            2 => Some(Self::RawIp),
            _ => None,
        }
    }
}

/// Build `SetDataFormat`.
pub fn set_data_format_request(
    assignment: ClientAssignment,
    transaction: TransactionId,
    link_layer: LinkLayer,
) -> Result<QmiRequest, WdaError> {
    if assignment.service() != ServiceId::WDA {
        return Err(WdaError::WrongService);
    }
    let tlvs = vec![Tlv::new(
        LINK_LAYER_PROTOCOL,
        link_layer.bits().to_le_bytes().to_vec(),
    )?];
    Ok(QmiRequest::new(
        ServiceId::WDA,
        assignment.client_id(),
        transaction,
        SET_DATA_FORMAT,
        encode_tlvs(&tlvs)?,
    )?)
}

/// What the modem says it settled on.
///
/// Read back rather than assumed: a modem is free to answer success and keep
/// the framing it had, and the whole failure this module exists for is the two
/// sides disagreeing while both report success.
pub fn parse_data_format(response: &QmiResponse) -> Option<LinkLayer> {
    let tlvs = response.tlvs().ok()?;
    let tlv = tlvs.iter().find(|tlv| tlv.kind == LINK_LAYER_PROTOCOL)?;
    let bytes: [u8; 4] = tlv.value.get(..4)?.try_into().ok()?;
    LinkLayer::from_bits(u32::from_le_bytes(bytes))
}

#[derive(Debug)]
pub enum WdaError {
    WrongService,
    Wire(WireError),
}

impl std::fmt::Display for WdaError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongService => write!(formatter, "not a WDA client"),
            Self::Wire(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for WdaError {}

impl From<WireError> for WdaError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assignment(service: ServiceId) -> ClientAssignment {
        ClientAssignment::new(service, ClientId::allocated(7).expect("client")).expect("assignment")
    }

    /// 🔴 Four bytes, little endian. A single byte is accepted by some
    /// firmware and silently ignored by the rest -- and "silently ignored" is
    /// exactly the failure this whole module exists to prevent, so the width
    /// is pinned rather than left to whatever the value happens to fit in.
    #[test]
    fn the_link_layer_is_a_four_byte_little_endian_value() {
        let request =
            set_data_format_request(assignment(ServiceId::WDA), TransactionId::new(1), LinkLayer::RawIp)
                .expect("request");
        let encoded = request.encode();
        let position = encoded
            .windows(3)
            .position(|window| window == [LINK_LAYER_PROTOCOL, 0x04, 0x00])
            .expect("the TLV must declare a length of four");
        assert_eq!(&encoded[position + 3..position + 7], &[2, 0, 0, 0]);
    }

    #[test]
    fn ethernet_and_raw_ip_are_different_values() {
        assert_ne!(LinkLayer::Ethernet.bits(), LinkLayer::RawIp.bits());
        assert_eq!(LinkLayer::from_bits(2), Some(LinkLayer::RawIp));
        assert_eq!(LinkLayer::from_bits(0), None);
    }

    /// A WDS client cannot carry this message, and sending it on one would
    /// reach a service that has its own meaning for message 0x0020.
    #[test]
    fn only_a_wda_client_may_send_it() {
        assert!(set_data_format_request(
            assignment(ServiceId::WDS),
            TransactionId::new(1),
            LinkLayer::RawIp
        )
        .is_err());
    }
}
