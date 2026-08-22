//! SOCKS5, the parts a forwarding proxy needs.
//!
//! RFC 1928 for the handshake and CONNECT, RFC 1929 for username/password
//! authentication. UDP ASSOCIATE and BIND are not implemented: nothing in this
//! product uses them, and a half-working UDP path is worse than an honest
//! refusal, which is what an unsupported command receives.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

pub const VERSION: u8 = 0x05;
pub const AUTH_NONE: u8 = 0x00;
pub const AUTH_USER_PASSWORD: u8 = 0x02;
pub const AUTH_UNACCEPTABLE: u8 = 0xFF;
pub const USER_PASSWORD_VERSION: u8 = 0x01;

pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;

pub const REPLY_SUCCESS: u8 = 0x00;
pub const REPLY_GENERAL_FAILURE: u8 = 0x01;
pub const REPLY_NOT_ALLOWED: u8 = 0x02;
pub const REPLY_HOST_UNREACHABLE: u8 = 0x04;
pub const REPLY_CONNECTION_REFUSED: u8 = 0x05;
pub const REPLY_COMMAND_NOT_SUPPORTED: u8 = 0x07;
pub const REPLY_ADDRESS_NOT_SUPPORTED: u8 = 0x08;

/// Where a client asked to go.
///
/// A domain is kept as a domain rather than resolved here. Resolving at the
/// proxy would use the proxy's resolver and its network view, which is exactly
/// what a client routing through a specific SIM is trying to avoid.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Target {
    Ip(SocketAddr),
    Domain { host: String, port: u16 },
}

impl fmt::Display for Target {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(address) => write!(formatter, "{address}"),
            Self::Domain { host, port } => write!(formatter, "{host}:{port}"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    /// The first byte was not 0x05, so this is not a SOCKS5 client at all.
    NotSocks5(u8),
    Truncated,
    NoAcceptableAuth,
    UnsupportedAddressType(u8),
    UnsupportedCommand(u8),
    BadCredentials,
}

impl ProtocolError {
    /// The SOCKS5 reply code that describes this failure to the client.
    pub fn reply_code(self) -> u8 {
        match self {
            Self::UnsupportedCommand(_) => REPLY_COMMAND_NOT_SUPPORTED,
            Self::UnsupportedAddressType(_) => REPLY_ADDRESS_NOT_SUPPORTED,
            Self::BadCredentials => REPLY_NOT_ALLOWED,
            _ => REPLY_GENERAL_FAILURE,
        }
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotSocks5(version) => write!(formatter, "not a socks5 client (version {version})"),
            Self::Truncated => formatter.write_str("the handshake ended early"),
            Self::NoAcceptableAuth => formatter.write_str("no acceptable authentication method"),
            Self::UnsupportedAddressType(value) => {
                write!(formatter, "unsupported address type {value}")
            }
            Self::UnsupportedCommand(value) => write!(formatter, "unsupported command {value}"),
            Self::BadCredentials => formatter.write_str("username or password is incorrect"),
        }
    }
}

impl std::error::Error for ProtocolError {}

/// Chooses an authentication method from what the client offered.
///
/// When credentials are configured, offering none is refused rather than
/// downgraded: a proxy that silently accepts an unauthenticated client because
/// it asked nicely is not authenticated at all.
pub fn select_auth_method(offered: &[u8], require_password: bool) -> Result<u8, ProtocolError> {
    let wanted = if require_password {
        AUTH_USER_PASSWORD
    } else {
        AUTH_NONE
    };
    if offered.contains(&wanted) {
        Ok(wanted)
    } else {
        Err(ProtocolError::NoAcceptableAuth)
    }
}

/// Parses a username/password sub-negotiation body (RFC 1929), after the
/// version byte.
pub fn parse_user_password(body: &[u8]) -> Result<(String, String), ProtocolError> {
    let mut cursor = 0usize;
    let username = take_prefixed_string(body, &mut cursor)?;
    let password = take_prefixed_string(body, &mut cursor)?;
    Ok((username, password))
}

fn take_prefixed_string(body: &[u8], cursor: &mut usize) -> Result<String, ProtocolError> {
    let length = *body.get(*cursor).ok_or(ProtocolError::Truncated)? as usize;
    *cursor += 1;
    let end = cursor.checked_add(length).ok_or(ProtocolError::Truncated)?;
    let bytes = body.get(*cursor..end).ok_or(ProtocolError::Truncated)?;
    *cursor = end;
    // RFC 1929 does not name an encoding. Treating it as UTF-8 and refusing
    // anything else beats silently mangling a credential into one that cannot
    // match what was configured.
    String::from_utf8(bytes.to_vec()).map_err(|_| ProtocolError::BadCredentials)
}

/// Parses a request after the version byte: CMD, RSV, ATYP, address, port.
pub fn parse_request(body: &[u8]) -> Result<Target, ProtocolError> {
    let command = *body.first().ok_or(ProtocolError::Truncated)?;
    if command == CMD_UDP_ASSOCIATE || command != CMD_CONNECT {
        return Err(ProtocolError::UnsupportedCommand(command));
    }
    let address_type = *body.get(2).ok_or(ProtocolError::Truncated)?;
    let rest = body.get(3..).ok_or(ProtocolError::Truncated)?;
    match address_type {
        ATYP_IPV4 => {
            let octets: [u8; 4] = rest.get(..4).ok_or(ProtocolError::Truncated)?
                .try_into()
                .map_err(|_| ProtocolError::Truncated)?;
            let port = read_port(rest, 4)?;
            Ok(Target::Ip(SocketAddr::from((Ipv4Addr::from(octets), port))))
        }
        ATYP_IPV6 => {
            let octets: [u8; 16] = rest.get(..16).ok_or(ProtocolError::Truncated)?
                .try_into()
                .map_err(|_| ProtocolError::Truncated)?;
            let port = read_port(rest, 16)?;
            Ok(Target::Ip(SocketAddr::from((Ipv6Addr::from(octets), port))))
        }
        ATYP_DOMAIN => {
            let length = *rest.first().ok_or(ProtocolError::Truncated)? as usize;
            let host = rest.get(1..1 + length).ok_or(ProtocolError::Truncated)?;
            let host = String::from_utf8(host.to_vec())
                .map_err(|_| ProtocolError::UnsupportedAddressType(ATYP_DOMAIN))?;
            let port = read_port(rest, 1 + length)?;
            Ok(Target::Domain { host, port })
        }
        other => Err(ProtocolError::UnsupportedAddressType(other)),
    }
}

fn read_port(body: &[u8], offset: usize) -> Result<u16, ProtocolError> {
    let high = *body.get(offset).ok_or(ProtocolError::Truncated)?;
    let low = *body.get(offset + 1).ok_or(ProtocolError::Truncated)?;
    Ok(u16::from_be_bytes([high, low]))
}

/// Builds a reply. The bound address is reported as 0.0.0.0:0 — a CONNECT
/// client has no use for it, and reporting the real local address would leak
/// the edge's internal addressing to whoever is using the proxy.
pub fn reply(code: u8) -> [u8; 10] {
    [VERSION, code, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0]
}

/// The request that asks an upstream SOCKS5 proxy for a CONNECT.
pub fn connect_request(target: &Target) -> Vec<u8> {
    let mut request = vec![VERSION, CMD_CONNECT, 0x00];
    match target {
        Target::Ip(SocketAddr::V4(address)) => {
            request.push(ATYP_IPV4);
            request.extend_from_slice(&address.ip().octets());
            request.extend_from_slice(&address.port().to_be_bytes());
        }
        Target::Ip(SocketAddr::V6(address)) => {
            request.push(ATYP_IPV6);
            request.extend_from_slice(&address.ip().octets());
            request.extend_from_slice(&address.port().to_be_bytes());
        }
        Target::Domain { host, port } => {
            request.push(ATYP_DOMAIN);
            request.push(host.len() as u8);
            request.extend_from_slice(host.as_bytes());
            request.extend_from_slice(&port.to_be_bytes());
        }
    }
    request
}

/// The username/password credential block an upstream expects (RFC 1929).
pub fn user_password_request(username: &str, password: &str) -> Vec<u8> {
    let mut body = vec![USER_PASSWORD_VERSION, username.len() as u8];
    body.extend_from_slice(username.as_bytes());
    body.push(password.len() as u8);
    body.extend_from_slice(password.as_bytes());
    body
}
