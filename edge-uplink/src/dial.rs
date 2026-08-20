//! Blocking WSS dialer. TLS 1.3 mTLS is required; plaintext `ws://` is rejected.

use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use tungstenite::client::IntoClientRequest;
use tungstenite::http::header::SEC_WEBSOCKET_PROTOCOL;
use tungstenite::http::HeaderValue;
use tungstenite::protocol::WebSocketConfig;
use tungstenite::client::client_with_config;
use tungstenite::{Message, WebSocket};
use vodoge_contract::{Envelope, WS_SUBPROTOCOL};

use crate::codec::{decode_json, encode_json};
use crate::session::{Inbound, LinkSession, SessionError};

/// Device WebSocket path on the gateway.
pub const PATH: &str = "/v1/edge";

const MAX_FRAME_BYTES: usize = 1 << 20;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Errors from connecting or transferring envelopes.
#[derive(Debug)]
pub enum DialError {
    PlaintextRejected,
    UnsupportedUrl(String),
    Tls(rustls::Error),
    Io(std::io::Error),
    Handshake(String),
    NonBinaryFrame,
    Closed,
    Protocol(SessionError),
}

impl std::fmt::Display for DialError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PlaintextRejected => formatter.write_str("plaintext ws:// is not permitted"),
            Self::UnsupportedUrl(url) => write!(formatter, "unsupported uplink url {url}"),
            Self::Tls(err) => write!(formatter, "tls: {err}"),
            Self::Io(err) => write!(formatter, "io: {err}"),
            Self::Handshake(reason) => write!(formatter, "websocket handshake: {reason}"),
            Self::NonBinaryFrame => formatter.write_str("only binary websocket frames are allowed"),
            Self::Closed => formatter.write_str("connection closed"),
            Self::Protocol(err) => write!(formatter, "{err}"),
        }
    }
}

impl std::error::Error for DialError {}

impl From<std::io::Error> for DialError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<rustls::Error> for DialError {
    fn from(err: rustls::Error) -> Self {
        Self::Tls(err)
    }
}

impl From<SessionError> for DialError {
    fn from(err: SessionError) -> Self {
        Self::Protocol(err)
    }
}

#[derive(Debug)]
struct WssTarget {
    host: String,
    addr: String,
    path: String,
}

fn parse_wss(url: &str) -> Result<WssTarget, DialError> {
    if url.starts_with("ws://") {
        return Err(DialError::PlaintextRejected);
    }
    let rest = url
        .strip_prefix("wss://")
        .ok_or_else(|| DialError::UnsupportedUrl(url.to_string()))?;
    if rest.is_empty() || rest.starts_with('[') {
        return Err(DialError::UnsupportedUrl(url.to_string()));
    }
    let (hostport, path) = match rest.split_once('/') {
        Some((hostport, path)) => (hostport, format!("/{path}")),
        None => (rest, PATH.to_string()),
    };
    if hostport.is_empty() || hostport.contains('/') {
        return Err(DialError::UnsupportedUrl(url.to_string()));
    }
    let (host, addr) = match hostport.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
            (host.to_string(), format!("{host}:{port}"))
        }
        _ => (hostport.to_string(), format!("{hostport}:443")),
    };
    Ok(WssTarget { host, addr, path })
}

/// One authenticated WSS socket after the HTTP upgrade.
pub struct Socket {
    inner: WebSocket<StreamOwned<ClientConnection, TcpStream>>,
}

impl Socket {
    /// Dials `wss://` with the supplied TLS 1.3 mTLS config.
    pub fn connect(url: &str, tls: Arc<ClientConfig>) -> Result<Self, DialError> {
        let target = parse_wss(url)?;
        let mut last_io = None;
        let mut tcp = None;
        for addr in target.addr.to_socket_addrs().map_err(DialError::Io)? {
            match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
                Ok(stream) => {
                    tcp = Some(stream);
                    break;
                }
                Err(err) => last_io = Some(err),
            }
        }
        let tcp = tcp.ok_or_else(|| {
            last_io.unwrap_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, target.addr.clone())
            })
        })?;
        tcp.set_nodelay(true)?;
        tcp.set_read_timeout(Some(CONNECT_TIMEOUT))?;
        tcp.set_write_timeout(Some(CONNECT_TIMEOUT))?;

        let server_name = ServerName::try_from(target.host.clone())
            .map_err(|_| DialError::UnsupportedUrl(target.host.clone()))?;
        let tls_conn = ClientConnection::new(tls, server_name)?;
        let stream = StreamOwned::new(tls_conn, tcp);

        let uri = format!("wss://{}{}", target.host, target.path);
        let mut request = uri
            .into_client_request()
            .map_err(|err| DialError::Handshake(err.to_string()))?;
        request.headers_mut().insert(
            SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_static(WS_SUBPROTOCOL),
        );

        let config = WebSocketConfig {
            max_message_size: Some(MAX_FRAME_BYTES),
            max_frame_size: Some(MAX_FRAME_BYTES),
            ..WebSocketConfig::default()
        };
        let (inner, response) = client_with_config(request, stream, Some(config))
            .map_err(|err| DialError::Handshake(err.to_string()))?;
        if response.status() != tungstenite::http::StatusCode::SWITCHING_PROTOCOLS {
            return Err(DialError::Handshake(format!(
                "unexpected status {}",
                response.status()
            )));
        }
        Ok(Self { inner })
    }

    pub fn send_envelope(&mut self, envelope: &Envelope) -> Result<(), DialError> {
        let bytes = encode_json(envelope).map_err(DialError::Protocol)?;
        self.inner
            .send(Message::Binary(bytes))
            .map_err(|err| DialError::Handshake(err.to_string()))
    }

    pub fn recv_envelope(&mut self) -> Result<Envelope, DialError> {
        loop {
            match self
                .inner
                .read()
                .map_err(|err| DialError::Handshake(err.to_string()))?
            {
                Message::Binary(bytes) => {
                    return decode_json(&bytes).map_err(DialError::Protocol);
                }
                Message::Ping(payload) => {
                    self.inner
                        .send(Message::Pong(payload))
                        .map_err(|err| DialError::Handshake(err.to_string()))?;
                }
                Message::Pong(_) => {}
                Message::Close(_) => return Err(DialError::Closed),
                Message::Text(_) | Message::Frame(_) => return Err(DialError::NonBinaryFrame),
            }
        }
    }

    /// Sends Resume as the first application frame and waits for ResumeAck.
    pub fn resume(
        &mut self,
        session: &mut LinkSession,
        connection_id: &str,
        now: Instant,
    ) -> Result<Inbound, DialError> {
        let envelope = session.handshake(connection_id, now)?;
        self.send_envelope(&envelope)?;
        let inbound = self.recv_envelope()?;
        Ok(session.on_inbound(inbound, now)?)
    }

    pub fn close(&mut self) -> Result<(), DialError> {
        self.inner
            .close(None)
            .map_err(|err| DialError::Handshake(err.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::parse_wss;
    use super::DialError;

    #[test]
    fn rejects_plaintext_ws() {
        match parse_wss("ws://gateway.example/v1/edge") {
            Err(DialError::PlaintextRejected) => {}
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn parses_wss_host_port_and_path() {
        let target = parse_wss("wss://gateway.test:8443/v1/edge").expect("url");
        assert_eq!(target.host, "gateway.test");
        assert_eq!(target.addr, "gateway.test:8443");
        assert_eq!(target.path, "/v1/edge");
    }
}
