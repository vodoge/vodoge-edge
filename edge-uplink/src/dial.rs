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
/// Read timeout during a live session. Expiring is normal: the worker turns it
/// into `DialError::Timeout` and uses it to drive heartbeat and replay.
const SESSION_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Write timeout during a live session. Replaying a large backlog can keep the
/// socket busy far longer than a connect attempt, and a write that expires is
/// reported as a fatal handshake error rather than being retried, so this must
/// not be the connect budget.
const SESSION_WRITE_TIMEOUT: Duration = Duration::from_secs(90);
/// How long the kernel may hold unacknowledged data before it fails the
/// connection outright.
///
/// SO_SNDTIMEO is not enough, and the reason is worth recording. It does expire,
/// but it surfaces as WouldBlock, and every layer above -- rustls, tungstenite,
/// this crate -- correctly treats WouldBlock as "not yet", so the write is
/// retried forever. Nothing in userspace ever concludes the peer is gone.
///
/// What was actually observed: the cloud publishes the device port through
/// docker-proxy. Replacing the gateway container leaves docker-proxy holding
/// the outside connection with nothing behind it, so it stops reading and
/// advertises a zero window. The socket enters TCP persist and probes it
/// forever -- `timer:(persist,1min26sec,0)` -- while the agent sits in writev
/// with 368 KB queued. It stayed there for over five minutes, uplink dead,
/// device apparently online, and only recovered by accident.
///
/// TCP_USER_TIMEOUT is the only mechanism that ends this, because it acts in
/// the kernel: unacknowledged data older than this fails the connection with a
/// hard error rather than a retryable one. It covers zero-window probing, which
/// is exactly the case here.
///
/// Two minutes: longer than any legitimate stall behind a busy gateway, short
/// enough that a device recovers on its own. Reconnecting is cheap -- Resume
/// replays from the committed cursor and nothing is lost.
#[cfg(target_os = "linux")]
const TCP_USER_TIMEOUT: Duration = Duration::from_secs(120);

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
    Timeout,
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
            Self::Timeout => formatter.write_str("read timed out"),
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

/// Byte-oriented WSS (or a test double) that carries JSON envelopes.
pub trait FrameConn {
    fn send_envelope(&mut self, envelope: &Envelope) -> Result<(), DialError>;
    fn recv_envelope(&mut self) -> Result<Envelope, DialError>;

    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> Result<(), DialError> {
        let _ = timeout;
        Ok(())
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

/// Bounds how long the kernel will keep retrying unacknowledged data.
///
/// Linux only. Other platforms get the std timeouts alone, which is a real gap
/// rather than an equivalent -- see TCP_USER_TIMEOUT above for why they are not
/// sufficient. The edge agent runs on Linux; this exists so the crate still
/// builds and tests anywhere.
#[cfg(target_os = "linux")]
fn set_user_timeout(sock: &TcpStream) -> Result<(), DialError> {
    use std::os::fd::AsRawFd;

    let millis = TCP_USER_TIMEOUT.as_millis() as libc::c_uint;
    // SAFETY: the fd is owned by `sock` and outlives the call, and the value
    // pointer and its length describe the c_uint immediately above.
    let result = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_USER_TIMEOUT,
            std::ptr::addr_of!(millis).cast(),
            std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(DialError::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn set_user_timeout(_sock: &TcpStream) -> Result<(), DialError> {
    Ok(())
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
        tcp.set_read_timeout(Some(SESSION_READ_TIMEOUT))?;
        tcp.set_write_timeout(Some(SESSION_WRITE_TIMEOUT))?;
        set_user_timeout(&tcp)?;

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
            match self.inner.read() {
                Ok(Message::Binary(bytes)) => {
                    return decode_json(&bytes).map_err(DialError::Protocol);
                }
                Ok(Message::Ping(payload)) => {
                    self.inner
                        .send(Message::Pong(payload))
                        .map_err(|err| DialError::Handshake(err.to_string()))?;
                }
                Ok(Message::Pong(_)) => {}
                Ok(Message::Close(_)) => return Err(DialError::Closed),
                Ok(Message::Text(_) | Message::Frame(_)) => return Err(DialError::NonBinaryFrame),
                Err(tungstenite::Error::Io(err))
                    if err.kind() == std::io::ErrorKind::TimedOut
                        || err.kind() == std::io::ErrorKind::WouldBlock =>
                {
                    return Err(DialError::Timeout);
                }
                Err(tungstenite::Error::ConnectionClosed) => return Err(DialError::Closed),
                Err(err) => return Err(DialError::Handshake(err.to_string())),
            }
        }
    }

    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) -> Result<(), DialError> {
        self.inner.get_mut().sock.set_read_timeout(timeout)?;
        Ok(())
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

impl FrameConn for Socket {
    fn send_envelope(&mut self, envelope: &Envelope) -> Result<(), DialError> {
        Socket::send_envelope(self, envelope)
    }

    fn recv_envelope(&mut self) -> Result<Envelope, DialError> {
        Socket::recv_envelope(self)
    }

    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> Result<(), DialError> {
        Socket::set_read_timeout(self, timeout)
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
