//! The proxy listeners the edge runs on behalf of the cloud.
//!
//! Each instance is a SOCKS5 listener bound to one modem's network interface,
//! so traffic through it leaves over that SIM. That binding is the entire
//! point: without it the packets would take the box's default route and the
//! proxy would be indistinguishable from any other.
//!
//! The cloud sends desired state and this reconciles against it — the set of
//! listeners that should exist, not a sequence of start and stop instructions.
//! A device that missed an earlier change would otherwise stay wrong forever.

pub mod bind;
pub mod probe;
pub mod socks5;

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use socks5::{ProtocolError, Target};

/// One listener's configuration, as the cloud describes it.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct InstanceSpec {
    pub id: String,
    #[serde(default)]
    pub name: String,
    pub modem_imei: String,
    #[serde(default = "default_protocol")]
    pub protocol: String,
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
    pub listen_port: u16,
    #[serde(default)]
    pub auth_enabled: bool,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub upstream_id: String,
    #[serde(default)]
    pub enabled: bool,
}

fn default_protocol() -> String {
    "socks5".to_string()
}

fn default_listen_addr() -> String {
    "0.0.0.0".to_string()
}

/// An upstream proxy to chain through.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct UpstreamSpec {
    pub id: String,
    #[serde(default)]
    pub name: String,
    pub address: String,
    #[serde(default = "default_protocol")]
    pub protocol: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub enabled: bool,
}

/// What one listener has carried. Counters are cumulative for the lifetime of
/// the listener; the reporter turns them into per-interval deltas.
#[derive(Debug, Default)]
pub struct Counters {
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
    pub connections: AtomicU64,
    pub errors: AtomicU64,
}

/// A snapshot of the counters, for reporting.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct CounterSnapshot {
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub connections: u64,
    pub errors: u64,
}

impl Counters {
    pub fn snapshot(&self) -> CounterSnapshot {
        CounterSnapshot {
            bytes_up: self.bytes_up.load(Ordering::Relaxed),
            bytes_down: self.bytes_down.load(Ordering::Relaxed),
            connections: self.connections.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
        }
    }
}

/// What a running listener looks like from outside.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InstanceStatus {
    pub id: String,
    pub listening: bool,
    pub listen_addr: String,
    pub interface: Option<String>,
    /// Why it is not listening, when it is not.
    pub error: Option<String>,
    pub counters: CounterSnapshot,
}

struct Running {
    spec: InstanceSpec,
    handle: tokio::task::JoinHandle<()>,
    counters: Arc<Counters>,
    bound: SocketAddr,
    interface: Option<String>,
}

/// Runs and reconciles the listeners for one device.
pub struct ProxyManager {
    running: Mutex<HashMap<String, Running>>,
    failed: Mutex<HashMap<String, (InstanceSpec, String)>>,
    upstreams: Mutex<HashMap<String, UpstreamSpec>>,
    /// Maps a modem IMEI to the network interface its data session uses.
    resolver: Arc<dyn InterfaceResolver>,
}

/// Finds the network interface belonging to a modem.
///
/// A trait so the manager can be exercised without cellular hardware: the
/// binding is the one part of this that cannot be tested on a workstation.
pub trait InterfaceResolver: Send + Sync {
    fn interface_for(&self, modem_imei: &str) -> Option<String>;
}

/// Binds nothing, for tests and for a host with no cellular interfaces.
pub struct NoInterfaces;

impl InterfaceResolver for NoInterfaces {
    fn interface_for(&self, _modem_imei: &str) -> Option<String> {
        None
    }
}

impl ProxyManager {
    pub fn new(resolver: Arc<dyn InterfaceResolver>) -> Self {
        Self {
            running: Mutex::new(HashMap::new()),
            failed: Mutex::new(HashMap::new()),
            upstreams: Mutex::new(HashMap::new()),
            resolver,
        }
    }

    /// Applies the cloud's desired state.
    ///
    /// Returns the status of every instance in the specification, including
    /// the ones that could not be started — a listener that failed to bind
    /// must not look the same as one that was never configured.
    pub async fn apply(
        &self,
        instances: Vec<InstanceSpec>,
        upstreams: Vec<UpstreamSpec>,
    ) -> Vec<InstanceStatus> {
        {
            let mut table = self.upstreams.lock().await;
            table.clear();
            for upstream in upstreams {
                table.insert(upstream.id.clone(), upstream);
            }
        }

        let wanted: HashMap<String, InstanceSpec> = instances
            .into_iter()
            .map(|spec| (spec.id.clone(), spec))
            .collect();

        // Anything no longer wanted, or wanted differently, is stopped first.
        // Restarting on any change rather than diffing field by field: the
        // fields that matter all require a new listener anyway, and a partial
        // reconfiguration is a state nobody can reason about.
        {
            let mut running = self.running.lock().await;
            let stale: Vec<String> = running
                .keys()
                .filter(|id| match wanted.get(*id) {
                    None => true,
                    Some(spec) => !spec.enabled || differs(spec, &running[*id].spec),
                })
                .cloned()
                .collect();
            for id in stale {
                if let Some(previous) = running.remove(&id) {
                    previous.handle.abort();
                }
            }
        }
        self.failed.lock().await.clear();

        let mut statuses = Vec::with_capacity(wanted.len());
        for (id, spec) in wanted {
            if !spec.enabled {
                statuses.push(InstanceStatus {
                    id,
                    listening: false,
                    listen_addr: format!("{}:{}", spec.listen_addr, spec.listen_port),
                    interface: None,
                    error: None,
                    counters: CounterSnapshot::default(),
                });
                continue;
            }
            if self.running.lock().await.contains_key(&id) {
                statuses.push(self.status_of(&id).await.expect("running"));
                continue;
            }
            statuses.push(self.start(spec).await);
        }
        statuses
    }

    /// Starts one listener, reporting rather than raising when it cannot bind.
    pub async fn start(&self, spec: InstanceSpec) -> InstanceStatus {
        let listen_addr = format!("{}:{}", spec.listen_addr, spec.listen_port);
        let interface = self.resolver.interface_for(&spec.modem_imei);
        // No interface means no way to honour "leave over this SIM", and a
        // listener that silently used the default route would send traffic out
        // of the wrong connection while looking correct.
        if interface.is_none() {
            let reason = format!("no network interface for modem {}", spec.modem_imei);
            self.failed
                .lock()
                .await
                .insert(spec.id.clone(), (spec.clone(), reason.clone()));
            return InstanceStatus {
                id: spec.id,
                listening: false,
                listen_addr,
                interface: None,
                error: Some(reason),
                counters: CounterSnapshot::default(),
            };
        }

        let listener = match TcpListener::bind(&listen_addr).await {
            Ok(listener) => listener,
            Err(error) => {
                let reason = error.to_string();
                self.failed
                    .lock()
                    .await
                    .insert(spec.id.clone(), (spec.clone(), reason.clone()));
                return InstanceStatus {
                    id: spec.id,
                    listening: false,
                    listen_addr,
                    interface,
                    error: Some(reason),
                    counters: CounterSnapshot::default(),
                };
            }
        };
        let bound = listener.local_addr().unwrap_or_else(|_| {
            "0.0.0.0:0".parse().expect("a literal address parses")
        });

        let counters = Arc::new(Counters::default());
        let upstream = match self.upstreams.lock().await.get(&spec.upstream_id) {
            Some(found) if found.enabled => Some(found.clone()),
            _ => None,
        };
        let task_counters = Arc::clone(&counters);
        let task_spec = spec.clone();
        let task_interface = interface.clone();
        let handle = tokio::spawn(async move {
            serve(listener, task_spec, upstream, task_interface, task_counters).await;
        });

        let status = InstanceStatus {
            id: spec.id.clone(),
            listening: true,
            listen_addr: bound.to_string(),
            interface: interface.clone(),
            error: None,
            counters: counters.snapshot(),
        };
        self.running.lock().await.insert(
            spec.id.clone(),
            Running {
                spec,
                handle,
                counters,
                bound,
                interface,
            },
        );
        status
    }

    /// Stops one listener. Returns false when it was not running.
    pub async fn stop(&self, id: &str) -> bool {
        match self.running.lock().await.remove(id) {
            Some(previous) => {
                previous.handle.abort();
                true
            }
            None => false,
        }
    }

    /// Stops and starts one listener, keeping its configuration.
    ///
    /// The counters restart with it: they measure a listener, and carrying
    /// them across a restart would report traffic the current one never saw.
    pub async fn restart(&self, id: &str) -> Option<InstanceStatus> {
        let spec = match self.running.lock().await.get(id) {
            Some(running) => running.spec.clone(),
            None => self.failed.lock().await.get(id).map(|(spec, _)| spec.clone())?,
        };
        self.stop(id).await;
        Some(self.start(spec).await)
    }

    /// The upstream with this id from the last applied configuration.
    ///
    /// The cloud sends an id when it asks for a probe, never the credential —
    /// a secret that has already been delivered should not travel again for
    /// every diagnostic.
    pub async fn upstream(&self, id: &str) -> Option<UpstreamSpec> {
        self.upstreams.lock().await.get(id).cloned()
    }

    pub async fn status_of(&self, id: &str) -> Option<InstanceStatus> {
        if let Some(running) = self.running.lock().await.get(id) {
            return Some(InstanceStatus {
                id: id.to_string(),
                listening: true,
                listen_addr: running.bound.to_string(),
                interface: running.interface.clone(),
                error: None,
                counters: running.counters.snapshot(),
            });
        }
        let failed = self.failed.lock().await;
        let (spec, reason) = failed.get(id)?;
        Some(InstanceStatus {
            id: id.to_string(),
            listening: false,
            listen_addr: format!("{}:{}", spec.listen_addr, spec.listen_port),
            interface: None,
            error: Some(reason.clone()),
            counters: CounterSnapshot::default(),
        })
    }

    /// Every instance's status, running or failed.
    pub async fn statuses(&self) -> Vec<InstanceStatus> {
        let mut out = Vec::new();
        for (id, running) in self.running.lock().await.iter() {
            out.push(InstanceStatus {
                id: id.clone(),
                listening: true,
                listen_addr: running.bound.to_string(),
                interface: running.interface.clone(),
                error: None,
                counters: running.counters.snapshot(),
            });
        }
        for (id, (spec, reason)) in self.failed.lock().await.iter() {
            out.push(InstanceStatus {
                id: id.clone(),
                listening: false,
                listen_addr: format!("{}:{}", spec.listen_addr, spec.listen_port),
                interface: None,
                error: Some(reason.clone()),
                counters: CounterSnapshot::default(),
            });
        }
        out.sort_by(|left, right| left.id.cmp(&right.id));
        out
    }
}

/// True when a change requires a new listener, which every field here does.
fn differs(wanted: &InstanceSpec, running: &InstanceSpec) -> bool {
    wanted.listen_addr != running.listen_addr
        || wanted.listen_port != running.listen_port
        || wanted.modem_imei != running.modem_imei
        || wanted.protocol != running.protocol
        || wanted.auth_enabled != running.auth_enabled
        || wanted.username != running.username
        || wanted.password != running.password
        || wanted.upstream_id != running.upstream_id
}

async fn serve(
    listener: TcpListener,
    spec: InstanceSpec,
    upstream: Option<UpstreamSpec>,
    interface: Option<String>,
    counters: Arc<Counters>,
) {
    loop {
        let (client, _peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            // A failed accept is usually transient — a descriptor limit, a
            // client that vanished mid-handshake. Ending the loop would take
            // the listener down for the rest of the process's life.
            Err(_) => {
                counters.errors.fetch_add(1, Ordering::Relaxed);
                continue;
            }
        };
        counters.connections.fetch_add(1, Ordering::Relaxed);
        let spec = spec.clone();
        let upstream = upstream.clone();
        let interface = interface.clone();
        let counters = Arc::clone(&counters);
        tokio::spawn(async move {
            if handle_client(client, &spec, upstream.as_ref(), interface.as_deref(), &counters)
                .await
                .is_err()
            {
                counters.errors.fetch_add(1, Ordering::Relaxed);
            }
        });
    }
}

async fn handle_client(
    mut client: TcpStream,
    spec: &InstanceSpec,
    upstream: Option<&UpstreamSpec>,
    interface: Option<&str>,
    counters: &Counters,
) -> io::Result<()> {
    let target = match negotiate(&mut client, spec).await {
        Ok(target) => target,
        Err(error) => {
            let _ = client.write_all(&socks5::reply(error.reply_code())).await;
            return Err(io::Error::new(io::ErrorKind::InvalidData, error));
        }
    };

    let server = match connect_out(&target, upstream, interface).await {
        Ok(stream) => stream,
        Err(error) => {
            let code = match error.kind() {
                io::ErrorKind::ConnectionRefused => socks5::REPLY_CONNECTION_REFUSED,
                io::ErrorKind::TimedOut | io::ErrorKind::NotFound => {
                    socks5::REPLY_HOST_UNREACHABLE
                }
                _ => socks5::REPLY_GENERAL_FAILURE,
            };
            let _ = client.write_all(&socks5::reply(code)).await;
            return Err(error);
        }
    };

    client.write_all(&socks5::reply(socks5::REPLY_SUCCESS)).await?;
    relay(client, server, counters).await
}

async fn negotiate(client: &mut TcpStream, spec: &InstanceSpec) -> Result<Target, ProtocolError> {
    let mut header = [0u8; 2];
    read_exact(client, &mut header).await?;
    if header[0] != socks5::VERSION {
        return Err(ProtocolError::NotSocks5(header[0]));
    }
    let mut methods = vec![0u8; header[1] as usize];
    read_exact(client, &mut methods).await?;

    let method = socks5::select_auth_method(&methods, spec.auth_enabled)?;
    write_all(client, &[socks5::VERSION, method]).await?;
    if method == socks5::AUTH_UNACCEPTABLE {
        return Err(ProtocolError::NoAcceptableAuth);
    }

    if spec.auth_enabled {
        let mut version = [0u8; 1];
        read_exact(client, &mut version).await?;
        if version[0] != socks5::USER_PASSWORD_VERSION {
            return Err(ProtocolError::BadCredentials);
        }
        // Read the two length-prefixed fields one at a time; their combined
        // length is not known in advance.
        let username = read_prefixed(client).await?;
        let password = read_prefixed(client).await?;
        let ok = username == spec.username && password == spec.password;
        write_all(client, &[socks5::USER_PASSWORD_VERSION, if ok { 0 } else { 1 }]).await?;
        if !ok {
            return Err(ProtocolError::BadCredentials);
        }
    }

    let mut head = [0u8; 4];
    read_exact(client, &mut head).await?;
    if head[0] != socks5::VERSION {
        return Err(ProtocolError::NotSocks5(head[0]));
    }
    // Re-assemble what parse_request expects: CMD, RSV, ATYP, then the address.
    let mut body = vec![head[1], head[2], head[3]];
    match head[3] {
        socks5::ATYP_IPV4 => body.extend(read_n(client, 4 + 2).await?),
        socks5::ATYP_IPV6 => body.extend(read_n(client, 16 + 2).await?),
        socks5::ATYP_DOMAIN => {
            let mut length = [0u8; 1];
            read_exact(client, &mut length).await?;
            body.push(length[0]);
            body.extend(read_n(client, length[0] as usize + 2).await?);
        }
        other => return Err(ProtocolError::UnsupportedAddressType(other)),
    }
    socks5::parse_request(&body)
}

async fn connect_out(
    target: &Target,
    upstream: Option<&UpstreamSpec>,
    interface: Option<&str>,
) -> io::Result<TcpStream> {
    match upstream {
        Some(upstream) => {
            let mut stream = bind::connect_via(&upstream.address, interface).await?;
            upstream_handshake(&mut stream, upstream, target).await?;
            Ok(stream)
        }
        // No upstream: straight out over the modem's interface, which is the
        // ordinary case and the reason the whole feature exists.
        None => bind::connect_via(&target.to_string(), interface).await,
    }
}

async fn upstream_handshake(
    stream: &mut TcpStream,
    upstream: &UpstreamSpec,
    target: &Target,
) -> io::Result<()> {
    let wants_auth = !upstream.username.is_empty();
    let offer: &[u8] = if wants_auth {
        &[socks5::VERSION, 1, socks5::AUTH_USER_PASSWORD]
    } else {
        &[socks5::VERSION, 1, socks5::AUTH_NONE]
    };
    stream.write_all(offer).await?;
    let mut chosen = [0u8; 2];
    stream.read_exact(&mut chosen).await?;
    if chosen[0] != socks5::VERSION || chosen[1] == socks5::AUTH_UNACCEPTABLE {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "upstream refused every authentication method offered",
        ));
    }
    if chosen[1] == socks5::AUTH_USER_PASSWORD {
        stream
            .write_all(&socks5::user_password_request(
                &upstream.username,
                &upstream.password,
            ))
            .await?;
        let mut status = [0u8; 2];
        stream.read_exact(&mut status).await?;
        if status[1] != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "upstream rejected the credentials",
            ));
        }
    }
    stream.write_all(&socks5::connect_request(target)).await?;
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await?;
    if reply[1] != socks5::REPLY_SUCCESS {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("upstream refused the connection (code {})", reply[1]),
        ));
    }
    // Drain the bound address so the stream is positioned at the payload.
    match reply[3] {
        socks5::ATYP_IPV4 => drain(stream, 4 + 2).await?,
        socks5::ATYP_IPV6 => drain(stream, 16 + 2).await?,
        socks5::ATYP_DOMAIN => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await?;
            drain(stream, length[0] as usize + 2).await?;
        }
        _ => {}
    }
    Ok(())
}

async fn relay(client: TcpStream, server: TcpStream, counters: &Counters) -> io::Result<()> {
    let (mut client_read, mut client_write) = client.into_split();
    let (mut server_read, mut server_write) = server.into_split();

    let up = async {
        let copied = tokio::io::copy(&mut client_read, &mut server_write).await;
        let _ = server_write.shutdown().await;
        copied
    };
    let down = async {
        let copied = tokio::io::copy(&mut server_read, &mut client_write).await;
        let _ = client_write.shutdown().await;
        copied
    };
    let (sent, received) = tokio::join!(up, down);
    counters
        .bytes_up
        .fetch_add(sent.unwrap_or(0), Ordering::Relaxed);
    counters
        .bytes_down
        .fetch_add(received.unwrap_or(0), Ordering::Relaxed);
    Ok(())
}

async fn read_exact(stream: &mut TcpStream, buffer: &mut [u8]) -> Result<(), ProtocolError> {
    stream
        .read_exact(buffer)
        .await
        .map(|_| ())
        .map_err(|_| ProtocolError::Truncated)
}

async fn read_n(stream: &mut TcpStream, count: usize) -> Result<Vec<u8>, ProtocolError> {
    let mut buffer = vec![0u8; count];
    read_exact(stream, &mut buffer).await?;
    Ok(buffer)
}

async fn read_prefixed(stream: &mut TcpStream) -> Result<String, ProtocolError> {
    let mut length = [0u8; 1];
    read_exact(stream, &mut length).await?;
    let bytes = read_n(stream, length[0] as usize).await?;
    String::from_utf8(bytes).map_err(|_| ProtocolError::BadCredentials)
}

async fn write_all(stream: &mut TcpStream, bytes: &[u8]) -> Result<(), ProtocolError> {
    stream
        .write_all(bytes)
        .await
        .map_err(|_| ProtocolError::Truncated)
}

async fn drain(stream: &mut TcpStream, count: usize) -> io::Result<()> {
    let mut buffer = vec![0u8; count];
    stream.read_exact(&mut buffer).await.map(|_| ())
}
