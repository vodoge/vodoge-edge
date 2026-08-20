//! Edge-initiated WSS session: Resume first, then heartbeat, then backoff.

use std::time::{Duration, Instant};

use vodoge_contract::{
    Envelope, MessageKind, PingPayload, PongPayload, ProtocolErrorPayload, ResumeAckPayload,
    ResumePayload, UplinkAckPayload, PROTOCOL_VERSION,
};

/// Default edge-to-cloud ping period from the protocol.
pub const PING_INTERVAL: Duration = Duration::from_secs(30);
/// Cloud idle timeout; the edge treats a missed pong as a dead connection.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(90);
/// First reconnect wait after a drop.
pub const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
/// Cap for exponential reconnect backoff.
pub const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// Local sequence cursors included in Resume. The cloud does not trust them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResumeSnapshot {
    pub last_assigned_seq: u64,
    pub last_acked_seq: u64,
    pub lowest_retained_seq: Option<u64>,
    pub pending_gap_ids: Vec<String>,
    pub capability_matrix_version: String,
    pub edge_version: Option<String>,
    pub queue_records: Option<i64>,
    pub queue_bytes: Option<i64>,
}

/// Configuration for one device uplink session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkConfig {
    pub device_id: String,
    pub snapshot: ResumeSnapshot,
    pub ping_interval: Duration,
    pub idle_timeout: Duration,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
}

impl LinkConfig {
    pub fn new(device_id: impl Into<String>, snapshot: ResumeSnapshot) -> Result<Self, SessionError> {
        let device_id = device_id.into();
        if device_id.trim().is_empty() {
            return Err(SessionError::EmptyDeviceId);
        }
        Ok(Self {
            device_id,
            snapshot,
            ping_interval: PING_INTERVAL,
            idle_timeout: IDLE_TIMEOUT,
            initial_backoff: INITIAL_BACKOFF,
            max_backoff: MAX_BACKOFF,
        })
    }
}

/// Observable phase of the session state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Idle,
    Resuming,
    Live,
    Backoff,
}

/// Result of handling one inbound envelope.
#[derive(Clone, Debug)]
pub enum Inbound {
    ResumeAck(ResumeAckPayload),
    UplinkAck(UplinkAckPayload),
    Pong(PongPayload),
    ProtocolError(ProtocolErrorPayload),
    CommandDeliver(Envelope),
    IgnoredStale,
}

/// Protocol or identity error that ends the current attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionError {
    EmptyDeviceId,
    EmptyConnectionId,
    AlreadyConnected,
    NotResuming,
    NotLive,
    DeviceMismatch,
    ConnectionMismatch,
    UnexpectedKind(String),
    InvalidEnvelope(String),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyDeviceId => formatter.write_str("device_id is required"),
            Self::EmptyConnectionId => formatter.write_str("connection_id is required"),
            Self::AlreadyConnected => formatter.write_str("session already has a live connection"),
            Self::NotResuming => formatter.write_str("session is not waiting for ResumeAck"),
            Self::NotLive => formatter.write_str("session is not live"),
            Self::DeviceMismatch => formatter.write_str("envelope device_id does not match"),
            Self::ConnectionMismatch => formatter.write_str("envelope connection_id does not match"),
            Self::UnexpectedKind(kind) => write!(formatter, "unexpected envelope {kind}"),
            Self::InvalidEnvelope(reason) => write!(formatter, "invalid envelope: {reason}"),
        }
    }
}

impl std::error::Error for SessionError {}

/// Edge-side WSS protocol state. Transport and persistence stay outside.
pub struct LinkSession {
    config: LinkConfig,
    phase: Phase,
    connection_id: Option<String>,
    committed_through: Option<u64>,
    max_in_flight: Option<i64>,
    next_id: u64,
    origin: Option<Instant>,
    next_ping_at: Option<Instant>,
    last_recv_at: Option<Instant>,
    reconnect_at: Option<Instant>,
    backoff: Duration,
}

impl LinkSession {
    pub fn new(config: LinkConfig) -> Self {
        let backoff = config.initial_backoff;
        Self {
            config,
            phase: Phase::Idle,
            connection_id: None,
            committed_through: None,
            max_in_flight: None,
            next_id: 0,
            origin: None,
            next_ping_at: None,
            last_recv_at: None,
            reconnect_at: None,
            backoff,
        }
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn connection_id(&self) -> Option<&str> {
        self.connection_id.as_deref()
    }

    pub fn committed_through(&self) -> Option<u64> {
        self.committed_through
    }

    pub fn max_in_flight(&self) -> Option<i64> {
        self.max_in_flight
    }

    pub fn reconnect_delay(&self) -> Duration {
        self.backoff
    }

    pub fn reconnect_at(&self) -> Option<Instant> {
        self.reconnect_at
    }

    pub fn device_id(&self) -> &str {
        &self.config.device_id
    }

    pub fn snapshot(&self) -> &ResumeSnapshot {
        &self.config.snapshot
    }

    /// Replace local Resume cursors. Capability and version fields are kept
    /// by the caller; reconnect must send a fresh outbox snapshot.
    pub fn set_snapshot(&mut self, snapshot: ResumeSnapshot) {
        self.config.snapshot = snapshot;
    }

    pub(crate) fn stamp(&self, now: Instant) -> i64 {
        self.timestamp(now)
    }

    /// After the TLS socket is up, emit Resume as the first outbound envelope.
    pub fn handshake(
        &mut self,
        connection_id: impl Into<String>,
        now: Instant,
    ) -> Result<Envelope, SessionError> {
        if self.phase == Phase::Resuming || self.phase == Phase::Live {
            return Err(SessionError::AlreadyConnected);
        }
        let connection_id = connection_id.into();
        if connection_id.trim().is_empty() {
            return Err(SessionError::EmptyConnectionId);
        }

        let snapshot = &self.config.snapshot;
        let payload = ResumePayload {
            connection_id: connection_id.clone(),
            last_assigned_seq: snapshot.last_assigned_seq,
            lowest_retained_seq: snapshot.lowest_retained_seq,
            last_acked_seq: snapshot.last_acked_seq,
            pending_gap_ids: snapshot.pending_gap_ids.clone(),
            capability_matrix_version: snapshot.capability_matrix_version.clone(),
            edge_version: snapshot.edge_version.clone(),
            queue_records: snapshot.queue_records,
            queue_bytes: snapshot.queue_bytes,
        };
        self.phase = Phase::Resuming;
        self.connection_id = Some(connection_id);
        self.committed_through = None;
        self.max_in_flight = None;
        self.origin = Some(now);
        self.next_ping_at = None;
        self.last_recv_at = Some(now);
        self.reconnect_at = None;
        Ok(self.envelope(
            MessageKind::Resume,
            serde_json::to_value(payload).expect("resume payload"),
            None,
            now,
        ))
    }

    pub fn on_inbound(&mut self, envelope: Envelope, now: Instant) -> Result<Inbound, SessionError> {
        envelope
            .validate_sequence()
            .map_err(SessionError::InvalidEnvelope)?;
        if envelope.device_id != self.config.device_id {
            return Err(SessionError::DeviceMismatch);
        }
        match envelope.kind {
            MessageKind::ResumeAck => self.on_resume_ack(envelope, now),
            MessageKind::UplinkAck => self.on_uplink_ack(envelope, now),
            MessageKind::Pong => self.on_pong(envelope, now),
            MessageKind::ProtocolError => self.on_protocol_error(envelope, now),
            MessageKind::CommandDeliver => Ok(Inbound::CommandDeliver(envelope)),
            other => Err(SessionError::UnexpectedKind(other.as_str().to_string())),
        }
    }

    /// Returns the next Ping when the heartbeat is due. None until ResumeAck.
    pub fn poll(&mut self, now: Instant) -> Option<Envelope> {
        if self.phase != Phase::Live {
            return None;
        }
        if self.idle_expired(now) {
            self.drop_connection(now);
            return None;
        }
        let due = self.next_ping_at?;
        if now < due {
            return None;
        }
        let connection_id = self.connection_id.clone()?;
        let payload = PingPayload {
            connection_id,
            sent_at: self.timestamp(now),
        };
        self.next_ping_at = Some(now + self.config.ping_interval);
        Some(self.envelope(
            MessageKind::Ping,
            serde_json::to_value(payload).expect("ping payload"),
            None,
            now,
        ))
    }

    pub fn on_disconnect(&mut self, now: Instant) {
        if self.phase == Phase::Idle {
            self.reconnect_at = Some(now + self.backoff);
            self.phase = Phase::Backoff;
            return;
        }
        self.drop_connection(now);
    }

    fn on_resume_ack(&mut self, envelope: Envelope, now: Instant) -> Result<Inbound, SessionError> {
        if self.phase != Phase::Resuming {
            return Err(SessionError::NotResuming);
        }
        let ack: ResumeAckPayload = serde_json::from_value(envelope.payload)
            .map_err(|err| SessionError::InvalidEnvelope(err.to_string()))?;
        self.require_connection(&ack.connection_id)?;
        self.phase = Phase::Live;
        self.committed_through = Some(ack.committed_through);
        self.max_in_flight = Some(ack.max_in_flight);
        self.last_recv_at = Some(now);
        self.next_ping_at = Some(now + self.config.ping_interval);
        self.backoff = self.config.initial_backoff;
        self.reconnect_at = None;
        Ok(Inbound::ResumeAck(ack))
    }

    fn on_uplink_ack(&mut self, envelope: Envelope, now: Instant) -> Result<Inbound, SessionError> {
        if self.phase != Phase::Live {
            return Err(SessionError::NotLive);
        }
        let ack: UplinkAckPayload = serde_json::from_value(envelope.payload)
            .map_err(|err| SessionError::InvalidEnvelope(err.to_string()))?;
        if self.connection_id.as_deref() != Some(ack.connection_id.as_str()) {
            return Ok(Inbound::IgnoredStale);
        }
        self.last_recv_at = Some(now);
        self.committed_through = Some(ack.committed_through);
        Ok(Inbound::UplinkAck(ack))
    }

    fn on_pong(&mut self, envelope: Envelope, now: Instant) -> Result<Inbound, SessionError> {
        if self.phase != Phase::Live {
            return Err(SessionError::NotLive);
        }
        let pong: PongPayload = serde_json::from_value(envelope.payload)
            .map_err(|err| SessionError::InvalidEnvelope(err.to_string()))?;
        if self.connection_id.as_deref() != Some(pong.connection_id.as_str()) {
            return Ok(Inbound::IgnoredStale);
        }
        self.last_recv_at = Some(now);
        Ok(Inbound::Pong(pong))
    }

    fn on_protocol_error(
        &mut self,
        envelope: Envelope,
        now: Instant,
    ) -> Result<Inbound, SessionError> {
        let error: ProtocolErrorPayload = serde_json::from_value(envelope.payload)
            .map_err(|err| SessionError::InvalidEnvelope(err.to_string()))?;
        self.drop_connection(now);
        Ok(Inbound::ProtocolError(error))
    }

    fn require_connection(&self, connection_id: &str) -> Result<(), SessionError> {
        if self.connection_id.as_deref() != Some(connection_id) {
            return Err(SessionError::ConnectionMismatch);
        }
        Ok(())
    }

    fn idle_expired(&self, now: Instant) -> bool {
        match self.last_recv_at {
            Some(last) => now.saturating_duration_since(last) >= self.config.idle_timeout,
            None => false,
        }
    }

    fn drop_connection(&mut self, now: Instant) {
        self.phase = Phase::Backoff;
        self.connection_id = None;
        self.origin = None;
        self.next_ping_at = None;
        self.last_recv_at = None;
        self.reconnect_at = Some(now + self.backoff);
        let doubled = self.backoff.saturating_mul(2);
        self.backoff = if doubled > self.config.max_backoff {
            self.config.max_backoff
        } else {
            doubled
        };
    }

    fn envelope(
        &mut self,
        kind: MessageKind,
        payload: serde_json::Value,
        seq: Option<u64>,
        now: Instant,
    ) -> Envelope {
        Envelope {
            v: PROTOCOL_VERSION,
            kind,
            id: self.alloc_id(),
            ts: self.timestamp(now),
            device_id: self.config.device_id.clone(),
            seq,
            trace_id: None,
            payload,
        }
    }

    fn alloc_id(&mut self) -> String {
        self.next_id += 1;
        format!("00000000-0000-4000-8000-{:012}", self.next_id)
    }

    fn timestamp(&self, now: Instant) -> i64 {
        match self.origin {
            Some(origin) => now.saturating_duration_since(origin).as_millis() as i64,
            None => 0,
        }
    }
}
