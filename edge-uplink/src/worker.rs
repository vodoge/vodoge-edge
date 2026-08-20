//! Durable outbox replay over a WSS frame connection.
//!
//! Transport is a [`FrameConn`] so tests can inject a fake socket. Persistence
//! is an [`Outbox`] so this module does not open SQLite.

use std::time::Instant;

use vodoge_contract::{Envelope, MessageKind, PROTOCOL_VERSION};

use crate::dial::{DialError, FrameConn};
use crate::session::{
    Inbound, LinkConfig, LinkSession, Phase, ResumeSnapshot, SessionError, PING_INTERVAL,
};
use crate::{SequenceRange, UplinkAck, UplinkError};

/// One retained sequenced envelope ready to send on the wire.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedRecord {
    pub sequence: u64,
    pub envelope_id: String,
    pub kind: String,
    pub payload: Vec<u8>,
}

/// Local journal used to build Resume snapshots and apply cumulative acks.
pub trait Outbox {
    type Error: std::fmt::Display;

    fn last_allocated(&self) -> u64;
    fn committed_through(&self) -> u64;
    fn lowest_retained_seq(&self) -> Option<u64>;
    fn pending_gap_ids(&self) -> Vec<String>;
    fn queue_records(&self) -> i64;
    fn queue_bytes(&self) -> Option<i64>;
    fn observe_ack(&mut self, ack: UplinkAck) -> Result<Vec<u64>, Self::Error>;
    fn retained(&self) -> Result<Vec<RetainedRecord>, Self::Error>;
}

/// Drives Resume, replay, heartbeat, and reconnect against one outbox.
pub struct UplinkWorker<O> {
    session: LinkSession,
    outbox: O,
    next_connection: u64,
    last_connection_id: Option<String>,
}

/// Failures while running one uplink attempt.
#[derive(Debug)]
pub enum WorkerError {
    Dial(DialError),
    Session(SessionError),
    Uplink(UplinkError),
    Outbox(String),
    InvalidKind(String),
    InvalidPayload(String),
}

impl std::fmt::Display for WorkerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dial(err) => write!(formatter, "{err}"),
            Self::Session(err) => write!(formatter, "{err}"),
            Self::Uplink(err) => write!(formatter, "{err}"),
            Self::Outbox(err) => write!(formatter, "{err}"),
            Self::InvalidKind(kind) => write!(formatter, "unknown retained message kind {kind}"),
            Self::InvalidPayload(reason) => write!(formatter, "invalid retained payload: {reason}"),
        }
    }
}

impl std::error::Error for WorkerError {}

impl From<DialError> for WorkerError {
    fn from(err: DialError) -> Self {
        Self::Dial(err)
    }
}

impl From<SessionError> for WorkerError {
    fn from(err: SessionError) -> Self {
        Self::Session(err)
    }
}

impl From<UplinkError> for WorkerError {
    fn from(err: UplinkError) -> Self {
        Self::Uplink(err)
    }
}

impl<O: Outbox> UplinkWorker<O> {
    pub fn new(config: LinkConfig, outbox: O) -> Self {
        Self {
            session: LinkSession::new(config),
            outbox,
            next_connection: 0,
            last_connection_id: None,
        }
    }

    pub fn session(&self) -> &LinkSession {
        &self.session
    }

    pub fn outbox(&self) -> &O {
        &self.outbox
    }

    pub fn outbox_mut(&mut self) -> &mut O {
        &mut self.outbox
    }

    pub fn last_connection_id(&self) -> Option<&str> {
        self.last_connection_id.as_deref()
    }

    pub fn reconnect_delay(&self) -> std::time::Duration {
        self.session.reconnect_delay()
    }

    /// Sends Resume with cursors from the outbox and a new `connection_id`.
    pub fn start<C: FrameConn>(
        &mut self,
        conn: &mut C,
        now: Instant,
    ) -> Result<String, WorkerError> {
        self.refresh_snapshot();
        let connection_id = self.alloc_connection_id();
        let resume = self.session.handshake(&connection_id, now)?;
        conn.set_read_timeout(Some(PING_INTERVAL))?;
        if let Err(err) = conn.send_envelope(&resume) {
            self.mark_dropped(now);
            return Err(err.into());
        }
        self.last_connection_id = Some(connection_id.clone());
        Ok(connection_id)
    }

    /// Handshake, then process frames until the socket drops.
    pub fn run<C: FrameConn>(&mut self, conn: &mut C, now: Instant) -> Result<(), WorkerError> {
        self.start(conn, now)?;
        loop {
            match conn.recv_envelope() {
                Ok(envelope) => {
                    if let Err(err) = self.on_inbound(conn, envelope, now) {
                        self.mark_dropped(now);
                        return Err(err);
                    }
                    if self.session.phase() == Phase::Backoff {
                        return Ok(());
                    }
                }
                Err(DialError::Timeout) => {
                    self.poll(conn, now)?;
                    if self.session.phase() == Phase::Backoff {
                        return Ok(());
                    }
                }
                Err(DialError::Closed) => {
                    self.mark_dropped(now);
                    return Ok(());
                }
                Err(err) => {
                    self.mark_dropped(now);
                    return Err(err.into());
                }
            }
        }
    }

    pub fn on_inbound<C: FrameConn>(
        &mut self,
        conn: &mut C,
        envelope: Envelope,
        now: Instant,
    ) -> Result<Inbound, WorkerError> {
        let inbound = self.session.on_inbound(envelope, now)?;
        match &inbound {
            Inbound::ResumeAck(ack) => {
                self.apply_ack(ack.committed_through, &ack.missing_ranges, ack.more_missing)?;
                self.replay(conn, now)?;
            }
            Inbound::UplinkAck(ack) => {
                self.apply_ack(ack.committed_through, &ack.missing_ranges, ack.more_missing)?;
            }
            Inbound::IgnoredStale | Inbound::Pong(_) => {}
            Inbound::ProtocolError(_) => {}
        }
        Ok(inbound)
    }

    /// Sends Ping when the 30s heartbeat is due.
    pub fn poll<C: FrameConn>(
        &mut self,
        conn: &mut C,
        now: Instant,
    ) -> Result<Option<Envelope>, WorkerError> {
        let ping = self.session.poll(now);
        if let Some(ref envelope) = ping {
            conn.send_envelope(envelope)?;
        }
        Ok(ping)
    }

    pub fn on_disconnect(&mut self, now: Instant) {
        self.mark_dropped(now);
    }

    fn replay<C: FrameConn>(&mut self, conn: &mut C, now: Instant) -> Result<(), WorkerError> {
        let committed_through = self.outbox.committed_through();
        let mut records = self
            .outbox
            .retained()
            .map_err(|err| WorkerError::Outbox(err.to_string()))?;
        records.sort_by_key(|record| record.sequence);
        for record in records {
            if record.sequence <= committed_through {
                continue;
            }
            let envelope = self.sequenced_envelope(&record, now)?;
            conn.send_envelope(&envelope)?;
        }
        Ok(())
    }

    fn sequenced_envelope(
        &self,
        record: &RetainedRecord,
        now: Instant,
    ) -> Result<Envelope, WorkerError> {
        let kind = parse_kind(&record.kind)?;
        let payload = serde_json::from_slice(&record.payload)
            .map_err(|err| WorkerError::InvalidPayload(err.to_string()))?;
        Ok(Envelope {
            v: PROTOCOL_VERSION,
            kind,
            id: record.envelope_id.clone(),
            ts: self.session.stamp(now),
            device_id: self.session.device_id().to_owned(),
            seq: Some(record.sequence),
            trace_id: None,
            payload,
        })
    }

    fn apply_ack(
        &mut self,
        committed_through: u64,
        missing_ranges: &[vodoge_contract::SequenceRange],
        more_missing: bool,
    ) -> Result<Vec<u64>, WorkerError> {
        let ranges = missing_ranges
            .iter()
            .map(|range| SequenceRange::new(range.from, range.through))
            .collect::<Result<Vec<_>, _>>()?;
        let ack = UplinkAck::new(committed_through, ranges, more_missing)?;
        self.outbox
            .observe_ack(ack)
            .map_err(|err| WorkerError::Outbox(err.to_string()))
    }

    fn refresh_snapshot(&mut self) {
        let previous = self.session.snapshot();
        let snapshot = ResumeSnapshot {
            last_assigned_seq: self.outbox.last_allocated(),
            last_acked_seq: self.outbox.committed_through(),
            lowest_retained_seq: self.outbox.lowest_retained_seq(),
            pending_gap_ids: self.outbox.pending_gap_ids(),
            capability_matrix_version: previous.capability_matrix_version.clone(),
            edge_version: previous.edge_version.clone(),
            queue_records: Some(self.outbox.queue_records()),
            queue_bytes: self.outbox.queue_bytes(),
        };
        self.session.set_snapshot(snapshot);
    }

    fn alloc_connection_id(&mut self) -> String {
        self.next_connection += 1;
        format!("10000000-0000-4000-8000-{:012}", self.next_connection)
    }

    fn mark_dropped(&mut self, now: Instant) {
        if self.session.phase() != Phase::Backoff {
            self.session.on_disconnect(now);
        }
    }
}

fn parse_kind(kind: &str) -> Result<MessageKind, WorkerError> {
    serde_json::from_value(serde_json::Value::String(kind.to_owned()))
        .map_err(|_| WorkerError::InvalidKind(kind.to_owned()))
}
