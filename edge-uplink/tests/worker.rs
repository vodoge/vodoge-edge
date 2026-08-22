use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

use edge_uplink::codec::{decode_json, encode_json};
use edge_uplink::dial::{DialError, FrameConn};
use edge_uplink::session::{Inbound, LinkConfig, Phase, ResumeSnapshot, INITIAL_BACKOFF, PING_INTERVAL};
use edge_uplink::worker::{Outbox, RetainedRecord, UplinkWorker};
use edge_uplink::{EnvelopeId, RetentionClass, UplinkAck, UplinkError, UplinkState};
use vodoge_contract::{
    Envelope, MessageKind, PongPayload, ResumeAckPayload, ResumePayload, UplinkAckPayload,
};

struct MemoryOutbox {
    state: UplinkState,
    kinds: BTreeMap<u64, String>,
}

impl MemoryOutbox {
    fn new() -> Self {
        Self {
            state: UplinkState::new(),
            kinds: BTreeMap::new(),
        }
    }

    fn persist(&mut self, id: &str, kind: &str, n: u64) {
        let payload = serde_json::to_vec(&serde_json::json!({ "n": n })).expect("json");
        let sequence = self
            .state
            .append(
                EnvelopeId::new(id).expect("id"),
                payload,
                RetentionClass::Protected,
            )
            .expect("append");
        self.kinds.insert(sequence, kind.to_owned());
    }
}

impl Outbox for MemoryOutbox {
    type Error = UplinkError;

    fn last_allocated(&self) -> u64 {
        self.state.last_allocated()
    }

    fn committed_through(&self) -> u64 {
        self.state.committed_through()
    }

    fn lowest_retained_seq(&self) -> Option<u64> {
        self.state.retained_records().next().map(|record| record.sequence())
    }

    fn pending_gap_ids(&self) -> Vec<String> {
        Vec::new()
    }

    fn queue_records(&self) -> i64 {
        self.state.retained_records().count() as i64
    }

    fn queue_bytes(&self) -> Option<i64> {
        Some(
            self.state
                .retained_records()
                .map(|record| record.payload().len() as i64)
                .sum(),
        )
    }

    fn observe_ack(&mut self, ack: UplinkAck) -> Result<Vec<u64>, Self::Error> {
        let deleted = self.state.observe_ack(ack)?.deleted_sequences;
        for sequence in &deleted {
            self.kinds.remove(sequence);
        }
        Ok(deleted)
    }

    fn retained(&self) -> Result<Vec<RetainedRecord>, Self::Error> {
        Ok(self
            .state
            .retained_records()
            .map(|record| RetainedRecord {
                sequence: record.sequence(),
                envelope_id: record.envelope_id().as_str().to_owned(),
                kind: self
                    .kinds
                    .get(&record.sequence())
                    .cloned()
                    .unwrap_or_default(),
                payload: record.payload().to_vec(),
            })
            .collect())
    }
}

#[derive(Clone)]
enum Scripted {
    ResumeAck { committed_through: u64 },
    UplinkAck {
        committed_through: u64,
        connection_id: Option<String>,
    },
    /// An ack that names sequences the peer never stored.
    UplinkAckWithGap {
        committed_through: u64,
        gaps: Vec<(u64, u64)>,
    },
    Closed,
}

struct FakeConn {
    inbound: VecDeque<Scripted>,
    outbound: Vec<Envelope>,
}

impl FakeConn {
    fn script(frames: impl IntoIterator<Item = Scripted>) -> Self {
        Self {
            inbound: frames.into_iter().collect(),
            outbound: Vec::new(),
        }
    }

    fn last_resume(&self) -> ResumePayload {
        let resume = self
            .outbound
            .iter()
            .rev()
            .find(|envelope| envelope.kind == MessageKind::Resume)
            .expect("resume sent");
        serde_json::from_value(resume.payload.clone()).expect("resume payload")
    }

    fn sequenced(&self) -> Vec<&Envelope> {
        self.outbound
            .iter()
            .filter(|envelope| envelope.seq.is_some())
            .collect()
    }
}

impl FrameConn for FakeConn {
    fn send_envelope(&mut self, envelope: &Envelope) -> Result<(), DialError> {
        let bytes = encode_json(envelope).map_err(DialError::Protocol)?;
        self.outbound
            .push(decode_json(&bytes).map_err(DialError::Protocol)?);
        Ok(())
    }

    fn recv_envelope(&mut self) -> Result<Envelope, DialError> {
        match self.inbound.pop_front().unwrap_or(Scripted::Closed) {
            Scripted::ResumeAck { committed_through } => {
                let resume = self.last_resume();
                let device_id = self
                    .outbound
                    .iter()
                    .rev()
                    .find(|envelope| envelope.kind == MessageKind::Resume)
                    .map(|envelope| envelope.device_id.clone())
                    .expect("resume");
                Ok(resume_ack(device_id, resume.connection_id, committed_through))
            }
            Scripted::UplinkAck {
                committed_through,
                connection_id,
            } => {
                let connection_id = connection_id.unwrap_or_else(|| self.last_resume().connection_id);
                let device_id = self
                    .outbound
                    .iter()
                    .rev()
                    .find(|envelope| envelope.kind == MessageKind::Resume)
                    .map(|envelope| envelope.device_id.clone())
                    .expect("resume");
                Ok(uplink_ack(device_id, connection_id, committed_through))
            }
            Scripted::UplinkAckWithGap {
                committed_through,
                gaps,
            } => {
                let connection_id = self.last_resume().connection_id;
                let device_id = self
                    .outbound
                    .iter()
                    .rev()
                    .find(|envelope| envelope.kind == MessageKind::Resume)
                    .map(|envelope| envelope.device_id.clone())
                    .expect("resume");
                Ok(uplink_ack_with_gap(device_id, connection_id, committed_through, &gaps))
            }
            Scripted::Closed => Err(DialError::Closed),
        }
    }
}

fn snapshot() -> ResumeSnapshot {
    ResumeSnapshot {
        last_assigned_seq: 0,
        last_acked_seq: 0,
        lowest_retained_seq: None,
        pending_gap_ids: Vec::new(),
        capability_matrix_version: "1".into(),
        edge_version: Some("0.1.0".into()),
        queue_records: None,
        queue_bytes: None,
    }
}

fn worker_with(records: MemoryOutbox) -> UplinkWorker<MemoryOutbox> {
    let config = LinkConfig::new("dev-1", snapshot()).expect("config");
    UplinkWorker::new(config, records)
}

fn persist_123() -> MemoryOutbox {
    let mut outbox = MemoryOutbox::new();
    outbox.persist("env-1", "SmsReceived", 1);
    outbox.persist("env-2", "SmsReceived", 2);
    outbox.persist("env-3", "SmsReceived", 3);
    outbox
}

fn resume_ack(device_id: String, connection_id: String, committed_through: u64) -> Envelope {
    Envelope {
        v: 1,
        kind: MessageKind::ResumeAck,
        id: "resume-ack".into(),
        ts: 1,
        device_id,
        seq: None,
        trace_id: None,
        payload: serde_json::to_value(ResumeAckPayload {
            connection_id,
            committed_through,
            missing_ranges: Vec::new(),
            more_missing: false,
            max_in_flight: 32,
            server_time: 1,
        })
        .unwrap(),
    }
}

fn uplink_ack(device_id: String, connection_id: String, committed_through: u64) -> Envelope {
    Envelope {
        v: 1,
        kind: MessageKind::UplinkAck,
        id: format!("uplink-ack-{committed_through}"),
        ts: 2,
        device_id,
        seq: None,
        trace_id: None,
        payload: serde_json::to_value(UplinkAckPayload {
            connection_id,
            committed_through,
            missing_ranges: Vec::new(),
            more_missing: false,
            max_in_flight: 32,
        })
        .unwrap(),
    }
}

#[test]
fn resume_replays_from_committed_through_and_duplicate_ack_is_noop() {
    let mut worker = worker_with(persist_123());
    let mut conn = FakeConn::script([
        Scripted::ResumeAck {
            committed_through: 1,
        },
        Scripted::UplinkAck {
            committed_through: 3,
            connection_id: None,
        },
        Scripted::UplinkAck {
            committed_through: 3,
            connection_id: None,
        },
        Scripted::Closed,
    ]);

    worker.run(&mut conn, Instant::now()).expect("run");

    let resume: ResumePayload = serde_json::from_value(conn.outbound[0].payload.clone()).unwrap();
    assert_eq!(conn.outbound[0].kind, MessageKind::Resume);
    assert_eq!(resume.last_assigned_seq, 3);
    assert_eq!(resume.last_acked_seq, 0);
    assert_eq!(resume.lowest_retained_seq, Some(1));

    let sequenced = conn.sequenced();
    assert_eq!(sequenced.len(), 2);
    assert_eq!(sequenced[0].seq, Some(2));
    assert_eq!(sequenced[0].id, "env-2");
    assert_eq!(sequenced[0].kind, MessageKind::SmsReceived);
    assert_eq!(sequenced[1].seq, Some(3));
    assert_eq!(sequenced[1].id, "env-3");
    assert_eq!(worker.outbox().committed_through(), 3);
    assert!(worker.outbox().retained().expect("retained").is_empty());
    assert_eq!(worker.session().phase(), Phase::Backoff);
}

#[test]
fn stale_connection_id_ack_does_not_advance_outbox() {
    let mut worker = worker_with(persist_123());
    let mut conn = FakeConn::script([]);
    let now = Instant::now();
    let connection_id = worker.start(&mut conn, now).expect("start");
    worker
        .on_inbound(
            &mut conn,
            resume_ack("dev-1".into(), connection_id.clone(), 1),
            now,
        )
        .expect("resume ack");
    assert_eq!(worker.outbox().committed_through(), 1);

    let inbound = worker
        .on_inbound(
            &mut conn,
            uplink_ack("dev-1".into(), "old-conn".into(), 99),
            now,
        )
        .expect("stale");
    assert!(matches!(inbound, Inbound::IgnoredStale));
    assert_eq!(worker.outbox().committed_through(), 1);
    assert_eq!(
        worker
            .outbox()
            .retained()
            .expect("retained")
            .iter()
            .map(|record| record.sequence)
            .collect::<Vec<_>>(),
        vec![2, 3]
    );
}

#[test]
fn heartbeat_sends_ping_after_thirty_seconds() {
    let mut worker = worker_with(persist_123());
    let mut conn = FakeConn::script([]);
    let now = Instant::now();
    let connection_id = worker.start(&mut conn, now).expect("start");
    worker
        .on_inbound(
            &mut conn,
            resume_ack("dev-1".into(), connection_id, 1),
            now,
        )
        .expect("resume ack");

    assert!(worker
        .poll(&mut conn, now + Duration::from_secs(29))
        .expect("early poll")
        .is_none());
    let ping = worker
        .poll(&mut conn, now + PING_INTERVAL)
        .expect("due")
        .expect("ping");
    assert_eq!(ping.kind, MessageKind::Ping);
    assert_eq!(conn.outbound.last().map(|envelope| envelope.kind), Some(MessageKind::Ping));
}

#[test]
fn reconnect_uses_a_new_connection_id_and_exponential_backoff() {
    let mut worker = worker_with(persist_123());
    let now = Instant::now();
    let mut first = FakeConn::script([
        Scripted::ResumeAck {
            committed_through: 1,
        },
        Scripted::Closed,
    ]);
    worker.run(&mut first, now).expect("first session");
    let first_id = worker.last_connection_id().expect("first id").to_owned();
    assert_eq!(worker.session().phase(), Phase::Backoff);
    assert_eq!(worker.reconnect_delay(), INITIAL_BACKOFF * 2);

    let mut second = FakeConn::script([
        Scripted::ResumeAck {
            committed_through: 1,
        },
        Scripted::Closed,
    ]);
    worker
        .run(&mut second, now + worker.reconnect_delay())
        .expect("second session");
    let second_id = worker.last_connection_id().expect("second id").to_owned();
    assert_ne!(first_id, second_id);

    let resume: ResumePayload = serde_json::from_value(second.outbound[0].payload.clone()).unwrap();
    assert_eq!(resume.connection_id, second_id);
    assert_eq!(resume.last_acked_seq, 1);
    assert_eq!(resume.last_assigned_seq, 3);
    assert_eq!(resume.lowest_retained_seq, Some(2));
}

#[test]
fn pong_on_live_session_is_ignored_by_the_outbox() {
    let mut worker = worker_with(persist_123());
    let mut conn = FakeConn::script([]);
    let now = Instant::now();
    let connection_id = worker.start(&mut conn, now).expect("start");
    worker
        .on_inbound(
            &mut conn,
            resume_ack("dev-1".into(), connection_id.clone(), 1),
            now,
        )
        .expect("resume ack");
    let pong = Envelope {
        v: 1,
        kind: MessageKind::Pong,
        id: "pong".into(),
        ts: 4,
        device_id: "dev-1".into(),
        seq: None,
        trace_id: None,
        payload: serde_json::to_value(PongPayload {
            connection_id,
            ping_id: "ping".into(),
            server_time: 4,
        })
        .unwrap(),
    };
    assert!(matches!(
        worker.on_inbound(&mut conn, pong, now).expect("pong"),
        Inbound::Pong(_)
    ));
    assert_eq!(worker.outbox().committed_through(), 1);
}

fn uplink_ack_with_gap(
    device_id: String,
    connection_id: String,
    committed_through: u64,
    gaps: &[(u64, u64)],
) -> Envelope {
    Envelope {
        v: 1,
        kind: MessageKind::UplinkAck,
        id: format!("uplink-ack-gap-{committed_through}"),
        ts: 2,
        device_id,
        seq: None,
        trace_id: None,
        payload: serde_json::to_value(UplinkAckPayload {
            connection_id,
            committed_through,
            missing_ranges: gaps
                .iter()
                .map(|(from, through)| vodoge_contract::SequenceRange {
                    from: *from,
                    through: *through,
                })
                .collect(),
            more_missing: false,
            max_in_flight: 32,
        })
        .unwrap(),
    }
}

/// An ack naming a gap must put those records back on the wire.
///
/// The replay cursor only ever moved forward, so a record that was sent and
/// never stored stayed lost: the peer reported it missing in every ack, this
/// side acknowledged that, and never resent it. Because the peer's
/// committed_through cannot advance past a hole, in-flight then grew to the
/// window size and the replay budget reached zero — the uplink stopped sending
/// anything at all while the link looked perfectly healthy. On the deployment
/// that stranded three thousand records, including every inbound message.
#[test]
fn a_reported_gap_is_resent() {
    let mut worker = worker_with(persist_123());
    let mut conn = FakeConn::script([
        // Resume acks through 1, so 2 and 3 go out.
        Scripted::ResumeAck {
            committed_through: 1,
        },
        // The peer stored 3 but never stored 2, so it can only commit through
        // 1 and reports the hole.
        Scripted::UplinkAckWithGap {
            committed_through: 1,
            gaps: vec![(2, 2)],
        },
        Scripted::Closed,
    ]);

    worker.run(&mut conn, Instant::now()).expect("run");

    let sent: Vec<u64> = conn.sequenced().iter().filter_map(|e| e.seq).collect();
    let resends = sent.iter().filter(|seq| **seq == 2).count();
    assert!(
        resends >= 2,
        "record 2 should have been sent again after the gap was reported; sent: {sent:?}",
    );
}

/// A clean ack must not rewind anything — resending what the peer already has
/// would turn a healthy link into a loop.
#[test]
fn an_ack_without_a_gap_resends_nothing() {
    let mut worker = worker_with(persist_123());
    let mut conn = FakeConn::script([
        Scripted::ResumeAck {
            committed_through: 1,
        },
        Scripted::UplinkAck {
            committed_through: 3,
            connection_id: None,
        },
        Scripted::Closed,
    ]);

    worker.run(&mut conn, Instant::now()).expect("run");

    let sent: Vec<u64> = conn.sequenced().iter().filter_map(|e| e.seq).collect();
    assert_eq!(sent, vec![2, 3], "a clean ack resent something: {sent:?}");
}
