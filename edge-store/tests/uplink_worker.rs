use std::collections::VecDeque;
use std::time::Instant;

use edge_store::DurableOutbox;
use edge_uplink::codec::{decode_json, encode_json};
use edge_uplink::dial::{DialError, FrameConn};
use edge_uplink::session::{LinkConfig, ResumeSnapshot};
use edge_uplink::worker::{Outbox, UplinkWorker};
use edge_uplink::{EnvelopeId, RetentionClass};
use vodoge_contract::{
    Envelope, MessageKind, ResumeAckPayload, ResumePayload, UplinkAckPayload,
};

#[derive(Clone)]
enum Scripted {
    ResumeAck { committed_through: u64 },
    UplinkAck { committed_through: u64 },
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

    fn last_resume(&self) -> (String, ResumePayload) {
        let resume = self
            .outbound
            .iter()
            .rev()
            .find(|envelope| envelope.kind == MessageKind::Resume)
            .expect("resume sent");
        let payload = serde_json::from_value(resume.payload.clone()).expect("resume payload");
        (resume.device_id.clone(), payload)
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
                let (device_id, resume) = self.last_resume();
                Ok(Envelope {
                    v: 1,
                    kind: MessageKind::ResumeAck,
                    id: "resume-ack".into(),
                    ts: 1,
                    device_id,
                    seq: None,
                    trace_id: None,
                    payload: serde_json::to_value(ResumeAckPayload {
                        connection_id: resume.connection_id,
                        committed_through,
                        missing_ranges: Vec::new(),
                        more_missing: false,
                        max_in_flight: 32,
                        server_time: 1,
                    })
                    .unwrap(),
                })
            }
            Scripted::UplinkAck { committed_through } => {
                let (device_id, resume) = self.last_resume();
                Ok(Envelope {
                    v: 1,
                    kind: MessageKind::UplinkAck,
                    id: format!("ack-{committed_through}"),
                    ts: 2,
                    device_id,
                    seq: None,
                    trace_id: None,
                    payload: serde_json::to_value(UplinkAckPayload {
                        connection_id: resume.connection_id,
                        committed_through,
                        missing_ranges: Vec::new(),
                        more_missing: false,
                        max_in_flight: 32,
                    })
                    .unwrap(),
                })
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
        edge_version: None,
        queue_records: None,
        queue_bytes: None,
    }
}

#[test]
fn sqlite_outbox_replays_after_resume_ack_and_duplicate_ack_is_noop() {
    let mut outbox = DurableOutbox::open_in_memory().expect("outbox");
    for (id, n) in [("env-1", 1u64), ("env-2", 2), ("env-3", 3)] {
        let payload = serde_json::to_vec(&serde_json::json!({ "n": n })).unwrap();
        outbox
            .append(
                EnvelopeId::new(id).expect("id"),
                "SmsReceived",
                payload,
                RetentionClass::Protected,
            )
            .expect("append");
    }
    assert_eq!(outbox.committed_through(), 0);
    assert_eq!(outbox.last_allocated(), 3);

    let config = LinkConfig::new("dev-1", snapshot()).expect("config");
    let mut worker = UplinkWorker::new(config, outbox);
    let mut conn = FakeConn::script([
        Scripted::ResumeAck {
            committed_through: 1,
        },
        Scripted::UplinkAck {
            committed_through: 3,
        },
        Scripted::UplinkAck {
            committed_through: 3,
        },
        Scripted::Closed,
    ]);

    worker.run(&mut conn, Instant::now()).expect("run");

    let sequenced: Vec<_> = conn
        .outbound
        .iter()
        .filter(|envelope| envelope.seq.is_some())
        .collect();
    assert_eq!(sequenced.len(), 2);
    assert_eq!(sequenced[0].seq, Some(2));
    assert_eq!(sequenced[0].id, "env-2");
    assert_eq!(sequenced[1].seq, Some(3));
    assert_eq!(sequenced[1].id, "env-3");
    assert_eq!(Outbox::committed_through(worker.outbox()), 3);
    assert!(Outbox::retained(worker.outbox()).expect("retained").is_empty());
}
