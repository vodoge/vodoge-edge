use std::time::{Duration, Instant};

use edge_uplink::codec::{decode_json, encode_json};
use edge_uplink::session::{
    Inbound, LinkConfig, LinkSession, Phase, ResumeSnapshot, INITIAL_BACKOFF, MAX_BACKOFF,
    PING_INTERVAL,
};
use vodoge_contract::{Envelope, MessageKind, PongPayload, ResumeAckPayload, UplinkAckPayload};

fn snapshot() -> ResumeSnapshot {
    ResumeSnapshot {
        last_assigned_seq: 5,
        last_acked_seq: 2,
        lowest_retained_seq: None,
        pending_gap_ids: Vec::new(),
        capability_matrix_version: "1".into(),
        edge_version: Some("0.1.0".into()),
        queue_records: None,
        queue_bytes: None,
    }
}

fn session() -> LinkSession {
    LinkSession::new(LinkConfig::new("dev-1", snapshot()).expect("config"))
}

fn live(now: Instant) -> (LinkSession, Instant) {
    let mut session = session();
    session.handshake("conn-1", now).expect("resume");
    let ack = resume_ack("conn-1", 2);
    session.on_inbound(ack, now).expect("resume ack");
    (session, now)
}

fn resume_ack(connection_id: &str, committed_through: u64) -> Envelope {
    Envelope {
        v: 1,
        kind: MessageKind::ResumeAck,
        id: "ack".into(),
        ts: 1,
        device_id: "dev-1".into(),
        seq: None,
        trace_id: None,
        payload: serde_json::to_value(ResumeAckPayload {
            connection_id: connection_id.into(),
            committed_through,
            missing_ranges: Vec::new(),
            more_missing: false,
            max_in_flight: 32,
            server_time: 1,
        })
        .unwrap(),
    }
}

#[test]
fn handshake_emits_resume_before_any_heartbeat() {
    let mut session = session();
    let now = Instant::now();
    let resume = session.handshake("conn-1", now).expect("resume");
    assert_eq!(resume.kind, MessageKind::Resume);
    assert_eq!(resume.device_id, "dev-1");
    assert_eq!(session.phase(), Phase::Resuming);
    assert!(session.poll(now + PING_INTERVAL).is_none());

    let bytes = encode_json(&resume).expect("encode");
    let decoded = decode_json(&bytes).expect("decode");
    assert_eq!(decoded.kind, MessageKind::Resume);
    let payload: vodoge_contract::ResumePayload =
        serde_json::from_value(decoded.payload).expect("payload");
    assert_eq!(payload.connection_id, "conn-1");
    assert_eq!(payload.last_assigned_seq, 5);
    assert_eq!(payload.last_acked_seq, 2);
}

#[test]
fn resume_ack_starts_heartbeat_and_resets_backoff() {
    let now = Instant::now();
    let (mut session, now) = live(now);
    assert_eq!(session.phase(), Phase::Live);
    assert_eq!(session.committed_through(), Some(2));
    assert!(session.poll(now + Duration::from_secs(29)).is_none());

    let ping = session.poll(now + PING_INTERVAL).expect("ping");
    assert_eq!(ping.kind, MessageKind::Ping);
    assert!(session.poll(now + PING_INTERVAL).is_none());

    session.on_disconnect(now + Duration::from_secs(40));
    assert_eq!(session.phase(), Phase::Backoff);
    assert_eq!(session.reconnect_delay(), INITIAL_BACKOFF * 2);

    let resume = session
        .handshake("conn-2", now + Duration::from_secs(41))
        .expect("reconnect resume");
    assert_eq!(resume.kind, MessageKind::Resume);
    session
        .on_inbound(
            resume_ack("conn-2", 2),
            now + Duration::from_secs(41),
        )
        .expect("second resume ack");
    session.on_disconnect(now + Duration::from_secs(42));
    assert_eq!(session.reconnect_delay(), INITIAL_BACKOFF * 2);
}

#[test]
fn reconnect_backoff_doubles_until_the_cap() {
    let mut session = session();
    let now = Instant::now();
    for attempt in 0..8 {
        session.handshake(format!("conn-{attempt}"), now).unwrap();
        session.on_disconnect(now);
    }
    assert_eq!(session.reconnect_delay(), MAX_BACKOFF);
}

#[test]
fn stale_uplink_ack_is_ignored() {
    let now = Instant::now();
    let (mut session, now) = live(now);
    let stale = Envelope {
        v: 1,
        kind: MessageKind::UplinkAck,
        id: "stale".into(),
        ts: 2,
        device_id: "dev-1".into(),
        seq: None,
        trace_id: None,
        payload: serde_json::to_value(UplinkAckPayload {
            connection_id: "old-conn".into(),
            committed_through: 99,
            missing_ranges: Vec::new(),
            more_missing: false,
            max_in_flight: 32,
        })
        .unwrap(),
    };
    let outcome = session.on_inbound(stale, now).expect("stale");
    assert!(matches!(outcome, Inbound::IgnoredStale));
    assert_eq!(session.committed_through(), Some(2));

    let live_ack = Envelope {
        v: 1,
        kind: MessageKind::UplinkAck,
        id: "live".into(),
        ts: 3,
        device_id: "dev-1".into(),
        seq: None,
        trace_id: None,
        payload: serde_json::to_value(UplinkAckPayload {
            connection_id: "conn-1".into(),
            committed_through: 5,
            missing_ranges: Vec::new(),
            more_missing: false,
            max_in_flight: 32,
        })
        .unwrap(),
    };
    match session.on_inbound(live_ack, now).expect("live ack") {
        Inbound::UplinkAck(ack) => assert_eq!(ack.committed_through, 5),
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(session.committed_through(), Some(5));
}

#[test]
fn pong_keeps_the_session_live_and_idle_timeout_drops_it() {
    let now = Instant::now();
    let (mut session, now) = live(now);
    let pong = Envelope {
        v: 1,
        kind: MessageKind::Pong,
        id: "pong".into(),
        ts: 4,
        device_id: "dev-1".into(),
        seq: None,
        trace_id: None,
        payload: serde_json::to_value(PongPayload {
            connection_id: "conn-1".into(),
            ping_id: "ping".into(),
            server_time: 4,
        })
        .unwrap(),
    };
    let later = now + Duration::from_secs(1);
    assert!(matches!(
        session.on_inbound(pong, later),
        Ok(Inbound::Pong(_))
    ));
    assert_eq!(session.phase(), Phase::Live);
    assert!(session.poll(later + Duration::from_secs(90)).is_none());
    assert_eq!(session.phase(), Phase::Backoff);
}
