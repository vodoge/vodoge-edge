use edge_store::DurableOutbox;
use edge_uplink::{EnvelopeId, RetentionClass, UplinkAck};

fn envelope(name: &str) -> EnvelopeId {
    EnvelopeId::new(name).expect("id")
}

fn ack(through: u64) -> UplinkAck {
    UplinkAck::new(through, Vec::new(), false).expect("ack")
}

#[test]
fn survives_reopen_without_losing_unacked_records() {
    let path = std::env::temp_dir().join(format!(
        "vodoge-outbox-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    ));
    let _ = std::fs::remove_file(&path);

    {
        let mut outbox = DurableOutbox::open(&path, 100).expect("open");
        outbox
            .append(envelope("sms-1"), "SmsReceived", b"one", RetentionClass::Protected)
            .expect("append 1");
        outbox
            .append(envelope("sms-2"), "SmsReceived", b"two", RetentionClass::Evictable)
            .expect("append 2");
        outbox.observe_ack(ack(1)).expect("ack first");
        assert_eq!(outbox.committed_through(), 1);
        assert_eq!(outbox.retained_count(), 1);
    }

    let reopened = DurableOutbox::open(&path, 100).expect("reopen");
    assert_eq!(reopened.committed_through(), 1);
    assert_eq!(reopened.last_allocated(), 2);
    let replay = reopened.replay();
    assert_eq!(replay.len(), 1);
    assert_eq!(replay[0].0, 2);
    assert_eq!(replay[0].2, b"two");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn capacity_eviction_alerts_instead_of_silent_drop() {
    let mut outbox = DurableOutbox::from_store(
        edge_store::Store::open_in_memory().expect("mem"),
        2,
    )
    .expect("outbox");
    outbox
        .append(envelope("a"), "SmsReceived", b"a", RetentionClass::Evictable)
        .expect("a");
    outbox
        .append(envelope("b"), "SmsReceived", b"b", RetentionClass::Evictable)
        .expect("b");
    let (seq, alert) = outbox
        .append(envelope("c"), "SmsReceived", b"c", RetentionClass::Evictable)
        .expect("c");
    assert_eq!(seq, 3);
    let alert = alert.expect("capacity alert");
    assert_eq!(alert.evicted_seq, 1);
    assert_eq!(outbox.retained_count(), 2);
    let sequences: Vec<u64> = outbox.replay().into_iter().map(|row| row.0).collect();
    assert_eq!(sequences, vec![2, 3]);
}

#[test]
fn protected_records_are_not_evicted() {
    let mut outbox = DurableOutbox::from_store(
        edge_store::Store::open_in_memory().expect("mem"),
        1,
    )
    .expect("outbox");
    outbox
        .append(
            envelope("result"),
            "CommandResult",
            b"ok",
            RetentionClass::Protected,
        )
        .expect("protected");
    let (_, alert) = outbox
        .append(envelope("sms"), "SmsReceived", b"x", RetentionClass::Evictable)
        .expect("second");
    assert!(alert.is_some());
    let kinds: Vec<u64> = outbox.replay().into_iter().map(|row| row.0).collect();
    assert!(kinds.contains(&1), "protected seq 1 must remain");
}
