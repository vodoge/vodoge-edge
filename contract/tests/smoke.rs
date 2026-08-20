use vodoge_contract::{Envelope, MessageKind, PROTOCOL_VERSION, SCHEMA_ID, WS_SUBPROTOCOL};

#[test]
fn generated_constants_match_schema() {
    assert_eq!(PROTOCOL_VERSION, 1);
    assert!(SCHEMA_ID.contains("edge-cloud"));
    assert_eq!(WS_SUBPROTOCOL, "vodoge.edge.v1");
    assert!(MessageKind::SmsReceived.is_sequenced());
    assert!(!MessageKind::Resume.is_sequenced());
}

#[test]
fn sequenced_envelope_requires_seq() {
    let envelope: Envelope = serde_json::from_str(
        r#"{
            "v": 1,
            "kind": "Resume",
            "id": "11111111-1111-1111-1111-111111111111",
            "ts": 1,
            "device_id": "22222222-2222-2222-2222-222222222222",
            "payload": {"connection_id": "33333333-3333-3333-3333-333333333333"}
        }"#,
    )
    .expect("resume envelope deserializes");
    envelope.validate_sequence().expect("resume has no seq");

    let sms: Envelope = serde_json::from_str(
        r#"{
            "v": 1,
            "kind": "SmsReceived",
            "id": "11111111-1111-1111-1111-111111111111",
            "ts": 1,
            "device_id": "22222222-2222-2222-2222-222222222222",
            "seq": "7",
            "payload": {}
        }"#,
    )
    .expect("sms envelope deserializes");
    sms.validate_sequence().expect("sms seq is present");
    assert_eq!(sms.seq, Some(7));
}
