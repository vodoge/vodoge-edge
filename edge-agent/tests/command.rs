use edge_agent::{
    CommandExecutor, FakeSendPort, RECEIPT_ACCEPTED, RECEIPT_DUPLICATE, RESULT_FAILED,
    RESULT_SUCCEEDED,
};
use edge_core::{Bearer, BearerSupport, CapabilityMatrix, CarrierProfile, ModemFamily};
use edge_uplink::RetentionClass;
use sha2::{Digest, Sha256};
use vodoge_contract::{
    Command, CommandDeliverPayload, CommandResultPayload, ContextValue, Envelope, MessageKind,
};

const CMD_ID: &str = "11111111-1111-4111-8111-111111111111";
const DELIVERY_A: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const DELIVERY_B: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

fn send_sms_payload(cmd_id: &str) -> CommandDeliverPayload {
    CommandDeliverPayload {
        cmd_id: cmd_id.into(),
        issued_at: 1_000,
        expires_at: 10_000,
        attempt: Some(1),
        command: Command::SendSms {
            to: "+15551212".into(),
            body: "hello".into(),
            modem_imei: Some("867018069509705".into()),
            iccid: None,
        },
    }
}

fn result_json(result: &CommandResultPayload) -> serde_json::Value {
    serde_json::to_value(result).expect("result json")
}

#[test]
fn first_deliver_executes_once() {
    let mut executor = CommandExecutor::new(FakeSendPort::new());
    let outcome = executor
        .deliver(DELIVERY_A, send_sms_payload(CMD_ID), 1_500)
        .expect("first deliver");

    assert_eq!(outcome.receipt.status, RECEIPT_ACCEPTED);
    assert_eq!(outcome.receipt.cmd_id, CMD_ID);
    assert_eq!(outcome.receipt.delivery_id, DELIVERY_A);
    assert_eq!(outcome.result.status, RESULT_SUCCEEDED);
    assert_eq!(outcome.result.cmd_id, CMD_ID);
    assert_eq!(outcome.result_sequence, 1);
    assert!(outcome.executed);
    assert_eq!(executor.port().sent().len(), 1);
    assert_eq!(executor.port().sent()[0].to, "+15551212");
    assert_eq!(executor.port().sent()[0].body, "hello");

    assert!(!MessageKind::CommandReceipt.is_sequenced());
    assert!(MessageKind::CommandResult.is_sequenced());
    let record = executor
        .uplink()
        .retained_record(1)
        .expect("sequenced command result");
    assert_eq!(record.retention(), RetentionClass::Protected);
    let stored: CommandResultPayload =
        serde_json::from_slice(record.payload()).expect("stored result");
    assert_eq!(result_json(&stored), result_json(&outcome.result));
}

#[test]
fn redelivery_does_not_send_sms_again() {
    let mut executor = CommandExecutor::new(FakeSendPort::new());
    let first = executor
        .deliver(DELIVERY_A, send_sms_payload(CMD_ID), 1_500)
        .expect("first deliver");
    let second = executor
        .deliver(DELIVERY_B, send_sms_payload(CMD_ID), 1_700)
        .expect("redelivery");

    assert_eq!(executor.port().sent().len(), 1);
    assert!(!second.executed);
    assert_eq!(second.receipt.status, RECEIPT_DUPLICATE);
    assert_eq!(second.receipt.delivery_id, DELIVERY_B);
    assert_eq!(second.receipt.cmd_id, first.receipt.cmd_id);
    assert_eq!(result_json(&second.result), result_json(&first.result));
    assert_eq!(second.result_sequence, first.result_sequence);
    assert_eq!(executor.uplink().retained_records().count(), 1);
}

#[test]
fn failure_still_emits_command_result() {
    let mut port = FakeSendPort::new();
    port.fail_with("send_failed", "radio off");
    let mut executor = CommandExecutor::new(port);
    let outcome = executor
        .deliver(DELIVERY_A, send_sms_payload(CMD_ID), 1_500)
        .expect("failed send still completes");

    assert_eq!(outcome.receipt.status, RECEIPT_ACCEPTED);
    assert_eq!(outcome.result.status, RESULT_FAILED);
    assert_eq!(outcome.result.reason_code.as_deref(), Some("send_failed"));
    assert_eq!(outcome.result_sequence, 1);
    assert!(outcome.executed);
    assert!(executor.port().sent().is_empty());

    let replay = executor
        .deliver(DELIVERY_B, send_sms_payload(CMD_ID), 1_800)
        .expect("failed command redelivery");
    assert_eq!(replay.receipt.status, RECEIPT_DUPLICATE);
    assert_eq!(result_json(&replay.result), result_json(&outcome.result));
    assert!(executor.port().sent().is_empty());
}

#[test]
fn envelope_deliver_uses_id_as_delivery_id() {
    let mut executor = CommandExecutor::new(FakeSendPort::new());
    let envelope = Envelope {
        v: 1,
        kind: MessageKind::CommandDeliver,
        id: DELIVERY_A.into(),
        ts: 1_500,
        device_id: "dev-1".into(),
        seq: None,
        trace_id: None,
        payload: serde_json::to_value(send_sms_payload(CMD_ID)).expect("payload"),
    };
    let outcome = executor
        .handle_envelope(&envelope, 1_500)
        .expect("envelope deliver");
    assert_eq!(outcome.receipt.delivery_id, DELIVERY_A);
    assert_eq!(outcome.result.status, RESULT_SUCCEEDED);
    assert_eq!(executor.port().sent().len(), 1);
}

fn hot_matrix_json() -> serde_json::Value {
    serde_json::json!({
        "version": "hot-1",
        "fallback": {
            "sms_mo": { "kind": "probe" },
            "sms_mt": { "kind": "probe" },
            "data": { "kind": "probe" },
            "voice": { "kind": "probe" }
        },
        "rule": [{
            "modem_family": "EC20",
            "carrier": "CN-Telecom",
            "sms_mo": { "kind": "supported", "bearer": "cellular" },
            "sms_mt": { "kind": "supported", "bearer": "cellular" }
        }]
    })
}

fn matrix_command(cmd_id: &str, version: &str, sha: &str, matrix: ContextValue) -> CommandDeliverPayload {
    CommandDeliverPayload {
        cmd_id: cmd_id.into(),
        issued_at: 1_000,
        expires_at: 10_000,
        attempt: Some(1),
        command: Command::UpdateCapabilityMatrix {
            matrix_version: version.into(),
            matrix_sha256: sha.into(),
            matrix,
        },
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn update_capability_matrix_changes_the_live_verdict() {
    let json = hot_matrix_json();
    let matrix: ContextValue = serde_json::from_value(json.clone()).expect("context");
    let sha = sha256_hex(&serde_json::to_vec(&matrix).expect("bytes"));
    let mut executor = CommandExecutor::new(FakeSendPort::new());

    let builtin = CapabilityMatrix::builtin().expect("builtin");
    let before = builtin.query(&ModemFamily::EC20, &CarrierProfile::CN_TELECOM);
    assert!(matches!(before.capability.sms_mo, BearerSupport::Unsupported { .. }));

    let outcome = executor
        .deliver(DELIVERY_A, matrix_command(CMD_ID, "hot-1", &sha, matrix), 1_500)
        .expect("install matrix");

    assert_eq!(outcome.receipt.status, RECEIPT_ACCEPTED);
    assert_eq!(outcome.result.status, RESULT_SUCCEEDED);
    assert!(outcome.executed);
    assert_eq!(executor.matrix().version(), "hot-1");
    let after = executor
        .matrix()
        .query(&ModemFamily::EC20, &CarrierProfile::CN_TELECOM);
    assert_eq!(after.capability.sms_mo, BearerSupport::Supported(Bearer::Cellular));

    let replay = executor
        .deliver(DELIVERY_B, matrix_command(CMD_ID, "hot-1", &sha, serde_json::from_value(json).unwrap()), 1_800)
        .expect("redelivery");
    assert_eq!(replay.receipt.status, RECEIPT_DUPLICATE);
    assert!(!replay.executed);
    assert_eq!(executor.matrix().version(), "hot-1");
}

#[test]
fn update_capability_matrix_rejects_a_bad_digest_without_replacing() {
    let matrix: ContextValue = serde_json::from_value(hot_matrix_json()).expect("context");
    let mut executor = CommandExecutor::new(FakeSendPort::new());
    let before = executor.matrix().version().to_string();

    let outcome = executor
        .deliver(
            DELIVERY_A,
            matrix_command(CMD_ID, "hot-1", "deadbeef", matrix),
            1_500,
        )
        .expect("bad digest still completes");

    assert_eq!(outcome.result.status, RESULT_FAILED);
    assert_eq!(
        outcome.result.reason_code.as_deref(),
        Some("matrix_sha256_mismatch")
    );
    assert!(!outcome.executed);
    assert_eq!(executor.matrix().version(), before);
}
