use edge_agent::{
    CommandExecutor, FakeSendPort, FakeUpdatePort, UpdatePort, RECEIPT_ACCEPTED, RECEIPT_DUPLICATE,
    RESULT_FAILED, RESULT_SUCCEEDED,
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

fn self_update_payload(cmd_id: &str, version: &str) -> CommandDeliverPayload {
    CommandDeliverPayload {
        cmd_id: cmd_id.into(),
        issued_at: 1_000,
        expires_at: 10_000,
        attempt: Some(1),
        command: Command::SelfUpdate {
            version: version.into(),
            url: "https://updates.vodoge.com/edge/1.1.0".into(),
            sha256: "abc".into(),
            signature: "sig".into(),
        },
    }
}

#[test]
fn self_update_rolls_back_when_resume_handshake_fails() {
    let updater = FakeUpdatePort::new("1.0.0");
    let mut executor = CommandExecutor::with_updater(FakeSendPort::new(), updater);
    let outcome = executor
        .deliver(DELIVERY_A, self_update_payload(CMD_ID, "1.1.0"), 1_500)
        .expect("stage update");

    assert_eq!(outcome.result.status, RESULT_SUCCEEDED);
    assert_eq!(executor.running_version(), "1.1.0");
    assert_eq!(executor.updater().staged().len(), 1);
    assert_eq!(executor.updater().staged()[0].version, "1.1.0");

    let restored = executor
        .confirm_handshake(false)
        .expect("rollback after failed resume");
    assert_eq!(restored.as_deref(), Some("1.0.0"));
    assert_eq!(executor.running_version(), "1.0.0");
    assert_eq!(executor.updater().current(), "1.0.0");
    assert_eq!(executor.updater().restored(), &["1.0.0".to_string()]);
}

#[test]
fn self_update_keeps_the_new_binary_after_resume() {
    let mut executor =
        CommandExecutor::with_updater(FakeSendPort::new(), FakeUpdatePort::new("1.0.0"));
    executor
        .deliver(DELIVERY_A, self_update_payload(CMD_ID, "1.1.0"), 1_500)
        .expect("stage update");
    assert!(executor.confirm_handshake(true).expect("handshake").is_none());
    assert_eq!(executor.running_version(), "1.1.0");
    assert!(executor.updater().restored().is_empty());
}

/// A port that records which relay method was called and answers with a value
/// the assertion can recognise. It exists to prove routing, not behaviour: the
/// real implementations live in edge-bin, behind hardware.
#[derive(Default)]
struct RecordingPort {
    calls: Vec<String>,
}

impl edge_agent::SendPort for RecordingPort {
    fn send_sms(&mut self, _send: &edge_agent::SmsSend) -> Result<(), edge_agent::SendError> {
        self.calls.push("send_sms".into());
        Ok(())
    }

    fn run_at(
        &mut self,
        imei: &str,
        command: &str,
        timeout_ms: Option<i64>,
    ) -> Result<serde_json::Value, edge_agent::SendError> {
        self.calls.push(format!("run_at {imei} {command} {timeout_ms:?}"));
        Ok(serde_json::json!({"lines": ["+CSQ: 24,99"], "ok": true}))
    }

    fn send_ussd(
        &mut self,
        _imei: &str,
        code: &str,
        stage: &str,
    ) -> Result<serde_json::Value, edge_agent::SendError> {
        self.calls.push(format!("send_ussd {code} {stage}"));
        Ok(serde_json::json!({"text": "余额 12.34 元"}))
    }

    fn set_radio(&mut self, _imei: &str, enabled: bool) -> Result<(), edge_agent::SendError> {
        self.calls.push(format!("set_radio {enabled}"));
        Ok(())
    }

    fn scan_operators(&mut self, _imei: &str) -> Result<serde_json::Value, edge_agent::SendError> {
        self.calls.push("scan_operators".into());
        Ok(serde_json::json!({"operators": []}))
    }

    fn select_operator(
        &mut self,
        _imei: &str,
        mode: &str,
        plmn: Option<&str>,
    ) -> Result<serde_json::Value, edge_agent::SendError> {
        self.calls.push(format!("select_operator {mode} {plmn:?}"));
        Ok(serde_json::Value::Null)
    }

    fn modem_report(&mut self, _imei: &str) -> Result<serde_json::Value, edge_agent::SendError> {
        self.calls.push("modem_report".into());
        Ok(serde_json::json!({"signal": {"dbm": -51}}))
    }

    fn reset_usb(&mut self, _imei: &str) -> Result<serde_json::Value, edge_agent::SendError> {
        self.calls.push("reset_usb".into());
        Ok(serde_json::Value::Null)
    }

    fn list_esim_profiles(
        &mut self,
        _imei: &str,
    ) -> Result<serde_json::Value, edge_agent::SendError> {
        self.calls.push("list_esim_profiles".into());
        Ok(serde_json::json!({"profiles": []}))
    }

    fn switch_esim_profile(
        &mut self,
        _imei: &str,
        target: &str,
    ) -> Result<serde_json::Value, edge_agent::SendError> {
        self.calls.push(format!("switch_esim_profile {target}"));
        Ok(serde_json::Value::Null)
    }
}

fn deliver(command: Command, port: RecordingPort) -> (CommandResultPayload, Vec<String>) {
    let mut executor = CommandExecutor::new(port);
    let outcome = executor
        .deliver(
            DELIVERY_A,
            CommandDeliverPayload {
                cmd_id: CMD_ID.into(),
                issued_at: 1_000,
                expires_at: 10_000,
                attempt: Some(1),
                command,
            },
            1_500,
        )
        .expect("deliver");
    let calls = executor.port().calls.clone();
    (outcome.result, calls)
}

const IMEI: &str = "867018069514820";

/// Every relayed command must reach its port method. Before the relay existed
/// they all fell through to the catch-all and reported `unsupported_command`,
/// which is exactly what this would catch if a variant were ever dropped from
/// the match.
#[test]
fn every_relayed_command_reaches_the_port() {
    let cases: Vec<(Command, &str)> = vec![
        (
            Command::RunAtCommand {
                modem_imei: IMEI.into(),
                command: "AT+CSQ".into(),
                timeout_ms: None,
            },
            "run_at 867018069514820 AT+CSQ None",
        ),
        (
            Command::SendUssd {
                modem_imei: IMEI.into(),
                code: "*101#".into(),
                stage: None,
            },
            "send_ussd *101# start",
        ),
        (
            Command::SetRadio {
                modem_imei: IMEI.into(),
                enabled: false,
            },
            "set_radio false",
        ),
        (
            Command::ScanOperators {
                modem_imei: IMEI.into(),
            },
            "scan_operators",
        ),
        (
            Command::SelectOperator {
                modem_imei: IMEI.into(),
                mode: "manual".into(),
                plmn: Some("460-01".into()),
            },
            "select_operator manual Some(\"460-01\")",
        ),
        (
            Command::ModemReport {
                modem_imei: IMEI.into(),
            },
            "modem_report",
        ),
        (
            Command::ResetModemUsb {
                modem_imei: IMEI.into(),
            },
            "reset_usb",
        ),
        (
            Command::ListEsimProfiles {
                modem_imei: IMEI.into(),
            },
            "list_esim_profiles",
        ),
        (
            Command::SwitchEsimProfile {
                modem_imei: IMEI.into(),
                target_iccid: "89852351225042214201".into(),
            },
            "switch_esim_profile 89852351225042214201",
        ),
    ];

    for (command, expected_call) in cases {
        let (result, calls) = deliver(command, RecordingPort::default());
        assert_eq!(
            result.status, RESULT_SUCCEEDED,
            "{expected_call} produced {:?}",
            result.reason
        );
        assert_eq!(calls, vec![expected_call.to_string()]);
    }
}

/// A diagnostic is only useful if what it read comes back with it.
#[test]
fn a_reading_travels_in_the_result_details() {
    let (result, _) = deliver(
        Command::RunAtCommand {
            modem_imei: IMEI.into(),
            command: "AT+CSQ".into(),
            timeout_ms: Some(5_000),
        },
        RecordingPort::default(),
    );

    let details = result_json(&result);
    assert_eq!(details["details"]["lines"][0], "+CSQ: 24,99");
    assert_eq!(details["details"]["ok"], true);
}

/// An action with nothing to report must not invent an empty object: `details`
/// is absent, which is what "there was no reading" looks like on the wire.
#[test]
fn an_action_with_no_reading_sends_no_details() {
    let (result, _) = deliver(
        Command::SetRadio {
            modem_imei: IMEI.into(),
            enabled: true,
        },
        RecordingPort::default(),
    );

    assert!(result.details.is_none());
    let encoded = result_json(&result);
    assert!(
        encoded.get("details").is_none(),
        "details should not be serialised at all, got {encoded}",
    );
}

/// A port that cannot perform an action reports a failure the console can
/// read, rather than a success that did nothing.
#[test]
fn an_unimplemented_action_fails_with_its_name() {
    struct BarePort;
    impl edge_agent::SendPort for BarePort {
        fn send_sms(&mut self, _send: &edge_agent::SmsSend) -> Result<(), edge_agent::SendError> {
            Ok(())
        }
    }

    let mut executor = CommandExecutor::new(BarePort);
    let outcome = executor
        .deliver(
            DELIVERY_A,
            CommandDeliverPayload {
                cmd_id: CMD_ID.into(),
                issued_at: 1_000,
                expires_at: 10_000,
                attempt: Some(1),
                command: Command::ScanOperators {
                    modem_imei: IMEI.into(),
                },
            },
            1_500,
        )
        .expect("deliver");

    assert_eq!(outcome.result.status, RESULT_FAILED);
    assert_eq!(outcome.result.reason_code.as_deref(), Some("unsupported_command"));
    assert!(
        outcome
            .result
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("scan_operators"),
        "the reason must name the action: {:?}",
        outcome.result.reason,
    );
}
