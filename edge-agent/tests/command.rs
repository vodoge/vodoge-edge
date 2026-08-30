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
    fn send_sms(
        &mut self,
        _send: &edge_agent::SmsSend,
    ) -> Result<serde_json::Value, edge_agent::SendError> {
        self.calls.push("send_sms".into());
        Ok(serde_json::Value::Null)
    }

    fn run_at(
        &mut self,
        imei: &str,
        command: &str,
        timeout_ms: Option<i64>,
        force: bool,
    ) -> Result<serde_json::Value, edge_agent::SendError> {
        self.calls
            .push(format!("run_at {imei} {command} {timeout_ms:?} force={force}"));
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

    fn set_data_network(
        &mut self,
        _imei: &str,
        enabled: bool,
    ) -> Result<serde_json::Value, edge_agent::SendError> {
        self.calls.push(format!("set_data_network {enabled}"));
        Ok(serde_json::Value::Null)
    }

    fn set_usbnet_mode(
        &mut self,
        _imei: &str,
        mode: &str,
    ) -> Result<serde_json::Value, edge_agent::SendError> {
        self.calls.push(format!("set_usbnet_mode {mode}"));
        Ok(serde_json::Value::Null)
    }

    fn reregister_network(
        &mut self,
        _imei: &str,
    ) -> Result<serde_json::Value, edge_agent::SendError> {
        self.calls.push("reregister_network".into());
        Ok(serde_json::Value::Null)
    }

    fn refresh_modems(&mut self) -> Result<serde_json::Value, edge_agent::SendError> {
        self.calls.push("refresh_modems".into());
        Ok(serde_json::Value::Null)
    }

    fn update_card_policies(
        &mut self,
        policy_version: &str,
        policies: &[vodoge_contract::CardPolicy],
    ) -> Result<serde_json::Value, edge_agent::SendError> {
        self.calls.push(format!(
            "update_card_policies {policy_version} {}",
            policies
                .iter()
                .map(|policy| format!("{}:{}", policy.iccid, policy.vertical))
                .collect::<Vec<_>>()
                .join(",")
        ));
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

    fn read_esim_info(
        &mut self,
        _imei: &str,
    ) -> Result<serde_json::Value, edge_agent::SendError> {
        self.calls.push("read_esim_info".into());
        Ok(serde_json::json!({"eid": "89086030202200000026000178339240"}))
    }

    fn retrieve_esim_notification(
        &mut self,
        _imei: &str,
        sequence_number: i64,
    ) -> Result<serde_json::Value, edge_agent::SendError> {
        self.calls.push(format!("retrieve_esim_notification {sequence_number}"));
        Ok(serde_json::json!({"delivered": false}))
    }

    fn initiate_esim_authentication(
        &mut self,
        _imei: &str,
        smdp_address: Option<&str>,
    ) -> Result<serde_json::Value, edge_agent::SendError> {
        self.calls.push(format!(
            "initiate_esim_authentication {}",
            smdp_address.unwrap_or("from-chip")
        ));
        Ok(serde_json::json!({"transaction_id": "E4F6996D64A543FC8A7F6F8F97F9428D"}))
    }

    fn download_esim_profile(
        &mut self,
        _imei: &str,
        activation_code: &str,
        confirmation_code: Option<&str>,
    ) -> Result<serde_json::Value, edge_agent::SendError> {
        // The activation code is recorded here, and only here, because this
        // is a fake whose whole job is to prove the field arrived. Nothing on
        // the real path puts it anywhere.
        self.calls.push(format!(
            "download_esim_profile {activation_code} cc={}",
            confirmation_code.unwrap_or("none")
        ));
        Ok(serde_json::json!({"installed": true, "enabled": false}))
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

/// Every relayed command must reach its port method.
///
/// Dropping a variant from the match is now a build error -- the catch-all
/// that used to answer `unsupported_command` is gone, having existed at the
/// end only for `update_card_policy`, which had no arm. What the compiler
/// still cannot see is an arm wired to the wrong port method, or to none,
/// which is what these assertions are for.
#[test]
fn every_relayed_command_reaches_the_port() {
    let cases: Vec<(Command, &str)> = vec![
        (
            Command::RunAtCommand {
                modem_imei: IMEI.into(),
                command: "AT+CSQ".into(),
                timeout_ms: None,
                force: false,
            },
            "run_at 867018069514820 AT+CSQ None force=false",
        ),
        (
            // The flag has to reach the port: it is what the port consults
            // before sending a command its classifier holds back.
            Command::RunAtCommand {
                modem_imei: IMEI.into(),
                command: "AT+CFUN=0".into(),
                timeout_ms: None,
                force: true,
            },
            "run_at 867018069514820 AT+CFUN=0 None force=true",
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
            Command::SetDataNetwork {
                modem_imei: IMEI.into(),
                enabled: false,
            },
            "set_data_network false",
        ),
        (
            Command::SetUsbnetMode {
                modem_imei: IMEI.into(),
                mode: "ecm".into(),
            },
            "set_usbnet_mode ecm",
        ),
        (
            Command::ReregisterNetwork {
                modem_imei: IMEI.into(),
            },
            "reregister_network",
        ),
        (Command::RefreshModems, "refresh_modems"),
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
        (
            Command::ReadEsimInfo {
                modem_imei: IMEI.into(),
            },
            "read_esim_info",
        ),
        (
            Command::RetrieveEsimNotification {
                modem_imei: IMEI.into(),
                sequence_number: 3,
            },
            "retrieve_esim_notification 3",
        ),
        (
            // No address supplied, so the chip is asked where to go. That is
            // the normal case: the bench eUICCs have no default SM-DP+ and
            // the address comes off their pending notifications.
            Command::InitiateEsimAuthentication {
                modem_imei: IMEI.into(),
                smdp_address: None,
            },
            "initiate_esim_authentication from-chip",
        ),
        (
            Command::InitiateEsimAuthentication {
                modem_imei: IMEI.into(),
                smdp_address: Some("wbg.prod.ondemandconnectivity.com".into()),
            },
            "initiate_esim_authentication wbg.prod.ondemandconnectivity.com",
        ),
        (
            Command::DownloadEsimProfile {
                modem_imei: IMEI.into(),
                activation_code: "LPA:1$smdp.example.com$AAAA-BBBB".into(),
                confirmation_code: None,
            },
            "download_esim_profile LPA:1$smdp.example.com$AAAA-BBBB cc=none",
        ),
        (
            // The one kind that had no arm at all: the cloud's push came back
            // `unsupported_command` while the console showed the policy as
            // saved. It addresses cards rather than a modem, so it carries no
            // IMEI and every device gets the tenant's whole set.
            Command::UpdateCardPolicy {
                policy_version: "2026-08-28T00:00:00Z".into(),
                policies: vec![vodoge_contract::CardPolicy {
                    iccid: "8985235122504221420".into(),
                    cellular_enabled: true,
                    vertical: "cn".into(),
                    apn: Some("cmnet".into()),
                    capability: None,
                }],
            },
            "update_card_policies 2026-08-28T00:00:00Z 8985235122504221420:cn",
        ),
        (
            Command::DownloadEsimProfile {
                modem_imei: IMEI.into(),
                activation_code: "1$smdp.example.com$AAAA-BBBB".into(),
                confirmation_code: Some("13572468".into()),
            },
            "download_esim_profile 1$smdp.example.com$AAAA-BBBB cc=13572468",
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
            force: false,
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
        fn send_sms(
            &mut self,
            _send: &edge_agent::SmsSend,
        ) -> Result<serde_json::Value, edge_agent::SendError> {
            Ok(serde_json::Value::Null)
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

/// Downloading a profile installs it and leaves it disabled, and the result
/// has to say both. "Installed" on its own reads as "in use", and on a module
/// whose one working profile is carrying traffic that is the difference
/// between a spare and an outage.
#[test]
fn a_downloaded_profile_reports_that_it_was_not_enabled() {
    let (result, _) = deliver(
        Command::DownloadEsimProfile {
            modem_imei: IMEI.into(),
            activation_code: "LPA:1$smdp.example.com$AAAA-BBBB".into(),
            confirmation_code: None,
        },
        RecordingPort::default(),
    );
    let details = result_json(&result);
    assert_eq!(details["details"]["installed"], true);
    assert_eq!(details["details"]["enabled"], false);
}

/// A menu selection has to reach the port still labelled `continue`.
///
/// This is the top of the chain the edge half of multi-level USSD hangs from:
/// the console sends `stage: "continue"`, and the port uses that one word to
/// decide whether the request may release the session it is answering. If the
/// relay ever flattened an explicit stage back to the default the way an
/// absent one is flattened, the module would be sent `AT+CUSD=2` and then a
/// fresh, chargeable request for a USSD code named `2`, and nothing further
/// down could tell that had happened.
#[test]
fn an_explicit_ussd_stage_reaches_the_port_unflattened() {
    for stage in ["start", "continue", "cancel"] {
        let (_, calls) = deliver(
            Command::SendUssd {
                modem_imei: IMEI.into(),
                code: "2".into(),
                stage: Some(stage.into()),
            },
            RecordingPort::default(),
        );
        assert_eq!(calls, vec![format!("send_ussd 2 {stage}")]);
    }
}

/// The bench eUICC in `867018069514820`, read on 2026-08-25 (T089).
const EID: &str = "89086030202200000026000178339240";
/// WEBBING, the profile that is enabled on it. Twenty digits.
const WEBBING_ICCID: &str = "89852351225042214201";
/// The US profile T031 switched to and back from. Nineteen digits, which is
/// the other end of the range the cloud accepts.
const US_ICCID: &str = "8901240527197122156";

/// A port whose eSIM commands answer with whatever a test hands it.
struct EsimPort {
    details: serde_json::Value,
    fails: bool,
}

impl EsimPort {
    fn answering(details: serde_json::Value) -> Self {
        Self {
            details,
            fails: false,
        }
    }

    fn failing() -> Self {
        Self {
            details: serde_json::Value::Null,
            fails: true,
        }
    }

    fn answer(&self) -> Result<serde_json::Value, edge_agent::SendError> {
        if self.fails {
            return Err(edge_agent::SendError::new(
                "esim_info_failed",
                "open ISD-R channel: no such applet",
            ));
        }
        Ok(self.details.clone())
    }
}

impl edge_agent::SendPort for EsimPort {
    fn send_sms(
        &mut self,
        _send: &edge_agent::SmsSend,
    ) -> Result<serde_json::Value, edge_agent::SendError> {
        Ok(serde_json::Value::Null)
    }

    fn read_esim_info(
        &mut self,
        _imei: &str,
    ) -> Result<serde_json::Value, edge_agent::SendError> {
        self.answer()
    }

    fn switch_esim_profile(
        &mut self,
        _imei: &str,
        _target: &str,
    ) -> Result<serde_json::Value, edge_agent::SendError> {
        self.answer()
    }

    fn modem_report(&mut self, _imei: &str) -> Result<serde_json::Value, edge_agent::SendError> {
        self.answer()
    }
}

fn inventory_details(profiles: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "imei": IMEI,
        "eid": EID,
        "inventory": {
            "modem_imei": IMEI,
            "eid": EID,
            "collected_at": 1_756_000_000_000_i64,
            "profiles": profiles,
        },
    })
}

fn bench_profiles() -> serde_json::Value {
    serde_json::json!([
        {"iccid": WEBBING_ICCID, "state": "enabled", "nickname": "WEBBING"},
        {"iccid": US_ICCID, "state": "disabled"},
    ])
}

fn deliver_esim(command: Command, port: EsimPort) -> edge_agent::DeliveryOutcome {
    let mut executor = CommandExecutor::new(port);
    executor
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
        .expect("deliver")
}

fn read_chip() -> Command {
    Command::ReadEsimInfo {
        modem_imei: IMEI.into(),
    }
}

fn switch_chip() -> Command {
    Command::SwitchEsimProfile {
        modem_imei: IMEI.into(),
        target_iccid: US_ICCID.into(),
    }
}

/// The whole point of the card: a chip read has to leave the command with an
/// inventory the cloud can project, not just a reading the console can draw.
#[test]
fn a_chip_read_carries_its_inventory_out_of_the_command() {
    let outcome = deliver_esim(
        read_chip(),
        EsimPort::answering(inventory_details(bench_profiles())),
    );

    assert_eq!(outcome.result.status, RESULT_SUCCEEDED);
    let inventory = outcome
        .inventory
        .expect("read_esim_info produces an inventory");
    assert_eq!(inventory.eid, EID);
    assert_eq!(inventory.modem_imei, IMEI);
    assert_eq!(inventory.profiles.len(), 2);
    assert_eq!(inventory.profiles[0].iccid, WEBBING_ICCID);
    assert_eq!(inventory.profiles[0].state, "enabled");
    assert_eq!(inventory.profiles[0].nickname.as_deref(), Some("WEBBING"));
    assert_eq!(inventory.profiles[1].state, "disabled");
    assert!(inventory.profiles[1].nickname.is_none());
    assert!(MessageKind::EsimInventory.is_sequenced());
}

/// A switch is the only thing that changes which ICCID is enabled, so it is
/// the one other moment an inventory may be produced. Without it the stored
/// inventory would contradict the card from the moment an operator acted.
#[test]
fn a_switch_carries_the_chip_it_read_back() {
    let outcome = deliver_esim(
        switch_chip(),
        EsimPort::answering(inventory_details(serde_json::json!([
            {"iccid": WEBBING_ICCID, "state": "disabled"},
            {"iccid": US_ICCID, "state": "enabled"}
        ]))),
    );

    let inventory = outcome
        .inventory
        .expect("a switch reports the chip it left");
    assert_eq!(inventory.profiles[0].state, "disabled");
    assert_eq!(inventory.profiles[1].state, "enabled");
}

/// Redelivery must not produce a second envelope. It carries its own sequence
/// number and its own envelope id, so a replay would spend a sequence to
/// project rows that are already there.
#[test]
fn a_replayed_delivery_does_not_send_the_inventory_again() {
    let mut executor =
        CommandExecutor::new(EsimPort::answering(inventory_details(bench_profiles())));
    let payload = CommandDeliverPayload {
        cmd_id: CMD_ID.into(),
        issued_at: 1_000,
        expires_at: 10_000,
        attempt: Some(1),
        command: read_chip(),
    };

    let first = executor
        .deliver(DELIVERY_A, payload.clone(), 1_500)
        .expect("first");
    let second = executor
        .deliver(DELIVERY_B, payload, 1_600)
        .expect("replay");

    assert!(first.inventory.is_some());
    assert!(first.executed);
    assert!(!second.executed);
    assert!(
        second.inventory.is_none(),
        "a replay must not resend the inventory",
    );
}

/// Only two commands may produce one. Any other command carrying a key of the
/// same name is a coincidence, not an inventory, and treating it as one would
/// let an unrelated diagnostic write to the eSIM projection.
#[test]
fn only_the_two_chip_commands_produce_an_inventory() {
    let outcome = deliver_esim(
        Command::ModemReport {
            modem_imei: IMEI.into(),
        },
        EsimPort::answering(inventory_details(bench_profiles())),
    );

    assert_eq!(outcome.result.status, RESULT_SUCCEEDED);
    assert!(outcome.inventory.is_none());
}

/// A command that failed read nothing, whatever it managed to say on the way
/// out. `867018069509705` is not an eUICC and this is the path it takes.
#[test]
fn a_failed_chip_read_carries_no_inventory() {
    let outcome = deliver_esim(read_chip(), EsimPort::failing());

    assert_eq!(outcome.result.status, RESULT_FAILED);
    assert_eq!(
        outcome.result.reason_code.as_deref(),
        Some("esim_info_failed")
    );
    assert!(outcome.inventory.is_none());
}

/// A read that produced no inventory is normal, not an error: a card that is
/// not an eUICC has no EID, and the payload cannot be written without one.
#[test]
fn a_read_without_an_inventory_still_succeeds() {
    let outcome = deliver_esim(
        read_chip(),
        EsimPort::answering(
            serde_json::json!({"imei": IMEI, "inventory": serde_json::Value::Null}),
        ),
    );

    assert_eq!(outcome.result.status, RESULT_SUCCEEDED);
    assert!(outcome.inventory.is_none());
}

/// The last gate before the wire. A payload the cloud cannot store is worse
/// than none: it is counted as a contract violation, and the projection treats
/// an inventory as the complete contents of a chip -- so one that arrives with
/// half its profiles marks the other half deleted.
#[test]
fn an_inventory_the_cloud_could_not_store_never_leaves() {
    let rejected: Vec<(&str, serde_json::Value)> = vec![
        (
            "an EID one digit short",
            serde_json::json!({
                "modem_imei": IMEI, "eid": "8908603020220000002600017833924",
                "collected_at": 1_756_000_000_000_i64, "profiles": [],
            }),
        ),
        (
            "an EID that is not digits",
            serde_json::json!({
                "modem_imei": IMEI, "eid": "8908603020220000002600017833924x",
                "collected_at": 1_756_000_000_000_i64, "profiles": [],
            }),
        ),
        (
            "an IMEI that is not one",
            serde_json::json!({
                "modem_imei": "867018", "eid": EID,
                "collected_at": 1_756_000_000_000_i64, "profiles": [],
            }),
        ),
        (
            "an ICCID that is too short",
            serde_json::json!({
                "modem_imei": IMEI, "eid": EID, "collected_at": 1_756_000_000_000_i64,
                "profiles": [{"iccid": "890124052719712", "state": "enabled"}],
            }),
        ),
        (
            "a state the column would refuse",
            serde_json::json!({
                "modem_imei": IMEI, "eid": EID, "collected_at": 1_756_000_000_000_i64,
                "profiles": [{"iccid": WEBBING_ICCID, "state": "active"}],
            }),
        ),
        (
            "a collected_at before the epoch",
            serde_json::json!({
                "modem_imei": IMEI, "eid": EID, "collected_at": -1_i64, "profiles": [],
            }),
        ),
        (
            "a field the payload does not have",
            serde_json::json!({
                "modem_imei": IMEI, "eid": EID, "collected_at": 1_756_000_000_000_i64,
                "profiles": [], "chip": "EC20",
            }),
        ),
    ];

    for (why, inventory) in rejected {
        let outcome = deliver_esim(
            read_chip(),
            EsimPort::answering(serde_json::json!({"imei": IMEI, "inventory": inventory})),
        );
        assert_eq!(outcome.result.status, RESULT_SUCCEEDED, "{why}");
        assert!(outcome.inventory.is_none(), "{why} must not reach the wire");
    }
}

/// Sixty-four is the schema's limit, so sixty-four must pass and sixty-five
/// must not. Truncating would be the worst of the three outcomes: the cloud
/// would mark every profile that fell off the end as deleted.
#[test]
fn an_inventory_stops_being_sendable_one_profile_past_the_limit() {
    for (count, expected) in [(64_usize, true), (65_usize, false)] {
        let profiles: Vec<serde_json::Value> = (0..count)
            .map(|index| {
                serde_json::json!({
                    "iccid": format!("8985235122504221{index:04}"),
                    "state": "disabled",
                })
            })
            .collect();
        let outcome = deliver_esim(
            read_chip(),
            EsimPort::answering(inventory_details(serde_json::Value::Array(profiles))),
        );
        assert_eq!(outcome.inventory.is_some(), expected, "{count} profiles");
    }
}

/// The iron rule, at the point it actually matters: an untested pairing does
/// not reach the modem at all.
///
/// The refusal has to happen before the port is touched, not after, or the
/// message has already cost money by the time anyone reads the reason.
#[test]
fn a_send_on_an_untested_pairing_never_reaches_the_modem() {
    let mut port = FakeSendPort::new();
    port.unmeasured();
    let mut executor = CommandExecutor::new(port);
    let outcome = executor
        .deliver(DELIVERY_A, send_sms_payload(CMD_ID), 1_500)
        .expect("the command still completes, with a refusal");

    assert_eq!(outcome.result.status, RESULT_FAILED);
    assert_eq!(
        outcome.result.reason_code.as_deref(),
        Some("sms_mo_refused_by_untested"),
        "the refusal names the layer, so the reader knows a test is the fix",
    );
    assert!(
        executor.port().sent().is_empty(),
        "nothing may be sent on a pairing nobody has measured",
    );
}

/// The subscription layer, at the same point. This is the Club case: the
/// module and the network were measured and work; the plan is what does not
/// include sending.
#[test]
fn a_plan_recorded_as_receive_only_refuses_the_send_and_says_so() {
    let mut port = FakeSendPort::new();
    port.with_subscription(edge_core::SubscriptionCapability {
        sms_send: Some(false),
        sms_receive: Some(true),
        ..edge_core::SubscriptionCapability::default()
    });
    let mut executor = CommandExecutor::new(port);
    let outcome = executor
        .deliver(DELIVERY_A, send_sms_payload(CMD_ID), 1_500)
        .expect("refused, not dropped");

    assert_eq!(outcome.result.status, RESULT_FAILED);
    assert_eq!(
        outcome.result.reason_code.as_deref(),
        Some("sms_mo_refused_by_subscription"),
        "a billing limit must not be reported as a hardware or coverage fault",
    );
    assert!(executor.port().sent().is_empty());
}

/// A measured pairing with nothing declared against the card still sends.
///
/// Guards the direction of the veto: an undeclared plan withholds nothing, or
/// every card would stop working until somebody filled a form in.
#[test]
fn an_undeclared_plan_withholds_nothing() {
    let mut executor = CommandExecutor::new(FakeSendPort::new());
    let outcome = executor
        .deliver(DELIVERY_A, send_sms_payload(CMD_ID), 1_500)
        .expect("send");

    assert_eq!(outcome.result.status, RESULT_SUCCEEDED);
    assert_eq!(executor.port().sent().len(), 1);
}

/// 🔴 The push must survive a restart, and until 2026-08-30 it did not.
///
/// `live_matrix` is seeded from the built-in TOML at startup and the pushed
/// document lived only in memory, so every deploy silently reverted the fleet
/// to the compiled-in rules. The cloud never put it back: that command is
/// already `succeeded`, so it is not redelivered.
///
/// It was not theoretical. The support ledger published on 2026-08-29 was in
/// force and verified on the bench, then lost to the next deploy — and the
/// China Telecom pairing it had authorised went back to being refused as
/// untested, with nothing anywhere saying why.
#[test]
fn an_installed_matrix_is_handed_to_the_port_for_storage() {
    let json = hot_matrix_json();
    let matrix: ContextValue = serde_json::from_value(json.clone()).expect("context");
    let sha = sha256_hex(&serde_json::to_vec(&matrix).expect("bytes"));
    let mut executor = CommandExecutor::new(FakeSendPort::new());

    let outcome = executor
        .deliver(DELIVERY_A, matrix_command(CMD_ID, "hot-1", &sha, matrix), 1_500)
        .expect("install matrix");
    assert_eq!(outcome.result.status, RESULT_SUCCEEDED);

    let stored = executor
        .port()
        .persisted_matrix()
        .expect("the installed matrix was never handed over for storage");
    assert_eq!(stored.0, "hot-1");
    assert_eq!(stored.1, sha);
    // The bytes, not a re-serialisation of the parsed matrix: the digest the
    // cloud computed is over what it sent.
    let round: serde_json::Value = serde_json::from_str(&stored.2).expect("stored document");
    assert_eq!(round, json);
}

/// A matrix read back at startup governs routing, which is the whole point of
/// storing it.
#[test]
fn a_restored_matrix_replaces_the_built_in_one() {
    let mut executor = CommandExecutor::new(FakeSendPort::new());
    let before = executor
        .matrix()
        .query(&ModemFamily::EC20, &CarrierProfile::CN_TELECOM);
    assert!(matches!(before.capability.sms_mo, BearerSupport::Unsupported { .. }));

    let json = hot_matrix_json();
    let value: ContextValue = serde_json::from_value(json).expect("context");
    let parsed = CapabilityMatrix::from_json_value(
        &serde_json::to_value(&value).expect("json"),
    )
    .expect("parse");
    executor.restore_matrix(parsed);

    let after = executor
        .matrix()
        .query(&ModemFamily::EC20, &CarrierProfile::CN_TELECOM);
    assert_eq!(after.capability.sms_mo, BearerSupport::Supported(Bearer::Cellular));
}
