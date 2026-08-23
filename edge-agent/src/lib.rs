//! Command execution for the Vodoge edge agent.
//!
//! A `CommandReceipt` means the `cmd_id` was durably recorded for
//! deduplication. It is not success. Only a sequenced `CommandResult` is
//! terminal.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use edge_core::CapabilityMatrix;
use edge_uplink::update::UpdateGuard;
use edge_uplink::{EnvelopeId, RetentionClass, UplinkError, UplinkState};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use vodoge_contract::{
    Command, CommandDeliverPayload, CommandReceiptPayload, CommandResultPayload, ContextValue,
    Envelope, MessageKind,
};

/// Receipt status: first durable accept of a `cmd_id`.
pub const RECEIPT_ACCEPTED: &str = "accepted";
/// Receipt status: the `cmd_id` was already recorded.
pub const RECEIPT_DUPLICATE: &str = "duplicate";

/// Terminal result after a successful hardware action.
pub const RESULT_SUCCEEDED: &str = "succeeded";
/// Terminal result after a failed hardware action.
pub const RESULT_FAILED: &str = "failed";
/// Terminal result when a non-idempotent action was started with unknown outcome.
pub const RESULT_UNKNOWN: &str = "unknown";
/// Terminal result when the delivery is already past `expires_at`.
pub const RESULT_EXPIRED: &str = "expired";

/// One SMS send attempt presented to a [`SendPort`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmsSend {
    pub to: String,
    pub body: String,
    pub modem_imei: Option<String>,
    pub iccid: Option<String>,
}

/// Error returned by [`SendPort::send_sms`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SendError {
    pub reason_code: String,
    pub message: String,
}

impl SendError {
    pub fn new(reason_code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            reason_code: reason_code.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for SendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.reason_code, self.message)
    }
}

impl Error for SendError {}

/// Executes `SendSms` without requiring a real modem.
pub trait SendPort {
    /// Sends one SMS and returns what the modem said about it.
    ///
    /// The JSON goes into the result's `details`, like every diagnostic below,
    /// and it is not decoration here: it carries the TP-MR the network will
    /// quote back in the delivery receipt. Without it the cloud can only guess
    /// which sent message a `+CDS` belongs to by picking the most recent one
    /// to that number, which is right on a quiet bench and silently wrong the
    /// first time two messages to one recipient are in flight together.
    fn send_sms(&mut self, send: &SmsSend) -> Result<JsonValue, SendError>;
    fn restart_modem(&mut self, _imei: &str) -> Result<(), SendError> {
        Err(unsupported("restart_modem"))
    }

    // The diagnostic actions below already existed on the edge panel, where
    // they could only be driven by someone with a shell on the box. Reaching
    // them from the cloud is the whole point of the relay.
    //
    // Each returns the JSON that goes into the result's `details`, so a
    // console can render an AT response or a scan list without a second
    // round trip. Defaults refuse rather than pretend: a port that cannot do
    // one of these must say so, not report a success with no effect.

    fn run_at(
        &mut self,
        _imei: &str,
        _command: &str,
        _timeout_ms: Option<i64>,
    ) -> Result<JsonValue, SendError> {
        Err(unsupported("run_at_command"))
    }

    /// `stage` is one of `start`, `continue` or `cancel`.
    fn send_ussd(&mut self, _imei: &str, _code: &str, _stage: &str) -> Result<JsonValue, SendError> {
        Err(unsupported("send_ussd"))
    }

    fn set_radio(&mut self, _imei: &str, _enabled: bool) -> Result<(), SendError> {
        Err(unsupported("set_radio"))
    }

    fn scan_operators(&mut self, _imei: &str) -> Result<JsonValue, SendError> {
        Err(unsupported("scan_operators"))
    }

    /// `plmn` is present only for manual selection.
    fn select_operator(
        &mut self,
        _imei: &str,
        _mode: &str,
        _plmn: Option<&str>,
    ) -> Result<JsonValue, SendError> {
        Err(unsupported("select_operator"))
    }

    fn modem_report(&mut self, _imei: &str) -> Result<JsonValue, SendError> {
        Err(unsupported("modem_report"))
    }

    fn reset_usb(&mut self, _imei: &str) -> Result<JsonValue, SendError> {
        Err(unsupported("reset_modem_usb"))
    }

    /// Bring the packet data bearer up or down.
    fn set_data_network(&mut self, _imei: &str, _enabled: bool) -> Result<JsonValue, SendError> {
        Err(unsupported("set_data_network"))
    }

    /// Choose which USB network function the module exposes.
    ///
    /// `mode` is one of `rmnet`, `ecm`, `mbim` or `rndis`. Whether the module
    /// applies it on the spot or at its next restart is the module's own
    /// business — the EC20s on the bench re-enumerate immediately — so an
    /// implementation reports what the module read back, not what it wrote.
    fn set_usbnet_mode(&mut self, _imei: &str, _mode: &str) -> Result<JsonValue, SendError> {
        Err(unsupported("set_usbnet_mode"))
    }

    /// Drop the network registration and take it again.
    ///
    /// The cure for a modem that is attached to a cell but getting nothing
    /// through it. The module is off-network in between, so this is not free.
    fn reregister_network(&mut self, _imei: &str) -> Result<JsonValue, SendError> {
        Err(unsupported("reregister_network"))
    }

    /// Look for modems now rather than at the next poll.
    ///
    /// Takes no IMEI: the point is the ones that are not in the inventory yet.
    fn refresh_modems(&mut self) -> Result<JsonValue, SendError> {
        Err(unsupported("refresh_modems"))
    }

    fn list_esim_profiles(&mut self, _imei: &str) -> Result<JsonValue, SendError> {
        Err(unsupported("list_esim_profiles"))
    }

    fn switch_esim_profile(
        &mut self,
        _imei: &str,
        _target_iccid: &str,
    ) -> Result<JsonValue, SendError> {
        Err(unsupported("switch_esim_profile"))
    }

    // The proxy actions. These are device-level rather than modem-level: a
    // configuration names the modems it wants, so applying it is one operation
    // over the whole set.

    /// Applies the cloud's desired proxy state and reports what is listening.
    fn configure_proxy(
        &mut self,
        _instances: &JsonValue,
        _upstreams: &JsonValue,
    ) -> Result<JsonValue, SendError> {
        Err(unsupported("configure_proxy"))
    }

    /// `action` is one of `start`, `stop` or `restart`.
    fn proxy_lifecycle(
        &mut self,
        _instance_id: &str,
        _action: &str,
    ) -> Result<JsonValue, SendError> {
        Err(unsupported("proxy_lifecycle"))
    }

    fn probe_upstream_proxy(&mut self, _upstream_id: &str) -> Result<JsonValue, SendError> {
        Err(unsupported("probe_upstream_proxy"))
    }

    /// Drops and re-establishes the data session so the network assigns a new
    /// address.
    fn rotate_ip(&mut self, _imei: &str) -> Result<JsonValue, SendError> {
        Err(unsupported("rotate_ip"))
    }
}

fn unsupported(what: &str) -> SendError {
    SendError::new("unsupported_command", format!("{what} is not implemented"))
}

/// In-memory send target used by command tests.
#[derive(Clone, Debug, Default)]
pub struct FakeSendPort {
    sent: Vec<SmsSend>,
    restarted: Vec<String>,
    error: Option<SendError>,
}

impl FakeSendPort {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn fail_with(&mut self, reason_code: impl Into<String>, message: impl Into<String>) {
        self.error = Some(SendError::new(reason_code, message));
    }

    pub fn sent(&self) -> &[SmsSend] {
        &self.sent
    }

    pub fn restarted(&self) -> &[String] {
        &self.restarted
    }
}

impl SendPort for FakeSendPort {
    fn send_sms(&mut self, send: &SmsSend) -> Result<JsonValue, SendError> {
        if let Some(error) = self.error.clone() {
            return Err(error);
        }
        self.sent.push(send.clone());
        Ok(JsonValue::Null)
    }

    fn restart_modem(&mut self, imei: &str) -> Result<(), SendError> {
        if let Some(error) = self.error.clone() {
            return Err(error);
        }
        self.restarted.push(imei.to_string());
        Ok(())
    }
}

/// One SelfUpdate command presented to an [`UpdatePort`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelfUpdateRequest {
    pub version: String,
    pub url: String,
    pub sha256: String,
    pub signature: String,
}

/// Stages a new edge binary. The uplink handshake decides whether it stays.
pub trait UpdatePort {
    fn stage(&mut self, request: &SelfUpdateRequest) -> Result<(), SendError>;
    fn restore(&mut self, version: &str) -> Result<(), SendError>;
    fn current(&self) -> String;
}

/// Rejects SelfUpdate when no installer is configured.
#[derive(Clone, Debug, Default)]
pub struct RejectUpdate {
    current: String,
}

impl RejectUpdate {
    pub fn new(current: impl Into<String>) -> Self {
        Self {
            current: current.into(),
        }
    }
}

impl UpdatePort for RejectUpdate {
    fn stage(&mut self, _request: &SelfUpdateRequest) -> Result<(), SendError> {
        Err(SendError::new(
            "update_not_configured",
            "self-update is not configured on this edge",
        ))
    }

    fn restore(&mut self, version: &str) -> Result<(), SendError> {
        self.current = version.to_string();
        Ok(())
    }

    fn current(&self) -> String {
        self.current.clone()
    }
}

/// In-memory installer used by self-update tests.
#[derive(Clone, Debug)]
pub struct FakeUpdatePort {
    current: String,
    staged: Vec<SelfUpdateRequest>,
    restored: Vec<String>,
    error: Option<SendError>,
}

impl FakeUpdatePort {
    pub fn new(current: impl Into<String>) -> Self {
        Self {
            current: current.into(),
            staged: Vec::new(),
            restored: Vec::new(),
            error: None,
        }
    }

    pub fn fail_with(&mut self, reason_code: impl Into<String>, message: impl Into<String>) {
        self.error = Some(SendError::new(reason_code, message));
    }

    pub fn staged(&self) -> &[SelfUpdateRequest] {
        &self.staged
    }

    pub fn restored(&self) -> &[String] {
        &self.restored
    }
}

impl UpdatePort for FakeUpdatePort {
    fn stage(&mut self, request: &SelfUpdateRequest) -> Result<(), SendError> {
        if let Some(error) = self.error.clone() {
            return Err(error);
        }
        if request.sha256.trim().is_empty() {
            return Err(SendError::new("update_sha256_missing", "self-update sha256 is required"));
        }
        self.staged.push(request.clone());
        self.current = request.version.clone();
        Ok(())
    }

    fn restore(&mut self, version: &str) -> Result<(), SendError> {
        self.restored.push(version.to_string());
        self.current = version.to_string();
        Ok(())
    }

    fn current(&self) -> String {
        self.current.clone()
    }
}

/// Receipt plus the sequenced terminal result of one `CommandDeliver`.
#[derive(Clone, Debug)]
pub struct DeliveryOutcome {
    pub receipt: CommandReceiptPayload,
    pub result: CommandResultPayload,
    pub result_sequence: u64,
    pub executed: bool,
}

/// Accepts `CommandDeliver`, persists `cmd_id`, executes at most once, and
/// always sequences a `CommandResult`.
pub struct CommandExecutor<P, U = RejectUpdate> {
    port: P,
    updater: U,
    guard: UpdateGuard,
    commands: BTreeMap<String, StoredCommand>,
    uplink: UplinkState,
    matrix: CapabilityMatrix,
}

#[derive(Clone, Debug)]
struct StoredCommand {
    phase: Phase,
    result: Option<CommandResultPayload>,
    result_sequence: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Recorded,
    Executing,
    Terminal,
}

impl<P: SendPort> CommandExecutor<P, RejectUpdate> {
    pub fn new(port: P) -> Self {
        Self::with_updater(port, RejectUpdate::new("0.1.0"))
    }
}

impl<P: SendPort, U: UpdatePort> CommandExecutor<P, U> {
    pub fn with_updater(port: P, updater: U) -> Self {
        let current = updater.current();
        Self {
            port,
            updater,
            guard: UpdateGuard::new(current),
            commands: BTreeMap::new(),
            uplink: UplinkState::new(),
            matrix: CapabilityMatrix::builtin().expect("built-in capability matrix"),
        }
    }

    pub fn port(&self) -> &P {
        &self.port
    }

    pub fn updater(&self) -> &U {
        &self.updater
    }

    pub fn uplink(&self) -> &UplinkState {
        &self.uplink
    }

    pub fn matrix(&self) -> &CapabilityMatrix {
        &self.matrix
    }

    pub fn running_version(&self) -> &str {
        &self.guard.current
    }

    /// After Resume, keep the staged binary or restore the previous one.
    pub fn confirm_handshake(&mut self, handshake_ok: bool) -> Result<Option<String>, SendError> {
        let Some(previous) = self.guard.rollback_if_handshake_failed(handshake_ok) else {
            return Ok(None);
        };
        self.updater.restore(&previous)?;
        Ok(Some(previous))
    }

    /// Handle one physical `CommandDeliver` envelope.
    pub fn handle_envelope(
        &mut self,
        envelope: &Envelope,
        now_ms: i64,
    ) -> Result<DeliveryOutcome, CommandError> {
        envelope
            .validate_sequence()
            .map_err(CommandError::InvalidEnvelope)?;
        if envelope.kind != MessageKind::CommandDeliver {
            return Err(CommandError::UnexpectedKind(envelope.kind.as_str().to_string()));
        }
        let payload: CommandDeliverPayload = serde_json::from_value(envelope.payload.clone())
            .map_err(|err| CommandError::InvalidEnvelope(err.to_string()))?;
        self.deliver(&envelope.id, payload, now_ms)
    }

    /// Persist `cmd_id`, emit a receipt, execute at most once, and sequence a result.
    pub fn deliver(
        &mut self,
        delivery_id: impl Into<String>,
        payload: CommandDeliverPayload,
        now_ms: i64,
    ) -> Result<DeliveryOutcome, CommandError> {
        let delivery_id = delivery_id.into();
        if delivery_id.trim().is_empty() {
            return Err(CommandError::EmptyDeliveryId);
        }
        if payload.cmd_id.trim().is_empty() {
            return Err(CommandError::EmptyCmdId);
        }

        let first_seen = !self.commands.contains_key(&payload.cmd_id);
        match self.commands.get(&payload.cmd_id).map(|stored| stored.phase) {
            Some(Phase::Terminal) => {
                return self
                    .replay(&payload.cmd_id, &delivery_id, now_ms)
                    .ok_or(CommandError::EmptyCmdId);
            }
            Some(Phase::Executing) => {
                return self.finish_unknown(&payload, &delivery_id, now_ms);
            }
            Some(Phase::Recorded) | None => {}
        }
        if first_seen {
            self.commands.insert(
                payload.cmd_id.clone(),
                StoredCommand {
                    phase: Phase::Recorded,
                    result: None,
                    result_sequence: None,
                },
            );
        }

        let receipt = receipt(
            &payload.cmd_id,
            &delivery_id,
            if first_seen {
                RECEIPT_ACCEPTED
            } else {
                RECEIPT_DUPLICATE
            },
            now_ms,
        );
        let attempts = payload.attempt.unwrap_or(1);
        let (result, executed) = if now_ms >= payload.expires_at {
            (
                terminal_result(
                    &payload.cmd_id,
                    RESULT_EXPIRED,
                    now_ms,
                    attempts,
                    Some("expired"),
                    Some("command expired before execution"),
                ),
                false,
            )
        } else {
            self.execute(&payload, now_ms, attempts)?
        };
        let sequence = self.store_terminal(&payload.cmd_id, result.clone())?;

        Ok(DeliveryOutcome {
            receipt,
            result,
            result_sequence: sequence,
            executed,
        })
    }

    fn replay(
        &self,
        cmd_id: &str,
        delivery_id: &str,
        now_ms: i64,
    ) -> Option<DeliveryOutcome> {
        let stored = self.commands.get(cmd_id)?;
        let result = stored.result.clone()?;
        let sequence = stored.result_sequence?;
        Some(DeliveryOutcome {
            receipt: receipt(cmd_id, delivery_id, RECEIPT_DUPLICATE, now_ms),
            result,
            result_sequence: sequence,
            executed: false,
        })
    }

    fn execute(
        &mut self,
        payload: &CommandDeliverPayload,
        now_ms: i64,
        attempts: i64,
    ) -> Result<(CommandResultPayload, bool), CommandError> {
        match &payload.command {
            Command::SendSms {
                to,
                body,
                modem_imei,
                iccid,
            } => {
                self.mark_executing(&payload.cmd_id);
                let send = SmsSend {
                    to: to.clone(),
                    body: body.clone(),
                    modem_imei: modem_imei.clone(),
                    iccid: iccid.clone(),
                };
                // Same shape as the diagnostic relays: whatever the port
                // reported travels back in `details`. For a send that is the
                // message reference, which the cloud stores against the
                // message so a later status report settles the right one.
                let outcome = self.port.send_sms(&send);
                Ok((
                    diagnostic_result(&payload.cmd_id, now_ms, attempts, outcome),
                    true,
                ))
            }
            Command::RestartModem { modem_imei } => {
                self.mark_executing(&payload.cmd_id);
                let result = match self.port.restart_modem(modem_imei) {
                    Ok(()) => terminal_result(
                        &payload.cmd_id,
                        RESULT_SUCCEEDED,
                        now_ms,
                        attempts,
                        None,
                        None,
                    ),
                    Err(error) => terminal_result(
                        &payload.cmd_id,
                        RESULT_FAILED,
                        now_ms,
                        attempts,
                        Some(error.reason_code.as_str()),
                        Some(error.message.as_str()),
                    ),
                };
                Ok((result, true))
            }
            Command::UpdateCapabilityMatrix {
                matrix_version,
                matrix_sha256,
                matrix,
            } => match install_matrix(matrix_version, matrix_sha256, matrix) {
                Ok(parsed) => {
                    self.matrix = parsed;
                    Ok((
                        terminal_result(
                            &payload.cmd_id,
                            RESULT_SUCCEEDED,
                            now_ms,
                            attempts,
                            None,
                            None,
                        ),
                        true,
                    ))
                }
                Err((reason_code, message)) => Ok((
                    terminal_result(
                        &payload.cmd_id,
                        RESULT_FAILED,
                        now_ms,
                        attempts,
                        Some(reason_code),
                        Some(&message),
                    ),
                    false,
                )),
            },
            Command::SelfUpdate {
                version,
                url,
                sha256,
                signature,
            } => {
                let request = SelfUpdateRequest {
                    version: version.clone(),
                    url: url.clone(),
                    sha256: sha256.clone(),
                    signature: signature.clone(),
                };
                match self.updater.stage(&request) {
                    Ok(()) => {
                        self.guard.start(version.clone());
                        Ok((
                            terminal_result(
                                &payload.cmd_id,
                                RESULT_SUCCEEDED,
                                now_ms,
                                attempts,
                                None,
                                None,
                            ),
                            true,
                        ))
                    }
                    Err(error) => Ok((
                        terminal_result(
                            &payload.cmd_id,
                            RESULT_FAILED,
                            now_ms,
                            attempts,
                            Some(error.reason_code.as_str()),
                            Some(error.message.as_str()),
                        ),
                        true,
                    )),
                }
            }
            // The diagnostic relay. Each of these already worked on the edge
            // panel; the executor simply routes the cloud's request to the
            // same port and puts whatever came back into `details`.
            //
            // All are marked executed: even a failed AT command consumed the
            // radio and must not be retried behind the caller's back.
            Command::RunAtCommand {
                modem_imei,
                command,
                timeout_ms,
            } => {
                self.mark_executing(&payload.cmd_id);
                let outcome = self.port.run_at(modem_imei, command, *timeout_ms);
                Ok((
                    diagnostic_result(&payload.cmd_id, now_ms, attempts, outcome),
                    true,
                ))
            }
            Command::SendUssd {
                modem_imei,
                code,
                stage,
            } => {
                self.mark_executing(&payload.cmd_id);
                let stage = stage.as_deref().unwrap_or("start");
                let outcome = self.port.send_ussd(modem_imei, code, stage);
                Ok((
                    diagnostic_result(&payload.cmd_id, now_ms, attempts, outcome),
                    true,
                ))
            }
            Command::SetRadio {
                modem_imei,
                enabled,
            } => {
                self.mark_executing(&payload.cmd_id);
                let outcome = self
                    .port
                    .set_radio(modem_imei, *enabled)
                    .map(|()| JsonValue::Null);
                Ok((
                    diagnostic_result(&payload.cmd_id, now_ms, attempts, outcome),
                    true,
                ))
            }
            Command::ScanOperators { modem_imei } => {
                self.mark_executing(&payload.cmd_id);
                let outcome = self.port.scan_operators(modem_imei);
                Ok((
                    diagnostic_result(&payload.cmd_id, now_ms, attempts, outcome),
                    true,
                ))
            }
            Command::SelectOperator {
                modem_imei,
                mode,
                plmn,
            } => {
                self.mark_executing(&payload.cmd_id);
                let outcome = self.port.select_operator(modem_imei, mode, plmn.as_deref());
                Ok((
                    diagnostic_result(&payload.cmd_id, now_ms, attempts, outcome),
                    true,
                ))
            }
            Command::ModemReport { modem_imei } => {
                self.mark_executing(&payload.cmd_id);
                let outcome = self.port.modem_report(modem_imei);
                Ok((
                    diagnostic_result(&payload.cmd_id, now_ms, attempts, outcome),
                    true,
                ))
            }
            Command::ResetModemUsb { modem_imei } => {
                self.mark_executing(&payload.cmd_id);
                let outcome = self.port.reset_usb(modem_imei);
                Ok((
                    diagnostic_result(&payload.cmd_id, now_ms, attempts, outcome),
                    true,
                ))
            }
            Command::SetDataNetwork {
                modem_imei,
                enabled,
            } => {
                self.mark_executing(&payload.cmd_id);
                let outcome = self.port.set_data_network(modem_imei, *enabled);
                Ok((
                    diagnostic_result(&payload.cmd_id, now_ms, attempts, outcome),
                    true,
                ))
            }
            Command::SetUsbnetMode { modem_imei, mode } => {
                self.mark_executing(&payload.cmd_id);
                let outcome = self.port.set_usbnet_mode(modem_imei, mode.as_str());
                Ok((
                    diagnostic_result(&payload.cmd_id, now_ms, attempts, outcome),
                    true,
                ))
            }
            Command::ReregisterNetwork { modem_imei } => {
                self.mark_executing(&payload.cmd_id);
                let outcome = self.port.reregister_network(modem_imei);
                Ok((
                    diagnostic_result(&payload.cmd_id, now_ms, attempts, outcome),
                    true,
                ))
            }
            Command::RefreshModems => {
                self.mark_executing(&payload.cmd_id);
                let outcome = self.port.refresh_modems();
                Ok((
                    diagnostic_result(&payload.cmd_id, now_ms, attempts, outcome),
                    true,
                ))
            }
            Command::ListEsimProfiles { modem_imei } => {
                self.mark_executing(&payload.cmd_id);
                let outcome = self.port.list_esim_profiles(modem_imei);
                Ok((
                    diagnostic_result(&payload.cmd_id, now_ms, attempts, outcome),
                    true,
                ))
            }
            Command::SwitchEsimProfile {
                modem_imei,
                target_iccid,
            } => {
                self.mark_executing(&payload.cmd_id);
                let outcome = self.port.switch_esim_profile(modem_imei, target_iccid);
                Ok((
                    diagnostic_result(&payload.cmd_id, now_ms, attempts, outcome),
                    true,
                ))
            }
            Command::ConfigureProxy {
                instances,
                upstreams,
            } => {
                self.mark_executing(&payload.cmd_id);
                // The specs travel as contract types; the proxy manager reads
                // them as JSON so its shape stays its own rather than being
                // pinned to the generated bindings.
                let instances = serde_json::to_value(instances).unwrap_or(JsonValue::Null);
                let upstreams = serde_json::to_value(upstreams).unwrap_or(JsonValue::Null);
                let outcome = self.port.configure_proxy(&instances, &upstreams);
                Ok((
                    diagnostic_result(&payload.cmd_id, now_ms, attempts, outcome),
                    true,
                ))
            }
            Command::ProxyLifecycle {
                instance_id,
                action,
            } => {
                self.mark_executing(&payload.cmd_id);
                let outcome = self.port.proxy_lifecycle(instance_id, action);
                Ok((
                    diagnostic_result(&payload.cmd_id, now_ms, attempts, outcome),
                    true,
                ))
            }
            Command::ProbeUpstreamProxy { upstream_id } => {
                self.mark_executing(&payload.cmd_id);
                let outcome = self.port.probe_upstream_proxy(upstream_id);
                Ok((
                    diagnostic_result(&payload.cmd_id, now_ms, attempts, outcome),
                    true,
                ))
            }
            Command::RotateIp { modem_imei } => {
                self.mark_executing(&payload.cmd_id);
                let outcome = self.port.rotate_ip(modem_imei);
                Ok((
                    diagnostic_result(&payload.cmd_id, now_ms, attempts, outcome),
                    true,
                ))
            }
            _ => Ok((
                terminal_result(
                    &payload.cmd_id,
                    RESULT_FAILED,
                    now_ms,
                    attempts,
                    Some("unsupported_command"),
                    Some("command kind is not implemented"),
                ),
                false,
            )),
        }
    }

    fn finish_unknown(
        &mut self,
        payload: &CommandDeliverPayload,
        delivery_id: &str,
        now_ms: i64,
    ) -> Result<DeliveryOutcome, CommandError> {
        let attempts = payload.attempt.unwrap_or(1);
        let result = terminal_result(
            &payload.cmd_id,
            RESULT_UNKNOWN,
            now_ms,
            attempts,
            Some("outcome_unknown"),
            Some("command was executing when the agent lost the modem result"),
        );
        let sequence = self.store_terminal(&payload.cmd_id, result.clone())?;
        Ok(DeliveryOutcome {
            receipt: receipt(&payload.cmd_id, delivery_id, RECEIPT_DUPLICATE, now_ms),
            result,
            result_sequence: sequence,
            executed: false,
        })
    }

    fn mark_executing(&mut self, cmd_id: &str) {
        if let Some(stored) = self.commands.get_mut(cmd_id) {
            stored.phase = Phase::Executing;
        }
    }

    fn store_terminal(
        &mut self,
        cmd_id: &str,
        result: CommandResultPayload,
    ) -> Result<u64, CommandError> {
        let envelope_id = result_envelope_id(cmd_id)?;
        let payload = serde_json::to_vec(&result).expect("command result payload");
        let sequence = match self
            .uplink
            .append(envelope_id, payload, RetentionClass::Protected)
        {
            Ok(sequence) => sequence,
            Err(UplinkError::DuplicateEnvelopeId { sequence, .. }) => sequence,
            Err(error) => return Err(CommandError::Uplink(error)),
        };

        let stored = self
            .commands
            .get_mut(cmd_id)
            .ok_or(CommandError::EmptyCmdId)?;
        stored.phase = Phase::Terminal;
        stored.result = Some(result);
        stored.result_sequence = Some(sequence);
        Ok(sequence)
    }
}

/// The envelope id for a command's result.
///
/// The command id itself. It has to be a UUID — the contract says so and the
/// cloud's journal stores it in a uuid column — and it has to be the same on
/// every replay, because the outbox deduplicates by it and a reconnect resends
/// the result.
///
/// `command-result:{cmd_id}` satisfied the second and not the first, so every
/// result the cloud received was rejected by PostgreSQL, which ended the device
/// session; the edge reconnected, replayed the same result and was cut off
/// again, forever. There is exactly one result per command, so the command's
/// own id is unique here.
fn result_envelope_id(cmd_id: &str) -> Result<EnvelopeId, CommandError> {
    EnvelopeId::new(cmd_id.to_string()).map_err(CommandError::Uplink)
}

fn receipt(
    cmd_id: &str,
    delivery_id: &str,
    status: &str,
    received_at: i64,
) -> CommandReceiptPayload {
    CommandReceiptPayload {
        cmd_id: cmd_id.to_string(),
        delivery_id: delivery_id.to_string(),
        status: status.to_string(),
        received_at,
        retry_after_ms: None,
        reason_code: None,
    }
}

fn install_matrix(
    matrix_version: &str,
    matrix_sha256: &str,
    matrix: &ContextValue,
) -> Result<CapabilityMatrix, (&'static str, String)> {
    let bytes = serde_json::to_vec(matrix)
        .map_err(|err| ("matrix_invalid", err.to_string()))?;
    let digest = hex_sha256(&bytes);
    if !digest.eq_ignore_ascii_case(matrix_sha256.trim()) {
        return Err((
            "matrix_sha256_mismatch",
            "capability matrix sha256 does not match".to_string(),
        ));
    }
    let value = serde_json::to_value(matrix)
        .map_err(|err| ("matrix_invalid", err.to_string()))?;
    let parsed = CapabilityMatrix::from_json_value(&value)
        .map_err(|err| ("matrix_invalid", err.to_string()))?;
    if parsed.version() != matrix_version {
        return Err((
            "matrix_version_mismatch",
            format!(
                "matrix version {} does not match command {}",
                parsed.version(),
                matrix_version
            ),
        ));
    }
    Ok(parsed)
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

/// Bridges a diagnostic result into the contract's own JSON tree.
///
/// `ContextValue` is generated code and cannot grow a `From` impl of its own.
/// Numbers that are not finite have no JSON representation at all, so they
/// become null rather than silently serialising as something else.
fn context_value(value: JsonValue) -> ContextValue {
    match value {
        JsonValue::Null => ContextValue::Null,
        JsonValue::Bool(inner) => ContextValue::Bool(inner),
        JsonValue::Number(inner) => match inner.as_f64() {
            Some(number) if number.is_finite() => ContextValue::Number(number),
            _ => ContextValue::Null,
        },
        JsonValue::String(inner) => ContextValue::String(inner),
        JsonValue::Array(items) => {
            ContextValue::Array(items.into_iter().map(context_value).collect())
        }
        JsonValue::Object(entries) => ContextValue::Object(
            entries
                .into_iter()
                .map(|(key, value)| (key, context_value(value)))
                .collect(),
        ),
    }
}

/// One diagnostic action's outcome, in the shape every branch of `execute`
/// needs it. Written once because there are now ten of them and each was
/// otherwise twenty lines of the same match.
fn diagnostic_result(
    cmd_id: &str,
    now_ms: i64,
    attempts: i64,
    outcome: Result<JsonValue, SendError>,
) -> CommandResultPayload {
    match outcome {
        Ok(details) => {
            let mut result =
                terminal_result(cmd_id, RESULT_SUCCEEDED, now_ms, attempts, None, None);
            if !details.is_null() {
                result.details = Some(context_value(details));
            }
            result
        }
        Err(error) => terminal_result(
            cmd_id,
            RESULT_FAILED,
            now_ms,
            attempts,
            Some(error.reason_code.as_str()),
            Some(error.message.as_str()),
        ),
    }
}

fn terminal_result(
    cmd_id: &str,
    status: &str,
    completed_at: i64,
    attempts: i64,
    reason_code: Option<&str>,
    reason: Option<&str>,
) -> CommandResultPayload {
    CommandResultPayload {
        cmd_id: cmd_id.to_string(),
        status: status.to_string(),
        completed_at,
        attempts,
        reason_code: reason_code.map(str::to_string),
        reason: reason.map(str::to_string),
        details: None,
    }
}

/// Errors from command acceptance or result sequencing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandError {
    EmptyCmdId,
    EmptyDeliveryId,
    UnexpectedKind(String),
    InvalidEnvelope(String),
    Uplink(UplinkError),
}

impl fmt::Display for CommandError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyCmdId => formatter.write_str("cmd_id must not be empty"),
            Self::EmptyDeliveryId => formatter.write_str("delivery_id must not be empty"),
            Self::UnexpectedKind(kind) => write!(formatter, "unexpected envelope {kind}"),
            Self::InvalidEnvelope(reason) => write!(formatter, "invalid envelope: {reason}"),
            Self::Uplink(error) => write!(formatter, "{error}"),
        }
    }
}

impl Error for CommandError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Uplink(error) => Some(error),
            _ => None,
        }
    }
}

impl From<UplinkError> for CommandError {
    fn from(value: UplinkError) -> Self {
        Self::Uplink(value)
    }
}
