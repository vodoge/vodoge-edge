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
    fn send_sms(&mut self, send: &SmsSend) -> Result<(), SendError>;
    fn restart_modem(&mut self, _imei: &str) -> Result<(), SendError> {
        Err(SendError::new(
            "unsupported_command",
            "restart_modem is not implemented",
        ))
    }
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
    fn send_sms(&mut self, send: &SmsSend) -> Result<(), SendError> {
        if let Some(error) = self.error.clone() {
            return Err(error);
        }
        self.sent.push(send.clone());
        Ok(())
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
                let result = match self.port.send_sms(&send) {
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

fn result_envelope_id(cmd_id: &str) -> Result<EnvelopeId, CommandError> {
    EnvelopeId::new(format!("command-result:{cmd_id}")).map_err(CommandError::Uplink)
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
