//! Command execution for the Vodoge edge agent.
//!
//! A `CommandReceipt` means the `cmd_id` was durably recorded for
//! deduplication. It is not success. Only a sequenced `CommandResult` is
//! terminal.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use edge_core::{
    builtin_strategy_registry, CapabilityMatrix, OperatingContext, Operation, RefusedBy,
    SupportLedger,
};
use edge_uplink::update::UpdateGuard;
use edge_uplink::{EnvelopeId, RetentionClass, UplinkError, UplinkState};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use vodoge_contract::{
    CardPolicy, Command, CommandDeliverPayload, CommandReceiptPayload, CommandResultPayload,
    ContextValue, Envelope, EsimInventoryPayload, MessageKind,
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

/// One packet data context to write, as `ConfigureApn` asked for it.
///
/// 🔴 `password` goes down and never comes back: the state payload carries
/// `has_password` and no field this could be read into. Anything that logs
/// this struct logs a credential, so nothing does.
#[derive(Clone, Copy, Debug)]
pub struct ApnWrite<'a> {
    pub imei: &'a str,
    pub cid: u8,
    /// `IP`, `IPV6` or `IPV4V6`. `None` keeps whatever type the context
    /// already has, which is what an edit that only changes credentials means.
    pub pdp_type: Option<&'a str>,
    pub apn: &'a str,
    pub username: Option<&'a str>,
    pub password: Option<&'a str>,
    /// `none`, `pap`, `chap` or `pap_or_chap`.
    pub auth: Option<&'a str>,
}

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

    /// Store the capability matrix that was just installed, so it survives a
    /// restart.
    ///
    /// Without it the push lives only in memory and every restart silently
    /// reverts the fleet to the compiled-in rules — the cloud does not re-send,
    /// because the command already succeeded. The document is handed over
    /// verbatim: the digest the cloud computed is over the bytes it sent.
    ///
    /// Failing to store is reported but does not fail the command. The matrix
    /// is installed and governing behaviour by the time this runs; answering
    /// the cloud with a failure would invite a redelivery of something that
    /// already took.
    fn persist_capability_matrix(
        &mut self,
        _version: &str,
        _sha256: &str,
        _document: &str,
    ) -> Result<(), SendError> {
        Ok(())
    }

    /// The module's identity and the policy on the card in it.
    ///
    /// Supplied by the port rather than decided here because the facts live in
    /// the edge binary's store, while the rule that reads them lives with the
    /// capability matrix, which is here. A port that cannot answer leaves the
    /// operation unresolved — see the call site, which refuses rather than
    /// proceeding, because "we could not tell what this module is" is not a
    /// reason to send anyway.
    fn operating_context(&mut self, _imei: Option<&str>) -> Result<OperatingContext, SendError> {
        Err(unsupported("operating_context"))
    }
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

    /// Run one AT command.
    ///
    /// `force` carries the caller's intent past the agent's own classification
    /// of disruptive commands; see `edge_core::classify_at_command`. It is not
    /// a permission — the console decides who may ask — only a statement that
    /// the disruptive command was the one meant.
    fn run_at(
        &mut self,
        _imei: &str,
        _command: &str,
        _timeout_ms: Option<i64>,
        _force: bool,
    ) -> Result<JsonValue, SendError> {
        Err(unsupported("run_at_command"))
    }

    /// `stage` is one of `start`, `continue` or `cancel`.
    fn send_ussd(
        &mut self,
        _imei: &str,
        _code: &str,
        _stage: &str,
    ) -> Result<JsonValue, SendError> {
        Err(unsupported("send_ussd"))
    }

    fn set_radio(&mut self, _imei: &str, _enabled: bool) -> Result<(), SendError> {
        Err(unsupported("set_radio"))
    }

    /// Write one packet data context on the module.
    ///
    /// Taken as a struct rather than seven positional arguments because four
    /// of them are optional strings: a call site that shifted `username` into
    /// `password` would compile and would send the password as the username.
    fn configure_apn(&mut self, _request: &ApnWrite<'_>) -> Result<JsonValue, SendError> {
        Err(unsupported("configure_apn"))
    }

    /// Rename one profile on the card, or clear its name.
    fn rename_esim_profile(
        &mut self,
        _imei: &str,
        _iccid: &str,
        _nickname: &str,
    ) -> Result<JsonValue, SendError> {
        Err(unsupported("rename_esim_profile"))
    }

    /// Take one profile out of service without enabling another.
    fn disable_esim_profile(&mut self, _imei: &str, _iccid: &str) -> Result<JsonValue, SendError> {
        Err(unsupported("disable_esim_profile"))
    }

    /// Remove one profile from the card. Irreversible.
    fn delete_esim_profile(&mut self, _imei: &str, _iccid: &str) -> Result<JsonValue, SendError> {
        Err(unsupported("delete_esim_profile"))
    }

    /// Approve one observed endpoint for an identity probe.
    ///
    /// It takes a key and nothing else on purpose: the command approves
    /// something the agent already saw, and accepting a port or an IMEI here
    /// would let the cloud describe hardware nobody has looked at.
    fn claim_modem_candidate(&mut self, _candidate_key: &str) -> Result<JsonValue, SendError> {
        Err(unsupported("claim_modem_candidate"))
    }

    /// Take that approval back: stop probing an endpoint somebody nodded at.
    ///
    /// The agent refuses when the module behind it is currently managed.
    /// Revoking then would leave a registered module nothing talks to -- it
    /// keeps its row, keeps appearing in `managed_imeis`, and produces no
    /// alert, because the silence watchdog watches devices rather than
    /// modules. Unmanage first, then revoke.
    fn revoke_modem_candidate(&mut self, _candidate_key: &str) -> Result<JsonValue, SendError> {
        Err(unsupported("revoke_modem_candidate"))
    }

    /// The agent's own recent log lines.
    ///
    /// The same ring the LAN panel serves. It exists because reaching these
    /// lines otherwise means an SSH session and `journalctl`, which is the
    /// access neither an on-site operator nor a cloud one has.
    /// Start managing a module the agent has already identified.
    fn register_modem(&mut self, _imei: &str, _note: Option<&str>) -> Result<JsonValue, SendError> {
        Err(unsupported("register_modem"))
    }

    /// Stop managing a module. What it produced is kept.
    fn unregister_modem(&mut self, _imei: &str) -> Result<JsonValue, SendError> {
        Err(unsupported("unregister_modem"))
    }

    /// Adopt a module the agent has never seen. The C that `register_modem`
    /// does not cover.
    ///
    /// That one refuses an IMEI nothing has observed, which is right when the
    /// hardware is on the bus and wrong when somebody is building the register
    /// ahead of the machine arriving. The cost is that no observation exists to
    /// check the input against, so the family is required and the IMEI is
    /// validated here rather than taken on trust.
    ///
    /// The record it writes has NOT passed the adoption gates -- there is
    /// nothing to run them against. Retroactive enforcement answers
    /// `Hold(NeverObserved)` for it: alerted, never unbound. The first real
    /// verdict happens on the pass where the hardware finally appears.
    fn create_modem(
        &mut self,
        _imei: &str,
        _family: &str,
        _note: Option<&str>,
    ) -> Result<JsonValue, SendError> {
        Err(unsupported("create_modem"))
    }

    /// Edit an adopted module's record. The U in this catalogue's CRUD.
    ///
    /// Only the note moves. The adoption date and who made the decision are
    /// provenance, not fields: the only way to change them was unregister and
    /// re-register, which rewrites them to today -- and that is exactly what
    /// this exists to avoid.
    ///
    /// `None` clears the note. There is no way to say "leave it alone",
    /// because a caller who wants that does not send this command.
    fn update_modem(&mut self, _imei: &str, _note: Option<&str>) -> Result<JsonValue, SendError> {
        Err(unsupported("update_modem"))
    }

    /// Re-run the adoption gates against a module the gates have marked.
    ///
    /// Not a way to silence the mark. The agent clears it only when the gates
    /// pass again; when they still refuse it keeps the mark and restarts the
    /// quarantine countdown, so somebody fixing the real cause -- usually by
    /// pushing a matrix -- is not raced by the grace period. Adoption
    /// provenance is never touched: the existing workaround is unregister and
    /// re-register, which rewrites it to today.
    fn reconfirm_modem(&mut self, _imei: &str) -> Result<JsonValue, SendError> {
        Err(unsupported("reconfirm_modem"))
    }

    fn read_logs(
        &mut self,
        _after: Option<u64>,
        _limit: Option<u32>,
        _contains: Option<&str>,
    ) -> Result<JsonValue, SendError> {
        Err(unsupported("read_logs"))
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

    /// Store the card policy set the cloud just pushed.
    ///
    /// The whole set arrives every time and replaces what is held, so an
    /// implementation must not merge: a card the cloud has stopped listing has
    /// had its policy withdrawn.
    ///
    /// Takes the policies as the contract carries them. The agent deliberately
    /// does not interpret `vertical` on the way in -- an unrecognised value
    /// still has to be written down, or a newer build could not act on it
    /// without asking the cloud to push again.
    fn update_card_policies(
        &mut self,
        _policy_version: &str,
        _policies: &[CardPolicy],
    ) -> Result<JsonValue, SendError> {
        Err(unsupported("update_card_policy"))
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

    /// What the eUICC says about itself: EID, chip information, and the
    /// notifications it has not managed to hand to an SM-DP+.
    ///
    /// Read-only. Nothing here changes anything on the chip.
    fn read_esim_info(&mut self, _imei: &str) -> Result<JsonValue, SendError> {
        Err(unsupported("read_esim_info"))
    }

    /// Fetch one pending notification off the eUICC by sequence number.
    ///
    /// The first of the three steps in a notification retry. The other two —
    /// posting it to the SM-DP+ and then removing it from the card — need an
    /// HTTP client and a write, and this reads.
    fn retrieve_esim_notification(
        &mut self,
        _imei: &str,
        _sequence_number: i64,
    ) -> Result<JsonValue, SendError> {
        Err(unsupported("retrieve_esim_notification"))
    }

    /// Start an ES9+ session with an SM-DP+ and stop at its signed answer.
    ///
    /// Read-only on both sides. `InitiateAuthentication` is the one ES9+
    /// function that needs no activation code and leaves no trace on an
    /// account, so it is what proves the chain from this chip to a real
    /// server without touching either.
    ///
    /// `smdp_address` is optional because the chip usually knows one: its
    /// configured default, or failing that the address its pending
    /// notifications name.
    fn initiate_esim_authentication(
        &mut self,
        _imei: &str,
        _smdp_address: Option<&str>,
    ) -> Result<JsonValue, SendError> {
        Err(unsupported("initiate_esim_authentication"))
    }

    /// Download one profile from an SM-DP+ and install it on the eUICC.
    ///
    /// The one action in this trait that cannot be undone from here. It
    /// installs and it does not enable: SGP.22 keeps those apart, and a module
    /// whose only working profile was replaced by an untested one is a module
    /// that is off the network with nobody able to reach it.
    ///
    /// The activation code is a one-time credential. It is a parameter and
    /// never a field of the result.
    fn download_esim_profile(
        &mut self,
        _imei: &str,
        _activation_code: &str,
        _confirmation_code: Option<&str>,
    ) -> Result<JsonValue, SendError> {
        Err(unsupported("download_esim_profile"))
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
#[derive(Clone, Debug)]
pub struct FakeSendPort {
    sent: Vec<SmsSend>,
    restarted: Vec<String>,
    error: Option<SendError>,
    context: OperatingContext,
    persisted_matrix: Option<(String, String, String)>,
}

impl Default for FakeSendPort {
    fn default() -> Self {
        Self {
            sent: Vec::new(),
            restarted: Vec::new(),
            error: None,
            context: measured_context(),
            persisted_matrix: None,
        }
    }
}

/// An EC20 on China Mobile: the pairing the shipped ledger records as working.
fn measured_context() -> OperatingContext {
    OperatingContext {
        family: edge_core::ModemFamily::EC20,
        carrier: edge_core::CarrierProfile::CN_MOBILE,
        subscription: edge_core::SubscriptionCapability::default(),
    }
}

impl FakeSendPort {
    pub fn new() -> Self {
        Self::default()
    }

    /// Present as a module and network nobody has measured, so the ledger
    /// refuses. The point of a knob rather than a second fake: the refusal has
    /// to be reachable through the same path a real send takes.
    pub fn unmeasured(&mut self) -> &mut Self {
        self.context.family = edge_core::ModemFamily::from("SIM7600G");
        self
    }

    /// Declare what the plan on this card is sold as doing.
    pub fn with_subscription(
        &mut self,
        subscription: edge_core::SubscriptionCapability,
    ) -> &mut Self {
        self.context.subscription = subscription;
        self
    }

    /// What was handed over for storage, if anything.
    pub fn persisted_matrix(&self) -> Option<(String, String, String)> {
        self.persisted_matrix.clone()
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
    /// A module and card the built-in matrix has a measured rule for.
    ///
    /// Chosen so the fake exercises the *send*, not the refusal: an EC20 on
    /// China Mobile is the pairing the shipped ledger records as working. A
    /// test that wants the refusal path builds a context that has none, which
    /// is what `unmeasured` is for.
    fn operating_context(&mut self, _imei: Option<&str>) -> Result<OperatingContext, SendError> {
        Ok(self.context.clone())
    }

    fn persist_capability_matrix(
        &mut self,
        version: &str,
        sha256: &str,
        document: &str,
    ) -> Result<(), SendError> {
        self.persisted_matrix = Some((version.to_owned(), sha256.to_owned(), document.to_owned()));
        Ok(())
    }

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
            return Err(SendError::new(
                "update_sha256_missing",
                "self-update sha256 is required",
            ));
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
    /// The chip contents this command happened to read, when it read a whole
    /// one and the reading is fit to send.
    ///
    /// Set only on the delivery that actually ran the command. A replay must
    /// not resend it: the inventory is a separate sequenced envelope with its
    /// own id, so a second copy would consume a second sequence number and
    /// project the same rows again for nothing.
    pub inventory: Option<EsimInventoryPayload>,
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
    /// 🔴 版本号是个**看得出是假的**占位值，因为这个 crate 不可能知道调用它的
    /// 二进制是哪一版。生产侧必须用 `with_updater` 传
    /// `env!("CARGO_PKG_VERSION")`（`edge-bin` 就是这么做的）。
    ///
    /// ⚠️ 这里原来写的是 `"0.1.0"` —— 一个**看起来像真的**版本号，而生产路径
    /// 当时正好走的就是 `new()`。
    ///
    /// 🔴 **它当时是对的，而这正是它危险的地方。** workspace 的版本号恰好也是
    /// `0.1.0`，所以守卫报的和上行 hello 报的
    /// （`env!("CARGO_PKG_VERSION")`）**碰巧一致**——没有任何症状，没有任何人
    /// 会去查。分叉会在**第一次升版本号**的那一刻发生：hello 报新版本，而守卫
    /// 仍然报 `0.1.0`，然后拿这个陈旧的数字去判「刷进去的是不是新的」。
    ///
    /// 一个靠巧合正确的常量，比一个明显错的常量更难发现。占位值就该长得像
    /// 占位值——`0.0.0-version-not-supplied` 泄漏到任何地方都会被一眼认出来。
    pub fn new(port: P) -> Self {
        Self::with_updater(port, RejectUpdate::new("0.0.0-version-not-supplied"))
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
            return Err(CommandError::UnexpectedKind(
                envelope.kind.as_str().to_string(),
            ));
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
        match self
            .commands
            .get(&payload.cmd_id)
            .map(|stored| stored.phase)
        {
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
        // Filled by `execute`, and only by the two branches of it that read a
        // whole chip. A delivery that did not execute -- expired, replayed, or
        // interrupted -- leaves it empty, which is what stops a reconnect from
        // spending a second sequence number to project rows that are there.
        let mut inventory = None;
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
            self.execute(&payload, now_ms, attempts, &mut inventory)?
        };
        let sequence = self.store_terminal(&payload.cmd_id, result.clone())?;

        Ok(DeliveryOutcome {
            receipt,
            result,
            result_sequence: sequence,
            executed,
            inventory,
        })
    }

    fn replay(&self, cmd_id: &str, delivery_id: &str, now_ms: i64) -> Option<DeliveryOutcome> {
        let stored = self.commands.get(cmd_id)?;
        let result = stored.result.clone()?;
        let sequence = stored.result_sequence?;
        Some(DeliveryOutcome {
            receipt: receipt(cmd_id, delivery_id, RECEIPT_DUPLICATE, now_ms),
            result,
            result_sequence: sequence,
            executed: false,
            inventory: None,
        })
    }

    fn execute(
        &mut self,
        payload: &CommandDeliverPayload,
        now_ms: i64,
        attempts: i64,
        inventory: &mut Option<EsimInventoryPayload>,
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
                // Decided before the modem is touched: a send that the
                // measured (module, network) pair or the card's own plan does
                // not cover must not be attempted and then explained. The
                // refusal names which of the three layers withheld it, so the
                // reader is told whether the fix is a test, a different
                // module, or a form somebody has to fill in.
                let outcome =
                    match self.refuse_unsupported(modem_imei.as_deref(), Operation::SmsSend) {
                        Some(refusal) => Err(refusal),
                        // Same shape as the diagnostic relays: whatever the port
                        // reported travels back in `details`. For a send that is
                        // the message reference, which the cloud stores against
                        // the message so a later status report settles the right
                        // one.
                        None => self.port.send_sms(&send),
                    };
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
            } => match install_matrix(
                matrix_version,
                matrix_sha256,
                matrix,
                self.guard.current.as_str(),
            ) {
                Ok(parsed) => {
                    self.matrix = parsed;
                    // Stored after the parse, so a restart cannot load a
                    // document this agent rejected.
                    match serde_json::to_string(matrix) {
                        Ok(document) => {
                            if let Err(error) = self.port.persist_capability_matrix(
                                matrix_version,
                                matrix_sha256,
                                &document,
                            ) {
                                // Reported, not fatal: see the port method.
                                eprintln!(
                                    "capability matrix not persisted, it will be lost on restart: {}",
                                    error.message
                                );
                            }
                        }
                        Err(error) => eprintln!(
                            "capability matrix not serialisable, it will be lost on restart: {error}"
                        ),
                    }
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
                force,
            } => {
                self.mark_executing(&payload.cmd_id);
                // The contract makes `force` optional, so an absent field is
                // the safe reading: not forced. Defaulting the other way would
                // let a command with the field omitted run a disruptive AT.
                let outcome =
                    self.port
                        .run_at(modem_imei, command, *timeout_ms, force.unwrap_or(false));
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
            Command::ConfigureApn {
                modem_imei,
                cid,
                pdp_type,
                apn,
                username,
                password,
                auth,
            } => {
                self.mark_executing(&payload.cmd_id);
                let outcome = self.port.configure_apn(&ApnWrite {
                    imei: modem_imei,
                    // The contract carries the identifier as an integer and
                    // constrains it to 0..=255 there; the port is typed to
                    // that range. A value outside it cannot have passed
                    // validation, so clamping is unreachable rather than
                    // lossy -- and it is still better than a cast that would
                    // silently wrap 256 to 0, which is a context that exists.
                    cid: u8::try_from(*cid).unwrap_or(u8::MAX),
                    pdp_type: pdp_type.as_deref(),
                    apn,
                    username: username.as_deref(),
                    password: password.as_deref(),
                    auth: auth.as_deref(),
                });
                Ok((
                    diagnostic_result(&payload.cmd_id, now_ms, attempts, outcome),
                    true,
                ))
            }
            Command::RenameEsimProfile {
                modem_imei,
                iccid,
                nickname,
            } => {
                self.mark_executing(&payload.cmd_id);
                let outcome = self.port.rename_esim_profile(
                    modem_imei,
                    iccid,
                    nickname.as_deref().unwrap_or_default(),
                );
                Ok((
                    diagnostic_result(&payload.cmd_id, now_ms, attempts, outcome),
                    true,
                ))
            }
            Command::DisableEsimProfile { modem_imei, iccid } => {
                self.mark_executing(&payload.cmd_id);
                let outcome = self.port.disable_esim_profile(modem_imei, iccid);
                Ok((
                    diagnostic_result(&payload.cmd_id, now_ms, attempts, outcome),
                    true,
                ))
            }
            Command::DeleteEsimProfile { modem_imei, iccid } => {
                self.mark_executing(&payload.cmd_id);
                let outcome = self.port.delete_esim_profile(modem_imei, iccid);
                Ok((
                    diagnostic_result(&payload.cmd_id, now_ms, attempts, outcome),
                    true,
                ))
            }
            Command::ClaimModemCandidate { candidate_key } => {
                self.mark_executing(&payload.cmd_id);
                let outcome = self.port.claim_modem_candidate(candidate_key);
                Ok((
                    diagnostic_result(&payload.cmd_id, now_ms, attempts, outcome),
                    true,
                ))
            }
            Command::RevokeModemCandidate { candidate_key } => {
                self.mark_executing(&payload.cmd_id);
                let outcome = self.port.revoke_modem_candidate(candidate_key);
                Ok((
                    diagnostic_result(&payload.cmd_id, now_ms, attempts, outcome),
                    true,
                ))
            }
            Command::RegisterModem { modem_imei, note } => {
                self.mark_executing(&payload.cmd_id);
                let outcome = self.port.register_modem(modem_imei, note.as_deref());
                Ok((
                    diagnostic_result(&payload.cmd_id, now_ms, attempts, outcome),
                    true,
                ))
            }
            Command::UnregisterModem { modem_imei } => {
                self.mark_executing(&payload.cmd_id);
                let outcome = self.port.unregister_modem(modem_imei);
                Ok((
                    diagnostic_result(&payload.cmd_id, now_ms, attempts, outcome),
                    true,
                ))
            }
            Command::CreateModem {
                modem_imei,
                family,
                note,
            } => {
                self.mark_executing(&payload.cmd_id);
                let outcome = self.port.create_modem(modem_imei, family, note.as_deref());
                Ok((
                    diagnostic_result(&payload.cmd_id, now_ms, attempts, outcome),
                    true,
                ))
            }
            Command::UpdateModem { modem_imei, note } => {
                self.mark_executing(&payload.cmd_id);
                let outcome = self.port.update_modem(modem_imei, note.as_deref());
                Ok((
                    diagnostic_result(&payload.cmd_id, now_ms, attempts, outcome),
                    true,
                ))
            }
            Command::ReconfirmModem { modem_imei } => {
                self.mark_executing(&payload.cmd_id);
                let outcome = self.port.reconfirm_modem(modem_imei);
                Ok((
                    diagnostic_result(&payload.cmd_id, now_ms, attempts, outcome),
                    true,
                ))
            }
            Command::ReadLogs {
                after,
                limit,
                contains,
            } => {
                self.mark_executing(&payload.cmd_id);
                // Both are integers in the contract and bounded there --
                // `after` at zero and above, `limit` at 1..=500. A negative
                // that reached here could not have been validated, and
                // treating it as absent is the reading that cannot invent a
                // cursor.
                let outcome = self.port.read_logs(
                    after.and_then(|value| u64::try_from(value).ok()),
                    limit.and_then(|value| u32::try_from(value).ok()),
                    contains.as_deref(),
                );
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
            Command::UpdateCardPolicy {
                policy_version,
                policies,
            } => {
                self.mark_executing(&payload.cmd_id);
                let outcome = self.port.update_card_policies(policy_version, policies);
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
                // The list changes at exactly this moment and at no other, so
                // this is where the stored inventory has to be brought level
                // with the card.
                *inventory = esim_inventory(outcome.as_ref());
                Ok((
                    diagnostic_result(&payload.cmd_id, now_ms, attempts, outcome),
                    true,
                ))
            }
            Command::ReadEsimInfo { modem_imei } => {
                self.mark_executing(&payload.cmd_id);
                let outcome = self.port.read_esim_info(modem_imei);
                // The chip is already on the stack here. The envelope costs no
                // extra APDU and no second ISD-R channel.
                *inventory = esim_inventory(outcome.as_ref());
                Ok((
                    diagnostic_result(&payload.cmd_id, now_ms, attempts, outcome),
                    true,
                ))
            }
            Command::RetrieveEsimNotification {
                modem_imei,
                sequence_number,
            } => {
                self.mark_executing(&payload.cmd_id);
                let outcome = self
                    .port
                    .retrieve_esim_notification(modem_imei, *sequence_number);
                Ok((
                    diagnostic_result(&payload.cmd_id, now_ms, attempts, outcome),
                    true,
                ))
            }
            Command::InitiateEsimAuthentication {
                modem_imei,
                smdp_address,
            } => {
                self.mark_executing(&payload.cmd_id);
                let outcome = self
                    .port
                    .initiate_esim_authentication(modem_imei, smdp_address.as_deref());
                Ok((
                    diagnostic_result(&payload.cmd_id, now_ms, attempts, outcome),
                    true,
                ))
            }
            Command::DownloadEsimProfile {
                modem_imei,
                activation_code,
                confirmation_code,
            } => {
                self.mark_executing(&payload.cmd_id);
                let outcome = self.port.download_esim_profile(
                    modem_imei,
                    activation_code,
                    confirmation_code.as_deref(),
                );
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
            } // No catch-all. `update_card_policy` was the last kind the
              // contract carried and this match did not, and while the arm was
              // missing the cloud's push came back `unsupported_command` -- a
              // runtime answer to what is really a build-time question.
              //
              // Exhaustiveness is the guard now: a kind added to the contract
              // stops the build here until somebody decides what it does. A
              // *port* that cannot perform an action it was handed still refuses
              // at run time, through the trait defaults, which is a different
              // fact and keeps its own reason code.
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
            inventory: None,
        })
    }

    /// `Some(refusal)` when this operation must not be attempted.
    ///
    /// The three layers are resolved in `edge-core`; what happens here is
    /// only the plumbing — asking the port what module and card it is holding,
    /// and turning a refusal into the error a `CommandResult` carries.
    ///
    /// A port that cannot describe its own module refuses too. That is the
    /// deliberate direction to fail: the whole point of the ledger is that
    /// nothing runs on hardware nobody has measured, and "we could not work
    /// out what this is" is the strongest possible case of that.
    fn refuse_unsupported(
        &mut self,
        imei: Option<&str>,
        operation: Operation,
    ) -> Option<SendError> {
        let context = match self.port.operating_context(imei) {
            Ok(context) => context,
            Err(error) => {
                return Some(SendError::new(
                    "operating_context_unavailable",
                    format!(
                        "could not establish which module and card this is, so {} was not attempted: {}",
                        operation.wire(),
                        error.message
                    ),
                ));
            }
        };

        let ledger = SupportLedger::from_matrix(&self.matrix);
        let registry = match builtin_strategy_registry(ledger) {
            Ok(registry) => registry,
            Err(error) => {
                // A registry that will not build is a fault in this binary,
                // not in the request. It still refuses: acting on a policy
                // that could not be assembled is the one outcome worse than
                // not acting.
                return Some(SendError::new(
                    "strategy_registry_invalid",
                    error.to_string(),
                ));
            }
        };

        let resolved = registry.resolve(
            &context.family,
            &context.carrier,
            &context.subscription,
            operation,
        );
        match resolved.support {
            edge_core::Support::Supported(_) => None,
            edge_core::Support::Unsupported { by, reason } => Some(SendError::new(
                format!("{}_refused_by_{}", operation.wire(), by.wire()),
                match by {
                    RefusedBy::Ledger => format!(
                        "{reason}. Nothing is attempted on an untested pairing; measure it and record the result."
                    ),
                    _ => reason,
                },
            )),
        }
    }

    /// Adopt a matrix read back from storage at startup.
    ///
    /// The counterpart to `persist_capability_matrix`. Separate from a
    /// constructor argument because the caller has to parse the stored
    /// document first, and a document that no longer parses -- a downgrade, a
    /// corrupted row -- should leave the built-in one standing rather than
    /// stop the agent starting.
    pub fn restore_matrix(&mut self, matrix: CapabilityMatrix) {
        self.matrix = matrix;
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
    running_version: &str,
) -> Result<CapabilityMatrix, (&'static str, String)> {
    let bytes = serde_json::to_vec(matrix).map_err(|err| ("matrix_invalid", err.to_string()))?;
    let digest = hex_sha256(&bytes);
    if !digest.eq_ignore_ascii_case(matrix_sha256.trim()) {
        return Err((
            "matrix_sha256_mismatch",
            "capability matrix sha256 does not match".to_string(),
        ));
    }
    let value = serde_json::to_value(matrix).map_err(|err| ("matrix_invalid", err.to_string()))?;
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
    // 🔴 本 build 够不够格读这份文档。不够就**整份拒绝**，上一份原样留着。
    //
    // 理由不是洁癖：`MatrixDocument` 没有 `deny_unknown_fields`，所以一个
    // 旧 build 读到带 `[[device]]` 的新文档会**静默地**把整段丢掉 ——
    // 也就是没有纳管的闸 1，而且不报错。滚动升级期间这必然发生，
    // 而「装了一半」比「没装」难查得多：云端看到 succeeded，边缘却在按
    // 一份它读不全的文档做纳管决定。
    //
    // 拒绝在这里，是因为这是**唯一**的安装点：拒了就既不会进内存，
    // 也不会被 persist（那一步在调用方，只在 Ok 之后才走）。
    match parsed.version_check(running_version) {
        check if check.admits() => {}
        edge_core::VersionCheck::TooOld { required, running } => {
            return Err((
                "matrix_needs_newer_agent",
                format!(
                    "capability matrix requires agent {required}, this one is {running}; \
                     keeping the previous matrix"
                ),
            ));
        }
        edge_core::VersionCheck::Unreadable { required, running } => {
            return Err((
                "matrix_needs_newer_agent",
                format!(
                    "capability matrix requires agent {required:?} and this one reports \
                     {running:?}; neither can be compared, so the matrix is refused rather \
                     than assumed compatible"
                ),
            ));
        }
        // admits() 已经覆盖，这里只是让 match 穷举 —— 加变体时编译失败。
        edge_core::VersionCheck::NotRequired | edge_core::VersionCheck::Satisfied => {}
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

/// Key the edge carries an `EsimInventory` payload under inside the reading a
/// chip command returns.
///
/// The inventory travels with the reading rather than on a side channel so
/// that what the projection stores and what the console displays come from one
/// read of one chip. Two paths would eventually disagree, and the disagreement
/// would look exactly like a card that had changed.
const INVENTORY_DETAIL_KEY: &str = "inventory";

/// The chip inventory a reading is carrying, if it is fit to send.
///
/// Read out of the port's own JSON rather than out of the finished
/// `CommandResult`. The result's `details` are a `ContextValue`, whose numbers
/// are `f64` -- `collected_at` survives the trip as `1756000000000.0`, which is
/// not an integer and will not parse back into the payload. The reading is also
/// the earlier and more truthful of the two.
///
/// Only two commands ever call this, and that is enforced by where it is
/// called from: `read_esim_info`, which has the whole chip on hand already so
/// the envelope costs no extra APDU, and `switch_esim_profile`, the one
/// operation that changes which ICCID is enabled. Nothing polls: this payload
/// is `sequenced` and may be 128 KiB, so a periodic copy would be an expensive
/// heartbeat carrying an answer that only changes when a person changes it.
fn esim_inventory(reading: Result<&JsonValue, &SendError>) -> Option<EsimInventoryPayload> {
    let payload: EsimInventoryPayload =
        serde_json::from_value(reading.ok()?.get(INVENTORY_DETAIL_KEY)?.clone()).ok()?;
    // The last gate before the wire, and the only one that knows the contract.
    // The modem crate decides what the inventory *is*; this decides whether it
    // may be sent, because a payload the cloud cannot store is worse than none:
    // it is counted as a contract violation, and a projection run against half
    // an inventory marks the profiles it is missing as deleted.
    inventory_fits_contract(&payload).then_some(payload)
}

/// Whether an inventory payload matches every shape the uplink schema fixes.
fn inventory_fits_contract(payload: &EsimInventoryPayload) -> bool {
    if !digits_within(&payload.modem_imei, 14, 16) {
        return false;
    }
    if !digits_within(&payload.eid, 32, 32) {
        return false;
    }
    if !(0..=MAX_EPOCH_MILLIS).contains(&payload.collected_at) {
        return false;
    }
    if payload.profiles.len() > MAX_INVENTORY_PROFILES {
        return false;
    }
    payload.profiles.iter().all(|profile| {
        digits_within(&profile.iccid, 19, 20)
            && PROFILE_STATES.contains(&profile.state.as_str())
            && profile
                .nickname
                .as_ref()
                .map_or(true, |nickname| nickname.chars().count() <= 256)
    })
}

fn digits_within(value: &str, shortest: usize, longest: usize) -> bool {
    (shortest..=longest).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_digit())
}

/// The four profile states the cloud will store, from the uplink schema.
const PROFILE_STATES: [&str; 4] = ["enabled", "disabled", "deleted", "unknown"];

/// Largest `collected_at` the uplink schema allows, in epoch milliseconds.
const MAX_EPOCH_MILLIS: i64 = 253_402_300_799_999;

/// Most profiles one inventory payload may carry.
const MAX_INVENTORY_PROFILES: usize = 64;

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
