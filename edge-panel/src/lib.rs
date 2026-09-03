//! Local LAN panel. It reads only the SQLite cache so it still works offline.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::{header, HeaderValue, StatusCode, Uri};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use edge_core::{CapabilityMatrix, CarrierProfile, ModemFamily, Network};
use edge_panel_api::{
    AtBody, ClaimCandidateBody, DiscoveryBody, MessageBody, MessagesBody, ModemBody, PanelMode,
    RadioBody, RegistrationBody, ResetBody, RestartBody, SendBody, StatusBody, SwitchBody, UssdBody,
};

/// The `Actions` trait below returns these, so whoever implements it reaches
/// for them here — re-exported rather than made a second import.
///
/// ⚠️ They are **defined** in `edge-panel-api` so the browser half can
/// deserialise into the same types; this crate is where they are *used*, and
/// `edge-bin` implements `Actions` against it. Sending an implementor to a
/// second crate for the return types of a trait it found here would be worse
/// ergonomics for no gain — there is still exactly one definition.
pub use edge_panel_api::{
    AtResult, CandidateClaimResult, ProfileBody, ProfilesResult, RegistrationResult, ReportResult,
    RescanResult, ScanResult, ScannedOperatorBody, UsbResetResult, UssdResult,
};
use edge_store::{LocalMessage, LocalModem, LocalModemDiscovery, Store, StoreError};

mod logs;
pub use logs::{log_error, log_line, LogLine, LogRing};

const INDEX: &str = include_str!("index.html");

/// The Leptos panel's bundle, served at `/next` while the old panel keeps `/`.
///
/// 🔴 **Embedded, not read from disk.** The agent ships as one binary onto a
/// machine that may have no filesystem layout we control, and the existing
/// panel has always been a single `include_str!`. A rewrite that quietly added
/// "and these three files next to it" would be a regression in the one property
/// that makes this panel usable when everything else is broken.
///
/// 🔴 Built with `--filehash false`, so the names are stable and this block
/// never needs editing. The first version kept trunk's content hash, which
/// meant **every rebuild of `edge-ui` renamed the files and left the router
/// pointing at names that no longer existed** — a trap that would have sprung
/// on the very first feature area of the migration.
///
/// Dropping the hash drops cache-busting, so the two handlers answer
/// `no-cache` instead. That is the right trade here: half a megabyte over a
/// LAN, for a diagnostic tool whose whole job is to be current at the moment
/// something is wrong.
const NEXT_INDEX: &str = include_str!("../../edge-ui/dist/index.html");
const NEXT_JS: &str = include_str!("../../edge-ui/dist/edge-ui.js");
const NEXT_WASM: &[u8] = include_bytes!("../../edge-ui/dist/edge-ui_bg.wasm");

/// How long a modem row stays trustworthy after its last successful poll.
///
/// A modem that stops answering keeps its row in the store. Without an age check
/// the panel presents a stick that was unplugged hours ago as if it were still
/// searching for a network, which is worse than saying nothing about it.
const STALE_AFTER_MS: i64 = 60_000;

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or(0)
}

/// Read-only view of locally cached modems and SMS.
pub trait Inbox: Send + Sync {
    fn list_messages(&self) -> Result<Vec<LocalMessage>, PanelError>;
    fn list_modems(&self) -> Result<Vec<LocalModem>, PanelError>;
    /// Hardware endpoints observed by the poller, including ones that could
    /// not provide an IMEI and therefore are not modem inventory records.
    fn list_modem_discoveries(&self) -> Result<Vec<LocalModemDiscovery>, PanelError> {
        Ok(Vec::new())
    }
}

/// Local send/restart actions. Optional so a read-only panel still works.
pub trait Actions: Send + Sync {
    /// `commission` sends on a pairing the ledger has not measured, so that it
    /// can be measured. See `SendBody`.
    fn send_sms(
        &self,
        to: String,
        body: String,
        imei: Option<String>,
        commission: bool,
    ) -> Result<(), PanelError>;
    fn restart_modem(&self, imei: String) -> Result<(), PanelError>;
    /// Run one AT command against a modem's control port.
    ///
    /// A module that answers `+CME ERROR` has answered, so that comes back as
    /// `Ok` carrying the error terminator. Only losing the port is an `Err`:
    /// a console has to show what the module actually said.
    fn at_command(
        &self,
        imei: Option<String>,
        command: String,
        force: bool,
    ) -> Result<AtResult, PanelError>;
    /// Re-enumerate a modem's USB device.
    ///
    /// `restart_modem` goes through QMI, so it cannot recover a module whose
    /// QMI stack has desynced — allocating a client to send the restart is
    /// itself a QMI request. This is the path that works when that one cannot.
    fn usb_reset(&self, imei: Option<String>) -> Result<UsbResetResult, PanelError>;
    /// Read-only diagnostic snapshot of one modem.
    fn modem_report(&self, imei: Option<String>) -> Result<ReportResult, PanelError>;
    /// List the profiles held by a modem's eUICC.
    fn list_profiles(&self, imei: Option<String>) -> Result<ProfilesResult, PanelError>;
    /// Enable or disable one eUICC profile by ICCID.
    fn switch_profile(
        &self,
        imei: Option<String>,
        iccid: String,
        enable: bool,
    ) -> Result<(), PanelError>;
    /// Sweep for visible networks. This takes the radio away for as long as the
    /// scan runs, so the modem serves nothing while it is in progress.
    fn scan_operators(&self, imei: Option<String>) -> Result<ScanResult, PanelError>;
    /// Run one USSD request and wait for the network's reply.
    fn ussd(&self, imei: Option<String>, code: String) -> Result<UssdResult, PanelError>;
    /// Cancel an open USSD session.
    fn ussd_cancel(&self, imei: Option<String>) -> Result<(), PanelError>;
    /// Put a modem's radio into low power or bring it back online.
    ///
    /// This goes through QMI rather than `AT+CFUN`, whose reset form wedges a
    /// module often enough that it is not worth exposing on a button.
    fn set_radio(&self, imei: Option<String>, online: bool) -> Result<(), PanelError>;
    /// Ask the hardware poll loop to enumerate again immediately. The result
    /// describes the kernel endpoints visible before probing; the updated
    /// status appears on the next poll rather than claiming a synchronous
    /// hardware operation completed.
    fn rescan_modems(&self) -> Result<RescanResult, PanelError> {
        Err(PanelError::Action("local modem rescan is not configured".into()))
    }
    /// Persist an operator approval for one already discovered serial
    /// endpoint. Implementations must re-check the live endpoint rather than
    /// accepting a free-form port name from the panel.
    fn claim_modem_candidate(
        &self,
        _candidate_key: String,
    ) -> Result<CandidateClaimResult, PanelError> {
        Err(PanelError::Action(
            "local modem candidate claim is not configured".into(),
        ))
    }
    /// Adopt an identified module, so the agent starts managing it.
    ///
    /// Implementations must confirm the IMEI belongs to a module the agent has
    /// actually seen. Accepting a free-form IMEI from the panel would let an
    /// operator adopt hardware that is not there and then wonder why it is
    /// permanently offline.
    fn register_modem(
        &self,
        _imei: String,
        _source: &str,
    ) -> Result<RegistrationResult, PanelError> {
        Err(PanelError::Action(
            "local modem registration is not configured".into(),
        ))
    }

    /// Stop managing a module. History it produced is deliberately kept.
    fn unregister_modem(&self, _imei: String) -> Result<RegistrationResult, PanelError> {
        Err(PanelError::Action(
            "local modem registration is not configured".into(),
        ))
    }

    /// Modems currently executing an operator-initiated command.
    ///
    /// Such a modem stops answering the poll loop, and a long command outlasts
    /// the staleness window, so without this the panel calls a busy modem
    /// offline.
    fn busy_modems(&self) -> Vec<String> {
        Vec::new()
    }
}

/// Errors from the local panel store or a local action.
#[derive(Debug)]
pub enum PanelError {
    Store(StoreError),
    Action(String),
}

impl std::fmt::Display for PanelError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(error) => write!(formatter, "{error}"),
            Self::Action(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for PanelError {}

impl From<StoreError> for PanelError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

/// In-memory inbox used by panel tests.
#[derive(Clone, Debug, Default)]
pub struct MemoryInbox {
    pub messages: Vec<LocalMessage>,
    pub modems: Vec<LocalModem>,
    pub discoveries: Vec<LocalModemDiscovery>,
}

impl Inbox for MemoryInbox {
    fn list_messages(&self) -> Result<Vec<LocalMessage>, PanelError> {
        Ok(self.messages.clone())
    }

    fn list_modems(&self) -> Result<Vec<LocalModem>, PanelError> {
        Ok(self.modems.clone())
    }

    fn list_modem_discoveries(&self) -> Result<Vec<LocalModemDiscovery>, PanelError> {
        Ok(self.discoveries.clone())
    }
}

/// SQLite-backed inbox. The connection is not Sync, so it is locked per request.
pub struct StoreInbox {
    store: Mutex<Store>,
}

impl StoreInbox {
    pub fn new(store: Store) -> Self {
        Self {
            store: Mutex::new(store),
        }
    }
}

impl Inbox for StoreInbox {
    fn list_messages(&self) -> Result<Vec<LocalMessage>, PanelError> {
        let store = self.store.lock().expect("panel store lock");
        Ok(store.list_local_messages()?)
    }

    fn list_modems(&self) -> Result<Vec<LocalModem>, PanelError> {
        let store = self.store.lock().expect("panel store lock");
        Ok(store.list_managed_modems()?)
    }

    fn list_modem_discoveries(&self) -> Result<Vec<LocalModemDiscovery>, PanelError> {
        let store = self.store.lock().expect("panel store lock");
        Ok(store.list_local_modem_discoveries()?)
    }
}

struct PanelState {
    inbox: Arc<dyn Inbox>,
    actions: Option<Arc<dyn Actions>>,
    uplink_online: Arc<AtomicBool>,
    /// The matrix the agent is currently routing by, shared with the poll loop
    /// so a cloud-pushed replacement shows up here too. Queried rather than
    /// stored per modem: what a module can do is a property of the matrix in
    /// force, and a copy written into the row at probe time would go on
    /// claiming a rule that a later push removed.
    matrix: Arc<Mutex<CapabilityMatrix>>,
}

/// HTTP router for the offline panel. Bind it on the LAN; it does not call the cloud.
pub fn router(inbox: Arc<dyn Inbox>) -> Router {
    router_with_actions(inbox, None)
}

/// HTTP router with optional local send/restart actions.
pub fn router_with_actions(inbox: Arc<dyn Inbox>, actions: Option<Arc<dyn Actions>>) -> Router {
    router_with_uplink(inbox, actions, Arc::new(AtomicBool::new(false)))
}

/// HTTP router that reports capabilities against a caller-supplied matrix.
///
/// The layers above default to the compiled-in matrix. Only the agent passes
/// the live one, because only the agent can receive a replacement.
pub fn router_with_matrix(
    inbox: Arc<dyn Inbox>,
    actions: Option<Arc<dyn Actions>>,
    uplink_online: Arc<AtomicBool>,
    matrix: Arc<Mutex<CapabilityMatrix>>,
) -> Router {
    build_router(inbox, actions, uplink_online, matrix)
}

/// HTTP router whose reported mode follows a live uplink flag.
///
/// The panel used to report `local` unconditionally, so it kept claiming the
/// device was offline long after the cloud session was established.
pub fn router_with_uplink(
    inbox: Arc<dyn Inbox>,
    actions: Option<Arc<dyn Actions>>,
    uplink_online: Arc<AtomicBool>,
) -> Router {
    // The compiled-in matrix. A caller that can receive a pushed replacement
    // goes through `router_with_matrix` instead.
    let matrix = Arc::new(Mutex::new(
        CapabilityMatrix::builtin().unwrap_or_else(|error| {
            panic!("built-in capability matrix does not parse: {error}")
        }),
    ));
    build_router(inbox, actions, uplink_online, matrix)
}

fn build_router(
    inbox: Arc<dyn Inbox>,
    actions: Option<Arc<dyn Actions>>,
    uplink_online: Arc<AtomicBool>,
    matrix: Arc<Mutex<CapabilityMatrix>>,
) -> Router {
    Router::new()
        .route("/", get(index))
        // Stage 1 of the migration: both panels served at once. The old one
        // stays at `/` until the new one covers every function, because this
        // panel is the last visible window during a failure and a half-migrated
        // rewrite in its place is worse than the thing it replaces.
        .route("/next", get(next_index))
        .route("/next/edge-ui.js", get(next_js))
        .route("/next/edge-ui_bg.wasm", get(next_wasm))
        .route("/api/status", get(status))
        .route("/api/logs", get(read_logs))
        .route("/api/messages", get(messages))
        .route("/api/send", post(send_sms))
        .route("/api/restart", post(restart_modem))
        .route("/api/at", post(at_command))
        .route("/api/usb-reset", post(usb_reset))
        .route("/api/report", post(modem_report))
        .route("/api/esim", post(list_profiles))
        .route("/api/esim/switch", post(switch_profile))
        .route("/api/scan", post(scan_operators))
        .route("/api/ussd", post(ussd))
        .route("/api/ussd/cancel", post(ussd_cancel))
        .route("/api/radio", post(set_radio))
        .route("/api/rescan", post(rescan_modems))
        .route("/api/discoveries/claim", post(claim_modem_candidate))
        .route("/api/modems/register", post(register_modem))
        .route("/api/modems/unregister", post(unregister_modem))
        .with_state(Arc::new(PanelState {
            inbox,
            actions,
            uplink_online,
            matrix,
        }))
}

/// Serve the panel until the process exits.
pub async fn serve(
    bind: impl tokio::net::ToSocketAddrs,
    inbox: Arc<dyn Inbox>,
    actions: Option<Arc<dyn Actions>>,
    uplink_online: Arc<AtomicBool>,
    matrix: Arc<Mutex<CapabilityMatrix>>,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(
        listener,
        router_with_matrix(inbox, actions, uplink_online, matrix),
    )
    .await
}

async fn index() -> Html<&'static str> {
    Html(INDEX)
}

async fn next_index() -> Html<&'static str> {
    Html(NEXT_INDEX)
}

async fn next_js() -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/javascript"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        NEXT_JS,
    )
        .into_response()
}

async fn next_wasm() -> Response {
    (
        [
            (header::CONTENT_TYPE, "application/wasm"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        NEXT_WASM,
    )
        .into_response()
}

async fn status(State(state): State<Arc<PanelState>>) -> Response {
    let mode = if state.uplink_online.load(Ordering::Relaxed) {
        PanelMode::Cloud
    } else {
        PanelMode::Local
    };
    let now = now_ms();
    let busy = state
        .actions
        .as_ref()
        .map(|actions| actions.busy_modems())
        .unwrap_or_default();
    // Cloned out under its own lock rather than held across the loop: the
    // agent replaces this whole value when the cloud pushes a new matrix.
    let matrix = state.matrix.lock().expect("capability matrix").clone();
    match (state.inbox.list_modems(), state.inbox.list_modem_discoveries()) {
        (Ok(modems), Ok(discoveries)) => Json(StatusBody {
            mode,
            modems: modems
                .into_iter()
                .map(|modem| {
                    let is_busy = busy.iter().any(|imei| *imei == modem.imei);
                    modem_body(modem, now, is_busy, &matrix)
                })
                .collect(),
            discoveries: discoveries.into_iter().map(discovery_body).collect(),
        })
        .into_response(),
        _ => json_error(StatusCode::INTERNAL_SERVER_ERROR, "store unavailable"),
    }
}

/// The panel does not wait for a full probe here: one candidate can take a
/// few seconds, while the poll loop owns the radio lock and is the only place
/// allowed to build the durable observation. This endpoint only requests that
/// its ordinary wait is cut short.
async fn rescan_modems(State(state): State<Arc<PanelState>>) -> Response {
    let Some(actions) = state.actions.as_ref() else {
        return json_error(StatusCode::NOT_IMPLEMENTED, "local modem rescan is not configured");
    };
    match actions.rescan_modems() {
        Ok(result) => Json(serde_json::json!({
            "status": "requested",
            "found": result.found,
            "control_ports": result.control_ports,
        }))
        .into_response(),
        Err(error) => json_error(StatusCode::BAD_GATEWAY, error.to_string()),
    }
}

/// Save an explicit approval for an endpoint the ordinary discovery pass has
/// already shown. The poller, not this HTTP request, owns the eventual AT
/// probe so the radio lock and durable observation stay in one place.
async fn register_modem(
    State(state): State<Arc<PanelState>>,
    Json(body): Json<RegistrationBody>,
) -> Response {
    registration(state, body.imei, true).await
}

async fn unregister_modem(
    State(state): State<Arc<PanelState>>,
    Json(body): Json<RegistrationBody>,
) -> Response {
    registration(state, body.imei, false).await
}

/// Both directions, because they differ only in which action is called and a
/// second copy of the validation is a second place for it to drift.
async fn registration(state: Arc<PanelState>, imei: String, adopt: bool) -> Response {
    let Some(actions) = state.actions.as_ref() else {
        return json_error(
            StatusCode::NOT_IMPLEMENTED,
            "local modem registration is not configured",
        );
    };
    let imei = imei.trim().to_string();
    if imei.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "imei is required");
    }
    let outcome = if adopt {
        actions.register_modem(imei, "panel")
    } else {
        actions.unregister_modem(imei)
    };
    match outcome {
        Ok(result) => Json(result).into_response(),
        Err(error) => json_error(StatusCode::BAD_GATEWAY, error.to_string()),
    }
}

async fn claim_modem_candidate(
    State(state): State<Arc<PanelState>>,
    Json(body): Json<ClaimCandidateBody>,
) -> Response {
    let candidate_key = body.candidate_key.trim().to_string();
    if candidate_key.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "candidate_key is required");
    }
    let Some(actions) = state.actions.as_ref() else {
        return json_error(
            StatusCode::NOT_IMPLEMENTED,
            "local modem candidate claim is not configured",
        );
    };
    match actions.claim_modem_candidate(candidate_key) {
        Ok(result) => Json(serde_json::json!({
            "status": "claimed",
            "candidate_key": result.candidate_key,
        }))
        .into_response(),
        Err(error) => json_error(StatusCode::BAD_GATEWAY, error.to_string()),
    }
}

/// Serve log lines after a cursor.
///
/// Polling with a cursor rather than streaming keeps this working through the
/// kind of flaky link a site panel is reached over: a dropped request costs one
/// interval, not the session.
async fn read_logs(uri: Uri) -> Response {
    let ring = LogRing::global();
    let lines = ring.since(cursor_from_query(uri.query()));
    Json(serde_json::json!({ "lines": lines, "cursor": ring.cursor() })).into_response()
}

/// Read `after=<n>` without pulling in a query-string extractor. The panel
/// takes exactly one numeric parameter, and the crate deliberately builds axum
/// with a minimal feature set.
fn cursor_from_query(query: Option<&str>) -> u64 {
    query
        .unwrap_or_default()
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| *key == "after")
        .and_then(|(_, value)| value.parse().ok())
        .unwrap_or(0)
}

async fn messages(State(state): State<Arc<PanelState>>) -> Response {
    match state.inbox.list_messages() {
        Ok(rows) => Json(MessagesBody {
            messages: rows.into_iter().map(message_body).collect(),
        })
        .into_response(),
        Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "store unavailable"),
    }
}

async fn send_sms(
    State(state): State<Arc<PanelState>>,
    Json(body): Json<SendBody>,
) -> Response {
    let Some(actions) = state.actions.as_ref() else {
        return json_error(StatusCode::NOT_IMPLEMENTED, "local send is not configured");
    };
    if body.to.trim().is_empty() || body.body.trim().is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "to and body are required");
    }
    match actions.send_sms(body.to, body.body, body.imei, body.commission) {
        Ok(()) => Json(serde_json::json!({ "status": "sent" })).into_response(),
        Err(error) => json_error(StatusCode::BAD_GATEWAY, error.to_string()),
    }
}

/// Commands the operator types are passed through untouched. This endpoint is
/// the reason the panel is bound to the LAN and never exposed to the cloud:
/// `AT+CFUN=1,1` and friends can wedge a module, so the blast radius has to
/// stay inside the site.
async fn at_command(
    State(state): State<Arc<PanelState>>,
    Json(body): Json<AtBody>,
) -> Response {
    let Some(actions) = state.actions.as_ref() else {
        return json_error(StatusCode::NOT_IMPLEMENTED, "local AT is not configured");
    };
    let command = body.command.trim().to_string();
    if command.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "command is required");
    }
    match actions.at_command(body.imei, command, body.force) {
        Ok(result) => Json(result).into_response(),
        Err(error) => json_error(StatusCode::BAD_GATEWAY, error.to_string()),
    }
}

/// Taking the radio down disconnects the modem from its network, so the caller
/// states which way it should go rather than toggling blind.
async fn set_radio(
    State(state): State<Arc<PanelState>>,
    Json(body): Json<RadioBody>,
) -> Response {
    let Some(actions) = state.actions.as_ref() else {
        return json_error(StatusCode::NOT_IMPLEMENTED, "local radio control is not configured");
    };
    match actions.set_radio(body.imei, body.online) {
        Ok(()) => Json(serde_json::json!({ "status": "ok" })).into_response(),
        Err(error) => json_error(StatusCode::BAD_GATEWAY, error.to_string()),
    }
}

/// The network answers after the command returns, so this endpoint holds the
/// request until the reply arrives or the wait runs out.
async fn ussd(State(state): State<Arc<PanelState>>, Json(body): Json<UssdBody>) -> Response {
    let Some(actions) = state.actions.as_ref() else {
        return json_error(StatusCode::NOT_IMPLEMENTED, "local USSD is not configured");
    };
    let code = body.code.trim().to_string();
    if code.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "code is required");
    }
    match actions.ussd(body.imei, code) {
        Ok(result) => Json(result).into_response(),
        Err(error) => json_error(StatusCode::BAD_GATEWAY, error.to_string()),
    }
}

/// An abandoned session keeps the network waiting and blocks the next request,
/// so cancelling is a first-class action rather than something to work around.
async fn ussd_cancel(
    State(state): State<Arc<PanelState>>,
    Json(body): Json<ResetBody>,
) -> Response {
    let Some(actions) = state.actions.as_ref() else {
        return json_error(StatusCode::NOT_IMPLEMENTED, "local USSD is not configured");
    };
    match actions.ussd_cancel(body.imei) {
        Ok(()) => Json(serde_json::json!({ "status": "cancelled" })).into_response(),
        Err(error) => json_error(StatusCode::BAD_GATEWAY, error.to_string()),
    }
}

/// The scan runs for as long as the module needs to sweep every band, so this
/// endpoint is deliberately slow rather than returning early with a partial
/// list that would look like a complete one.
async fn scan_operators(
    State(state): State<Arc<PanelState>>,
    Json(body): Json<ResetBody>,
) -> Response {
    let Some(actions) = state.actions.as_ref() else {
        return json_error(StatusCode::NOT_IMPLEMENTED, "local scan is not configured");
    };
    match actions.scan_operators(body.imei) {
        Ok(result) => Json(result).into_response(),
        Err(error) => json_error(StatusCode::BAD_GATEWAY, error.to_string()),
    }
}

async fn list_profiles(
    State(state): State<Arc<PanelState>>,
    Json(body): Json<ResetBody>,
) -> Response {
    let Some(actions) = state.actions.as_ref() else {
        return json_error(StatusCode::NOT_IMPLEMENTED, "local eSIM access is not configured");
    };
    match actions.list_profiles(body.imei) {
        Ok(result) => Json(result).into_response(),
        Err(error) => json_error(StatusCode::BAD_GATEWAY, error.to_string()),
    }
}

/// Switching takes the modem off its current network while the card refreshes,
/// so the caller must name the profile explicitly rather than toggling
/// whatever happens to be active.
async fn switch_profile(
    State(state): State<Arc<PanelState>>,
    Json(body): Json<SwitchBody>,
) -> Response {
    let Some(actions) = state.actions.as_ref() else {
        return json_error(StatusCode::NOT_IMPLEMENTED, "local eSIM access is not configured");
    };
    if body.iccid.trim().is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "iccid is required");
    }
    match actions.switch_profile(body.imei, body.iccid, body.enable) {
        Ok(()) => Json(serde_json::json!({ "status": "ok" })).into_response(),
        Err(error) => json_error(StatusCode::BAD_GATEWAY, error.to_string()),
    }
}

async fn modem_report(
    State(state): State<Arc<PanelState>>,
    Json(body): Json<ResetBody>,
) -> Response {
    let Some(actions) = state.actions.as_ref() else {
        return json_error(StatusCode::NOT_IMPLEMENTED, "local diagnostics are not configured");
    };
    match actions.modem_report(body.imei) {
        Ok(result) => Json(result).into_response(),
        Err(error) => json_error(StatusCode::BAD_GATEWAY, error.to_string()),
    }
}

/// The character device disappears while the module re-enumerates, so the
/// caller should expect the modem list to be briefly incomplete afterwards.
async fn usb_reset(
    State(state): State<Arc<PanelState>>,
    Json(body): Json<ResetBody>,
) -> Response {
    let Some(actions) = state.actions.as_ref() else {
        return json_error(StatusCode::NOT_IMPLEMENTED, "local reset is not configured");
    };
    match actions.usb_reset(body.imei) {
        Ok(result) => Json(result).into_response(),
        Err(error) => json_error(StatusCode::BAD_GATEWAY, error.to_string()),
    }
}

async fn restart_modem(
    State(state): State<Arc<PanelState>>,
    Json(body): Json<RestartBody>,
) -> Response {
    let Some(actions) = state.actions.as_ref() else {
        return json_error(StatusCode::NOT_IMPLEMENTED, "local restart is not configured");
    };
    if body.imei.trim().is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "imei is required");
    }
    match actions.restart_modem(body.imei) {
        Ok(()) => Json(serde_json::json!({ "status": "restarted" })).into_response(),
        Err(error) => json_error(StatusCode::BAD_GATEWAY, error.to_string()),
    }
}

fn json_error(status: StatusCode, message: impl Into<String>) -> Response {
    let message = message.into();
    let mut response = (status, Json(serde_json::json!({ "error": message }))).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    response
}

/// Report a modem that has gone quiet as offline rather than repeating the
/// registration state it happened to have when it was last reachable.
///
/// ⚠️ A free function rather than `impl ModemBody`, and `From` below is a
/// free function for the same reason: `ModemBody` lives in `edge-panel-api`
/// now so that the browser can deserialise into it, and Rust's orphan rule
/// will not let this crate hang inherent or foreign-trait impls on a foreign
/// type. The conversion belongs on this side either way — it reads
/// `edge-store` rows, and `edge-store` carries a bundled SQLite that must
/// never reach the wasm bundle.
fn modem_body(value: LocalModem, now: i64, busy: bool, matrix: &CapabilityMatrix) -> ModemBody {
        let stale = value
            .last_seen
            .map(|seen| now.saturating_sub(seen) > STALE_AFTER_MS)
            .unwrap_or(true);
        // Busy wins over stale: a modem mid-scan has stopped answering the poll
        // loop on purpose, and reporting that as offline sends the operator
        // looking for a fault that does not exist.
        let state = if busy {
            "Busy".to_string()
        } else if stale {
            "Offline".to_string()
        } else {
            value.state
        };
        let network = match (value.mcc, value.mnc) {
            (Some(mcc), Some(mnc)) => Some(Network::new(mcc, mnc)),
            _ => None,
        };
        let home = match (value.home_mcc, value.home_mnc) {
            (Some(mcc), Some(mnc)) => Some(Network::new(mcc, mnc)),
            _ => None,
        };
        // Keyed on the home carrier rather than the serving one, matching the
        // agent's own lookup: what a card can do belongs to the subscription,
        // and a roaming card keeps its own operator's rules.
        let carrier = CarrierProfile::from(
            home.map(|network| network.carrier_profile())
                .unwrap_or("Generic-International"),
        );
        let family = ModemFamily::from(value.family.as_str());
        // The enum itself now, not a hand-written spelling of it: `serde` owns
        // the wire names, and the browser deserialises into the same type.
        let capability_origin = matrix.query(&family, &carrier).origin;
        ModemBody {
            imei: value.imei,
            family: value.family,
            iccid: value.iccid,
            state,
            last_seen: value.last_seen,
            home: home.map(|n| n.describe()),
            home_numeric: home.map(|n| n.numeric()),
            imsi: value.imsi,
            network: network.map(|n| n.label()),
            network_numeric: network.map(|n| n.numeric()),
            discovery: value.discovery,
            manageable: value.manageable,
            control_port: value.control_port,
            firmware: value.firmware,
            msisdn: value.msisdn,
            carrier_profile: carrier.as_str().to_string(),
            capability_origin,
        }
    }

/// See the note on `modem_body`: a free function because the type is foreign.
fn discovery_body(value: LocalModemDiscovery) -> DiscoveryBody {
    {
        DiscoveryBody {
            candidate_key: value.candidate_key,
            usb_device: value.usb_device,
            transport: value.transport,
            control_port: value.control_port,
            vendor_id: value.vendor_id,
            product_id: value.product_id,
            state: value.state,
            imei: value.imei,
            detail: value.detail,
            last_seen: value.last_seen,
        }
    }
}

/// See the note on `modem_body`: a free function because the type is foreign.
fn message_body(value: LocalMessage) -> MessageBody {
    {
        MessageBody {
            seq: value.seq,
            peer: value.peer,
            body: value.body,
            bearer: value.bearer,
            direction: value.direction,
            received_at: value.received_at,
            modem_imei: value.modem_imei,
        }
    }
}

#[cfg(test)]
mod query_tests {
    use super::cursor_from_query;

    #[test]
    fn cursor_is_read_from_the_query() {
        assert_eq!(cursor_from_query(Some("after=42")), 42);
        assert_eq!(cursor_from_query(Some("x=1&after=7&y=2")), 7);
    }

    /// A missing or unusable cursor means "send everything retained", not an
    /// error: a panel that just loaded has no cursor yet.
    #[test]
    fn a_missing_or_bad_cursor_starts_from_the_beginning() {
        assert_eq!(cursor_from_query(None), 0);
        assert_eq!(cursor_from_query(Some("")), 0);
        assert_eq!(cursor_from_query(Some("after=abc")), 0);
    }
}
