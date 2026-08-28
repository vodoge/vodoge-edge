//! Local LAN panel. It reads only the SQLite cache so it still works offline.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::{header, HeaderValue, StatusCode, Uri};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use edge_core::Network;
use edge_store::{LocalMessage, LocalModem, LocalModemDiscovery, Store, StoreError};
use serde::{Deserialize, Serialize};

mod logs;
pub use logs::{log_error, log_line, LogLine, LogRing};

const INDEX: &str = include_str!("index.html");

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
    fn send_sms(&self, to: String, body: String, imei: Option<String>) -> Result<(), PanelError>;
    fn restart_modem(&self, imei: String) -> Result<(), PanelError>;
    /// Run one AT command against a modem's control port.
    ///
    /// A module that answers `+CME ERROR` has answered, so that comes back as
    /// `Ok` carrying the error terminator. Only losing the port is an `Err`:
    /// a console has to show what the module actually said.
    fn at_command(&self, imei: Option<String>, command: String) -> Result<AtResult, PanelError>;
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
    /// Modems currently executing an operator-initiated command.
    ///
    /// Such a modem stops answering the poll loop, and a long command outlasts
    /// the staleness window, so without this the panel calls a busy modem
    /// offline.
    fn busy_modems(&self) -> Vec<String> {
        Vec::new()
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ScannedOperatorBody {
    pub numeric: String,
    pub long_name: String,
    pub short_name: String,
    pub status: String,
    pub access_technology: Option<String>,
}

/// One USSD exchange as the panel reports it.
#[derive(Clone, Debug, Serialize)]
pub struct UssdResult {
    pub code: String,
    pub stage: String,
    pub text: String,
    pub dcs: Option<u8>,
    /// True when the network is waiting for a follow-up on the same session.
    pub expects_reply: bool,
    pub elapsed_ms: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ScanResult {
    pub imei: Option<String>,
    pub elapsed_ms: u64,
    pub operators: Vec<ScannedOperatorBody>,
}

/// Immediate acknowledgement for a requested hardware rescan.
#[derive(Clone, Debug, Serialize)]
pub struct RescanResult {
    pub found: usize,
    pub control_ports: Vec<String>,
}

/// Acknowledgement that one observed serial endpoint was approved for a
/// later AT identity probe. It intentionally has no port or IMEI input.
#[derive(Clone, Debug, Serialize)]
pub struct CandidateClaimResult {
    pub candidate_key: String,
}

/// One eUICC profile as the panel reports it.
#[derive(Clone, Debug, Serialize)]
pub struct ProfileBody {
    pub iccid: String,
    pub label: String,
    pub enabled: bool,
    pub provider: Option<String>,
    pub name: Option<String>,
    pub nickname: Option<String>,
    pub class: Option<u8>,
    pub isdp_aid: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProfilesResult {
    pub imei: Option<String>,
    pub profiles: Vec<ProfileBody>,
}

/// Structured answers to the diagnostic batch.
#[derive(Clone, Debug, Default, Serialize)]
pub struct ReportResult {
    pub imei: Option<String>,
    pub port: String,
    pub signal_dbm: Option<i16>,
    pub signal_index: Option<u8>,
    pub cs_registration: Option<String>,
    pub ps_registration: Option<String>,
    pub operator: Option<String>,
    pub access_technology: Option<String>,
    pub imsi: Option<String>,
    pub iccid: Option<String>,
    pub msisdn: Option<String>,
    pub firmware: Option<String>,
    pub sms_centre: Option<String>,
    /// Commands the module refused, so an empty field can be told apart from a
    /// field the module declined to report.
    pub refused: Vec<String>,
}

/// Where a USB reset landed.
#[derive(Clone, Debug, Serialize)]
pub struct UsbResetResult {
    pub device: String,
    pub node: String,
}

/// One AT exchange as the panel reports it.
#[derive(Clone, Debug, Serialize)]
pub struct AtResult {
    pub port: String,
    pub command: String,
    pub lines: Vec<String>,
    pub terminator: String,
    pub ok: bool,
    pub elapsed_ms: u64,
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
        Ok(store.list_local_modems()?)
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
}

/// HTTP router for the offline panel. Bind it on the LAN; it does not call the cloud.
pub fn router(inbox: Arc<dyn Inbox>) -> Router {
    router_with_actions(inbox, None)
}

/// HTTP router with optional local send/restart actions.
pub fn router_with_actions(inbox: Arc<dyn Inbox>, actions: Option<Arc<dyn Actions>>) -> Router {
    router_with_uplink(inbox, actions, Arc::new(AtomicBool::new(false)))
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
    Router::new()
        .route("/", get(index))
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
        .with_state(Arc::new(PanelState {
            inbox,
            actions,
            uplink_online,
        }))
}

/// Serve the panel until the process exits.
pub async fn serve(
    bind: impl tokio::net::ToSocketAddrs,
    inbox: Arc<dyn Inbox>,
    actions: Option<Arc<dyn Actions>>,
    uplink_online: Arc<AtomicBool>,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, router_with_uplink(inbox, actions, uplink_online)).await
}

async fn index() -> Html<&'static str> {
    Html(INDEX)
}

async fn status(State(state): State<Arc<PanelState>>) -> Response {
    let mode = if state.uplink_online.load(Ordering::Relaxed) {
        "cloud"
    } else {
        "local"
    };
    let now = now_ms();
    let busy = state
        .actions
        .as_ref()
        .map(|actions| actions.busy_modems())
        .unwrap_or_default();
    match (state.inbox.list_modems(), state.inbox.list_modem_discoveries()) {
        (Ok(modems), Ok(discoveries)) => Json(StatusBody {
            mode,
            modems: modems
                .into_iter()
                .map(|modem| {
                    let is_busy = busy.iter().any(|imei| *imei == modem.imei);
                    ModemBody::observed(modem, now, is_busy)
                })
                .collect(),
            discoveries: discoveries.into_iter().map(DiscoveryBody::from).collect(),
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
            messages: rows.into_iter().map(MessageBody::from).collect(),
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
    match actions.send_sms(body.to, body.body, body.imei) {
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
    match actions.at_command(body.imei, command) {
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

#[derive(Deserialize)]
struct SendBody {
    to: String,
    body: String,
    imei: Option<String>,
}

#[derive(Deserialize)]
struct RadioBody {
    online: bool,
    imei: Option<String>,
}

#[derive(Deserialize)]
struct UssdBody {
    code: String,
    imei: Option<String>,
}

#[derive(Deserialize)]
struct SwitchBody {
    iccid: String,
    enable: bool,
    imei: Option<String>,
}

#[derive(Deserialize)]
struct ResetBody {
    imei: Option<String>,
}

#[derive(Deserialize)]
struct AtBody {
    command: String,
    imei: Option<String>,
}

#[derive(Deserialize)]
struct RestartBody {
    imei: String,
}

#[derive(Deserialize)]
struct ClaimCandidateBody {
    candidate_key: String,
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

#[derive(Serialize)]
struct StatusBody {
    mode: &'static str,
    modems: Vec<ModemBody>,
    discoveries: Vec<DiscoveryBody>,
}

#[derive(Serialize)]
struct ModemBody {
    imei: String,
    family: String,
    iccid: Option<String>,
    state: String,
    last_seen: Option<i64>,
    /// Whose subscription this is, from the card's IMSI. This is what tells
    /// two similar sticks apart.
    home: Option<String>,
    home_numeric: Option<String>,
    imsi: Option<String>,
    /// Where the modem is currently registered. On a roaming card this is a
    /// different operator, so it is shown separately rather than instead.
    network: Option<String>,
    network_numeric: Option<String>,
    discovery: String,
    manageable: bool,
    control_port: Option<String>,
}

impl ModemBody {
    /// Report a modem that has gone quiet as offline rather than repeating the
    /// registration state it happened to have when it was last reachable.
    fn observed(value: LocalModem, now: i64, busy: bool) -> Self {
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
        Self {
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
        }
    }
}

#[derive(Serialize)]
struct DiscoveryBody {
    candidate_key: String,
    usb_device: Option<String>,
    transport: String,
    control_port: String,
    vendor_id: Option<String>,
    product_id: Option<String>,
    state: String,
    imei: Option<String>,
    detail: String,
    last_seen: i64,
}

impl From<LocalModemDiscovery> for DiscoveryBody {
    fn from(value: LocalModemDiscovery) -> Self {
        Self {
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

#[derive(Serialize)]
struct MessagesBody {
    messages: Vec<MessageBody>,
}

#[derive(Serialize)]
struct MessageBody {
    seq: u64,
    peer: String,
    body: String,
    bearer: String,
    direction: String,
    received_at: i64,
    modem_imei: Option<String>,
}

impl From<LocalMessage> for MessageBody {
    fn from(value: LocalMessage) -> Self {
        Self {
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
