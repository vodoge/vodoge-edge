//! Local LAN panel. It reads only the SQLite cache so it still works offline.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use edge_store::{LocalMessage, LocalModem, Store, StoreError};
use serde::{Deserialize, Serialize};

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
}

/// Local send/restart actions. Optional so a read-only panel still works.
pub trait Actions: Send + Sync {
    fn send_sms(&self, to: String, body: String, imei: Option<String>) -> Result<(), PanelError>;
    fn restart_modem(&self, imei: String) -> Result<(), PanelError>;
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
}

impl Inbox for MemoryInbox {
    fn list_messages(&self) -> Result<Vec<LocalMessage>, PanelError> {
        Ok(self.messages.clone())
    }

    fn list_modems(&self) -> Result<Vec<LocalModem>, PanelError> {
        Ok(self.modems.clone())
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
        .route("/api/messages", get(messages))
        .route("/api/send", post(send_sms))
        .route("/api/restart", post(restart_modem))
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
    match state.inbox.list_modems() {
        Ok(modems) => Json(StatusBody {
            mode,
            modems: modems
                .into_iter()
                .map(|modem| ModemBody::observed(modem, now))
                .collect(),
        })
        .into_response(),
        Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "store unavailable"),
    }
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
struct RestartBody {
    imei: String,
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
}

#[derive(Serialize)]
struct ModemBody {
    imei: String,
    family: String,
    iccid: Option<String>,
    state: String,
    last_seen: Option<i64>,
}

impl ModemBody {
    /// Report a modem that has gone quiet as offline rather than repeating the
    /// registration state it happened to have when it was last reachable.
    fn observed(value: LocalModem, now: i64) -> Self {
        let stale = value
            .last_seen
            .map(|seen| now.saturating_sub(seen) > STALE_AFTER_MS)
            .unwrap_or(true);
        Self {
            imei: value.imei,
            family: value.family,
            iccid: value.iccid,
            state: if stale {
                "Offline".to_string()
            } else {
                value.state
            },
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
