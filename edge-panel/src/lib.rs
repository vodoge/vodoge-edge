//! Local LAN panel. It reads only the SQLite cache so it still works offline.

use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use edge_store::{LocalMessage, LocalModem, Store, StoreError};
use serde::Serialize;

const INDEX: &str = include_str!("index.html");

/// Read-only view of locally cached modems and SMS.
pub trait Inbox: Send + Sync {
    fn list_messages(&self) -> Result<Vec<LocalMessage>, PanelError>;
    fn list_modems(&self) -> Result<Vec<LocalModem>, PanelError>;
}

/// Errors from the local panel store.
#[derive(Debug)]
pub enum PanelError {
    Store(StoreError),
}

impl std::fmt::Display for PanelError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(error) => write!(formatter, "{error}"),
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

/// HTTP router for the offline panel. Bind it on the LAN; it does not call the cloud.
pub fn router(inbox: Arc<dyn Inbox>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/status", get(status))
        .route("/api/messages", get(messages))
        .with_state(inbox)
}

/// Serve the panel until the process exits.
pub async fn serve(bind: impl tokio::net::ToSocketAddrs, inbox: Arc<dyn Inbox>) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, router(inbox)).await
}

async fn index() -> Html<&'static str> {
    Html(INDEX)
}

async fn status(State(inbox): State<Arc<dyn Inbox>>) -> Response {
    match inbox.list_modems() {
        Ok(modems) => Json(StatusBody {
            mode: "local",
            modems: modems.into_iter().map(ModemBody::from).collect(),
        })
        .into_response(),
        Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "store unavailable"),
    }
}

async fn messages(State(inbox): State<Arc<dyn Inbox>>) -> Response {
    match inbox.list_messages() {
        Ok(rows) => Json(MessagesBody {
            messages: rows.into_iter().map(MessageBody::from).collect(),
        })
        .into_response(),
        Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "store unavailable"),
    }
}

fn json_error(status: StatusCode, message: &'static str) -> Response {
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

impl From<LocalModem> for ModemBody {
    fn from(value: LocalModem) -> Self {
        Self {
            imei: value.imei,
            family: value.family,
            iccid: value.iccid,
            state: value.state,
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
