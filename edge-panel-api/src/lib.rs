//! The panel's HTTP API, as types both sides of it share.
//!
//! 🔴 **Why this crate exists, and why it is not `vodoge-contract`.**
//!
//! `docs/frontend-rebuild/edge-leptos.md` gave the reason for moving the panel
//! to Leptos as "the front end can reuse `vodoge-contract`'s serde types, so a
//! change to the uplink struct stops it compiling". Checked against the code,
//! that guards the wrong boundary: `edge-panel` does not depend on
//! `vodoge-contract` at all, and never has. `vodoge-contract` is the
//! **edge↔cloud uplink protocol**. The panel's own API is a separate, smaller
//! surface that was defined privately inside `edge-panel/src/lib.rs`, where
//! nothing outside that file could name it.
//!
//! So the compile-time link is real, but it belongs here: the server
//! serialises **these** types and the browser deserialises **these** types.
//! Rename a field and the front end stops compiling — which is the whole
//! reason the panel is being rewritten in Rust rather than in anything else.
//!
//! ## What may and may not live here
//!
//! ⚠️ **No I/O, and nothing that cannot reach `wasm32-unknown-unknown`.** The
//! browser half of the panel compiles to wasm, so this crate may depend only
//! on `serde` and on `edge-core` — which was checked and does build for wasm32
//! (its whole dependency list is serde, serde_json and toml).
//!
//! In particular it must never reach `edge-store`: that crate carries
//! `rusqlite` with a bundled SQLite, so a single type borrowed from it would
//! take the whole database engine into the browser bundle. The conversions
//! *from* the store's rows *into* these types stay on the server side, where
//! the store already is.


/// Re-exported so the browser half can match on it without depending on
/// `edge-core` directly — the wire vocabulary arrives with the wire types.
pub use edge_core::CapabilityOrigin;
use serde::{Deserialize, Serialize};

/// Whether the agent currently has an uplink to the cloud.
///
/// 🔴 An enum, where the server had `mode: &'static str` holding `"cloud"` or
/// `"local"`. Two reasons it could not stay a string:
///
/// 1. `&'static str` cannot be deserialised — there is nothing for the
///    borrowed data to live in — so a shared type could not have kept it.
/// 2. A string is a spelling, and a spelling on one side of a wire is a
///    spelling that can disagree with the other side. The set is closed and
///    always was; naming it makes the compiler hold both ends to it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PanelMode {
    /// The agent is connected to the cloud; commands can arrive from it.
    Cloud,
    /// No uplink. The panel is the only way in, which is the case it exists for.
    Local,
}

/// `GET /api/status` — what the panel draws its first screen from.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StatusBody {
    pub mode: PanelMode,
    pub modems: Vec<ModemBody>,
    pub discoveries: Vec<DiscoveryBody>,
}

/// One modem row, as the panel shows it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ModemBody {
    pub imei: String,
    pub family: String,
    pub iccid: Option<String>,
    pub state: String,
    pub last_seen: Option<i64>,
    /// Whose subscription this is, from the card's IMSI. This is what tells
    /// two similar sticks apart.
    pub home: Option<String>,
    pub home_numeric: Option<String>,
    pub imsi: Option<String>,
    /// Where the modem is currently registered. On a roaming card this is a
    /// different operator, so it is shown separately rather than instead.
    pub network: Option<String>,
    pub network_numeric: Option<String>,
    pub discovery: String,
    pub manageable: bool,
    pub control_port: Option<String>,
    /// Firmware revision and the card's own number, both carried in the modem
    /// row rather than fetched by a diagnostic so the panel can show them
    /// without taking the radio away from the poll loop.
    pub firmware: Option<String>,
    pub msisdn: Option<String>,
    /// The carrier half of the capability-matrix key, derived from the home
    /// network. Shown because it is half of what a new rule must be written
    /// against, and it is not readable off the operator name.
    pub carrier_profile: String,
    /// `rule` when the matrix has an entry for this (family, carrier) pair,
    /// `fallback` when it has never heard of the combination.
    ///
    /// Deliberately not called "measured". A rule is free to say `probe`, and
    /// several do -- that is a decision that this pair varies or was never
    /// characterised, which is a different fact from nobody having considered
    /// it. Only the second one is worth interrupting an operator about, and
    /// only the second one is what a new rule would fix.
    ///
    /// Note that a recognised family is not enough on its own: `UFI103S` is a
    /// known variant with no rules in the built-in matrix, so it lands here.
    ///
    /// ⚠️ `edge_core::CapabilityOrigin` itself, not a copy of its spelling.
    /// The server used to map the enum onto `"rule"` / `"fallback"` by hand at
    /// the point of serialising, which is a mapping that can drift from the
    /// enum it is mapping. There is one spelling now and `serde` owns it.
    pub capability_origin: CapabilityOrigin,
}

/// A USB device the agent can see but has not adopted as a modem.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiscoveryBody {
    pub candidate_key: String,
    pub usb_device: Option<String>,
    pub transport: String,
    pub control_port: String,
    pub vendor_id: Option<String>,
    pub product_id: Option<String>,
    pub state: String,
    pub imei: Option<String>,
    pub detail: String,
    pub last_seen: i64,
}

/// `GET /api/messages` — the SMS the agent has cached locally.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessagesBody {
    pub messages: Vec<MessageBody>,
}

/// One cached SMS, in either direction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageBody {
    pub seq: u64,
    pub peer: String,
    pub body: String,
    pub bearer: String,
    pub direction: String,
    pub received_at: i64,
    pub modem_imei: Option<String>,
}

/* ── 动作结果 ───────────────────────────────────────────────────────
 *
 * `Actions` 那一族方法的返回值。它们本来就是 `pub`（`edge-bin` 实现那个 trait），
 * 但只是 `Serialize` —— 服务端能把它们写出去，浏览器读不回来。补上 `Deserialize`
 * 才让两端共用同一个类型，这是整件事的全部意义。
 *
 * ⚠️ 全部自包含：只用原始类型和彼此，不碰 `edge-store`。搬迁时确认过。
 */

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScannedOperatorBody {
    pub numeric: String,
    pub long_name: String,
    pub short_name: String,
    pub status: String,
    pub access_technology: Option<String>,
}

/// One USSD exchange as the panel reports it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UssdResult {
    pub code: String,
    pub stage: String,
    pub text: String,
    pub dcs: Option<u8>,
    /// True when the network is waiting for a follow-up on the same session.
    pub expects_reply: bool,
    pub elapsed_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanResult {
    pub imei: Option<String>,
    pub elapsed_ms: u64,
    pub operators: Vec<ScannedOperatorBody>,
}

/// Immediate acknowledgement for a requested hardware rescan.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RescanResult {
    pub found: usize,
    pub control_ports: Vec<String>,
}

/// Acknowledgement that one observed serial endpoint was approved for a
/// later AT identity probe. It intentionally has no port or IMEI input.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CandidateClaimResult {
    pub candidate_key: String,
}

/// What an adoption or a removal changed.
///
/// `changed` is false when the module was already in that state, which is not
/// an error: the panel and a cloud command can both do this, and the second
/// one arriving is not a fault.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegistrationResult {
    pub imei: String,
    pub registered: bool,
    pub changed: bool,
}

/// One eUICC profile as the panel reports it.
#[derive(Clone, Debug, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProfilesResult {
    pub imei: Option<String>,
    pub profiles: Vec<ProfileBody>,
}

/// Structured answers to the diagnostic batch.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
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
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UsbResetResult {
    pub device: String,
    pub node: String,
}

/// One AT exchange as the panel reports it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AtResult {
    pub port: String,
    pub command: String,
    pub lines: Vec<String>,
    pub terminator: String,
    pub ok: bool,
    pub elapsed_ms: u64,
}

/* ── 请求体 ─────────────────────────────────────────────────────────
 *
 * 服务端反序列化它们，浏览器**序列化**它们 —— 所以补的是 `Serialize`，
 * 和上面响应类型补 `Deserialize` 正好相反。两个方向都补齐之后，请求和响应
 * 各自只有一份定义，改一个字段两端一起编译不过。
 *
 * ⚠️ 字段改成 `pub` 是为了让浏览器那半边能构造它们；服务端只是反序列化，
 * 从来不需要 `pub`，所以这不是原来漏了什么。
 */

#[derive(Serialize, Deserialize)]
pub struct SendBody {
    pub to: String,
    pub body: String,
    pub imei: Option<String>,
    /// Send on a pairing the ledger has not measured, in order to find out
    /// what it does. This is the commissioning path: "untested is
    /// unsupported" would otherwise make the first test of anything
    /// impossible. Absent is false, so nothing reaches it by accident, and
    /// the result of the exercise belongs in the ledger rather than in
    /// somebody's memory of having tried it once.
    #[serde(default)]
    pub commission: bool,
}

#[derive(Serialize, Deserialize)]
pub struct RadioBody {
    pub online: bool,
    pub imei: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct UssdBody {
    pub code: String,
    pub imei: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct SwitchBody {
    pub iccid: String,
    pub enable: bool,
    pub imei: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct ResetBody {
    pub imei: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct AtBody {
    pub command: String,
    pub imei: Option<String>,
    /// Send a command the agent classifies as disruptive anyway. Absent is
    /// false, so a page that predates the classifier can only ask for the
    /// safe set rather than silently bypassing it.
    #[serde(default)]
    pub force: bool,
}

#[derive(Serialize, Deserialize)]
pub struct RestartBody {
    pub imei: String,
}

#[derive(Serialize, Deserialize)]
pub struct ClaimCandidateBody {
    pub candidate_key: String,
}

#[derive(Serialize, Deserialize)]
pub struct RegistrationBody {
    pub imei: String,
}
