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

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ScannedOperatorBody {
    pub numeric: String,
    pub long_name: String,
    pub short_name: String,
    pub status: String,
    pub access_technology: Option<String>,
}

/// One USSD exchange as the panel reports it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UssdResult {
    pub code: String,
    pub stage: String,
    pub text: String,
    pub dcs: Option<u8>,
    /// True when the network is waiting for a follow-up on the same session.
    pub expects_reply: bool,
    pub elapsed_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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

/// `POST /api/discoveries/claim` 的应答。
///
/// ⚠️ 和 [`CandidateClaimResult`] 分开是有原因的：`status` 是**面板说的**，
/// 不是 `Actions` 实现说的 —— 实现只回答「哪个候选被批准了」，「claimed」这个
/// 字是这一层加上去的。
///
/// 🔴 在此之前这个应答是 handler 用 `serde_json::json!` 现拼的，`status` 这个
/// 字段在任何类型里都不存在。旧面板靠它判断成败（`result.status !== "claimed"`
/// 就报「认领回执与候选不一致」），而浏览器那半边一旦按 `CandidateClaimResult`
/// 反序列化，就会**安静地丢掉它**。这正是这次迁移要堵的那类洞：线上有的字段，
/// 类型里没有。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClaimReceipt {
    /// 恒为 `"claimed"`。旧面板拿它当成功标志，所以不能拿掉 —— 它还在 `/` 上跑。
    pub status: String,
    pub candidate_key: String,
}

impl ClaimReceipt {
    pub fn claimed(candidate_key: String) -> Self {
        Self {
            status: "claimed".into(),
            candidate_key,
        }
    }
}

/// `POST /api/rescan` 的应答。
///
/// ⚠️ 这个端点**只是把轮询循环的等待打断**，不在这次 HTTP 请求里真的探测——
/// `found` / `control_ports` 是打断前那一轮缓存的旧值，不是这次重扫的结果。
/// `status` 恒为 `"requested"`，提醒的正是这件事：请求已经收到，结果还没有。
///
/// 🔴 在此之前是 handler 用 `serde_json::json!` 现拼的，`status` 这个字段在
/// `RescanResult`（`Actions` 实现返回的类型）里根本不存在。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RescanReceipt {
    pub status: String,
    pub found: usize,
    pub control_ports: Vec<String>,
}

impl RescanReceipt {
    pub fn requested(result: RescanResult) -> Self {
        Self {
            status: "requested".into(),
            found: result.found,
            control_ports: result.control_ports,
        }
    }
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
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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

/// One captured log line.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct LogLine {
    /// Monotonic cursor. A reader passes the last one it saw to get only what
    /// came after, so a poll never re-delivers or skips a line.
    pub seq: u64,
    pub at: i64,
    pub text: String,
}

/// `GET /api/logs?after=<seq>`.
///
/// ⚠️ 只有 `seq / at / text` 三个字段。**没有级别、没有话题、没有模组** ——
/// 面板上那些筛选是从行文推断出来的，见 `edge_core::classify`。这个类型存在的
/// 意义之一就是让这件事在类型上看得见：服务端给不出的东西，这里也没有。
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LogsBody {
    pub lines: Vec<LogLine>,
    /// 服务端当前的游标。下一次带着它来问，就既不会重发也不会漏。
    pub cursor: u64,
}

/// `POST /api/send` 的应答。
///
/// ⚠️ 和 `ClaimReceipt` 同一个理由：在此之前是 handler 用 `serde_json::json!`
/// 现拼的，`status` 这个字段在任何类型里都不存在。
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SendReceipt {
    /// 恒为 `"sent"`。
    ///
    /// 🔴 「sent」的意思是**代理接受了这次提交**，不是网络投递成功。投递回执
    /// 是后来的事，走 SMS-STATUS-REPORT，不在这个应答里。
    pub status: String,
}

impl SendReceipt {
    pub fn sent() -> Self {
        Self {
            status: "sent".into(),
        }
    }
}

/* ── 「会写」端点的回执 ──────────────────────────────────────────────
 *
 * `/api/radio`、`/api/ussd/cancel`、`/api/esim/switch`、`/api/restart` 四条。
 * 它们的 `Actions` 方法全都返回 `Result<(), PanelError>` —— 实现只回答「这次
 * 调用有没有抛错」，再没有别的了。于是服务端一直用 `serde_json::json!` 现拼一个
 * `{"status": ...}`，那个字段在任何类型里都不存在，和 `ClaimReceipt` /
 * `RescanReceipt` / `SendReceipt` 补上之前是同一个洞。
 *
 * 🔴 **这四条的共同事实：`Ok` 只说明命令被接受了，不说明硬件到位了。**
 * 所以回执里没有一个字段声称硬件的当前状态。它们带的是「这次请求点的是谁、
 * 要求往哪个方向走」——够操作员把回执和自己刚按的那个按钮对上，仅此而已。
 * 想知道现在到底怎么样，得去读别的端点，能读的地方写在各自的类型上。
 *
 * ⚠️ `status` 一律保留原来那个字面量，但**理由不是前端**。
 *
 * 这里原先写的是「浏览器读的就是这个字段，换掉前端会安静地变空」——
 * 那是错的，我核过：`grep '\"status\"' edge-ui/src/` **零命中**。四个调用点
 * 收的是 `Load<serde_json::Value>`，只 match `Ready(_)` / `Failed(why)`，
 * 整个 body 都丢掉；`esim.rs` 甚至自己硬写 `claim = \"ok\"`。
 *
 * 保留它的真理由是**线格式向后兼容**：这几条端点是拿 `curl` 直接打得到的，
 * 而模组卡死的时候手上常常只剩 `curl`。删掉一个外部消费者可能在读的字段，
 * 属于悄悄改契约。`receipt_tests` 里每个类型钉一条，守的是这件事。
 */

/// 面板发出一次 profile 切换之后，等多久才去回读卡片。
///
/// 🔴 这个数字不是超时，是**等 eUICC 走完 REFRESH**。`set_profile` 请求了
/// REFRESH，卡要重新初始化，期间 ISD-R 通道是关着的，读得更早读到的是切换
/// 还没走完的那个状态。改版之前的面板等的也是 8 秒。
///
/// ⚠️ 借来的数，不是量出来的：这台机器上没有人计过一次 REFRESH 要多久
/// （`edge-bin` 里 `ESIM_READBACK_ATTEMPTS` 的注释记的是同一件事）。放在这里
/// 而不是各写各的，是为了将来量出真数时只有一处要改。
pub const ESIM_SETTLE_MS: u64 = 8_000;

/// `POST /api/radio` 的应答。
///
/// 🔴 `status` 恒为 `"ok"`，意思是**那一次 QMI 工作模式设置返回了成功**，
/// 不是模组已经到了那个状态。关射频之后模组立刻脱网；开射频之后它要重新搜网
/// 注册，几十秒内 `/api/status` 上它仍然是 `Offline` —— 那不是失败，是还没到
/// 时候。回执里因此没有任何一个字段说「射频现在是开的」。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RadioReceipt {
    /// 恒为 `"ok"`。见上面为什么这不等于射频到位。
    pub status: String,
    /// 请求点名的模组。
    ///
    /// 🔴 `None` 不是「所有模组」，是「**没点名**」：代理这时取的是它 modem map
    /// 里的第一条，而面板不知道那是哪一根。这批硬件没有人能物理接触，把一次
    /// 脱网操作记到错的模组头上，是要人去救错模组的 —— 所以这里原样回
    /// `None`，而不是编一个 IMEI 出来。
    pub imei: Option<String>,
    /// 请求的方向：`true` 要求 Online，`false` 要求 LowPower。
    ///
    /// ⚠️ 名字里的 `requested_` 是故意的。叫 `online` 的字段会被读成「射频现在
    /// 是开的」，而这个端点从不回读，它只知道自己被要求做什么。
    pub requested_online: bool,
}

impl RadioReceipt {
    pub fn accepted(imei: Option<String>, online: bool) -> Self {
        Self {
            status: "ok".into(),
            imei,
            requested_online: online,
        }
    }
}

/// `POST /api/ussd/cancel` 的应答。
///
/// 🔴 `status` 恒为 `"cancelled"`，意思是**取消命令被端口接受了**，不是网络那
/// 边的会话确实结束了。
///
/// 🔴 这四条回执里只有它给不出回读路径：面板没有任何端点能回答「这根模组上
/// 现在还有没有开着的 USSD 会话」。给不出就不给 —— 编一个 `confirmed: true`
/// 出来，正是浏览器那半边刚刚修掉的毛病（原版 `.catch(() => {})` 吞掉失败，
/// 不管端点回什么都画「已取消」）。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UssdCancelReceipt {
    /// 恒为 `"cancelled"`。
    pub status: String,
    /// 请求点名的模组；`None` 的含义同 [`RadioReceipt::imei`]。
    pub imei: Option<String>,
}

impl UssdCancelReceipt {
    pub fn cancelled(imei: Option<String>) -> Self {
        Self {
            status: "cancelled".into(),
            imei,
        }
    }
}

/// `POST /api/restart` 的应答。
///
/// 🔴 `status` 恒为 `"restarted"`，意思是**重启命令返回了**，不是模组已经回来。
/// 模组会从总线上消失再回来，这期间它在 `/api/status` 上是 `Offline`。
///
/// ⚠️ `imei` 回的是**真正交给 `Actions::restart_modem` 的那个字符串**，不是
/// 规整过的漂亮版本。回执的用处是让操作员认出「被重启的是这一根」，那就必须
/// 是实际打过去的那个值。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RestartReceipt {
    /// 恒为 `"restarted"`。
    pub status: String,
    /// 被重启的模组。这条端点要求指名，所以不是 `Option`。
    pub imei: String,
}

impl RestartReceipt {
    pub fn restarted(imei: String) -> Self {
        Self {
            status: "restarted".into(),
            imei,
        }
    }
}

/// `POST /api/esim/switch` 的应答。
///
/// 🔴 **这条端点的 ok 是这块面板明文规定不采信的那一个。** eSIM 那一栏的注释
/// 记着理由：它在一次**没发生**的切换上回过 ok，也在一次**发生了**的切换上回过
/// error。所以这个回执被设计成**说不出**「切换成功了」这句话 —— 它里面没有任何
/// 一个字段描述卡片当前的状态，只有 [`Self::seen`] 那个洞，和把它填上要走的路。
///
/// 面板的判决逻辑分成「端点声称了什么」和「卡说了什么」两件事（见 `edge-ui`
/// 的 `Receipt.claim` / `Receipt.seen`）。合成一个字段就等于让端点替卡说话，
/// 所以这里的字段名和那边对齐，让两边说的是同一种话。
///
/// ⚠️ 面板这条路和云端那条路不一样：`edge-bin` 走云端下发的切换会在之后回读
/// 芯片（`esim_inventory_after_switch`），面板这条**完全没有回读**。所以是
/// 浏览器/`curl` 那一端必须自己去读，而不是可以偷懒。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SwitchReceipt {
    /// 恒为 `"ok"`。🔴 只表示那一次 QMI `set_profile` 返回了成功。
    pub status: String,
    /// 请求点名的模组；`None` 的含义同 [`RadioReceipt::imei`]。
    pub imei: Option<String>,
    /// 被操作的 profile。切换要求指名 ICCID，所以这一条一定有。
    ///
    /// 没有它，一个回执对不上任何东西：操作员手上可能有好几次切换在飞，而
    /// 回读到的列表是按 ICCID 找行的。
    pub iccid: String,
    /// 请求的方向：`true` 要求启用，`false` 要求停用。
    ///
    /// ⚠️ 和 [`RadioReceipt::requested_online`] 同一个理由带 `requested_` 前缀。
    /// 回读出来的状态要和它比，比出来的才是判决。
    pub requested_enable: bool,
    /// 卡上回读到的启用状态。
    ///
    /// 🔴 **恒为 `None`**，因为这个端点不回读。留成 `Option` 而不是干脆不放这
    /// 个字段，是因为「不知道」是这里唯一诚实的答案，而它需要在线上有个形状 ——
    /// 将来服务端真的回读了，这里变成 `Some`，线格式不用动。
    pub seen: Option<bool>,
    /// 去哪个端点回读。
    ///
    /// 写在回执里而不是只写在浏览器代码里：模组卡死的时候手上常常只剩
    /// `curl`，那时候这条回执自己得说清下一步。
    ///
    /// ⚠️ **它是 `POST`，而且要带 body。** 这条最早只写了路径，而
    /// `/api/esim` 注册的是 `post(list_profiles)`、handler 要一个反序列化成
    /// `ResetBody` 的 body —— 照字面 `curl http://host:8743/api/esim` 是
    /// `GET`，回 405。一条「下一步」指令在它专门为之而写的那种紧急情况下
    /// 第一次就失败，比不写更坏。完整的下一步是：
    ///
    /// ```text
    /// curl -XPOST host:8743/api/esim -H 'content-type: application/json' -d '{}'
    /// ```
    pub readback_with: String,
    /// 回读之前要等多久（毫秒）。见 [`ESIM_SETTLE_MS`]。
    pub readback_after_ms: u64,
}

impl SwitchReceipt {
    pub fn accepted(imei: Option<String>, iccid: String, enable: bool) -> Self {
        Self {
            status: "ok".into(),
            imei,
            iccid,
            requested_enable: enable,
            seen: None,
            readback_with: "/api/esim".into(),
            readback_after_ms: ESIM_SETTLE_MS,
        }
    }
}

#[cfg(test)]
mod receipt_tests {
    use super::*;

    fn wire<T: Serialize>(value: &T) -> serde_json::Value {
        serde_json::to_value(value).expect("回执必须能序列化")
    }

    /// 🔴 这一条守的是一次**安静的**回归：浏览器那半边收的是
    /// `Load<serde_json::Value>`，判断成败靠读 `status`。把手拼的 `json!` 换成
    /// 结构体的时候，只要哪个字面量写错、或者谁觉得 `status` 冗余把它删了，
    /// 前端不会报错 —— 它会照常渲染，只是那一格永远是空的。
    ///
    /// ⚠️ 断言的是**字面量本身**，不是「有这个字段」。`"ok"` 和 `"cancelled"`
    /// 和 `"restarted"` 三个词各自出现在不同端点的前端分支里，换成同一个词
    /// 一样会让前端变空。
    #[test]
    fn every_receipt_still_carries_the_status_word_the_old_wire_had() {
        assert_eq!(wire(&RadioReceipt::accepted(None, true))["status"], "ok");
        assert_eq!(
            wire(&UssdCancelReceipt::cancelled(None))["status"],
            "cancelled"
        );
        assert_eq!(
            wire(&RestartReceipt::restarted("867018069514820".into()))["status"],
            "restarted"
        );
        assert_eq!(
            wire(&SwitchReceipt::accepted(
                None,
                "89852351225042214201".into(),
                true
            ))["status"],
            "ok"
        );
    }

    /// 方向是**请求的**方向，不是回读到的状态 —— 两个方向都钉住，免得
    /// 构造函数把入参丢了还能靠默认值蒙对一半。
    #[test]
    fn a_radio_receipt_repeats_which_way_it_was_asked_to_go() {
        let off = RadioReceipt::accepted(Some("867018069514820".into()), false);
        assert!(!off.requested_online);
        assert_eq!(off.imei.as_deref(), Some("867018069514820"));
        assert!(RadioReceipt::accepted(None, true).requested_online);
    }

    /// 🔴 不点名不是「所有模组」，是「不知道是哪一根」。回执必须把这件事
    /// 原样带回去，而不是替代理编一个 IMEI —— 这批硬件没人能物理接触，
    /// 一次记错模组的脱网操作要人去救错的那一根。
    #[test]
    fn an_unnamed_request_comes_back_unnamed() {
        assert!(RadioReceipt::accepted(None, false).imei.is_none());
        assert!(UssdCancelReceipt::cancelled(None).imei.is_none());
        assert!(SwitchReceipt::accepted(None, "8985".into(), true)
            .imei
            .is_none());
    }

    /// 🔴 这一条是整块面板那条原则的类型化身：**端点说 ok 不作数。**
    /// `seen` 是卡回读出来的状态，这个端点从不回读，所以它只能是 `None`；
    /// 谁哪天让它变成 `Some`，必须是因为真加了回读，而不是因为顺手。
    #[test]
    fn a_switch_receipt_never_claims_to_know_what_the_card_did() {
        let receipt = SwitchReceipt::accepted(
            Some("867018069514820".into()),
            "89852351225042214201".into(),
            true,
        );
        assert_eq!(receipt.seen, None);
        // 线上也得是 null，不能被 `skip_serializing_if` 之类的东西吞掉：
        // 一个不存在的字段和一个 `null` 字段，在读它的人眼里不是一回事。
        assert!(wire(&receipt).get("seen").is_some_and(|v| v.is_null()));
    }

    /// 回执自己要说得出下一步。模组卡死的时候手上常常只剩 `curl`，
    /// 「等多久、读哪儿」写在浏览器代码里那时候是够不着的。
    #[test]
    fn a_switch_receipt_says_where_and_when_to_read_the_card_back() {
        let receipt = SwitchReceipt::accepted(None, "89852351225042214201".into(), false);
        assert_eq!(receipt.readback_with, "/api/esim");
        assert_eq!(receipt.readback_after_ms, ESIM_SETTLE_MS);
        assert_eq!(receipt.iccid, "89852351225042214201");
        assert!(!receipt.requested_enable);
        // 回读的目标必须是路由表上真有的那条读端点，不能指向自己 ——
        // 指回 `/api/esim/switch` 就是让人再切一次。
        assert_ne!(receipt.readback_with, "/api/esim/switch");
    }

    /// 🔴 这四个类型存在的全部意义：服务端序列化它们，浏览器**用同一个类型**
    /// 反序列化回来。只 `Serialize` 的话，改一个字段名两端不会一起编译不过，
    /// 而那正是这次迁移要堵的洞。
    #[test]
    fn every_receipt_survives_the_round_trip_the_browser_makes() {
        let radio = RadioReceipt::accepted(Some("867018069514820".into()), false);
        let cancel = UssdCancelReceipt::cancelled(Some("867018069514820".into()));
        let restart = RestartReceipt::restarted("867018069514820".into());
        let switch = SwitchReceipt::accepted(None, "89852351225042214201".into(), true);
        assert_eq!(
            serde_json::from_value::<RadioReceipt>(wire(&radio)).expect("radio"),
            radio
        );
        assert_eq!(
            serde_json::from_value::<UssdCancelReceipt>(wire(&cancel)).expect("cancel"),
            cancel
        );
        assert_eq!(
            serde_json::from_value::<RestartReceipt>(wire(&restart)).expect("restart"),
            restart
        );
        assert_eq!(
            serde_json::from_value::<SwitchReceipt>(wire(&switch)).expect("switch"),
            switch
        );
    }
}
