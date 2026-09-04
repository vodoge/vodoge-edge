//! 状态页：模组列表、USB 候选、以及一条永远不谎称自己是实时的新鲜度。
//!
//! 🔴 **这一页存在的意义是在别的东西都坏掉的时候还能看。** 所以它对「坏掉」的
//! 表达方式比对「正常」的更讲究——被替换掉的那版把加载失败画成了空列表，那是
//! 最糟的答案：它让操作员停止查找。
//!
//! 搬迁时刻意保留的三件事（原版注释里写明是有意为之的）：
//!
//! - **确认框的不对称**：认领候选要问、纳管不问、取消纳管要问。不要统一。
//! - **多个定时器间隔各不相同**：重扫后 +1s（立刻读会拿到旧缓存）、认领后
//!   +10s（认领只是给下一轮轮询上膛，HTTP 回执不是模组身份）。不要合并。
//! - **取消也要留痕**：分不清「对话框被关掉」和「命令发出去了」是排障时最贵的
//!   一种含糊。

use edge_panel_api::{ModemBody, PanelMode, StatusBody};
use leptos::prelude::*;
use thaw::*;

use crate::api::{self, Load};

/// 轮询周期。原版是 10 秒，新鲜度的「陈旧」阈值是它的 2.5 倍。
///
/// ⚠️ 2.5 倍不是随手取的数，是「漏了两拍半」。改成固定秒数会让这两个数各走各的。
pub const STATUS_EVERY_MS: u64 = 10_000;

/// 一次认领的三种下场。
///
/// ✅ 原版这里已经是对的——`claimNotes` 本来就用三种不同形状表示 pending /
/// 成功 / 失败。整页其余部分都把失败折叠成了空，唯独这里没有，所以它是原样搬
/// 过来的，只是从「三种形状的对象」变成一个真枚举。
#[allow(dead_code)]
// 候选纳管还没搬（阶段 2 第 4 项）；这个形状先立在这里，
// 因为它是原版**唯一做对了三态**的地方，别在搬迁里丢掉。
#[derive(Clone, Debug, PartialEq)]
pub enum ClaimNote {
    Pending,
    Claimed,
    Failed(String),
}

/// 这一页的全部状态。
///
/// `Copy`，因为字段全是 `RwSignal`——Leptos 的信号本身就是 Copy 的句柄，
/// 把状态结构体也做成 Copy 省掉每个闭包里一次 `.clone()`。
#[derive(Clone, Copy)]
pub struct StatusState {
    /// 最近一次轮询的结果。🔴 `Load` 而不是 `Option`——失败必须能被画出来。
    pub load: RwSignal<Load<StatusBody>>,
    /// 最后一次**成功**加载的时刻。失败时不更新，所以「数据停在 N 前」会继续走远，
    /// 这是对的：它说的是数据的年龄，不是请求的年龄。
    pub last_ok: RwSignal<f64>,
    /// 每秒一跳。所有相对时间都靠它，不跳的话「N 秒前」会冻在数据到达那一刻。
    pub now: RwSignal<f64>,
    /// 当前选中的模组。整个面板唯一的全局上下文。
    pub active: RwSignal<Option<String>>,
    /// 轮询是否在飞。🔴 原版没有这个，慢响应会重叠、旧响应能覆盖新响应。
    pub in_flight: RwSignal<bool>,
}

impl StatusState {
    pub fn new() -> Self {
        Self {
            load: RwSignal::new(Load::Loading),
            last_ok: RwSignal::new(0.0),
            now: RwSignal::new(now_ms()),
            active: RwSignal::new(None),
            in_flight: RwSignal::new(false),
        }
    }
}

pub fn now_ms() -> f64 {
    js_sys::Date::now()
}

/// 「N 秒前 / N 分钟前」，或者从没成功过时的那句话。
fn since(now: f64, then: f64) -> String {
    if then <= 0.0 {
        return "还没读到过".into();
    }
    let secs = ((now - then) / 1000.0).max(0.0) as u64;
    match secs {
        0..=1 => "刚刚".into(),
        2..=59 => format!("{secs} 秒前"),
        60..=3599 => format!("{} 分钟前", secs / 60),
        _ => format!("{} 小时前", secs / 3600),
    }
}

/// 新鲜度：**永远不声称自己是实时的**。
///
/// 🔴 原版注释在 markup 里写着 "Never claim to be live"。它说的是数据的年龄，
/// 不是连接的状态——一次成功的 HTTP 读不代表 USB 上真的有人应答。
#[component]
pub fn Freshness(state: StatusState) -> impl IntoView {
    let text = move || {
        let now = state.now.get();
        let last = state.last_ok.get();
        match state.load.get() {
            // ⚠️ 只说状态，不说原因。原因归下面那条错误横幅——它有地方把话讲完。
            // 徽章里塞完整原因会让这一行长到挤掉标题，而且同一句话在屏幕上出现
            // 两遍，读的人要先确认它们是不是同一件事。
            //
            // 但它仍然带着数据的年龄：连不上的时候「上一次读到是什么时候」正是
            // 操作员要判断的东西——刚断和断了十分钟，处理方式不一样。
            Load::Failed(_) => format!("连不上 · 数据 {}", since(now, last)),
            _ => format!("数据 {}", since(now, last)),
        }
    };
    let stale = move || {
        matches!(state.load.get(), Load::Failed(_))
            || (state.last_ok.get() > 0.0
                && state.now.get() - state.last_ok.get() > (STATUS_EVERY_MS as f64) * 2.5)
    };
    view! {
        <Badge appearance=Signal::derive(move || if stale() { BadgeAppearance::Filled } else { BadgeAppearance::Outline })
               color=Signal::derive(move || if stale() { BadgeColor::Danger } else { BadgeColor::Success })>
            {text}
        </Badge>
    }
}

/// 模组状态字符串归一化。
///
/// ⚠️ 服务端有**两套拼写**：store 写的是小写（`registered`），面板自己合成的是
/// 大写（`Busy` / `Offline`，见 edge-panel/src/lib.rs）。原版有个 `stateKey()`
/// 做同样的事，搬迁时不能只处理其中一套。
fn state_key(raw: &str) -> String {
    raw.to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_lowercase())
        .collect()
}

/// 状态字符串的中文标签。
///
/// 🔴 **见过的值才给标签，没见过的原样显示。** 这条规则不是洁癖：原版曾经给
/// 十四种「发现状态」和一个叫 `mbim` 的传输方式编过标签，而 agent 只写五种
/// 状态三种传输——多出来的那些永远不会出现，真正会出现的 `serial` 反而漏了。
/// 一个永远不出现的标签和一个漏掉的标签，从屏幕上看是一样的。
///
/// agent 与面板一共会写这些（2026-09-04 对着生产 /api/status 核过）：
///
/// | 值 | 谁写的 | 意思 |
/// |---|---|---|
/// | `Offline` | 面板合成（`modem_body`）| 超过 `STALE_AFTER_MS` 没答话 |
/// | `Busy` | 面板合成（`modem_body`）| 正在扫网等，**故意**不答轮询 |
/// | `registered` / `searching` / `denied` | agent，来自 `Registration` | 注册状态 |
/// | `online` | agent 的 AT-only 探测路径 | 它答话了——⚠️ **不等于可管理** |
///
/// ⚠️ `online` 的措辞要小心。`edge-bin` 那里的注释写得很清楚：这个值的意思是
/// 「模组答话了」，而那条路径同时把 `manageable` 设成 false（每一个结构化操作
/// 都走 QMI，AT-only 的模组做不了）。所以标签是「在线（仅 AT）」而不是光写
/// 「在线」——后者会让人以为它和其它三根一样能用。
fn state_label(raw: &str) -> String {
    match state_key(raw).as_str() {
        "registered" => "已注册".into(),
        "searching" => "搜网中".into(),
        "denied" => "被拒绝".into(),
        "offline" => "离线".into(),
        "busy" => "忙".into(),
        "online" => "在线（仅 AT）".into(),
        // 没见过的原样端出去。编一个标签比显示原文更坏。
        _ => raw.to_string(),
    }
}

/// 这一根模组是不是 QMI 可管理的。
///
/// 🔴 住在这里而不是某一页里，是因为**不止一页需要它**：危险区靠它决定画
/// 「危险区」还是「AT 通道」，eSIM 靠它决定按钮能不能点。这两处不一致过——
/// 危险区写着「eSIM 操作不可用」，而同一屏下面的 eSIM「读取」按钮是亮的。
///
/// ⚠️ 找不到这根模组时按「可管理」处理。原版 `activeManageable()` 是同样的
/// 防御性默认值，覆盖的是「选中了」和「状态数据到达」之间那个短暂的间隙，
/// 不是一条业务规则。
pub fn manageable(body: &StatusBody, imei: &str) -> bool {
    body.modems
        .iter()
        .find(|m| m.imei == imei)
        .map(|m| m.manageable)
        .unwrap_or(true)
}

fn state_tone(raw: &str) -> BadgeColor {
    match state_key(raw).as_str() {
        "registered" | "home" => BadgeColor::Success,
        "roaming" => BadgeColor::Warning,
        "busy" => BadgeColor::Informative,
        "offline" | "denied" | "notregistered" => BadgeColor::Danger,
        _ => BadgeColor::Subtle,
    }
}

/// 心跳距今多久。⚠️ 「模组没给 last_seen」和「很久以前」是两回事，前者说 `—`
/// ——复用上面那个 `since`，它已经把「从没读到过」和真实间隔分开了。
fn heartbeat(last_seen: Option<i64>, now: f64) -> String {
    match last_seen {
        Some(seen) if seen > 0 => since(now, seen as f64),
        _ => "—".into(),
    }
}

/// 接口类型的短标签。⚠️ 只认 agent 真写的三种，别的原样显示。
fn discovery_label(raw: &str) -> &str {
    match raw {
        "qmi" => "QMI",
        "at" => "AT",
        "serial" => "串口",
        other => other,
    }
}

/// 左栏里的一根模组。
///
/// 🔴 **卡归属和驻留网络是两行，不是一行。** 2026-09-04 的生产机队里三根 QMI
/// 模组**全在漫游**：一根香港 CSL、一根中国移动大陆、一根**美国 310-240**，而
/// 驻留网络有两根都是「中国移动」。只画驻留网络的话，那两根在屏幕上一模一样，
/// 而它们的卡来自完全不同的运营商。旧面板的注释早就点出这件事，搬迁时我把它
/// 压成了一张只有驻留网络的表。
#[component]
fn ModemCard(modem: ModemBody, state: StatusState) -> impl IntoView {
    let imei = modem.imei.clone();
    let selected = {
        let imei = imei.clone();
        move || state.active.get().as_deref() == Some(imei.as_str())
    };
    let on_click = {
        let imei = imei.clone();
        move |_| state.active.set(Some(imei.clone()))
    };

    let home = modem.home.clone();
    let network = modem.network.clone();
    let network_numeric = modem.network_numeric.clone();
    let iccid = modem.iccid.clone();
    let family = modem.family.clone();
    let last_seen = modem.last_seen;
    let discovery = discovery_label(&modem.discovery).to_string();
    let manageable = modem.manageable;
    let fallback = matches!(
        modem.capability_origin,
        edge_core::CapabilityOrigin::Fallback
    );
    let carrier = modem.carrier_profile.clone();
    let state_raw = modem.state.clone();

    view! {
        <button
            class=move || {
                if selected() { "vd-modem vd-modem--on" } else { "vd-modem" }
            }
            on:click=on_click
        >
            <span class="vd-modem-top">
                <span class="vd-modem-imei">{imei.clone()}</span>
                <Badge color=state_tone(&state_raw) size=BadgeSize::Small>
                    {state_label(&state_raw)}
                </Badge>
            </span>

            // 卡是谁的。排在驻留网络前面——漫游时这两者属于不同的运营商，
            // 而「这是哪张卡」才是区分两根相似棒子的东西。
            <span class="vd-modem-line">
                {home.clone().unwrap_or_else(|| "卡归属未知".into())}
            </span>
            <span class="vd-modem-line vd-faint">
                {match (network.clone(), network_numeric.clone()) {
                    (Some(n), Some(num)) => format!("驻留 {n} ({num})"),
                    (Some(n), None) => format!("驻留 {n}"),
                    _ => "未驻留网络".into(),
                }}
            </span>
            <span class="vd-modem-line vd-faint">
                {move || {
                    format!(
                        "{family} · 心跳 {}",
                        heartbeat(last_seen, state.now.get()),
                    )
                }}
            </span>
            <span class="vd-modem-line vd-faint">
                {iccid.clone().map(|c| format!("ICCID {c}")).unwrap_or_else(|| "ICCID —".into())}
            </span>

            <span class="vd-modem-flags">
                <Badge appearance=BadgeAppearance::Outline size=BadgeSize::Small>
                    {discovery}
                </Badge>
                <Badge
                    appearance=BadgeAppearance::Outline
                    size=BadgeSize::Small
                    color=if manageable { BadgeColor::Success } else { BadgeColor::Warning }
                >
                    {if manageable { "可管理" } else { "仅 AT" }}
                </Badge>
                // ⚠️ 只在矩阵**从没听说过**这个组合时才出现。有规则的即使规则说
                // 「probe」也不吭声——那是有人做过的决定，不是一个待解的问题。
                {fallback
                    .then(|| {
                        view! {
                            <Badge color=BadgeColor::Warning size=BadgeSize::Small>
                                "矩阵无规则"
                            </Badge>
                        }
                    })}
            </span>
            // 写规则要用的那两个键，只在需要的人面前出现，而且拼法和矩阵一致，
            // 好让人直接抄进 TOML 而不是猜。
            {fallback
                .then(|| {
                    view! {
                        <span class="vd-modem-line vd-faint">
                            {format!("规则键 {} · {carrier}", modem.family)}
                        </span>
                    }
                })}
        </button>
    }
}

/// 左栏：模组列表。**四种画面，一种都不能画成另一种。**
///
/// 在飞、读不到、真的没有、有——这四件事在屏幕上必须长得不一样。整块面板
/// 的其余部分都瞄准这里选中的那一根，所以这一栏画错的代价比别处大：
/// 「读不到」画成「没有模组」，看的人会以为硬件掉了，然后去机房。
#[component]
pub fn ModemRail(state: StatusState) -> impl IntoView {
    view! {
        {move || match state.load.get() {
            // ① 在飞。和「没有」是两回事。
            Load::Loading => view! { <Spinner label="正在读取 agent…" /> }.into_any(),

            // ② 🔴 失败，画在**这一栏上**，带原因。原版把它折叠成了空列表，
            //    失败原因只出现在另一个标签的控制台里。
            Load::Failed(why) => {
                view! {
                    <MessageBar intent=MessageBarIntent::Error layout=MessageBarLayout::Multiline>
                        <MessageBarBody>
                            <MessageBarTitle>"读不到模组列表"</MessageBarTitle>
                            {why}
                        </MessageBarBody>
                    </MessageBar>
                }
                    .into_any()
            }

            Load::Ready(body) => {
                let discoveries = body.discoveries.len();
                if body.modems.is_empty() {
                    // ③ 真的没有。这是一句关于这台机器的事实，而且要说清下一步。
                    return view! {
                        <MessageBar intent=MessageBarIntent::Info layout=MessageBarLayout::Multiline>
                            <MessageBarBody>
                                {if discoveries > 0 {
                                    format!(
                                        "没有已纳管的模组，但看到 {discoveries} 个 USB 候选——它们要先被纳入探测。",
                                    )
                                } else {
                                    "没有检测到模组。插上模组后按「重扫 USB」。".to_string()
                                }}
                            </MessageBarBody>
                        </MessageBar>
                    }
                        .into_any();
                }
                let st = state;
                view! {
                    <div class="vd-modem-list">
                        {body
                            .modems
                            .into_iter()
                            .map(|m| view! { <ModemCard modem=m state=st /> })
                            .collect_view()}
                    </div>
                }
                    .into_any()
            }
        }}
    }
}

/// 顶栏那句「这台机器在哪种模式下」。
#[component]
pub fn ModeLabel(state: StatusState) -> impl IntoView {
    move || match state.load.get() {
        Load::Ready(body) => {
            let mode = match body.mode {
                PanelMode::Cloud => "已连上云端",
                PanelMode::Local => "本地模式（无上行）",
            };
            view! { <Caption1>{mode}</Caption1> }.into_any()
        }
        _ => ().into_any(),
    }
}

/// 拉一次状态。
///
/// 🔴 带在飞保护——原版没有，`setInterval` 上的慢响应会重叠，旧响应可以覆盖新的。
pub async fn poll(state: StatusState) {
    if state.in_flight.get_untracked() {
        return;
    }
    state.in_flight.set(true);
    let result: Load<StatusBody> = api::get("/api/status", "读取状态").await;
    if matches!(result, Load::Ready(_)) {
        state.last_ok.set(now_ms());
    }
    state.load.set(result);
    state.in_flight.set(false);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 🔴 这些值不是编出来的，是 2026-09-04 从生产 `/api/status` 抓下来的。
    ///
    /// 开发全程用 `edge-panel/examples/serve.rs` 的造数据，那份数据里 state
    /// 只有 `Offline` 和 `searching` 两种。真实机队还写 `registered` 和
    /// `online`，而 `online` 恰恰是最容易被误读的那一个。
    #[test]
    fn every_state_the_fleet_actually_writes_has_a_chinese_label() {
        for (raw, want) in [
            ("Offline", "离线"),
            ("Busy", "忙"),
            ("registered", "已注册"),
            ("searching", "搜网中"),
            ("denied", "被拒绝"),
        ] {
            assert_eq!(state_label(raw), want, "{raw} 没有中文标签");
        }
    }

    /// ⚠️ `online` 的意思是「模组答话了」，**不是**「可以用」。
    ///
    /// 写这个值的是 `edge-bin` 的 AT-only 探测路径，那条路径同时把
    /// `manageable` 设成 false —— 每一个结构化操作都走 QMI，AT-only 的模组
    /// 做不了。标签必须把这件事说出来，否则屏幕上它和另外三根一样是「在线」。
    #[test]
    fn online_says_it_is_at_only_rather_than_just_online() {
        let label = state_label("online");
        assert!(label.contains("在线"), "{label}");
        assert!(
            label.contains("AT"),
            "「在线」单独出现会让人以为这一根和别的一样能用：{label}"
        );
    }

    /// 没见过的值原样端出去。编一个标签比显示原文更坏 —— 原版就是这么把
    /// 十四种不存在的状态和一个不存在的传输方式画上屏幕的。
    #[test]
    fn a_state_nobody_writes_is_shown_as_the_agent_spelled_it() {
        assert_eq!(state_label("brand-new-thing"), "brand-new-thing");
        assert_eq!(state_label(""), "");
    }

    /// 大小写两套拼写都要认：store 写小写，面板自己合成的是大写。
    #[test]
    fn both_spellings_of_the_same_state_get_the_same_label() {
        assert_eq!(state_label("Offline"), state_label("offline"));
        assert_eq!(state_label("REGISTERED"), state_label("registered"));
        // `BadgeColor` 没有 `PartialEq`/`Debug`，所以比的是归一化后的键 ——
        // `state_tone` 本来就只看这个键。
        assert_eq!(state_key("Offline"), state_key("offline"));
        assert_eq!(state_key("REGISTERED"), state_key("registered"));
    }
}
