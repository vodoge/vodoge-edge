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
    /// 最后一次**读成功**的列表，连同它的时刻。
    ///
    /// 🔴 读失败时不清空模组列表——`health.rs` 早就是这么做的（「下面是上一次
    /// 的结果」），而这一栏是全项目唯一还在无条件丢掉上一帧的读取路径。
    /// 一次网络抖动让四根模组从屏幕上一起消失，比显示一份标注了年龄的旧列表
    /// 坏得多：前者看起来像硬件全掉了。
    pub stale: RwSignal<Option<(StatusBody, f64)>>,
    /// 舰队的时间轴。见 `trace.rs` 开头那段。
    ///
    /// 🔴 **这个字段不进 `lib.rs` 的换模组清场。** 那段注释写着「加新页面的人：
    /// 你的状态也要在这里清一次」，而轨迹是唯一的例外——它是**舰队级**的、
    /// 跨模组的，切一次模组清一次就等于永远看不到轮换，而轮换正是它存在的理由。
    pub trace: RwSignal<std::collections::VecDeque<crate::trace::Frame>>,
}

impl StatusState {
    pub fn new() -> Self {
        Self {
            load: RwSignal::new(Load::Loading),
            last_ok: RwSignal::new(0.0),
            now: RwSignal::new(now_ms()),
            active: RwSignal::new(None),
            in_flight: RwSignal::new(false),
            stale: RwSignal::new(None),
            trace: RwSignal::new(std::collections::VecDeque::new()),
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

/// 时:分:秒。⚠️ 和 `health.rs` / `logs.rs` 等处同源的那一份——重复了六份，
/// 该收进 `edge-core`，但那是另一件事，不在这次改动里顺手做。
fn hhmmss(at: f64) -> String {
    let d = js_sys::Date::new(&at.into());
    format!(
        "{:02}:{:02}:{:02}",
        d.get_hours(),
        d.get_minutes(),
        d.get_seconds()
    )
}

/// 轨迹条带画多少格。10 秒一帧 × 60 = 10 分钟，正好塞进 15.5rem 的左栏。
///
/// ⚠️ 只是**画**多少格；`trace.rs` 留的是 360 帧（1 小时）。翻转次数按全部
/// 帧算，条带只显示尾巴——两者的窗口不一样，所以文案里必须各自说清自己的跨度。
const TRACE_COLS: usize = 60;

/// 一根模组最近十分钟答没答。
///
/// 🔴 四种格子，四种颜色，**「读不到 agent」必须自成一色**。把它画成「离线」，
/// 一次网络抖动就会在屏幕上变成一段模组掉线——而那是会让人跑一趟机房的结论。
#[component]
fn TraceStrip(state: StatusState, #[prop(into)] imei: String) -> impl IntoView {
    view! {
        <span class="vd-trace" aria-hidden="true">
            {move || {
                let t = state.trace.get();
                crate::trace::strip(&t, &imei, TRACE_COLS)
                    .into_iter()
                    .map(|c| {
                        let cls = match c {
                            crate::trace::Cell::Answering => "vd-tick vd-tick--up",
                            crate::trace::Cell::Silent => "vd-tick vd-tick--down",
                            crate::trace::Cell::Absent => "vd-tick vd-tick--gone",
                            crate::trace::Cell::Unread => "vd-tick vd-tick--unread",
                            crate::trace::Cell::Unobserved => "vd-tick vd-tick--none",
                        };
                        view! { <i class=cls></i> }
                    })
                    .collect_view()
            }}
        </span>
    }
}

/// 舰队一行：在册几根、此刻答几根、观察窗内同时答几根。
///
/// 🔴 **「在册 3、而同时应答从没超过 2」这一句就是结论本身**——它等价于
/// 「总线挂不住三个」，正是 2026-09-04 那次操作员要拿 shell 采六分钟 `lsusb`
/// 才得到的判断。零 agent 改动，全部从轨迹推出来。
#[component]
fn FleetLine(state: StatusState) -> impl IntoView {
    view! {
        {move || {
            let t = state.trace.get();
            let registered = match state.load.get() {
                Load::Ready(b) => b.modems.len(),
                _ => state.stale.get().map(|(b, _)| b.modems.len()).unwrap_or(0),
            };
            let window = crate::trace::window_ms(&t);
            let now = crate::trace::latest_answering(&t);
            let span = crate::trace::concurrency(&t);

            // ⚠️ 观察不足时**什么都不说**。两帧就敢下「总线挂不住三个」的结论，
            //    比不说更坏——它会让人相信一个还没被观察到的模式。
            if window < 60_000.0 || registered == 0 {
                return view! {
                    <span class="vd-fleet vd-faint">
                        {format!("在册 {registered} 根 · 轨迹还在攒（不足 1 分钟）")}
                    </span>
                }.into_any();
            }

            let mins = (window / 60_000.0).round() as i64;
            let now_txt = match now {
                Some((_, n)) => format!("此刻应答 {n}"),
                None => "此刻读不到 agent".to_string(),
            };
            let (lo, hi) = span.unwrap_or((0, 0));
            let span_txt = if lo == hi {
                format!("同时应答恒为 {lo}")
            } else {
                format!("同时应答 {lo}–{hi}")
            };
            // 🔴 这就是那句结论。在册数大于历史同时应答上限 = 挂不住。
            let verdict = registered > hi;

            view! {
                <span class="vd-fleet">
                    <span>{format!("在册 {registered} 根 · {now_txt}")}</span>
                    <span class="vd-faint">{format!("近 {mins} 分钟：{span_txt}")}</span>
                    {verdict
                        .then(|| {
                            view! {
                                <Badge color=BadgeColor::Warning size=BadgeSize::Small>
                                    {format!("{registered} 根在册，但同时最多只应答过 {hi} 根")}
                                </Badge>
                            }
                        })}
                </span>
            }.into_any()
        }}
    }
}

/// 控制口那一行怎么写。
///
/// 🔴 **掉线模组的 `control_port` 是「上一次应答时」的值，不是现在的。**
///
/// 2026-09-04 把这个字段画上卡之后，立刻在生产上撞见：`867018069509705`
/// 掉线 4.8 小时，卡上仍写着 `/dev/cdc-wdm0`，而那个插座早就被
/// `867018069514820` 接管了（日志里 `poll /dev/cdc-wdm0 imei=…514820 ok`）。
/// 屏幕上**两张卡写着同一个端口**，看的人没法知道哪张是真的。
///
/// 端口会易主正是这个字段存在的理由；那就更不能把陈旧的那个说成当前的。
fn port_label(port: Option<&str>, answering: bool) -> String {
    match (port, answering) {
        (Some(p), true) => p.to_string(),
        (Some(p), false) => format!("最后见于 {p}"),
        (None, _) => "控制口 —".to_string(),
    }
}

/// 舰队总览里画多少格：整条轨迹（1 小时）。中栏够宽，不必截。
const TRACE_COLS_WIDE: usize = crate::trace::TRACE_KEEP;

/// 中栏在**没选模组**时画什么。
///
/// 🔴 以前这里是一句「先在左边选一根模组。」，占着半个屏幕什么都不说——而这
/// 正是每次打开面板落地的第一眼。五个标签里有三个在没选模组时毫无意义。
///
/// 现在放舰队总览：三根模组的轨迹**对齐**铺开一小时。轮换是三根之间的相位
/// 关系，单看一根看不出来；这块地方够宽，正好画得下。
#[component]
pub fn FleetOverview(state: StatusState) -> impl IntoView {
    view! {
        <div class="vd-fleetview">
            <FleetLine state=state />

            // 颜色是承重的，所以图例不能省——尤其「读不到 agent」那一格，
            // 它长得不像故障，因为它**不是**故障。
            <div class="vd-legend">
                <span><i class="vd-tick vd-tick--up"></i>"答了"</span>
                <span><i class="vd-tick vd-tick--down"></i>"没答"</span>
                <span><i class="vd-tick vd-tick--gone"></i>"不在列表里"</span>
                <span><i class="vd-tick vd-tick--unread"></i>"没问到 agent（不是模组的事）"</span>
            </div>

            {move || {
                let t = state.trace.get();
                if t.is_empty() {
                    return view! {
                        <Caption1>"还没有观测。状态每 10 秒读一次，轨迹从第一次读到时开始攒。"</Caption1>
                    }.into_any();
                }
                let body = match state.load.get() {
                    Load::Ready(b) => Some(b),
                    _ => state.stale.get().map(|(b, _)| b),
                };
                let Some(body) = body else {
                    return view! { <Caption1>"还没读到模组列表。"</Caption1> }.into_any();
                };
                let window = crate::trace::window_ms(&t);
                let mins = (window / 60_000.0).round() as i64;
                let st = state;
                view! {
                    <div class="vd-fleetrows">
                        {body
                            .modems
                            .into_iter()
                            .map(|m| {
                                let imei = m.imei.clone();
                                let flip = crate::trace::flips(&t, &imei);
                                let up = answering(&m.state);
                                let port = port_label(m.control_port.as_deref(), up);
                                view! {
                                    <div class="vd-fleetrow">
                                        <span class="vd-fleetrow-head">
                                            <b>{m.imei.clone()}</b>
                                            <Badge
                                                color=state_tone(&m.state)
                                                size=BadgeSize::Small
                                            >
                                                {state_label(&m.state)}
                                            </Badge>
                                            <span class="vd-faint">
                                                {m.home.clone().unwrap_or_else(|| "卡归属未知".into())}
                                            </span>
                                            <span class="vd-log-port">{port}</span>
                                            <span class="vd-faint vd-fleetrow-flip">
                                                {if window < 60_000.0 {
                                                    String::new()
                                                } else {
                                                    format!("近 {mins} 分钟翻转 {flip} 次")
                                                }}
                                            </span>
                                        </span>
                                        <TraceStripWide state=st imei=imei />
                                    </div>
                                }
                            })
                            .collect_view()}
                    </div>
                }.into_any()
            }}
        </div>
    }
}

/// 总览里那条更宽的轨迹。和左栏那条同源，只是格数不同。
#[component]
fn TraceStripWide(state: StatusState, #[prop(into)] imei: String) -> impl IntoView {
    view! {
        <span class="vd-trace vd-trace--wide" aria-hidden="true">
            {move || {
                let t = state.trace.get();
                crate::trace::strip(&t, &imei, TRACE_COLS_WIDE)
                    .into_iter()
                    .map(|c| {
                        let cls = match c {
                            crate::trace::Cell::Answering => "vd-tick vd-tick--up",
                            crate::trace::Cell::Silent => "vd-tick vd-tick--down",
                            crate::trace::Cell::Absent => "vd-tick vd-tick--gone",
                            crate::trace::Cell::Unread => "vd-tick vd-tick--unread",
                            crate::trace::Cell::Unobserved => "vd-tick vd-tick--none",
                        };
                        view! { <i class=cls></i> }
                    })
                    .collect_view()
            }}
        </span>
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
    let control_port = modem.control_port.clone();
    // 在 view! 之前算成 bool：`state_raw` 会被 move 进闭包。
    let up = answering(&modem.state);
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
            // 🔴 控制口。2026-09-04 整件事就是「哪个 cdc-wdm 节点消失了」，
            // 而节点在重新枚举时会在模组之间**重新分配**——不写在卡上，
            // 操作员永远拼不出这条因果。agent 一直在给这个字段，只是没人画。
            <span class="vd-modem-line vd-faint">
                {port_label(control_port.as_deref(), up)}
            </span>

            // 最近十分钟的应答轨迹。快照说「现在怎么样」，这条说「一直怎么样」。
            <TraceStrip state=state imei=imei.clone() />
            <span class="vd-modem-line vd-faint vd-modem-flip">
                {
                    let imei = imei.clone();
                    move || {
                        let t = state.trace.get();
                        let w = crate::trace::window_ms(&t);
                        // ⚠️ 翻转次数**必须**配着实际观察长度一起说。只写「翻转
                        //    22 次」不写分母，看着像结论，其实没有尺度。
                        if w < 60_000.0 {
                            return String::new();
                        }
                        let n = crate::trace::flips(&t, &imei);
                        if n == 0 {
                            return String::new();
                        }
                        format!("近 {} 分钟翻转 {n} 次", (w / 60_000.0).round() as i64)
                    }
                }
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
        // 舰队一行在四种画面**之上**：它说的是这一小时的形态，
        // 不属于「这一次读到了什么」。
        <FleetLine state=state />
        {move || match state.load.get() {
            // ① 在飞。和「没有」是两回事。
            Load::Loading => view! { <Spinner label="正在读取 agent…" /> }.into_any(),

            // ② 🔴 失败，画在**这一栏上**，带原因。原版把它折叠成了空列表，
            //    失败原因只出现在另一个标签的控制台里。
            Load::Failed(why) => {
                // 🔴 读不到**不清空列表**。`health.rs` 早就是这么做的
                //    （「下面是上一次的结果」），而这一栏一直是全项目唯一
                //    无条件丢掉上一帧的读取路径。一次网络抖动让四根模组从
                //    屏幕上一起消失，看起来就是「硬件全掉了」——而这块面板
                //    的职责恰恰是在故障时说清「我没问到」和「它没了」的区别。
                let stale = state.stale.get();
                let st = state;
                view! {
                    <MessageBar intent=MessageBarIntent::Error layout=MessageBarLayout::Multiline>
                        <MessageBarBody>
                            <MessageBarTitle>"读不到模组列表"</MessageBarTitle>
                            {why}
                        </MessageBarBody>
                    </MessageBar>
                    {stale
                        .map(|(body, at)| {
                            view! {
                                <MessageBar
                                    intent=MessageBarIntent::Warning
                                    layout=MessageBarLayout::Multiline
                                >
                                    <MessageBarBody>
                                        {format!(
                                            "下面是上一次读到的列表，读于 {} —— 不是现在的状态。",
                                            hhmmss(at),
                                        )}
                                    </MessageBarBody>
                                </MessageBar>
                                <div class="vd-modem-list vd-stale">
                                    {body
                                        .modems
                                        .into_iter()
                                        .map(|m| view! { <ModemCard modem=m state=st /> })
                                        .collect_view()}
                                </div>
                            }
                        })}
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
    let at = now_ms();

    // 🔴 **两个分支都要往轨迹里推一帧。** 只推成功的那些，会在轨迹上造出一段
    // 假的连续——十分钟读不到 agent 会被画成十分钟一切正常。
    match &result {
        Load::Ready(body) => {
            state.last_ok.set(at);
            state.stale.set(Some((body.clone(), at)));
            // 🔴 选中的那一根要是从机队里消失了，就地取消选中——理由见
            //    `selection_after`。只在读成功的这一帧做。
            let kept = selection_after(&body.modems, state.active.get_untracked().as_deref());
            if kept != state.active.get_untracked() {
                state.active.set(kept);
            }
            let seen = body
                .modems
                .iter()
                .map(|m| (m.imei.clone(), answering(&m.state)))
                .collect();
            state
                .trace
                .update(|t| crate::trace::push(t, crate::trace::Frame { at, ok: true, seen }));
        }
        Load::Failed(_) => {
            state.trace.update(|t| {
                crate::trace::push(
                    t,
                    crate::trace::Frame {
                        at,
                        ok: false,
                        seen: Vec::new(),
                    },
                )
            });
        }
        Load::Loading => {}
    }

    state.load.set(result);
    state.in_flight.set(false);
}

/// 读到新列表之后，选中的那一根还该不该留着。
///
/// 🔴 **从机队里消失的模组必须取消选中。** 关射频、USB 复位、扫网这三件事，
/// 面板自己都写着「这一根会暂时从机队消失」。消失期间选中项还挂在那儿，而
/// `manageable()` 对找不到的 IMEI 默认返回 `true` —— 于是 eSIM 切换和危险区
/// 按钮全是亮的，点下去打到一根不存在的模组上。旧面板每次 `load()` 都做这个
/// 核对（`if (activeImei && !modems.some(...)) select(null)`），搬迁时漏了。
///
/// ⚠️ **「掉线」不算消失。** 2026-09-04 起这批模组一直在轮流掉线，一根
/// `Offline` 但仍在列表里的模组，恰恰是你可能想给它做 USB 复位的那一根。
/// 判据只有一个：它还在不在 `modems` 里。
///
/// ⚠️ 只在**读成功**的那一帧调用。读失败时列表是空的，拿它去核对等于每次
/// 网络抖动都把操作员的选中项清掉。
pub fn selection_after(modems: &[ModemBody], active: Option<&str>) -> Option<String> {
    let want = active?;
    modems
        .iter()
        .any(|m| m.imei == want)
        .then(|| want.to_string())
}

/// 这一帧里，这根模组算不算「答了」。
///
/// ⚠️ `Offline` 是 agent 按 `last_seen` 超过 60 秒判的（`edge-panel` 的
/// `STALE_AFTER_MS`）。除它以外的状态都意味着这一轮探测拿到了回应——
/// 包括 `denied`、`notregistered` 这些「答了但注册不上」的。
/// **答没答**和**注册没注册**是两件事，轨迹画的是前者。
pub fn answering(raw: &str) -> bool {
    state_key(raw) != "offline"
}

#[cfg(test)]
mod tests {
    use super::port_label;

    fn modem(imei: &str, state: &str) -> ModemBody {
        ModemBody {
            imei: imei.to_string(),
            family: "EC20".into(),
            state: state.to_string(),
            discovery: "qmi".into(),
            manageable: true,
            capability_origin: edge_panel_api::CapabilityOrigin::Rule,
            carrier_profile: String::new(),
            control_port: None,
            firmware: None,
            home: None,
            home_numeric: None,
            iccid: None,
            imsi: None,
            last_seen: None,
            msisdn: None,
            network: None,
            network_numeric: None,
        }
    }

    /// 🔴 从机队里消失的模组要取消选中，否则之后每个操作都瞄着一根不在的棒子。
    #[test]
    fn a_modem_that_left_the_fleet_stops_being_selected() {
        let fleet = vec![modem("111", "registered")];
        assert_eq!(
            super::selection_after(&fleet, Some("222")),
            None,
            "222 已经不在机队里了"
        );
        assert_eq!(
            super::selection_after(&fleet, Some("111")),
            Some("111".to_string())
        );
        assert_eq!(super::selection_after(&fleet, None), None, "本来就没选");
    }

    /// ⚠️ 掉线**不算**消失。这批模组一直在轮流掉线，而一根掉线但还在列表里的
    /// 模组，恰恰是你可能想给它做 USB 复位的那一根。
    #[test]
    fn going_offline_is_not_the_same_as_leaving_the_fleet() {
        let fleet = vec![modem("111", "Offline")];
        assert_eq!(
            super::selection_after(&fleet, Some("111")),
            Some("111".to_string()),
            "掉线的模组还在列表里，选中项不该被清掉"
        );
    }

    /// 🔴 掉线模组卡上的端口是**旧值**，不能说成当前的。
    ///
    /// 2026-09-04 生产实测：两根模组同时写着 `/dev/cdc-wdm0`，一根心跳 10 秒、
    /// 一根心跳 4.8 小时。不标年龄的话，看的人没法知道哪一根真的在那个插座上。
    #[test]
    fn a_silent_modems_port_is_marked_as_where_it_was_last_seen() {
        assert_eq!(
            port_label(Some("/dev/cdc-wdm0"), true),
            "/dev/cdc-wdm0",
            "还在应答的，端口就是当前的"
        );
        assert_eq!(
            port_label(Some("/dev/cdc-wdm0"), false),
            "最后见于 /dev/cdc-wdm0",
            "不应答的，端口是上一次应答时的值——插座可能已经易主"
        );
    }

    /// 没有端口就说没有，不编造。
    #[test]
    fn a_missing_port_is_never_invented() {
        assert_eq!(port_label(None, true), "控制口 —");
        assert_eq!(port_label(None, false), "控制口 —");
    }

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
