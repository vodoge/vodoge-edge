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
fn Freshness(state: StatusState) -> impl IntoView {
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

fn state_tone(raw: &str) -> BadgeColor {
    match state_key(raw).as_str() {
        "registered" | "home" => BadgeColor::Success,
        "roaming" => BadgeColor::Warning,
        "busy" => BadgeColor::Informative,
        "offline" | "denied" | "notregistered" => BadgeColor::Danger,
        _ => BadgeColor::Subtle,
    }
}

#[component]
fn ModemRow(modem: ModemBody, state: StatusState) -> impl IntoView {
    let imei = modem.imei.clone();
    let selected = {
        let imei = imei.clone();
        move || state.active.get().as_deref() == Some(imei.as_str())
    };
    let on_click = {
        let imei = imei.clone();
        move |_| state.active.set(Some(imei.clone()))
    };
    let origin = match modem.capability_origin {
        edge_panel_api::CapabilityOrigin::Rule => "规则",
        edge_panel_api::CapabilityOrigin::Fallback => "回退",
    };
    view! {
        <TableRow>
            <TableCell>
                <Button
                    appearance=Signal::derive(move || if selected() { ButtonAppearance::Primary } else { ButtonAppearance::Subtle })
                    on_click=on_click
                >
                    {modem.imei.clone()}
                </Button>
            </TableCell>
            <TableCell>{modem.family.clone()}</TableCell>
            <TableCell>
                <Badge color=state_tone(&modem.state)>{modem.state.clone()}</Badge>
            </TableCell>
            <TableCell>{modem.network.clone().unwrap_or_else(|| "—".into())}</TableCell>
            <TableCell>{modem.iccid.clone().unwrap_or_else(|| "—".into())}</TableCell>
            <TableCell>{origin}</TableCell>
        </TableRow>
    }
}

/// 模组列表。**四种画面，一种都不能画成另一种。**
#[component]
pub fn StatusPage(state: StatusState) -> impl IntoView {
    view! {
        <Card>
            <CardHeader>
                <Body1><b>"模组"</b></Body1>
                <CardHeaderAction slot>
                    <Freshness state=state />
                </CardHeaderAction>
            </CardHeader>

            {move || match state.load.get() {
                // ① 在飞。和「没有」是两回事。
                Load::Loading => view! { <Spinner label="正在读取 agent…" /> }.into_any(),

                // ② 🔴 失败，画在**这一页上**，带原因。原版把它折叠成了空列表，
                //    失败原因只出现在另一个标签的控制台里。
                Load::Failed(why) => view! {
                    <MessageBar intent=MessageBarIntent::Error>
                        <MessageBarBody>
                            <MessageBarTitle>"读不到模组列表"</MessageBarTitle>
                            {why}
                        </MessageBarBody>
                    </MessageBar>
                }.into_any(),

                Load::Ready(body) => {
                    let mode = match body.mode {
                        PanelMode::Cloud => "已连上云端",
                        PanelMode::Local => "本地模式（无上行）",
                    };
                    let modems = body.modems.clone();
                    let discoveries = body.discoveries.len();
                    if modems.is_empty() {
                        // ③ 真的没有。这是一句关于这台机器的事实，
                        //    而且要说清下一步——候选存在与否会改变措辞。
                        return view! {
                            <Text>{mode}</Text>
                            <MessageBar intent=MessageBarIntent::Info>
                                <MessageBarBody>
                                    {if discoveries > 0 {
                                        format!("没有已纳管的模组，但看到 {discoveries} 个 USB 候选——它们要先被纳入探测。")
                                    } else {
                                        "没有检测到模组。插上模组后按「重扫 USB」。".to_string()
                                    }}
                                </MessageBarBody>
                            </MessageBar>
                        }.into_any();
                    }
                    // ④ 有数据。
                    let st = state;
                    view! {
                        <Text>{mode}</Text>
                        <Table>
                            <TableHeader>
                                <TableRow>
                                    <TableHeaderCell>"IMEI"</TableHeaderCell>
                                    <TableHeaderCell>"型号"</TableHeaderCell>
                                    <TableHeaderCell>"状态"</TableHeaderCell>
                                    <TableHeaderCell>"驻留网络"</TableHeaderCell>
                                    <TableHeaderCell>"ICCID"</TableHeaderCell>
                                    <TableHeaderCell>"能力来源"</TableHeaderCell>
                                </TableRow>
                            </TableHeader>
                            <TableBody>
                                {modems
                                    .into_iter()
                                    .map(|m| view! { <ModemRow modem=m state=st /> })
                                    .collect_view()}
                            </TableBody>
                        </Table>
                    }.into_any()
                }
            }}
        </Card>
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
