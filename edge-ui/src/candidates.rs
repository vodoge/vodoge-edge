//! USB / 串口候选：两个**不一样**的决定。
//!
//! 🔴 这一栏最容易被误解的地方，是它上面那两个按钮不是同一件事的两种说法：
//!
//! - **确认纳入探测**（claim）：批准 agent 去问一个**还没人跟它说过话**的串口。
//!   下一轮轮询才会向它发 `AT+CGSN`。这里既不录端口也不录 IMEI —— 认领只是给
//!   下一轮轮询上膛，**HTTP 回执不是模组身份**。
//! - **纳管**（adopt）：模组已经用 IMEI 应答过了，剩下的问题只是这台 agent 要不
//!   要管它。
//!
//! 把两者混成一个「确认」按钮，就等于让操作员在不知道自己批准了什么的情况下
//! 按下去。原版把它们分开了，这里照搬。
//!
//! ⚠️ 认领成功之后**不立刻刷新**。立刻刷新会拿到还没被探测过的旧状态，而屏幕
//! 上「已纳入探测」紧跟着一个「已发现」，看起来就像认领没生效。等一个轮询周期
//! 再刷 —— 原版的注释把这件事写得很清楚，这里保留。

use std::collections::HashMap;

use edge_panel_api::{ClaimReceipt, DiscoveryBody, RegistrationResult, RescanReceipt, StatusBody};
use leptos::prelude::*;
use thaw::*;

use crate::api::{self, Load};
use crate::status::{ClaimNote, StatusState, STATUS_EVERY_MS};

/// 候选状态归一化。原版：小写之后只留字母。
///
/// ⚠️ 「只留字母」不是随手写的：`probe-failed` / `probe_failed` / `ProbeFailed`
/// 都要落到同一个键上，而服务端这个字段是自由文本。
fn state_key(state: &str) -> String {
    state
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .collect()
}

fn state_label(key: &str) -> &'static str {
    match key {
        "manageable" => "可管理",
        "probefailed" => "探测失败",
        "atonly" => "仅 AT 识别",
        "claimed" => "已纳入探测/等待识别",
        _ => "已发现",
    }
}

/// 接口类型。⚠️ 只认 agent 真的会写的三种（`edge-bin` 的 `DiscoveryTransport::
/// wire`）：`qmi` / `at` / `serial`。旧面板这里犯过错——给「serial」漏掉了
/// 标签，又给一堆 agent 从没写过的拼法发明了标签。这里反过来：三种精确认领，
/// 见到没见过的原样显示，绝不瞎编一个像是发明出来的标签。
fn transport_label(transport: &str) -> &str {
    match transport {
        "qmi" => "QMI",
        "at" => "AT",
        "serial" => "串口",
        other => other,
    }
}

fn state_tone(key: &str) -> BadgeColor {
    match key {
        "manageable" => BadgeColor::Success,
        "probefailed" => BadgeColor::Danger,
        "atonly" | "found" => BadgeColor::Warning,
        _ => BadgeColor::Informative,
    }
}

/// 认领只对**串口**且**还没被探测过**的候选有意义。
fn can_claim(c: &DiscoveryBody) -> bool {
    c.transport == "serial" && state_key(&c.state) == "found" && !c.candidate_key.is_empty()
}

/// 纳管的前提是它已经报出过 IMEI，而且还不在管理列表里。
fn can_adopt(c: &DiscoveryBody, modems: &[String]) -> bool {
    match c.imei.as_deref() {
        Some(imei) if !imei.is_empty() => !modems.iter().any(|m| m == imei),
        _ => false,
    }
}

fn hardware(c: &DiscoveryBody) -> Option<String> {
    if c.vendor_id.is_none() && c.product_id.is_none() {
        return None;
    }
    Some(format!(
        "USB {}:{}",
        c.vendor_id.as_deref().unwrap_or("????"),
        c.product_id.as_deref().unwrap_or("????")
    ))
}

/// 浏览器自带的确认框。
///
/// ⚠️ 用原生的而不是 Thaw 的 `Dialog`：这两个按钮各自会改变现场硬件的行为，
/// 而原生确认框是**模态**的、无法被样式表藏起来、也不会因为这段 wasm 出问题就
/// 静默放行。这里要的正是这几点。
fn confirmed(message: &str) -> bool {
    web_sys::window()
        .and_then(|w| w.confirm_with_message(message).ok())
        .unwrap_or(false)
}

/// 主动重扫 USB 设备与控制口。
///
/// ⚠️ 这个按钮**不读取**任何东西——`POST /api/rescan` 只是把轮询循环的等待
/// 打断，真正的探测在下一轮轮询里发生。原版的注释把这件事写得很清楚：立刻
/// 回读会拿到打断前的旧缓存，所以诚实的做法是把这次请求的结果说成「已请求」，
/// 让正常的状态刷新去带回新的发现记录——不在这次往返里假装已经看到了新结果。
#[derive(Clone, Copy)]
pub struct RescanState {
    pub busy: RwSignal<bool>,
    /// 上一次重扫完成（或失败）的时刻。
    pub at: RwSignal<Option<f64>>,
    pub note: RwSignal<Option<String>>,
    pub failed: RwSignal<bool>,
}

impl RescanState {
    pub fn new() -> Self {
        Self {
            busy: RwSignal::new(false),
            at: RwSignal::new(None),
            note: RwSignal::new(None),
            failed: RwSignal::new(false),
        }
    }
}

pub async fn rescan(state: StatusState, rescan: RescanState) {
    if rescan.busy.get_untracked() {
        return;
    }
    rescan.busy.set(true);
    rescan.note.set(Some("正在读取 USB 设备与控制口…".into()));
    let got: Load<RescanReceipt> =
        api::post("/api/rescan", &serde_json::json!({}), "重扫 USB").await;
    rescan.busy.set(false);
    rescan.at.set(Some(crate::status::now_ms()));
    match got {
        Load::Ready(receipt) => {
            rescan.failed.set(false);
            rescan.note.set(Some(requested_note(&receipt)));
            // ⚠️ 探测在下一轮轮询里发生，不在这次请求里——给它一秒钟，再刷
            // 一次状态，好让新的发现记录能被看到。原版用的也是这个数。
            crate::sleep(1_000).await;
            crate::status::poll(state).await;
        }
        Load::Failed(why) => {
            rescan.failed.set(true);
            rescan.note.set(Some(format!("重扫失败 · {why}")));
        }
        Load::Loading => {}
    }
}

/// 「已请求重扫」这句话，抽成纯函数好测。
///
/// ⚠️ 说的是「已请求」不是「已完成」——见模块文档，这次往返里还没有新结果。
fn requested_note(receipt: &RescanReceipt) -> String {
    let ports = if receipt.control_ports.is_empty() {
        String::new()
    } else {
        format!(" · {}", receipt.control_ports.join("、"))
    };
    format!(
        "已请求重扫 · {} 个控制口{ports} · 等待下一轮探测结果",
        receipt.found
    )
}

/// 每个候选各自的认领笔记。键是 `candidate_key`。
#[derive(Clone, Copy)]
pub struct ClaimState {
    notes: RwSignal<HashMap<String, ClaimNote>>,
}

impl ClaimState {
    pub fn new() -> Self {
        Self {
            notes: RwSignal::new(HashMap::new()),
        }
    }

    fn note(&self, key: &str) -> Option<ClaimNote> {
        self.notes.get().get(key).cloned()
    }

    fn set(&self, key: &str, note: ClaimNote) {
        self.notes.update(|m| {
            m.insert(key.to_string(), note);
        });
    }
}

async fn claim(state: StatusState, claims: ClaimState, key: String) {
    claims.set(&key, ClaimNote::Pending);
    let body = serde_json::json!({ "candidate_key": key });
    let got: Load<ClaimReceipt> = api::post("/api/discoveries/claim", &body, "纳入探测").await;
    match got {
        Load::Ready(receipt) => {
            // 回执要对得上。回执说的是另一个候选,就不能拿它当这一个的成功 ——
            // 原版这条检查是对的,搬过来。
            if receipt.status != "claimed" || receipt.candidate_key != key {
                claims.set(&key, ClaimNote::Failed("回执与候选不一致".into()));
                return;
            }
            claims.set(&key, ClaimNote::Claimed);
            // ⚠️ 等一个轮询周期再刷。认领只是给下一轮轮询上膛,立刻刷会拿到
            // 还没被探测过的旧状态。
            set_timeout(
                move || {
                    leptos::task::spawn_local(async move { crate::status::poll(state).await });
                },
                std::time::Duration::from_millis(STATUS_EVERY_MS),
            );
        }
        Load::Failed(why) => claims.set(&key, ClaimNote::Failed(why)),
        Load::Loading => {}
    }
}

async fn adopt(state: StatusState, claims: ClaimState, key: String, imei: String) {
    claims.set(&key, ClaimNote::Pending);
    let body = serde_json::json!({ "imei": imei });
    let got: Load<RegistrationResult> = api::post("/api/modems/register", &body, "纳管").await;
    match got {
        Load::Ready(result) => {
            if !result.registered || result.imei != imei {
                claims.set(&key, ClaimNote::Failed("纳管回执与候选不一致".into()));
                return;
            }
            claims.set(&key, ClaimNote::Claimed);
            // 纳管是立刻生效的（模组已经报过 IMEI），所以这里可以马上刷。
            leptos::task::spawn_local(async move { crate::status::poll(state).await });
        }
        Load::Failed(why) => claims.set(&key, ClaimNote::Failed(why)),
        Load::Loading => {}
    }
}

#[component]
pub fn CandidatesPage(
    state: StatusState,
    claims: ClaimState,
    rescan_state: RescanState,
) -> impl IntoView {
    view! {
        <Card>
            <CardHeader>
                <Body1><b>"USB 候选"</b></Body1>
                <CardHeaderAction slot>
                    <Button
                        disabled=rescan_state.busy
                        on_click=move |_| {
                            leptos::task::spawn_local(async move {
                                rescan(state, rescan_state).await
                            });
                        }
                    >
                        {move || if rescan_state.busy.get() { "重扫中…" } else { "重扫 USB" }}
                    </Button>
                </CardHeaderAction>
            </CardHeader>
            {move || {
                rescan_state
                    .note
                    .get()
                    .map(|note| {
                        let intent = if rescan_state.failed.get() {
                            MessageBarIntent::Error
                        } else {
                            MessageBarIntent::Info
                        };
                        view! {
                            <MessageBar intent=intent layout=MessageBarLayout::Multiline>
                                <MessageBarBody>{note}</MessageBarBody>
                            </MessageBar>
                        }
                    })
            }}
            {move || match state.load.get() {
                // 🔴 三态分开。读不到候选**不是**「没有候选」——后者会让操作员
                // 以为线插错了，然后去拔一根好好的线。
                Load::Loading => view! { <Caption1>"正在读候选…"</Caption1> }.into_any(),
                Load::Failed(why) => {
                    view! {
                        <MessageBar
                            intent=MessageBarIntent::Error
                            layout=MessageBarLayout::Multiline
                        >
                            <MessageBarBody>
                                <MessageBarTitle>"这次没读到"</MessageBarTitle>
                                {why}
                            </MessageBarBody>
                        </MessageBar>
                    }
                        .into_any()
                }
                Load::Ready(body) => view! { <List body=body claims=claims state=state /> }.into_any(),
            }}
        </Card>
    }
}

#[component]
fn List(body: StatusBody, claims: ClaimState, state: StatusState) -> impl IntoView {
    if body.discoveries.is_empty() {
        // 这是真的「一个都没有」，和上面那个「读不到」是两回事。
        return view! { <Caption1>"没有发现任何 USB 候选。"</Caption1> }.into_any();
    }
    let managed: Vec<String> = body.modems.iter().map(|m| m.imei.clone()).collect();

    view! {
        <Table>
            <TableHeader>
                <TableRow>
                    <TableHeaderCell>"候选"</TableHeaderCell>
                    <TableHeaderCell>"接口"</TableHeaderCell>
                    <TableHeaderCell>"状态"</TableHeaderCell>
                    <TableHeaderCell>"硬件"</TableHeaderCell>
                    <TableHeaderCell>"详情"</TableHeaderCell>
                    <TableHeaderCell>"操作"</TableHeaderCell>
                </TableRow>
            </TableHeader>
            <TableBody>
                {body
                    .discoveries
                    .into_iter()
                    .map(|c| {
                        let managed = managed.clone();
                        view! { <Row c=c managed=managed claims=claims state=state /> }
                    })
                    .collect_view()}
            </TableBody>
        </Table>
    }
    .into_any()
}

#[component]
fn Row(
    c: DiscoveryBody,
    managed: Vec<String>,
    claims: ClaimState,
    state: StatusState,
) -> impl IntoView {
    let key = c.candidate_key.clone();
    let skey = state_key(&c.state);
    let claimable = can_claim(&c);
    let adoptable = can_adopt(&c, &managed);
    let imei = c.imei.clone().unwrap_or_default();
    let detail = c.detail.clone();
    let port = c.control_port.clone();
    let hw = hardware(&c);

    // 服务端已经说它 claimed，或者这一次会话里刚认领成功过。
    let held = {
        let key = key.clone();
        let skey = skey.clone();
        Memo::new(move |_| {
            skey == "claimed" || claims.note(&key) == Some(ClaimNote::Claimed) && skey == "found"
        })
    };

    let note = {
        let key = key.clone();
        Memo::new(move |_| claims.note(&key))
    };

    let busy = Memo::new(move |_| note.get() == Some(ClaimNote::Pending));

    let label_key = skey.clone();
    let tone_key = skey.clone();

    view! {
        <TableRow>
            <TableCell>
                <Caption1>{port}</Caption1>
            </TableCell>
            <TableCell>
                <Caption1>{transport_label(&c.transport).to_string()}</Caption1>
            </TableCell>
            <TableCell>
                {move || {
                    let (label, tone) = if held.get() {
                        (state_label("claimed"), state_tone("claimed"))
                    } else {
                        (state_label(&label_key), state_tone(&tone_key))
                    };
                    view! { <Badge color=tone size=BadgeSize::Small>{label}</Badge> }
                }}
            </TableCell>
            <TableCell>{hw.unwrap_or_else(|| "—".into())}</TableCell>
            <TableCell>
                {move || {
                    // 认领笔记盖过服务端的详情：操作员刚按下去的那件事,比一条
                    // 上一轮才更新的诊断更要紧。
                    if held.get() {
                        view! {
                            <Caption1>"已确认纳入探测；等待下一轮轮询尝试 AT+CGSN。"</Caption1>
                        }
                            .into_any()
                    } else if let Some(ClaimNote::Failed(why)) = note.get() {
                        view! {
                            <MessageBar
                                intent=MessageBarIntent::Error
                                layout=MessageBarLayout::Multiline
                            >
                                <MessageBarBody>{format!("失败 · {why}")}</MessageBarBody>
                            </MessageBar>
                        }
                            .into_any()
                    } else if detail.is_empty() {
                        view! { <Caption1>"未返回诊断详情"</Caption1> }.into_any()
                    } else {
                        let detail = detail.clone();
                        view! { <Caption1>{detail}</Caption1> }.into_any()
                    }
                }}
            </TableCell>
            <TableCell>
                <Flex gap=FlexGap::Small style="flex-wrap: wrap;">
                    {claimable
                        .then(|| {
                            let key = key.clone();
                            view! {
                                <Button
                                    disabled=Signal::derive(move || busy.get() || held.get())
                                    on_click=move |_| {
                                        if !confirmed(
                                            "确认将这个已发现的串口候选纳入探测？\n\
                                             不会手动录入端口或 IMEI；下一轮轮询才会向现有候选尝试 AT+CGSN。",
                                        ) {
                                            return;
                                        }
                                        let key = key.clone();
                                        leptos::task::spawn_local(async move {
                                            claim(state, claims, key).await
                                        });
                                    }
                                >
                                    {move || if busy.get() { "确认中…" } else { "确认纳入探测" }}
                                </Button>
                            }
                        })}
                    {adoptable
                        .then(|| {
                            let key = key.clone();
                            let imei = imei.clone();
                            view! {
                                <Button
                                    appearance=ButtonAppearance::Primary
                                    disabled=busy
                                    on_click=move |_| {
                                        let key = key.clone();
                                        let imei = imei.clone();
                                        leptos::task::spawn_local(async move {
                                            adopt(state, claims, key, imei).await
                                        });
                                    }
                                >
                                    {move || if busy.get() { "纳管中…" } else { "纳管" }}
                                </Button>
                            }
                        })}
                </Flex>
            </TableCell>
        </TableRow>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate() -> DiscoveryBody {
        DiscoveryBody {
            candidate_key: "serial:usb:2-4.2:port:/dev/ttyUSB8".into(),
            usb_device: Some("2-4.2".into()),
            transport: "serial".into(),
            control_port: "/dev/ttyUSB8".into(),
            vendor_id: Some("2c7c".into()),
            product_id: Some("0125".into()),
            state: "found".into(),
            imei: None,
            detail: "no identity yet".into(),
            last_seen: 0,
        }
    }

    /// 认领只对串口候选有意义，而且只在它还没被探测过的时候。
    #[test]
    fn claiming_is_offered_only_where_it_means_anything() {
        assert!(can_claim(&candidate()));

        let mut probed = candidate();
        probed.state = "manageable".into();
        assert!(!can_claim(&probed), "已经能管的不需要再批准探测");

        let mut usb = candidate();
        usb.transport = "qmi".into();
        assert!(!can_claim(&usb), "认领是给串口候选的");

        let mut nameless = candidate();
        nameless.candidate_key = String::new();
        assert!(!can_claim(&nameless), "没有 key 就没有可认领的东西");
    }

    /// 纳管的前提是它报过 IMEI，而且还没被管着。
    #[test]
    fn adopting_needs_an_imei_that_is_not_already_managed() {
        let mut c = candidate();
        assert!(!can_adopt(&c, &[]), "没有 IMEI 就不该给纳管按钮");

        c.imei = Some("867018069509705".into());
        assert!(can_adopt(&c, &[]));
        assert!(
            !can_adopt(&c, &["867018069509705".to_string()]),
            "已经在管的不该再出现纳管按钮"
        );
    }

    /// 说的是「已请求」不是「已完成」——这次往返没有新结果，只有一个被
    /// 打断的等待。
    #[test]
    fn the_rescan_note_says_requested_not_done() {
        let receipt = edge_panel_api::RescanReceipt {
            status: "requested".into(),
            found: 2,
            control_ports: vec!["/dev/cdc-wdm0".into(), "/dev/ttyUSB2".into()],
        };
        let note = requested_note(&receipt);
        assert!(note.contains("已请求"), "{note}");
        assert!(!note.contains("已完成") && !note.contains("完成"), "{note}");
        assert!(note.contains("2 个控制口"), "{note}");
        assert!(note.contains("/dev/cdc-wdm0"), "端口要列出来：{note}");
        assert!(note.contains("等待下一轮"), "要说清结果还没到：{note}");
    }

    /// 没有控制口时不留一个空的顿号。
    #[test]
    fn the_rescan_note_has_no_dangling_separator_with_no_ports() {
        let receipt = edge_panel_api::RescanReceipt {
            status: "requested".into(),
            found: 0,
            control_ports: Vec::new(),
        };
        let note = requested_note(&receipt);
        assert!(!note.contains("· ·"), "{note}");
        assert!(!note.trim_end().ends_with('、'), "{note}");
    }

    /// 三种接口类型精确认领，见到没见过的原样显示——不瞎编。
    #[test]
    fn transport_labels_are_exact_and_never_invented() {
        assert_eq!(transport_label("qmi"), "QMI");
        assert_eq!(transport_label("at"), "AT");
        assert_eq!(transport_label("serial"), "串口");
        assert_eq!(
            transport_label("mbim"),
            "mbim",
            "mbim 是 USBNET 模式，不是接口类型，这里没见过就原样显示，不套用别处的标签"
        );
    }

    /// 状态键归一化：服务端这个字段是自由文本。
    #[test]
    fn the_state_key_survives_however_the_agent_spells_it() {
        for spelling in ["probefailed", "probe-failed", "probe_failed", "ProbeFailed"] {
            assert_eq!(state_key(spelling), "probefailed", "拼法：{spelling}");
            assert_eq!(state_label(&state_key(spelling)), "探测失败");
        }
        // 没见过的状态不编造标签，落回「已发现」。
        assert_eq!(state_label(&state_key("brand new thing")), "已发现");
    }

    #[test]
    fn hardware_shows_what_it_has_and_marks_what_it_lacks() {
        assert_eq!(hardware(&candidate()).as_deref(), Some("USB 2c7c:0125"));

        // 两边各缺一次 —— 只验一边的话，另一边的 "????" 是没人守的。
        let mut no_product = candidate();
        no_product.product_id = None;
        assert_eq!(hardware(&no_product).as_deref(), Some("USB 2c7c:????"));

        let mut no_vendor = candidate();
        no_vendor.vendor_id = None;
        assert_eq!(hardware(&no_vendor).as_deref(), Some("USB ????:0125"));

        let mut none = candidate();
        none.vendor_id = None;
        none.product_id = None;
        assert_eq!(hardware(&none), None, "两个都没有就不画这一格");
    }
}
