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
    let usb = format!(
        "USB {}:{}",
        c.vendor_id.as_deref().unwrap_or("????"),
        c.product_id.as_deref().unwrap_or("????")
    );
    // 型号在前，USB 身份在后：运维先问「这是什么」，再问「插在哪个口」。
    //
    // 读不到型号就只画 USB 身份，**不填 unknown 也不猜**。这一格是纳管前的
    // 最后一眼，写一个编出来的型号比留空更坏 —— 闸 2 也正是拿这个值去查
    // 规则的，屏幕上说 EC20 而闸按别的判，事后没人能对上账。
    Some(
        match c
            .family
            .as_deref()
            .map(str::trim)
            .filter(|family| !family.is_empty() && *family != "unknown")
        {
            Some(family) => format!("{family} · {usb}"),
            None => usb,
        },
    )
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
        // ⚠️ 全仓库唯一一个不带类型的请求体，而且是对的：`/api/rescan` 的
        // handler 只取 `State`，**根本不收 body**（edge-panel/src/lib.rs 的
        // `rescan_modems`）。给它编一个类型出来会凭空造出一个服务端并不读的
        // 契约。`api.rs` 里那条守卫按路径把它放行。
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

/// 撤销一个串口的探测批准。
///
/// 和 `claim` 成对。服务端会拒绝撤销一根**已经纳管**的模组 —— 撤了那个串口
/// 就不再被打开，而纳管记录还在，机队上会多一根没人说话的模组。那条拒绝的
/// 文案里写着正确顺序（先取消纳管），照原样显示给运维。
async fn revoke(state: StatusState, claims: ClaimState, key: String) {
    claims.set(&key, ClaimNote::Pending);
    let body = edge_panel_api::ClaimCandidateBody {
        candidate_key: key.clone(),
    };
    let got: Load<edge_panel_api::RevokeReceipt> =
        api::post("/api/discoveries/revoke", &body, "撤销探测批准").await;
    match got {
        Load::Ready(receipt) => {
            if receipt.candidate_key != key {
                claims.set(&key, ClaimNote::Failed("回执与候选不一致".into()));
                return;
            }
            // `not-approved` 也是成功 —— 但它说的是「本来就没批准过」，
            // 通常意味着点错了行。不能和「撤掉了」显示成同一件事。
            if receipt.status == "not-approved" {
                claims.set(&key, ClaimNote::Failed("这个候选本来就没有被批准过".into()));
                return;
            }
            claims.set(&key, ClaimNote::Revoked);
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

async fn claim(state: StatusState, claims: ClaimState, key: String) {
    claims.set(&key, ClaimNote::Pending);
    let body = edge_panel_api::ClaimCandidateBody {
        candidate_key: key.clone(),
    };
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

async fn adopt(
    state: StatusState,
    claims: ClaimState,
    key: String,
    imei: String,
    note: Option<String>,
) {
    claims.set(&key, ClaimNote::Pending);
    // 「为什么纳管这一根」在按下按钮的那一刻记下来，是唯一还答得上的时刻。
    // 事后再问，答案就只在某个人的记忆里 —— 0015 建 note 这一列正是为此。
    let body = edge_panel_api::RegistrationBody {
        imei: imei.clone(),
        note,
    };
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
                        <div class="vd-actions">
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
                    </div>

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

        }
}

#[component]
fn List(body: StatusBody, claims: ClaimState, state: StatusState) -> impl IntoView {
    if body.discoveries.is_empty() {
        // 这是真的「一个都没有」，和上面那个「读不到」是两回事。
        return view! { <Caption1>"没有发现任何 USB 候选。"</Caption1> }.into_any();
    }
    let managed: Vec<String> = body.modems.iter().map(|m| m.imei.clone()).collect();

    // 🔴 不用表格。这一栏只有 15rem 宽，六列会挤成一团。竖排一条一块，
    // 和上面的模组列表同一个形状——它们本来就是同一类东西（哪个口上挂着什么）。
    view! {
        <div class="vd-cand-list">
            {body
                .discoveries
                .into_iter()
                .map(|c| {
                    let managed = managed.clone();
                    view! { <Row c=c managed=managed claims=claims state=state /> }
                })
                .collect_view()}
        </div>
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
    // 视图和动作各拿一份：动作那份会被闭包 move 走。
    let imei_shown = imei.clone();
    let detail = c.detail.clone();
    // 🔴 行标识用 USB 路径，不用控制口。
    //
    // 2026-09-04 对着生产 /api/status 核过：`control_port` 在这个机队里**不唯一**
    // ——`/dev/cdc-wdm0` 同时属于 `qmi:usb:1-1.2`（IMEI …9705）和
    // `qmi:usb:1-1.3.1`（IMEI …2811）两个候选。拿它当行标识，屏幕上就是两行
    // 一模一样的东西，而操作员正要在其中一行上按「认领」或「纳管」。
    //
    // `usb_device`（1-1.2 / 1-1.3.1）才是区分它们的东西，也正是运维推理「哪一根
    // 插在哪」时用的东西。原版显示的就是它（`d.usb_device || candidateKey(d)`），
    // 搬迁时我错换成了控制口。控制口仍然画出来，只是降为次要信息。
    let key_for_revoke = key.clone();
    // 每一行自己的备注草稿。放在行上而不是提上去：同时有好几个候选待纳管时，
    // 一个共享的输入框会把上一行打了一半的理由带到下一行去。
    let adopt_note = RwSignal::new(String::new());
    let identity = c
        .usb_device
        .clone()
        .unwrap_or_else(|| c.candidate_key.clone());
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
            <div class="vd-cand">
            <div class="vd-cand-cell">
                <div>
                    <Caption1Strong>{identity}</Caption1Strong>
                </div>
                <div>
                    <Caption1>{port}</Caption1>
                </div>
            </div>
            <div class="vd-cand-cell">
                <Caption1>{transport_label(&c.transport).to_string()}</Caption1>
            </div>
            <div class="vd-cand-cell">
                {move || {
                    let (label, tone) = if held.get() {
                        (state_label("claimed"), state_tone("claimed"))
                    } else {
                        (state_label(&label_key), state_tone(&tone_key))
                    };
                    view! { <Badge color=tone size=BadgeSize::Small>{label}</Badge> }
                }}
            </div>
            <div class="vd-cand-cell">{hw.unwrap_or_else(|| "—".into())}</div>
            // IMEI —— 纳管按的就是它。
            //
            // 机队上三根 EC20 的 vid:pid 一模一样，型号那一格分不出它们；
            // `usb_device` 说的是「插在哪个口」。而纳管这个动作的参数是 IMEI，
            // 屏幕上不画它，运维就是在盲按。还没报出 IMEI 的候选留一个破折号 ——
            // 那种行本来也按不了「纳管」。
            <div class="vd-cand-cell">
                <Caption1>
                    {if imei_shown.is_empty() { "—".to_string() } else { format!("IMEI {imei_shown}") }}
                </Caption1>
            </div>
            <div class="vd-cand-cell">
                {move || {
                    // 认领笔记盖过服务端的详情：操作员刚按下去的那件事,比一条
                    // 上一轮才更新的诊断更要紧。
                    if held.get() {
                        view! {
                            <Caption1>"已确认纳入探测；等待下一轮轮询尝试 AT+CGSN。"</Caption1>
                        }
                            .into_any()
                    } else if note.get() == Some(ClaimNote::Revoked) {
                        view! {
                            <Caption1>"已撤销探测批准；下一轮起不再打开这个口。"</Caption1>
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
            </div>
            <div class="vd-cand-cell">
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
                    {move || {
                        // 只有已批准的行才谈得上撤销。用 `held` 而不是
                        // `skey == "claimed"`：这一次会话里刚批准过、服务端
                        // 还没来得及改状态的那一行，也该能立刻撤回来。
                        held.get().then(|| {
                            let key = key_for_revoke.clone();
                            view! {
                                <Button
                                    disabled=busy
                                    on_click=move |_| {
                                        if !confirmed(
                                            "撤销这个串口的探测批准？\n\
                                             下一轮轮询起不再打开它。\n\
                                             已经纳管的模组会被拒绝——那种要先取消纳管。",
                                        ) {
                                            return;
                                        }
                                        let key = key.clone();
                                        leptos::task::spawn_local(async move {
                                            revoke(state, claims, key).await
                                        });
                                    }
                                >
                                    {move || if busy.get() { "撤销中…" } else { "撤销批准" }}
                                </Button>
                            }
                        })
                    }}
                    {adoptable
                        .then(|| {
                            view! {
                                // 纳管时顺手写下理由。不是必填 —— 逼着填会让人
                                // 打一个句号了事，那比空着更坏。
                                <Input
                                    value=adopt_note
                                    placeholder="为什么纳管它（可空）"
                                />
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
                                        let note = adopt_note.get_untracked().trim().to_string();
                                        let note = (!note.is_empty()).then_some(note);
                                        leptos::task::spawn_local(async move {
                                            adopt(state, claims, key, imei, note).await
                                        });
                                    }
                                >
                                    {move || if busy.get() { "纳管中…" } else { "纳管" }}
                                </Button>
                            }
                        })}
                </Flex>
            </div>
            </div>
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
            family: Some("EC20".into()),
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

    /// 🔴 生产机队里 `control_port` **不唯一**，`usb_device` 才区分得开。
    ///
    /// 2026-09-04 从真实 `/api/status` 抓下来的四个候选里，`/dev/cdc-wdm0`
    /// 同时属于 `qmi:usb:1-1.2`（IMEI …9705）和 `qmi:usb:1-1.3.1`
    /// （IMEI …2811）。拿控制口当行标识，屏幕上就是两行一模一样的东西，
    /// 而操作员正要在其中一行上按「认领」或「纳管」。
    ///
    /// 这个函数是那一列实际用的表达式，抽出来是为了能对着真实形状测。
    fn row_identity(c: &DiscoveryBody) -> String {
        c.usb_device
            .clone()
            .unwrap_or_else(|| c.candidate_key.clone())
    }

    #[test]
    fn two_candidates_sharing_a_control_port_are_still_told_apart() {
        // 真实数据里这两个候选共用 /dev/cdc-wdm0。
        let mut a = candidate();
        a.candidate_key = "qmi:usb:1-1.2".into();
        a.usb_device = Some("1-1.2".into());
        a.control_port = "/dev/cdc-wdm0".into();

        let mut b = candidate();
        b.candidate_key = "qmi:usb:1-1.3.1".into();
        b.usb_device = Some("1-1.3.1".into());
        b.control_port = "/dev/cdc-wdm0".into();

        assert_eq!(a.control_port, b.control_port, "前提：生产里它们确实同口");
        assert_ne!(
            row_identity(&a),
            row_identity(&b),
            "同一个控制口上的两个候选在屏幕上必须分得开"
        );
    }

    /// `usb_device` 缺失时落回 candidate_key —— 那个一定唯一，因为它就是键。
    #[test]
    fn a_candidate_without_a_usb_path_falls_back_to_something_unique() {
        let mut c = candidate();
        c.usb_device = None;
        assert_eq!(row_identity(&c), c.candidate_key);
        assert!(!row_identity(&c).is_empty());
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
    /// 🔴 运维要在这一行上按「纳管」，行上就得说清纳管的是什么。
    ///
    /// 只画 USB vid:pid 是不够的：机队上三根 EC20 的 vid:pid 一模一样
    /// （2c7c:0125），光看这个分不出按的是哪一根。型号回答「这是什么硬件」，
    /// IMEI 回答「是哪一根」—— 缺任何一个，「手动管理」就成了盲按。
    #[test]
    fn a_row_says_what_you_are_about_to_adopt() {
        let c = candidate();
        let text = hardware(&c).expect("有 USB 身份就该有一行硬件说明");
        assert!(text.contains("EC20"), "没说型号：{text}");
        assert!(text.contains("2c7c:0125"), "没说 USB 身份：{text}");
    }

    /// 型号还没读出来时不能编一个 —— 那一格留空比写错强。
    #[test]
    fn an_unread_family_is_left_blank_not_guessed() {
        let mut c = candidate();
        c.family = None;
        let text = hardware(&c).expect("USB 身份还在");
        assert!(text.contains("2c7c:0125"), "USB 身份不该跟着消失：{text}");
        assert!(
            !text.contains("unknown") && !text.contains("EC"),
            "型号读不到时不该编一个：{text}"
        );
    }

    #[test]
    fn hardware_shows_what_it_has_and_marks_what_it_lacks() {
        assert_eq!(
            hardware(&candidate()).as_deref(),
            Some("EC20 · USB 2c7c:0125")
        );

        // 两边各缺一次 —— 只验一边的话，另一边的 "????" 是没人守的。
        //
        // 型号读到了但 USB 身份缺一半时，缺的那一半仍要显式标出来：这一格
        // 是给人看的，"????" 说的是「这里本该有个值，我们没读到」，而留空
        // 会被读成「这块硬件就是这样」。
        let mut no_product = candidate();
        no_product.product_id = None;
        assert_eq!(
            hardware(&no_product).as_deref(),
            Some("EC20 · USB 2c7c:????")
        );

        let mut no_vendor = candidate();
        no_vendor.vendor_id = None;
        assert_eq!(
            hardware(&no_vendor).as_deref(),
            Some("EC20 · USB ????:0125")
        );

        let mut none = candidate();
        none.vendor_id = None;
        none.product_id = None;
        assert_eq!(hardware(&none), None, "两个都没有就不画这一格");
    }
}
