//! eSIM profile。
//!
//! 🔴 **这一栏不采信端点的答复。**
//!
//! 原版的注释把理由写得很直白：这个端点在一次**没发生**的切换上回过 ok，也在
//! 一次**发生了**的切换上回过 error。所以两种答复落到同一个地方 —— 记下来，
//! 但不当结果。真正的结果来自等卡片 REFRESH 之后回读 `/api/esim`。
//!
//! 屏幕上分开写两件事：**端点声称了什么**，和**卡说了什么**。
//!
//! ## 五种判决
//!
//! | 判决 | 意思 |
//! |---|---|
//! | `Refused` | 对话框里点了取消。**一个字节都没发出去。** |
//! | `Match` | 回读到的状态和请求一致。端点当时若报了失败，特别点出来。 |
//! | `Mismatch` | 回读到的状态和请求不一致。端点若回的是 ok，那是一次**假成功**。 |
//! | `Missing` | 回读到的列表里根本没有这条 ICCID。面板不替卡猜。 |
//! | `Unknown` | 回读本身失败了。**不知道**，而面板不会拿端点的答复来顶替。 |
//!
//! `Unknown` 是最要紧的一格：它不是 `Mismatch`。「不知道」和「没生效」要人做
//! 的事完全不同。

use edge_panel_api::{ProfileBody, ProfilesResult, SwitchBody};
use leptos::prelude::*;
use thaw::*;

use crate::api::{self, Load};
use crate::status::StatusState;

/// 等卡片多久再去问它。
///
/// ⚠️ 改版前的面板切换之后也是等 8 秒才刷新机队。读得更早，报的是 REFRESH 还
/// 没走完的那个状态。
const SETTLE_MS: u64 = 8_000;

fn class_label(class: Option<u8>) -> &'static str {
    match class {
        Some(0) => "测试",
        Some(1) => "预置",
        Some(2) => "运营",
        _ => "—",
    }
}

/// 一条 profile 在屏幕上叫什么。
///
/// ⚠️ 顺序是 nickname → name → provider → ICCID。落到 ICCID 也比空着强 ——
/// 一条没有名字的 profile，操作员没法在对话框里认出自己要动的是哪一条。
pub fn profile_name(p: &ProfileBody) -> String {
    for candidate in [&p.nickname, &p.name, &p.provider] {
        if let Some(value) = candidate {
            if !value.is_empty() {
                return value.clone();
            }
        }
    }
    if !p.label.is_empty() {
        return p.label.clone();
    }
    p.iccid.clone()
}

/// 一次切换的结局。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// 还在确认。
    Pending,
    /// 取消了，什么都没发出去。
    Refused,
    Match,
    Mismatch,
    Missing,
    Unknown,
}

/// 一次切换的回执。
///
/// 🔴 `claim` 和 `seen` 是**两个字段**，这是这一整块的核心：一个是端点声称的，
/// 一个是卡回读出来的。合成一个字段，就等于让端点替卡说话。
#[derive(Clone, Debug, PartialEq)]
pub struct Receipt {
    pub iccid: String,
    pub label: String,
    pub enable: bool,
    pub at: f64,
    /// 进行到哪一步（等待中显示）。
    pub step: String,
    /// 端点**声称**的。空字符串表示还没有答复。
    pub claim: String,
    /// 端点是不是报了失败。判决文本要用到它。
    pub endpoint_failed: bool,
    /// 卡**回读**出来的启用状态。
    pub seen: Option<bool>,
    pub seen_text: String,
    pub verdict: Verdict,
    pub verdict_text: String,
}

/// 拿回读到的列表给一次切换下判决。
///
/// ⚠️ 纯函数，好让它能被直接测 —— 这一段是整个面板最不能出错的判断之一。
pub fn judge(receipt: &mut Receipt, profiles: &[ProfileBody], read_at: &str) {
    receipt.step = String::new();
    let Some(found) = profiles.iter().find(|p| p.iccid == receipt.iccid) else {
        receipt.verdict = Verdict::Missing;
        receipt.seen = None;
        receipt.seen_text = "列表里没有这条 ICCID".into();
        receipt.verdict_text = format!(
            "无法确认：回读到的 profile 列表里根本没有 {}。面板不替卡猜它现在是什么状态。",
            receipt.iccid
        );
        return;
    };
    receipt.seen = Some(found.enabled);
    receipt.seen_text = format!(
        "{} · 读于 {read_at}",
        if found.enabled {
            "已启用"
        } else {
            "未启用"
        }
    );
    if found.enabled == receipt.enable {
        receipt.verdict = Verdict::Match;
        receipt.verdict_text = format!(
            "已生效：回读到 {} 现在{}，与请求一致。{}",
            receipt.label,
            if receipt.enable {
                "已启用"
            } else {
                "未启用"
            },
            if receipt.endpoint_failed {
                "注意：端点当时报的是失败，卡却确实换了 —— 以回读为准。"
            } else {
                ""
            }
        );
    } else {
        receipt.verdict = Verdict::Mismatch;
        receipt.verdict_text = format!(
            "没有生效：请求{} {}，回读却显示它{}。{}",
            if receipt.enable { "启用" } else { "停用" },
            receipt.label,
            if found.enabled {
                "仍然是已启用"
            } else {
                "仍然是未启用"
            },
            if receipt.endpoint_failed {
                "端点也报了失败，两边一致 —— 卡没有被改动。"
            } else {
                "而端点回的是 ok —— 这是一次假成功，不要当它做过。"
            }
        );
    }
}

/// 切换之前给操作员看的那段话。
pub fn ask(
    profile: &ProfileBody,
    enable: bool,
    profiles: &[ProfileBody],
    imei: Option<&str>,
) -> String {
    let name = profile_name(profile);
    let live = profiles.iter().find(|p| p.enabled);
    let mut lines = vec![
        format!("{} profile {name}", if enable { "启用" } else { "停用" }),
        String::new(),
        format!("ICCID：{}", profile.iccid),
        format!("目标：{}", imei.unwrap_or("未选模组")),
    ];
    if enable {
        if let Some(live) = live {
            if live.iccid != profile.iccid {
                lines.push(format!(
                    "代价：{} 会被一并停用 —— 卡上同一时刻只有一个 profile 启用。",
                    profile_name(live)
                ));
            }
        }
    }
    lines.push(String::new());
    lines.push("切换会把模组从它当前的网络上摘下来，直到卡片 REFRESH 完成。".into());
    if !enable {
        if let Some(live) = live {
            if live.iccid == profile.iccid {
                lines.push("停用之后卡上没有启用中的 profile —— 这一根没有网络可以回去。".into());
            }
        }
    }
    lines.push("这批硬件没有人能物理接触，插拔不是退路。".into());
    lines.push(String::new());
    lines.push(format!(
        "发出之后端点回的 ok 不作数：面板会等 {} 秒再回读 /api/esim，屏幕上写的是回读到的状态。",
        SETTLE_MS / 1000
    ));
    lines.push(String::new());
    lines.push("确定要发出去吗？".into());
    lines.join("\n")
}

#[derive(Clone, Copy)]
pub struct EsimState {
    pub profiles: RwSignal<Load<ProfilesResult>>,
    /// `None` 表示这一次会话还没有切换过。
    pub receipt: RwSignal<Option<Receipt>>,
    /// 还没读过。⚠️ 和「读到了但是空的」是两回事。
    pub read: RwSignal<bool>,
}

impl EsimState {
    pub fn new() -> Self {
        Self {
            profiles: RwSignal::new(Load::Loading),
            receipt: RwSignal::new(None),
            read: RwSignal::new(false),
        }
    }

    /// 换了一根模组，这一栏手上的东西全部作废。
    ///
    /// 🔴 profile 列表是**某一张卡**的。留在屏幕上配着另一根模组的标题，它就被
    /// 读成那一根的了——而这一栏的按钮会拿着表里的 ICCID 和当前选中的 IMEI 去
    /// 发真正的 ES10c 写操作。切换回执同理：一次判决是关于一张卡的。
    ///
    /// `read` 也要清，否则按钮会写着「重新读取」，等于替新模组宣称「已经读过了」。
    pub fn forget_modem(&self) {
        self.profiles.set(Load::Loading);
        self.receipt.set(None);
        self.read.set(false);
    }
}

fn confirmed(message: &str) -> bool {
    web_sys::window()
        .and_then(|w| w.confirm_with_message(message).ok())
        .unwrap_or(false)
}

fn hhmmss(at: f64) -> String {
    let date = js_sys::Date::new(&at.into());
    format!(
        "{:02}:{:02}:{:02}",
        date.get_hours(),
        date.get_minutes(),
        date.get_seconds()
    )
}

async fn read(state: EsimState, imei: Option<String>) -> Option<ProfilesResult> {
    state.profiles.set(Load::Loading);
    let body = serde_json::json!({ "imei": imei });
    let got: Load<ProfilesResult> = api::post("/api/esim", &body, "eSIM").await;
    state.read.set(true);
    let out = match &got {
        Load::Ready(result) => Some(result.clone()),
        _ => None,
    };
    state.profiles.set(got);
    out
}

async fn switch(state: EsimState, imei: Option<String>, iccid: String, enable: bool) {
    let profiles = match state.profiles.get_untracked() {
        Load::Ready(result) => result.profiles,
        _ => Vec::new(),
    };
    let profile = profiles
        .iter()
        .find(|p| p.iccid == iccid)
        .cloned()
        .unwrap_or_else(|| ProfileBody {
            iccid: iccid.clone(),
            label: String::new(),
            enabled: false,
            provider: None,
            name: None,
            nickname: None,
            class: None,
            isdp_aid: None,
        });
    let label = profile_name(&profile);

    if !confirmed(&ask(&profile, enable, &profiles, imei.as_deref())) {
        // 取消也要留痕。没有痕迹的话，操作员剩下的正是这个对话框本来要消除的
        // 那份不确定：到底发出去了没有。
        state.receipt.set(Some(Receipt {
            iccid,
            label,
            enable,
            at: crate::status::now_ms(),
            step: String::new(),
            claim: "没有发出".into(),
            endpoint_failed: false,
            seen: None,
            seen_text: "卡没有被碰过".into(),
            verdict: Verdict::Refused,
            verdict_text: "已取消：一个字节都没有发出去，卡上的状态没有变。".into(),
        }));
        return;
    }

    state.receipt.set(Some(Receipt {
        iccid: iccid.clone(),
        label: label.clone(),
        enable,
        at: crate::status::now_ms(),
        step: "发送中…".into(),
        claim: String::new(),
        endpoint_failed: false,
        seen: None,
        seen_text: String::new(),
        verdict: Verdict::Pending,
        verdict_text: "还在确认 —— 结果以回读为准。".into(),
    }));

    let body = SwitchBody {
        iccid: iccid.clone(),
        enable,
        imei: imei.clone(),
    };
    let sent: Load<serde_json::Value> = api::post("/api/esim/switch", &body, "切换 profile").await;
    state.receipt.update(|r| {
        if let Some(r) = r {
            match &sent {
                Load::Failed(why) => {
                    r.endpoint_failed = true;
                    r.claim = format!("失败：{why}");
                }
                _ => r.claim = "ok".into(),
            }
            // ⚠️ 两种答复落到**同一条路**上，理由是一样的：这个端点在没发生的
            // 切换上回过 ok，也在发生了的切换上回过 error。下一步都是问卡。
            r.step = format!("等卡片 REFRESH… {} 秒", SETTLE_MS / 1000);
        }
    });

    crate::sleep(SETTLE_MS).await;

    state.receipt.update(|r| {
        if let Some(r) = r {
            r.step = "回读 /api/esim…".into();
        }
    });

    match read(state, imei).await {
        Some(result) => {
            let at = hhmmss(crate::status::now_ms());
            state.receipt.update(|r| {
                if let Some(r) = r {
                    judge(r, &result.profiles, &at);
                }
            });
        }
        None => {
            // 🔴 第三种结局，而且它**不是**「没生效」：谁也不知道。
            let why = match state.profiles.get_untracked() {
                Load::Failed(why) => why,
                _ => "读不到".into(),
            };
            state.receipt.update(|r| {
                if let Some(r) = r {
                    r.step = String::new();
                    r.verdict = Verdict::Unknown;
                    r.seen_text = "回读失败".into();
                    r.verdict_text = format!(
                        "无法确认：回读 /api/esim 失败（{why}）。卡是什么状态不知道 —— \
                         面板不会拿端点的答复来顶替。"
                    );
                }
            });
        }
    }
}

#[component]
pub fn EsimPage(
    active: RwSignal<Option<String>>,
    state: EsimState,
    status: StatusState,
) -> impl IntoView {
    // 🔴 这一根走不走 QMI。eSIM 的每一个操作都走 QMI（ES10c 要开逻辑通道），
    // 所以 AT-only 的模组在这里**一件事都做不了**——服务端会以
    // `no matching QMI modem` 拒掉，而那是一块全中文面板上唯一的英文。
    //
    // 更要紧的是自相矛盾：同一屏上方的危险区对这根模组画的正是「AT 通道」，
    // 正文写着「需要 QMI 的射频开关、eSIM 操作与 USB 恢复不可用」，而下面这个
    // 「读取」按钮却是亮的。旧面板两处都挂了 `activeManageable()`，搬迁时漏了。
    let usable = Memo::new(move |_| match (active.get(), status.load.get()) {
        (Some(imei), Load::Ready(body)) => crate::status::manageable(&body, &imei),
        // 还没选模组、或者状态还没到——按钮本来就该是灰的（下面 is_none 那一条），
        // 这里不额外收紧，保持和危险区同样的防御性默认值。
        _ => true,
    });

    view! {
        <Card>
            <CardHeader>
                <Body1><b>"eSIM profile"</b></Body1>
                <CardHeaderAction slot>
                    <Button
                        disabled=Signal::derive(move || active.get().is_none() || !usable.get())
                        on_click=move |_| {
                            let imei = active.get_untracked();
                            leptos::task::spawn_local(async move {
                                read(state, imei).await;
                            });
                        }
                    >
                        {move || if state.read.get() { "重新读取" } else { "读取" }}
                    </Button>
                </CardHeaderAction>
            </CardHeader>

            // 在任何人点之前就摆在屏幕上。一个只在确认框里才出现的代价，
            // 到得太晚了 —— 它本该改变的那个决定已经做完了。
            <MessageBar intent=MessageBarIntent::Warning layout=MessageBarLayout::Multiline>
                <MessageBarBody>
                    "切换会把模组从它当前的网络上摘下来，直到卡片 REFRESH 完成。\
                     eUICC 上同一时刻只有一个 profile 启用，所以启用一条就是停用另一条；\
                     把最后一条停掉之后没有网络可回。这批硬件没有人能物理接触，插拔不是退路。\
                     发出之后面板不采信 /api/esim/switch 的 ok —— 它等 8 秒再回读 /api/esim，\
                     屏幕上写的是回读到的状态。"
                </MessageBarBody>
            </MessageBar>

            {move || state.receipt.get().map(|r| view! { <ReceiptCard receipt=r /> })}

            {move || {
                if active.get().is_none() {
                    return view! { <Caption1>"先在左边选一根模组。"</Caption1> }.into_any();
                }
                if !usable.get() {
                    // 和危险区那一段说同一件事，用同样的话。
                    return view! {
                        <Caption1>
                            "这一根由 AT 控制口管理，没有 QMI 通道 —— eSIM 的读取与切换都做不了。"
                        </Caption1>
                    }
                    .into_any();
                }
                match state.profiles.get() {
                    Load::Loading if !state.read.get() => {
                        view! { <Caption1>"还没有读取。"</Caption1> }.into_any()
                    }
                    Load::Loading => view! { <Caption1>"正在读 profile…"</Caption1> }.into_any(),
                    // 🔴 读不到 ≠ 卡上没有 profile。
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
                    Load::Ready(result) => {
                        if result.profiles.is_empty() {
                            return view! {
                                <Caption1>"卡上没有 profile —— 读取本身成功了。"</Caption1>
                            }
                            .into_any();
                        }
                        view! { <Profiles result=result active=active state=state /> }.into_any()
                    }
                }
            }}
        </Card>
    }
}

#[component]
fn ReceiptCard(receipt: Receipt) -> impl IntoView {
    let intent = match receipt.verdict {
        Verdict::Match => MessageBarIntent::Success,
        Verdict::Mismatch => MessageBarIntent::Error,
        // ⚠️ Missing / Unknown / Refused 都不是「失败」，是「不知道」或者
        // 「没发生」。用警告色而不是错误色，因为要人做的事不一样。
        Verdict::Missing | Verdict::Unknown | Verdict::Refused => MessageBarIntent::Warning,
        Verdict::Pending => MessageBarIntent::Info,
    };
    let head = format!("切换回执 · {}", hhmmss(receipt.at));
    view! {
        <MessageBar intent=intent layout=MessageBarLayout::Multiline>
            <MessageBarBody>
                <MessageBarTitle>{head}</MessageBarTitle>
                <div>{receipt.verdict_text}</div>
                // 端点声称的和卡说的分两行写。合成一行就等于让端点替卡说话。
                <Caption1>
                    {format!(
                        "端点声称：{}　卡回读：{}{}",
                        if receipt.claim.is_empty() { "还没回" } else { &receipt.claim },
                        if receipt.seen_text.is_empty() { "还没读" } else { &receipt.seen_text },
                        if receipt.step.is_empty() {
                            String::new()
                        } else {
                            format!("　{}", receipt.step)
                        },
                    )}
                </Caption1>
            </MessageBarBody>
        </MessageBar>
    }
}

#[component]
fn Profiles(
    result: ProfilesResult,
    active: RwSignal<Option<String>>,
    state: EsimState,
) -> impl IntoView {
    view! {
        <Table>
            <TableHeader>
                <TableRow>
                    <TableHeaderCell>"名称"</TableHeaderCell>
                    <TableHeaderCell>"ICCID"</TableHeaderCell>
                    <TableHeaderCell>"类别"</TableHeaderCell>
                    <TableHeaderCell>"状态"</TableHeaderCell>
                    <TableHeaderCell>"操作"</TableHeaderCell>
                </TableRow>
            </TableHeader>
            <TableBody>
                {result
                    .profiles
                    .into_iter()
                    .map(|p| {
                        let name = profile_name(&p);
                        let iccid = p.iccid.clone();
                        let enable = !p.enabled;
                        let enabled = p.enabled;
                        let class = class_label(p.class);
                        view! {
                            <TableRow>
                                <TableCell>{name}</TableCell>
                                <TableCell>
                                    <Caption1>{p.iccid.clone()}</Caption1>
                                </TableCell>
                                <TableCell>{class}</TableCell>
                                <TableCell>
                                    <Badge
                                        color=if enabled {
                                            BadgeColor::Success
                                        } else {
                                            BadgeColor::Informative
                                        }
                                        size=BadgeSize::Small
                                    >
                                        {if enabled { "已启用" } else { "未启用" }}
                                    </Badge>
                                </TableCell>
                                <TableCell>
                                    <Button
                                        size=ButtonSize::Small
                                        on_click=move |_| {
                                            let imei = active.get_untracked();
                                            let iccid = iccid.clone();
                                            leptos::task::spawn_local(async move {
                                                switch(state, imei, iccid, enable).await
                                            });
                                        }
                                    >
                                        {if enabled { "停用" } else { "启用" }}
                                    </Button>
                                </TableCell>
                            </TableRow>
                        }
                    })
                    .collect_view()}
            </TableBody>
        </Table>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 🔴 AT-only 的模组在这一栏一件事都做不了，按钮不能是亮的。
    ///
    /// 生产机队里有一根 EC200U-CN（`manageable=false`、`discovery="at"`），
    /// 压根没有 cdc-wdm 接口。eSIM 的每一个操作都走 QMI，服务端会以
    /// `no matching QMI modem` 拒掉——那是一块全中文面板上唯一的英文。
    ///
    /// 更要紧的是自相矛盾：同一屏上方的危险区对这根模组画的正是「AT 通道」，
    /// 正文写着「eSIM 操作不可用」。旧面板两处都挂了 `activeManageable()`。
    #[test]
    fn an_at_only_modem_is_not_offered_esim_actions() {
        use edge_core::CapabilityOrigin;
        use edge_panel_api::{ModemBody, PanelMode, StatusBody};

        let at_only = ModemBody {
            imei: "868019060490134".into(),
            family: "EC200U-CN".into(),
            iccid: None,
            state: "online".into(),
            last_seen: Some(0),
            home: None,
            home_numeric: None,
            imsi: None,
            network: None,
            network_numeric: None,
            discovery: "at".into(),
            manageable: false,
            control_port: Some("/dev/ttyUSB4".into()),
            firmware: None,
            msisdn: None,
            carrier_profile: String::new(),
            capability_origin: CapabilityOrigin::Rule,
        };
        let mut qmi = at_only.clone();
        qmi.imei = "867018069509705".into();
        qmi.manageable = true;
        qmi.discovery = "qmi".into();

        let body = StatusBody {
            mode: PanelMode::Cloud,
            modems: vec![at_only.clone(), qmi.clone()],
            discoveries: Vec::new(),
        };

        assert!(
            !crate::status::manageable(&body, &at_only.imei),
            "EC200U-CN 走 AT，eSIM 够不到它"
        );
        assert!(
            crate::status::manageable(&body, &qmi.imei),
            "QMI 那几根照常可用——修这条不能把所有人一起关掉"
        );
    }

    /// 🔴 换模组必须把这一栏清空——留着的 profile 表配着新模组的标题，就是
    /// 在说「这些卡在这根模组里」，而按钮会拿表里的 ICCID 去发真的写操作。
    #[test]
    fn switching_modems_forgets_the_previous_cards_profiles() {
        let state = EsimState::new();
        state.profiles.set(Load::Ready(ProfilesResult {
            imei: Some("867018069509705".into()),
            profiles: vec![profile("8986001", true)],
        }));
        state.read.set(true);
        state.receipt.set(Some(receipt("8986001", true, false)));

        state.forget_modem();

        assert!(
            matches!(state.profiles.get_untracked(), Load::Loading),
            "上一张卡的 profile 表必须清掉"
        );
        assert_eq!(
            state.receipt.get_untracked(),
            None,
            "切换回执是关于一张卡的"
        );
        assert!(
            !state.read.get_untracked(),
            "read 留着的话按钮会写「重新读取」，等于替新模组宣称已经读过了"
        );
    }

    fn profile(iccid: &str, enabled: bool) -> ProfileBody {
        ProfileBody {
            iccid: iccid.into(),
            label: String::new(),
            enabled,
            provider: Some("CMCC".into()),
            name: None,
            nickname: None,
            class: Some(2),
            isdp_aid: None,
        }
    }

    fn receipt(iccid: &str, enable: bool, endpoint_failed: bool) -> Receipt {
        Receipt {
            iccid: iccid.into(),
            label: "测试卡".into(),
            enable,
            at: 0.0,
            step: "等卡片…".into(),
            claim: if endpoint_failed {
                "失败：boom".into()
            } else {
                "ok".into()
            },
            endpoint_failed,
            seen: None,
            seen_text: String::new(),
            verdict: Verdict::Pending,
            verdict_text: String::new(),
        }
    }

    /// 🔴 端点回 ok、卡却没换 —— 这是一次假成功，必须被说出来。
    ///
    /// 原版的注释记着这个端点确实这么干过：在一次没发生的切换上回过 ok。
    #[test]
    fn an_endpoint_that_claimed_ok_on_a_switch_that_did_not_happen_is_called_out() {
        let mut r = receipt("8986001", true, false);
        judge(&mut r, &[profile("8986001", false)], "12:00:00");
        assert_eq!(r.verdict, Verdict::Mismatch);
        assert!(
            r.verdict_text.contains("假成功"),
            "端点回 ok 而卡没换，必须点破：{}",
            r.verdict_text
        );
        assert_eq!(r.seen, Some(false), "卡说的要记下来");
    }

    /// 反过来也一样：端点报了失败，卡却确实换了 —— 以回读为准。
    #[test]
    fn a_switch_that_happened_despite_an_error_is_reported_as_done() {
        let mut r = receipt("8986001", true, true);
        judge(&mut r, &[profile("8986001", true)], "12:00:00");
        assert_eq!(r.verdict, Verdict::Match);
        assert!(
            r.verdict_text.contains("端点当时报的是失败"),
            "两边不一致这件事要说出来：{}",
            r.verdict_text
        );
    }

    /// 端点报失败、卡也没换：两边一致，卡没有被改动。
    #[test]
    fn an_error_that_matches_the_card_says_nothing_was_changed() {
        let mut r = receipt("8986001", true, true);
        judge(&mut r, &[profile("8986001", false)], "12:00:00");
        assert_eq!(r.verdict, Verdict::Mismatch);
        assert!(
            r.verdict_text.contains("卡没有被改动"),
            "{}",
            r.verdict_text
        );
        assert!(!r.verdict_text.contains("假成功"), "这一次端点没有撒谎");
    }

    /// 回读到的列表里没有这条 ICCID —— 面板不替卡猜。
    #[test]
    fn a_profile_that_vanished_is_not_guessed_at() {
        let mut r = receipt("8986001", true, false);
        judge(&mut r, &[profile("8986002", true)], "12:00:00");
        assert_eq!(r.verdict, Verdict::Missing);
        assert_eq!(r.seen, None, "没读到就是没读到，不能填一个值进去");
        assert!(r.verdict_text.contains("不替卡猜"), "{}", r.verdict_text);
    }

    /// 名字落到 ICCID 也比空着强。
    #[test]
    fn a_profile_always_has_something_to_call_it_by() {
        let mut p = profile("8986001", true);
        assert_eq!(profile_name(&p), "CMCC", "有 provider 用 provider");
        p.name = Some("China Mobile".into());
        assert_eq!(profile_name(&p), "China Mobile", "name 比 provider 优先");
        p.nickname = Some("主卡".into());
        assert_eq!(profile_name(&p), "主卡", "nickname 最优先");

        let bare = ProfileBody {
            iccid: "8986001".into(),
            label: String::new(),
            enabled: false,
            provider: None,
            name: None,
            nickname: None,
            class: None,
            isdp_aid: None,
        };
        assert_eq!(profile_name(&bare), "8986001", "什么都没有就用 ICCID");
    }

    /// 启用另一条时，被顶掉的那一条要在对话框里指名。
    #[test]
    fn enabling_one_names_the_profile_it_will_switch_off() {
        let live = profile("8986001", true);
        let other = profile("8986002", false);
        let text = ask(
            &other,
            true,
            &[live.clone(), other.clone()],
            Some("860000000000001"),
        );
        assert!(text.contains("会被一并停用"), "要说清代价：{text}");
        assert!(
            text.contains("8986001") || text.contains("CMCC"),
            "要指名是哪一条"
        );
        assert!(
            text.contains("不采信") || text.contains("不作数"),
            "要说清 ok 不作数"
        );
    }

    /// 停掉最后一条启用中的 profile —— 那一根没有网络可以回去。
    #[test]
    fn switching_off_the_last_one_says_there_is_nothing_to_come_back_to() {
        let live = profile("8986001", true);
        let text = ask(&live, false, &[live.clone()], None);
        assert!(
            text.contains("没有网络可以回去"),
            "停掉最后一条必须说清楚：{text}"
        );
        assert!(text.contains("未选模组"), "没选模组也要说出来");
    }

    /// 停用一条**不是**当前启用的 profile，不该吓唬人。
    #[test]
    fn switching_off_an_idle_profile_does_not_cry_wolf() {
        let live = profile("8986001", true);
        let idle = profile("8986002", false);
        let text = ask(&idle, false, &[live, idle.clone()], None);
        assert!(
            !text.contains("没有网络可以回去"),
            "它本来就没启用，停用它不会让这一根断网：{text}"
        );
    }
}
