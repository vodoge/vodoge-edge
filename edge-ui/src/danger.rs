//! 危险区：射频开关、USB 复位、取消纳管。
//!
//! 三个按钮，各自的代价原版都写在确认框里，这里照搬：
//!
//! - **关射频**：不是 `AT+CFUN` —— `lib.rs`写着那条的复位形式楔死过模组，不
//!   值得放在按钮上。走的是 QMI 工作模式（LowPower/Online），回来的路是同
//!   一个按钮，但**只有软件这一条**：这批硬件没有人能物理接触，而 2026-08-25
//!   有一次 QMI 模式切换被 error 60 拒在半路，把模组停在 +CFUN: 7 出不来。
//! - **USB 复位**：QMI 栈卡死时唯一能恢复的手段。
//! - **取消纳管**：不再轮询，从列表消失；历史保留，之后可在 USB 候选里重新
//!   纳管——这不是删除。
//!
//! ## 🔴 一处没有照搬的地方：射频状态不能是一个全局变量
//!
//! 原版的 `radioOnline` 是**一个**布尔值，初始化一次，只在操作员按下按钮时
//! 改变，从不随选中的模组切换而重置，服务端也没有对应字段。后果是：把 A 的
//! 射频关掉，切到 B，按钮上写的还是「开射频」——这是关于 B 的谎言，B 的射频
//! 状态从来没被问过。这正是这次迁移要抓的那一类缺陷（状态在说谎），所以这里
//! 换成**按 IMEI 分开记**：每一根自己的「假定射频状态」，默认在线，只有操作
//! 员真的对**这一根**按过按钮才会变。这仍然是本地记忆而不是服务端真相（服务
//! 端确实没有上报这个字段），但至少不会把一根模组的操作结果安在另一根头上。
//!
//! ## 🔴 另一处不一致：USB 复位的确认框点了取消，原版不留痕
//!
//! 关射频/开射频和取消纳管，点了取消都会留下一条「已取消」的记录——原版自己
//! 的注释说了为什么：「没有痕迹的话，操作员没法区分自己驳回的确认框和已经发
//! 出去的命令」。USB 复位的确认框却是 `if (!confirm(...)) return;`，悄悄
//! 什么都不做。这条理由对三个按钮同样成立，看起来是遗漏不是故意的，这里补上。

use edge_panel_api::{RegistrationResult, UsbResetResult};
use leptos::prelude::*;
use std::collections::HashMap;
use thaw::*;

use crate::api::{self, Load};
use crate::status::{manageable, StatusState};

#[derive(Clone, Debug, PartialEq)]
pub enum DangerNote {
    /// 确认框里点了取消。**没有发出去。**
    Refused(String),
    Done(String),
    Failed(String),
}

#[derive(Clone, Copy)]
pub struct DangerState {
    /// 每根模组自己假定的射频状态。⚠️ 不在这里的当作在线——见模块文档，
    /// 这是本地记忆，不是服务端真相。
    radio: RwSignal<HashMap<String, bool>>,
    pub note: RwSignal<Option<DangerNote>>,
    pub busy: RwSignal<bool>,
}

impl DangerState {
    pub fn new() -> Self {
        Self {
            radio: RwSignal::new(HashMap::new()),
            note: RwSignal::new(None),
            busy: RwSignal::new(false),
        }
    }

    /// 换了一根模组，上一次操作的结果作废。
    ///
    /// 🔴 `note` 是全局一条而且文案里不含 IMEI，留着就会被安在新模组头上：
    /// 一条绿色的「射频已关闭。」配着一个写着「关射频」的按钮，两者互相矛盾，
    /// 而这批硬件没人能物理接触——把一次脱网操作记到错的模组上，是要人去救
    /// 错模组的。
    ///
    /// ⚠️ `radio` **不清**。它本来就是按 IMEI 分开记的（这一半一直是对的），
    /// 清掉反而会让每根模组的射频状态在切换后忘记。
    pub fn forget_modem(&self) {
        self.note.set(None);
    }
}

/// 这一根现在假定是不是在线。不在表里就是在线——原版全局默认值也是如此。
fn radio_online(radio: &HashMap<String, bool>, imei: &str) -> bool {
    radio.get(imei).copied().unwrap_or(true)
}

fn confirmed(message: &str) -> bool {
    web_sys::window()
        .and_then(|w| w.confirm_with_message(message).ok())
        .unwrap_or(false)
}

fn radio_ask(imei: &str, go_online: bool, manageable: bool) -> String {
    if !manageable {
        // 🔴 AT-only 的那条路，代价和退路都和 QMI 那条不一样，不能共用一段文案。
        //
        // ⚠️ 这条路在一处上**比 QMI 更安全**：`AT+CFUN=0` 之后模组仍然在总线
        // 上、AT 口仍然应答，回程就在同一个口上。而 QMI 的 LowPower 在
        // 2026-08-25 被 error 60 拒在半路，把模组停在 +CFUN: 7 出不来。
        return if go_online {
            format!(
                "恢复射频（AT 路径）\n\n\
                 目标：{imei}\n\
                 动作：/api/radio → 这一根没有 QMI 口，发 AT+CFUN=1\n\n\
                 模组会重新搜网并注册，这要几十秒。\n\n\
                 确定要恢复吗？"
            )
        } else {
            format!(
                "关闭射频（AT 路径）\n\n\
                 目标：{imei}\n\
                 动作：/api/radio → 这一根没有 QMI 口，发 AT+CFUN=0\n\
                 （**不带复位**。带复位的 AT+CFUN=1,1 会让模组重启并重新枚举 USB，\n\
                 那是最后手段，不是按钮该发的东西。）\n\n\
                 这一根会立刻脱网：收不到短信、没有数据。\n\n\
                 回来的路是同一个按钮（AT+CFUN=1），而且**关掉之后 AT 口还在、\n\
                 模组也不离开总线**——恢复通道不会跟着射频一起消失。这一点上它\n\
                 比 QMI 那条路稳：LowPower 曾经把一根模组停在 +CFUN: 7 出不来。\n\n\
                 确定要关吗？"
            )
        };
    }
    if go_online {
        format!(
            "恢复射频\n\n\
             目标：{imei}\n\
             动作：/api/radio → QMI 工作模式设回 Online\n\n\
             模组会重新搜网并注册，这要几十秒。期间机队里它看起来仍然是离线的，\n\
             面板会在 5 秒后自动刷新一次，没回来就再刷新。\n\n\
             确定要恢复吗？"
        )
    } else {
        format!(
            "关闭射频\n\n\
             目标：{imei}\n\
             动作：/api/radio → QMI 工作模式设成 LowPower\n\
             （不是 AT+CFUN —— lib.rs 写着那条的复位形式楔死过模组，不值得放在按钮上。）\n\n\
             这一根会立刻脱网：收不到短信、没有数据、在它上面的通话会断，\n\
             面板上它会暂时从机队里消失，心跳停在这一刻。\n\n\
             回来的路是同一个按钮（QMI Online）—— LowPower 是这三根每天来回走\n\
             很多次的模式。但退路只有软件这一条：这批硬件没有人能物理接触，\n\
             而 2026-08-25 有一次 QMI 模式切换被 error 60 拒在半路，把模组停在\n\
             +CFUN: 7 出不来（那次走的是 Offline，不是这里的 LowPower）。\n\n\
             确定要关吗？"
        )
    }
}

async fn toggle_radio(state: DangerState, status: StatusState, imei: String) {
    let go_online = !radio_online(&state.radio.get_untracked(), &imei);
    // 走哪条路决定确认框说什么。⚠️ 读的是**此刻**的状态：模组可能刚掉了 QMI。
    let manageable_now = match status.load.get_untracked() {
        Load::Ready(body) => manageable(&body, &imei),
        _ => true,
    };
    if !confirmed(&radio_ask(&imei, go_online, manageable_now)) {
        state.note.set(Some(DangerNote::Refused(format!(
            "已取消{}射频 {imei} —— 没有发出，射频没有被碰过。",
            if go_online { "恢复" } else { "关闭" }
        ))));
        return;
    }
    state.busy.set(true);
    let body = edge_panel_api::RadioBody {
        online: go_online,
        imei: Some(imei.clone()),
    };
    let got: Load<serde_json::Value> = api::post("/api/radio", &body, "射频").await;
    state.busy.set(false);
    match got {
        Load::Ready(_) => {
            state.radio.update(|m| {
                m.insert(imei, go_online);
            });
            state.note.set(Some(DangerNote::Done(format!(
                "射频已{}。",
                if go_online { "恢复" } else { "关闭" }
            ))));
            // ⚠️ 5 秒后刷新一次：模组重新搜网需要几十秒，读得太早只会报告
            // 「仍然离线」，那不是失败，是还没到时候。
            crate::sleep(5_000).await;
            crate::status::poll(status).await;
        }
        Load::Failed(why) => state.note.set(Some(DangerNote::Failed(why))),
        Load::Loading => {}
    }
}

async fn usb_reset(state: DangerState, status: StatusState, imei: String) {
    if !confirmed(&format!(
        "重新枚举 {imei} 的 USB 设备？\nQMI 栈卡死时这是唯一能恢复的手段。"
    )) {
        // 🔴 原版这里悄悄什么都不做——见模块文档，这是补上的一致性。
        state.note.set(Some(DangerNote::Refused(format!(
            "已取消 USB 复位 {imei} —— 没有发出，设备没有被碰过。"
        ))));
        return;
    }
    state.busy.set(true);
    let body = edge_panel_api::ResetBody { imei: Some(imei) };
    let got: Load<UsbResetResult> = api::post("/api/usb-reset", &body, "USB 复位").await;
    state.busy.set(false);
    match got {
        Load::Ready(result) => {
            state.note.set(Some(DangerNote::Done(format!(
                "USB {} 已重新枚举（{}）。",
                result.device, result.node
            ))));
            // ⚠️ 12 秒——原版量出来的重新枚举耗时，比射频恢复更久。
            crate::sleep(12_000).await;
            crate::status::poll(status).await;
        }
        Load::Failed(why) => state.note.set(Some(DangerNote::Failed(why))),
        Load::Loading => {}
    }
}

async fn unregister(
    state: DangerState,
    status: StatusState,
    active: RwSignal<Option<String>>,
    imei: String,
) {
    if !confirmed(&format!(
        "取消纳管 {imei}？\n它将不再被轮询，并从上方列表消失。\n\
         它承载过的短信和命令都会保留，之后可在 USB 候选里重新纳管。"
    )) {
        state.note.set(Some(DangerNote::Refused(format!(
            "已取消操作；{imei} 仍在管理中。"
        ))));
        return;
    }
    state.busy.set(true);
    let body = edge_panel_api::RegistrationBody { imei: imei.clone(), note: None };
    let got: Load<RegistrationResult> =
        api::post("/api/modems/unregister", &body, "取消纳管").await;
    state.busy.set(false);
    match got {
        Load::Ready(result) => {
            state.note.set(Some(DangerNote::Done(if result.changed {
                format!("已取消纳管 {imei}。")
            } else {
                format!("{imei} 本就不在管理中。")
            })));
            active.set(None);
            crate::status::poll(status).await;
        }
        Load::Failed(why) => state.note.set(Some(DangerNote::Failed(format!(
            "取消纳管 {imei} 失败：{why}"
        )))),
        Load::Loading => {}
    }
}

/// 危险区里哪几个按钮该出现。
///
/// 🔴 **USB 复位不看 `manageable`。**
///
/// 它写的是设备的 `authorized` 属性，全程不碰 QMI —— 服务端 `recover_usb` 的
/// 路径是「IMEI → USB 位置 → 写 sysfs」，`/api/usb-reset` 也没有任何 QMI 前置
/// 条件。把它和「关射频」（那个确实走 QMI 工作模式）一起藏在 `manageable`
/// 后面，是搬迁时按"危险操作"归类归错了。
///
/// 代价在 2026-09-04 兑现了：电信那根 EC200U（AT-only）发完一条短信之后
/// **AT 通道挂死、USB 仍然在线**，而这正是 USB 复位唯一能救的形态 ——
/// 面板上却连按钮都没有，旁边还写着一句「USB 恢复不可用」，那句话是错的。
///
/// ⚠️ AT-only 的模组反而**更需要**它：它们没有 QMI 那条备用通道，AT 一死就
/// 什么都不剩了。
pub struct DangerButtons {
    /// 关/开射频。**也永远可用。**
    ///
    /// 以前它跟着 `manageable` 走，因为面板只知道 QMI 那条路。现在服务端在
    /// 「这一根根本没有 QMI 口」时回落到 `AT+CFUN=0/1`，所以 AT-only 的模组
    /// 也有射频开关了。
    pub radio: bool,
    /// USB 复位。**永远可用。**
    pub usb_reset: bool,
}

pub fn danger_buttons(_manageable: bool) -> DangerButtons {
    DangerButtons {
        radio: true,
        usb_reset: true,
    }
}

#[component]
pub fn DangerZone(status: StatusState, state: DangerState) -> impl IntoView {
    view! {
        {move || {
            let Some(imei) = status.active.get() else {
                return ().into_any();
            };
            let is_manageable = match status.load.get() {
                Load::Ready(body) => manageable(&body, &imei),
                _ => true,
            };
            let online = radio_online(&state.radio.get(), &imei);

            let heading = format!(
                "{} · {imei}",
                if is_manageable { "危险区" } else { "AT 通道" }
            );
            view! {
                    // ⚠️ 这一行带着 IMEI，而且「危险区」和「AT 通道」是两种不同的
                    // 处境——AT-only 的模组够不到 QMI，射频开关和 USB 复位都不可用。
                    <Caption1Strong>{heading}</Caption1Strong>

                    {move || {
                        state
                            .note
                            .get()
                            .map(|note| {
                                let (intent, text) = match note {
                                    DangerNote::Refused(t) => (MessageBarIntent::Warning, t),
                                    DangerNote::Done(t) => (MessageBarIntent::Success, t),
                                    DangerNote::Failed(t) => (MessageBarIntent::Error, t),
                                };
                                view! {
                                    <MessageBar intent=intent layout=MessageBarLayout::Multiline>
                                        <MessageBarBody>{text}</MessageBarBody>
                                    </MessageBar>
                                }
                            })
                    }}

                    {
                        let buttons = danger_buttons(is_manageable);
                        let imei_radio = imei.clone();
                        let imei_usb = imei.clone();
                        view! {
                            <Flex gap=FlexGap::Small style="flex-wrap: wrap;">
                                {buttons
                                    .radio
                                    .then(|| {
                                        view! {
                                            <Button
                                                disabled=state.busy
                                                on_click=move |_| {
                                                    let imei = imei_radio.clone();
                                                    leptos::task::spawn_local(async move {
                                                        toggle_radio(state, status, imei).await
                                                    });
                                                }
                                            >
                                                {if online { "关射频" } else { "开射频" }}
                                            </Button>
                                        }
                                    })}
                                {buttons
                                    .usb_reset
                                    .then(|| {
                                        view! {
                                            <Button
                                                disabled=state.busy
                                                on_click=move |_| {
                                                    let imei = imei_usb.clone();
                                                    leptos::task::spawn_local(async move {
                                                        usb_reset(state, status, imei).await
                                                    });
                                                }
                                            >
                                                "USB 复位"
                                            </Button>
                                        }
                                    })}
                            </Flex>
                            <Caption1>
                                {if is_manageable {
                                    "两个操作都会让这根模组暂时从机队消失。"
                                } else {
                                    "该设备经 AT 控制口管理。射频开关走 AT+CFUN（不带复位），\
                                     USB 复位写的是 USB 授权位 —— 两者都不经过 QMI，都可用。\
                                     只有 eSIM 操作需要 QMI，不可用。"
                                }}
                            </Caption1>
                        }
                    }

                    <Button
                        appearance=ButtonAppearance::Primary
                        disabled=state.busy
                        on_click=move |_| {
                            let imei = imei.clone();
                            leptos::task::spawn_local(async move {
                                unregister(state, status, status.active, imei).await
                            });
                        }
                    >
                        "取消纳管"
                    </Button>
                    <Caption1>
                        "不再轮询它，并从上方列表移除。历史保留，之后可在 USB 候选里重新纳管。"
                    </Caption1>

            }
                .into_any()
        }}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 🔴 「射频已关闭。」不含 IMEI，留在另一根模组下面就是在说那一根被关了。
    #[test]
    fn switching_modems_forgets_the_previous_result_but_not_the_radio_map() {
        let state = DangerState::new();
        state
            .note
            .set(Some(DangerNote::Done("射频已关闭。".into())));
        state.radio.update(|m| {
            m.insert("867018069509705".to_string(), false);
        });

        state.forget_modem();

        assert_eq!(state.note.get_untracked(), None, "上一根的操作结果必须清掉");
        assert!(
            !radio_online(&state.radio.get_untracked(), "867018069509705"),
            "⚠️ 射频状态是按 IMEI 记的，**不能**跟着清——清了每根模组的射频状态\
             都会在切换后被忘掉"
        );
    }

    /// 🔴 每根模组各自记，不能把 A 的操作结果安在 B 头上。
    #[test]
    fn radio_state_does_not_leak_across_modems() {
        let mut radio = HashMap::new();
        assert!(radio_online(&radio, "a"), "没记录过的默认在线");
        assert!(radio_online(&radio, "b"), "b 从没被操作过，也该是在线");

        radio.insert("a".to_string(), false);
        assert!(!radio_online(&radio, "a"), "a 被关了");
        assert!(
            radio_online(&radio, "b"),
            "关 a 的射频不该把 b 也读成关的——这正是原版那个全局变量的 bug"
        );
    }

    /// 🔴 AT-only 的模组也必须能按 USB 复位。
    ///
    /// 2026-09-04：电信那根 EC200U 发完一条短信之后 AT 通道挂死、USB 仍然在
    /// 线——那正是 USB 复位唯一能救的形态。而面板上连按钮都没有，旁边还写着
    /// 一句「USB 恢复不可用」。那句话是错的：服务端 `/api/usb-reset` 写的是
    /// 设备的 `authorized` 属性，没有任何 QMI 前置条件。
    ///
    /// ⚠️ AT-only 反而**更需要**它：没有 QMI 那条备用通道，AT 一死就什么都
    /// 不剩了。
    #[test]
    fn an_at_only_modem_can_still_be_usb_reset() {
        let at_only = danger_buttons(false);
        assert!(
            at_only.usb_reset,
            "AT-only 拿不到 USB 复位 —— 而它没有 QMI 备用通道，AT 一死就没有任何恢复入口"
        );
        assert!(
            at_only.radio,
            "AT-only 拿不到射频开关 —— 服务端已经会在没有 QMI 口时回落到 AT+CFUN=0/1"
        );

        let full = danger_buttons(true);
        assert!(full.usb_reset && full.radio);
    }

    /// 找不到模组时按「可管理」处理，这是防御性默认值不是业务规则。
    #[test]
    fn an_unknown_modem_defaults_to_manageable() {
        let body = edge_panel_api::StatusBody {
            mode: edge_panel_api::PanelMode::Local,
            modems: Vec::new(),
            discoveries: Vec::new(),
            retirements: Vec::new(),
            retro_enforcing: false,
            adoptions: Vec::new(),
        };
        assert!(manageable(&body, "867018069509705"));
    }

    #[test]
    fn the_dialog_names_both_the_cost_and_the_only_way_back() {
        let off = radio_ask("867018069509705", false, true);
        assert!(off.contains("867018069509705"));
        assert!(off.contains("立刻脱网"), "要说清代价：{off}");
        assert!(
            off.contains("没有人能物理接触"),
            "要说清退路只有软件：{off}"
        );

        let on = radio_ask("867018069509705", true, true);
        assert!(on.contains("几十秒"), "要说清要等多久：{on}");
        assert!(!on.contains("立刻脱网"), "恢复射频不该用关闭那份文案：{on}");
    }

    /// 🔴 AT 那条路的确认框必须说清它是 AT，而且**不带复位**。
    ///
    /// 两条路的退路不一样：QMI 的 LowPower 在 2026-08-25 被 error 60 拒在半路，
    /// 把模组停在 `+CFUN: 7` 出不来；而 `AT+CFUN=0` 之后模组还在总线上、AT 口
    /// 还应答，回程就在同一个口上。共用一段文案会把这个差别抹掉，而那正是
    /// 操作员按下去之前该知道的。
    #[test]
    fn the_at_path_dialog_names_the_command_and_rules_out_the_resetting_form() {
        let off = radio_ask("868019060490134", false, false);
        assert!(off.contains("AT+CFUN=0"), "没说清发的是哪条命令：{off}");
        assert!(off.contains("不带复位"), "没排除带复位那种形式：{off}");
        assert!(off.contains("AT 口还在"), "没说清退路还在：{off}");

        let on = radio_ask("868019060490134", true, false);
        assert!(on.contains("AT+CFUN=1"));

        // 可管理的模组仍然走 QMI，文案不能被换成 AT 的。
        let qmi = radio_ask("867018069514820", false, true);
        assert!(qmi.contains("QMI"), "可管理的模组该走 QMI：{qmi}");
        assert!(!qmi.contains("AT+CFUN=0"));
    }
}
