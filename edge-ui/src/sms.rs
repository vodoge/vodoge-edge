//! 短信：发出去的和收进来的。
//!
//! ## 两处拒绝，都必须说清楚「模组没有被碰过」
//!
//! 🔴 **没选模组不是小事。** 不带 IMEI 发出去，代理会取它 modem map 里的第一
//! 条 —— 而这个机队里有一根，每一次 MO 短信提交都会让它掉出 USB 总线。所以
//! 「先选一根」不是提示，是拦截，而且要说明白为什么。
//!
//! 🔴 **封禁的模组要在发之前就说话。** 表在 [`edge_core::sms_block`]，判词在
//! 体检页也出现一次。这里再拦一次。
//!
//! ⚠️ 两处检查都做**两遍**：按钮置灰一遍，[`send`] 里面再一遍。原版的注释把
//! 理由写得很好 —— 在文本框里按回车会提交表单，而一个只活在属性里的守卫，离
//! 「不存在」只差一次按键和一次过期的渲染。
//!
//! ## 收件箱
//!
//! ⚠️ `modem_imei` 为空的消息在**两个视图里都显示**。因为一个字段缺失就把行
//! 丢掉，正是一个收件箱悄悄丢信的方式。
//!
//! ## 字数表
//!
//! 编码规则来自 [`edge_core::draft`]，和 daemon 的编码器是同一份。这个编码器
//! **不分片**：超了就是发不出去。所以这件事要在按钮**之前**看得见。

use edge_panel_api::{MessageBody, MessagesBody, SendReceipt};
use leptos::prelude::*;
use thaw::*;

use crate::api::{self, Load};
use crate::status::StatusState;

/// 收件箱轮询间隔。跟着状态页走，10 秒。
pub const INBOX_EVERY_MS: u64 = 10_000;

#[derive(Clone, Copy)]
pub struct SmsState {
    pub inbox: RwSignal<Load<MessagesBody>>,
    pub to: RwSignal<String>,
    pub body: RwSignal<String>,
    /// 上一次发送的结果。`None` 表示这一次会话还没发过。
    pub note: RwSignal<Option<SendNote>>,
    /// 只看当前选中的那一根。
    pub mine: RwSignal<bool>,
    /// 操作员明确认下了这一根的发送代价。
    ///
    /// 🔴 **这是「我知道这一根会掉线」，不是一个全局开关。** 换模组必须清掉
    /// （见 [`SmsState::forget_modem`]）—— 在 A 上认下的代价漂到 B 头上，
    /// 就成了「替另一根做了决定」。
    pub commission: RwSignal<bool>,
    inflight: RwSignal<bool>,
}

/// 一次发送的结局。
///
/// 🔴 `Refused` 和 `Failed` 是**两件事**，分开是这一栏最要紧的区别：
/// 前者是面板自己拦下来的，**模组没有被碰过**；后者是请求真的发出去了、
/// 代理拒绝或失败了。把它们画成同一个红条，操作员会以为模组已经被戳过一次。
#[derive(Clone, Debug, PartialEq)]
pub enum SendNote {
    Sending,
    /// 面板拦下的。模组没有被碰过。
    Refused(String),
    /// 代理那边失败的。
    Failed(String),
    Sent,
    /// 发在一根**已知会掉线**的模组上。带着封禁表的 `also`：短信多半真的发出
    /// 去了，接下来那一根会离开总线几十秒 —— 两件事都要说，不然操作员会重发。
    SentWithCost(String),
}

impl SmsState {
    pub fn new() -> Self {
        Self {
            inbox: RwSignal::new(Load::Loading),
            to: RwSignal::new(String::new()),
            body: RwSignal::new(String::new()),
            commission: RwSignal::new(false),
            note: RwSignal::new(None),
            mine: RwSignal::new(false),
            inflight: RwSignal::new(false),
        }
    }

    /// 换了一根模组，上一次发送的结局作废。
    ///
    /// 🔴 一条「已提交给代理」留在另一根模组旁边，读起来就是那一根发出去了；
    /// 而一条点名上一个 IMEI 的拒绝，读起来像是对**这一根**的拒绝。原版
    /// `select()` 清 `sendStatus` 就是为了这个。
    ///
    /// ⚠️ 号码和内容**不清**。那是操作员正在打的字，换根模组重发是常事，
    /// 原版也没有清它们。
    pub fn forget_modem(&self) {
        self.note.set(None);
        // 🔴 代价的认可**不跨模组**。勾的是「我知道**这一根**发完会掉线」，
        //    留着它切到下一根，等于替另一根做了这个决定。
        //
        // ⚠️ 正在打的号码和内容**故意留着**（切模组去查点东西再切回来是常事），
        //    但这一个不留 —— 它不是草稿，是一次授权。
        self.commission.set(false);
    }
}

pub async fn poll(state: SmsState) {
    if state.inflight.get_untracked() {
        return;
    }
    state.inflight.set(true);
    let got: Load<MessagesBody> = api::get("/api/messages", "本地短信").await;
    // ⚠️ 只在真的有结果时覆盖，别把一次失败写成 Loading。
    if !matches!(got, Load::Loading) {
        state.inbox.set(got);
    }
    state.inflight.set(false);
}

/// 面板自己的拦截。返回 `Some(理由)` 表示**不要发**。
///
/// 抽成一个函数是为了能被测试直接调 —— 它是这一栏唯一会阻止硬件被触碰的东西。
fn refusal(active: Option<&str>, commission: bool) -> Option<Refusal> {
    let Some(imei) = active else {
        // 🔴 **这一条 `commission` 也越不过去。**
        //
        // 服务端的 `blocked_send` 里 `commission` 会短路掉全部检查，包括
        // 「没带 IMEI」那一条。面板这里比服务端更严，是故意的：不带 IMEI 时
        // 代理取的是它 modem map 里的第一条，而那一根**可能正是封禁的那根**。
        // 「我知道这一根的代价」和「随便挑一根替我承担代价」是两回事。
        return Some(Refusal {
            // ⚠️ 标题不能是「这一根发不了」—— 一根都没选的时候，没有「这一根」。
            title: "先选一根模组",
            why: "不选的话代理会取它 modem map 里的第一条，\
                  而机队里有一根发 MO 短信就会掉出 USB 总线。"
                .into(),
        });
    };
    if commission {
        // 操作员已经在勾选框旁边读过代价，并且明确选了承担它。
        return None;
    }
    edge_core::sms_block(imei).map(|block| Refusal {
        title: "这一根发不了",
        why: format!("{imei} 被面板禁止发送短信。{}", block.why),
    })
}

/// 勾选框旁边那句话。
///
/// 🔴 **必须带上封禁表的 `also`。** 那一句是「短信多半真的发出去了」——而它
/// 在此之前**一个地方都没显示过**，`refusal` 只用了 `why`。真要发的时候，
/// 那才是操作员最需要知道的一句：被告知「失败」的人会重发，对方收两次。
fn commission_ask(imei: &str) -> Option<String> {
    let block = edge_core::sms_block(imei)?;
    Some(format!(
        "仍然发送 —— 我知道代价。{} {}",
        block.why, block.also
    ))
}

/// 一次拒绝：标题和理由。分开是因为这两种拒绝的**标题不一样** —— 一个是「还
/// 没选」，另一个是「选了但这根不行」。
#[derive(Clone, Debug, PartialEq)]
struct Refusal {
    title: &'static str,
    why: String,
}

async fn send(state: SmsState, active: Option<String>) {
    let commission = state.commission.get_untracked();
    // ⚠️ 第二遍检查。按钮置灰是第一遍，而在文本框里按回车会绕过它。
    if let Some(refused) = refusal(active.as_deref(), commission) {
        state.note.set(Some(SendNote::Refused(refused.why)));
        return;
    }
    let to = state.to.get_untracked();
    let body = state.body.get_untracked();
    if to.trim().is_empty() || body.trim().is_empty() {
        state
            .note
            .set(Some(SendNote::Refused("号码和内容都要填。".into())));
        return;
    }

    state.note.set(Some(SendNote::Sending));
    // ⚠️ `imei` 必须带上。这个字段就是上面那段拦截存在的理由。
    // ⚠️ `commission` 是**唯一**能越过短信封禁表的路径（见 edge-panel 的
    // `blocked_send`）。只有操作员在勾选框旁边读过代价并勾上，才会是 true。
    let blocked_note = active
        .as_deref()
        .and_then(edge_core::sms_block)
        .filter(|_| commission)
        .map(|block| block.also.to_string());
    let payload = edge_panel_api::SendBody {
        to,
        body,
        imei: active,
        commission,
    };
    let got: Load<SendReceipt> = api::post("/api/send", &payload, "发送").await;
    match got {
        Load::Ready(receipt) if receipt.status == "sent" => {
            // 🔴 在封禁的那一根上发成功之后，**不能只说「已提交」**。
            //    那一根接下来会离开总线几十秒 —— 那是已知代价，不是故障；
            //    而且短信多半真的发出去了，操作员这时候最不该做的就是重发。
            state.note.set(Some(match blocked_note {
                Some(also) => SendNote::SentWithCost(also),
                None => SendNote::Sent,
            }));
            state.to.set(String::new());
            state.body.set(String::new());
            leptos::task::spawn_local(async move { poll(state).await });
        }
        Load::Ready(receipt) => state.note.set(Some(SendNote::Failed(format!(
            "代理回了一个没见过的回执：{}",
            receipt.status
        )))),
        Load::Failed(why) => state.note.set(Some(SendNote::Failed(why))),
        Load::Loading => {}
    }
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

fn direction_label(direction: &str) -> &'static str {
    match direction {
        "in" | "inbound" | "mt" => "收",
        "out" | "outbound" | "mo" => "发",
        _ => "?",
    }
}

/// 收件箱按当前选中模组收窄。
///
/// ⚠️ `modem_imei` 为空的行**保留**：一个字段缺失就丢行，是收件箱悄悄丢信的
/// 方式。原版这里是对的，照搬。
fn narrowed(messages: &[MessageBody], mine: bool, active: Option<&str>) -> Vec<MessageBody> {
    match (mine, active) {
        (true, Some(imei)) => messages
            .iter()
            .filter(|m| m.modem_imei.is_none() || m.modem_imei.as_deref() == Some(imei))
            .cloned()
            .collect(),
        _ => messages.to_vec(),
    }
}

#[component]
pub fn SmsPage(state: SmsState, status: StatusState) -> impl IntoView {
    let active = status.active;

    let blocked = Memo::new(move |_| refusal(active.get().as_deref(), state.commission.get()));
    // 这一根有没有「认下代价就能发」这条路。没选模组时没有。
    let ask = Memo::new(move |_| active.get().as_deref().and_then(commission_ask));
    let meter = Memo::new(move |_| {
        let body = state.body.get();
        if body.is_empty() {
            format!(
                "编码由内容决定：只用 A-Z a-z 0-9 空格 . , ! ? : + - 走 GSM-7（{} 字），\
                 其余一律 UCS-2（{} 字）。本机编码器不分片，超了直接拒绝。",
                edge_core::GSM7_MAX_SEPTETS,
                edge_core::UCS2_MAX_CHARS
            )
        } else {
            let d = edge_core::draft(&body);
            format!(
                "{} · {} / {}{}",
                d.encoding.label(),
                d.units,
                d.limit,
                if d.over {
                    " —— 超了，这条会被编码器拒掉（不会分片发出去）"
                } else {
                    ""
                }
            )
        }
    });

    view! {
                <Caption1Strong>"发送"</Caption1Strong>

                {move || {
                    blocked
                        .get()
                        .map(|refused| {
                            view! {
                                <MessageBar
                                    intent=MessageBarIntent::Warning
                                    layout=MessageBarLayout::Multiline
                                >
                                    <MessageBarBody>
                                        <MessageBarTitle>{refused.title}</MessageBarTitle>
                                        {refused.why}
                                    </MessageBarBody>
                                </MessageBar>
                            }
                        })
                }}

                // 🔴 认下代价才能发。勾选框上写的是**完整的代价**，包括
                //    「短信多半真的发出去了」——那一句在此之前一处都没显示过，
                //    而它正是操作员按下去之后最需要记得的：被告知「失败」的人
                //    会重发，对方收两次。
                {move || {
                    ask.get()
                        .map(|label| {
                            view! {
                                <Checkbox
                                    checked=state.commission
                                    label=label
                                />
                            }
                        })
                }}

                <Flex gap=FlexGap::Small style="flex-wrap: wrap;" align=FlexAlign::Center>
                    <Input value=state.to placeholder="号码" disabled=Signal::derive(move || blocked.get().is_some()) />
                    <Input value=state.body placeholder="内容" disabled=Signal::derive(move || blocked.get().is_some()) />
                    <Button
                        appearance=ButtonAppearance::Primary
                        disabled=Signal::derive(move || {
                            blocked.get().is_some() || state.note.get() == Some(SendNote::Sending)
                        })
                        on_click=move |_| {
                            let active = active.get_untracked();
                            leptos::task::spawn_local(async move { send(state, active).await });
                        }
                    >
                        {move || {
                            if state.note.get() == Some(SendNote::Sending) { "发送中…" } else { "发送" }
                        }}
                    </Button>
                </Flex>

                {move || {
                    let over = edge_core::draft(&state.body.get()).over;
                    let text = meter.get();
                    if over {
                        view! {
                            <MessageBar
                                intent=MessageBarIntent::Warning
                                layout=MessageBarLayout::Multiline
                            >
                                <MessageBarBody>{text}</MessageBarBody>
                            </MessageBar>
                        }
                            .into_any()
                    } else {
                        view! { <Caption1>{text}</Caption1> }.into_any()
                    }
                }}

                {move || {
                    state
                        .note
                        .get()
                        .map(|note| {
                            match note {
                                SendNote::Sending => {
                                    view! { <Caption1>"发送中…"</Caption1> }.into_any()
                                }
                                // 🔴 「没有发出 —— 模组没有被碰过」是这里最要紧的一句话。
                                SendNote::Refused(why) => {
                                    view! {
                                        <MessageBar
                                            intent=MessageBarIntent::Warning
                                            layout=MessageBarLayout::Multiline
                                        >
                                            <MessageBarBody>
                                                <MessageBarTitle>
                                                    "没有发出 —— 模组没有被碰过"
                                                </MessageBarTitle>
                                                {why}
                                            </MessageBarBody>
                                        </MessageBar>
                                    }
                                        .into_any()
                                }
                                SendNote::Failed(why) => {
                                    view! {
                                        <MessageBar
                                            intent=MessageBarIntent::Error
                                            layout=MessageBarLayout::Multiline
                                        >
                                            <MessageBarBody>
                                                // ⚠️ 和上面那条拒绝的区别就在这句话里：
                                                // 那边是面板拦下的、模组没有被碰过；这边
                                                // 请求真的到了代理。写「发送失败」会把两件
                                                // 事说成一件，而且和下面 api 层给的
                                                // 「发送：…」前缀重复。
                                                <MessageBarTitle>
                                                    "请求到了代理，代理没有接受"
                                                </MessageBarTitle>
                                                {why}
                                            </MessageBarBody>
                                        </MessageBar>
                                    }
                                        .into_any()
                                }
                                // ⚠️ 「已提交」不是「已送达」。投递回执是后来的事。
                                SendNote::Sent => {
                                    view! {
                                        <MessageBar intent=MessageBarIntent::Success>
                                            <MessageBarBody>
                                                "已提交给代理（不是已送达 —— 投递回执是后来的事）"
                                            </MessageBarBody>
                                        </MessageBar>
                                    }
                                        .into_any()
                                }
                                // 🔴 发在一根已知会掉线的模组上。**两件事都要说**：
                                //    接下来它会离开总线（是代价，不是故障），以及
                                //    短信多半真的发出去了（所以别重发）。
                                SendNote::SentWithCost(also) => {
                                    view! {
                                        <MessageBar
                                            intent=MessageBarIntent::Warning
                                            layout=MessageBarLayout::Multiline
                                        >
                                            <MessageBarBody>
                                                <MessageBarTitle>
                                                    "已提交 —— 接下来这一根会离开总线几十秒"
                                                </MessageBarTitle>
                                                {format!("{also} 它掉线是预期之中的，不是这次发送失败。")}
                                            </MessageBarBody>
                                        </MessageBar>
                                    }
                                        .into_any()
                                }
                            }
                        })
                }}


                <Divider />
                <Caption1Strong>"本地收件箱 · 断网也保留在本机"</Caption1Strong>
                        <div class="vd-actions">
    {move || {
                            active
                                .get()
                                .map(|imei| {
                                    let short = imei.chars().rev().take(6).collect::<Vec<_>>();
                                    let short: String = short.into_iter().rev().collect();
                                    view! {
                                        <Checkbox
                                            checked=state.mine
                                            label=format!("只看 …{short}")
                                        />
                                    }
                                })
                        }}
                    </div>


                {move || match state.inbox.get() {
                    // 🔴 读不到 ≠ 没有短信。原版这里正是把 500 读成了空列表。
                    Load::Loading => view! { <Caption1>"正在读本地短信…"</Caption1> }.into_any(),
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
                    Load::Ready(body) => {
                        let total = body.messages.len();
                        let rows = narrowed(&body.messages, state.mine.get(), active.get().as_deref());
                        if rows.is_empty() {
                            let say = if total == 0 {
                                "本机还没有短信。"
                            } else {
                                "这一根名下没有短信 —— 别的模组的还在，去掉「只看」就能看到。"
                            };
                            return view! { <Caption1>{say}</Caption1> }.into_any();
                        }
                        let count = format!("{} / {} 条", rows.len(), total);
                        view! {
                            <Caption1>{count}</Caption1>
                            <Table>
                                <TableHeader>
                                    <TableRow>
                                        <TableHeaderCell>"时间"</TableHeaderCell>
                                        <TableHeaderCell>"方向"</TableHeaderCell>
                                        <TableHeaderCell>"对端"</TableHeaderCell>
                                        <TableHeaderCell>"模组"</TableHeaderCell>
                                        <TableHeaderCell>"内容"</TableHeaderCell>
                                    </TableRow>
                                </TableHeader>
                                <TableBody>
                                    {rows
                                        .into_iter()
                                        .map(|m| {
                                            view! {
                                                <TableRow>
                                                    <TableCell>
                                                        <Caption1>{hhmmss(m.received_at as f64)}</Caption1>
                                                    </TableCell>
                                                    <TableCell>
                                                        <Badge size=BadgeSize::Small>
                                                            {direction_label(&m.direction)}
                                                        </Badge>
                                                    </TableCell>
                                                    <TableCell>{m.peer}</TableCell>
                                                    // 方向和模组都在载荷里，而改版前的面板把两者都
                                                    // 扔了 —— 三根棒子的往来落在同一个列表里。
                                                    <TableCell>
                                                        <Caption1>
                                                            {m.modem_imei.unwrap_or_else(|| "未记录".into())}
                                                        </Caption1>
                                                    </TableCell>
                                                    <TableCell>{m.body}</TableCell>
                                                </TableRow>
                                            }
                                        })
                                        .collect_view()}
                                </TableBody>
                            </Table>
                        }
                            .into_any()
                    }
                }}

        }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 🔴 一条「已提交给代理」留在另一根旁边，读起来就是那一根发出去了。
    #[test]
    fn switching_modems_forgets_the_last_send_but_keeps_what_is_being_typed() {
        let state = SmsState::new();
        state.note.set(Some(SendNote::Sent));
        state.to.set("8613800100500".into());
        state.body.set("还没发完的一句话".into());

        state.forget_modem();

        assert_eq!(state.note.get_untracked(), None, "上一次发送的结局必须清掉");
        assert_eq!(
            state.to.get_untracked(),
            "8613800100500",
            "⚠️ 号码是操作员正在打的字，换根模组重发是常事，不能清"
        );
        assert_eq!(state.body.get_untracked(), "还没发完的一句话", "内容同上");
    }

    fn message(imei: Option<&str>) -> MessageBody {
        MessageBody {
            seq: 1,
            peer: "8613800100500".into(),
            body: "hi".into(),
            bearer: "sms".into(),
            direction: "in".into(),
            received_at: 0,
            modem_imei: imei.map(str::to_string),
        }
    }

    /// 不选模组必须被拦下，而且理由要说到「代理会取第一条」。
    ///
    /// 这不是提示语的口味问题：机队里有一根发 MO 短信就掉出 USB 总线，而代理
    /// 在没有 IMEI 时会替你抽签。
    #[test]
    fn sending_without_a_chosen_modem_is_refused_and_says_why() {
        let refused = refusal(None, false).expect("不选模组必须被拦");
        let why = &refused.why;
        assert_eq!(
            refused.title, "先选一根模组",
            "一根都没选的时候没有「这一根」"
        );
        assert!(why.contains("第一条"), "要说清代理会替你抽签：{why}");
        assert!(why.contains("USB 总线"), "要说清后果：{why}");
    }

    /// 封禁表里的那一根，在这里也拦一次。
    #[test]
    fn a_blocked_modem_is_refused_here_too() {
        let imei = edge_core::blocked_imeis().next().expect("封禁表不能是空的");
        let refused = refusal(Some(imei), false).expect("封禁的模组必须被拦");
        let why = &refused.why;
        assert_eq!(refused.title, "这一根发不了");
        assert!(why.contains(imei), "要指名是哪一根：{why}");
        assert!(
            why.contains("总线") || why.contains("QMI"),
            "要说清为什么，而不是只说「不许」：{why}"
        );
    }

    #[test]
    fn an_ordinary_modem_is_not_refused() {
        assert_eq!(refusal(Some("860000000000001"), false), None);
    }

    /// 🔴 没记模组的消息在两个视图里都留着。
    ///
    /// 因为一个字段缺失就把行丢掉，是一个收件箱悄悄丢信的方式。
    #[test]
    fn a_message_with_no_recorded_modem_is_never_hidden() {
        let all = vec![
            message(Some("867018069509705")),
            message(Some("860000000000001")),
            message(None),
        ];

        let wide = narrowed(&all, false, Some("867018069509705"));
        assert_eq!(wide.len(), 3, "没开「只看」时全都显示");

        let narrow = narrowed(&all, true, Some("867018069509705"));
        assert_eq!(narrow.len(), 2, "只剩这一根的，加上没记模组的那条");
        assert!(
            narrow.iter().any(|m| m.modem_imei.is_none()),
            "没记模组的那条必须还在"
        );
    }

    /// 没选模组时「只看」无从谈起，不该把列表清空。
    #[test]
    fn narrowing_to_nothing_shows_everything() {
        let all = vec![message(Some("867018069509705")), message(None)];
        assert_eq!(narrowed(&all, true, None).len(), 2);
    }

    /// 字数表用的是 daemon 那一份规则。
    #[test]
    fn the_meter_reads_the_same_rules_the_encoder_uses() {
        assert_eq!(edge_core::draft("hello").limit, edge_core::GSM7_MAX_SEPTETS);
        assert_eq!(
            edge_core::draft("hello #").limit,
            edge_core::UCS2_MAX_CHARS,
            "一个 # 就把限额从 160 打到 70"
        );
    }

    /// 🔴 认下代价之后才发得出去，而且**代价那句话必须完整**。
    ///
    /// 封禁表有两句：`why`（每发一条丢一次模组）和 `also`（短信多半真的发出
    /// 去了，所以别重发）。在此之前面板只显示 `why` —— 而真要发的时候，
    /// `also` 才是最要紧的一句：被告知「失败」的人会重发，对方收两次。
    #[test]
    fn commissioning_opens_the_path_and_states_the_whole_cost() {
        let imei = edge_core::blocked_imeis().next().expect("封禁表不能是空的");
        let block = edge_core::sms_block(imei).expect("有条目");

        assert!(refusal(Some(imei), false).is_some(), "没勾之前必须还是拦着");
        assert!(
            refusal(Some(imei), true).is_none(),
            "勾了之后要放行 —— 否则这个入口是假的"
        );

        let label = commission_ask(imei).expect("封禁的模组要给出这条路");
        assert!(label.contains(block.why), "勾选框上没写清代价：{label}");
        assert!(
            label.contains(block.also),
            "勾选框上少了「短信多半真的发出去了」——那正是按下去之后最该记得的：{label}"
        );
    }

    /// 🔴 没选模组时，`commission` 也越不过去。
    ///
    /// 服务端的 `blocked_send` 里 commission 会短路掉全部检查，包括这一条。
    /// 面板这里比服务端更严，是故意的：不带 IMEI 时代理取 modem map 里的第一
    /// 条，而那一根**可能正是封禁的那根**。「我知道这一根的代价」和「随便挑
    /// 一根替我承担代价」是两回事。
    #[test]
    fn commissioning_never_covers_having_picked_no_modem() {
        let refused = refusal(None, true).expect("没选模组时 commission 也不能放行");
        assert_eq!(refused.title, "先选一根模组");
    }

    /// 没被封禁的模组不该出现这个勾选框 —— 它是给有代价的那根用的。
    #[test]
    fn a_modem_with_no_block_gets_no_commission_box() {
        assert!(commission_ask("867018069514820").is_none());
    }

    /// 🔴 认下的代价**不跨模组**。
    ///
    /// 勾的是「我知道**这一根**发完会掉线」。留着它切到下一根，等于替另一根
    /// 做了这个决定 —— 这正是 `lib.rs` 那段换模组清场要防的那类事。
    #[test]
    fn the_accepted_cost_does_not_follow_you_to_the_next_modem() {
        let src = include_str!("sms.rs");
        let body = src
            .split("pub fn forget_modem")
            .nth(1)
            .expect("forget_modem 还在吗");
        let body = &body[..body.find("\n    }").unwrap_or(body.len())];
        assert!(
            body.contains("commission.set(false)"),
            "换模组没有清掉 commission —— 在 A 上认下的代价会漂到 B 头上"
        );
    }
}
