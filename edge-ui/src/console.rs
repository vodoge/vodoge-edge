//! AT / USSD 控制台。
//!
//! 🔴 **这是整个面板唯一一处能把任意命令直接打进模组的地方**，也是守护进程
//! 刻意不自己走的那条路：`/api/at` 只开在局域网上，正是为了让它不能从云端
//! 被触发。所以这一栏的职责不是拦住谁，而是让打字的那个人知道自己在哪一种
//! 处境里 —— 守卫表在 [`edge_core::at_guard`]，那里记着每一条的代价和**回程**。
//!
//! ## 只读探针是一排按钮，改状态的一律手输
//!
//! ⚠️ 原版的注释写得很清楚，照搬：一键的 `AT+CFUN=1,1` 正是开发期间把一个模组
//! 弄到搁浅、数据会话丢失的原因。**打字本身就是那道守卫。**
//!
//! ## 两道不同的守卫，分别属于两个不同的判断者
//!
//! - **浏览器的守卫**：[`edge_core::at_guard`]，8 条命令，判断者是这个仓库
//!   实测出来的代价，问的是「你知道这条命令会做什么吗」。
//! - **agent 自己的分类器**：`edge_core::classify_at_command`（住在 edge-core，
//!   这一层不重新实现它——它是服务端已经在用的同一份判断），拒绝任何改动
//!   射频、通话、短信、卡或持久配置的命令，除非带 `force`。这一道问的是
//!   「你确定要发，不是打错了」，和浏览器的守卫是**两个不同的判断者**：一个
//!   在按下发送前问人，一个在命令已经到了 agent 手上时再问一次。`强制` 勾选
//!   框每次发送后自动复位——一个忘了关的开关，就是一道被永久关掉的守卫。
//!
//! 一条命令先过浏览器的守卫（如果它命中），确认框点了确定就等于「meant it」，
//! 这时会带 `force` 一并发出，不再让 agent 的分类器对同一件事再问一次；没
//! 命中浏览器守卫的命令，`force` 只取决于那个勾选框。
//!
//! ## USSD 和 AT 共用一个框，一份历史
//!
//! 下拉框切的是「这一行要发给谁」，不是两个独立的控制台。⚠️ 切到 AT **不会**
//! 关掉一个开着的 USSD 会话——只有「取消会话」会。原版的注释把理由写得很
//! 直白：一个被遗弃的会话会让网络那边一直等着，也会挡住下一次 USSD 请求，
//! 所以「取消」跟着会话走，不跟着下拉框走。
//!
//! ## 记录不落盘
//!
//! ⚠️ 这个框是 `AT+CPIN=1234` 被打出来的地方。记录只在内存里，标签页关掉就没
//! 了 —— 一份活得比标签页更久的记录，就是在存那个东西。

use edge_panel_api::{AtResult, UssdResult};
use leptos::prelude::*;
use thaw::*;

use crate::api::{self, Load};

/// 只读探针。⚠️ 这一排里**不能**出现任何改状态的命令。
const QUICK: &[(&str, &str)] = &[
    ("信号", "AT+CSQ"),
    ("注册 CS", "AT+CREG?"),
    ("注册 PS", "AT+CEREG?"),
    ("运营商", "AT+COPS?"),
    ("SIM", "AT+CPIN?"),
    ("ICCID", "AT+QCCID"),
    ("IMSI", "AT+CIMI"),
    ("本机号", "AT+CNUM"),
    ("固件", "AT+QGMR"),
    ("短信中心", "AT+CSCA?"),
    ("IMS", "AT+QCFG=\"ims\""),
];

/// 记录保留多少条。**条**而不是行：一条往返才是人会去读、去复制、去翻过的单位。
const KEEP: usize = 200;

/// 历史命令保留多少条（上下键翻的那个）。
const HISTORY: usize = 100;

/// 这一行是发给谁的。⚠️ 只是「往哪个端点走」，不是两个独立的控制台 ——
/// 历史、记录、取消按钮都是共用的。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    At,
    Ussd,
}

/// 一次往返。
#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    pub seq: u64,
    pub at: f64,
    pub mode: Mode,
    pub command: String,
    pub state: Exchange,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Exchange {
    /// 发出去了，还没回来。
    Waiting,
    /// 模组答了。⚠️ 「答了」不等于「成功」：`+CME ERROR` 也是一种应答，
    /// 而且是最要紧的那种 —— 它告诉你模组还活着，只是拒绝了这一条。
    Answered(AtResult),
    /// 运营商答了。
    UssdAnswered(UssdResult),
    /// 连模组/网络都没够到。
    Lost(String),
    /// 面板拦下的：确认框里点了取消。**命令没有发出去。**
    Refused,
    /// 一句中性的记录，不是一次命令的往返（比如「USSD 会话已取消」）。
    Note(String),
}

#[derive(Clone, Copy)]
pub struct ConsoleState {
    pub entries: RwSignal<Vec<Entry>>,
    pub input: RwSignal<String>,
    pub mode: RwSignal<Mode>,
    /// 「强制」勾选框。⚠️ 每次发送后自动复位——原版的注释说得很清楚：
    /// 一个忘了关的开关，就是一道被永久关掉的守卫。
    pub force: RwSignal<bool>,
    /// 有一个 USSD 会话开着，运营商在等回复。⚠️ 跟着会话走，不跟着模式的
    /// 下拉框走——切到 AT 不会关掉它。
    pub ussd_open: RwSignal<bool>,
    /// 被 [`KEEP`] 挤掉的条数，累计。少了东西要认。
    pub dropped: RwSignal<usize>,
    /// 上下键翻的历史，最新在后。每条连着它当时的模式——翻回一条 USSD
    /// 命令要把下拉框也翻回 USSD，否则历史翻出来的字符串会被当成 AT 发出去。
    history: RwSignal<Vec<(Mode, String)>>,
    /// 翻到第几条。`None` 表示正在编辑当前这一行。
    cursor: RwSignal<Option<usize>>,
    /// 开始翻之前那半行没写完的字，以及当时的模式。⚠️ 翻回来要还给人。
    draft: RwSignal<(Mode, String)>,
    seq: RwSignal<u64>,
}

impl ConsoleState {
    pub fn new() -> Self {
        Self {
            entries: RwSignal::new(Vec::new()),
            input: RwSignal::new(String::new()),
            mode: RwSignal::new(Mode::At),
            force: RwSignal::new(false),
            ussd_open: RwSignal::new(false),
            dropped: RwSignal::new(0),
            history: RwSignal::new(Vec::new()),
            cursor: RwSignal::new(None),
            draft: RwSignal::new((Mode::At, String::new())),
            seq: RwSignal::new(0),
        }
    }

    /// 换了一根模组，USSD 会话标记作废。
    ///
    /// 🔴 会话是**某一根模组和运营商之间**的。标记留着的话，「取消会话」那个
    /// 按钮会挂在新模组下面，按下去把 `AT+CUSD=2` 发给一根根本没有会话的模组，
    /// 而真正开着的那个会话被丢在那里——`lib.rs` 说得很清楚：被遗弃的会话会
    /// 让网络一直等着，并挡住下一次请求。
    ///
    /// ⚠️ 记录和历史**不清**。它们是这次会话的排查记录，不是某一根模组的属性；
    /// 每一条记录都有自己的时间戳，而记录本来就是拿来跨模组对照看的。
    pub fn forget_modem(&self) {
        self.ussd_open.set(false);
    }
}

/// 往上翻一条历史。返回要放进输入框的内容**连同它当时的模式**。
///
/// ⚠️ 第一次往上翻时，要把手上那半行没写完的字（和它的模式）**存起来** ——
/// 翻到底再往下翻回来的时候必须还给人。原版做对了这件事，照搬；模式也跟着
/// 一起翻，否则翻回一条 USSD 命令时下拉框还停在 AT 上，回车会把 `*100#`
/// 当成 AT 命令发出去。
fn back(
    history: &[(Mode, String)],
    cursor: Option<usize>,
    current: (Mode, &str),
) -> (Option<usize>, Mode, String) {
    if history.is_empty() {
        return (cursor, current.0, current.1.to_string());
    }
    let at = match cursor {
        None => history.len() - 1,
        Some(0) => 0,
        Some(i) => i - 1,
    };
    let (mode, text) = history[at].clone();
    (Some(at), mode, text)
}

/// 往下翻一条。翻过最后一条就回到那半行草稿（连同它的模式）。
fn forward(
    history: &[(Mode, String)],
    cursor: Option<usize>,
    draft: (Mode, &str),
) -> (Option<usize>, Mode, String) {
    match cursor {
        None => (None, draft.0, draft.1.to_string()),
        Some(i) if i + 1 < history.len() => {
            let (mode, text) = history[i + 1].clone();
            (Some(i + 1), mode, text)
        }
        Some(_) => (None, draft.0, draft.1.to_string()),
    }
}

fn confirmed(message: &str) -> bool {
    web_sys::window()
        .and_then(|w| w.confirm_with_message(message).ok())
        .unwrap_or(false)
}

fn now_ms() -> f64 {
    crate::status::now_ms()
}

fn push(state: ConsoleState, entry: Entry) {
    state.entries.update(|list| {
        list.push(entry);
        if list.len() > KEEP {
            let over = list.len() - KEEP;
            list.drain(..over);
            state.dropped.update(|n| *n += over);
        }
    });
}

fn update_entry(state: ConsoleState, seq: u64, next: Exchange) {
    state.entries.update(|list| {
        if let Some(entry) = list.iter_mut().find(|e| e.seq == seq) {
            entry.state = next;
        }
    });
}

/// 发一条命令 —— AT 或 USSD，由 `state.mode` 决定发给哪个端点。
///
/// ⚠️ 确认在这里做，不在按钮上。上下键调出来的命令、只读探针、手输的回车，
/// 三条路都汇到这里 —— 守卫只放在其中一条路上，等于没放。
pub async fn run(state: ConsoleState, active: Option<String>, command: String, mode: Mode) {
    let command = command.trim().to_string();
    if command.is_empty() {
        return;
    }

    state.seq.update(|n| *n += 1);
    let seq = state.seq.get_untracked();

    // 浏览器的守卫只认 AT 命令的形状（见 `edge_core::guarded`），USSD 码
    // （`*100#` 这一类）天然不会命中，所以这一段对两种模式都能安全跑一遍。
    let mut force = state.force.get_untracked();
    if let Some(what) = edge_core::guarded(&command) {
        if !confirmed(&edge_core::ask(what, &command, active.as_deref())) {
            // 拒绝也要留痕。没有痕迹的话，一个被点掉的对话框和一条安静发出去的
            // 命令，在屏幕上分不出来。
            push(
                state,
                Entry {
                    seq,
                    at: now_ms(),
                    mode,
                    command,
                    state: Exchange::Refused,
                },
            );
            return;
        }
        // 确认框点了确定就等于「meant it」——不再让 agent 自己的分类器对
        // 同一件事又拒一次，逼人在两道守卫上各同意一遍。
        force = true;
    }

    // 进历史。⚠️ 只在真的要发的时候才进 —— 取消掉的命令翻上来会让人以为它发过。
    state.history.update(|h| {
        if h.last().map(|(_, text)| text.as_str()) != Some(command.as_str()) {
            h.push((mode, command.clone()));
            if h.len() > HISTORY {
                let over = h.len() - HISTORY;
                h.drain(..over);
            }
        }
    });
    state.cursor.set(None);
    state.draft.set((mode, String::new()));
    state.input.set(String::new());
    // 「强制」每次发送后自动复位，不管这次命中的是哪一条路径——一个忘了关
    // 的开关就是一道被永久关掉的守卫。
    state.force.set(false);

    push(
        state,
        Entry {
            seq,
            at: now_ms(),
            mode,
            command: command.clone(),
            state: Exchange::Waiting,
        },
    );

    match mode {
        Mode::At => {
            let body = edge_panel_api::AtBody {
                command,
                imei: active,
                force,
            };
            let got: Load<AtResult> = api::post("/api/at", &body, "AT").await;
            match got {
                Load::Ready(result) => update_entry(state, seq, Exchange::Answered(result)),
                Load::Failed(why) => update_entry(state, seq, Exchange::Lost(why)),
                Load::Loading => {}
            }
        }
        Mode::Ussd => {
            let body = edge_panel_api::UssdBody {
                code: command,
                imei: active,
            };
            let got: Load<UssdResult> = api::post("/api/ussd", &body, "USSD").await;
            match got {
                Load::Ready(result) => {
                    // ⚠️ 会话开不开只看这一次答复，不看上一次——一次
                    // `expects_reply: false` 的应答就是网络自己把会话结束了。
                    state.ussd_open.set(result.expects_reply);
                    update_entry(state, seq, Exchange::UssdAnswered(result));
                }
                Load::Failed(why) => update_entry(state, seq, Exchange::Lost(why)),
                Load::Loading => {}
            }
        }
    }
}

/// 取消一个开着的 USSD 会话。
///
/// 🔴 原版这里 `.catch(() => {})` 吞掉失败，不管端点回了什么都显示「已取消」。
/// 那正是这整个迁移要修的那类问题：一次没有发生的取消，画成了「已经取消」——
/// 会话可能还在网络那边等着，操作员却以为它已经结束了。这里改成诚实：
/// 取消失败就说取消失败，`ussd_open` 不动，因为**不知道**它现在开不开。
pub async fn cancel_ussd(state: ConsoleState, active: Option<String>) {
    state.seq.update(|n| *n += 1);
    let seq = state.seq.get_untracked();
    push(
        state,
        Entry {
            seq,
            at: now_ms(),
            mode: Mode::Ussd,
            command: "取消会话".into(),
            state: Exchange::Waiting,
        },
    );
    let body = edge_panel_api::ResetBody { imei: active };
    let got: Load<serde_json::Value> = api::post("/api/ussd/cancel", &body, "取消 USSD 会话").await;
    match got {
        Load::Ready(_) => {
            state.ussd_open.set(false);
            update_entry(state, seq, Exchange::Note("USSD 会话已取消。".into()));
        }
        Load::Failed(why) => {
            // 会话到底还开不开，这一次请求没能确认——所以不动 `ussd_open`。
            update_entry(
                state,
                seq,
                Exchange::Lost(format!("取消没有成功：{why}。会话可能仍然开着。")),
            );
        }
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

#[component]
pub fn ConsolePage(active: RwSignal<Option<String>>, state: ConsoleState) -> impl IntoView {
    // 手输框那条路：用下拉框当前选的模式——那正是操作员刚刚亲手选的东西。
    let send = move |command: String| {
        let active = active.get_untracked();
        let mode = state.mode.get_untracked();
        leptos::task::spawn_local(async move { run(state, active, command, mode).await });
    };

    // 🔴 只读探针那一排**永远走 AT**，不看下拉框。
    //
    // 这一排按钮上方写着「这一排全是只读查询，不会改模组状态」。它们和手输框
    // 共用同一个 `run()`，而 `run()` 原先是从 `state.mode` 取模式的——于是模式
    // 停在 USSD 时，点「信号」会把 `AT+CSQ` 当成 USSD code 发出去：`/api/ussd`
    // 那条路先无条件发一次 `AT+CUSD=2` 释放掉现有会话，再发
    // `AT+CUSD=1,"AT+CSQ",15`。整个过程没有确认框（`guarded("AT+CSQ")` 是
    // `None`），服务端也拦不住——`refuse_disruptive_at` 只装在 `/api/at` 上，
    // `/api/ussd` 不经过它。
    //
    // 一排自称只读的按钮真的动了运营商侧的东西，这正是这块面板通篇在防的事。
    // 探针是 AT 命令，所以它们发 AT，和下拉框无关。
    let probe = move |command: String| {
        let active = active.get_untracked();
        leptos::task::spawn_local(async move { run(state, active, command, Mode::At).await });
    };

    view! {
                        <div class="vd-actions">
    <Caption1>
                            {move || match active.get() {
                                // ⚠️ 未选模组时命令落在哪里，必须在框边上就说清楚 ——
                                // 对话框里也会再说一次。
                                None => "未选模组 —— 命令会落在第一个应答的控制口".to_string(),
                                Some(imei) => format!("发往 {imei}"),
                            }}
                        </Caption1>
                    </div>


                <Caption1Strong>"只读探针"</Caption1Strong>
                <Caption1>"这一排全是只读查询，不会改模组状态。改状态的命令一律手输 —— 打字本身就是那道守卫。"</Caption1>
                <Flex gap=FlexGap::Small style="flex-wrap: wrap;">
                    {QUICK
                        .iter()
                        .map(|(label, command)| {
                            let command = command.to_string();
                            let probe = probe.clone();
                            view! {
                                <Button
                                    size=ButtonSize::Small
                                    on_click=move |_| probe(command.clone())
                                >
                                    {*label}
                                </Button>
                            }
                        })
                        .collect_view()}
                </Flex>

                // ⚠️ USSD 会话开着的话，这句话跟着会话走——不跟着下面那个下拉框走。
                // 切到 AT 不会关掉它，只有「取消会话」会。
                {move || {
                    state
                        .ussd_open
                        .get()
                        .then(|| {
                            view! {
                                <MessageBar
                                    intent=MessageBarIntent::Warning
                                    layout=MessageBarLayout::Multiline
                                >
                                    <MessageBarBody>
                                        <div>
                                            "USSD 会话开着 —— 运营商在等回复。把菜单选项直接填进输入框再发一次；切到 AT 不会关掉它，只有「取消会话」会。"
                                        </div>
                                    </MessageBarBody>
                                    <MessageBarActions>
                                        <Button
                                            size=ButtonSize::Small
                                            on_click=move |_| {
                                                let active = active.get_untracked();
                                                leptos::task::spawn_local(async move {
                                                    cancel_ussd(state, active).await
                                                });
                                            }
                                        >
                                            "取消会话"
                                        </Button>
                                    </MessageBarActions>
                                </MessageBar>
                            }
                        })
                }}

                <Flex gap=FlexGap::Small style="flex-wrap: wrap;" align=FlexAlign::Center>
                    // 两个模式按钮而不是下拉框：Thaw 0.4.8 的 `Select` 双向绑定的是
                    // `Model<String>`，和这里的 `RwSignal<Mode>` 之间没有现成的转换，
                    // 硬凑一个字符串代理只会多一处「两份状态要保持同步」的地方；
                    // Thaw 0.4.8 也没有 ToggleButton，用 appearance 表示选中态。
                    <Button
                        appearance=Signal::derive(move || {
                            if state.mode.get() == Mode::At {
                                ButtonAppearance::Primary
                            } else {
                                ButtonAppearance::Secondary
                            }
                        })
                        on_click=move |_| state.mode.set(Mode::At)
                    >
                        "AT"
                    </Button>
                    <Button
                        appearance=Signal::derive(move || {
                            if state.mode.get() == Mode::Ussd {
                                ButtonAppearance::Primary
                            } else {
                                ButtonAppearance::Secondary
                            }
                        })
                        on_click=move |_| state.mode.set(Mode::Ussd)
                    >
                        "USSD"
                    </Button>

                    // ⚠️ 键盘处理挂在外面这个 div 上，不在 `Input` 上：Thaw 0.4.8 的
                    // `Input` 没有 `on_key_down` 这个 prop。按键会冒泡上来，效果一样，
                    // 而且不用改组件库。
                    <div on:keydown=move |event: web_sys::KeyboardEvent| {
                            match event.key().as_str() {
                                "Enter" => {
                                    event.prevent_default();
                                    send(state.input.get_untracked());
                                }
                                "ArrowUp" => {
                                    event.prevent_default();
                                    let history = state.history.get_untracked();
                                    let cursor = state.cursor.get_untracked();
                                    if cursor.is_none() {
                                        // 翻之前先把这半行（连同模式）存下来。
                                        state.draft.set((state.mode.get_untracked(), state.input.get_untracked()));
                                    }
                                    let (next, mode, text) = back(
                                        &history,
                                        cursor,
                                        (state.mode.get_untracked(), &state.input.get_untracked()),
                                    );
                                    state.cursor.set(next);
                                    state.mode.set(mode);
                                    state.input.set(text);
                                }
                                "ArrowDown" => {
                                    event.prevent_default();
                                    let history = state.history.get_untracked();
                                    let draft = state.draft.get_untracked();
                                    let (next, mode, text) = forward(
                                        &history,
                                        state.cursor.get_untracked(),
                                        (draft.0, &draft.1),
                                    );
                                    state.cursor.set(next);
                                    state.mode.set(mode);
                                    state.input.set(text);
                                }
                                "Escape" => {
                                    // ⚠️ Esc 是「取消我正在打的这一行」，不只是失焦。
                                    // 一行留在框里的半截命令，正是下一次回车会误发出去
                                    // 的那个东西。
                                    event.prevent_default();
                                    state.input.set(String::new());
                                    state.cursor.set(None);
                                    state.draft.set((state.mode.get_untracked(), String::new()));
                                }
                                _ => {}
                            }
                        }
                    >
                        <Input
                            value=state.input
                            placeholder=Signal::derive(move || match state.mode.get() {
                                Mode::At => "AT+…（回车发出，↑↓ 翻历史，Esc 清空这一行）".to_string(),
                                Mode::Ussd => "*100#（回车发出，↑↓ 翻历史，Esc 清空这一行）".to_string(),
                            })
                        />
                    </div>
                    <Button
                        appearance=ButtonAppearance::Primary
                        on_click=move |_| send(state.input.get_untracked())
                    >
                        "发出"
                    </Button>

                    // ⚠️ 只在 AT 模式下有意义：agent 自己的分类器（`edge_core::
                    // classify_at_command`，服务端已经在用的同一份判断）会拒绝任何
                    // 改动射频、通话、短信、卡或持久配置的命令，除非带 force。这一格
                    // 每次发送后自动复位——见模块文档。
                    //
                    // 🔴 用 `For` 而不是 `move || (…).then(...)`（原本试过，见下）把
                    // 这个 checkbox 包成一个只有 0 或 1 个元素、键是 `seq` 的列表。
                    // 每次发送/取消都会把 `seq` 往前推一格，这里的键跟着变，`For`
                    // 的 diff 会把「旧键」当成被删掉、「新键」当成刚加上——也就是
                    // 把 `<Checkbox>` 整个拆了重建，而不是原地更新它的 props。
                    //
                    // 这不是洁癖：Thaw 0.4.8 的这个 checkbox，从代码里（不是从用户
                    // 点击）把 `force` 改回 `false` 时，只有样式（勾选图标、CSS 类）
                    // 会跟着变，原生 `<input>` 那个 `checked` **属性**不会同步。属性
                    // 卡在陈旧的 `true` 上，下一次用户点这个看起来已经没勾的框，
                    // 浏览器的原生切换逻辑是拿那个陈旧的 `true` 去翻，翻成
                    // `false`——和当前状态一样，什么都看不出来，得再点一次才能真的
                    // 勾上。这正是「忘了关的开关」那句话要避免的那类静默失效，只是
                    // 换了个由头。曾经试过在同一个 `.then()` 分支里加一个不相关的
                    // `seq` 依赖逼它重新求值，没用——分支形状（`Some(...)`）没变，
                    // Leptos 只会原地更新 props，同一个 bug。只有真的换掉整个分支
                    // （用 `For` 的键值变化）才会真的重新创建 DOM 节点。
                    // `each` 自己读 `state.mode` / `state.seq`——把这两个 `.get()`
                    // 放进包一层的 `{move || ...}` 反而会让 `For` 追踪不到，因为
                    // 那样 `each` 闭包本身就只是「返回一份已经算好的快照」，不再
                    // 在自己的求值里触发信号读取。让 `For` 的 diff 逻辑亲自感知到
                    // 键集合变化，才能保证它真的按键去重建，而不是被外层的
                    // 「同一种形状」优化成原地更新 props。
                    <For
                        each=move || {
                            if state.mode.get() == Mode::At {
                                vec![state.seq.get()]
                            } else {
                                Vec::new()
                            }
                        }
                        key=|seq| *seq
                        let:_seq
                    >
                        <Checkbox checked=state.force label="强制" />
                    </For>
                </Flex>

                <GuardList />
                <Transcript state=state />

        }
}

/// 守卫命令表。⚠️ 要在**任何人打字之前**就摆在屏幕上 —— 一条只在对话框里
/// 才出现的守卫，等于让人在按下去之后才第一次读到代价。
#[component]
fn GuardList() -> impl IntoView {
    view! {
        <Caption1Strong>"这些命令发出前会先问一次"</Caption1Strong>
        <Table>
            <TableBody>
                {edge_core::GUARDS
                    .iter()
                    .map(|g| {
                        view! {
                            <TableRow>
                                <TableCell>
                                    <Caption1>{g.label}</Caption1>
                                </TableCell>
                                <TableCell>
                                    <Caption1>{g.warn}</Caption1>
                                </TableCell>
                            </TableRow>
                        }
                    })
                    .collect_view()}
            </TableBody>
        </Table>
    }
}

#[component]
fn Transcript(state: ConsoleState) -> impl IntoView {
    move || {
        let entries = state.entries.get();
        let dropped = state.dropped.get();
        if entries.is_empty() {
            return view! { <Caption1>"还没有发过命令。"</Caption1> }.into_any();
        }
        view! {
            {(dropped > 0)
                .then(|| {
                    view! {
                        <Badge color=BadgeColor::Warning size=BadgeSize::Small>
                            {format!("已丢弃最旧 {dropped} 条")}
                        </Badge>
                    }
                })}
            {entries
                .into_iter()
                .rev()
                .map(|entry| view! { <Exchange entry=entry /> })
                .collect_view()}
        }
        .into_any()
    }
}

#[component]
#[allow(non_snake_case)]
fn Exchange(entry: Entry) -> impl IntoView {
    let head = format!("{}  {}", hhmmss(entry.at), entry.command);
    match entry.state {
        Exchange::Waiting => view! {
            <MessageBar intent=MessageBarIntent::Info layout=MessageBarLayout::Multiline>
                <MessageBarBody>
                    <MessageBarTitle>{head}</MessageBarTitle>
                    "发出去了，还没回来…"
                </MessageBarBody>
            </MessageBar>
        }
        .into_any(),
        // 🔴 命令没有发出去。这一条和「发了但失败」必须分得开。
        Exchange::Refused => view! {
            <MessageBar intent=MessageBarIntent::Warning layout=MessageBarLayout::Multiline>
                <MessageBarBody>
                    <MessageBarTitle>{head}</MessageBarTitle>
                    "已取消 —— 命令没有发出去，模组没有被碰过。"
                </MessageBarBody>
            </MessageBar>
        }
        .into_any(),
        Exchange::Note(text) => view! {
            <MessageBar intent=MessageBarIntent::Info layout=MessageBarLayout::Multiline>
                <MessageBarBody>
                    <MessageBarTitle>{head}</MessageBarTitle>
                    {text}
                </MessageBarBody>
            </MessageBar>
        }
        .into_any(),
        Exchange::Lost(why) => view! {
            <MessageBar intent=MessageBarIntent::Error layout=MessageBarLayout::Multiline>
                <MessageBarBody>
                    <MessageBarTitle>{head}</MessageBarTitle>
                    {why}
                </MessageBarBody>
            </MessageBar>
        }
        .into_any(),
        Exchange::Answered(result) => {
            // ⚠️ `ok == false` 不是「没够到模组」，是模组**答了 `+CME ERROR`**。
            // 那是一次成功的往返，而且往往是最有用的一次 —— 它说明模组还活着。
            let intent = if result.ok {
                MessageBarIntent::Success
            } else {
                MessageBarIntent::Warning
            };
            let tail = format!(
                "{} · {} · {} ms",
                result.port, result.terminator, result.elapsed_ms
            );
            view! {
                <MessageBar intent=intent layout=MessageBarLayout::Multiline>
                    <MessageBarBody>
                        <MessageBarTitle>{head}</MessageBarTitle>
                        <div>
                            {result
                                .lines
                                .into_iter()
                                .map(|line| view! { <div><code>{line}</code></div> })
                                .collect_view()}
                        </div>
                        <Caption1>{tail}</Caption1>
                    </MessageBarBody>
                </MessageBar>
            }
            .into_any()
        }
        Exchange::UssdAnswered(result) => {
            // ⚠️ `expects_reply` 决定的是会话开不开（在 `run()` 里处理），
            // 这里只负责把运营商说的话画出来，并且在还等着回复时提醒一句 ——
            // 原版把这句话单独标了 warn 色，照搬。
            let tail = format!("{} · {} ms", result.stage, result.elapsed_ms);
            view! {
                <MessageBar intent=MessageBarIntent::Success layout=MessageBarLayout::Multiline>
                    <MessageBarBody>
                        <MessageBarTitle>{head}</MessageBarTitle>
                        <div>{result.text.clone()}</div>
                        {result
                            .expects_reply
                            .then(|| {
                                view! {
                                    <div>"运营商在等待回复 —— 把选项填进输入框再发一次"</div>
                                }
                            })}
                        <Caption1>{tail}</Caption1>
                    </MessageBarBody>
                </MessageBar>
            }
            .into_any()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 🔴 USSD 会话是**某一根模组和运营商之间**的。标记跨模组留着，
    /// 「取消会话」就会把 AT+CUSD=2 发给一根没有会话的模组。
    #[test]
    fn switching_modems_forgets_the_ussd_session_but_keeps_the_transcript() {
        let state = ConsoleState::new();
        state.ussd_open.set(true);
        state.entries.update(|list| {
            list.push(Entry {
                seq: 1,
                at: 0.0,
                mode: Mode::Ussd,
                command: "*100#".into(),
                state: Exchange::Refused,
            })
        });
        state.mode.set(Mode::Ussd);

        state.forget_modem();

        assert!(
            !state.ussd_open.get_untracked(),
            "会话标记必须清掉，否则「取消会话」会取消到错的模组"
        );
        assert_eq!(
            state.entries.get_untracked().len(),
            1,
            "⚠️ 记录是这次排查的记录，不是某根模组的属性，不能清"
        );
    }

    /// 只读探针这一排里不能有任何改状态的命令。
    ///
    /// 一键的 `AT+CFUN=1,1` 正是开发期间把一个模组弄到搁浅的原因。这一排是
    /// 按钮，按钮不该有代价。
    #[test]
    fn every_quick_probe_is_read_only() {
        for (label, command) in QUICK {
            assert_eq!(
                edge_core::guarded(command),
                None,
                "只读探针里出现了一条要先问一次的命令：{label} = {command}"
            );
            assert!(
                command.ends_with('?')
                    || command.starts_with("AT+CSQ")
                    || command.starts_with("AT+CIMI")
                    || command.starts_with("AT+CNUM")
                    || command.starts_with("AT+QCCID")
                    || command.starts_with("AT+QGMR")
                    || command.contains("=\""),
                "{command} 看起来不像一条查询"
            );
        }
        assert!(QUICK.len() >= 8, "这一排空了的话上面的循环什么也没检查");
    }

    /// ↑ 翻历史时，手上那半行没写完的字要留着，翻回来还给人。
    #[test]
    fn walking_the_history_gives_back_the_half_written_line() {
        let history = vec![
            (Mode::At, "AT+CSQ".to_string()),
            (Mode::At, "AT+COPS?".to_string()),
        ];

        // 从「正在打一半」开始往上翻。
        let (cursor, mode, text) = back(&history, None, (Mode::At, "AT+CP"));
        assert_eq!(cursor, Some(1));
        assert_eq!(mode, Mode::At);
        assert_eq!(text, "AT+COPS?", "第一次往上是最近一条");

        let (cursor, mode, text) = back(&history, cursor, (mode, &text));
        assert_eq!(cursor, Some(0));
        assert_eq!(text, "AT+CSQ");

        // 翻到底再往上，停住，不越界。
        let (cursor, mode, text) = back(&history, cursor, (mode, &text));
        assert_eq!(cursor, Some(0));
        assert_eq!(text, "AT+CSQ");

        // 往下翻回去，最后要拿回那半行。
        let (cursor, mode, text) = forward(&history, cursor, (mode, "AT+CP"));
        assert_eq!(cursor, Some(1));
        assert_eq!(text, "AT+COPS?");

        let (cursor, _mode, text) = forward(&history, cursor, (mode, "AT+CP"));
        assert_eq!(cursor, None);
        assert_eq!(text, "AT+CP", "翻过最后一条要把那半行还回来");
    }

    /// 历史是空的时候，上下键不能把人正在打的字吃掉。
    #[test]
    fn an_empty_history_does_not_eat_what_is_being_typed() {
        let (cursor, mode, text) = back(&[], None, (Mode::At, "AT+CSQ"));
        assert_eq!(cursor, None);
        assert_eq!(mode, Mode::At);
        assert_eq!(text, "AT+CSQ");
    }

    /// 🔴 翻历史要把模式也翻回去，否则一条 USSD 命令会被当成 AT 命令重发。
    #[test]
    fn walking_the_history_restores_the_mode_the_command_was_sent_in() {
        let history = vec![
            (Mode::Ussd, "*100#".to_string()),
            (Mode::At, "AT+CSQ".to_string()),
        ];
        let (cursor, mode, text) = back(&history, None, (Mode::At, ""));
        assert_eq!(mode, Mode::At, "最近一条是 AT");
        assert_eq!(text, "AT+CSQ");

        let (_, mode, text) = back(&history, cursor, (mode, &text));
        assert_eq!(mode, Mode::Ussd, "翻到 USSD 那条时，模式要跟着变回 USSD");
        assert_eq!(text, "*100#");
    }

    /// 守卫表要真的有东西，而且屏幕上那张表和判定用的是同一份。
    #[test]
    fn the_on_screen_list_is_the_guard_table_itself() {
        assert_eq!(edge_core::GUARDS.len(), 8, "屏幕上的守卫表条数变了");
        for row in edge_core::GUARDS {
            assert!(!row.label.is_empty());
            assert!(!row.warn.is_empty(), "{} 没有说代价", row.label);
        }
    }

    /// USSD 码天然不会命中浏览器那 8 条 AT 守卫——它们的形状是 `AT+…`，
    /// USSD 码是 `*100#` 这一类。这条测试钉住这个前提：`run()` 对两种模式
    /// 共用同一段守卫检查，如果哪天守卫表学会了匹配非 AT 字符串，这里要红。
    #[test]
    fn ussd_codes_never_trip_the_at_guard_table() {
        for code in ["*100#", "*#06#", "##002#", "*133*1#"] {
            assert_eq!(
                edge_core::guarded(code),
                None,
                "USSD 码 {code} 不该命中任何一条 AT 守卫"
            );
        }
    }

    /// Mode 是 Eq 的，切换模式时下拉框的值比较要能用 `==`，不用字符串。
    #[test]
    fn mode_round_trips_through_its_wire_string() {
        assert_ne!(Mode::At, Mode::Ussd);
        assert_eq!(Mode::At, Mode::At);
    }
}
