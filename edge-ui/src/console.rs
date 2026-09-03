//! AT 控制台。
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
//! ## 记录不落盘
//!
//! ⚠️ 这个框是 `AT+CPIN=1234` 被打出来的地方。记录只在内存里，标签页关掉就没
//! 了 —— 一份活得比标签页更久的记录，就是在存那个东西。

use edge_panel_api::AtResult;
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

/// 一次往返。
#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    pub seq: u64,
    pub at: f64,
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
    /// 连模组都没够到。
    Lost(String),
    /// 面板拦下的：确认框里点了取消。**命令没有发出去。**
    Refused,
}

#[derive(Clone, Copy)]
pub struct ConsoleState {
    pub entries: RwSignal<Vec<Entry>>,
    pub input: RwSignal<String>,
    /// 被 [`KEEP`] 挤掉的条数，累计。少了东西要认。
    pub dropped: RwSignal<usize>,
    /// 上下键翻的历史，最新在后。
    history: RwSignal<Vec<String>>,
    /// 翻到第几条。`None` 表示正在编辑当前这一行。
    cursor: RwSignal<Option<usize>>,
    /// 开始翻之前那半行没写完的字。⚠️ 翻回来要还给人。
    draft: RwSignal<String>,
    seq: RwSignal<u64>,
}

impl ConsoleState {
    pub fn new() -> Self {
        Self {
            entries: RwSignal::new(Vec::new()),
            input: RwSignal::new(String::new()),
            dropped: RwSignal::new(0),
            history: RwSignal::new(Vec::new()),
            cursor: RwSignal::new(None),
            draft: RwSignal::new(String::new()),
            seq: RwSignal::new(0),
        }
    }
}

/// 往上翻一条历史。返回要放进输入框的内容。
///
/// ⚠️ 第一次往上翻时，要把手上那半行没写完的字**存起来** —— 翻到底再往下翻
/// 回来的时候必须还给人。原版做对了这件事，照搬。
fn back(history: &[String], cursor: Option<usize>, current: &str) -> (Option<usize>, String) {
    if history.is_empty() {
        return (cursor, current.to_string());
    }
    match cursor {
        None => (Some(history.len() - 1), history[history.len() - 1].clone()),
        Some(0) => (Some(0), history[0].clone()),
        Some(i) => (Some(i - 1), history[i - 1].clone()),
    }
}

/// 往下翻一条。翻过最后一条就回到那半行草稿。
fn forward(history: &[String], cursor: Option<usize>, draft: &str) -> (Option<usize>, String) {
    match cursor {
        None => (None, draft.to_string()),
        Some(i) if i + 1 < history.len() => (Some(i + 1), history[i + 1].clone()),
        Some(_) => (None, draft.to_string()),
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

/// 发一条命令。
///
/// ⚠️ 确认在这里做，不在按钮上。上下键调出来的命令、只读探针、手输的回车，
/// 三条路都汇到这里 —— 守卫只放在其中一条路上，等于没放。
pub async fn run(state: ConsoleState, active: Option<String>, command: String) {
    let command = command.trim().to_string();
    if command.is_empty() {
        return;
    }

    state.seq.update(|n| *n += 1);
    let seq = state.seq.get_untracked();

    if let Some(what) = edge_core::guarded(&command) {
        if !confirmed(&edge_core::ask(what, &command, active.as_deref())) {
            // 拒绝也要留痕。没有痕迹的话，一个被点掉的对话框和一条安静发出去的
            // 命令，在屏幕上分不出来。
            push(
                state,
                Entry {
                    seq,
                    at: now_ms(),
                    command,
                    state: Exchange::Refused,
                },
            );
            return;
        }
    }

    // 进历史。⚠️ 只在真的要发的时候才进 —— 取消掉的命令翻上来会让人以为它发过。
    state.history.update(|h| {
        if h.last().map(String::as_str) != Some(command.as_str()) {
            h.push(command.clone());
            if h.len() > HISTORY {
                let over = h.len() - HISTORY;
                h.drain(..over);
            }
        }
    });
    state.cursor.set(None);
    state.draft.set(String::new());
    state.input.set(String::new());

    push(
        state,
        Entry {
            seq,
            at: now_ms(),
            command: command.clone(),
            state: Exchange::Waiting,
        },
    );

    let body = serde_json::json!({ "command": command, "imei": active });
    let got: Load<AtResult> = api::post("/api/at", &body, "AT").await;
    match got {
        Load::Ready(result) => update_entry(state, seq, Exchange::Answered(result)),
        Load::Failed(why) => update_entry(state, seq, Exchange::Lost(why)),
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
    let send = move |command: String| {
        let active = active.get_untracked();
        leptos::task::spawn_local(async move { run(state, active, command).await });
    };

    view! {
        <Card>
            <CardHeader>
                <Body1><b>"AT 控制台"</b></Body1>
                <CardHeaderDescription slot>
                    <Caption1>
                        {move || match active.get() {
                            // ⚠️ 未选模组时命令落在哪里，必须在框边上就说清楚 ——
                            // 对话框里也会再说一次。
                            None => "未选模组 —— 命令会落在第一个应答的控制口".to_string(),
                            Some(imei) => format!("发往 {imei}"),
                        }}
                    </Caption1>
                </CardHeaderDescription>
            </CardHeader>

            <Caption1Strong>"只读探针"</Caption1Strong>
            <Caption1>"这一排全是只读查询，不会改模组状态。改状态的命令一律手输 —— 打字本身就是那道守卫。"</Caption1>
            <Flex gap=FlexGap::Small style="flex-wrap: wrap;">
                {QUICK
                    .iter()
                    .map(|(label, command)| {
                        let command = command.to_string();
                        let send = send.clone();
                        view! {
                            <Button
                                size=ButtonSize::Small
                                on_click=move |_| send(command.clone())
                            >
                                {*label}
                            </Button>
                        }
                    })
                    .collect_view()}
            </Flex>

            <Flex gap=FlexGap::Small style="flex-wrap: wrap;" align=FlexAlign::Center>
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
                                    // 翻之前先把这半行存下来。
                                    state.draft.set(state.input.get_untracked());
                                }
                                let (next, text) = back(
                                    &history,
                                    cursor,
                                    &state.input.get_untracked(),
                                );
                                state.cursor.set(next);
                                state.input.set(text);
                            }
                            "ArrowDown" => {
                                event.prevent_default();
                                let history = state.history.get_untracked();
                                let (next, text) = forward(
                                    &history,
                                    state.cursor.get_untracked(),
                                    &state.draft.get_untracked(),
                                );
                                state.cursor.set(next);
                                state.input.set(text);
                            }
                            "Escape" => {
                                // ⚠️ Esc 是「取消我正在打的这一行」，不只是失焦。
                                // 一行留在框里的半截命令，正是下一次回车会误发出去
                                // 的那个东西。
                                event.prevent_default();
                                state.input.set(String::new());
                                state.cursor.set(None);
                                state.draft.set(String::new());
                            }
                            _ => {}
                        }
                    }
                >
                    <Input
                        value=state.input
                        placeholder="AT+…（回车发出，↑↓ 翻历史，Esc 清空这一行）"
                    />
                </div>
                <Button
                    appearance=ButtonAppearance::Primary
                    on_click=move |_| send(state.input.get_untracked())
                >
                    "发出"
                </Button>
            </Flex>

            <GuardList />
            <Transcript state=state />
        </Card>
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let history = vec!["AT+CSQ".to_string(), "AT+COPS?".to_string()];

        // 从「正在打一半」开始往上翻。
        let (cursor, text) = back(&history, None, "AT+CP");
        assert_eq!(cursor, Some(1));
        assert_eq!(text, "AT+COPS?", "第一次往上是最近一条");

        let (cursor, text) = back(&history, cursor, &text);
        assert_eq!(cursor, Some(0));
        assert_eq!(text, "AT+CSQ");

        // 翻到底再往上，停住，不越界。
        let (cursor, text) = back(&history, cursor, &text);
        assert_eq!(cursor, Some(0));
        assert_eq!(text, "AT+CSQ");

        // 往下翻回去，最后要拿回那半行。
        let (cursor, text) = forward(&history, cursor, "AT+CP");
        assert_eq!(cursor, Some(1));
        assert_eq!(text, "AT+COPS?");

        let (cursor, text) = forward(&history, cursor, "AT+CP");
        assert_eq!(cursor, None);
        assert_eq!(text, "AT+CP", "翻过最后一条要把那半行还回来");
    }

    /// 历史是空的时候，上下键不能把人正在打的字吃掉。
    #[test]
    fn an_empty_history_does_not_eat_what_is_being_typed() {
        let (cursor, text) = back(&[], None, "AT+CSQ");
        assert_eq!(cursor, None);
        assert_eq!(text, "AT+CSQ");
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
}
