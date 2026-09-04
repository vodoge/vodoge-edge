//! 日志列。
//!
//! daemon 自己的输出是看清一根模组在干什么最快的路，但够到它原本要一个 SSH
//! 会话加 `journalctl` —— 而那恰恰是现场操作员没有的权限。服务端把同样的行
//! 留在一个 500 行的环里，这一栏把它端到局域网上。
//!
//! ## 这一栏必须说实话的几件事
//!
//! 🔴 **级别、话题、模组归属，一样都不是服务端标的。** `/api/logs` 只给
//! `{seq, at, text}`（见 [`edge_panel_api::LogsBody`]），下面每一个筛选按钮
//! 背后都是 [`edge_core::classify`] 从行文里**猜**出来的。猜错是可能的，所以
//! 屏幕上要写着这句话 —— 否则「错 0 条」会被当成 daemon 的结论。
//!
//! 🔴 **轮询失败不能画成「没有日志」。** 这是整个迁移要修的那个缺陷在这一栏
//! 的样子：上一次没读到，就说上一次没读到，而不是让屏幕安静地停在旧行上装作
//! 什么都没发生。
//!
//! 🔴 **丢了行要认。** 客户端只留 [`KEEP`] 行；超出的最旧那些被丢掉时，状态
//! 行里要写「已丢弃最旧 N 条」。屏幕上少了东西而不说，比少了东西更糟。
//!
//! ## 和旧面板的一处差别，故意的
//!
//! 旧面板的搜索框收正则，语法错了会亮一个「正则语法错误」。这里只做**纯文本
//! 包含**：wasm 包里没有 `regex`（整个 workspace 都没引这个依赖），而自己手写
//! 一个「像正则」的子集，会让 `.` `*` `[]` 这些字符的含义和操作员的预期悄悄
//! 错开 —— 那比没有正则坏得多。所以框上写的是「包含文本」，不是「正则」。

use edge_core::{Level, Topic, TOPIC_ORDER};
use edge_panel_api::{LogLine, LogsBody};
use leptos::prelude::*;
use thaw::*;

use crate::api::{self, Load};

/// 轮询间隔。和状态页的 10 秒分开：日志要跟得上手上的操作，10 秒太钝。
pub const LOGS_EVERY_MS: u64 = 2_000;

/// 客户端**保留**多少行。
///
/// ⚠️ 和 [`RENDER`] 是两件事，分开是有理由的，原版的注释说得很清楚：
///
/// - 一条保留的行是一个小对象（连推断出来的字段约 250 B），5000 条约 1.2 MB ——
///   这个流的四小时四十五分钟，浏览器根本不会在意的内存。
/// - 一条**画出来**的行是四个 DOM 节点加上排版，那才是让标签页变卡的东西。
///
/// 分开的好处是实的：筛选跑遍全部 5000 条保留行，所以它够得到比这一栏能滚动
/// 的 2000 行**更早**的时间。
const KEEP: usize = 5_000;

/// 实际画出来多少行。超出的部分不画，但状态行里要说清楚少画了多少 ——
/// 屏幕上少了东西而不说，比少了东西更糟。
const RENDER: usize = 2_000;

/// 多久没读到就算「迟了」。两倍轮询间隔——一次丢包不该让屏幕开始喊。
const LATE_MS: f64 = (LOGS_EVERY_MS * 2) as f64;

/// 一行日志加上它被推断出来的那些属性。
#[derive(Clone, Debug, PartialEq)]
pub struct Row {
    pub line: LogLine,
    pub level: Level,
    pub topic: Topic,
    pub beat: bool,
    /// 确凿归属（行里写了 `imei=`）。
    pub imei: Option<String>,
    /// 行里出现的 `/dev/…` 控制口。画在行首。
    ///
    /// 🔴 **端口是会易主的。** 2026-09-04 那次，USB 重新枚举之后
    /// `/dev/cdc-wdm1` 换了一根模组当主人——这条因果的载体就是它。
    /// 模组筛选跟着**模组**走，看不见「同一个插座换了人」；把端口写在行首，
    /// 易主真发生时不用筛也看得见（`… cdc-wdm0 → 509705` 之后跟着
    /// `… cdc-wdm0 → 514820`）。
    ///
    /// ⚠️ **没有**为它做下拉框。查过 500 行真实日志：端口在这个窗口里一次都
    /// 没易主，而且现成的「包含文本」搜 `cdc-wdm1` 就能筛——一个不回答新问题
    /// 的下拉框，只是在本就拥挤的筛选栏上多占一格。`classify` 一直在算这个
    /// 字段，`Row` 以前直接扔掉了。
    pub port: Option<String>,
    /// 行里出现的裸 15 位数字。**是猜的**，所以和 `imei` 分开放，画法也要分开。
    pub bare: Vec<String>,
}

/// 这一栏的全部状态。
#[derive(Clone, Copy)]
pub struct LogState {
    /// 收到的行，最旧在前。
    pub rows: RwSignal<Vec<Row>>,
    /// 暂停时攒着的行。恢复时一次性并进 `rows`。
    pub held: RwSignal<Vec<Row>>,
    /// 服务端游标。带着它去问，既不重发也不漏。
    pub cursor: RwSignal<u64>,
    /// 上一次轮询的结果。⚠️ 不是「有没有日志」，是「有没有读到」。
    pub last: RwSignal<Load<()>>,
    /// 上一次**成功**读到的时刻。
    pub at: RwSignal<Option<f64>>,
    /// 因为超过 [`KEEP`] 而被丢掉的最旧的行数，累计。
    pub dropped: RwSignal<usize>,
    pub paused: RwSignal<bool>,
    /// 三个级别各自开着还是关着。⚠️ 是三个独立信号而不是一个数组信号：Thaw 的
    /// `Checkbox` 收 `Model<bool>`（双向），给不了「读数组第 i 位、写回第 i 位」
    /// 这种投影。
    pub levels: [RwSignal<bool>; 3],
    /// 静音心跳：把那条每 10 秒三条的 `poll … ok` 藏起来。
    pub quiet: RwSignal<bool>,
    pub topic: RwSignal<String>,
    pub imei: RwSignal<String>,
    pub query: RwSignal<String>,
    /// 现在几点，让「几秒前」会走。
    pub now: RwSignal<f64>,
    /// 有没有一次拉取正在路上。防止慢链路上堆起一串重复请求。
    inflight: RwSignal<bool>,
}

impl LogState {
    pub fn new() -> Self {
        Self {
            rows: RwSignal::new(Vec::new()),
            held: RwSignal::new(Vec::new()),
            cursor: RwSignal::new(0),
            last: RwSignal::new(Load::Loading),
            at: RwSignal::new(None),
            dropped: RwSignal::new(0),
            paused: RwSignal::new(false),
            levels: [
                RwSignal::new(true),
                RwSignal::new(true),
                RwSignal::new(true),
            ],
            quiet: RwSignal::new(false),
            topic: RwSignal::new(String::new()),
            imei: RwSignal::new(String::new()),
            query: RwSignal::new(String::new()),
            now: RwSignal::new(crate::status::now_ms()),
            inflight: RwSignal::new(false),
        }
    }
}

fn level_index(level: Level) -> usize {
    match level {
        Level::Err => 0,
        Level::Warn => 1,
        Level::Info => 2,
    }
}

const LEVELS: [Level; 3] = [Level::Err, Level::Warn, Level::Info];

/// 拉一次日志。
pub async fn poll(state: LogState) {
    if state.inflight.get_untracked() {
        return;
    }
    state.inflight.set(true);

    let after = state.cursor.get_untracked();
    let body: Load<LogsBody> = api::get(&format!("/api/logs?after={after}"), "日志").await;

    match body {
        Load::Failed(why) => {
            // ⚠️ 只改「上一次读得怎么样」，**不动已经收到的行**。手上那些行仍然
            // 是真的，只是不新了；把它们清掉等于因为读不到而销毁证据。
            state.last.set(Load::Failed(why));
        }
        Load::Loading => {}
        Load::Ready(body) => {
            state.last.set(Load::Ready(()));
            state.at.set(Some(crate::status::now_ms()));
            state.cursor.set(body.cursor);

            let fresh: Vec<Row> = body
                .lines
                .into_iter()
                .map(|line| {
                    let c = edge_core::classify(&line.text);
                    Row {
                        line,
                        level: c.level,
                        topic: c.topic,
                        beat: c.beat,
                        imei: c.imei,
                        port: c.port,
                        bare: c.bare,
                    }
                })
                .collect();

            if fresh.is_empty() {
                state.inflight.set(false);
                return;
            }

            if state.paused.get_untracked() {
                state.held.update(|held| {
                    held.extend(fresh);
                    trim(held, &state.dropped);
                });
            } else {
                state.rows.update(|rows| {
                    rows.extend(fresh);
                    trim(rows, &state.dropped);
                });
            }
        }
    }
    state.inflight.set(false);
}

/// 砍到 [`KEEP`] 行，并把砍掉多少记进 `dropped` —— 少了东西要认。
fn trim(rows: &mut Vec<Row>, dropped: &RwSignal<usize>) {
    if rows.len() > KEEP {
        let cut = rows.len() - KEEP;
        rows.drain(..cut);
        dropped.update(|n| *n += cut);
    }
}

/// 恢复播放：把暂停期间攒的行并进来。
fn resume(state: LogState) {
    let held = std::mem::take(&mut *state.held.write());
    if !held.is_empty() {
        state.rows.update(|rows| {
            rows.extend(held);
            trim(rows, &state.dropped);
        });
    }
    state.paused.set(false);
}

/// 一行过不过得了当前的筛选。
fn keeps(state: &LogState, row: &Row, query: &str) -> bool {
    if !state.levels[level_index(row.level)].get() {
        return false;
    }
    if state.quiet.get() && row.beat {
        return false;
    }
    let topic = state.topic.get();
    if !topic.is_empty() && topic != topic_key(row.topic) {
        return false;
    }
    let imei = state.imei.get();
    if !imei.is_empty() && row.imei.as_deref() != Some(imei.as_str()) {
        return false;
    }
    if !query.is_empty() && !row.line.text.to_lowercase().contains(query) {
        return false;
    }
    true
}

fn topic_key(t: Topic) -> &'static str {
    match t {
        Topic::Poll => "poll",
        Topic::Report => "report",
        Topic::Sms => "sms",
        Topic::Uplink => "uplink",
        Topic::Usb => "usb",
        Topic::Restart => "restart",
        Topic::At => "at",
        Topic::Modem => "modem",
        Topic::Panel => "panel",
        Topic::Proxy => "proxy",
        Topic::Command => "command",
        Topic::Other => "other",
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
pub fn LogsPage(state: LogState) -> impl IntoView {
    let counts = Memo::new(move |_| {
        let rows = state.rows.get();
        let mut n = [0usize; 3];
        for row in rows.iter() {
            n[level_index(row.level)] += 1;
        }
        n
    });

    // 筛选跑遍**全部**保留的行，不只是画出来的那些。
    let shown = Memo::new(move |_| {
        let query = state.query.get().trim().to_lowercase();
        state
            .rows
            .get()
            .iter()
            .filter(|row| keeps(&state, row, &query))
            .cloned()
            .collect::<Vec<_>>()
    });

    // 只画最新的 RENDER 行。⚠️ 少画的那些要在状态行里认。
    let drawn = Memo::new(move |_| {
        let rows = shown.get();
        let from = rows.len().saturating_sub(RENDER);
        rows[from..].to_vec()
    });

    // 有哪些模组在已收到的行里出现过——下拉框只列真出现过的，不列一堆空选项。
    let imeis = Memo::new(move |_| {
        let mut seen: Vec<String> = state
            .rows
            .get()
            .iter()
            .filter_map(|row| row.imei.clone())
            .collect();
        seen.sort();
        seen.dedup();
        seen
    });

    view! {
                        <div class="vd-actions">
    <Freshness state=state />
                    </div>


                // ⚠️ 这句话不能省。屏幕上「错 0 条」很容易被当成 daemon 的结论，
                // 而它其实是这段 wasm 读着行文猜的。
                <Caption1>
                    "级别 / 话题 / 模组都是从行文推断的，不是服务端标的 —— /api/logs 只给时间和文本。"
                </Caption1>

                // ⚠️ Thaw 0.4.8 的 `Flex` 没有 wrap 这个 prop，而这一排在窄屏上必须能折行。
                    // 一行内联样式，不进样式表，也不动那块中央覆写。
                    <Flex gap=FlexGap::Small align=FlexAlign::Center style="flex-wrap: wrap;">
                    {LEVELS
                        .iter()
                        .enumerate()
                        .map(|(i, level)| {
                            let level = *level;
                            view! {
                                // ⚠️ `label` 必须是个 `Signal`，不能是 `format!` 出来的
                                // `String`：后者在建视图时求一次值，计数会永远停在 0 —— 而
                                // 屏幕上「错 0」看着像个结论,不像个没在更新的数。
                                <Checkbox
                                    checked=state.levels[i]
                                    label=Signal::derive(move || {
                                        format!("{} {}", level.label(), counts.get()[i])
                                    })
                                />
                            }
                        })
                        .collect_view()}

                    <Checkbox
                        checked=state.quiet
                        label="静音心跳"
                    />

                    <Select value=state.topic>
                        <option value="">"全部话题"</option>
                        {TOPIC_ORDER
                            .iter()
                            .map(|t| {
                                view! { <option value=topic_key(*t)>{t.label()}</option> }
                            })
                            .collect_view()}
                    </Select>

                    <Select value=state.imei>
                        <option value="">"全部模组"</option>
                        {move || {
                            imeis
                                .get()
                                .into_iter()
                                .map(|imei| { let shown = imei.clone(); view! { <option value=imei>{shown}</option> } })
                                .collect_view()
                        }}
                    </Select>

                    // 「包含文本」而不是「正则」：见模块开头。写着什么就做什么。
                    <Input value=state.query placeholder="包含文本" />

                    {move || {
                        if state.paused.get() {
                            let held = state.held.get().len();
                            view! {
                                <Button
                                    appearance=ButtonAppearance::Primary
                                    on_click=move |_| resume(state)
                                >
                                    {format!("继续（缓冲 {held} 条）")}
                                </Button>
                            }
                                .into_any()
                        } else {
                            view! {
                                <Button on_click=move |_| state.paused.set(true)>"暂停"</Button>
                            }
                                .into_any()
                        }
                    }}
                </Flex>

                <Tally state=state shown=shown />

                {move || {
                    let rows = drawn.get();
                    if rows.is_empty() {
                        let total = state.rows.get().len();
                        let say = if total == 0 {
                            // ⚠️ 「还没有行」和「读不到」是两回事，后者由 Freshness 说。
                            "还没有收到日志行。"
                        } else {
                            "当前筛选下没有行 —— 收到的行还在，只是被筛掉了。"
                        };
                        view! { <Caption1>{say}</Caption1> }.into_any()
                    } else {
                        view! {
                            // 🔴 不用表格。日志栏只有 26rem 宽，四列表格会把「轮询」
                            // 折成两行、把行文截掉——而行文是这一栏唯一真正要读的东西。
                            //
                            // 改成两行一条：短的元信息一行，行文独占一行；级别再用
                            // 左边一条色带标一次，好让人竖着扫过去只找红的。
                            <div class="vd-log">
                                {rows
                                    .into_iter()
                                    .rev()
                                    .map(|row| {
                                        let tone = match row.level {
                                            Level::Err => BadgeColor::Danger,
                                            Level::Warn => BadgeColor::Warning,
                                            Level::Info => BadgeColor::Informative,
                                        };
                                        let cls = match row.level {
                                            Level::Err => "vd-log-row vd-log-row--err",
                                            Level::Warn => "vd-log-row vd-log-row--warn",
                                            Level::Info => "vd-log-row",
                                        };
                                        view! {
                                            <div class=cls>
                                                <div class="vd-log-meta">
                                                    <span class="vd-log-at">
                                                        {hhmmss(row.line.at as f64)}
                                                    </span>
                                                    <Badge color=tone size=BadgeSize::Small>
                                                        {row.level.label()}
                                                    </Badge>
                                                    <span class="vd-faint">{row.topic.label()}</span>
                                                    // 控制口。见 `Row::port`：
                                                    // 同一个插座换主人是看得见的因果。
                                                    {row
                                                        .port
                                                        .clone()
                                                        .map(|p| {
                                                            view! {
                                                                <span class="vd-log-port">{p}</span>
                                                            }
                                                        })}
                                                </div>
                                                <div class="vd-log-text">{row.line.text.clone()}</div>
                                            </div>
                                        }
                                    })
                                    .collect_view()}
                            </div>
                        }
                            .into_any()
                    }
                }}

        }
}

/// 「上一次读得怎么样」。⚠️ 这一格从不声称自己是新的。
#[component]
fn Freshness(state: LogState) -> impl IntoView {
    move || {
        let now = state.now.get();
        let at = state.at.get();
        match state.last.get() {
            Load::Loading if at.is_none() => view! {
                <Badge color=BadgeColor::Informative>"正在读日志…"</Badge>
            }
            .into_any(),
            Load::Failed(why) => {
                let since = at
                    .map(|at| format!("，最后一次读到是 {}", hhmmss(at)))
                    .unwrap_or_default();
                // ⚠️ 不再加「上次没读到：」前缀 —— `api` 层给的 `why` 已经以
                // 「日志：」开头（那是它的约定：错误信息被复制走之后仍要说得清
                // 是什么失败了）。两个前缀叠起来是「上次没读到：日志：连不上」。
                // 红色本身就在说「没读到」。
                view! {
                    <Badge color=BadgeColor::Danger>{format!("{why}{since}")}</Badge>
                }
                .into_any()
            }
            _ => {
                let at = at.unwrap_or(now);
                let late = now - at > LATE_MS;
                let text = format!("刷新于 {}", hhmmss(at));
                if late {
                    // 迟了就说迟了。间隔到了却没有新的一次成功，屏幕上不能还是绿的。
                    view! { <Badge color=BadgeColor::Warning>{text}</Badge> }.into_any()
                } else {
                    view! { <Badge color=BadgeColor::Success>{text}</Badge> }.into_any()
                }
            }
        }
    }
}

/// 计数行：显示多少、留了多少、丢了多少、筛掉多少。
#[component]
fn Tally(state: LogState, shown: Memo<Vec<Row>>) -> impl IntoView {
    move || {
        let kept = state.rows.get().len();
        let visible = shown.get().len();
        let dropped = state.dropped.get();
        let hidden = kept - visible;
        let oldest = state.rows.get().first().map(|row| row.line.at as f64);
        view! {
            <Flex gap=FlexGap::Small style="flex-wrap: wrap;">
                <Caption1>{format!("显示 {visible} / 保留 {kept}（上限 {KEEP}）")}</Caption1>
                {oldest
                    .map(|at| view! { <Caption1>{format!("自 {}", hhmmss(at))}</Caption1> })}
                {(hidden > 0)
                    .then(|| {
                        view! { <Caption1>{format!("筛掉 {hidden} 条")}</Caption1> }
                    })}
                // ⚠️ 画不下的那些也要认。筛选仍然覆盖全部保留的行 —— 少的只是
                // 画出来的部分，不是被搜索的部分。
                {(visible > RENDER)
                    .then(|| {
                        view! {
                            <Caption1>
                                {format!(
                                    "只画了最新的 {RENDER} 行，另有 {} 行没画（筛选仍覆盖全部 {} 行）",
                                    visible - RENDER,
                                    kept,
                                )}
                            </Caption1>
                        }
                    })}
                // 少了东西要认，而且要显眼。
                {(dropped > 0)
                    .then(|| {
                        view! {
                            <Badge color=BadgeColor::Warning size=BadgeSize::Small>
                                {format!("已丢弃最旧 {dropped} 条")}
                            </Badge>
                        }
                    })}
            </Flex>
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(text: &str, seq: u64) -> Row {
        let c = edge_core::classify(text);
        Row {
            line: LogLine {
                seq,
                at: 0,
                text: text.to_string(),
            },
            level: c.level,
            topic: c.topic,
            beat: c.beat,
            imei: c.imei,
            port: c.port,
            bare: c.bare,
        }
    }

    /// 🔴 `classify` 算好的两个字段，`Row` 以前直接扔掉。
    ///
    /// `port` 是「同一个插座换主人」这条因果的载体：2026-09-04 USB 重新枚举
    /// 之后 `/dev/cdc-wdm1` 换了一根模组当主人。模组筛选跟着**模组**走，
    /// 看不见这件事。
    #[test]
    fn a_row_carries_the_port_that_classify_already_worked_out() {
        let r = row("poll /dev/cdc-wdm1 imei=862547055142811 ok", 1);
        assert_eq!(r.port.as_deref(), Some("/dev/cdc-wdm1"));
        assert_eq!(r.imei.as_deref(), Some("862547055142811"));

        // 没有端口的行不许编一个出来。
        let r = row("poll imei=867018069509705 absent from both enumerations", 2);
        assert_eq!(r.port, None, "这一行确实没有 /dev/ 路径");
        assert_eq!(r.imei.as_deref(), Some("867018069509705"));
    }

    /// ⚠️ 猜出来的归属和确凿的归属分开存，因为屏幕上也要分开画。
    #[test]
    fn a_guessed_imei_never_lands_in_the_confirmed_field() {
        let r = row("uplink queued for 862547055142811 retry=2", 3);
        assert_eq!(r.imei, None, "行里没写 imei=，就不算确凿归属");
        assert!(
            r.bare.contains(&"862547055142811".to_string()),
            "但裸号要收进 bare，画法和确凿的分开"
        );
    }

    /// 环满时丢的是**最旧**的，而且丢了多少要记下来。
    ///
    /// 屏幕上少了东西而不说，比少了东西更糟。
    #[test]
    fn trimming_drops_the_oldest_and_admits_how_many() {
        let dropped = RwSignal::new(0usize);
        let mut rows: Vec<Row> = (0..KEEP as u64 + 5).map(|i| row("poll: x", i)).collect();
        trim(&mut rows, &dropped);
        assert_eq!(rows.len(), KEEP);
        assert_eq!(dropped.get_untracked(), 5, "丢了 5 条就要认 5 条");
        assert_eq!(rows[0].line.seq, 5, "留下的是新的那一头");

        // 再砍一次，计数是累加的。
        rows.extend((0..3).map(|i| row("poll: x", 9000 + i)));
        trim(&mut rows, &dropped);
        assert_eq!(dropped.get_untracked(), 8, "计数要累加，不是覆盖");
    }

    /// 没超过上限时一条都不该丢。
    #[test]
    fn a_short_column_loses_nothing() {
        let dropped = RwSignal::new(0usize);
        let mut rows: Vec<Row> = (0..10).map(|i| row("poll: x", i)).collect();
        trim(&mut rows, &dropped);
        assert_eq!(rows.len(), 10);
        assert_eq!(dropped.get_untracked(), 0);
    }

    /// 服务端那个环的容量。⚠️ 和 `edge-panel/src/logs.rs` 的 `CAPACITY` 是
    /// 同一个数，写在两处——两个 crate 之间没有牵一条编译期的线（`edge-ui`
    /// 编译到 wasm，不依赖服务端那个 crate）。这里的存在意义只是把「客户端
    /// 必须比服务端环留得更久」这条要求钉在一处，改 `CAPACITY` 的时候要记得
    /// 回来改这个数。
    const SERVER_RING_CAPACITY: usize = 500;

    /// 🔴 客户端保留必须比服务端那个环留得更久，否则一旦标签页开着的时间
    /// 超过服务端环能覆盖的窗口，服务端那份 500 行的记录就是**唯一**还在的
    /// 记录——而它比这个面板自己的缓冲区短。
    #[test]
    fn the_client_keeps_more_than_the_servers_own_ring() {
        assert!(
            KEEP > SERVER_RING_CAPACITY,
            "客户端保留 {KEEP} 行，服务端环 {SERVER_RING_CAPACITY} 行——\
             客户端应该留得比服务端更久，不能更短"
        );
    }

    /// 🔴 保留和绘制是两个数，而且保留的那个要更大。
    ///
    /// 分开的好处是实的：筛选跑遍全部保留行，所以它够得到比这一栏能滚动的范围
    /// 更早的时间。两个数并成一个，就等于把搜索的射程砍到和滚动条一样长。
    #[test]
    fn what_is_kept_reaches_further_back_than_what_is_drawn() {
        assert!(
            KEEP > RENDER,
            "保留 {KEEP} 不比绘制 {RENDER} 多，那分开就没有意义了"
        );
        assert_eq!(KEEP, 5_000, "和原版一致");
        assert_eq!(RENDER, 2_000, "和原版一致");
    }
}
