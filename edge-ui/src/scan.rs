//! 全频段扫网。
//!
//! 🔴 **这一栏最要紧的事，是它在扫的时候要一直说话。** 一次扫描最长三分钟，
//! 期间这一根**不服务**：不注册、不收短信、没有数据，在它上面的通话会断。
//! 三分钟里，一个置灰的按钮和一个卡死的按钮长得一模一样 —— 所以有一条按秒
//! 走的进度条，和一句一直摆在那里的话说明这一根此刻在做什么。
//!
//! ⚠️ 进度条走的是**本地的秒表**，不是模组的进度：模组不会告诉我们它扫到哪
//! 了。所以它标的是「已 N 秒 / 最长 180 秒」，不是「完成了百分之多少」。
//!
//! ## 这张表不是什么
//!
//! 它是**一次扫描的快照**，不是实时的。「当前」是模组当时驻留的网络，「禁止」
//! 来自模组自己的禁止 PLMN 列表 —— 那是这个模组的说法，不是关于这家运营商的
//! 陈述。原版把这两句话写在表下面，照搬。
//!
//! ## 三态
//!
//! 🔴 原版这里是 `this.operators = r.operators || []` —— 扫失败画成「没有扫到
//! 网络」。一次失败的扫描和一片没有信号的地方，在屏幕上看起来一样，而它们要
//! 做的事完全相反。

use edge_panel_api::{ScanResult, ScannedOperatorBody};
use leptos::prelude::*;
use thaw::*;

use crate::api::{self, Load};

/// 一次扫描的上限。⚠️ 和 `edge-bin` 里那个超时是同一个数，写在两处。
///
/// 这里用它只为画进度条和说「最长 N 秒」；真正的超时在代理那边。两边不一致
/// 的后果是屏幕上的秒表跑完了而请求还在，那时进度条会停在满格 —— 下面的
/// `elapsed` 做了 clamp，不会画出超过 100% 的条。
const SCAN_LIMIT_MS: f64 = 180_000.0;

/// 扫网的四态。
#[derive(Clone, Debug, PartialEq)]
pub enum Scan {
    Idle,
    /// 扫描中。`since` 是本地开始的时刻，进度条靠它走。
    Running {
        since: f64,
        stale: Option<(ScanResult, f64)>,
    },
    Done {
        result: ScanResult,
        at: f64,
    },
    /// 🔴 和 `Done { operators: [] }` 是两回事：一个是「没读到」，一个是
    /// 「这里真的一个网都没有」。后者要人换地方，前者要人再试一次。
    Failed {
        why: String,
        stale: Option<(ScanResult, f64)>,
    },
}

#[derive(Clone, Copy)]
pub struct ScanState {
    pub scan: RwSignal<Scan>,
    /// 每秒一跳，进度条和「已 N 秒」靠它。
    pub now: RwSignal<f64>,
}

impl ScanState {
    pub fn new() -> Self {
        Self {
            scan: RwSignal::new(Scan::Idle),
            now: RwSignal::new(crate::status::now_ms()),
        }
    }
}

fn status_label(status: &str) -> &str {
    match status {
        "current" => "当前",
        "available" => "可用",
        "forbidden" => "禁止",
        other => other,
    }
}

fn status_tone(status: &str) -> BadgeColor {
    match status {
        "current" => BadgeColor::Success,
        "forbidden" => BadgeColor::Danger,
        _ => BadgeColor::Informative,
    }
}

/// 运营商的显示名：长名优先，没有就用短名，都没有就用 MCC/MNC。
///
/// ⚠️ 原版是 `op.long_name || op.short_name`，两个都空的时候这一格是空的 ——
/// 一行没有名字的运营商比一行写着号码的运营商难认得多。
fn operator_name(op: &ScannedOperatorBody) -> String {
    if !op.long_name.is_empty() {
        op.long_name.clone()
    } else if !op.short_name.is_empty() {
        op.short_name.clone()
    } else {
        op.numeric.clone()
    }
}

fn ask(imei: &str) -> String {
    format!(
        "全频段扫网\n\n\
         目标：{imei}\n\
         动作：/api/scan → AT+COPS=?，最长 {} 秒\n\n\
         扫描期间这一根不服务：不注册、不收短信、没有数据，\n\
         在它上面的通话会断。机队里它会显示为「忙」，不是离线。\n\n\
         扫完它自己回来，不需要任何补救动作 —— 这一条和命令框里那些\n\
         要先问一次的命令不同，它没有走不回来的那一半。\n\n\
         确定要扫吗？",
        (SCAN_LIMIT_MS / 1000.0).round() as u64
    )
}

fn confirmed(message: &str) -> bool {
    web_sys::window()
        .and_then(|w| w.confirm_with_message(message).ok())
        .unwrap_or(false)
}

/// 把当前手上的结果取出来，供 `Running` / `Failed` 带着走。
fn stale_of(scan: &Scan) -> Option<(ScanResult, f64)> {
    match scan {
        Scan::Done { result, at } => Some((result.clone(), *at)),
        Scan::Running { stale, .. } | Scan::Failed { stale, .. } => stale.clone(),
        Scan::Idle => None,
    }
}

async fn run(state: ScanState, imei: String) {
    let stale = stale_of(&state.scan.get_untracked());
    state.scan.set(Scan::Running {
        since: crate::status::now_ms(),
        stale: stale.clone(),
    });

    let body = serde_json::json!({ "imei": imei });
    let got: Load<ScanResult> = api::post("/api/scan", &body, "扫网").await;
    match got {
        Load::Ready(result) => state.scan.set(Scan::Done {
            result,
            at: crate::status::now_ms(),
        }),
        Load::Failed(why) => state.scan.set(Scan::Failed { why, stale }),
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
pub fn ScanPage(active: RwSignal<Option<String>>, state: ScanState) -> impl IntoView {
    let running = Memo::new(move |_| matches!(state.scan.get(), Scan::Running { .. }));

    view! {
        <Card>
            <CardHeader>
                <Body1><b>"扫网"</b></Body1>
                <CardHeaderAction slot>
                    <Button
                        appearance=ButtonAppearance::Primary
                        disabled=Signal::derive(move || active.get().is_none() || running.get())
                        on_click=move |_| {
                            let Some(imei) = active.get_untracked() else { return };
                            if !confirmed(&ask(&imei)) {
                                return;
                            }
                            leptos::task::spawn_local(async move { run(state, imei).await });
                        }
                    >
                        {move || {
                            if running.get() {
                                "扫描中…"
                            } else if matches!(state.scan.get(), Scan::Idle) {
                                "扫网"
                            } else {
                                "重新扫网"
                            }
                        }}
                    </Button>
                </CardHeaderAction>
            </CardHeader>

            {move || match state.scan.get() {
                Scan::Idle => {
                    let say = if active.get().is_none() {
                        "先在左边选一根模组。"
                    } else {
                        "还没有扫描。全频段扫网期间这一根不服务，最长 180 秒。"
                    };
                    view! { <Caption1>{say}</Caption1> }.into_any()
                }
                Scan::Running { since, stale } => {
                    let elapsed = ((state.now.get() - since) / 1000.0).max(0.0);
                    let limit = SCAN_LIMIT_MS / 1000.0;
                    view! {
                        // ⚠️ 三分钟里必须一直有东西在动，否则「在扫」和「卡死」
                        // 长得一模一样。这条进度条走的是本地秒表。
                        <ProgressBar
                            value=Signal::derive(move || elapsed.min(limit))
                            max=Signal::derive(move || limit)
                            color=ProgressBarColor::Warning
                        />
                        <Caption1>
                            {format!(
                                "扫描中 · 已 {} 秒 / 最长 {} 秒 · 剩 {} 秒",
                                elapsed.round() as u64,
                                limit as u64,
                                (limit - elapsed).max(0.0).round() as u64,
                            )}
                        </Caption1>
                        <MessageBar
                            intent=MessageBarIntent::Warning
                            layout=MessageBarLayout::Multiline
                        >
                            <MessageBarBody>
                                "这一根此刻不服务：不注册、不收短信、没有数据。\
                                 它在机队里会显示为「忙」而不是离线。扫完自己回来，\
                                 不需要任何补救动作。"
                            </MessageBarBody>
                        </MessageBar>
                        {stale
                            .map(|(result, at)| {
                                view! { <Stale result=result at=at note="下面是上一次的结果。" /> }
                            })}
                    }
                        .into_any()
                }
                Scan::Failed { why, stale } => {
                    view! {
                        <MessageBar
                            intent=MessageBarIntent::Error
                            layout=MessageBarLayout::Multiline
                        >
                            <MessageBarBody>
                                <MessageBarTitle>"这次没扫成"</MessageBarTitle>
                                {why}
                            </MessageBarBody>
                        </MessageBar>
                        {stale
                            .map(|(result, at)| {
                                view! {
                                    <Stale
                                        result=result
                                        at=at
                                        note="下面是上一次的结果，不是刚才那次。"
                                    />
                                }
                            })}
                    }
                        .into_any()
                }
                Scan::Done { result, at } => {
                    view! { <Found result=result at=at /> }.into_any()
                }
            }}
        </Card>
    }
}

#[component]
fn Stale(result: ScanResult, at: f64, note: &'static str) -> impl IntoView {
    view! {
        <MessageBar intent=MessageBarIntent::Warning layout=MessageBarLayout::Multiline>
            <MessageBarBody>{format!("{note}扫于 {}。", hhmmss(at))}</MessageBarBody>
        </MessageBar>
        <Operators result=result />
    }
}

#[component]
fn Found(result: ScanResult, at: f64) -> impl IntoView {
    let count = result.operators.len();
    let seconds = (result.elapsed_ms as f64 / 1000.0).round() as u64;
    view! {
        <Caption1>{format!("扫于 {} · 耗时 {seconds} 秒 · {count} 个网络", hhmmss(at))}</Caption1>
        <Operators result=result />
    }
}

#[component]
fn Operators(result: ScanResult) -> impl IntoView {
    if result.operators.is_empty() {
        // ⚠️ 这是真的「一个都没扫到」。扫失败由上面那条红条说，不在这里。
        return view! {
            <Caption1>"没有扫到网络 —— 扫描本身成功了，这里确实没有可用的网。"</Caption1>
        }
        .into_any();
    }
    view! {
        <Table>
            <TableHeader>
                <TableRow>
                    <TableHeaderCell>"运营商"</TableHeaderCell>
                    <TableHeaderCell>"MCC/MNC"</TableHeaderCell>
                    <TableHeaderCell>"制式"</TableHeaderCell>
                    <TableHeaderCell>"状态"</TableHeaderCell>
                </TableRow>
            </TableHeader>
            <TableBody>
                {result
                    .operators
                    .into_iter()
                    .map(|op| {
                        let name = operator_name(&op);
                        let tone = status_tone(&op.status);
                        let label = status_label(&op.status).to_string();
                        view! {
                            <TableRow>
                                <TableCell>{name}</TableCell>
                                <TableCell>{op.numeric}</TableCell>
                                <TableCell>
                                    {op.access_technology.unwrap_or_else(|| "—".into())}
                                </TableCell>
                                <TableCell>
                                    <Badge color=tone size=BadgeSize::Small>{label}</Badge>
                                </TableCell>
                            </TableRow>
                        }
                    })
                    .collect_view()}
            </TableBody>
        </Table>
        // 原版把这两句话写在表下面，照搬：这张表最容易被当成实时的网络状况，
        // 而「禁止」最容易被当成关于运营商的陈述。
        <Caption1>
            "这是一次扫描的快照，不是实时的。「当前」是模组当时驻留的网络，\
             「禁止」来自模组自己的禁止 PLMN 列表。手动锁一个网要用 AT+COPS=1,…。"
        </Caption1>
    }
    .into_any()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(numeric: &str, long: &str, short: &str, status: &str) -> ScannedOperatorBody {
        ScannedOperatorBody {
            numeric: numeric.into(),
            long_name: long.into(),
            short_name: short.into(),
            status: status.into(),
            access_technology: Some("LTE".into()),
        }
    }

    fn result() -> ScanResult {
        ScanResult {
            imei: Some("860000000000001".into()),
            elapsed_ms: 42_000,
            operators: vec![op("46000", "CHINA MOBILE", "CMCC", "current")],
        }
    }

    /// 一行没有名字的运营商比一行写着号码的运营商难认得多。
    #[test]
    fn an_operator_always_has_something_to_call_it_by() {
        assert_eq!(
            operator_name(&op("46000", "CHINA MOBILE", "CMCC", "current")),
            "CHINA MOBILE"
        );
        assert_eq!(
            operator_name(&op("46000", "", "CMCC", "current")),
            "CMCC",
            "长名空了用短名"
        );
        assert_eq!(
            operator_name(&op("46000", "", "", "current")),
            "46000",
            "两个都空就用号码，不能画一个空格子"
        );
    }

    /// 没见过的状态原样显示，不编造标签。
    #[test]
    fn an_unknown_status_is_shown_as_the_module_said_it() {
        assert_eq!(status_label("current"), "当前");
        assert_eq!(status_label("forbidden"), "禁止");
        assert_eq!(status_label("available"), "可用");
        assert_eq!(status_label("unheard-of"), "unheard-of");
    }

    /// 确认框必须说清代价：三分钟不服务，以及扫完自己回来。
    ///
    /// 后半句同样要紧 —— 一个不敢按的操作员和一个乱按的操作员一样糟。
    #[test]
    fn the_dialog_says_both_what_it_costs_and_that_it_comes_back() {
        let text = ask("860000000000001");
        assert!(text.contains("860000000000001"), "要指名是哪一根");
        assert!(text.contains("不服务"), "要说清代价：{text}");
        assert!(text.contains("180 秒"), "要说清多久");
        assert!(text.contains("自己回来"), "也要说清它会回来");
    }

    /// 🔴 失败和「一个网都没扫到」必须分得开，而且失败时旧结果要留着。
    #[test]
    fn a_failed_sweep_keeps_what_the_last_one_found() {
        let done = Scan::Done {
            result: result(),
            at: 1.0,
        };
        let stale = stale_of(&done);
        assert!(stale.is_some(), "手上有结果的时候要能带走");

        let failed = Scan::Failed {
            why: "boom".into(),
            stale: stale.clone(),
        };
        assert!(
            matches!(&failed, Scan::Failed { stale: Some(_), .. }),
            "扫失败不该把上一次的结果一起清掉"
        );
        // 再失败一次，旧结果仍然在。
        assert!(stale_of(&failed).is_some());

        // 空结果**不是**失败：它是一个真的答案。
        let empty = Scan::Done {
            result: ScanResult {
                imei: None,
                elapsed_ms: 1,
                operators: Vec::new(),
            },
            at: 2.0,
        };
        assert!(matches!(empty, Scan::Done { .. }));
    }

    #[test]
    fn nothing_is_stale_before_the_first_sweep() {
        assert!(stale_of(&Scan::Idle).is_none());
    }
}
