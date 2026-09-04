//! 体检：向一根模组下发一批**只读** AT 查询，然后回答三个问题。
//!
//! 🔴 **这一页的价值不在那张事实网格，在网格上面那三句判词。** 十行等重的
//! 数据会让操作员自己去找那三行要紧的；说出「哪个问题被这一行回答了」才是区别。
//! 原版注释写着同样的话，搬迁时不要把判词当成装饰砍掉。
//!
//! ## 四态，不是三态
//!
//! ⚠️ 这一页和状态页不同：它是**可以重跑的**。所以「这次失败了、但手上还有上次
//! 的结果」是一种真实且必须画得出来的状态——原版在这里退化得最厉害：
//!
//! - 加载中：没有任何响应式字段，`busy()` 直接改 DOM 上按钮的文字
//! - 失败：`report` 保持 `null`，于是画出「还没有体检结果」的空态，失败原因只
//!   出现在**另一个标签页**的控制台转录里
//! - 重跑失败：上一次的结果和它的旧时间戳原样留在屏幕上，没有任何标记
//!
//! 第三条最坏：屏幕上是一份看起来正常、实际上是十分钟前的体检。

use edge_panel_api::ReportResult;
use leptos::prelude::*;
use thaw::*;

use crate::api::{self, Load};

/// 体检的四种画面。
#[derive(Clone, Debug)]
pub enum Health {
    /// 还没跑过。
    Idle,
    /// 在跑。⚠️ 如果手上有旧结果，它仍然画着——但要标出「正在重读」。
    Running { stale: Option<(ReportResult, f64)> },
    /// 读到了。`f64` 是读到的时刻，不是渲染的时刻。
    Done { report: ReportResult, at: f64 },
    /// 没读到。🔴 `stale` 让「失败」和「失败但手上还有旧数据」分得开。
    Failed {
        why: String,
        stale: Option<(ReportResult, f64)>,
    },
}

impl Health {
    /// 手上现有的结果，不管它是新读的还是上一次留下的。
    fn held(&self) -> Option<(&ReportResult, f64)> {
        match self {
            Health::Done { report, at } => Some((report, *at)),
            Health::Running {
                stale: Some((r, at)),
            }
            | Health::Failed {
                stale: Some((r, at)),
                ..
            } => Some((r, *at)),
            _ => None,
        }
    }
}

fn reg_label(value: &str) -> &str {
    match value {
        "home" => "已注册(本网)",
        "roaming" => "已注册(漫游)",
        "searching" => "搜网中",
        "denied" => "被拒绝",
        "not_registered" => "未注册",
        "unknown" => "未知",
        other => other,
    }
}

fn registered(value: Option<&str>) -> bool {
    matches!(value, Some("home") | Some("roaming"))
}

/// 一句判词。
struct Verdict {
    key: &'static str,
    tone: MessageBarIntent,
    say: String,
}

/// 三句固定的判词，外加一句只在命中封禁表时出现的。
///
/// ⚠️ CS 与 PS **分开说**是刻意的：一根模组可以只挂上数据域而没有电路域，
/// 而那正是短信会安静地失败的状态。
fn verdicts(r: &ReportResult) -> Vec<Verdict> {
    verdicts_in(r, edge_core::sms_blocks())
}

/// 同一套判词，但封禁表由调用方给。
///
/// 🔴 生产表在 2026-09-04 之后是空的。测试用 `edge_core::SAMPLE_BLOCKS` 跑，
/// 这样「封禁的模组要在体检页自己说话」这条路不会跟着表一起变成空测试。
fn verdicts_in(
    r: &ReportResult,
    blocks: &'static [(&'static str, edge_core::SmsBlock)],
) -> Vec<Verdict> {
    let cs = r.cs_registration.as_deref();
    let ps = r.ps_registration.as_deref();
    let mut said = Vec::new();

    said.push(match (registered(cs), registered(ps)) {
        (true, true) => Verdict {
            key: "注册",
            tone: MessageBarIntent::Success,
            say: "CS 与 PS 都已注册 —— 短信与数据都有路。".into(),
        },
        (false, true) => Verdict {
            key: "注册",
            tone: MessageBarIntent::Warning,
            say: "只注册了 PS：数据可用，而 CS 域不在 —— 短信会安静地失败。".into(),
        },
        (true, false) => Verdict {
            key: "注册",
            tone: MessageBarIntent::Warning,
            say: "只注册了 CS：短信有路，数据没有。".into(),
        },
        (false, false) if cs.is_some() || ps.is_some() => Verdict {
            key: "注册",
            tone: MessageBarIntent::Error,
            say: format!(
                "两个域都没有注册（CS {} / PS {}）。",
                cs.map(reg_label).unwrap_or("—"),
                ps.map(reg_label).unwrap_or("—")
            ),
        },
        _ => Verdict {
            key: "注册",
            tone: MessageBarIntent::Info,
            say: "模组没有给出注册状态。".into(),
        },
    });

    // 阈值原样照搬：-85 以上好，-100 以上够用，再往下收发都不稳。
    said.push(match r.signal_dbm {
        None => Verdict {
            key: "信号",
            tone: MessageBarIntent::Info,
            say: "没有读到信号。".into(),
        },
        Some(dbm) if dbm > -85 => Verdict {
            key: "信号",
            tone: MessageBarIntent::Success,
            say: format!("{dbm} dBm —— 好。"),
        },
        Some(dbm) if dbm > -100 => Verdict {
            key: "信号",
            tone: MessageBarIntent::Warning,
            say: format!("{dbm} dBm —— 够用，但边缘。"),
        },
        Some(dbm) => Verdict {
            key: "信号",
            tone: MessageBarIntent::Error,
            say: format!("{dbm} dBm —— 太弱，收发都会不稳。"),
        },
    });

    said.push(match r.sms_centre.as_deref() {
        Some(centre) => Verdict {
            key: "短信",
            tone: MessageBarIntent::Success,
            say: format!("短信中心 {centre}。"),
        },
        None => Verdict {
            key: "短信",
            tone: MessageBarIntent::Error,
            say: "卡上没有短信中心号码 —— 发出去的短信会被丢掉。".into(),
        },
    });

    // 🔴 这一条不是关于这次读取的：这根模组的 MO 通路已知会让模组离开总线，
    // 而体检页正是发短信之前有人会看的地方。表在 `edge-core`，不在这里——
    // 它是一条实测出来的硬件事实，不是这块 UI 的意见。
    if let Some(imei) = r.imei.as_deref() {
        if let Some(block) = edge_core::sms_block_in(blocks, imei) {
            said.push(Verdict {
                key: "MO 短信",
                tone: MessageBarIntent::Error,
                say: format!("面板禁止从这一根发短信 —— {}", block.why),
            });
        }
    }
    said
}

/// 一行事实。`tone` 决定它是好、是坏，还是「模组没给」。
struct Fact {
    group: &'static str,
    label: &'static str,
    value: Option<String>,
    good: Option<bool>,
}

/// 事实网格。⚠️ 顺序即屏幕顺序，分组顺序是「网络 → 卡 → 设备」。
fn facts(r: &ReportResult) -> Vec<Fact> {
    let signal = r.signal_dbm.map(|dbm| match r.signal_index {
        Some(idx) => format!("{dbm} dBm (CSQ {idx})"),
        None => format!("{dbm} dBm"),
    });
    // 旧面板这一格是**三档**：> -85 上绿徽章、-85..-100 不上徽章、≤ -100 上红。
    // 中间那一档是故意不上色的 —— -93 dBm 能用，只是边缘；染成红的会让人以为
    // 这一根已经断了，然后去拔它。「够用，但边缘」这句话由判词去说，事实网格
    // 只负责不撒谎。
    let signal_good = r.signal_dbm.and_then(|dbm| {
        if dbm > -85 {
            Some(true)
        } else if dbm > -100 {
            None
        } else {
            Some(false)
        }
    });
    vec![
        Fact {
            group: "网络",
            label: "信号",
            value: signal,
            good: signal_good,
        },
        Fact {
            group: "网络",
            label: "注册 CS",
            value: r
                .cs_registration
                .as_deref()
                .map(|v| reg_label(v).to_string()),
            good: r.cs_registration.as_deref().map(|v| registered(Some(v))),
        },
        Fact {
            group: "网络",
            label: "注册 PS",
            value: r
                .ps_registration
                .as_deref()
                .map(|v| reg_label(v).to_string()),
            good: r.ps_registration.as_deref().map(|v| registered(Some(v))),
        },
        Fact {
            group: "网络",
            label: "运营商",
            value: r.operator.clone(),
            good: None,
        },
        Fact {
            group: "网络",
            label: "接入制式",
            value: r.access_technology.clone(),
            good: None,
        },
        Fact {
            group: "卡",
            label: "ICCID",
            value: r.iccid.clone(),
            good: None,
        },
        Fact {
            group: "卡",
            label: "IMSI",
            value: r.imsi.clone(),
            good: None,
        },
        Fact {
            group: "卡",
            label: "本机号",
            value: r.msisdn.clone(),
            good: None,
        },
        Fact {
            group: "卡",
            label: "短信中心",
            value: r.sms_centre.clone(),
            good: Some(r.sms_centre.is_some()),
        },
        Fact {
            group: "设备",
            label: "固件",
            value: r.firmware.clone(),
            good: None,
        },
    ]
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
fn FactGrid(report: ReportResult) -> impl IntoView {
    let rows = facts(&report);
    let groups = ["网络", "卡", "设备"];
    view! {
        {groups
            .into_iter()
            .map(|group| {
                let items: Vec<_> = rows
                    .iter()
                    .filter(|f| f.group == group)
                    .map(|f| {
                        let shown = f.value.clone().unwrap_or_else(|| "模组没给".into());
                        let absent = f.value.is_none();
                        (f.label, shown, absent, f.good)
                    })
                    .collect();
                view! {
                    <Caption1Strong>{group}</Caption1Strong>
                    <Table>
                        <TableBody>
                            {items
                                .into_iter()
                                .map(|(label, shown, absent, good)| view! {
                                    <TableRow>
                                        <TableCell>{label}</TableCell>
                                        <TableCell>
                                            {if absent {
                                                view! { <Caption1>{shown}</Caption1> }.into_any()
                                            } else {
                                                match good {
                                                    Some(true) => view! {
                                                        <Badge color=BadgeColor::Success>{shown}</Badge>
                                                    }.into_any(),
                                                    Some(false) => view! {
                                                        <Badge color=BadgeColor::Danger>{shown}</Badge>
                                                    }.into_any(),
                                                    None => view! { <Text>{shown}</Text> }.into_any(),
                                                }
                                            }}
                                        </TableCell>
                                    </TableRow>
                                })
                                .collect_view()}
                        </TableBody>
                    </Table>
                }
            })
            .collect_view()}
    }
}

#[component]
pub fn HealthPage(active: RwSignal<Option<String>>, state: RwSignal<Health>) -> impl IntoView {
    let run = move |_| {
        let Some(imei) = active.get_untracked() else {
            return;
        };
        // 重跑时把手上的结果带进 Running，这样屏幕不会先空一下再填回来。
        let stale = state.get_untracked().held().map(|(r, at)| (r.clone(), at));
        state.set(Health::Running {
            stale: stale.clone(),
        });
        leptos::task::spawn_local(async move {
            let body = edge_panel_api::ResetBody { imei: Some(imei) };
            let result: Load<ReportResult> = api::post("/api/report", &body, "体检").await;
            state.set(match result {
                Load::Ready(report) => Health::Done {
                    report,
                    at: js_sys::Date::now(),
                },
                Load::Failed(why) => Health::Failed { why, stale },
                Load::Loading => Health::Running { stale },
            });
        });
    };

    view! {
                        <div class="vd-actions">
    <Button
                            appearance=ButtonAppearance::Primary
                            disabled=Signal::derive(move || {
                                active.get().is_none() || matches!(state.get(), Health::Running { .. })
                            })
                            on_click=run
                        >
                            {move || match state.get() {
                                Health::Running { .. } => "读取中…",
                                Health::Idle => "体检",
                                _ => "重新体检",
                            }}
                        </Button>
                    </div>


                {move || match state.get() {
                    Health::Idle => view! {
                        <Text>
                            {move || if active.get().is_none() {
                                "先在左边选一根模组。"
                            } else {
                                "还没有体检结果。体检只下发只读查询，不改模组任何状态。"
                            }}
                        </Text>
                    }.into_any(),

                    // 🔴 失败画在**这一页上**，带原因；如果手上还有旧结果，它继续画着，
                    //    但明确标出是哪一次的——原版在这里什么都不说。
                    Health::Failed { why, stale } => view! {
                        <MessageBar intent=MessageBarIntent::Error layout=MessageBarLayout::Multiline>
                            <MessageBarBody>
                                <MessageBarTitle>"这次没读到"</MessageBarTitle>
                                {why}
                            </MessageBarBody>
                        </MessageBar>
                        {stale.map(|(report, at)| view! {
                            <MessageBar intent=MessageBarIntent::Warning layout=MessageBarLayout::Multiline>
                                <MessageBarBody>
                                    {format!("下面是上一次的结果，读于 {}，不是刚才那次。", hhmmss(at))}
                                </MessageBarBody>
                            </MessageBar>
                            <Verdicts report=report.clone() />
                            <FactGrid report=report />
                        })}
                    }.into_any(),

                    Health::Running { stale } => view! {
                        <Spinner label="正在读取…" />
                        {stale.map(|(report, at)| view! {
                            <Caption1>{format!("下面还是上一次的结果，读于 {}。", hhmmss(at))}</Caption1>
                            <Verdicts report=report.clone() />
                            <FactGrid report=report />
                        })}
                    }.into_any(),

                    Health::Done { report, at } => view! {
                        // ⚠️ 时间戳是承重的：信号和注册会在面板底下变，没有它，
                        //    十分钟前的网格和刚读的长得一模一样。
                        <Caption1>{format!("读于 {}", hhmmss(at))}</Caption1>
                        <Verdicts report=report.clone() />
                        <FactGrid report=report />
                    }.into_any(),
                }}

        }
}

#[component]
fn Verdicts(report: ReportResult) -> impl IntoView {
    let said = verdicts(&report);
    let refused = report.refused.clone();
    view! {
        {said
            .into_iter()
            .map(|v| view! {
                // Thaw 的 MessageBar 默认是 singleline（`white-space: nowrap`），
                // 一句长判词会被裁掉右半边——而恰恰是长的那句最要紧：解释「为什么
                // 从这根发短信会把模组打下总线」的那一整段。Multiline 是 Thaw 自带
                // 的版式，不用另写 CSS。
                <MessageBar intent=v.tone layout=MessageBarLayout::Multiline>
                    <MessageBarBody>
                        <MessageBarTitle>{v.key}</MessageBarTitle>
                        {v.say}
                    </MessageBarBody>
                </MessageBar>
            })
            .collect_view()}
        {(!refused.is_empty())
            .then(|| view! {
                // 被拒绝的命令要说出来：一个空字段和一个模组拒绝回答的字段，
                // 是两回事。
                <Caption1>{format!("模组拒绝了这些查询：{}", refused.join("、"))}</Caption1>
            })}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `MessageBarIntent` 没有 `PartialEq`，所以测试自己把它压成一个名字。
    fn tone(t: &MessageBarIntent) -> &'static str {
        match t {
            MessageBarIntent::Success => "ok",
            MessageBarIntent::Warning => "warn",
            MessageBarIntent::Error => "bad",
            MessageBarIntent::Info => "idle",
        }
    }

    fn report() -> ReportResult {
        ReportResult {
            imei: Some("860000000000001".into()),
            port: "/dev/cdc-wdm0".into(),
            signal_dbm: None,
            signal_index: None,
            cs_registration: Some("home".into()),
            ps_registration: Some("home".into()),
            operator: Some("CHINA MOBILE".into()),
            access_technology: Some("LTE".into()),
            imsi: None,
            iccid: None,
            msisdn: None,
            firmware: None,
            sms_centre: Some("+8613800100500".into()),
            refused: Vec::new(),
        }
    }

    fn signal_fact(dbm: i16) -> Fact {
        let mut r = report();
        r.signal_dbm = Some(dbm);
        facts(&r)
            .into_iter()
            .find(|f| f.label == "信号")
            .expect("事实网格里必须有信号这一行")
    }

    /// 信号徽章是**三档**，中间那档故意不上色。
    ///
    /// 移植的时候我把它压成了两档（`dbm > -85`），-93 dBm 就被染成了红的 ——
    /// 那是在告诉操作员「这根断了」，而它其实能用。这条测试守住中间那一档。
    #[test]
    fn a_workable_but_edgy_signal_wears_no_badge() {
        assert_eq!(signal_fact(-70).good, Some(true), "-70 dBm 是好信号");
        assert_eq!(signal_fact(-93).good, None, "-93 dBm 能用，不该染红");
        assert_eq!(signal_fact(-99).good, None, "-99 dBm 仍在中间那一档");
        assert_eq!(signal_fact(-105).good, Some(false), "-105 dBm 是坏信号");
    }

    /// 边界本身：`> -85` 和 `> -100`，不是 `>=`。
    #[test]
    fn the_signal_thresholds_sit_where_the_old_panel_put_them() {
        assert_eq!(
            signal_fact(-85).good,
            None,
            "-85 不算好，旧面板用的是 > -85"
        );
        assert_eq!(signal_fact(-84).good, Some(true));
        assert_eq!(signal_fact(-100).good, Some(false), "-100 不算中间档");
    }

    /// 封禁表里的那一根，在发短信之前必须自己说话。
    #[test]
    fn a_blocked_modem_says_so_on_the_health_page() {
        let mut r = report();
        r.imei = Some(edge_core::SAMPLE_BLOCKS[0].0.to_string());
        let said = verdicts_in(&r, edge_core::SAMPLE_BLOCKS);
        let block = said
            .iter()
            .find(|v| v.key == "MO 短信")
            .expect("封禁的模组必须出一条 MO 短信判词");
        assert_eq!(tone(&block.tone), "bad");
        assert!(
            block.say.contains("总线") || block.say.contains("QMI"),
            "判词要说清楚为什么，而不是只说「不许」：{}",
            block.say
        );

        let clean = verdicts(&report());
        assert!(
            !clean.iter().any(|v| v.key == "MO 短信"),
            "没被封的模组不该看到这一条"
        );
    }

    /// CS 与 PS 分开看：只注册了 PS 时短信会安静地失败，那句话必须出现。
    #[test]
    fn one_domain_registered_is_not_reported_as_registered() {
        let mut r = report();
        r.cs_registration = Some("unknown".into());
        let said = verdicts(&r);
        let reg = said
            .iter()
            .find(|v| v.key == "注册")
            .expect("必须有注册判词");
        assert_eq!(tone(&reg.tone), "warn", "半边注册不是「好」");
        assert!(reg.say.contains("短信"), "要点出丢的是短信：{}", reg.say);
    }
}
