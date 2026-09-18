//! 追溯执行在面板上的两种状态。
//!
//! 纯文案推导，不碰 DOM，所以能在本机 `cargo test -p edge-ui` 覆盖完。

use edge_panel_api::{GateFailureBody, RetirementBody};

/// 稳定标签 → 运维看得懂的话。
///
/// ⚠️ 不照抄 `BindRefusal` 的 `Display`。那四句是写给**正要纳管**的人的：
/// 「measure it and record the result before adopting」在一条「它已经被
/// 标记了」的提示里是错误的下一步指引。
fn reason_label(reason: &str) -> &str {
    match reason {
        "no_strategy" => "这个版本没有驱动它的策略",
        // ⚠️ 和上一条分开，因为下一步不同：上一条要改代码或换硬件，
        // 这一条要改**目录**，而目录是数据，改它不用发版。
        "not_in_catalogue" => "受支持设备列表里没有放行它",
        "never_measured" => "这一对（型号 × 运营商）从没被测过",
        "unreadable_usb_identity" => "读不出它的 USB 标识",
        "not_identified_yet" => "还没识别出型号或归属网络",
        other => other,
    }
}

fn minutes(ms: i64) -> i64 {
    (ms.max(0) + 59_999) / 60_000
}

/// 一根被标记的模组，那一行显示什么。
///
/// 🔴 必须说清「仍在管」。运维看到一个刺眼的标记，第一反应是「它已经掉了」；
/// 而实际上它还在被轮询、还在 `managed_imeis` 里，而且默认模式下**永远不会**
/// 被删。把「已经发生的损失」和「还有余地的状态」画成同一个样子，
/// 会让人去做一件不需要做的补救。
pub fn gate_notice(gate: &GateFailureBody, now: i64, enforcing: bool) -> String {
    let elapsed = now.saturating_sub(gate.since).max(0);
    let left_ms = edge_core::GRACE_MS.saturating_sub(elapsed).max(0);
    let left_passes = edge_core::GRACE_PASSES.saturating_sub(gate.passes);
    let head = format!("闸不再满足：{}", reason_label(&gate.reason));
    if !enforcing {
        // 默认模式。倒计时照常显示 —— 它是「这个状态持续了多久」的度量，
        // 但结尾必须说清楚不会自动删，否则运维会等一个永远不来的动作。
        return format!("{head} · 仍在管 · 已持续 {} 分钟 · 本机只标记不自动解绑", minutes(elapsed));
    }
    if left_ms == 0 && left_passes == 0 {
        return format!("{head} · 仍在管 · 下一轮判定即解绑");
    }
    format!(
        "{head} · 仍在管 · 还需 {} 分钟、{} 轮才自动解绑",
        minutes(left_ms),
        left_passes
    )
}

/// 一条已被自动摘除的记录，列表里显示什么。
///
/// 要回答的是「为什么它不再被管」——那正是 `registered_by` 存在的理由的镜像。
pub fn retirement_notice(row: &RetirementBody) -> String {
    let family = row.family.clone().unwrap_or_else(|| "型号未知".into());
    format!(
        "{} · {} · 由 {} 纳管 · 自动摘除：{}",
        row.imei,
        family,
        row.registered_by,
        reason_label(&row.reason),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gate(reason: &str, since: i64, passes: u32) -> GateFailureBody {
        GateFailureBody {
            reason: reason.into(),
            since,
            passes,
        }
    }

    /// 🔴 每一种情况都必须说出「仍在管」。
    ///
    /// 这是这段文案唯一非做不可的事：它区分「还有余地」和「已经没了」。
    #[test]
    fn every_notice_says_it_is_still_managed() {
        let now = 1_000_000;
        for enforcing in [false, true] {
            for passes in [0, 50, 999] {
                for since in [now, now - 10 * 60_000, now - 60 * 60_000] {
                    let text = gate_notice(&gate("never_measured", since, passes), now, enforcing);
                    assert!(
                        text.contains("仍在管"),
                        "少了「仍在管」，运维会以为它已经掉了：{text}"
                    );
                }
            }
        }
    }

    /// 只标记模式必须说清不会自动删 —— 否则运维会等一个永远不来的动作。
    #[test]
    fn mark_only_mode_says_it_will_not_unbind() {
        let text = gate_notice(&gate("never_measured", 0, 3), 600_000, false);
        assert!(text.contains("只标记不自动解绑"), "{text}");
        assert!(!text.contains("才自动解绑"), "只标记模式不该给出倒计时承诺：{text}");
    }

    /// 执行模式下要给出**两个**剩余量，因为两个条件都要满足。
    ///
    /// 只报时间的话，一台刚重启、时间够了但趟数还差 90 轮的机器，
    /// 会显示「还需 0 分钟」，而它其实还有十几分钟。
    #[test]
    fn enforcing_mode_reports_both_remaining_conditions() {
        let now = edge_core::GRACE_MS + 1_000;
        let text = gate_notice(&gate("never_measured", 1_000, 10), now, true);
        assert!(text.contains("还需"), "{text}");
        assert!(
            text.contains(&format!("{} 轮", edge_core::GRACE_PASSES - 10)),
            "少了趟数这一半：{text}"
        );
    }

    /// 两个条件都满足了就直说下一轮会删，不要再显示一个 0。
    #[test]
    fn a_satisfied_countdown_says_so_plainly() {
        let now = edge_core::GRACE_MS * 2;
        let text = gate_notice(&gate("no_strategy", 0, edge_core::GRACE_PASSES), now, true);
        assert!(text.contains("下一轮判定即解绑"), "{text}");
    }

    /// 文案不照抄 BindRefusal 的 Display —— 那几句是给正要纳管的人的。
    #[test]
    fn the_wording_does_not_tell_the_reader_to_adopt_it() {
        for reason in ["no_strategy", "never_measured", "unreadable_usb_identity"] {
            let text = gate_notice(&gate(reason, 0, 1), 60_000, true);
            assert!(!text.contains("adopt"), "{text}");
            assert!(!text.contains("before"), "{text}");
        }
    }

    /// 每一个真实的拒绝标签都要有中文。
    ///
    /// 靠「认不出就原样显示」兜底是对的（见下一条），但那是给**将来**新增的
    /// 变体留的余地，不是给现有变体偷懒的借口 —— 一个今天就存在的标签
    /// 露出英文，读的人会以为是程序出错了。
    #[test]
    fn every_refusal_that_exists_today_has_chinese() {
        for reason in [
            "no_strategy",
            "not_in_catalogue",
            "never_measured",
            "unreadable_usb_identity",
            "not_identified_yet",
        ] {
            let text = gate_notice(&gate(reason, 0, 1), 60_000, true);
            assert!(
                !text.contains(reason),
                "{reason} 还在露英文标签：{text}"
            );
        }
    }

    /// 认不出的标签原样显示，不吞掉。
    ///
    /// 加了新的 refusal 变体而忘了在这里加中文，结果应该是「显示一个英文
    /// 标签」，而不是「显示一句空话」——后者会让人以为没有原因。
    #[test]
    fn an_unmapped_reason_still_shows_something() {
        let text = gate_notice(&gate("some_new_refusal", 0, 1), 60_000, true);
        assert!(text.contains("some_new_refusal"), "{text}");
    }

    /// 时钟倒退不该显示负数分钟。
    #[test]
    fn a_clock_going_backwards_shows_no_negative_time() {
        let text = gate_notice(&gate("never_measured", 9_000_000, 1), 1_000, true);
        assert!(!text.contains('-'), "{text}");
    }

    #[test]
    fn a_retirement_says_who_adopted_it_and_why_it_went() {
        let row = RetirementBody {
            imei: "868019060490134".into(),
            retired_at: 1,
            reason: "never_measured".into(),
            detail: None,
            family: Some("EC200U-CN".into()),
            registered_by: "panel".into(),
            matrix_version: None,
        };
        let text = retirement_notice(&row);
        assert!(text.contains("868019060490134"));
        assert!(text.contains("EC200U-CN"));
        assert!(text.contains("panel"), "少了当初是谁纳管的，就答不了「为什么它在」");
        assert!(text.contains("从没被测过"));
    }
}

/// 这一趟**判不了**的原因 → 运维看得懂的话。
///
/// 🔴 和 `reason_label` 分开，因为两者说的是完全不同的事：那一个是「判定为该
///    解绑，倒计时在走」，这一个是「这一趟根本没判成，倒计时**没有**推进」。
///    把它们用同一套措辞，就会让人对一个还没有结论的状态去做补救。
///
/// ⚠️ 下一步各不相同，所以每一句都指向那一步 —— 而不是一句通用的「判不了」。
fn hold_label(reason: &str) -> &str {
    match reason {
        // 矩阵回落到内置的：这台机器对绝大多数「型号 × 运营商」都读成「没测过」，
        // 所以它**拒绝**做判定，而不是判定为不合规。
        "matrix_not_authoritative" => "这台机器的能力矩阵不权威，暂不判定",
        // 冷启动：连上云端之前不判，因为矩阵可能还没推下来。
        "uplink_never_resumed" => "还没连上过云端，暂不判定",
        "gate_state_unreadable" => "读不到它的闸标记，暂不判定",
        "never_observed" => "还没观测到这一根，暂不判定",
        "observation_stale" => "最近一次观测太旧，暂不判定",
        "family_unknown" => "型号还不知道，暂不判定",
        "family_disagrees" => "纳管时记的型号和现在观测到的对不上，暂不判定",
        "family_unrecognised" => "型号不认识，暂不判定",
        "missing_evidence" => "判定所需的证据不全，暂不判定",
        other => other,
    }
}

/// 一根这一趟判不了的模组，那一行显示什么。
///
/// 🔴 措辞刻意**不带危险色彩**。这不是「它出问题了」，是「这一趟没能检查它」——
///    而在此之前面板上这两种情况长得一模一样（hold 不写库里的标记，而面板读的
///    就是那个标记）。生产上 `retro_hold` 发生过 93 次，那 93 次里运维看到的都是
///    「一切正常」。
///
/// ⚠️ 明确说出「倒计时没有推进」。运维看到「暂不判定」会担心是不是在悄悄计时；
///    而事实恰恰相反 —— 判不了的这一趟对倒计时来说等于没发生。
pub fn hold_notice(reason: &str) -> String {
    format!("{}（倒计时没有推进）", hold_label(reason))
}

#[cfg(test)]
mod hold_tests {
    use super::{hold_label, hold_notice};

    /// 每一个 `HoldReason::wire()` 都要有自己的一句话。
    ///
    /// 🔴 **从 edge-core 的源码里数出来**，不是在这里再抄一遍。抄一遍的话，
    ///    将来多一个 HoldReason 时这条断言仍然是绿的 —— 它只会检查我抄下来的
    ///    那几个，而新增的那个会在面板上默默显示成英文标签。
    ///
    /// ⚠️ 读源码而不是反射：`HoldReason` 的几个变体带字段（`MatrixAuthority`、
    ///    `age_ms`、`BindRefusal`），构造不出一份「全部变体」的列表。而 `wire()`
    ///    的那张 match 表就是权威清单，把它读出来比重建它可靠。
    #[test]
    fn every_hold_reason_has_a_sentence() {
        let retro = include_str!("../../edge-core/src/retro.rs");
        let body = retro
            .split("impl HoldReason")
            .nth(1)
            .expect("edge-core 里找不到 impl HoldReason —— 这条断言在扫空气");
        // ⚠️ 按行扫 `Self::… => "…"`，不按 `}` 切：几个变体自己就带花括号
        //    （`ObservationStale { .. }`），按 `}` 切会在第四个变体处就截断 ——
        //    第一版正是这么写的，它只数出 4 个然后「通过」了前面那半条断言。
        let wires: Vec<&str> = body
            .split("fn wire")
            .nth(1)
            .expect("HoldReason 没有 wire()")
            .lines()
            .take_while(|line| !line.trim_start().starts_with("pub fn "))
            .filter_map(|line| {
                let (left, rest) = line.split_once("=> \"")?;
                if !left.contains("Self::") {
                    return None;
                }
                rest.split('"').next()
            })
            .collect();
        assert!(
            wires.len() >= 9,
            "只从 edge-core 数出 {} 个 HoldReason —— 解析坏了，不是变体变少了",
            wires.len(),
        );

        for reason in wires {
            assert_ne!(
                hold_label(reason),
                reason,
                "{reason} 没有中文，面板上会直接显示这个英文标签",
            );
        }
    }

    /// 🔴 必须说出「倒计时没有推进」。没有这句话，「暂不判定」读起来像
    ///    「正在悄悄计时」，而事实相反。
    #[test]
    fn the_notice_says_the_countdown_did_not_advance() {
        let notice = hold_notice("matrix_not_authoritative");
        assert!(
            notice.contains("倒计时没有推进"),
            "没说倒计时的事：{notice}",
        );
    }

    /// 负面对照：不认识的标签原样带出去，而不是编一句话。
    ///
    /// ⚠️ 这条挡的是「给 `other` 写一句通用中文」那种修法 —— 那会让一个**新增
    ///    的**原因看起来像已经被处理过了，而上面那条断言也就永远绿了。
    #[test]
    fn an_unknown_reason_is_passed_through_untranslated() {
        assert_eq!(hold_label("something_new"), "something_new");
    }
}
