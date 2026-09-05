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
