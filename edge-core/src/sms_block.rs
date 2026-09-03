//! Sticks this fleet will not send a message from.
//!
//! 🔴 **Not a policy invented here, and not "SMS is broken on this stick".**
//!
//! `867018069509705` stalls its own QMI interrupt endpoint on every MO submit:
//! the USB/IP session is torn down and the module leaves the bus for tens of
//! seconds. Measured 2026-08-25 by replaying one WMS RAW_SEND frame with the
//! agent stopped — the same frame succeeded on `cdc-wdm0`, was cleanly refused
//! by `cdc-wdm1`, and only this stick disconnected. Both transports trigger it
//! (QMI RAW_SEND and `AT+CMGS`), and a full `AT+CFUN=1,1` does not clear it.
//!
//! Two details decide the wording, and both cut against the obvious one:
//!
//! - **The message usually goes out.** The SIM's own MO reference counter in
//!   `EF_SMSS` advanced by 34 over a day of sends the console recorded as
//!   failures, and 10086 kept replying to them. Told "failed", an operator
//!   resends and the recipient gets it twice. So the cost is not a lost
//!   message, it is a lost module — and saying "发不出去" would be the same lie
//!   the daemon was fixed for telling.
//! - **There is no fix from this side**, which is why the hourly keepalive that
//!   used to send on this stick was switched off rather than retried.
//!
//! Keyed by IMEI because that is what identifies the hardware; the card in it
//! can be moved.
//!
//! ## Why this is in `edge-core` and not where it was
//!
//! ⚠️ It lived in a JavaScript object inside `edge-panel/src/index.html` — the
//! file the Leptos migration deletes. One copy, in the one place that is going
//! away, holding a fact measured on a bench that no longer has that stick in
//! the same slot.
//!
//! 🔴 **And it is enforced only in the browser.** `POST /api/send` does not
//! consult this table; a `curl` reaches the modem regardless. That is not
//! changed here — the migration is not the place to alter what the daemon
//! accepts — but it is worth writing down, because "the panel will not send
//! from this stick" and "this stick cannot be sent from" are different
//! statements and only the first one is true today.

/// Why one module is not to be sent from, in the words an operator needs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SmsBlock {
    /// What happens, mechanically.
    pub why: &'static str,
    /// The part that is counter-intuitive, and that the operator will
    /// otherwise get wrong on their own.
    pub also: &'static str,
    /// Where the claim comes from, so the next person can re-measure it rather
    /// than inherit it.
    pub source: &'static str,
}

const BLOCKED: &[(&str, SmsBlock)] = &[(
    "867018069509705",
    SmsBlock {
        why: "每一次 MO 短信提交都会让它挂掉自己的 QMI 中断端点，USB/IP 会话被拆掉，\
              模组离开总线几十秒。QMI 与 AT 两条路都会触发，完整的 AT+CFUN=1,1 也清不掉。",
        also: "代价不是「发不出去」：短信多半真的发出去了 —— 卡上 EF_SMSS 的 MO 计数\
               在被记成「失败」的那一天涨了 34，10086 一直在回。代价是每发一条就丢一次模组。",
        source: "vowifi T028 实测 2026-08-25：停掉 agent 后同一个 RAW_SEND 帧在 \
                 867018069514820 上成功、被 862547055142811 干净拒绝，只有这一根 disconnect。\
                 每小时的保号短信任务也因此被停掉。",
    },
)];

/// The block for one IMEI, if it has one.
///
/// ⚠️ Keyed on the IMEI exactly. The panel that used to hold this table had a
/// regression worth remembering: an earlier rule refused every modem whose
/// `manageable` was false, on the theory that "AT-only means sending needs a
/// path we have not measured". That refused sticks that send perfectly well.
/// The list is per-IMEI *measured* fact, and nothing may be added to it by
/// inference from a capability flag.
pub fn sms_block(imei: &str) -> Option<&'static SmsBlock> {
    BLOCKED
        .iter()
        .find(|(blocked, _)| *blocked == imei)
        .map(|(_, block)| block)
}

/// Every blocked IMEI, for a guard that wants to assert the list is non-empty.
pub fn blocked_imeis() -> impl Iterator<Item = &'static str> {
    BLOCKED.iter().map(|(imei, _)| *imei)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_measured_stick_is_blocked_and_says_why() {
        let block = sms_block("867018069509705").expect("the measured stick is on the list");
        // The wording matters as much as the entry: an operator told "failed"
        // resends, and the recipient gets it twice.
        assert!(
            block.also.contains("发出去了"),
            "the note no longer says the message usually goes out, which is the \
             half an operator gets wrong on their own"
        );
        assert!(
            block.source.contains("2026-08-25"),
            "the claim lost the date it was measured on"
        );
    }

    #[test]
    fn nothing_else_is_blocked_by_inference() {
        assert_eq!(blocked_imeis().count(), 1);
        assert!(sms_block("862547055142811").is_none());
        // The stick that was cleanly refused on the bench is not blocked: a
        // refusal is not a disconnect.
        assert!(sms_block("867018069514820").is_none());
    }
}
