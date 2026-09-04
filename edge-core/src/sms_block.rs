//! Sticks this fleet will not send a message from.
//!
//! 🔴 **这张表现在是空的，而且那不是「还没人填」。**
//!
//! ## 曾经在表里的那一根，和它为什么出去了
//!
//! `867018069509705` 曾经在这里。**2026-08-25 实测**：停掉 agent 后重放同一个
//! WMS RAW_SEND 帧，在 `867018069514820` 上成功、被 `862547055142811` 干净
//! 拒绝，**只有这一根 disconnect** —— 它每次 MO 提交都挂掉自己的 QMI 中断端点，
//! 离开总线几十秒；QMI 与 AT 两条路都触发，`AT+CFUN=1,1` 也清不掉。当时每小时
//! 的保号短信任务因此被停掉。那次测量是受控的，结论在当时是对的。
//!
//! **2026-09-04 它不再复现。** 从面板经 `commission` 发一条：模组全程没有离开
//! 总线（那个时段内核 USB 事件数为 0），投递报告回来 `status=delivered`。
//!
//! ⚠️ **中间变了一个变量：这根模组换了 USB 口。** 同一天查 USB 掉线时量到
//! `1-1.3` 的 1 号口带不动 500mA 的 EC20（插上四秒必掉，而 400mA 的 EC200U
//! 正常）。所以「发短信就掉线」很可能从来不是这颗模组的毛病，是那个口在发射
//! 电流冲击下塌了。**这一条没有被受控实验证实**，只是最能解释两次观测的读法。
//!
//! ## 🔴 什么时候该把它加回来
//!
//! 这张表的规矩没变：**只收实测事实，不许靠推断加条目**。反过来同样成立 ——
//! 上面那次解除也是一次观测，不是证明。加回来的条件是**再量到一次**：
//! 某一根在 MO 提交之后离开总线，而同一时刻别的模组没有。
//!
//! ⚠️ 尤其注意：如果把模组挪回一个供电勉强的口，很可能又能量到。那时候要判断
//! 的是「这根模组坏了」还是「这个口坏了」—— 判据是**同一根模组换个好口还复不
//! 复现**。8 月 25 日那次没有做这个对照，这是它留下的教训。
//!
//! ## 机制还在，而且必须保持可用
//!
//! 表空了不等于这条路可以烂掉。下一次真量到一根会掉的模组，加进 `BLOCKED`
//! 就该立刻在三个地方同时生效。所以这里提供 [`SAMPLE_BLOCKS`] 和 [`sms_block_in`]：
//! **守着这道门的测试用夹具跑，不依赖生产表里恰好有条目。** 否则表一空，
//! 那些测试就跟着变成空测试 —— 而这个仓库已经因为「守卫悄悄失效」踩过好几次。
//!
//! ## Why this is in `edge-core` and not where it was
//!
//! ⚠️ It lived in a JavaScript object inside `edge-panel/src/index.html` — the
//! file the Leptos migration deletes. One copy, in the one place that is going
//! away, holding a fact measured on a bench that no longer has that stick in
//! the same slot.
//!
//! ## 在哪里生效
//!
//! 三个地方，各有各的理由：
//!
//! 1. **`POST /api/send` 的 handler**（`edge-panel`）。这是真正的那道门 —— 一个
//!    `curl` 就是从这里进来的。不指名 `imei` 也拒，因为代理在没有 IMEI 时会取
//!    modem map 里的第一条，那样按 IMEI 的检查绕一下就没了。
//! 2. **发短信那一页**（`edge-ui`）。在按钮上就说清楚，而不是让人按下去之后
//!    才吃一个 403。
//! 3. **体检页的第四条判词**。那是发短信之前有人会看的地方。
//!
//! `commission=true` 是唯一的越过路径，语义是现成的：「在账本没量过的组合上
//! 发一次，为了知道会怎样」。这张表本身就是这样量出来的，所以复测必须做得到 ——
//! 只是要明确说出口，而不是默认发生。
//!
//! ⚠️ 云端下发的命令走的是另一条路（`edge-bin` 的 relay），**不经过这道门**。
//! 那是一个单独的决定，不在这里。

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

/// 🔴 **空的，而且是有理由的空。** 见模块开头：唯一那条在 2026-09-04 解除了。
///
/// 加条目之前先读模块开头「什么时候该把它加回来」那一节。
const BLOCKED: &[(&str, SmsBlock)] = &[];

/// 一条**只给测试用**的条目。
///
/// 🔴 生产表是空的，而这条路必须仍然可测：它是真正拦 `curl` 的那道门。没有这
/// 个夹具的话，表一空，守着它的测试就跟着变成空测试 —— 那正是这个仓库反复
/// 踩过的坑（守卫悄悄失效，而且不报错）。
///
/// ⚠️ IMEI 是一个**不可能属于真硬件**的值，免得它被误当成一条真记录。
pub const SAMPLE_BLOCKS: &[(&str, SmsBlock)] = &[(
    "000000000000000",
    SmsBlock {
        why: "（测试夹具）每一次 MO 提交都会让它离开总线几十秒。",
        also: "（测试夹具）短信多半真的发出去了，被告知失败的人会重发，对端收两次。",
        source: "（测试夹具）不是实测事实，只用来让封禁这条路在生产表为空时仍然可测。",
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
    sms_block_in(BLOCKED, imei)
}

/// 同一套查表，但表由调用方给。
///
/// 🔴 测试用它配 [`SAMPLE_BLOCKS`]，这样「有一根被封禁」这条路在生产表为空时仍然测
/// 得到。生产代码一律用 [`sms_block`]。
pub fn sms_block_in(
    table: &'static [(&'static str, SmsBlock)],
    imei: &str,
) -> Option<&'static SmsBlock> {
    table
        .iter()
        .find(|(blocked, _)| *blocked == imei)
        .map(|(_, block)| block)
}

/// Every blocked IMEI, for a guard that wants to assert the list is non-empty.
pub fn blocked_imeis() -> impl Iterator<Item = &'static str> {
    BLOCKED.iter().map(|(imei, _)| *imei)
}

/// 生产表本身。
///
/// 🔴 给的是**表**而不是查询函数，是为了让上层（`edge-panel` 的路由）能把它
/// 换成 [`SAMPLE_BLOCKS`] 来测那道门。表空了之后，门的接线在 HTTP 层面就再也测不到
/// 了 —— 除非表可以被注入。
pub fn sms_blocks() -> &'static [(&'static str, SmsBlock)] {
    BLOCKED
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 🔴 **生产表是空的，而且那是一个决定，不是遗漏。**
    ///
    /// 唯一那条（`867018069509705`）在 2026-09-04 解除 —— 理由、日期和「什么
    /// 时候该加回来」都写在模块开头。这条测试守的是：谁想加条目，先去读那一段。
    #[test]
    fn the_production_table_is_deliberately_empty() {
        assert_eq!(
            blocked_imeis().count(),
            0,
            "有人往表里加了条目 —— 先读模块开头「什么时候该把它加回来」，\
             那里写着加回来的条件是**再量到一次**，不是推断"
        );
        assert!(sms_block("867018069509705").is_none(), "那一根已经解除了");
    }

    /// 🔴 表空了，但这条路必须还能用。
    ///
    /// 下一次真量到一根会掉的模组，加进 `BLOCKED` 就该立刻生效。用夹具跑，
    /// 这样这条测试不依赖生产表里恰好有条目 —— 否则它会跟着表一起变成空测试。
    #[test]
    fn the_mechanism_still_works_when_a_stick_is_added() {
        let imei = SAMPLE_BLOCKS[0].0;
        let block = sms_block_in(SAMPLE_BLOCKS, imei).expect("夹具里的那条要查得到");
        assert!(
            sms_block_in(SAMPLE_BLOCKS, "867018069514820").is_none(),
            "别的不受影响"
        );

        // 措辞的两半都要在：机制是什么，以及那句反直觉的。
        assert!(!block.why.is_empty());
        assert!(
            block.also.contains("重发") || block.also.contains("发出去了"),
            "少了那句反直觉的 —— 被告知「失败」的人会重发，对端收两次"
        );
        assert!(!block.source.is_empty(), "来源不能空：下一个人要能去复测");
    }

    /// ⚠️ 夹具的 IMEI 不能像一个真的。
    #[test]
    fn the_fixture_cannot_be_mistaken_for_a_real_record() {
        let imei = SAMPLE_BLOCKS[0].0;
        assert!(
            imei.chars().all(|c| c == '0'),
            "夹具的 IMEI 长得像真的，会被误读成一条实测记录：{imei}"
        );
        assert!(SAMPLE_BLOCKS[0].1.source.contains("测试夹具"));
    }
}
