//! 追溯执行：已经纳管的模组，现在还过不过得了那两道闸。
//!
//! 判定是纯的，整个都在这里，好在工作站上测完 —— 云主机编译不了，
//! 而这段代码唯一的失败模式是**删掉不该删的行**。
//!
//! # 铁律
//!
//! 🔴 **读不到 ≠ 不合规。** 任何一处证据缺失都必须导致「维持现状 + 告警」，
//! 绝不导致解绑。这条不是谨慎，是付过学费的：`managed_imeis` 那次，
//! 一次短暂的存储读失败让整台设备被取消纳管。
//!
//! 「读 → 判定 → 删」天生是那个形状，所以这里把它拆成三段，每段之间放一个
//! 关口，而且**每一个 `Option` 都表示「读不到」，不表示「没有」**。
//!
//! # 三个关口
//!
//! - **A：判据可不可信** —— 与具体模组无关。矩阵是不是权威的、云端有没有
//!   机会说过话。
//! - **B：这一根的证据够不够新、够不够一致** —— 观测新鲜度、型号是否识别、
//!   纳管记录与当前观测是否一致。
//! - **C：过闸** —— `bind_gates`，但**必须**先按 [`RefusalKind`] 分类，
//!   因为它的极性在这个方向上是反的。
//!
//! 最后是 **D：隔离期** —— 真判定也不立刻执行。

use crate::{
    bind_gates, BindRefusal, CapabilityMatrix, CarrierProfile, ModemFamily, RefusalKind,
    StrategyRegistry, UsbIdentity,
};

/// 这份矩阵配不配用来**删**东西。
///
/// 🔴 [`crate::CapabilityOrigin::Fallback`] 回答的是「这一对没人写过规则」，
/// **不是**「矩阵丢了」。两种情况共用一个词，`query()` 分不出来 ——
/// 所以权威性必须从矩阵**外面**带进来。
///
/// 差别是致命的：内置矩阵 2026-09-05 之后只剩 3 条 EC20 规则。一旦回落到它，
/// EC25-CN、EG25-G、EC20 × CN-Unicom 全部读作「从没测过」，
/// 而追溯执行会把它们全部解绑。内置矩阵自己的文件头写着「这份文件**不是**
/// 真相源」—— 拿它去删真相是反的。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MatrixAuthority {
    /// 库里那一行解析成功，或本次运行云端推过一份。允许判定。
    Stored,
    /// 库里没有行 —— 这台机器从未收到过推送。
    BuiltinNoRow,
    /// 库里有行但解析不了。这是**读失败**，不是「没测过」。
    BuiltinUnparsed,
}

impl MatrixAuthority {
    pub fn may_unbind(self) -> bool {
        matches!(self, Self::Stored)
    }

    pub fn wire(self) -> &'static str {
        match self {
            Self::Stored => "stored",
            Self::BuiltinNoRow => "builtin_no_row",
            Self::BuiltinUnparsed => "builtin_unparsed",
        }
    }
}

/// 一根已纳管模组，这一趟凑到的全部证据。
///
/// ⚠️ 每一个 `Option` 都表示「**读不到**」，不表示「没有」——
/// 和 [`bind_gates`] 的约定一致。
#[derive(Clone, Debug)]
pub struct GateEvidence {
    pub imei: String,
    /// 纳管当时记下的型号。它的 upsert 有 COALESCE，不会被后来的坏轮次抹掉，
    /// 所以它是「当初是按哪一对放行的」这个问题的证据。
    /// 可以是 `None`：2026-09-05 之前经面板纳管的行没有写它。
    pub adopted_family: Option<ModemFamily>,
    /// 本轮从 `local_modems` 读到的型号。
    pub observed_family: Option<ModemFamily>,
    pub carrier: Option<CarrierProfile>,
    pub usb: Option<UsbIdentity>,
    /// `local_modems.last_seen` 与 now 的差。`None` = 从来没被观测过。
    pub observation_age_ms: Option<i64>,
    /// 已经连续判定为「该解绑」的起点与趟数，持久化在 `registered_modems`。
    pub failing_since_ms: Option<i64>,
    pub failing_passes: u32,
}

/// 为什么这一趟判不了。**每一条都通向「维持现状」。**
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HoldReason {
    MatrixNotAuthoritative(MatrixAuthority),
    UplinkNeverResumed,
    NeverObserved,
    ObservationStale { age_ms: i64 },
    FamilyUnknown,
    FamilyDisagrees { adopted: String, observed: String },
    FamilyUnrecognised(String),
    MissingEvidence(BindRefusal),
}

impl HoldReason {
    /// 给告警 context 用的短标签。常量，不含 IMEI。
    pub fn wire(&self) -> &'static str {
        match self {
            Self::MatrixNotAuthoritative(_) => "matrix_not_authoritative",
            Self::UplinkNeverResumed => "uplink_never_resumed",
            Self::NeverObserved => "never_observed",
            Self::ObservationStale { .. } => "observation_stale",
            Self::FamilyUnknown => "family_unknown",
            Self::FamilyDisagrees { .. } => "family_disagrees",
            Self::FamilyUnrecognised(_) => "family_unrecognised",
            Self::MissingEvidence(_) => "missing_evidence",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Enforcement {
    /// 两道闸现在依然过。调用方负责清掉隔离标记（如果有）。
    Keep,
    /// 判不了。维持现状 + 告警。**不清标记，也不推进倒计时**——
    /// 判不了的这一趟，对倒计时来说等于没发生。
    Hold(HoldReason),
    /// 真判定，但隔离期未满。写标记 / 推进倒计时 + 告警。**不删。**
    Quarantine {
        refusal: BindRefusal,
        elapsed_ms: i64,
        passes: u32,
    },
    /// 真判定，隔离期满。解绑。
    Unbind(BindRefusal),
}

/// 观测超过这么久就不拿来判定。
///
/// `local_modems` 的行在模组不在线期间是**冻结**的 —— 拿一行两周前的记录
/// 去查矩阵，查的是那时候插着的那张卡的运营商。
pub const OBSERVATION_MAX_AGE_MS: i64 = 10 * 60 * 1000;

/// 隔离期：真判定要连续站住这么久才执行。
///
/// 这个窗口的用途很具体：云端手误推了一份规则更少的矩阵，十分钟内补回来 ——
/// 在这个窗口里**一根都不会被删，也不需要任何人做任何事**，
/// 下一趟 `Keep` 会把标记自己清掉。
pub const GRACE_MS: i64 = 30 * 60 * 1000;

/// 隔离期的第二个条件：还要连续站住这么多趟。
///
/// 只有时间不够：一台 poll 老是被 150 秒的运营商扫描挡住的机器，
/// 会靠挂机时间蒙混过关，而它其实只做过两三次真实评估。
pub const GRACE_PASSES: u32 = 100;

/// 一根已纳管模组这一趟的判定。
pub fn enforce_one(
    registry: &StrategyRegistry,
    matrix: &CapabilityMatrix,
    authority: MatrixAuthority,
    uplink_ever_resumed: bool,
    evidence: &GateEvidence,
    now: i64,
) -> Enforcement {
    // ── A：判据可不可信 ───────────────────────────────────────────
    if !authority.may_unbind() {
        return Enforcement::Hold(HoldReason::MatrixNotAuthoritative(authority));
    }
    if !uplink_ever_resumed {
        // 冷启动第一轮只观测。云端连「我这里矩阵不对」都还没机会说。
        return Enforcement::Hold(HoldReason::UplinkNeverResumed);
    }

    // ── B：这一根的证据 ──────────────────────────────────────────
    let Some(age) = evidence.observation_age_ms else {
        return Enforcement::Hold(HoldReason::NeverObserved);
    };
    if age > OBSERVATION_MAX_AGE_MS {
        return Enforcement::Hold(HoldReason::ObservationStale { age_ms: age });
    }

    let Some(observed) = evidence.observed_family.clone() else {
        return Enforcement::Hold(HoldReason::FamilyUnknown);
    };
    if observed.as_str().trim().is_empty() || observed.as_str() == ModemFamily::UNKNOWN {
        return Enforcement::Hold(HoldReason::FamilyUnknown);
    }
    if let Some(adopted) = &evidence.adopted_family {
        if adopted != &observed {
            return Enforcement::Hold(HoldReason::FamilyDisagrees {
                adopted: adopted.as_str().to_owned(),
                observed: observed.as_str().to_owned(),
            });
        }
    }
    if matches!(observed, ModemFamily::Other(_)) {
        // 一个这个 build 不认识的 family 字符串，和一次退化读**不可区分**：
        // QMI 侧读不到型号时会写字面量 "Quectel"。而矩阵那边说 `Other` 是给
        // 「以数据形式先行交付的新硬件」留的。两个理由指向同一个动作。
        //
        // ⚠️ 这不会挡住真正的目标场景：EC25-CN 和 EG25-G 是**已识别**变体，
        //    依然可以被解绑。
        return Enforcement::Hold(HoldReason::FamilyUnrecognised(
            observed.as_str().to_owned(),
        ));
    }

    // ── C：过闸，但必须先分类 ───────────────────────────────────
    let pair = evidence
        .carrier
        .clone()
        .map(|carrier| (observed.clone(), carrier));
    match bind_gates(registry, matrix, evidence.usb, pair) {
        Ok(()) => Enforcement::Keep,
        Err(refusal) => match refusal.kind() {
            // 🔴 极性在这里是反的。见 `RefusalKind` 的文档。
            RefusalKind::MissingEvidence => {
                Enforcement::Hold(HoldReason::MissingEvidence(refusal))
            }
            // ── D：隔离期 ──────────────────────────────────────
            RefusalKind::Verdict => {
                let since = evidence.failing_since_ms.unwrap_or(now);
                // 🔴 时钟倒退只能让隔离期**变长**，不能变短。
                //
                // `.max(0)` 不是多余的：`i64::saturating_sub` 饱和在
                // `i64::MIN`，不在 0。起点若落在未来（NTP 往回跳、
                // 或一台没有 RTC 的机器刚开机），单靠 saturating 会算出一个
                // **负的**已用时长。判定结果仍然安全（负数 < GRACE_MS，
                // 所以只隔离），但那个数会原样进告警的 context，
                // 给运维一个「已隔离 -30 分钟」的读数。
                //
                // 测试 `a_clock_going_backwards_cannot_shorten_the_quarantine`
                // 先看到它红：left -1800000 / right 0。
                let elapsed = now.saturating_sub(since).max(0);
                let passes = evidence.failing_passes.saturating_add(1);
                if elapsed >= GRACE_MS && passes >= GRACE_PASSES {
                    Enforcement::Unbind(refusal)
                } else {
                    Enforcement::Quarantine {
                        refusal,
                        elapsed_ms: elapsed,
                        passes,
                    }
                }
            }
        },
    }
}
