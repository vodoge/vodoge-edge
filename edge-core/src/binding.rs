//! 纳管的两道闸。
//!
//! 方向是运维定的：**自动发现，手动纳管**，而且「管理到的设备必须是我们
//! 支持的、测试过的」。这个模块就是那两个形容词的机器形式：
//!
//! - **支持的** —— 这个 build 里有策略驱动这个 USB 硬件
//! - **测试过的** —— 这一对「型号 × 归属运营商」在能力矩阵里有过真实测量
//!
//! 两道闸都在**纳管**这一步问，而不是在每次操作时问。操作那一层是
//! `StrategyRegistry::resolve`，它回答的是另一个问题：「这个操作此刻能不能
//! 做」。⚠️ 不要把两层合并 —— 一根只测过 `sms_mt` 的模组该能被纳管，
//! 而它发短信依然该被 `resolve()` 拒掉。合并之后要么放宽了纳管，
//! 要么把「部分测量」变成了完全不可用。
//!
//! ## 为什么每一条都失败即拒
//!
//! 读不到 USB 标识、还没识别出型号、归属网络还没读到 —— 这三种都是
//! **信息缺失**，不是「没问题」。放行它们，闸就会在最需要它的那一刻
//! （一根刚插上、还没被认清的陌生硬件）失效。
//!
//! `edge-bin` 的 `driven_by_a_strategy` 已经把这条写下来了：
//! 「A node whose identity cannot be read is **refused**, not admitted.
//! The alternative fails open, and failing open here is how the gate quietly
//! stops being a gate.」这里是同一条规则，在另一个入口上。

use crate::{CapabilityMatrix, CarrierProfile, ModemFamily, StrategyRegistry, UsbIdentity};

/// 为什么这根模组现在不能被纳管。
///
/// 是 enum 而不是一句话，因为调用方不止一个（面板、云端命令），
/// 而且界面将来要能按种类给出不同的下一步动作。
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BindRefusal {
    /// USB 的 vendor/product 读不出来。**拒**，不是放行。
    UnreadableUsbIdentity,
    /// 这个 build 里没有任何策略驱动这个硬件。
    NoStrategy(UsbIdentity),
    /// 还没识别出型号，或还没读到卡的归属网络 —— 「这一对」尚未成立。
    /// 这通常是暂时的：再探测一轮就有了。
    NotIdentifiedYet,
    /// 这一对从来没有过真实测量。矩阵里要么没有它，要么有一条但四项全是
    /// `probe`，而 `probe` 按 `0046_support_ledger.sql` 的定义 grants nothing。
    NeverMeasured {
        family: ModemFamily,
        carrier: CarrierProfile,
    },
}

impl std::fmt::Display for BindRefusal {
    /// 面向运维的一句话，且每一句都说出**下一步做什么**。
    ///
    /// 英文是跟现有三条 `PanelError::Action` 的惯例走的（它们同时进日志）。
    /// 界面要中文化的话，应该按 enum 的种类映射，而不是去翻译这里的字符串。
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnreadableUsbIdentity => write!(
                formatter,
                "its USB identity could not be read, so it cannot be matched against the \
                 supported-device list; rescan, and if it stays unreadable the module is not \
                 enumerating properly"
            ),
            Self::NoStrategy(identity) => write!(
                formatter,
                "no strategy in this build drives {identity}; it is not on the supported-device \
                 list, and adopting it would put a row in the registry no probe can satisfy"
            ),
            Self::NotIdentifiedYet => write!(
                formatter,
                "its model and home network have not both been read yet, so there is no pairing \
                 to check against the ledger; wait for the next poll and try again"
            ),
            Self::NeverMeasured { family, carrier } => write!(
                formatter,
                "{family} on {carrier} has never been measured; measure it and record the result \
                 in the support ledger before adopting hardware that depends on it"
            ),
        }
    }
}

/// 两道闸，按顺序问。
///
/// `usb` 为 `None` 表示**读不到**，不表示「没有」；`pair` 为 `None` 表示
/// 型号或归属网络还没读到。两者都拒。
///
/// 闸的顺序是有意的：先答「这硬件我们支不支持」，再答「这一对测没测过」。
/// 反过来的话，一块完全陌生的硬件会拿到一句「没测过」，
/// 把人引向去做一次根本不该做的测量。
pub fn bind_gates(
    registry: &StrategyRegistry,
    matrix: &CapabilityMatrix,
    usb: Option<UsbIdentity>,
    pair: Option<(ModemFamily, CarrierProfile)>,
) -> Result<(), BindRefusal> {
    // 闸 1：支持的
    let Some(identity) = usb else {
        return Err(BindRefusal::UnreadableUsbIdentity);
    };
    if !registry.drives(identity) {
        return Err(BindRefusal::NoStrategy(identity));
    }

    // 闸 2：测试过的
    let Some((family, carrier)) = pair else {
        return Err(BindRefusal::NotIdentifiedYet);
    };
    if !matrix.query(&family, &carrier).capability.has_measurement() {
        return Err(BindRefusal::NeverMeasured { family, carrier });
    }

    Ok(())
}
