//! 纳管两道闸的判定。
//!
//! 每一条都对应一个真实的失效形状，不是为了覆盖率而列的组合。

use edge_core::{
    bind_gates, BindRefusal, CapabilityMatrix, CarrierProfile, ModemFamily, StrategyRegistry,
    SupportLedger, UsbIdentity,
};

fn registry() -> StrategyRegistry {
    // 空账本：这个 registry 只用来回答「驱不驱动得了」，那是编译期事实。
    // 能力判定走矩阵，不走它。
    edge_core::builtin_strategy_registry(SupportLedger::default()).expect("registry builds")
}

fn matrix(toml: &str) -> CapabilityMatrix {
    CapabilityMatrix::from_toml(toml).expect("test matrix parses")
}

/// 只有 fallback，没有任何规则。
fn empty_matrix() -> CapabilityMatrix {
    matrix(
        r#"
version = "test"
[fallback]
sms_mo = { kind = "probe" }
sms_mt = { kind = "probe" }
data = { kind = "probe" }
voice = { kind = "probe" }
"#,
    )
}

const EC20: UsbIdentity = UsbIdentity::new(0x2c7c, 0x0125);
/// 2026-08 卡在台架上的那两根高通棒：能被枚举，永远认不出，
/// 没有任何策略驱动它们。
const UNDRIVEN: UsbIdentity = UsbIdentity::new(0x05c6, 0x90b4);

fn cn_mobile_pair() -> (ModemFamily, CarrierProfile) {
    (ModemFamily::EC20, CarrierProfile::CN_MOBILE)
}

/// 读不到 USB 标识 → 拒。
///
/// 🔴 这一条是整个闸的成败所在。放行「读不到」等于在最需要闸的那一刻
/// （一根刚插上、还没被认清的陌生硬件）把它关掉。
/// edge-bin 的串口候选过滤今天正是**失败即放行**（`None => true`），
/// 这里不重复那个形状。
#[test]
fn an_unreadable_usb_identity_is_refused_not_admitted() {
    assert_eq!(
        bind_gates(&registry(), &empty_matrix(), None, Some(cn_mobile_pair())),
        Err(BindRefusal::UnreadableUsbIdentity)
    );
}

/// 没有策略驱动的硬件 → 拒，哪怕它的「对」碰巧测过。
#[test]
fn hardware_no_strategy_drives_cannot_be_adopted() {
    let full = matrix(
        r#"
version = "test"
[[rule]]
modem_family = "EC20"
carrier = "CN-Mobile"
sms_mo = { kind = "supported", bearer = "cellular" }
"#,
    );
    assert_eq!(
        bind_gates(&registry(), &full, Some(UNDRIVEN), Some(cn_mobile_pair())),
        Err(BindRefusal::NoStrategy(UNDRIVEN))
    );
}

/// 闸的顺序：硬件先答。
///
/// 陌生硬件 + 没测过的对，必须报「没有策略驱动」而不是「没测过」——
/// 后者会把人引向去为一块根本不该被纳管的硬件做一次测量。
#[test]
fn the_hardware_gate_answers_before_the_ledger_gate() {
    let refusal = bind_gates(
        &registry(),
        &empty_matrix(),
        Some(UNDRIVEN),
        Some((ModemFamily::EC20, CarrierProfile::CN_TELECOM)),
    );
    assert_eq!(refusal, Err(BindRefusal::NoStrategy(UNDRIVEN)));
}

/// 型号或归属网络还没读到 → 拒，但这是暂时的。
#[test]
fn a_module_not_yet_identified_is_refused() {
    assert_eq!(
        bind_gates(&registry(), &empty_matrix(), Some(EC20), None),
        Err(BindRefusal::NotIdentifiedYet)
    );
}

/// 矩阵里根本没有这一对 → 没测过。
#[test]
fn a_pair_with_no_rule_has_never_been_measured() {
    let (family, carrier) = cn_mobile_pair();
    assert_eq!(
        bind_gates(&registry(), &empty_matrix(), Some(EC20), Some(cn_mobile_pair())),
        Err(BindRefusal::NeverMeasured { family, carrier })
    );
}

/// 🔴 后门：有规则，但四项全是 `probe`。
///
/// `CapabilityMatrix::rules()` 不过滤 probe，所以这样一条会让
/// `SupportLedger::is_tested` 返回 true。要是闸 2 拿 `is_tested` 来问，
/// 四条 probe 规则就能放行一根「绑得上、但每个操作都被 resolve() 拒掉」
/// 的模组 —— 静默半可用，正是这套设计要防的东西。
#[test]
fn a_rule_that_is_all_probe_is_not_a_measurement() {
    let probes = matrix(
        r#"
version = "test"
[[rule]]
modem_family = "EC20"
carrier = "CN-Mobile"
sms_mo = { kind = "probe" }
sms_mt = { kind = "probe" }
data = { kind = "probe" }
voice = { kind = "probe" }
"#,
    );
    let (family, carrier) = cn_mobile_pair();
    assert_eq!(
        bind_gates(&registry(), &probes, Some(EC20), Some(cn_mobile_pair())),
        Err(BindRefusal::NeverMeasured { family, carrier })
    );
    // 阴性对照：同一条规则里只要有一项是真结论，就该放行。
    // 否则上面那句可能只是在测「这条规则没被读到」。
    let one_real = matrix(
        r#"
version = "test"
[[rule]]
modem_family = "EC20"
carrier = "CN-Mobile"
sms_mo = { kind = "probe" }
sms_mt = { kind = "supported", bearer = "cellular" }
data = { kind = "probe" }
voice = { kind = "probe" }
"#,
    );
    assert_eq!(
        bind_gates(&registry(), &one_real, Some(EC20), Some(cn_mobile_pair())),
        Ok(())
    );
}

/// 部分测量放行 —— 香港 CSL 和美国 310-240 就挂在这条上。
///
/// 它们是 EC20 × Generic-International：`sms_mo` 是 probe，
/// `sms_mt` 是 supported。两根都该留在机队里，而它们发短信仍会被
/// `resolve()` 拒掉。纳管不等于每个能力都开。
#[test]
fn the_two_generic_international_ec20s_survive_the_gates() {
    let live = matrix(
        r#"
version = "2026-09-01T03:32:24Z"
[[rule]]
modem_family = "EC20"
carrier = "Generic-International"
sms_mo = { kind = "probe" }
sms_mt = { kind = "supported", bearer = "cellular" }
"#,
    );
    assert_eq!(
        bind_gates(
            &registry(),
            &live,
            Some(EC20),
            Some((ModemFamily::EC20, CarrierProfile::GENERIC_INTERNATIONAL))
        ),
        Ok(())
    );
}

/// 否定结论也是测量。电信 × EC20 量过，结论是不行 ——
/// 那和「没人测过」是两件事，前者更有价值。
#[test]
fn a_measured_refusal_still_opens_the_gate() {
    let telecom = matrix(
        r#"
version = "test"
[[rule]]
modem_family = "EC20"
carrier = "CN-Telecom"
sms_mo = { kind = "unsupported", reason = "no_cdma_fallback_and_no_ct_volte_mbn" }
sms_mt = { kind = "unsupported", reason = "no_cdma_fallback_and_no_ct_volte_mbn" }
"#,
    );
    assert_eq!(
        bind_gates(
            &registry(),
            &telecom,
            Some(EC20),
            Some((ModemFamily::EC20, CarrierProfile::CN_TELECOM))
        ),
        Ok(())
    );
}

/// 2026-09-05 台架上那四根，对着**当天线上真正在跑的那份矩阵**过闸。
///
/// 这条测试回答的是「开关一开会不会掉东西」。它曾经是一次心算，而心算
/// 的第一版是错的：我拿仓库里的 `capability-matrix.toml` 得出「电信那根
/// 会掉」，实际设备上跑的是云端 2026-09-01 推的那一份，里面 EC200U 的
/// 规则早就有了，真正悬着的是两根 Generic-International 的 EC20。
///
/// 所以矩阵在这里是**逐字抄的线上文档**，不是内置那份：换掉它，这条测试
/// 就不再是它自称的那个东西了。
#[test]
fn the_live_fleet_survives_both_gates() {
    let live = matrix(
        r#"
version = "2026-09-01T03:32:24Z"
[[rule]]
modem_family = "EC20"
carrier = "CN-Mobile"
sms_mo = { kind = "supported", bearer = "cellular" }
sms_mt = { kind = "supported", bearer = "cellular" }
[[rule]]
modem_family = "EC20"
carrier = "CN-Telecom"
data = { kind = "supported", bearer = "cellular" }
sms_mo = { kind = "unsupported", reason = "no_cdma_fallback_and_no_ct_volte_mbn" }
sms_mt = { kind = "unsupported", reason = "no_cdma_fallback_and_no_ct_volte_mbn" }
[[rule]]
modem_family = "EC20"
carrier = "Generic-International"
sms_mo = { kind = "probe" }
sms_mt = { kind = "supported", bearer = "cellular" }
[[rule]]
modem_family = "EC200U-CN"
carrier = "CN-Telecom"
sms_mo = { kind = "supported", bearer = "cellular" }
sms_mt = { kind = "supported", bearer = "cellular" }
"#,
    );
    let ec200u = UsbIdentity::new(0x2c7c, 0x0901);

    for (label, usb, family, carrier) in [
        ("香港 CSL 862547055142811", EC20, ModemFamily::EC20, CarrierProfile::GENERIC_INTERNATIONAL),
        ("移动 867018069509705", EC20, ModemFamily::EC20, CarrierProfile::CN_MOBILE),
        ("美国 310-240 867018069514820", EC20, ModemFamily::EC20, CarrierProfile::GENERIC_INTERNATIONAL),
        ("电信 868019060490134", ec200u, ModemFamily::EC200U_CN, CarrierProfile::CN_TELECOM),
    ] {
        assert_eq!(
            bind_gates(&registry(), &live, Some(usb), Some((family, carrier))),
            Ok(()),
            "{label} 过不了闸 —— 开这个开关会把它解绑"
        );
    }
}

/// 阴性对照：同一份线上矩阵，换一根没人测过的对，必须被拦下。
///
/// 没有这条，上面那条可能只是在测「`bind_gates` 永远返回 Ok」。
#[test]
fn the_live_matrix_still_refuses_an_unmeasured_pair() {
    let live = matrix(
        r#"
version = "2026-09-01T03:32:24Z"
[[rule]]
modem_family = "EC20"
carrier = "CN-Mobile"
sms_mo = { kind = "supported", bearer = "cellular" }
"#,
    );
    // EC25-CN 的规则 2026-09-05 被作废了，而这个 build 依然驱动得了它 ——
    // 闸 1 过，闸 2 不过，正是「支持」与「测试过」两根轴分开的意义。
    assert!(registry().drives(EC20));
    assert_eq!(
        bind_gates(
            &registry(),
            &live,
            Some(EC20),
            Some((ModemFamily::EC25_CN, CarrierProfile::CN_UNICOM))
        ),
        Err(BindRefusal::NeverMeasured {
            family: ModemFamily::EC25_CN,
            carrier: CarrierProfile::CN_UNICOM
        })
    );
}
