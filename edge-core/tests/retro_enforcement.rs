//! 追溯执行的判定。
//!
//! 这个特性唯一的失败模式是**删掉不该删的行**，所以下面每一条都对应一个
//! 具体的、能让它误删的形状，而不是为覆盖率凑的组合。

use edge_core::{
    enforce_one, BindRefusal, CapabilityMatrix, CarrierProfile, Enforcement, GateEvidence,
    HoldReason, MatrixAuthority, ModemFamily, StrategyRegistry, SupportLedger, UsbIdentity,
    GRACE_MS, GRACE_PASSES, OBSERVATION_MAX_AGE_MS,
};

const EC20: UsbIdentity = UsbIdentity::new(0x2c7c, 0x0125);
const NOW: i64 = 1_757_000_000_000;

fn registry() -> StrategyRegistry {
    edge_core::builtin_strategy_registry(SupportLedger::default()).expect("registry builds")
}

/// 线上 2026-09-01 推的那份，逐字。
fn live_matrix() -> CapabilityMatrix {
    CapabilityMatrix::from_toml(
        r#"
version = "2026-09-01T03:32:24Z"
[[rule]]
modem_family = "EC20"
carrier = "CN-Mobile"
sms_mo = { kind = "supported", bearer = "cellular" }
sms_mt = { kind = "supported", bearer = "cellular" }
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
    )
    .expect("matrix parses")
}

/// 一根一切正常的移动卡 EC20。每条测试从它出发，只改自己关心的那一项。
fn healthy() -> GateEvidence {
    GateEvidence {
        imei: "867018069509705".into(),
        adopted_family: Some(ModemFamily::EC20),
        observed_family: Some(ModemFamily::EC20),
        carrier: Some(CarrierProfile::CN_MOBILE),
        usb: Some(EC20),
        observation_age_ms: Some(3_000),
        failing_since_ms: None,
        failing_passes: 0,
    }
}

fn decide(authority: MatrixAuthority, resumed: bool, ev: &GateEvidence) -> Enforcement {
    enforce_one(&registry(), &live_matrix(), authority, resumed, ev, NOW)
}

fn stored(ev: &GateEvidence) -> Enforcement {
    decide(MatrixAuthority::Stored, true, ev)
}

// ────────────────────────── 关口 A ──────────────────────────

/// 🔴 回落到内置矩阵时，一根都不许删。
///
/// 内置矩阵 2026-09-05 之后只剩 3 条 EC20 规则。一旦回落，
/// EC25-CN、EG25-G、EC20 × CN-Unicom 全部读作「从没测过」——
/// 而那不是测量结论，是这台机器没收到过推送。
/// 内置矩阵自己的文件头写着「这份文件**不是**真相源」。
#[test]
fn a_builtin_matrix_never_authorises_a_delete() {
    let mut ev = healthy();
    // 一个在内置矩阵里必然缺席、因而「看起来该删」的对。
    ev.adopted_family = Some(ModemFamily::EC25_CN);
    ev.observed_family = Some(ModemFamily::EC25_CN);
    ev.carrier = Some(CarrierProfile::CN_UNICOM);
    for authority in [MatrixAuthority::BuiltinNoRow, MatrixAuthority::BuiltinUnparsed] {
        assert_eq!(
            decide(authority, true, &ev),
            Enforcement::Hold(HoldReason::MatrixNotAuthoritative(authority)),
            "{authority:?} 下判定生效，等于拿一份没收到推送的矩阵去删真相"
        );
    }
}

/// 解析失败和「没测过」必须分开。前者是读失败。
#[test]
fn an_unparsed_matrix_is_a_read_failure_not_a_verdict() {
    assert!(!MatrixAuthority::BuiltinUnparsed.may_unbind());
    assert!(!MatrixAuthority::BuiltinNoRow.may_unbind());
    assert!(MatrixAuthority::Stored.may_unbind());
}

/// 本次启动 uplink 从没连上过 → 全体 Hold。
///
/// 云端连「我这里矩阵不对」都还没机会说，就先删东西，是把冷启动的
/// 前几秒变成了一个不可逆的窗口。
#[test]
fn nothing_is_deleted_before_the_cloud_has_had_a_chance_to_speak() {
    let mut ev = healthy();
    ev.observed_family = Some(ModemFamily::EC25_CN);
    ev.adopted_family = Some(ModemFamily::EC25_CN);
    assert_eq!(
        decide(MatrixAuthority::Stored, false, &ev),
        Enforcement::Hold(HoldReason::UplinkNeverResumed)
    );
}

// ────────────────────────── 关口 B ──────────────────────────

/// 纳管了但从没跑完一轮 poll —— 迁移进来的、或刚 adopt 的。
#[test]
fn a_module_never_observed_is_held_not_deleted() {
    let mut ev = healthy();
    ev.observation_age_ms = None;
    ev.observed_family = None;
    assert_eq!(stored(&ev), Enforcement::Hold(HoldReason::NeverObserved));
}

/// 🔴 冻结的观测行不能拿来判定。
///
/// `local_modems` 的行在模组不在线期间原样留着。拿一行两周前的记录去查
/// 矩阵，查的是那时候插着的那张卡的运营商 —— 换过卡的模组会按旧卡过闸。
#[test]
fn a_stale_observation_is_held_not_deleted() {
    let mut ev = healthy();
    ev.observation_age_ms = Some(OBSERVATION_MAX_AGE_MS + 1);
    assert!(matches!(
        stored(&ev),
        Enforcement::Hold(HoldReason::ObservationStale { .. })
    ));
    // 阴性对照：刚好在界内要照常判定。
    ev.observation_age_ms = Some(OBSERVATION_MAX_AGE_MS);
    assert_eq!(stored(&ev), Enforcement::Keep);
}

/// 🔴 型号读不出来 → Hold。
///
/// `at_family("", "")` 返回字面量 "unknown"，而只走 AT 的 EC200U 有规律地
/// 挂死约 15 分钟 —— 挂在探测中途就是这个形状。全程没有一次 `Err`：
/// 「读不到」被伪装成了「测过、结论是 unknown」，正好绕开 `NotIdentifiedYet`
/// 这个通道。这一条就是补那个洞的。
#[test]
fn a_degraded_family_read_is_held_not_deleted() {
    for degraded in [ModemFamily::UNKNOWN, "", "   "] {
        let mut ev = healthy();
        ev.adopted_family = None;
        ev.observed_family = Some(ModemFamily::from(degraded));
        assert_eq!(
            stored(&ev),
            Enforcement::Hold(HoldReason::FamilyUnknown),
            "型号读成 {degraded:?} 时判定生效，一次 AT 超时就能解绑一根好模组"
        );
    }
}

/// 纳管记录与当前观测不一致 → Hold。
///
/// 这是上一条的第二道网：`registered_modems.family` 的 upsert 有 COALESCE，
/// 不会被坏轮次抹掉，所以它和当前观测打架时，打架本身就是证据不可信的信号。
#[test]
fn a_family_that_disagrees_with_the_registry_is_held() {
    let mut ev = healthy();
    ev.observed_family = Some(ModemFamily::EC25_CN);
    assert_eq!(
        stored(&ev),
        Enforcement::Hold(HoldReason::FamilyDisagrees {
            adopted: "EC20".into(),
            observed: "EC25-CN".into()
        })
    );
}

/// 🔴 认不出的型号 → Hold，绝不据此解绑。
///
/// QMI 侧读不到型号时写的是字面量 "Quectel"（`get_model()` 的
/// `unwrap_or_else`）。一个这个 build 不认识的 family 字符串，和一次退化读
/// **不可区分**；而矩阵那边说 `Other` 是给「以数据形式先行交付的新硬件」
/// 留的。两个理由指向同一个动作。
#[test]
fn an_unrecognised_family_is_held_not_deleted() {
    for name in ["Quectel", "0", "SIM7600G"] {
        let mut ev = healthy();
        ev.adopted_family = None;
        ev.observed_family = Some(ModemFamily::from(name));
        assert_eq!(
            stored(&ev),
            Enforcement::Hold(HoldReason::FamilyUnrecognised(name.into())),
            "{name:?} 被当成判定依据"
        );
    }
}

/// 阴性对照：已识别的变体照样能被解绑 —— 上面那条不是在关掉整个特性。
#[test]
fn a_recognised_variant_is_still_reachable_by_a_verdict() {
    let mut ev = healthy();
    ev.adopted_family = Some(ModemFamily::EC25_CN);
    ev.observed_family = Some(ModemFamily::EC25_CN);
    ev.carrier = Some(CarrierProfile::CN_UNICOM);
    ev.failing_since_ms = Some(NOW - GRACE_MS);
    ev.failing_passes = GRACE_PASSES;
    assert!(matches!(stored(&ev), Enforcement::Unbind(_)));
}

// ────────────────────────── 关口 C：极性 ──────────────────────────

/// 🔴 `bind_gates` 的两个「信息缺失」变体绝不能变成删除。
///
/// 这是整个模块存在的理由。`bind_gates` 是为**准入**写的，四个变体的动作
/// 都是「拒」，所以一个 `is_err()` 把它们抹平没有代价。在追溯方向上极性是
/// 反的：前两个必须维持现状。少了这一层分类，一根被拔掉的模组
/// （discovery 行被剪掉 → 读不出 USB 标识）会被直接解绑。
#[test]
fn missing_evidence_from_the_gates_never_becomes_a_delete() {
    // 读不出 USB 标识 —— 模组被拔了，或 discovery 行被 24 小时保留期剪掉了。
    let mut ev = healthy();
    ev.usb = None;
    ev.failing_since_ms = Some(NOW - GRACE_MS * 10);
    ev.failing_passes = GRACE_PASSES * 10;
    assert_eq!(
        stored(&ev),
        Enforcement::Hold(HoldReason::MissingEvidence(
            BindRefusal::UnreadableUsbIdentity
        )),
        "隔离期早就满了也不能删 —— 判不了的那一趟对倒计时来说等于没发生"
    );

    // 归属网络还没读到。
    let mut ev = healthy();
    ev.carrier = None;
    assert_eq!(
        stored(&ev),
        Enforcement::Hold(HoldReason::MissingEvidence(BindRefusal::NotIdentifiedYet))
    );
}

// ────────────────────────── 关口 D：隔离期 ──────────────────────────

/// 第一次判为该删，只隔离，不删。
#[test]
fn a_fresh_verdict_only_quarantines() {
    let mut ev = healthy();
    ev.carrier = Some(CarrierProfile::CN_TELECOM); // 线上矩阵里 EC20 × 电信没有规则
    match stored(&ev) {
        Enforcement::Quarantine {
            elapsed_ms, passes, ..
        } => {
            assert_eq!(elapsed_ms, 0, "第一趟的已用时长必须是 0");
            assert_eq!(passes, 1);
        }
        other => panic!("第一次判定就删了：{other:?}"),
    }
}

/// 🔴 时长和趟数**两个**都要满足。
///
/// 只看时长：一台 poll 老被 150 秒运营商扫描挡住的机器，会靠挂机时间蒙混
/// 过关，而它其实只做过两三次真实评估。
/// 只看趟数：一次矩阵手误在几分钟内就能凑够趟数，而运维还来不及补回来。
#[test]
fn both_the_clock_and_the_pass_count_must_be_satisfied() {
    let mut ev = healthy();
    ev.carrier = Some(CarrierProfile::CN_TELECOM);

    // ⚠️ `failing_passes` 是**此前**的趟数，本趟再加一。所以「差一趟」是
    //    `GRACE_PASSES - 2`，不是 `- 1`。第一版写成 `- 1`，于是这条断言
    //    自己就是满足条件的，测了个寂寞 —— 它红过一次才被发现。
    ev.failing_since_ms = Some(NOW - GRACE_MS);
    ev.failing_passes = GRACE_PASSES - 2;
    assert!(
        matches!(stored(&ev), Enforcement::Quarantine { .. }),
        "时长够了、趟数差一趟，就删了"
    );

    ev.failing_since_ms = Some(NOW - GRACE_MS + 1);
    ev.failing_passes = GRACE_PASSES;
    assert!(
        matches!(stored(&ev), Enforcement::Quarantine { .. }),
        "趟数够了、时长差 1 毫秒，就删了"
    );

    // 两个都刚好够。
    ev.failing_since_ms = Some(NOW - GRACE_MS);
    ev.failing_passes = GRACE_PASSES - 1;
    assert!(matches!(stored(&ev), Enforcement::Unbind(_)));
}

/// 时钟倒退只能让隔离期**变长**。
#[test]
fn a_clock_going_backwards_cannot_shorten_the_quarantine() {
    let mut ev = healthy();
    ev.carrier = Some(CarrierProfile::CN_TELECOM);
    ev.failing_since_ms = Some(NOW + GRACE_MS); // 未来的起点
    ev.failing_passes = GRACE_PASSES;
    match stored(&ev) {
        Enforcement::Quarantine { elapsed_ms, .. } => assert_eq!(elapsed_ms, 0),
        other => panic!("时钟倒退让它提前到期了：{other:?}"),
    }
}

// ────────────────────────── 实机回归 ──────────────────────────

/// 2026-09-05 台架上那四根，对着当天线上的矩阵，全部 `Keep`。
///
/// 这条回答的是「把开关打开会不会掉东西」。它曾经是一次心算，而那次心算
/// 的第一版是错的。
#[test]
fn the_live_fleet_is_kept() {
    let ec200u = UsbIdentity::new(0x2c7c, 0x0901);
    for (label, family, carrier, usb) in [
        ("香港 CSL", ModemFamily::EC20, CarrierProfile::GENERIC_INTERNATIONAL, EC20),
        ("移动", ModemFamily::EC20, CarrierProfile::CN_MOBILE, EC20),
        ("美国 310-240", ModemFamily::EC20, CarrierProfile::GENERIC_INTERNATIONAL, EC20),
        ("电信", ModemFamily::EC200U_CN, CarrierProfile::CN_TELECOM, ec200u),
    ] {
        let ev = GateEvidence {
            imei: label.into(),
            // 电信那根的 registered_modems.family 是 None —— 它是我改动之前
            // 经面板纳管的。这一条同时钉住「adopted 为 None 时 B4 不生效」。
            adopted_family: if label == "电信" { None } else { Some(family.clone()) },
            observed_family: Some(family),
            carrier: Some(carrier),
            usb: Some(usb),
            observation_age_ms: Some(5_000),
            failing_since_ms: None,
            failing_passes: 0,
        };
        assert_eq!(stored(&ev), Enforcement::Keep, "{label} 会被追溯执行动到");
    }
}
