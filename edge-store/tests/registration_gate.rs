//! 追溯执行在库里的两个状态位，和退休记录。

use edge_store::{RegisteredModem, Retirement, Store};

fn store() -> Store {
    Store::open_in_memory().expect("open")
}

fn adopted(imei: &str) -> RegisteredModem {
    RegisteredModem {
        imei: imei.to_owned(),
        registered_at: 1_700_000_000_000,
        registered_by: "panel".into(),
        usb_device: Some("1-1.4.1".into()),
        family: Some("EC200U-CN".into()),
        note: None,
    }
}

fn retirement(imei: &str) -> Retirement {
    Retirement {
        imei: imei.to_owned(),
        registered_at: 1_700_000_000_000,
        registered_by: "panel".into(),
        family: Some("EC200U-CN".into()),
        usb_device: Some("1-1.4.1".into()),
        retired_at: 1_757_000_000_000,
        reason: "never_measured".into(),
        detail: Some("EC200U-CN on CN-Telecom has never been measured".into()),
        matrix_version: Some("2026-09-01T03:32:24Z".into()),
    }
}

/// 🔴 起点只在第一趟写入，之后不许被推后。
///
/// 每趟都刷新起点的话，倒计时永远走不到 30 分钟 —— 隔离期就成了一个永远
/// 不到期的摆设。那和关掉这个特性没有区别，但它看起来是开着的，
/// 而「看起来开着的关闭」比明确关闭危险得多。
#[test]
fn the_countdown_starts_once_and_is_never_pushed_forward() {
    let store = store();
    store.register_modem(&adopted("1")).expect("adopt");

    store.mark_gate_failure("1", "never_measured", 1_000).expect("first");
    store.mark_gate_failure("1", "never_measured", 9_000).expect("second");
    store.mark_gate_failure("1", "never_measured", 99_000).expect("third");

    let gate = store.gate_failure("1").expect("read").expect("marked");
    assert_eq!(gate.since, 1_000, "起点被后来的趟数推后了，倒计时永远走不完");
    assert_eq!(gate.passes, 3, "趟数没有累加，第二个条件永远满足不了");
    assert_eq!(gate.reason, "never_measured");
}

/// 闸又过了就清干净 —— 这是自愈发生的地方。
///
/// 云端手误推了一份规则更少的矩阵、十分钟内补回来：这个场景里一根都不会被
/// 删，也不需要任何人做任何事。清不干净的话，下一次真判定会带着上一次的
/// 倒计时立刻到期。
#[test]
fn passing_the_gates_again_clears_the_countdown_completely() {
    let store = store();
    store.register_modem(&adopted("1")).expect("adopt");
    store.mark_gate_failure("1", "never_measured", 1_000).expect("mark");
    store.clear_gate_failure("1").expect("clear");
    assert_eq!(store.gate_failure("1").expect("read"), None);

    // 清完之后重新开始计数，而不是接着上一次。
    store.mark_gate_failure("1", "no_strategy", 50_000).expect("mark again");
    let gate = store.gate_failure("1").expect("read").expect("marked");
    assert_eq!(gate.since, 50_000, "清完之后起点该是这一次的时刻");
    assert_eq!(gate.passes, 1, "趟数没清零，下一次判定会立刻到期");
}

/// 没有标记的模组读回 None，不是一个零值。
#[test]
fn an_unmarked_registration_reads_as_none() {
    let store = store();
    store.register_modem(&adopted("1")).expect("adopt");
    assert_eq!(store.gate_failure("1").expect("read"), None);
    // 根本不在注册表里的也一样，而不是报错。
    assert_eq!(store.gate_failure("nope").expect("read"), None);
}

/// 摘掉：纳管行没了，履历留下了。
#[test]
fn retiring_removes_the_registration_and_keeps_the_provenance() {
    let mut store = store();
    store.register_modem(&adopted("868019060490134")).expect("adopt");
    assert!(store.retire_modem(&retirement("868019060490134")).expect("retire"));

    assert!(
        !store.is_registered("868019060490134").expect("read"),
        "纳管行还在，等于什么都没做"
    );
    let kept = store
        .retired_registration("868019060490134")
        .expect("read")
        .expect("履历还在");
    assert_eq!(kept.registered_by, "panel");
    assert_eq!(kept.registered_at, 1_700_000_000_000);
    assert_eq!(kept.reason, "never_measured");
    assert_eq!(kept.matrix_version.as_deref(), Some("2026-09-01T03:32:24Z"));
    assert_eq!(store.list_retirements().expect("list").len(), 1);
}

/// 🔴 手动解绑**不**留退休记录。
///
/// 那是人做的决定，人知道原因；而且它不该在重新纳管时被自动复原 ——
/// 一次手动解绑之后再纳管，是一次**新的**决定，registered_at 就该是今天。
/// 退休记录的唯一用途是复原自动摘除所抹掉的履历。
#[test]
fn a_manual_unregister_leaves_no_retirement() {
    let store = store();
    store.register_modem(&adopted("1")).expect("adopt");
    assert!(store.unregister_modem("1").expect("unregister"));
    assert_eq!(store.retired_registration("1").expect("read"), None);
    assert!(store.list_retirements().expect("list").is_empty());
}

/// 履历复原之后，退休记录可以走。
#[test]
fn a_retirement_can_be_forgotten_once_the_provenance_is_restored() {
    let mut store = store();
    store.register_modem(&adopted("1")).expect("adopt");
    store.retire_modem(&retirement("1")).expect("retire");
    assert!(store.forget_retirement("1").expect("forget"));
    assert_eq!(store.retired_registration("1").expect("read"), None);
    assert!(!store.forget_retirement("1").expect("forget again"), "第二次该是 false");
}

/// 摘掉一根从没纳管过的，退休表不该凭空长出一行说它曾被管过。
#[test]
fn retiring_something_never_registered_reports_it_did_not_happen() {
    let mut store = store();
    assert!(
        !store.retire_modem(&retirement("1")).expect("retire"),
        "没有纳管行可删，返回值必须说出来"
    );
}

/// 🔴 重新纳管是一次**新的决定**，倒计时必须归零。
///
/// 场景：运维看到「闸不再满足，还需 8 分钟」的告警，检查后确认这是一次
/// 矩阵手误，手动把这一根重新纳管一次以示确认。如果 gate_failed_* 原样
/// 留着，下一趟真判定会带着那个旧的起点立刻到期 —— 运维的动作不但没有
/// 重置倒计时，反而什么都没改变。
#[test]
fn re_adopting_resets_the_countdown() {
    let store = store();
    store.register_modem(&adopted("1")).expect("adopt");
    store.mark_gate_failure("1", "never_measured", 1_000).expect("mark");
    store.mark_gate_failure("1", "never_measured", 9_000).expect("mark");

    store.register_modem(&adopted("1")).expect("re-adopt");
    assert_eq!(
        store.gate_failure("1").expect("read"),
        None,
        "重新纳管没有清掉倒计时，运维的确认动作等于没做"
    );
}

/// 阴性对照：重新纳管**不**改写首次纳管的时间与来源。
///
/// 这条是 0015 已有的保证（tests/registered_modems.rs 钉过），
/// 上面那条修改的是同一个 ON CONFLICT，不能顺手把它破坏掉。
#[test]
fn re_adopting_still_preserves_the_original_provenance() {
    let store = store();
    store.register_modem(&adopted("1")).expect("adopt");
    let mut again = adopted("1");
    again.registered_at = 9_999_999;
    again.registered_by = "cloud".into();
    store.register_modem(&again).expect("re-adopt");

    let row = store
        .registered_modems()
        .expect("read")
        .into_iter()
        .find(|row| row.imei == "1")
        .expect("still there");
    assert_eq!(row.registered_at, 1_700_000_000_000, "首次纳管时间被改写了");
    assert_eq!(row.registered_by, "panel", "首次纳管来源被改写了");
}
