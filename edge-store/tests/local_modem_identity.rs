//! 型号是身份，不是每轮的观测值。
//!
//! `local_modems` 的 upsert 对 `firmware` / `msisdn` / `mcc` / `mnc` /
//! `home_mcc` / `home_mnc` / `imsi` 全都做了 COALESCE —— 这些是「读到了才更新」
//! 的身份事实。`family` 混在它们中间，却是**无条件覆盖**的。
//!
//! 后果不是理论上的。台架上 2026-09-05 的 `local_modems` 里就有两行
//! `family = '0'`（固件读到了 `UFI103_CT 20220801`，型号却答了 `0`），
//! 而 `ModemFamily::from("0")` 落进 `Other("0")`，能力矩阵里没有它 ——
//! 纳管的第二道闸会把这一对判成「从没测过」。
//!
//! 最可能踩到的恰好是最脆弱的那一根：`at_family("", "")` 返回 `"unknown"`，
//! 而只走 AT 的 EC200U 有规律地挂死约 15 分钟。挂在探测中途，型号和固件
//! 都读回空串，这一根的型号就被写成了 `unknown`。

use edge_store::{LocalModem, Store};

fn seen(imei: &str, family: &str) -> LocalModem {
    LocalModem {
        imei: imei.to_owned(),
        family: family.to_owned(),
        firmware: None,
        msisdn: None,
        msisdn_iccid: None,
        apn_contexts: None,
        iccid: None,
        state: "registered".into(),
        last_seen: Some(1_700_000_000_000),
        mcc: None,
        mnc: None,
        home_mcc: None,
        home_mnc: None,
        imsi: None,
        discovery: "at".into(),
        manageable: false,
        control_port: Some("/dev/ttyUSB12".into()),
    }
}

fn family_of(store: &Store, imei: &str) -> String {
    store
        .list_local_modems()
        .expect("read")
        .into_iter()
        .find(|modem| modem.imei == imei)
        .expect("the row is there")
        .family
}

/// 🔴 一次读不出型号，不该抹掉上一次读出来的。
#[test]
fn an_unreadable_family_does_not_overwrite_a_known_one() {
    let store = Store::open_in_memory().expect("open");
    store
        .upsert_local_modem(&seen("868019060490134", "EC200U-CN"))
        .expect("first observation");
    // AT 通道挂死那一轮：at+cgmm 和 at+cgmr 都答空串，
    // `ModemFamily::detect_name` 于是返回 "unknown"。
    store
        .upsert_local_modem(&seen("868019060490134", "unknown"))
        .expect("degraded observation");
    assert_eq!(
        family_of(&store, "868019060490134"),
        "EC200U-CN",
        "一轮探测退化就把型号抹成 unknown，闸 2 立刻把这一对判成没测过"
    );
}

/// 空串同理 —— 它和 "unknown" 是同一件事的两种写法。
#[test]
fn an_empty_family_does_not_overwrite_a_known_one() {
    let store = Store::open_in_memory().expect("open");
    store.upsert_local_modem(&seen("1", "EC20")).expect("first");
    store.upsert_local_modem(&seen("1", "")).expect("degraded");
    assert_eq!(family_of(&store, "1"), "EC20");
}

/// 阴性对照：真的读出了一个**不同的**型号，要覆盖。
///
/// 没有这条，上面两条可以靠「family 永不更新」通过，而那会让一根从未被
/// 正确识别过的模组永远停在第一次的错误答案上。
#[test]
fn a_real_reading_still_replaces_the_stored_family() {
    let store = Store::open_in_memory().expect("open");
    store.upsert_local_modem(&seen("2", "EC20")).expect("first");
    store.upsert_local_modem(&seen("2", "EC25-CN")).expect("second");
    assert_eq!(family_of(&store, "2"), "EC25-CN");
}

/// 第一次观测就读不出型号时，还是要落一行 —— 那是真话，而且面板要显示它。
///
/// ⚠️ 这一条钉住的是「保守只针对**覆盖**」。把 unknown 也拒之门外会让一根
/// 认不出的模组在库里根本不存在，运维连它插着都看不到。
#[test]
fn a_first_sighting_records_unknown_rather_than_nothing() {
    let store = Store::open_in_memory().expect("open");
    store.upsert_local_modem(&seen("3", "unknown")).expect("first");
    assert_eq!(family_of(&store, "3"), "unknown");
}

/// `Other(_)` 里的垃圾**不**在这里拦。
///
/// 台架上那两行 `family = '0'` 就是这个形状：模组真的答了 `0`。代码分不出
/// `"0"` 和 `"SIM7600G"` —— 后者是一个合法的、只是本 build 不认识的型号。
/// 在这一层猜哪个是垃圾，就会把「这个 build 不认识的硬件」和「模组答了废话」
/// 混成一件事。这一条属于判定层：追溯执行对 `Other(_)` 维持现状并告警，
/// 而不是解绑。
#[test]
fn an_unrecognised_but_real_answer_is_stored_as_given() {
    let store = Store::open_in_memory().expect("open");
    store.upsert_local_modem(&seen("4", "EC20")).expect("first");
    store.upsert_local_modem(&seen("4", "SIM7600G")).expect("second");
    assert_eq!(family_of(&store, "4"), "SIM7600G");
}
