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

/// 🔴 号码不许活得比它的卡久。
///
/// 0011 建 `msisdn_iccid` 这一列时就把理由写下来了：「没有它，一个号码会活得
/// 比它的卡还久、被显示在下一张卡名下 —— 那比什么都不显示更坏，因为它是一个
/// 看起来合理的错答案。」
///
/// 但那一列当时只被用作缓存判据（「这个号是不是已经知道了」），没有用来作废。
/// 于是换卡之后如果新卡的号一时读不出来，upsert 的无条件 COALESCE 会把旧号
/// 原样留着 —— 而运维正是靠这个字段认卡的。
#[test]
fn a_number_does_not_outlive_the_card_it_was_read_from() {
    let store = Store::open_in_memory().expect("open");

    // 第一张卡，号码读到了。
    let mut row = modem_with_card("867018069509705", Some("8986003031401770106"));
    row.msisdn = Some("+8613800138000".into());
    row.msisdn_iccid = Some("8986003031401770106".into());
    store.upsert_local_modem(&row).expect("first card");

    // 换了一张卡，而新卡的号这一轮没读出来（AT+CNUM 失败，snapshot.msisdn 是 None）。
    row.iccid = Some("8985200014632179571".into());
    row.imsi = Some("454003063217957".into());
    row.home_mcc = Some(454);
    row.home_mnc = Some(0);
    row.msisdn = None;
    row.msisdn_iccid = None;
    store.upsert_local_modem(&row).expect("second card");

    let seen = store.list_local_modems().expect("read");
    let kept = seen.first().expect("one row");
    assert_eq!(kept.iccid.as_deref(), Some("8985200014632179571"), "卡换了");
    assert_eq!(
        kept.msisdn, None,
        "上一张卡的号码活了下来 —— 屏幕上会把它显示成这张新卡的号"
    );
    assert_eq!(kept.msisdn_iccid, None, "指向旧卡的凭据也该跟着走");
}

/// 卡没换时，读不到号码仍要保住上一次读到的 —— 这才是 COALESCE 的正当用途。
#[test]
fn the_same_card_keeps_the_number_a_failed_read_could_not_repeat() {
    let store = Store::open_in_memory().expect("open");
    let mut row = modem_with_card("867018069509705", Some("8986003031401770106"));
    row.msisdn = Some("+8613800138000".into());
    row.msisdn_iccid = Some("8986003031401770106".into());
    store.upsert_local_modem(&row).expect("first pass");

    // 同一张卡，这一轮没读到号。
    row.msisdn = None;
    row.msisdn_iccid = None;
    store.upsert_local_modem(&row).expect("silent pass");

    let seen = store.list_local_modems().expect("read");
    let kept = seen.first().expect("one row");
    assert_eq!(
        kept.msisdn.as_deref(),
        Some("+8613800138000"),
        "卡没换，读一次失败不该把号码抹掉"
    );
}

/// 归属网和 IMSI 也是卡上的事实，同一条规则。
#[test]
fn the_home_network_belongs_to_the_card_too() {
    let store = Store::open_in_memory().expect("open");
    let mut row = modem_with_card("867018069509705", Some("8986003031401770106"));
    row.imsi = Some("460026303803275".into());
    row.home_mcc = Some(460);
    row.home_mnc = Some(2);
    store.upsert_local_modem(&row).expect("first card");

    // 换卡，新卡这一轮还没读出归属网。
    row.iccid = Some("8985200014632179571".into());
    row.imsi = None;
    row.home_mcc = None;
    row.home_mnc = None;
    store.upsert_local_modem(&row).expect("second card");

    let seen = store.list_local_modems().expect("read");
    let kept = seen.first().expect("one row");
    assert_eq!(kept.home_mcc, None, "上一张卡的归属网活了下来 —— 闸 2 会拿它做判定");
    assert_eq!(kept.imsi, None, "上一张卡的 IMSI 活了下来");
}

fn modem_with_card(imei: &str, iccid: Option<&str>) -> edge_store::LocalModem {
    edge_store::LocalModem {
        imei: imei.into(),
        family: "EC20".into(),
        firmware: None,
        msisdn: None,
        msisdn_iccid: None,
        apn_contexts: None,
        iccid: iccid.map(str::to_owned),
        state: "online".into(),
        last_seen: Some(1),
        mcc: None,
        mnc: None,
        home_mcc: None,
        home_mnc: None,
        imsi: None,
        discovery: "qmi".into(),
        manageable: true,
        control_port: Some("/dev/cdc-wdm0".into()),
    }
}

/// 🔴 一根读不出卡号的模组，它的号码不能每一轮都被擦掉。
///
/// 这条钉的是继承判断里 `IS` 而不是 `=` 那个选择。AT-only 那条路曾经完全不读
/// ICCID（现在读了，但仍可能读不到：卡槽空、或者这块硬件既不答 `+QCCID` 也不答
/// `+CCID`），而 `AT+CNUM` 可能照样答得出号码。
///
/// 这时 `msisdn_iccid` 和当前 iccid **两边都是 NULL**。SQLite 里 `NULL = NULL`
/// 求值成 NULL 而不是真，于是用 `=` 写的话每一轮都落进 ELSE 把刚读到的号码
/// 擦掉 —— 屏幕上那一格会闪，而没有任何地方报错。`IS` 是空安全的，两边都
/// NULL 算相等。
#[test]
fn a_modem_with_no_readable_card_number_still_keeps_its_phone_number() {
    let store = Store::open_in_memory().expect("open");

    // 读不出 ICCID，但读到了号码。
    let mut row = modem_with_card("868019060490134", None);
    row.msisdn = Some("+8613900139000".into());
    row.msisdn_iccid = None;
    store.upsert_local_modem(&row).expect("first pass");

    // 下一轮：卡号照样读不出来，号码这一轮也没重读。
    row.msisdn = None;
    row.msisdn_iccid = None;
    store.upsert_local_modem(&row).expect("second pass");

    let seen = store.list_local_modems().expect("read");
    assert_eq!(
        seen.first().expect("one row").msisdn.as_deref(),
        Some("+8613900139000"),
        "两边都没有卡号时被判成了「换卡」，号码每一轮都会被擦掉"
    );
}
