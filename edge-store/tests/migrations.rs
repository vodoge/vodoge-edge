use edge_store::{CardPolicy, ManualModemProfile, Store};

/// The invariant is that migrations replay to the same schema, not that there
/// happen to be N of them. Asserting the count made every added migration look
/// like a regression and taught nothing when it failed.
#[test]
fn migrate_and_rollback() {
    let mut store = Store::open_in_memory().expect("open");
    let latest = store.schema_version().expect("version");
    assert!(latest > 0, "a fresh store should be migrated, got {latest}");

    store
        .enqueue(1, "11111111-1111-1111-1111-111111111111", "SmsReceived", b"{}", false)
        .expect("enqueue");
    assert_eq!(store.next_seq().expect("next"), 2);
    assert_eq!(store.ack_through(1).expect("ack"), 1);

    store.rollback_to(0).expect("rollback");
    assert_eq!(store.schema_version().expect("rolled"), 0);

    store.migrate().expect("re-upgrade");
    assert_eq!(
        store.schema_version().expect("upgraded"),
        latest,
        "re-upgrading must land on the same schema it started from",
    );
    assert_eq!(store.next_seq().expect("empty after rebuild"), 1);
}

/// A rollback drops the tables, so the columns a later migration added have to
/// come back with it. Without this a partial replay would only surface as a
/// query error much later.
#[test]
fn a_rebuilt_store_still_holds_every_column() {
    let mut store = Store::open_in_memory().expect("open");
    store.rollback_to(0).expect("rollback");
    store.migrate().expect("re-upgrade");

    store
        .upsert_local_modem(&edge_store::LocalModem {
            imei: "867018069509705".into(),
            family: "EC20".into(),
            firmware: None,
            msisdn: None,
            msisdn_iccid: None,
            apn_contexts: None,
            iccid: Some("8986".into()),
            state: "registered".into(),
            last_seen: Some(11),
            mcc: Some(460),
            mnc: Some(1),
        home_mcc: None,
        home_mnc: None,
        imsi: None,
        discovery: "qmi".into(),
        manageable: true,
        control_port: Some("/dev/cdc-wdm0".into()),
        })
        .expect("upsert after rebuild");

    let modems = store.list_local_modems().expect("list");
    assert_eq!(modems.len(), 1);
    assert_eq!(modems[0].mcc, Some(460));
    assert_eq!(modems[0].mnc, Some(1));
}

#[test]
fn a_rebuilt_store_still_holds_manual_profiles() {
    let mut store = Store::open_in_memory().expect("open");
    store.rollback_to(0).expect("rollback");
    store.migrate().expect("re-upgrade");

    store
        .upsert_manual_modem_profile(&ManualModemProfile {
            candidate_key: "qmi:usb:2-4.1".into(),
            usb_device: Some("2-4.1".into()),
            vendor_id: Some("2c7c".into()),
            product_id: Some("0125".into()),
            control_port: "/dev/cdc-wdm1".into(),
            approved_at: 100,
        })
        .expect("approve after rebuild");

    assert_eq!(
        store
            .list_manual_modem_profiles()
            .expect("list approvals")
            .len(),
        1
    );
}

/// A push replaces the set rather than merging into it.
///
/// The cloud sends every policy it holds on every push, so a card missing from
/// the new set has had its policy withdrawn. Merging would leave that card's
/// old rules in force on the device -- the one outcome an operator who deleted
/// a policy would never expect, and one nothing upstream could detect.
#[test]
fn a_card_dropped_from_a_push_loses_its_policy() {
    let mut store = Store::open_in_memory().expect("open");
    store
        .replace_card_policies(
            &[
                CardPolicy {
                    iccid: "8985235122504221420".into(),
                    cellular_enabled: true,
                    vertical: "cn".into(),
                    apn: Some("cmnet".into()),

                    sms_send: None,

                    sms_receive: None,

                    data: None,

                    voice: None,
                },
                CardPolicy {
                    iccid: "8901240527197122156".into(),
                    cellular_enabled: false,
                    vertical: "intl".into(),
                    apn: None,

                    sms_send: None,

                    sms_receive: None,

                    data: None,

                    voice: None,
                },
            ],
            "v1",
            10,
        )
        .expect("first push");
    assert_eq!(store.list_card_policies().expect("list").len(), 2);
    assert_eq!(store.card_policy_version().expect("version").as_deref(), Some("v1"));

    let kept = store
        .card_policy("8901240527197122156")
        .expect("read")
        .expect("the card was pushed");
    assert!(!kept.cellular_enabled);
    assert_eq!(kept.vertical, "intl");
    assert_eq!(kept.apn, None);

    store
        .replace_card_policies(
            &[CardPolicy {
                iccid: "8985235122504221420".into(),
                cellular_enabled: true,
                vertical: "cn".into(),
                apn: Some("cmnet".into()),

                sms_send: None,

                sms_receive: None,

                data: None,

                voice: None,
            }],
            "v2",
            20,
        )
        .expect("second push");

    assert_eq!(store.list_card_policies().expect("list").len(), 1);
    assert_eq!(
        store.card_policy("8901240527197122156").expect("read"),
        None,
        "a card the cloud stopped listing must not keep its old rules"
    );
    assert_eq!(store.card_policy_version().expect("version").as_deref(), Some("v2"));
}

/// An empty push is a withdrawal of everything, not a no-op.
#[test]
fn an_empty_push_clears_the_set() {
    let mut store = Store::open_in_memory().expect("open");
    store
        .replace_card_policies(
            &[CardPolicy {
                iccid: "8985235122504221420".into(),
                cellular_enabled: true,
                vertical: "cn".into(),
                apn: None,

                sms_send: None,

                sms_receive: None,

                data: None,

                voice: None,
            }],
            "v1",
            10,
        )
        .expect("push");
    store.replace_card_policies(&[], "v2", 20).expect("empty push");

    assert!(store.list_card_policies().expect("list").is_empty());
    // With no rows there is no version either: the version lives on the rows
    // so it cannot outlive the set it describes.
    assert_eq!(store.card_policy_version().expect("version"), None);
}

/// 生产库是**已经存在**的：0017 走的是 `ALTER TABLE ADD COLUMN`，不是建表。
///
/// 这条测试跑的正是那条路：回滚到 16（那时候候选表没有身份列），再前进一步。
/// 从零建库的那条路每个测试都在跑，唯独升级路径没人跑过 —— 而机队上的每一台
/// 走的都是升级。
#[test]
fn the_discovery_identity_columns_arrive_by_upgrade() {
    let mut store = Store::open_in_memory().expect("open");
    let latest = store.schema_version().expect("version");

    store
        .rollback_to(edge_store::DISCOVERY_IDENTITY_MIGRATION - 1)
        .expect("roll back to before the identity columns");

    // 前提要钉住，否则下面测的就不是升级。读取侧 SELECT 了那三列，
    // 所以列不在时它必然报错 —— 这比 has_table 更贴近真实读路径。
    assert!(
        store.list_local_modem_discoveries().is_err(),
        "回滚没有跨过 0017，下面那段不是在测升级"
    );

    store.migrate().expect("upgrade");
    assert_eq!(store.schema_version().expect("version"), latest);
    assert!(
        store.list_local_modem_discoveries().is_ok(),
        "升级之后读取侧必须能用"
    );
}

/// 读不到就不覆盖 —— 三列各自都要守住。
///
/// AT-only 那条路要好几轮才读得出 IMSI，中间几轮归属网是 `None`。每轮都覆盖
/// 的话，纳管闸的输入会在「有」和「无」之间反复横跳，按钮时灵时不灵，
/// 那比一直失败更难查。型号那一列同理：生产库里出现过两行 family='0'。
#[test]
fn a_pass_that_read_nothing_does_not_erase_what_an_earlier_pass_read() {
    let store = Store::open_in_memory().expect("open");
    let mut row = edge_store::LocalModemDiscovery {
        candidate_key: "usb/1-2".into(),
        usb_device: Some("1-2".into()),
        transport: "at".into(),
        control_port: "/dev/ttyUSB12".into(),
        vendor_id: Some("2c7c".into()),
        product_id: Some("0901".into()),
        state: "found".into(),
        imei: Some("868019060490134".into()),
        detail: "identified over AT and awaiting adoption".into(),
        last_seen: 1,
        family: Some("EC200U-CN".into()),
        home_mcc: Some(460),
        home_mnc: Some(11),
    };
    store.upsert_local_modem_discovery(&row).expect("first pass");

    // 下一趟什么都没读到。
    row.family = None;
    row.home_mcc = None;
    row.home_mnc = None;
    row.last_seen = 2;
    store.upsert_local_modem_discovery(&row).expect("silent pass");

    let seen = store.list_local_modem_discoveries().expect("read");
    let kept = seen.first().expect("one row");
    assert_eq!(kept.last_seen, 2, "这一趟的时间戳照常刷新");
    assert_eq!(kept.family.as_deref(), Some("EC200U-CN"), "型号被抹掉了");
    assert_eq!(kept.home_mcc, Some(460), "归属 MCC 被抹掉了");
    assert_eq!(kept.home_mnc, Some(11), "归属 MNC 被抹掉了");

    // 而模组把型号答成 "unknown" 的那一轮，同样不许覆盖。
    row.family = Some("unknown".into());
    row.last_seen = 3;
    store.upsert_local_modem_discovery(&row).expect("unknown pass");
    let seen = store.list_local_modem_discoveries().expect("read");
    assert_eq!(
        seen.first().expect("one row").family.as_deref(),
        Some("EC200U-CN"),
        "模组答 unknown 时不该把已知型号盖掉"
    );
}

/// 「这一趟没问成」不等于「卡不在」。
///
/// QMI 那条路真的读 EF_ICCID，`None` 的意思是卡不在，照写是对的。AT 那条路
/// 只在模组支持 `+QCCID` / `+CCID` 时才问得到；问不到时 `None` 的意思是
/// 「没问成」。
///
/// 🔴 两者用同一条规则的后果是会花钱的：QMI 口一挂、轮询降级到 AT，
/// `local_modems.iccid` 被抹成空 → 卡策略按 ICCID 查、查不到就是「没有声明」
/// → `unwrap_or_default()` 放行 → 一张写着「套餐不含发短信」的卡变成能发，
/// 没有日志也没有告警。
#[test]
fn a_pass_that_could_not_ask_for_the_card_does_not_erase_it() {
    let store = Store::open_in_memory().expect("open");
    let mut row = seen_modem("868019060490134", Some("89860325743130290814"));
    store
        .upsert_local_modem_with(&row, edge_store::CardRead::Answered)
        .expect("QMI pass read the card");

    // 降级到 AT，这一趟连问都没问成。
    row.iccid = None;
    row.last_seen = Some(2);
    store
        .upsert_local_modem_with(&row, edge_store::CardRead::Unasked)
        .expect("AT pass could not ask");

    let kept = store.list_local_modems().expect("read");
    assert_eq!(
        kept.first().expect("one row").iccid.as_deref(),
        Some("89860325743130290814"),
        "没问成被当成了没卡，卡策略会因此失效"
    );

    // 而真的问过、答案是「卡不在」时，照旧要清空 —— 否则拔掉的卡永远拔不掉。
    store
        .upsert_local_modem_with(&row, edge_store::CardRead::Answered)
        .expect("QMI pass says the tray is empty");
    assert_eq!(
        store.list_local_modems().expect("read").first().expect("one row").iccid,
        None,
        "问过了、答案是没卡，就该清空"
    );
}

fn seen_modem(imei: &str, iccid: Option<&str>) -> edge_store::LocalModem {
    edge_store::LocalModem {
        imei: imei.into(),
        family: "EC200U-CN".into(),
        firmware: None,
        msisdn: None,
        msisdn_iccid: None,
        apn_contexts: None,
        iccid: iccid.map(str::to_owned),
        state: "online".into(),
        last_seen: Some(1),
        mcc: None,
        mnc: None,
        home_mcc: Some(460),
        home_mnc: Some(11),
        imsi: Some("460115778153975".into()),
        discovery: "at".into(),
        manageable: false,
        control_port: Some("/dev/ttyUSB12".into()),
    }
}
