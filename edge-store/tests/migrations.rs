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
