use edge_store::Store;

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
            iccid: Some("8986".into()),
            state: "registered".into(),
            last_seen: Some(11),
            mcc: Some(460),
            mnc: Some(1),
        home_mcc: None,
        home_mnc: None,
        imsi: None,
        })
        .expect("upsert after rebuild");

    let modems = store.list_local_modems().expect("list");
    assert_eq!(modems.len(), 1);
    assert_eq!(modems[0].mcc, Some(460));
    assert_eq!(modems[0].mnc, Some(1));
}
