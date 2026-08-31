use edge_store::{LocalMessage, LocalModem, LocalModemDiscovery, ManualModemProfile, Store};

#[test]
fn local_inbox_survives_duplicate_seq() {
    let store = Store::open_in_memory().expect("open");
    let first = LocalMessage {
        seq: 1,
        peer: "10086".into(),
        body: "one".into(),
        bearer: "cellular".into(),
        direction: "inbound".into(),
        received_at: 10,
        modem_imei: Some("867018069509705".into()),
    };
    store.insert_local_message(&first).expect("insert");
    store
        .insert_local_message(&LocalMessage {
            body: "replaced".into(),
            received_at: 11,
            ..first.clone()
        })
        .expect("upsert");

    let messages = store.list_local_messages().expect("list");
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].body, "replaced");
    assert_eq!(messages[0].received_at, 11);

    store
        .upsert_local_modem(&LocalModem {
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
        .expect("modem");
    let modems = store.list_local_modems().expect("modems");
    assert_eq!(modems.len(), 1);
    assert_eq!(modems[0].family, "EC20");
}

#[test]
fn discovery_keeps_an_unidentified_endpoint_visible() {
    let store = Store::open_in_memory().expect("open");
    store
        .upsert_local_modem_discovery(&LocalModemDiscovery {
            candidate_key: "qmi:usb:2-4.1".into(),
            usb_device: Some("2-4.1".into()),
            transport: "qmi".into(),
            control_port: "/dev/cdc-wdm1".into(),
            vendor_id: Some("2c7c".into()),
            product_id: Some("0125".into()),
            state: "probe_failed".into(),
            imei: None,
            detail: "QMI transport error".into(),
            last_seen: 12,
        })
        .expect("record discovery");

    let discoveries = store.list_local_modem_discoveries().expect("list discoveries");
    assert_eq!(discoveries.len(), 1);
    assert_eq!(discoveries[0].control_port, "/dev/cdc-wdm1");
    assert_eq!(discoveries[0].imei, None);
    assert_eq!(discoveries[0].state, "probe_failed");
}

#[test]
fn manual_profile_updates_and_can_be_withdrawn() {
    let store = Store::open_in_memory().expect("open");
    let first = ManualModemProfile {
        candidate_key: "at:usb:2-4.2".into(),
        usb_device: Some("2-4.2".into()),
        vendor_id: Some("2c7c".into()),
        product_id: Some("0901".into()),
        control_port: "/dev/ttyUSB8".into(),
        approved_at: 10,
    };
    store
        .upsert_manual_modem_profile(&first)
        .expect("approve candidate");
    store
        .upsert_manual_modem_profile(&ManualModemProfile {
            control_port: "/dev/ttyUSB9".into(),
            approved_at: 20,
            ..first.clone()
        })
        .expect("update approval");

    let profiles = store.list_manual_modem_profiles().expect("list approvals");
    assert_eq!(profiles.len(), 1);
    assert_eq!(profiles[0].control_port, "/dev/ttyUSB9");
    assert_eq!(profiles[0].approved_at, 20);
    assert!(store
        .remove_manual_modem_profile("at:usb:2-4.2")
        .expect("withdraw approval"));
    assert!(!store
        .remove_manual_modem_profile("at:usb:2-4.2")
        .expect("withdraw missing approval"));
    assert!(store
        .list_manual_modem_profiles()
        .expect("list after withdraw")
        .is_empty());
}

/// 🔴 A candidate key is derived from USB topology, so a module that comes
/// back on a different bus path is a *new* row rather than an update to the
/// old one. Without a prune the list grows by one per re-plug and never
/// shrinks: this bench reached sixteen rows for four modules, with one port
/// name recorded against three different IMEIs.
#[test]
fn a_sighting_nothing_has_seen_for_a_day_is_forgotten() {
    let store = Store::open_in_memory().expect("open");
    let sighting = |key: &str, seen: i64| LocalModemDiscovery {
        candidate_key: key.into(),
        usb_device: Some("2-4.1".into()),
        transport: "qmi".into(),
        control_port: "/dev/cdc-wdm1".into(),
        vendor_id: Some("2c7c".into()),
        product_id: Some("0125".into()),
        state: "probe_failed".into(),
        imei: None,
        detail: "stale".into(),
        last_seen: seen,
    };
    let day = 24 * 60 * 60 * 1000;
    let now = 10 * day;
    store
        .upsert_local_modem_discovery(&sighting("qmi:usb:2-4.1", now - day - 1))
        .expect("stale");
    store
        .upsert_local_modem_discovery(&sighting("qmi:usb:2-4.2", now - 60_000))
        .expect("fresh");

    let removed = store.forget_stale_discoveries(now - day).expect("prune");
    assert_eq!(removed, 1, "exactly the one nothing has seen");

    let left = store.list_local_modem_discoveries().expect("list");
    assert_eq!(left.len(), 1);
    assert_eq!(
        left[0].candidate_key, "qmi:usb:2-4.2",
        "the prune took the wrong row"
    );
}

/// Pruning nothing must not be an error, because that is the normal case: it
/// runs every poll and almost always has nothing to do.
#[test]
fn pruning_an_empty_table_removes_nothing_and_succeeds() {
    let store = Store::open_in_memory().expect("open");
    assert_eq!(store.forget_stale_discoveries(1_000).expect("prune"), 0);
}
