use edge_store::{LocalMessage, LocalModem, Store};

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
            iccid: Some("8986".into()),
            state: "registered".into(),
            last_seen: Some(11),
        mcc: Some(460),
        mnc: Some(1),
        home_mcc: None,
        home_mnc: None,
        imsi: None,
        })
        .expect("modem");
    let modems = store.list_local_modems().expect("modems");
    assert_eq!(modems.len(), 1);
    assert_eq!(modems[0].family, "EC20");
}
