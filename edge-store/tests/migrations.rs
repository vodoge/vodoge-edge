use edge_store::Store;

#[test]
fn migrate_and_rollback() {
    let mut store = Store::open_in_memory().expect("open");
    assert_eq!(store.schema_version().expect("version"), 3);

    store
        .enqueue(1, "11111111-1111-1111-1111-111111111111", "SmsReceived", b"{}", false)
        .expect("enqueue");
    assert_eq!(store.next_seq().expect("next"), 2);
    assert_eq!(store.ack_through(1).expect("ack"), 1);

    store.rollback_to(0).expect("rollback");
    assert_eq!(store.schema_version().expect("rolled"), 0);

    store.migrate().expect("re-upgrade");
    assert_eq!(store.schema_version().expect("upgraded"), 3);
    assert_eq!(store.next_seq().expect("empty after rebuild"), 1);
}
