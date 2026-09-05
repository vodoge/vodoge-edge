//! Adopting a module, and the one-time migration that keeps a running bench
//! running.

use edge_store::{LocalModem, RegisteredModem, Store, REGISTRY_MIGRATION};

fn store() -> Store {
    Store::open_in_memory().expect("open")
}

/// A minimally populated observation. `LocalModem` has no `Default` on
/// purpose -- every field is something the agent actually read -- so the test
/// spells out the ones it needs.
fn seen(imei: &str) -> LocalModem {
    LocalModem {
        imei: imei.to_owned(),
        family: "EC20".into(),
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
        discovery: "qmi".into(),
        manageable: true,
        control_port: Some("/dev/cdc-wdm0".into()),
    }
}

fn adopted(imei: &str, by: &str) -> RegisteredModem {
    RegisteredModem {
        imei: imei.to_owned(),
        registered_at: 1_700_000_000_000,
        registered_by: by.to_owned(),
        usb_device: Some("1-1.2".into()),
        family: Some("EC20".into()),
        note: None,
    }
}

/// 🔴 The migration adopts whatever the agent was already managing.
///
/// Without it, the first start after the upgrade manages nothing: every module
/// drops to "candidate", the bench stops, and somebody has to re-adopt
/// hardware that was working five seconds earlier.
///
/// Reproduces the upgrade rather than describing it -- roll back to the schema
/// that predates the registry, record modules the way an older agent would
/// have, then migrate forward and check they were adopted. An earlier version
/// of this test rolled back to 0, which drops `local_modems` too, so there was
/// nothing to adopt and it asserted nothing.
#[test]
fn the_migration_adopts_modules_already_being_managed() {
    let mut store = store();
    let latest = store.schema_version().expect("version");

    // ⚠️ 具名，不是 `latest - 1`。那个写法把「注册表迁移是最后一条」编进了
    //    算式，而它在 0016 落地的那一刻就不成立了 —— 回滚不再跨过 0015，
    //    这条测试照常绿，断言的却是一次没发生过的迁移。
    store
        .rollback_to(REGISTRY_MIGRATION - 1)
        .expect("roll back to before the registry");
    // 前提本身也要钉住：回滚之后那张表必须真的不在。
    // 只断言结果的话，下一次编号漂移还是会让这条测试变空。
    assert!(
        !store.has_table("registered_modems").expect("introspect"),
        "回滚没有跨过注册表迁移，下面那段就不是在测迁移"
    );
    // An older agent's inventory: seen and managed, with no registry to be in.
    store.upsert_local_modem(&seen("862547055142811")).expect("older agent");
    store.upsert_local_modem(&seen("867018069509705")).expect("older agent");

    store.migrate().expect("upgrade");
    assert_eq!(store.schema_version().expect("version"), latest);

    let adopted = store.registered_modems().expect("read");
    let imeis: Vec<&str> = adopted.iter().map(|row| row.imei.as_str()).collect();
    assert_eq!(
        imeis,
        vec!["862547055142811", "867018069509705"],
        "everything the older agent managed must still be managed"
    );
    assert!(
        adopted.iter().all(|row| row.registered_by == "migration"),
        "adopted by the upgrade, and distinguishable from one a person chose"
    );
}

/// Replaying the upgrade produces one row per module, not a duplicate.
#[test]
fn replaying_the_migration_is_a_no_op() {
    let mut store = store();
    let latest = store.schema_version().expect("version");

    store.rollback_to(REGISTRY_MIGRATION - 1).expect("roll back");
    store.upsert_local_modem(&seen("862547055142811")).expect("older agent");
    store.migrate().expect("upgrade");
    store.migrate().expect("upgrade again");

    assert_eq!(store.registered_modems().expect("read").len(), 1);
}


/// Adopting twice is not an error. The panel and a cloud command can both do
/// it, they can race, and the second one arriving is not a fault worth
/// reporting to anybody.
#[test]
fn adopting_the_same_module_twice_is_idempotent() {
    let store = store();
    store.register_modem(&adopted("862547055142811", "panel")).expect("first");
    store.register_modem(&adopted("862547055142811", "cloud")).expect("second");

    let all = store.registered_modems().expect("read");
    assert_eq!(all.len(), 1, "one module, one row");
    assert_eq!(
        all[0].registered_by, "panel",
        "the original adopter is kept: who first chose to manage it does not \
         change because somebody re-sent the command"
    );
}

/// Refreshing the evidence must not blank what was already known. A module
/// adopted with a family and re-registered without one keeps it.
#[test]
fn re_adopting_without_evidence_does_not_erase_it() {
    let store = store();
    store.register_modem(&adopted("862547055142811", "panel")).expect("first");

    let mut thin = adopted("862547055142811", "cloud");
    thin.family = None;
    store.register_modem(&thin).expect("second");

    let all = store.registered_modems().expect("read");
    assert_eq!(all[0].family.as_deref(), Some("EC20"));
}

#[test]
fn unregistering_reports_whether_anything_was_managed() {
    let store = store();
    store.register_modem(&adopted("862547055142811", "panel")).expect("adopt");

    assert!(store.is_registered("862547055142811").expect("check"));
    assert!(store.unregister_modem("862547055142811").expect("remove"));
    assert!(!store.is_registered("862547055142811").expect("check again"));

    assert!(
        !store.unregister_modem("862547055142811").expect("again"),
        "removing what is not there is not a removal"
    );
}

/// 🔴 Unmanaging a module is a statement about the future, not a retraction of
/// what it did. Everything it carried stays.
#[test]
fn unregistering_leaves_what_the_module_did_alone() {
    let store = store();
    store
        .upsert_local_modem(&seen("862547055142811"))
        .expect("seen");
    store.register_modem(&adopted("862547055142811", "panel")).expect("adopt");

    store.unregister_modem("862547055142811").expect("remove");

    let seen = store.list_local_modems().expect("read");
    assert_eq!(
        seen.len(),
        1,
        "what the module was observed to be is not deleted by unmanaging it"
    );
}

/// Registration order is stable, so a list does not reshuffle between reads.
#[test]
fn the_registry_lists_in_adoption_order() {
    let store = store();
    let mut second = adopted("867018069509705", "panel");
    second.registered_at = 1_700_000_001_000;
    store.register_modem(&second).expect("second");
    store.register_modem(&adopted("862547055142811", "panel")).expect("first");

    let all = store.registered_modems().expect("read");
    let order: Vec<&str> = all.iter().map(|row| row.imei.as_str()).collect();
    assert_eq!(order, vec!["862547055142811", "867018069509705"]);
}
