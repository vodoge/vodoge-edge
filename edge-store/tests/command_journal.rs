use edge_store::Store;

fn store() -> Store {
    let mut store = Store::open_in_memory().expect("open");
    store.migrate().expect("migrate");
    store
}

/// 记下去、读回来。
#[test]
fn a_recorded_command_comes_back() {
    let store = store();
    store
        .record_command_phase("cmd-1", "executing", None, None, 1_000)
        .expect("record");

    let rows = store.load_command_journal().expect("load");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].cmd_id, "cmd-1");
    assert_eq!(rows[0].phase, "executing");
    assert_eq!(rows[0].result, None);
}

/// 终态一旦写下，后面的 `recorded`/`executing` 不许把它抹掉。
///
/// 🔴 这是 `COALESCE` 那两行在守的事。云端重推会让同一条命令再走一次
///    「记下来」的路径，而那两步手里没有结果 —— 直接覆盖就等于把
///    「执行过、结果是这个」退回成「不知道」，然后重放变成**重发**。
#[test]
fn a_terminal_result_is_not_erased_by_a_later_phase_write() {
    let store = store();
    store
        .record_command_phase("cmd-1", "executing", None, None, 1_000)
        .expect("executing");
    store
        .record_command_phase(
            "cmd-1",
            "terminal",
            Some(r#"{"cmd_id":"cmd-1","status":"succeeded"}"#),
            Some(7),
            2_000,
        )
        .expect("terminal");

    // 重推：又来一次「记下来」，手里没有结果。
    store
        .record_command_phase("cmd-1", "recorded", None, None, 3_000)
        .expect("recorded again");

    let rows = store.load_command_journal().expect("load");
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].result.as_deref(),
        Some(r#"{"cmd_id":"cmd-1","status":"succeeded"}"#),
        "终态结果被后来的一次写抹掉了 —— 重放会退化成重发"
    );
    assert_eq!(rows[0].result_sequence, Some(7));
}

/// 清理只丢旧的。
#[test]
fn pruning_keeps_what_is_still_inside_the_window() {
    let store = store();
    store
        .record_command_phase("old", "terminal", Some("{}"), Some(1), 1_000)
        .expect("old");
    store
        .record_command_phase("new", "terminal", Some("{}"), Some(2), 9_000)
        .expect("new");

    let removed = store.prune_command_journal(5_000).expect("prune");
    assert_eq!(removed, 1);

    let rows = store.load_command_journal().expect("load");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].cmd_id, "new");
}

/// 回滚到 0019 之前，这张表要跟着消失。
///
/// ⚠️ `rollback_to` 里那串 DROP TABLE 是手写的：漏掉一张的话，重放时
///    `CREATE TABLE IF NOT EXISTS` 会静默变成空操作，而它携带的列定义就再也
///    不会被验证 —— 这个文件里 0016 那次已经记过同一个教训。
#[test]
fn rolling_back_past_the_migration_drops_the_table() {
    let mut store = store();
    assert!(store.has_table("command_journal").expect("has table"));

    store.rollback_to(18).expect("rollback");
    assert!(
        !store.has_table("command_journal").expect("has table"),
        "回滚到 0019 之前，command_journal 还在"
    );

    store.migrate().expect("migrate again");
    assert!(store.has_table("command_journal").expect("has table"));
    // 重放之后还能用 —— 也就是那条 CREATE TABLE 真的又跑了一次。
    store
        .record_command_phase("cmd-1", "recorded", None, None, 1_000)
        .expect("record after replay");
}
