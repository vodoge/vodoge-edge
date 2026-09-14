//! 机器重装之后，把本地 journal 抬到云端游标之上。
//!
//! 🔴 这件事此前只有一段 README 里的手打 SQL，而那段 SQL 有**三种**失败方式，
//!
//! 三种都实测过：
//!
//!   ① 队列是空的（重装后最常见的状态）：
//!      `last_allocated = (SELECT MAX(seq) FROM uplink_outbox)` 拿到 NULL，
//!      而那一列是 `INTEGER NOT NULL` —— 直接报约束错误，什么都没改。
//!
//!   ② N 小于队列深度：`UPDATE uplink_outbox SET seq = seq + N` 撞唯一约束
//!      （`seq` 是 INTEGER PRIMARY KEY，按 rowid 升序改，改到一半就撞上还没挪的行）。
//!      实测：1..5 加 2 → `UNIQUE constraint failed: uplink_outbox.seq`。
//!
//!   ③ **跑两遍**。这是最糟的一种，因为它不报错：seq 又平移一次 N，而
//!      `committed_through` 还是 N，于是 `(N, 2N]` 这一段既没有记录也没有已接受的
//!      丢失声明。`UplinkState::rehydrate` 只检三件事，**不检这个区间有没有空洞**，
//!      所以 agent 正常启动 —— 然后每一次 ack 都是
//!      `AckCrossesUnresolvedSequence(N+1)`，上行永远推不动。
//!
//!      而且协议上救不回来：用 `missing_ranges` 把那段空洞声明出去，会被
//!      `MissingRangeAtOrBelowCursor` 拒掉。只能再手工改一次 SQLite。
//!
//! ⚠️ 那两条语句之间没有 BEGIN，所以 ①②③ 之外还有「第一条成过、第二条没成」的
//!    半应用状态。
//!
//! 所以这里的修复不是「平移」，是**把待发记录紧密地重编号到 N 之上**：
//! 空队列可用、不可能撞号、不留空洞（也就不可能砸死上行）、而且**幂等**。
//!
//! N 从哪来：不用查云端。`ResumeAck.committed_through` 每次重连都带着它，而那个
//! 数就是错误消息里印出来的那个（云端侧是 `app.ingress_window` 算的最长连续段，
//! 不是 `MAX(seq)` —— 两者在有空洞或剪枝过之后并不相等）。

use edge_store::{DurableOutbox, RescueOutcome, Store};
use edge_uplink::{EnvelopeId, RetentionClass, UplinkAck};

fn envelope(name: &str) -> EnvelopeId {
    EnvelopeId::new(name).expect("id")
}

fn ack(through: u64) -> UplinkAck {
    UplinkAck::new(through, Vec::new(), false).expect("ack")
}

/// 直接喂 store：`DurableOutbox::from_store` 取所有权，而这些用例要在同一个
/// store 上先排队、再修复、再重新 rehydrate。
///
/// `protected = true`：生产里每一个 append 调用点传的都是 Protected。
fn queue(store: &Store, names: &[&str]) {
    for (index, name) in names.iter().enumerate() {
        store
            .enqueue((index + 1) as i64, name, "SmsReceived", name.as_bytes(), true)
            .expect("enqueue");
    }
    store.set_cursor(0, names.len() as u64).expect("cursor");
}

#[test]
fn an_empty_queue_is_the_case_the_documented_sql_could_not_do() {
    let store = Store::open_in_memory().expect("mem");
    // 重装完、还没收到任何短信：队列空，游标 (0, 0)。
    assert_eq!(store.cursor().expect("cursor"), (0, 0));

    let outcome = store.rescue_uplink_sequence(194_653).expect("rescue");
    assert_eq!(outcome, RescueOutcome::Repaired { renumbered: 0, gaps_cleared: 0 });
    assert_eq!(store.cursor().expect("cursor"), (194_653, 194_653));

    // 而且 agent 起得来：这条路径走的就是 rehydrate。
    let outbox = DurableOutbox::from_store(store, 100_000).expect("rehydrate 拒绝了修复后的 journal");
    assert_eq!(outbox.committed_through(), 194_653);
    assert_eq!(outbox.last_allocated(), 194_653);
}

#[test]
fn a_queue_shallower_than_n_is_renumbered_densely_above_it() {
    let store = Store::open_in_memory().expect("mem");
    queue(&store, &["a", "b", "c"]);
    assert_eq!(store.cursor().expect("cursor"), (0, 3));

    let outcome = store.rescue_uplink_sequence(100).expect("rescue");
    assert_eq!(outcome, RescueOutcome::Repaired { renumbered: 3, gaps_cleared: 0 });
    assert_eq!(store.cursor().expect("cursor"), (100, 103));

    let rows = store.load_outbox().expect("rows");
    assert_eq!(
        rows.iter().map(|row| row.seq).collect::<Vec<_>>(),
        vec![101, 102, 103],
        "重编号之后必须是紧密的 N+1..N+count —— 留一个空洞就会砸死上行",
    );
    // 顺序和内容都不能变：seq 只是运输用的号，envelope_id 才是身份。
    assert_eq!(
        rows.iter().map(|row| row.envelope_id.as_str()).collect::<Vec<_>>(),
        vec!["a", "b", "c"],
    );
    assert!(rows.iter().all(|row| row.protected), "protected 标记丢了");
}

#[test]
fn a_queue_deeper_than_n_does_not_collide() {
    // 🔴 这是文档那条 SQL 会撞唯一约束的那一种：N(2) 小于队列深度(5)。
    //
    // ⚠️ 这种情形不只是「SQL 写不动」，它是**静默丢消息**那一种：老机器只发过
    //    2 条，新机器重装后又攒了 5 条并从 1 开始编号。不修的话云端 ack 到 2，
    //    而新机器会把自己的第 1、2 条（模组真的收到的消息）当成已送达删掉 ——
    //    云端从来没见过它们。所以它比「上行卡住」更糟：卡住是响的，这个不响。
    let store = Store::open_in_memory().expect("mem");
    queue(&store, &["a", "b", "c", "d", "e"]);

    let outcome = store.rescue_uplink_sequence(2).expect("rescue");
    assert_eq!(outcome, RescueOutcome::Repaired { renumbered: 5, gaps_cleared: 0 });
    assert_eq!(store.cursor().expect("cursor"), (2, 7));
    assert_eq!(
        store.load_outbox().expect("rows").iter().map(|r| r.seq).collect::<Vec<_>>(),
        vec![3, 4, 5, 6, 7],
    );
}

#[test]
fn n_just_above_the_queue_is_the_case_that_makes_the_staging_range_matter() {
    // 🔴 这一条是变异验证逼出来的。改号分两段走：先搬到一个中转区间，再落到目标。
    //    中转区间的起点如果只取「现有最大号 + 1」，那么当 N 只比现有最大号高一点
    //    时，中转区间会和**目标区间**重叠，第二段就撞号。
    //
    //    队列 1..3（最大 3），N=5：中转会是 4,5,6，而目标是 6,7,8 —— 6 撞上。
    //    起点取 `max(现有最大, 目标最大) + 1` 才和两者都不相交。
    //
    // ⚠️ 我原来的几条用例 N 都远大于队列（100、194653），中转和目标离得很远，
    //    所以把起点写错也全绿。一道只覆盖「数字差很远」的检查，覆盖不到相邻的那种。
    let store = Store::open_in_memory().expect("mem");
    queue(&store, &["a", "b", "c"]);

    let outcome = store.rescue_uplink_sequence(5).expect("rescue");
    assert_eq!(outcome, RescueOutcome::Repaired { renumbered: 3, gaps_cleared: 0 });
    assert_eq!(store.cursor().expect("cursor"), (5, 8));
    assert_eq!(
        store.load_outbox().expect("rows").iter().map(|r| r.seq).collect::<Vec<_>>(),
        vec![6, 7, 8],
    );
    assert_eq!(
        store.load_outbox().expect("rows").iter().map(|r| r.envelope_id.as_str()).collect::<Vec<_>>(),
        vec!["a", "b", "c"],
        "撞号会让某一条被覆盖或留在中转位置 —— 顺序和身份都要对得上",
    );
}

#[test]
fn running_it_twice_is_a_no_op_instead_of_bricking_the_uplink() {
    let store = Store::open_in_memory().expect("mem");
    queue(&store, &["a", "b", "c"]);

    assert_eq!(
        store.rescue_uplink_sequence(100).expect("first"),
        RescueOutcome::Repaired { renumbered: 3, gaps_cleared: 0 },
    );
    // 🔴 第二遍。文档那条 SQL 在这里会再平移一次 100，产出一个能启动但永远推不动的
    //    journal（(100, 200] 既无记录也无已接受丢失，而 rehydrate 不检这个）。
    assert_eq!(
        store.rescue_uplink_sequence(100).expect("second"),
        RescueOutcome::AlreadyAbove,
        "第二遍必须什么都不做",
    );
    assert_eq!(store.cursor().expect("cursor"), (100, 103));
    assert_eq!(
        store.load_outbox().expect("rows").iter().map(|r| r.seq).collect::<Vec<_>>(),
        vec![101, 102, 103],
    );

    // 而且它还能推进 —— 这是「没被砸死」的实际含义。
    let mut outbox = DurableOutbox::from_store(store, 100_000).expect("rehydrate");
    let deleted = outbox.observe_ack(ack(103)).expect("修复两次之后上行推不动了");
    assert_eq!(deleted, vec![101, 102, 103], "ack 应当把这三条落地并删掉");
    assert_eq!(outbox.committed_through(), 103);
}

#[test]
fn it_refuses_when_the_cloud_is_behind_the_local_journal() {
    let store = Store::open_in_memory().expect("mem");
    queue(&store, &["a", "b", "c"]);
    store.set_cursor(50, 60).expect("cursor");

    // 云端说 40，而本地已知「已提交到 50」。云端不会把提交过的东西退回去，
    // 所以这是个说不通的输入 —— 照它改会把游标往回搬。
    //
    // ⚠️ 判据必须是 `committed_through`（50）而不是 `last_allocated`（60）：
    //    N 低于 last_allocated 是**常态**，在途的记录就是那个差额。第一版拿
    //    last_allocated 做判据，于是下面那条「队列比 N 深」的用例也被一起拒了。
    let outcome = store.rescue_uplink_sequence(40).expect("rescue");
    assert_eq!(outcome, RescueOutcome::CloudWentBackwards { local_committed_through: 50 });
    assert_eq!(store.cursor().expect("cursor"), (50, 60), "拒绝的时候一个字节都不能改");
}

#[test]
fn the_repaired_journal_allocates_from_above_the_cloud_cursor() {
    let store = Store::open_in_memory().expect("mem");
    queue(&store, &["a"]);
    store.rescue_uplink_sequence(500).expect("rescue");

    let mut outbox = DurableOutbox::from_store(store, 100_000).expect("rehydrate");
    let (sequence, _) = outbox
        .append(envelope("after"), "SmsReceived", b"x", RetentionClass::Protected)
        .expect("append");
    assert_eq!(sequence, 502, "修复后的下一个号必须接在 N+count 之后");
}

#[test]
fn a_hole_in_the_band_is_what_bricks_the_uplink() {
    // 🔴 这一条不测修复，它测的是**为什么**修复必须紧密重编号。
    //
    // 手工造出「跑两遍」那种状态：游标 (100, 203)，记录在 201..203。
    // rehydrate 收下它（三条检查里没有一条管这个区间的空洞），然后 ack 永远过不去。
    let store = Store::open_in_memory().expect("mem");
    for (index, seq) in [201i64, 202, 203].iter().enumerate() {
        store
            .enqueue(*seq, &format!("env-{index}"), "SmsReceived", b"x", true)
            .expect("enqueue");
    }
    store.set_cursor(100, 203).expect("cursor");

    let mut outbox = DurableOutbox::from_store(store, 100_000)
        .expect("rehydrate 现在拒绝空洞了 —— 那这条注释要改，修复的理由也变了");
    let error = outbox.observe_ack(ack(203)).expect_err("居然推进成功了");
    assert!(
        format!("{error:?}").contains("AckCrossesUnresolvedSequence"),
        "空洞导致的失败换了形状：{error:?}",
    );
}

#[test]
fn the_rescue_survives_a_reopen() {
    let path = std::env::temp_dir().join(format!(
        "vodoge-rescue-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    ));
    let _ = std::fs::remove_file(&path);

    {
        let store = Store::open(&path).expect("open");
        queue(&store, &["a", "b"]);
        store.rescue_uplink_sequence(9_000).expect("rescue");
    }
    {
        let outbox = DurableOutbox::open(&path, 100_000).expect("reopen");
        assert_eq!(outbox.committed_through(), 9_000);
        assert_eq!(outbox.last_allocated(), 9_002);
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn the_cursor_it_writes_is_the_one_the_uplink_reads() {
    // ⚠️ `inbox.db` 和 `outbox.db` 用的是**同一套** MIGRATIONS，所以两个文件里都有
    //    `uplink_cursor` 和 `uplink_outbox`；而上行读的是 outbox.db 那一份。
    //    README 原来写着游标在 inbox.db —— 照着做的话 `UPDATE … WHERE id = 1` 会报
    //    「1 row changed」，改的是一个没人读的游标。这条断言钉住「修复写进去的，
    //    就是 DurableOutbox 读出来的那一份」。
    let store = Store::open_in_memory().expect("mem");
    queue(&store, &["a"]);
    store.rescue_uplink_sequence(777).expect("rescue");
    let (committed, allocated) = store.cursor().expect("cursor");
    let outbox = DurableOutbox::from_store(store, 100_000).expect("rehydrate");
    assert_eq!((outbox.committed_through(), outbox.last_allocated()), (committed, allocated));
}

/// 破坏性路径不许被任何读 argv 的二进制碰到。
///
/// 🔴 README 把这件事当作一条**活的安全属性**写着：`Store::rollback_to` 会 DROP
///    十一张表，而它「reachable from tests only —— `main()` takes no arguments,
///    there are no subcommands」。在这之前那句话只是散文，一条测试都没有。
///
///    M4 加了 `uplink-rescue` 这个二进制，而它**确实**读 argv。所以那句话从
///    「这棵树里没有东西读 argv」变成了「读 argv 的那些碰不到破坏性路径」——
///    后者才是真正要保住的东西，而这条断言是它的锁。
///
/// ⚠️ 扫的是每一个 `src/bin/*.rs` 和守护进程的 `main.rs`，**从目录枚举**，
///    不是一张手写的清单 —— 下一个人加第三个二进制，这条断言会自动覆盖它。
#[test]
fn no_argv_reachable_binary_can_reach_the_destructive_path() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf();

    let mut binaries: Vec<std::path::PathBuf> = Vec::new();
    for crate_dir in std::fs::read_dir(&root).expect("workspace") {
        let crate_dir = crate_dir.expect("entry").path();
        let bin_dir = crate_dir.join("src").join("bin");
        if bin_dir.is_dir() {
            for entry in std::fs::read_dir(&bin_dir).expect("bin dir") {
                let path = entry.expect("entry").path();
                if path.extension().is_some_and(|ext| ext == "rs") {
                    binaries.push(path);
                }
            }
        }
        let daemon = crate_dir.join("src").join("main.rs");
        if daemon.is_file() {
            binaries.push(daemon);
        }
    }
    assert!(
        binaries.len() >= 3,
        "只枚举到 {} 个二进制入口 —— 枚举本身坏了（应当至少有 edge-bin 的 main.rs、\
         qmi-probe、uplink-rescue）",
        binaries.len()
    );

    let mut offenders = Vec::new();
    for path in &binaries {
        let source = std::fs::read_to_string(path).expect("read");
        // 剥掉注释再找：这个文件自己的注释里就写着 `Store::rollback_to`，
        // 而 `uplink-rescue.rs` 的文档注释里也写着 —— 不剥的话这条断言会被
        // 它自己的说明绊倒（这个仓库同一类自指的坑踩过不止一次）。
        let code: String = source
            .lines()
            .filter(|line| {
                let trimmed = line.trim_start();
                !trimmed.starts_with("//") && !trimmed.starts_with("*")
            })
            .collect::<Vec<_>>()
            .join("\n");
        if code.contains("rollback_to") {
            offenders.push(path.display().to_string());
        }
    }
    assert_eq!(
        offenders,
        Vec::<String>::new(),
        "一个读 argv 的二进制碰到了 Store::rollback_to（DROP 十一张表）。\
         README「reachable from tests only」那句话是这棵树的安全属性之一，\
         要改它得先改那句话。",
    );
}
