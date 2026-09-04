use edge_store::{CapacityOutcome, DurableOutbox};
use edge_uplink::worker::Outbox;
use edge_uplink::{EnvelopeId, RetentionClass, UplinkAck};

fn envelope(name: &str) -> EnvelopeId {
    EnvelopeId::new(name).expect("id")
}

fn ack(through: u64) -> UplinkAck {
    UplinkAck::new(through, Vec::new(), false).expect("ack")
}

fn bounded(max_records: usize) -> DurableOutbox {
    DurableOutbox::from_store(edge_store::Store::open_in_memory().expect("mem"), max_records)
        .expect("outbox")
}

/// 生产里每一个 append 调用点传的都是 Protected，所以这是默认形状，不是特例。
fn append_protected(outbox: &mut DurableOutbox, name: &str) -> CapacityOutcome {
    outbox
        .append(envelope(name), "SmsReceived", name.as_bytes(), RetentionClass::Protected)
        .expect("append")
        .1
}

fn temp_db_path(tag: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "vodoge-outbox-{tag}-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    ));
    let _ = std::fs::remove_file(&path);
    path
}

#[test]
fn survives_reopen_without_losing_unacked_records() {
    let path = temp_db_path("reopen");

    {
        let mut outbox = DurableOutbox::open(&path, 100).expect("open");
        outbox
            .append(envelope("sms-1"), "SmsReceived", b"one", RetentionClass::Protected)
            .expect("append 1");
        outbox
            .append(envelope("sms-2"), "SmsReceived", b"two", RetentionClass::Evictable)
            .expect("append 2");
        outbox.observe_ack(ack(1)).expect("ack first");
        assert_eq!(outbox.committed_through(), 1);
        assert_eq!(outbox.retained_count(), 1);
    }

    let reopened = DurableOutbox::open(&path, 100).expect("reopen");
    assert_eq!(reopened.committed_through(), 1);
    assert_eq!(reopened.last_allocated(), 2);
    let replay = reopened.replay();
    assert_eq!(replay.len(), 1);
    assert_eq!(replay[0].0, 2);
    assert_eq!(replay[0].2, b"two");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn capacity_eviction_alerts_instead_of_silent_drop() {
    let mut outbox = bounded(2);
    outbox
        .append(envelope("a"), "SmsReceived", b"a", RetentionClass::Evictable)
        .expect("a");
    outbox
        .append(envelope("b"), "SmsReceived", b"b", RetentionClass::Evictable)
        .expect("b");
    let (seq, outcome) = outbox
        .append(envelope("c"), "SmsReceived", b"c", RetentionClass::Evictable)
        .expect("c");
    assert_eq!(seq, 3);
    let alert = outcome.alert().expect("capacity alert");
    assert_eq!(alert.evicted_seq, 1);
    assert_eq!(outbox.retained_count(), 2);
    let sequences: Vec<u64> = outbox.replay().into_iter().map(|row| row.0).collect();
    assert_eq!(sequences, vec![2, 3]);
}

#[test]
fn protected_records_are_not_evicted() {
    let mut outbox = bounded(1);
    outbox
        .append(
            envelope("result"),
            "CommandResult",
            b"ok",
            RetentionClass::Protected,
        )
        .expect("protected");
    let (_, outcome) = outbox
        .append(envelope("sms"), "SmsReceived", b"x", RetentionClass::Evictable)
        .expect("second");
    assert!(outcome.alert().is_some());
    let kinds: Vec<u64> = outbox.replay().into_iter().map(|row| row.0).collect();
    assert!(kinds.contains(&1), "protected seq 1 must remain");
}

/// 这条就是这次要修的 bug 本身。
///
/// 生产里 append 全部是 Protected，于是 `evict_if_needed` 找不到可淘汰的记录，
/// 旧代码 `let Some(sequence) = oldest else { return Ok(None) }` 静默返回：
/// 越过 100_000 之后不报错、不告警、不产生 CapacityAlert，队列一路涨到把磁盘
/// 吃满，而在那之前没有任何前置信号。
#[test]
fn an_all_protected_queue_says_it_is_overflowing() {
    let mut outbox = bounded(2);
    append_protected(&mut outbox, "one");
    append_protected(&mut outbox, "two");
    let outcome = append_protected(&mut outbox, "three");

    let overflow = outcome
        .overflow()
        .expect("越界且无从淘汰必须说出来，不能返回 WithinCapacity");
    assert_eq!(overflow.retained, 3);
    assert_eq!(overflow.max_records, 2);
    assert_eq!(overflow.over_by(), 1);
    assert_eq!(overflow.oldest_seq, Some(1));

    // 说出来归说出来，Protected 记录一条都不许丢：declare_loss 的红线。
    assert_eq!(outbox.retained_count(), 3);
    let sequences: Vec<u64> = outbox.replay().into_iter().map(|row| row.0).collect();
    assert_eq!(sequences, vec![1, 2, 3]);
    // ⚠️ 上面两条读的都是内存里的 state。腾地方最容易写坏的是**只删磁盘不删内存**：
    //    本次运行一切正常，重启之后记录凭空少了几条，而且没有 gap marker 解释。
    let persisted: Vec<u64> = Outbox::retained(&outbox)
        .expect("retained")
        .into_iter()
        .map(|row| row.sequence)
        .collect();
    assert_eq!(persisted, vec![1, 2, 3], "磁盘上的 Protected 记录一条都不许少");
}

/// "一切正常" 和 "满了但无从淘汰" 以前是同一个 `Ok(None)`。
/// 这条钉住的是它们必须是两个可区分的答案——不是某个具体字段的值。
#[test]
fn healthy_and_overflowing_are_different_answers() {
    let mut outbox = bounded(2);
    let first = append_protected(&mut outbox, "one");
    let second = append_protected(&mut outbox, "two");
    let third = append_protected(&mut outbox, "three");

    assert_eq!(first, CapacityOutcome::WithinCapacity);
    assert_eq!(
        second,
        CapacityOutcome::WithinCapacity,
        "刚好到上限还不算越界"
    );
    assert!(third.is_overflowing());
    assert_ne!(second, third, "健康和卡死必须不是同一个返回值");
    assert_eq!(outbox.max_records(), 2);
}

/// 越界状态是开机时就已经存在的：断网期间涨过头的库，重启后照样越界。
/// 而容量检查只在 append 里跑——不在打开时就能看见，一台已经越界的机器要等
/// 下一条短信进来才有信号，而那条短信可能正是写不进去的那条。
#[test]
fn reopening_an_over_capacity_database_is_visible_before_any_append() {
    let path = temp_db_path("overflow-reopen");
    {
        let mut outbox = DurableOutbox::open(&path, 100).expect("open");
        append_protected(&mut outbox, "one");
        append_protected(&mut outbox, "two");
        append_protected(&mut outbox, "three");
        assert!(
            outbox.capacity_overflow().is_none(),
            "上限之内不该报越界"
        );
    }

    let reopened = DurableOutbox::open(&path, 2).expect("reopen");
    let overflow = reopened
        .capacity_overflow()
        .expect("打开一个已经越界的库，不 append 也要能看出来");
    assert_eq!(overflow.retained, 3);
    assert_eq!(overflow.max_records, 2);
    let _ = std::fs::remove_file(&path);
}

/// 越界不是终身标记：云端确认之后队列被削回上限以内，机器就是健康的。
/// 否则一次断网会让这台机器在告警里永远显示故障，下一次真的卡死没人再信。
#[test]
fn draining_the_queue_clears_the_overflow() {
    let mut outbox = bounded(2);
    append_protected(&mut outbox, "one");
    append_protected(&mut outbox, "two");
    assert!(append_protected(&mut outbox, "three").is_overflowing());
    assert!(outbox.capacity_overflow().is_some());

    outbox.observe_ack(ack(3)).expect("ack");

    assert_eq!(outbox.retained_count(), 0);
    assert!(
        outbox.capacity_overflow().is_none(),
        "队列已经空了，还报越界就是假警报"
    );
    assert_eq!(
        append_protected(&mut outbox, "four"),
        CapacityOutcome::WithinCapacity
    );
}

/// 🔴 越界的时候**真的喊了**——这是整个容量改动存在的理由，而它一度零覆盖。
///
/// 2026-09-04 的对抗复核做了三个变异：删掉打印、删掉开机路径上的告警调用、
/// 删掉 append 路径上的告警调用。**三个全部保持全绿。** 也就是说，「这台机器
/// 唯一的前置信号」恰恰是唯一没人守的部分，而这正是这个仓库最忌讳的那件事
/// ——出错了，屏幕上什么都不说。
///
/// 节流标记是告警路径跑过的痕迹：只有走过 `overflow_warning` 才会被置上。
#[test]
fn crossing_the_limit_on_append_actually_raises_the_alarm() {
    let mut outbox = bounded(2);
    append_protected(&mut outbox, "one");
    append_protected(&mut outbox, "two");
    assert_eq!(
        outbox.overflow_warned_at(),
        None,
        "还没越界，不该有人喊过"
    );

    append_protected(&mut outbox, "three");
    assert!(
        outbox.overflow_warned_at().is_some(),
        "越界了却没有走过告警路径 —— 队列会一路涨到把磁盘吃满，\
         而在那之前没有任何前置信号"
    );
}

/// 🔴 开机时就已经越界的机器，**不等下一条消息进来就要喊**。
///
/// 容量检查只在 append 里跑。一台重启时就已经越界的机器要等下一条短信进来才
/// 有信号——而那条短信可能正是写不进去的那条。
#[test]
fn reopening_an_over_capacity_database_raises_the_alarm_at_boot() {
    let path = temp_db_path("overflow-boot");
    {
        let mut outbox = DurableOutbox::open(&path, 2).expect("open");
        append_protected(&mut outbox, "one");
        append_protected(&mut outbox, "two");
        append_protected(&mut outbox, "three");
    }

    let reopened = DurableOutbox::open(&path, 2).expect("reopen");
    assert!(
        reopened.overflow_warned_at().is_some(),
        "开机时就越界，却要等下一次 append 才喊 —— 而那次 append 可能正是失败的那次"
    );
    let _ = std::fs::remove_file(&path);
}

/// ⚠️ 削回上限以内之后，节流标记要清掉。
///
/// 否则队列被 ack 削下去再重新涨上来，这一次**新的**恶化会被上一轮的节流吃掉，
/// 最多再静默一整个步长才重新喊。复核指出：返回值那一半有测试，标记这一半没有。
#[test]
fn draining_back_under_the_limit_rearms_the_alarm() {
    let mut outbox = bounded(2);
    append_protected(&mut outbox, "one");
    append_protected(&mut outbox, "two");
    append_protected(&mut outbox, "three");
    assert!(outbox.overflow_warned_at().is_some(), "先让它喊过一次");

    // 削回上限以内。
    outbox.observe_ack(ack(3)).expect("ack");

    // ⚠️ 断言的是**端到端**的性质，不是标记什么时候被清。清除发生在下一次
    //    `evict_if_needed`（也就是下一次 append）里——我第一版直接断言 ack
    //    之后标记立刻为 `None`，那是我猜的时序，实际是红的。要紧的从来不是
    //    「哪一刻清的」，而是「重新涨上去会不会再喊」。
    append_protected(&mut outbox, "four");
    assert_eq!(
        outbox.overflow_warned_at(),
        None,
        "回到上限以内之后没有重新上膛"
    );

    append_protected(&mut outbox, "five");
    append_protected(&mut outbox, "six");
    assert!(
        outbox.overflow_warned_at().is_some(),
        "削回去之后重新涨上来，这一次新的恶化被上一轮的节流吃掉了 —— \
         最多要再静默一整个步长才重新喊"
    );
}
