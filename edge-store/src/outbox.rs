use edge_uplink::{
    EnvelopeId, GapId, RetentionClass, UplinkAck, UplinkError, UplinkGap, UplinkRecord, UplinkState,
};
use edge_uplink::worker::{Outbox, RetainedRecord};

use crate::{Store, StoreError};

/// Default capacity from the blueprint: 100_000 retained records.
pub const DEFAULT_MAX_RECORDS: usize = 100_000;

/// 越界之后每再涨这么多条记录，才允许再喊一次。
///
/// ⚠️ 告警本身写的是 stderr → journald → 磁盘，而这里要防的恰恰是磁盘被写满。
///    每 append 一次就喊一次，等于用日志去加速我们正在报警的那件事。
const OVERFLOW_WARN_STRIDE: usize = 1_000;

/// Alert produced when capacity eviction actually drops an evictable record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapacityAlert {
    pub gap_id: String,
    pub evicted_seq: u64,
}

/// 队列已经越过 `max_records`，而且一条可淘汰的记录都没有。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapacityOverflow {
    /// 当前保留的记录条数（已经大于 `max_records`）。
    pub retained: usize,
    /// 名义上限。它此刻是**没有约束力**的，这正是要告警的原因。
    pub max_records: usize,
    /// 队头那条挡着不能淘汰的记录，用来判断是哪一类 envelope 把队列焊死了。
    pub oldest_seq: Option<u64>,
}

impl CapacityOverflow {
    /// 超出上限多少条。
    pub const fn over_by(&self) -> usize {
        self.retained.saturating_sub(self.max_records)
    }
}

impl std::fmt::Display for CapacityOverflow {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "outbox over capacity: {} retained against a limit of {} (over by {}), \
             and not one record is evictable",
            self.retained,
            self.max_records,
            self.over_by()
        )?;
        if let Some(sequence) = self.oldest_seq {
            write!(formatter, "; head of line is seq {sequence}")?;
        }
        write!(
            formatter,
            "; the queue will keep growing until the disk fills"
        )
    }
}

/// 一次容量检查的结局。
///
/// 🔴 这三个分支必须分开返回，绝不能再退回 `Option<CapacityAlert>`。
///    旧代码里 "还没满" 和 "满了但没有任何东西可以淘汰" 都是 `Ok(None)`：
///    调用点无从区分，于是队列越过 100_000 之后既不报错也不告警，
///    一路涨到把边缘机磁盘吃满——那一刻短信入库和上行一起失败，
///    而在那之前**没有任何前置信号**。
/// ⚠️ 而且 `Overflowing` 不是理论分支：生产代码里所有 append 都传
///    `RetentionClass::Protected`（`Evictable` 出现 0 次），所以只要断网够久，
///    必然走到这一支。淘汰机制形同虚设这件事，只能靠这个返回值说出来。
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapacityOutcome {
    /// 还在 `max_records` 以内，什么都没做。
    WithinCapacity,
    /// 淘汰了最老的一条 `Evictable`，并留下 gap marker 顶替它的位置。
    Evicted(CapacityAlert),
    /// 🔴 已经越界，但没有一条记录可以淘汰：此刻队列是无上限增长的。
    Overflowing(CapacityOverflow),
}

impl CapacityOutcome {
    pub const fn alert(&self) -> Option<&CapacityAlert> {
        match self {
            Self::Evicted(alert) => Some(alert),
            _ => None,
        }
    }

    pub const fn overflow(&self) -> Option<&CapacityOverflow> {
        match self {
            Self::Overflowing(overflow) => Some(overflow),
            _ => None,
        }
    }

    /// 队列此刻是否处于"越界且无从淘汰"的状态——需要人看见的那个状态。
    pub const fn is_overflowing(&self) -> bool {
        matches!(self, Self::Overflowing(_))
    }
}

/// SQLite-backed journal. Mutations go to disk before in-memory state is used
/// as the send set, matching "commit locally, then upload".
pub struct DurableOutbox {
    store: Store,
    state: UplinkState,
    max_records: usize,
    /// 上一次为越界告警时的记录条数；`None` 表示当前不在越界状态。
    /// 只服务于告警的节流，不参与任何持久化状态。
    overflow_warned_at: Option<usize>,
}

impl DurableOutbox {
    pub fn open_in_memory() -> Result<Self, QueueError> {
        Self::from_store(Store::open_in_memory()?, DEFAULT_MAX_RECORDS)
    }

    pub fn open(
        path: impl AsRef<std::path::Path>,
        max_records: usize,
    ) -> Result<Self, QueueError> {
        Self::from_store(Store::open(path)?, max_records)
    }

    pub fn from_store(store: Store, max_records: usize) -> Result<Self, QueueError> {
        let (committed_through, last_allocated) = store.cursor()?;
        let mut records = Vec::new();
        for row in store.load_outbox()? {
            let retention = if row.protected {
                RetentionClass::Protected
            } else {
                RetentionClass::Evictable
            };
            records.push(UplinkRecord::restore(
                row.seq,
                EnvelopeId::new(row.envelope_id)?,
                row.payload,
                retention,
            ));
        }
        let state = UplinkState::rehydrate(committed_through, last_allocated, records)?;
        let mut outbox = Self {
            store,
            state,
            max_records: max_records.max(1),
            overflow_warned_at: None,
        };
        // ⚠️ 越界状态是**开机时就已经存在**的：断网期间涨过头的库重启后照样越界，
        //    而淘汰检查只在 append 里跑。不在这里喊一声，一台已经越界的机器
        //    要等到下一条短信进来才有信号——而"下一条短信"可能正是写不进去的那条。
        if let Some(overflow) = outbox.capacity_overflow() {
            outbox.warn_overflow(&overflow);
        }
        Ok(outbox)
    }

    pub fn committed_through(&self) -> u64 {
        self.state.committed_through()
    }

    pub fn last_allocated(&self) -> u64 {
        self.state.last_allocated()
    }

    pub fn retained_count(&self) -> usize {
        self.state.retained_records().count()
    }

    /// Persist a new sequenced envelope, then make it visible for replay.
    ///
    /// 🔴 越界（`CapacityOutcome::Overflowing`）不走 `Err`，尽管它确实是个故障。
    ///    因为记录**已经落库了**：这个函数先 enqueue 再做容量检查。返回 Err
    ///    等于对调用点撒谎说"没存进去"，而 edge-bin 的调用点是
    ///    `append 成功之后才 send_envelope` ——报个假错会把一条明明在队列里的
    ///    记录挡在上行之外，等于用"断网时不再上传"来处理"断网太久"。
    ///    所以：照常 Ok，但把越界这件事放进返回值里说清楚。
    pub fn append(
        &mut self,
        envelope_id: EnvelopeId,
        kind: &str,
        payload: impl Into<Vec<u8>>,
        retention: RetentionClass,
    ) -> Result<(u64, CapacityOutcome), QueueError> {
        let payload = payload.into();
        let mut next = self.state.clone();
        let sequence = next.append(envelope_id.clone(), payload.clone(), retention)?;
        self.store.enqueue(
            sequence as i64,
            envelope_id.as_str(),
            kind,
            &payload,
            retention == RetentionClass::Protected,
        )?;
        self.store
            .set_cursor(next.committed_through(), next.last_allocated())?;
        self.state = next;
        let outcome = self.evict_if_needed()?;
        Ok((sequence, outcome))
    }

    pub fn observe_ack(&mut self, ack: UplinkAck) -> Result<Vec<u64>, QueueError> {
        let outcome = self.state.observe_ack(ack)?;
        if !outcome.deleted_sequences.is_empty() {
            self.store.delete_sequences(&outcome.deleted_sequences)?;
        }
        self.store
            .set_cursor(self.state.committed_through(), self.state.last_allocated())?;
        Ok(outcome.deleted_sequences)
    }

    pub fn replay(&self) -> Vec<(u64, String, Vec<u8>)> {
        self.state
            .retained_records()
            .map(|record| {
                (
                    record.sequence(),
                    record.envelope_id().as_str().to_owned(),
                    record.payload().to_vec(),
                )
            })
            .collect()
    }

    pub fn lowest_retained_seq(&self) -> Option<u64> {
        self.state.retained_records().next().map(|record| record.sequence())
    }

    pub fn pending_gap_ids(&self) -> Vec<String> {
        self.state
            .pending_gaps()
            .map(|gap| gap.gap_id().as_str().to_owned())
            .collect()
    }

    pub fn queue_records(&self) -> i64 {
        self.retained_count() as i64
    }

    pub fn queue_bytes(&self) -> Option<i64> {
        Some(
            self.state
                .retained_records()
                .map(|record| record.payload().len() as i64)
                .sum(),
        )
    }

    /// 名义上限。上层要把它和 `queue_records` 一起报上去才谈得上有人看得见。
    pub const fn max_records(&self) -> usize {
        self.max_records
    }

    /// 此刻是否越界且无从淘汰。`None` 表示没有这个问题。
    ///
    /// ⚠️ "越界但还有 Evictable 可淘汰" 返回 `None`，因为那是下一次 append
    ///    就会自己消化掉的瞬时状态；这里要回答的是"卡死了没有"。
    pub fn capacity_overflow(&self) -> Option<CapacityOverflow> {
        let retained = self.retained_count();
        if retained <= self.max_records || self.oldest_evictable().is_some() {
            return None;
        }
        Some(CapacityOverflow {
            retained,
            max_records: self.max_records,
            oldest_seq: self.state.retained_records().next().map(|r| r.sequence()),
        })
    }

    /// 最老的一条可淘汰记录。
    ///
    /// 🔴 只认 `Evictable`：`declare_loss` 对 Protected 记录会直接
    ///    `ProtectedRecordCannotBeEvicted`，那是协议层的红线——Protected
    ///    意味着"丢了必须有人知道"，不能用一条 gap marker 顶掉。
    fn oldest_evictable(&self) -> Option<u64> {
        self.state
            .retained_records()
            .find(|record| record.retention() == RetentionClass::Evictable)
            .map(|record| record.sequence())
    }

    /// 越界告警。节流见 `OVERFLOW_WARN_STRIDE`。
    ///
    /// ⚠️ 走 stderr 是因为 edge-store 里没有 logger，而 edge-bin 是 journald 下的
    ///    服务，stderr 会进同一份日志（`Store::open` 的 WAL 回退也是这么喊的）。
    ///    调用点今天把 append 的第二个返回值全丢了（`Ok((seq, _))`），所以在它们
    ///    接上之前，这一行是这台机器唯一的前置信号。
    /// 决定这一次越界要不要喊，要喊就把那句话交出来。
    ///
    /// 🔴 **返回 `Option<String>` 而不是就地 `eprintln!`，是为了让「有没有喊」
    /// 这件事测得到。**
    ///
    /// 第一版是直接 `eprintln!`。2026-09-04 的对抗复核做了三个变异——删掉那行
    /// `eprintln!`、删掉开机路径上的调用、删掉 append 路径上的调用——**三个全
    /// 部保持全绿**。也就是说：整个改动的存在理由（「这台机器唯一的前置信号」）
    /// 恰恰是唯一零覆盖的部分，而这正是这个仓库最忌讳的那件事——出错了，屏幕上
    /// 什么都不说。
    ///
    /// 现在打印那一步留在调用点，判决在这里，两条路径各有一条测试盯着。
    fn overflow_warning(&mut self, overflow: &CapacityOverflow) -> Option<String> {
        if !overflow_warning_due(overflow.retained, self.overflow_warned_at) {
            return None;
        }
        self.overflow_warned_at = Some(overflow.retained);
        Some(overflow.to_string())
    }

    fn warn_overflow(&mut self, overflow: &CapacityOverflow) {
        if let Some(line) = self.overflow_warning(overflow) {
            // ⚠️ 用 `writeln!` 而不是 `eprintln!`：stderr 断管（EPIPE）时
            //    `eprintln!` 会 panic，而这条路上有一个返回 `Result` 的构造函数
            //    （`from_store`）。报警本身不该成为新的失败源。
            use std::io::Write;
            let _ = writeln!(std::io::stderr(), "{line}");
        }
    }

    /// 告警路径**跑没跑过**的可观察痕迹。
    ///
    /// 🔴 这是「有没有喊」在单元测试里唯一测得到的证据。节流标记只有走过
    /// `overflow_warning` 才会被置上，所以：**标记还是 `None`，就说明那条路
    /// 根本没被调用。** 复核抓到的两个漏网变异（开机路径、append 路径各删掉
    /// 一次调用）就是靠这个抓住的。
    ///
    /// ⚠️ 诚实说清它守不到的那一寸：**最后真正写进 stderr 的那一步测不到。**
    /// 不捕获进程的 stderr 就没法断言它，而为此改造整条日志出口不值得。这里
    /// 钉住的是「判决跑了、节流推进了、那句话被造出来了」；只删掉 `writeln!`
    /// 一行仍然会绿。知道边界在哪，比假装覆盖了要好。
    pub fn overflow_warned_at(&self) -> Option<usize> {
        self.overflow_warned_at
    }

    fn evict_if_needed(&mut self) -> Result<CapacityOutcome, QueueError> {
        let retained = self.retained_count();
        if retained <= self.max_records {
            // 回到上限以内：下一次越界要重新喊，不能被上一轮的节流吃掉。
            self.overflow_warned_at = None;
            return Ok(CapacityOutcome::WithinCapacity);
        }

        let Some(sequence) = self.oldest_evictable() else {
            let overflow = CapacityOverflow {
                retained,
                max_records: self.max_records,
                oldest_seq: self.state.retained_records().next().map(|r| r.sequence()),
            };
            self.warn_overflow(&overflow);
            return Ok(CapacityOutcome::Overflowing(overflow));
        };

        let gap_id = GapId::new(format!("capacity-{sequence}"))?;
        let gap: UplinkGap =
            self.state
                .declare_loss(gap_id.clone(), &[sequence], "queue_capacity")?;
        self.store.delete_sequences(&[sequence])?;
        self.store.insert_gap(
            gap.gap_id().as_str(),
            &format!("{}-{}", gap.ranges()[0].start(), gap.ranges()[0].end()),
            gap.reason(),
        )?;
        self.store
            .set_cursor(self.state.committed_through(), self.state.last_allocated())?;
        self.overflow_warned_at = None;
        Ok(CapacityOutcome::Evicted(CapacityAlert {
            gap_id: gap_id.as_str().to_owned(),
            evicted_seq: sequence,
        }))
    }
}

/// 这一次越界该不该再喊。
///
/// ⚠️ 判据是"记录条数比上次喊的时候又涨了一个 stride"，不是"又 append 了 N 次"：
///    ack 把队列削回去再涨上来，是一次新的恶化，应该重新喊。
const fn overflow_warning_due(retained: usize, warned_at: Option<usize>) -> bool {
    match warned_at {
        None => true,
        Some(previous) => retained >= previous.saturating_add(OVERFLOW_WARN_STRIDE),
    }
}

#[cfg(test)]
mod overflow_warning_tests {
    use super::{overflow_warning_due, OVERFLOW_WARN_STRIDE};

    /// 第一次越界必须喊：节流只能压后续的重复，不能压掉那条唯一的前置信号。
    #[test]
    fn the_first_crossing_always_warns() {
        assert!(overflow_warning_due(100_001, None));
    }

    /// 越界之后每条 append 都喊，等于用日志去填满我们正在告警的那块盘。
    #[test]
    fn a_single_record_later_stays_quiet() {
        assert!(!overflow_warning_due(100_002, Some(100_001)));
        assert!(!overflow_warning_due(
            100_001 + OVERFLOW_WARN_STRIDE - 1,
            Some(100_001)
        ));
    }

    /// 但情况持续恶化时必须再喊，否则一条开机日志会被后面几天的日志埋掉。
    #[test]
    fn another_stride_of_growth_warns_again() {
        assert!(overflow_warning_due(
            100_001 + OVERFLOW_WARN_STRIDE,
            Some(100_001)
        ));
    }
}

impl Outbox for DurableOutbox {
    type Error = QueueError;

    fn last_allocated(&self) -> u64 {
        DurableOutbox::last_allocated(self)
    }

    fn committed_through(&self) -> u64 {
        DurableOutbox::committed_through(self)
    }

    fn lowest_retained_seq(&self) -> Option<u64> {
        DurableOutbox::lowest_retained_seq(self)
    }

    fn pending_gap_ids(&self) -> Vec<String> {
        DurableOutbox::pending_gap_ids(self)
    }

    fn queue_records(&self) -> i64 {
        DurableOutbox::queue_records(self)
    }

    fn queue_bytes(&self) -> Option<i64> {
        DurableOutbox::queue_bytes(self)
    }

    fn observe_ack(&mut self, ack: UplinkAck) -> Result<Vec<u64>, Self::Error> {
        DurableOutbox::observe_ack(self, ack)
    }

    fn retained(&self) -> Result<Vec<RetainedRecord>, Self::Error> {
        Ok(self
            .store
            .load_outbox()?
            .into_iter()
            .map(|row| RetainedRecord {
                sequence: row.seq,
                envelope_id: row.envelope_id,
                kind: row.kind,
                payload: row.payload,
            })
            .collect())
    }
}

/// Errors from the durable outbox.
#[derive(Debug)]
pub enum QueueError {
    Store(StoreError),
    Uplink(UplinkError),
}

impl std::fmt::Display for QueueError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(error) => write!(formatter, "{error}"),
            Self::Uplink(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for QueueError {}

impl From<StoreError> for QueueError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

impl From<UplinkError> for QueueError {
    fn from(value: UplinkError) -> Self {
        Self::Uplink(value)
    }
}
