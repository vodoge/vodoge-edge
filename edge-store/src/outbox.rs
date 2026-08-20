use edge_uplink::{
    EnvelopeId, GapId, RetentionClass, UplinkAck, UplinkError, UplinkGap, UplinkRecord, UplinkState,
};

use crate::{Store, StoreError};

/// Default capacity from the blueprint: 100_000 retained records.
pub const DEFAULT_MAX_RECORDS: usize = 100_000;

/// Alert produced when capacity eviction actually drops an evictable record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapacityAlert {
    pub gap_id: String,
    pub evicted_seq: u64,
}

/// SQLite-backed journal. Mutations go to disk before in-memory state is used
/// as the send set, matching "commit locally, then upload".
pub struct DurableOutbox {
    store: Store,
    state: UplinkState,
    max_records: usize,
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
        Ok(Self {
            store,
            state,
            max_records: max_records.max(1),
        })
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
    pub fn append(
        &mut self,
        envelope_id: EnvelopeId,
        kind: &str,
        payload: impl Into<Vec<u8>>,
        retention: RetentionClass,
    ) -> Result<(u64, Option<CapacityAlert>), QueueError> {
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
        let alert = self.evict_if_needed()?;
        Ok((sequence, alert))
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

    fn evict_if_needed(&mut self) -> Result<Option<CapacityAlert>, QueueError> {
        if self.retained_count() <= self.max_records {
            return Ok(None);
        }

        let oldest = self
            .state
            .retained_records()
            .find(|record| record.retention() == RetentionClass::Evictable)
            .map(|record| record.sequence());
        let Some(sequence) = oldest else {
            return Ok(None);
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
        Ok(Some(CapacityAlert {
            gap_id: gap_id.as_str().to_owned(),
            evicted_seq: sequence,
        }))
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
