//! Pure state for the edge-to-cloud cumulative acknowledgement protocol.
//!
//! This crate has no storage or network dependency. A persistence adapter must
//! atomically persist each state transition before a transport acts on it.

pub mod codec;
pub mod dial;
pub mod session;
pub mod tls;
pub mod update;
pub mod worker;

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

/// Maximum recovery-hole hints accepted from one cloud acknowledgement.
pub const MAX_MISSING_RANGES: usize = 128;

/// A caller-supplied, stable identifier for one sequenced envelope.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EnvelopeId(String);

impl EnvelopeId {
    pub fn new(value: impl Into<String>) -> Result<Self, UplinkError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(UplinkError::EmptyIdentifier("envelope ID"));
        }

        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EnvelopeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A caller-supplied, stable identifier for one durable loss marker.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GapId(String);

impl GapId {
    pub fn new(value: impl Into<String>) -> Result<Self, UplinkError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(UplinkError::EmptyIdentifier("gap ID"));
        }

        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for GapId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// An inclusive sequence interval.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SequenceRange {
    start: u64,
    end: u64,
}

impl SequenceRange {
    pub fn new(start: u64, end: u64) -> Result<Self, UplinkError> {
        if start > end {
            return Err(UplinkError::InvalidSequenceRange { start, end });
        }

        Ok(Self { start, end })
    }

    pub const fn start(self) -> u64 {
        self.start
    }

    pub const fn end(self) -> u64 {
        self.end
    }
}

/// Whether an outbox record may become an explicit loss marker under pressure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetentionClass {
    Evictable,
    Protected,
}

/// One locally retained, sequenced envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UplinkRecord {
    sequence: u64,
    envelope_id: EnvelopeId,
    payload: Vec<u8>,
    retention: RetentionClass,
}

impl UplinkRecord {
    /// Rebuilds a record that was already allocated and persisted.
    pub fn restore(
        sequence: u64,
        envelope_id: EnvelopeId,
        payload: impl Into<Vec<u8>>,
        retention: RetentionClass,
    ) -> Self {
        Self {
            sequence,
            envelope_id,
            payload: payload.into(),
            retention,
        }
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn envelope_id(&self) -> &EnvelopeId {
        &self.envelope_id
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub const fn retention(&self) -> RetentionClass {
        self.retention
    }
}

/// A durable `UplinkGap` that must be retained until its acknowledgement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UplinkGap {
    gap_id: GapId,
    ranges: Vec<SequenceRange>,
    reason: String,
}

impl UplinkGap {
    pub fn gap_id(&self) -> &GapId {
        &self.gap_id
    }

    pub fn ranges(&self) -> &[SequenceRange] {
        &self.ranges
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }
}

/// A cloud cumulative acknowledgement and its non-authoritative recovery hint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UplinkAck {
    committed_through: u64,
    missing_ranges: Vec<SequenceRange>,
    more_missing: bool,
}

impl UplinkAck {
    pub fn new(
        committed_through: u64,
        missing_ranges: Vec<SequenceRange>,
        more_missing: bool,
    ) -> Result<Self, UplinkError> {
        if missing_ranges.len() > MAX_MISSING_RANGES {
            return Err(UplinkError::TooManyMissingRanges {
                actual: missing_ranges.len(),
                maximum: MAX_MISSING_RANGES,
            });
        }
        validate_sorted_non_overlapping(&missing_ranges)?;
        Ok(Self {
            committed_through,
            missing_ranges,
            more_missing,
        })
    }

    pub const fn committed_through(&self) -> u64 {
        self.committed_through
    }

    pub fn missing_ranges(&self) -> &[SequenceRange] {
        &self.missing_ranges
    }

    pub const fn more_missing(&self) -> bool {
        self.more_missing
    }
}

/// The observable result of processing an `UplinkAck`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AckOutcome {
    pub committed_through: u64,
    pub deleted_sequences: Vec<u64>,
    pub advanced: bool,
}

/// The observable result of accepting an `UplinkGapAck`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GapAckOutcome {
    pub gap_id: GapId,
    pub committed_through: u64,
    pub advanced: bool,
    pub already_accepted: bool,
}

/// In-memory model of the persisted edge outbox state.
///
/// `committed_through` moves only over retained records confirmed by an
/// `UplinkAck`, or over records previously replaced by an accepted `UplinkGap`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UplinkState {
    last_allocated: u64,
    committed_through: u64,
    records: BTreeMap<u64, UplinkRecord>,
    envelope_sequences: BTreeMap<EnvelopeId, u64>,
    missing_ranges: Vec<SequenceRange>,
    more_missing: bool,
    pending_gaps: BTreeMap<GapId, UplinkGap>,
    accepted_gaps: BTreeMap<GapId, UplinkGap>,
    accepted_loss_sequences: BTreeSet<u64>,
}

impl Default for UplinkState {
    fn default() -> Self {
        Self::new()
    }
}

impl UplinkState {
    /// Starts a device journal whose first allocated sequence will be `1`.
    pub fn new() -> Self {
        Self {
            last_allocated: 0,
            committed_through: 0,
            records: BTreeMap::new(),
            envelope_sequences: BTreeMap::new(),
            missing_ranges: Vec::new(),
            more_missing: false,
            pending_gaps: BTreeMap::new(),
            accepted_gaps: BTreeMap::new(),
            accepted_loss_sequences: BTreeSet::new(),
        }
    }

    /// Starts after a fully restored contiguous committed prefix.
    pub fn from_committed_through(committed_through: u64) -> Self {
        let mut state = Self::new();
        state.last_allocated = committed_through;
        state.committed_through = committed_through;
        state
    }

    pub const fn last_allocated(&self) -> u64 {
        self.last_allocated
    }

    pub const fn committed_through(&self) -> u64 {
        self.committed_through
    }

    pub fn missing_ranges(&self) -> &[SequenceRange] {
        &self.missing_ranges
    }

    pub const fn more_missing(&self) -> bool {
        self.more_missing
    }

    /// Rebuilds journal state after loading SQLite rows.
    pub fn rehydrate(
        committed_through: u64,
        last_allocated: u64,
        records: Vec<UplinkRecord>,
    ) -> Result<Self, UplinkError> {
        if last_allocated < committed_through {
            return Err(UplinkError::InvalidRestoredJournal);
        }

        let mut state = Self::from_committed_through(committed_through);
        state.last_allocated = last_allocated;
        for record in records {
            if record.sequence <= committed_through || record.sequence > last_allocated {
                return Err(UplinkError::InvalidRestoredJournal);
            }
            if state.records.contains_key(&record.sequence)
                || state.envelope_sequences.contains_key(&record.envelope_id)
            {
                return Err(UplinkError::InvalidRestoredJournal);
            }
            state
                .envelope_sequences
                .insert(record.envelope_id.clone(), record.sequence);
            state.records.insert(record.sequence, record);
        }
        Ok(state)
    }

    /// Allocates the next sequence and retains the original envelope identity.
    pub fn append(
        &mut self,
        envelope_id: EnvelopeId,
        payload: impl Into<Vec<u8>>,
        retention: RetentionClass,
    ) -> Result<u64, UplinkError> {
        if let Some(sequence) = self.envelope_sequences.get(&envelope_id) {
            return Err(UplinkError::DuplicateEnvelopeId {
                envelope_id,
                sequence: *sequence,
            });
        }

        let sequence = self
            .last_allocated
            .checked_add(1)
            .ok_or(UplinkError::SequenceExhausted)?;
        let record = UplinkRecord {
            sequence,
            envelope_id: envelope_id.clone(),
            payload: payload.into(),
            retention,
        };

        self.last_allocated = sequence;
        self.envelope_sequences.insert(envelope_id, sequence);
        self.records.insert(sequence, record);
        Ok(sequence)
    }

    pub fn retained_record(&self, sequence: u64) -> Option<&UplinkRecord> {
        self.records.get(&sequence)
    }

    /// Returns replay candidates in ascending sequence order with stable IDs.
    pub fn retained_records(&self) -> impl Iterator<Item = &UplinkRecord> {
        self.records.values()
    }

    /// Returns loss notices that must be sent before retained envelopes.
    pub fn pending_gaps(&self) -> impl Iterator<Item = &UplinkGap> {
        self.pending_gaps.values()
    }

    pub fn pending_gap(&self, gap_id: &GapId) -> Option<&UplinkGap> {
        self.pending_gaps.get(gap_id)
    }

    pub fn accepted_gap(&self, gap_id: &GapId) -> Option<&UplinkGap> {
        self.accepted_gaps.get(gap_id)
    }

    /// Stores one explicit loss marker and removes only the eligible records it names.
    pub fn declare_loss(
        &mut self,
        gap_id: GapId,
        sequences: &[u64],
        reason: impl Into<String>,
    ) -> Result<UplinkGap, UplinkError> {
        if self.pending_gaps.contains_key(&gap_id) || self.accepted_gaps.contains_key(&gap_id) {
            return Err(UplinkError::DuplicateGapId(gap_id));
        }

        let reason = reason.into();
        if reason.trim().is_empty() {
            return Err(UplinkError::EmptyGapReason);
        }

        let selected = selected_sequences(sequences)?;
        for sequence in &selected {
            match self.records.get(sequence) {
                Some(record) if record.retention == RetentionClass::Evictable => {}
                Some(_) => return Err(UplinkError::ProtectedRecordCannotBeEvicted(*sequence)),
                None => return Err(UplinkError::UnknownRetainedSequence(*sequence)),
            }
        }

        let gap = UplinkGap {
            gap_id: gap_id.clone(),
            ranges: ranges_for(&selected),
            reason,
        };
        for sequence in selected {
            self.records.remove(&sequence);
        }
        self.pending_gaps.insert(gap_id, gap.clone());
        Ok(gap)
    }

    /// Accepts a durable cloud loss-marker acknowledgement.
    pub fn accept_gap(&mut self, gap_id: &GapId) -> Result<GapAckOutcome, UplinkError> {
        if self.accepted_gaps.contains_key(gap_id) {
            return Ok(GapAckOutcome {
                gap_id: gap_id.clone(),
                committed_through: self.committed_through,
                advanced: false,
                already_accepted: true,
            });
        }

        let gap = self
            .pending_gaps
            .remove(gap_id)
            .ok_or_else(|| UplinkError::UnknownGapId(gap_id.clone()))?;
        for range in &gap.ranges {
            for sequence in range.start..=range.end {
                self.accepted_loss_sequences.insert(sequence);
            }
        }
        self.accepted_gaps.insert(gap_id.clone(), gap);

        let advanced = self.advance_across_accepted_losses();
        Ok(GapAckOutcome {
            gap_id: gap_id.clone(),
            committed_through: self.committed_through,
            advanced,
            already_accepted: false,
        })
    }

    /// Applies a cloud cumulative acknowledgement without trusting its holes as
    /// permission to delete records.
    pub fn observe_ack(&mut self, ack: UplinkAck) -> Result<AckOutcome, UplinkError> {
        if ack.committed_through < self.committed_through {
            return Ok(AckOutcome {
                committed_through: self.committed_through,
                deleted_sequences: Vec::new(),
                advanced: false,
            });
        }
        if ack.committed_through > self.last_allocated {
            return Err(UplinkError::AckBeyondAllocated {
                committed_through: ack.committed_through,
                last_allocated: self.last_allocated,
            });
        }
        self.validate_missing_hint(&ack)?;

        if ack.committed_through == self.committed_through {
            self.missing_ranges = ack.missing_ranges;
            self.more_missing = ack.more_missing;
            return Ok(AckOutcome {
                committed_through: self.committed_through,
                deleted_sequences: Vec::new(),
                advanced: false,
            });
        }

        for sequence in (self.committed_through + 1)..=ack.committed_through {
            if !self.records.contains_key(&sequence)
                && !self.accepted_loss_sequences.contains(&sequence)
            {
                return Err(UplinkError::AckCrossesUnresolvedSequence(sequence));
            }
        }

        let mut deleted_sequences = Vec::new();
        for sequence in (self.committed_through + 1)..=ack.committed_through {
            if self.records.remove(&sequence).is_some() {
                deleted_sequences.push(sequence);
            } else {
                self.accepted_loss_sequences.remove(&sequence);
            }
        }
        self.committed_through = ack.committed_through;
        self.missing_ranges = ack.missing_ranges;
        self.more_missing = ack.more_missing;

        Ok(AckOutcome {
            committed_through: self.committed_through,
            deleted_sequences,
            advanced: true,
        })
    }

    fn validate_missing_hint(&self, ack: &UplinkAck) -> Result<(), UplinkError> {
        for range in &ack.missing_ranges {
            if range.start <= ack.committed_through {
                return Err(UplinkError::MissingRangeAtOrBelowCursor {
                    range: *range,
                    committed_through: ack.committed_through,
                });
            }
            if range.end > self.last_allocated {
                return Err(UplinkError::MissingRangeBeyondAllocated {
                    range: *range,
                    last_allocated: self.last_allocated,
                });
            }
        }
        Ok(())
    }

    fn advance_across_accepted_losses(&mut self) -> bool {
        let original_cursor = self.committed_through;
        while let Some(next) = self.committed_through.checked_add(1) {
            if !self.accepted_loss_sequences.remove(&next) {
                break;
            }
            self.committed_through = next;
        }

        if self.committed_through != original_cursor {
            self.prune_committed_missing_ranges();
            true
        } else {
            false
        }
    }

    fn prune_committed_missing_ranges(&mut self) {
        if self.committed_through == u64::MAX {
            self.missing_ranges.clear();
            self.more_missing = false;
            return;
        }

        let next = self.committed_through + 1;
        self.missing_ranges = self
            .missing_ranges
            .iter()
            .filter_map(|range| {
                if range.end <= self.committed_through {
                    None
                } else if range.start <= self.committed_through {
                    Some(SequenceRange {
                        start: next,
                        end: range.end,
                    })
                } else {
                    Some(*range)
                }
            })
            .collect();
    }
}

/// Errors returned when a transition would violate the durable protocol model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UplinkError {
    EmptyIdentifier(&'static str),
    InvalidSequenceRange { start: u64, end: u64 },
    NonCanonicalRanges,
    TooManyMissingRanges { actual: usize, maximum: usize },
    SequenceExhausted,
    DuplicateEnvelopeId { envelope_id: EnvelopeId, sequence: u64 },
    AckBeyondAllocated { committed_through: u64, last_allocated: u64 },
    AckCrossesUnresolvedSequence(u64),
    MissingRangeAtOrBelowCursor { range: SequenceRange, committed_through: u64 },
    MissingRangeBeyondAllocated { range: SequenceRange, last_allocated: u64 },
    EmptyGap,
    EmptyGapReason,
    DuplicateGapId(GapId),
    DuplicateLossSequence(u64),
    UnknownRetainedSequence(u64),
    ProtectedRecordCannotBeEvicted(u64),
    UnknownGapId(GapId),
    InvalidRestoredJournal,
}

impl fmt::Display for UplinkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyIdentifier(kind) => write!(formatter, "{kind} must not be empty"),
            Self::InvalidSequenceRange { start, end } => {
                write!(formatter, "invalid sequence range {start}..={end}")
            }
            Self::NonCanonicalRanges => formatter.write_str("ranges must be sorted and non-overlapping"),
            Self::TooManyMissingRanges { actual, maximum } => {
                write!(formatter, "ack has {actual} missing ranges; maximum is {maximum}")
            }
            Self::SequenceExhausted => formatter.write_str("sequence space is exhausted"),
            Self::DuplicateEnvelopeId {
                envelope_id,
                sequence,
            } => write!(formatter, "envelope {envelope_id} is already allocated at sequence {sequence}"),
            Self::AckBeyondAllocated {
                committed_through,
                last_allocated,
            } => write!(
                formatter,
                "ack cursor {committed_through} exceeds last allocated sequence {last_allocated}"
            ),
            Self::AckCrossesUnresolvedSequence(sequence) => {
                write!(formatter, "ack crosses unresolved sequence {sequence}")
            }
            Self::MissingRangeAtOrBelowCursor {
                range,
                committed_through,
            } => write!(
                formatter,
                "missing range {}..={} is at or below cursor {committed_through}",
                range.start,
                range.end
            ),
            Self::MissingRangeBeyondAllocated {
                range,
                last_allocated,
            } => write!(
                formatter,
                "missing range {}..={} exceeds last allocated sequence {last_allocated}",
                range.start,
                range.end
            ),
            Self::EmptyGap => formatter.write_str("a gap must cover at least one sequence"),
            Self::EmptyGapReason => formatter.write_str("a gap reason must not be empty"),
            Self::DuplicateGapId(gap_id) => write!(formatter, "gap ID {gap_id} already exists"),
            Self::DuplicateLossSequence(sequence) => {
                write!(formatter, "sequence {sequence} appears more than once in a gap")
            }
            Self::UnknownRetainedSequence(sequence) => {
                write!(formatter, "sequence {sequence} is not retained")
            }
            Self::ProtectedRecordCannotBeEvicted(sequence) => {
                write!(formatter, "protected sequence {sequence} cannot be evicted")
            }
            Self::UnknownGapId(gap_id) => write!(formatter, "gap ID {gap_id} is not pending"),
            Self::InvalidRestoredJournal => {
                formatter.write_str("restored uplink journal is internally inconsistent")
            }
        }
    }
}

impl Error for UplinkError {}

fn validate_sorted_non_overlapping(ranges: &[SequenceRange]) -> Result<(), UplinkError> {
    for pair in ranges.windows(2) {
        if pair[0].start >= pair[1].start || pair[0].end >= pair[1].start {
            return Err(UplinkError::NonCanonicalRanges);
        }
    }
    Ok(())
}

fn selected_sequences(sequences: &[u64]) -> Result<BTreeSet<u64>, UplinkError> {
    if sequences.is_empty() {
        return Err(UplinkError::EmptyGap);
    }

    let mut selected = BTreeSet::new();
    for sequence in sequences {
        if !selected.insert(*sequence) {
            return Err(UplinkError::DuplicateLossSequence(*sequence));
        }
    }
    Ok(selected)
}

fn ranges_for(sequences: &BTreeSet<u64>) -> Vec<SequenceRange> {
    let mut ranges = Vec::new();
    let mut iterator = sequences.iter().copied();
    let Some(mut start) = iterator.next() else {
        return ranges;
    };
    let mut end = start;

    for sequence in iterator {
        if end.checked_add(1) == Some(sequence) {
            end = sequence;
        } else {
            ranges.push(SequenceRange { start, end });
            start = sequence;
            end = sequence;
        }
    }
    ranges.push(SequenceRange { start, end });
    ranges
}
