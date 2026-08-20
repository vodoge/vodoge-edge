use edge_uplink::{
    EnvelopeId, GapId, RetentionClass, SequenceRange, UplinkAck, UplinkError, UplinkState,
    MAX_MISSING_RANGES,
};

#[test]
fn cumulative_ack_keeps_records_above_a_hole_until_the_prefix_is_complete() {
    let mut state = five_records();

    let outcome = state
        .observe_ack(ack(2, &[(3, 3)]))
        .expect("the contiguous prefix is durable");
    assert_eq!(outcome.deleted_sequences, vec![1, 2]);
    assert_eq!(state.committed_through(), 2);
    assert_eq!(retained_sequences(&state), vec![3, 4, 5]);
    assert_eq!(state.missing_ranges(), &[range(3, 3)]);

    let outcome = state
        .observe_ack(ack(5, &[]))
        .expect("sequence 3 later completes the prefix");
    assert_eq!(outcome.deleted_sequences, vec![3, 4, 5]);
    assert_eq!(state.committed_through(), 5);
    assert!(retained_sequences(&state).is_empty());
}

#[test]
fn duplicate_and_stale_acks_do_not_delete_newer_records() {
    let mut state = five_records();
    state.observe_ack(ack(2, &[(3, 3)])).expect("prefix ack");

    let duplicate = state.observe_ack(ack(2, &[(3, 3)])).expect("duplicate ack");
    assert!(!duplicate.advanced);
    assert!(duplicate.deleted_sequences.is_empty());

    let stale = state.observe_ack(ack(1, &[])).expect("stale ack");
    assert!(!stale.advanced);
    assert_eq!(state.committed_through(), 2);
    assert_eq!(retained_sequences(&state), vec![3, 4, 5]);
}

#[test]
fn accepted_gap_is_the_only_intentional_way_to_skip_a_missing_sequence() {
    let mut state = five_records();
    state.observe_ack(ack(2, &[(3, 3)])).expect("prefix ack");

    let gap_id = gap_id("capacity-gap-3");
    let gap = state
        .declare_loss(gap_id.clone(), &[3], "storage pressure")
        .expect("evictable record becomes a durable gap");
    assert_eq!(gap.ranges(), &[range(3, 3)]);
    assert_eq!(retained_sequences(&state), vec![4, 5]);
    assert!(matches!(
        state.observe_ack(ack(5, &[])),
        Err(UplinkError::AckCrossesUnresolvedSequence(3))
    ));

    let accepted = state.accept_gap(&gap_id).expect("gap acknowledgement");
    assert!(accepted.advanced);
    assert_eq!(accepted.committed_through, 3);
    assert!(state.pending_gaps().next().is_none());
    assert!(state.accepted_gap(&gap_id).is_some());

    let outcome = state.observe_ack(ack(5, &[])).expect("remaining prefix ack");
    assert_eq!(outcome.deleted_sequences, vec![4, 5]);
    assert_eq!(state.committed_through(), 5);
}

#[test]
fn protected_records_cannot_be_evicted_or_covered_by_a_gap() {
    let mut state = UplinkState::new();
    let sequence = state
        .append(
            envelope_id("command-result"),
            b"terminal result".to_vec(),
            RetentionClass::Protected,
        )
        .expect("protected record");

    let gap_id = gap_id("forbidden-gap");
    assert!(matches!(
        state.declare_loss(gap_id.clone(), &[sequence], "storage pressure"),
        Err(UplinkError::ProtectedRecordCannotBeEvicted(1))
    ));
    assert!(state.retained_record(sequence).is_some());
    assert!(state.pending_gap(&gap_id).is_none());
}

#[test]
fn replay_keeps_the_original_envelope_id_and_rejects_reallocation() {
    let mut state = UplinkState::new();
    let envelope_id = envelope_id("stable-envelope");
    let sequence = state
        .append(
            envelope_id.clone(),
            b"event".to_vec(),
            RetentionClass::Evictable,
        )
        .expect("first allocation");

    let record = state.retained_record(sequence).expect("retained record");
    assert_eq!(record.envelope_id(), &envelope_id);
    assert_eq!(retained_sequences(&state), vec![1]);
    assert!(matches!(
        state.append(envelope_id, b"retry".to_vec(), RetentionClass::Evictable),
        Err(UplinkError::DuplicateEnvelopeId { sequence: 1, .. })
    ));
}

#[test]
fn acknowledgement_rejects_more_than_the_protocol_missing_range_limit() {
    let ranges = (1..=(MAX_MISSING_RANGES as u64 + 1))
        .map(|sequence| range(sequence, sequence))
        .collect();

    assert!(matches!(
        UplinkAck::new(0, ranges, true),
        Err(UplinkError::TooManyMissingRanges {
            actual: 129,
            maximum: MAX_MISSING_RANGES,
        })
    ));
}

fn five_records() -> UplinkState {
    let mut state = UplinkState::new();
    for sequence in 1..=5 {
        assert_eq!(
            state
                .append(
                    envelope_id(&format!("event-{sequence}")),
                    vec![sequence as u8],
                    RetentionClass::Evictable,
                )
                .expect("append"),
            sequence
        );
    }
    state
}

fn ack(committed_through: u64, missing_ranges: &[(u64, u64)]) -> UplinkAck {
    UplinkAck::new(
        committed_through,
        missing_ranges
            .iter()
            .map(|(start, end)| range(*start, *end))
            .collect(),
        false,
    )
    .expect("canonical acknowledgement")
}

fn range(start: u64, end: u64) -> SequenceRange {
    SequenceRange::new(start, end).expect("valid range")
}

fn envelope_id(value: &str) -> EnvelopeId {
    EnvelopeId::new(value).expect("valid envelope ID")
}

fn gap_id(value: &str) -> GapId {
    GapId::new(value).expect("valid gap ID")
}

fn retained_sequences(state: &UplinkState) -> Vec<u64> {
    state
        .retained_records()
        .map(|record| record.sequence())
        .collect()
}
