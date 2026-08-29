//! Deciding what to do with one pass of collected messages.
//!
//! Extracted because there are now two transports that collect -- QMI for the
//! modules that speak it, AT for the EC200U series that does not -- and the
//! sequencing between decoding a pass and clearing the module's storage is
//! where the subtle rules live. Two copies of it would agree on the easy pass
//! and diverge on exactly the ones that lose messages.
//!
//! Pure, and that is the point: no store, no radio, no clock beyond the `now`
//! handed in. The transports keep their own I/O -- reading the store's ingest
//! ledger, enqueuing upstream, deleting by whatever a module is addressed with
//! -- and share the decision.
//!
//! Two rules are the whole reason this is worth extracting:
//!
//! * **A fragment whose siblings have not arrived stays on the module.** The
//!   next pass completes it. Deleting it loses half a message permanently,
//!   which is worse than reading it twice.
//! * **A message the books already hold is deleted anyway.** Module storage is
//!   small and a full store silently stops accepting new messages, so a slot
//!   already carried away must not go on occupying it.

use crate::concat::{assemble, AssembledSms, ConcatPart};
use crate::FRAGMENT_GRACE_MS;

/// One decoded fragment, tied back to where it sits in the pass.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InboundFragment {
    /// Position in the pass. The transport turns this back into whatever it
    /// deletes by -- a QMI storage row, an AT storage index.
    pub slot: usize,
    /// The alphabet this fragment's coding scheme named.
    pub encoding: &'static str,
    pub fingerprint: String,
    pub part: ConcatPart,
}

/// One message ready to be stored and sent upstream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SettledMessage {
    pub message: AssembledSms,
    /// Read off a fragment this message was built from, never looked up by
    /// sender: one pass routinely holds several messages from one short code,
    /// and the first one's encoding is not the others'.
    pub encoding: &'static str,
    /// Pass positions that went into it, so the transport can clear exactly
    /// those and no others.
    pub slots: Vec<usize>,
    pub fingerprints: Vec<String>,
}

/// What a pass settles into.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InboundSettlement {
    /// Store these, then delete their slots. In that order: a delete that ran
    /// first would lose the message if anything after it failed.
    pub ready: Vec<SettledMessage>,
    /// Slots holding a message the books already have. Safe to delete now,
    /// with nothing to store first.
    pub already_ours: Vec<usize>,
    /// Fragments still waiting for siblings. Left where they are.
    pub pending: usize,
}

impl InboundSettlement {
    /// Every slot whose module copy may go, once `ready` has been stored.
    pub fn deletable(&self) -> Vec<usize> {
        let mut slots = self.already_ours.clone();
        for settled in &self.ready {
            slots.extend(settled.slots.iter().copied());
        }
        slots.sort_unstable();
        slots.dedup();
        slots
    }
}

/// Decide what one pass settles into.
///
/// `seen[n]` says whether `fragments[n]`'s fingerprint is already in the ingest
/// ledger. A shorter `seen` treats the rest as unseen, which is the safe
/// direction: the worst case is storing a message twice, and the alternative
/// would be deleting one that was never stored.
pub fn settle_inbound(
    fragments: Vec<InboundFragment>,
    seen: &[bool],
    now: i64,
) -> InboundSettlement {
    let mut parts: Vec<ConcatPart> = Vec::with_capacity(fragments.len());
    let mut encodings: Vec<&'static str> = Vec::with_capacity(fragments.len());
    let mut fingerprints: Vec<String> = Vec::with_capacity(fragments.len());
    let mut slots: Vec<usize> = Vec::with_capacity(fragments.len());
    let mut already_ours: Vec<usize> = Vec::new();

    for (index, fragment) in fragments.into_iter().enumerate() {
        if seen.get(index).copied().unwrap_or(false) {
            already_ours.push(fragment.slot);
            continue;
        }
        encodings.push(fragment.encoding);
        fingerprints.push(fragment.fingerprint);
        slots.push(fragment.slot);
        parts.push(fragment.part);
    }

    let (assembled, pending) = assemble(&parts, now, FRAGMENT_GRACE_MS);
    let ready = assembled
        .into_iter()
        .map(|message| {
            let encoding = message
                .sources
                .first()
                .and_then(|source| encodings.get(*source).copied())
                .unwrap_or("unknown");
            let slots = message
                .sources
                .iter()
                .filter_map(|source| slots.get(*source).copied())
                .collect();
            let fingerprints = message
                .sources
                .iter()
                .filter_map(|source| fingerprints.get(*source).cloned())
                .collect();
            SettledMessage {
                message,
                encoding,
                slots,
                fingerprints,
            }
        })
        .collect();

    InboundSettlement {
        ready,
        already_ours,
        pending: pending.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fragment(slot: usize, sender: &str, seq: u8, total: u8, body: &str) -> InboundFragment {
        InboundFragment {
            slot,
            encoding: "gsm7",
            fingerprint: format!("{sender}:{seq}:{body}"),
            part: ConcatPart {
                sender: sender.to_owned(),
                ref_id: if total > 1 { 7 } else { 0 },
                total,
                seq,
                body: body.to_owned(),
                received_at: Some(1_000),
            },
        }
    }

    /// 🔴 The rule that loses messages when it is broken: a fragment whose
    /// siblings have not arrived must not be cleared off the module. The next
    /// pass is what completes it, and there is no second copy anywhere.
    #[test]
    fn an_incomplete_message_leaves_its_fragment_on_the_module() {
        let settled = settle_inbound(vec![fragment(0, "10086", 1, 2, "first half")], &[false], 1_000);
        assert_eq!(settled.pending, 1);
        assert!(settled.ready.is_empty(), "half a message is not a message");
        assert!(
            settled.deletable().is_empty(),
            "clearing it would lose the half that did arrive"
        );
    }

    /// 🔴 The other rule: a message the books already hold is cleared anyway.
    /// Module storage is small and a full one stops accepting messages, so a
    /// slot already carried away must not go on occupying it.
    #[test]
    fn a_message_already_stored_is_cleared_without_being_stored_again() {
        let settled = settle_inbound(vec![fragment(3, "10086", 1, 1, "hello")], &[true], 1_000);
        assert!(settled.ready.is_empty(), "it must not be stored twice");
        assert_eq!(settled.already_ours, vec![3]);
        assert_eq!(settled.deletable(), vec![3], "the slot still has to come back");
    }

    #[test]
    fn a_whole_message_is_ready_and_its_slot_deletable() {
        let settled = settle_inbound(vec![fragment(2, "10086", 1, 1, "hello")], &[false], 1_000);
        assert_eq!(settled.ready.len(), 1);
        assert_eq!(settled.ready[0].message.body, "hello");
        assert_eq!(settled.ready[0].slots, vec![2]);
        assert_eq!(settled.ready[0].fingerprints.len(), 1);
        assert_eq!(settled.deletable(), vec![2]);
        assert_eq!(settled.pending, 0);
    }

    /// Slots are the module's, not the pass's. A message assembled from
    /// fragments at pass positions 0 and 1 may sit in storage rows 4 and 9,
    /// and deleting 0 and 1 would clear two messages nobody read.
    #[test]
    fn the_slots_reported_are_the_modules_own() {
        let settled = settle_inbound(
            vec![
                fragment(4, "10086", 1, 2, "first "),
                fragment(9, "10086", 2, 2, "second"),
            ],
            &[false, false],
            1_000,
        );
        assert_eq!(settled.ready.len(), 1);
        assert_eq!(settled.ready[0].slots, vec![4, 9]);
        assert_eq!(settled.deletable(), vec![4, 9]);
    }

    /// The alphabet comes off the message's own fragment. One pass regularly
    /// holds several messages from one short code, and looking the encoding up
    /// by sender hands the second message the first one's.
    #[test]
    fn each_message_carries_its_own_alphabet() {
        let mut ucs2 = fragment(1, "10086", 1, 1, "second");
        ucs2.encoding = "ucs2";
        let settled = settle_inbound(
            vec![fragment(0, "10086", 1, 1, "first"), ucs2],
            &[false, false],
            1_000,
        );
        assert_eq!(settled.ready.len(), 2);
        let encodings: Vec<_> = settled.ready.iter().map(|item| item.encoding).collect();
        assert!(encodings.contains(&"gsm7"));
        assert!(encodings.contains(&"ucs2"));
    }

    /// A pass mixing all three states settles each one its own way, which is
    /// the case a single-purpose test would miss.
    #[test]
    fn a_mixed_pass_settles_each_fragment_on_its_own_terms() {
        let settled = settle_inbound(
            vec![
                fragment(0, "10086", 1, 1, "already stored"),
                fragment(1, "10010", 1, 1, "new and whole"),
                fragment(2, "10001", 1, 3, "waiting for siblings"),
            ],
            &[true, false, false],
            1_000,
        );
        assert_eq!(settled.already_ours, vec![0]);
        assert_eq!(settled.ready.len(), 1);
        assert_eq!(settled.ready[0].slots, vec![1]);
        assert_eq!(settled.pending, 1);
        // The incomplete one is not in there; the other two are.
        assert_eq!(settled.deletable(), vec![0, 1]);
    }

    /// A short `seen` must treat the rest as unseen. Storing twice is
    /// recoverable; deleting something never stored is not.
    #[test]
    fn a_short_seen_list_errs_towards_storing_again() {
        let settled = settle_inbound(
            vec![
                fragment(0, "10086", 1, 1, "one"),
                fragment(1, "10086", 1, 1, "two"),
            ],
            &[true],
            1_000,
        );
        assert_eq!(settled.already_ours, vec![0]);
        assert_eq!(settled.ready.len(), 1, "the unlisted fragment is stored");
    }
}
