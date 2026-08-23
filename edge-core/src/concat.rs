use std::collections::BTreeMap;

/// How long a group waits for the fragments it is missing before what did
/// arrive is released.
///
/// A concatenation reference is eight bits and the network does not resend, so
/// a fragment lost in transit leaves its siblings on the modem with nothing to
/// complete them. Holding them forever is not caution: the modem's store is
/// fifty entries on the SIM, it is never emptied by anyone else, and once it is
/// full the module stops accepting new messages. That failure arrives days
/// later and looks like the network going quiet.
///
/// A day is long enough that no ordinary delivery delay trips it -- the
/// fragments of one message arrive seconds apart -- and short enough that a
/// handful of orphans cannot fill a store.
pub const FRAGMENT_GRACE_MS: i64 = 24 * 60 * 60 * 1000;

/// One fragment of a concatenated SMS.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConcatPart {
    pub sender: String,
    pub ref_id: u16,
    pub total: u8,
    pub seq: u8,
    pub body: String,
    /// When the service centre stamped it, in Unix milliseconds.
    ///
    /// Fragments of one message are stamped within a second of each other, so
    /// this is also what tells two deliveries that reused the same reference
    /// apart, and what says whether an unfinished group is still worth waiting
    /// for. `None` when the PDU carried no readable timestamp: such a group is
    /// never released early, because there is no honest way to call it old.
    pub received_at: Option<i64>,
}

/// A fully assembled inbound SMS, possibly from several fragments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssembledSms {
    pub sender: String,
    pub body: String,
    pub parts: u8,
    /// Positions in the slice handed to [`assemble`] that went into this
    /// message, in fragment order.
    ///
    /// The caller needs these to delete the right rows off the modem. Matching
    /// on sender and reference instead is not good enough: two deliveries can
    /// share both, and deleting by that pair would take a fragment that is
    /// still waiting for its siblings along with a message that is done.
    pub sources: Vec<usize>,
    /// Fragment numbers that never arrived, lowest first.
    ///
    /// Empty for a whole message. Non-empty only for a group released after
    /// [`FRAGMENT_GRACE_MS`], where `body` carries a marker in place of each
    /// gap so a hole is never read as the end of the text.
    pub missing: Vec<u8>,
}

/// Groups concatenation fragments into whole messages.
///
/// Returns the messages that can be stored, and the positions of the fragments
/// that should be left on the modem for a later pass.
///
/// Two things this has to get right, both found on the bench with a China
/// Mobile SIM holding nine fragments that had been re-read every eight seconds
/// for a day without one of them ever being stored or deleted:
///
/// *Duplicates are normal.* The service centre had delivered the same
/// four-fragment message twice, minutes apart, so reference `0xc3` was present
/// as eight rows: every sequence number, twice. The old rule asked for exactly
/// `total` fragments and so decided a complete message was incomplete -- and
/// because incomplete means "leave it on the modem", the duplicates could never
/// be cleared either. Fragments are now paired off by arrival order into as
/// many whole messages as the counts allow, which also handles the harder case
/// the same way: an eight-bit reference wraps, and two genuinely different
/// messages from one sender can carry the same one.
///
/// *A missing fragment is forever.* The same SIM held one fragment of a
/// two-fragment message whose sibling was lost. Nothing will ever complete it,
/// and waiting for it costs a storage slot permanently. See
/// [`FRAGMENT_GRACE_MS`].
pub fn assemble(
    parts: &[ConcatPart],
    now_ms: i64,
    grace_ms: i64,
) -> (Vec<AssembledSms>, Vec<usize>) {
    let mut groups: BTreeMap<(&str, u16, u8), Vec<usize>> = BTreeMap::new();
    let mut assembled = Vec::new();
    let mut pending = Vec::new();

    for (slot, part) in parts.iter().enumerate() {
        // A sequence number outside the header's own count is not a fragment of
        // anything this can reason about; treating it as a whole message at
        // least gets the text to the operator instead of parking it forever.
        if part.total <= 1 || part.seq == 0 || part.seq > part.total {
            assembled.push(AssembledSms {
                sender: part.sender.clone(),
                body: part.body.clone(),
                parts: 1,
                sources: vec![slot],
                missing: Vec::new(),
            });
            continue;
        }
        groups
            .entry((part.sender.as_str(), part.ref_id, part.total))
            .or_default()
            .push(slot);
    }

    for ((sender, _, total), slots) in groups {
        // One queue per sequence number, oldest first. Pairing across the
        // queues in that order keeps the fragments of one delivery together
        // when a reference has been used more than once.
        let mut queues: BTreeMap<u8, Vec<usize>> = BTreeMap::new();
        for slot in slots {
            queues.entry(parts[slot].seq).or_default().push(slot);
        }
        for queue in queues.values_mut() {
            queue.sort_by_key(|slot| (parts[*slot].received_at, *slot));
        }

        let whole = (1..=total)
            .map(|seq| queues.get(&seq).map_or(0, Vec::len))
            .min()
            .unwrap_or(0);
        for round in 0..whole {
            let sources: Vec<usize> = (1..=total).map(|seq| queues[&seq][round]).collect();
            assembled.push(AssembledSms {
                sender: sender.to_string(),
                body: sources.iter().map(|slot| parts[*slot].body.as_str()).collect(),
                parts: total,
                sources,
                missing: Vec::new(),
            });
        }

        let mut leftovers: Vec<usize> = queues
            .values()
            .flat_map(|queue| queue.iter().skip(whole).copied())
            .collect();
        if leftovers.is_empty() {
            continue;
        }
        leftovers.sort_unstable();

        let newest = leftovers
            .iter()
            .filter_map(|slot| parts[*slot].received_at)
            .max();
        let expired = newest.is_some_and(|stamp| now_ms.saturating_sub(stamp) > grace_ms);
        if !expired {
            pending.extend(leftovers);
            continue;
        }

        // Release what arrived. Every leftover row is named as a source even
        // when a duplicate of it was not used for the text, because the point
        // of releasing the group is to let the caller clear the store.
        let mut body = String::new();
        let mut missing = Vec::new();
        for seq in 1..=total {
            match leftovers.iter().find(|slot| parts[**slot].seq == seq) {
                Some(slot) => body.push_str(&parts[*slot].body),
                None => {
                    missing.push(seq);
                    body.push_str(&missing_marker(seq, total));
                }
            }
        }
        assembled.push(AssembledSms {
            sender: sender.to_string(),
            body,
            parts: total,
            sources: leftovers,
            missing,
        });
    }

    (assembled, pending)
}

/// Stands in for a fragment that never arrived.
///
/// A gap left silent reads as the end of the message. The operator has no other
/// way to know a sentence stops mid-word because the network dropped something,
/// and acting on half a message is worse than knowing half is missing.
fn missing_marker(seq: u8, total: u8) -> String {
    format!("[missing part {seq} of {total}]")
}
