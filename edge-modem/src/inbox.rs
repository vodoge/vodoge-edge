use std::collections::HashMap;

use crate::wms::StorageType;
use crate::{
    retain_mobile_terminated, ListedMessage, MessageTag, ModemPort, PortError, RawMessage,
};

/// Result of one inbound collection pass. MO rows are reported so callers can
/// see they were ignored; they are never read or deleted here.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InboxPass {
    pub inbound: Vec<CollectedMessage>,
    pub skipped_mo: Vec<ListedMessage>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CollectedMessage {
    pub index: u32,
    pub tag: MessageTag,
    /// Which store it came from. Carried so the delete afterwards targets the
    /// right one — the same index in the other store is a different message.
    pub storage: StorageType,
    pub raw: RawMessage,
}

/// List every stored message, keep only MT tags from the *response*, and read
/// those rows.
///
/// The tag is taken from what the modem returned, never from what the listing
/// asked for: a modem that ignores the request filter answers with MO rows
/// mixed in, and those must not be read or deleted here.
///
/// Read and unread are both collected. Read state says nothing about whether
/// we have stored a message — it says only that somebody, possibly a console
/// AT terminal, has looked at it. Whether a message is new is decided by
/// [`fragment_fingerprint`] against our own ledger.
pub fn collect_inbound<P: ModemPort>(port: &mut P) -> Result<InboxPass, PortError> {
    let listed = port.list_sms()?;
    let inbound_listed = retain_mobile_terminated(&listed);
    let skipped_mo = listed
        .into_iter()
        .filter(|message| !message.tag.is_mobile_terminated())
        .collect::<Vec<_>>();

    let mut inbound = Vec::with_capacity(inbound_listed.len());
    for message in inbound_listed {
        let raw = port.read_sms(message.storage, message.index)?;
        inbound.push(CollectedMessage {
            index: message.index,
            tag: message.tag,
            storage: message.storage,
            raw,
        });
    }

    Ok(InboxPass {
        inbound,
        skipped_mo,
    })
}

/// What our own books call one received fragment.
///
/// The collector reads every message the modem holds, read and unread alike,
/// because the read flag is not ours: one `AT+CMGR` from a console terminal
/// flips it, and a collector that skipped read rows lost that message for
/// good. Deduplication therefore cannot lean on the modem's state at all, and
/// leans on this instead — the service centre timestamp, the sender, and the
/// fragment's own place in its concatenation, plus a hash of the text so two
/// different messages stamped in the same second are still two messages.
///
/// Fragment-level rather than message-level on purpose: a multipart message is
/// stored only once all of its parts are in hand, so the parts that arrived
/// first must be recognisable on their own in a later pass.
pub fn fragment_fingerprint(
    sender: &str,
    received_at: Option<i64>,
    ref_id: u16,
    total: u8,
    seq: u8,
    body: &str,
) -> String {
    let stamp = received_at.map_or_else(|| "-".to_string(), |ms| ms.to_string());
    format!(
        "v1|{sender}|{stamp}|{ref_id:04x}|{total}|{seq}|{:016x}",
        fnv1a64(body.as_bytes())
    )
}

/// FNV-1a, 64 bit.
///
/// Written out rather than taken from `DefaultHasher` because these values are
/// persisted: the standard hasher is explicitly not stable across Rust
/// releases, so an upgrade would silently invalidate the whole ledger and
/// re-store every message still sitting on a modem. Not a security boundary —
/// the input is a message body we just decoded ourselves.
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Which fragments of this pass our books already account for, in the order
/// they were listed.
///
/// `ingested` says how many copies of each fingerprint were stored on earlier
/// passes. Copies matter: this bench has seen the service centre deliver the
/// same four-part message twice, and both deliveries are real messages the
/// operator should see. So the first `n` occurrences of a fingerprint already
/// stored `n` times are old, and everything beyond that is new.
///
/// A fragment reported here is not lost — it is one whose delete did not take
/// last time, and the caller should delete it rather than store it again.
pub fn seen_before(fingerprints: &[String], ingested: &HashMap<String, u32>) -> Vec<bool> {
    let mut matched: HashMap<&str, u32> = HashMap::new();
    fingerprints
        .iter()
        .map(|fingerprint| {
            let already = ingested.get(fingerprint.as_str()).copied().unwrap_or(0);
            let used = matched.entry(fingerprint.as_str()).or_insert(0);
            if *used < already {
                *used += 1;
                true
            } else {
                false
            }
        })
        .collect()
}

/// Delete only indexes that were collected as inbound MT. Never used for MO.
pub fn delete_inbound<P: ModemPort>(
    port: &mut P,
    inbound: &[CollectedMessage],
) -> Result<(), PortError> {
    for message in inbound {
        port.delete_sms(message.storage, message.index)?;
    }
    Ok(())
}

#[cfg(test)]
mod ledger_tests {
    use super::*;

    fn ledger(entries: &[(&str, u32)]) -> HashMap<String, u32> {
        entries
            .iter()
            .map(|(fingerprint, copies)| ((*fingerprint).to_string(), *copies))
            .collect()
    }

    /// The property the whole ledger exists for: identity comes from what the
    /// network sent, so it survives anything done to the modem afterwards.
    /// Marking a message read, or its moving to another storage index, must
    /// not make it look like a different message.
    #[test]
    fn the_same_delivery_fingerprints_the_same_way_twice() {
        let first = fragment_fingerprint("10086", Some(1_756_058_516_000), 0xc3, 4, 2, "part two");
        let second = fragment_fingerprint("10086", Some(1_756_058_516_000), 0xc3, 4, 2, "part two");
        assert_eq!(first, second);
    }

    #[test]
    fn a_different_fragment_of_one_message_is_a_different_row() {
        let second = fragment_fingerprint("10086", Some(1_756_058_516_000), 0xc3, 4, 2, "part two");
        let third = fragment_fingerprint("10086", Some(1_756_058_516_000), 0xc3, 4, 3, "part three");
        assert_ne!(second, third);
    }

    /// Two messages from one sender in the same second, which 10086 does send.
    /// Without the body in the key they would collide and the second would be
    /// silently dropped as a duplicate.
    #[test]
    fn two_texts_stamped_in_the_same_second_are_two_messages() {
        let stamp = Some(1_756_058_516_000);
        assert_ne!(
            fragment_fingerprint("10086", stamp, 0, 1, 1, "balance 12.30"),
            fragment_fingerprint("10086", stamp, 0, 1, 1, "balance 9.80")
        );
    }

    /// A PDU with no readable timestamp still gets a stable identity rather
    /// than a fresh one every pass, which would re-store it every eight
    /// seconds forever.
    #[test]
    fn an_undated_fragment_still_has_one_identity() {
        assert_eq!(
            fragment_fingerprint("10086", None, 0, 1, 1, "no scts"),
            fragment_fingerprint("10086", None, 0, 1, 1, "no scts")
        );
    }

    #[test]
    fn a_fragment_never_stored_is_new() {
        let pass = vec![fragment_fingerprint("10086", Some(1), 0, 1, 1, "hello")];
        assert_eq!(seen_before(&pass, &ledger(&[])), vec![false]);
    }

    /// The case that makes reading read messages safe: it is on the modem and
    /// it is on our books, so it is not stored again.
    #[test]
    fn a_fragment_already_stored_is_not_new_again() {
        let one = fragment_fingerprint("10086", Some(1), 0, 1, 1, "hello");
        assert_eq!(seen_before(&[one.clone()], &ledger(&[(&one, 1)])), vec![true]);
    }

    /// The service centre delivering the same message twice is a real event on
    /// this bench, and the second copy is a real message. Having stored one
    /// copy must not swallow the other.
    #[test]
    fn a_second_copy_of_a_stored_message_is_still_new() {
        let one = fragment_fingerprint("10086", Some(1), 0xc3, 2, 1, "half");
        let pass = vec![one.clone(), one.clone()];
        assert_eq!(seen_before(&pass, &ledger(&[(&one, 1)])), vec![true, false]);
    }

    #[test]
    fn both_copies_are_old_once_both_are_stored() {
        let one = fragment_fingerprint("10086", Some(1), 0xc3, 2, 1, "half");
        let pass = vec![one.clone(), one.clone()];
        assert_eq!(seen_before(&pass, &ledger(&[(&one, 2)])), vec![true, true]);
    }
}
