use std::collections::BTreeMap;

/// One fragment of a concatenated SMS.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConcatPart {
    pub sender: String,
    pub ref_id: u16,
    pub total: u8,
    pub seq: u8,
    pub body: String,
}

/// A fully assembled inbound SMS, possibly from several fragments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssembledSms {
    pub sender: String,
    pub body: String,
    pub parts: u8,
}

/// Groups concatenation fragments. Incomplete groups stay pending.
pub fn assemble(parts: &[ConcatPart]) -> (Vec<AssembledSms>, Vec<ConcatPart>) {
    let mut groups: BTreeMap<(String, u16, u8), Vec<ConcatPart>> = BTreeMap::new();
    let mut singles = Vec::new();
    let mut pending = Vec::new();

    for part in parts {
        if part.total <= 1 || part.seq == 0 {
            singles.push(AssembledSms {
                sender: part.sender.clone(),
                body: part.body.clone(),
                parts: 1,
            });
            continue;
        }
        groups
            .entry((part.sender.clone(), part.ref_id, part.total))
            .or_default()
            .push(part.clone());
    }

    let mut assembled = singles;
    for ((sender, _, total), mut group) in groups {
        group.sort_by_key(|part| part.seq);
        let complete = (1..=total).all(|seq| group.iter().any(|part| part.seq == seq));
        if complete && group.len() == total as usize {
            assembled.push(AssembledSms {
                sender,
                body: group.into_iter().map(|part| part.body).collect(),
                parts: total,
            });
        } else {
            pending.extend(group);
        }
    }

    (assembled, pending)
}
