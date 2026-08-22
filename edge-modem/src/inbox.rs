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

/// List, keep only MT tags from the *response*, and read those rows.
///
/// EC20 ignores the list-tag request argument. Filtering happens after parse.
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
