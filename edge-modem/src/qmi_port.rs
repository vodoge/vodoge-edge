use std::collections::BTreeSet;

use edge_core::{Bearer, Plmn, RegistrationEvidence};

use crate::{
    ListedMessage, MessageMode, MessageTag, ModemPort, NasRegistrationState, PortError, QmiClient,
    QmiTransport, RawMessage, StorageType, TransportKind,
};

const GSM_WCDMA_FORMAT: u8 = 0x06;

impl<T: QmiTransport> ModemPort for QmiClient<T> {
    fn transport_kind(&self) -> TransportKind {
        TransportKind::Qmi
    }

    fn imei(&mut self) -> Result<String, PortError> {
        self.get_serial_numbers()?
            .imei
            .ok_or(PortError::MissingImei)
    }

    fn firmware(&mut self) -> Result<String, PortError> {
        Ok(self.get_revision()?.device_rev_id)
    }

    fn registration_evidence(&mut self) -> Result<Vec<RegistrationEvidence>, PortError> {
        let mut evidence = Vec::new();
        if let Ok(serving) = self.get_serving_system() {
            let plmn = match (serving.mcc, serving.mnc) {
                (Some(mcc), Some(mnc)) if mcc != 0 => {
                    Some(Plmn::new(format!("{mcc:03}"), format!("{mnc}")))
                }
                _ => None,
            };
            evidence.push(RegistrationEvidence::serving_system(
                serving.registration_state == NasRegistrationState::Registered,
                plmn,
            ));
        }
        if let Ok(info) = self.get_cell_location() {
            if let Some(lte) = info.lte {
                evidence.push(RegistrationEvidence::cell_location(
                    Some(Plmn::new(lte.mcc, lte.mnc)),
                    Some(lte.global_cell_id),
                ));
            }
        }
        Ok(evidence)
    }

    fn list_sms(&mut self) -> Result<Vec<ListedMessage>, PortError> {
        // Every stored message, read and unread alike, from both stores.
        //
        // Both stores because the modem chooses where a received message
        // lands, and these EC20s use their own memory: reading only the SIM
        // showed an empty inbox while five messages sat on the device.
        //
        // Read as well as unread because of what the bench proved on
        // 2026-08-23. This asked the listing for unread messages only, on the
        // strength of a comment saying the EC20 ignores the tag. The comment
        // was wrong twice over. One `AT+CMGR` turned a stored message into
        // `REC READ`, and from that moment five consecutive collection passes
        // returned nothing while `AT+CPMS?` still counted it in the store: the
        // message was unreachable for good and its slot was held for good.
        // Anything that reads a message does this -- the console's own AT
        // terminal, a diagnostic, our own troubleshooting -- and it happened
        // at least twice in a single day of debugging.
        //
        // The obvious repair, asking the listing for read messages too, does
        // not work on this firmware. Measured against all three modules:
        // `QMI_WMS_LIST_MESSAGES` accepts `MT_NOT_READ` and rejects every
        // other tag outright -- `MT_READ` comes back as a failure with error
        // 47, the tag values for "all" are error 48, and omitting the tag is
        // rejected as a missing argument. There is no listing this firmware
        // offers that can name a read message; [`ModemPort::sweep_slots`] is
        // what finds those, by reading the slots themselves.
        //
        // The tag is still asked for both ways, because firmware that does
        // answer `MT_READ` gives a complete listing at once and leaves the
        // sweep nothing to find.
        //
        // What none of this may depend on is the read flag itself. It belongs
        // to the modem and any serial port can flip it, so whether a message
        // has already been stored is answered by our own ledger of ingested
        // fragments instead.
        //
        // A store or tag that cannot be listed is skipped rather than failing
        // the pass -- some modems have no SIM store at all, and refusing to
        // read any message because one query is unsupported is the wrong
        // trade. Entries are deduplicated on (store, index) because firmware
        // that ignores the tag answers both queries with the same rows, and
        // reading one message twice in a pass would store it twice.
        let mut listed = Vec::new();
        let mut seen = BTreeSet::new();
        for storage in [StorageType::Uim, StorageType::Nv] {
            for tag in [MessageTag::MtUnread, MessageTag::MtRead] {
                let found = match QmiClient::list_sms(self, storage, tag, MessageMode::Gw) {
                    Ok(found) => found,
                    Err(_) => continue,
                };
                for message in found {
                    if seen.insert((message.storage, message.index)) {
                        listed.push(message);
                    }
                }
            }
        }
        Ok(listed)
    }

    fn sweep_slots(&mut self, first: u32, count: u32) -> Result<Vec<ListedMessage>, PortError> {
        // Read the slots themselves, because the listing cannot name a
        // message somebody has marked read (see `list_sms`) and reading one
        // can: `QMI_WMS_RAW_READ` at the index of a read message returns it
        // with `MT_READ` on it in about eight milliseconds, and an empty slot
        // refuses in about the same. Measured on the bench: twelve reads in
        // 94 ms.
        //
        // Both stores, for the same reason the listing asks both.
        let mut found = Vec::new();
        for storage in [StorageType::Uim, StorageType::Nv] {
            for index in first..first.saturating_add(count) {
                let Ok(raw) = QmiClient::read_sms(self, storage, index, MessageMode::Gw) else {
                    continue;
                };
                // Only what the modem itself calls mobile-terminated. A slot
                // whose read carries no tag cannot be told apart from an
                // outgoing message, and "collecting" one of those would end
                // in deleting a record of something we sent.
                let Some(tag) = raw.tag.filter(|tag| tag.is_mobile_terminated()) else {
                    continue;
                };
                found.push(ListedMessage {
                    index,
                    tag,
                    storage,
                });
            }
        }
        Ok(found)
    }

    fn read_sms(&mut self, storage: StorageType, index: u32) -> Result<RawMessage, PortError> {
        Ok(QmiClient::read_sms(self, storage, index, MessageMode::Gw)?)
    }

    fn delete_sms(&mut self, storage: StorageType, index: u32) -> Result<(), PortError> {
        Ok(QmiClient::delete_sms(self, storage, index, MessageMode::Gw)?)
    }

    fn send_on(&mut self, bearer: Bearer, pdu: &[u8]) -> Result<(), PortError> {
        match bearer {
            Bearer::Cellular => {
                self.send_sms(GSM_WCDMA_FORMAT, pdu)?;
                Ok(())
            }
            other => Err(PortError::Session(format!(
                "QMI WMS cannot send on {other}"
            ))),
        }
    }
}
