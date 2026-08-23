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
        // Every stored message: both stores, read and unread alike.
        //
        // Both stores because the modem chooses where a received message
        // lands, and these EC20s use their own memory: reading only the SIM
        // showed an empty inbox while five messages sat on the device.
        //
        // Both tags because the EC20 *honours* the list-tag argument. This
        // asked for `MtUnread` alone, on the strength of a comment saying the
        // tag was ignored. The bench disproved that comment on 2026-08-23:
        // one `AT+CMGR` turned a stored message into `REC READ`, and from
        // that moment five consecutive collection passes returned nothing
        // while `AT+CPMS?` still counted it in the store. Anything that marks
        // a message read — the console's own AT terminal, a diagnostic, our
        // own troubleshooting — therefore made that message invisible for
        // good and pinned its storage slot for good.
        //
        // The read flag belongs to the modem and can be flipped by anyone
        // holding a serial port, so no part of our bookkeeping may rest on
        // it. What has already been stored is answered by our own ledger of
        // ingested fragments, not by the modem's idea of what has been read.
        //
        // A store or tag that cannot be listed is skipped rather than failing
        // the pass — some modems have no SIM store at all, and refusing to
        // read any message because one query is unsupported is the wrong
        // trade.
        //
        // A modem that genuinely does ignore the tag answers both queries
        // with the same rows, so entries are deduplicated on (store, index):
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
