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
        // Both stores. The modem chooses where a received message lands, and
        // these EC20s use their own memory: reading only the SIM showed an
        // empty inbox while five messages sat on the device.
        //
        // A store that cannot be listed is skipped rather than failing the
        // pass — some modems have no SIM store at all, and refusing to read
        // any message because one store is absent is the wrong trade.
        let mut listed = Vec::new();
        for storage in [StorageType::Uim, StorageType::Nv] {
            match QmiClient::list_sms(self, storage, MessageTag::MtUnread, MessageMode::Gw) {
                Ok(mut found) => listed.append(&mut found),
                Err(_) => continue,
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
