use std::collections::BTreeSet;

use edge_core::RegistrationEvidence;

use crate::{
    ListedMessage, MessageTag, ModemPort, PortError, RawMessage, TransportKind,
};

/// In-memory modem used by hardware-layer tests.
#[derive(Clone, Debug)]
pub struct FakeModem {
    pub imei: String,
    pub firmware: String,
    pub evidence: Vec<RegistrationEvidence>,
    messages: Vec<FakeSms>,
    reads: Vec<u32>,
    deletes: Vec<u32>,
    radio_on: bool,
}

#[derive(Clone, Debug)]
struct FakeSms {
    listed: ListedMessage,
    raw: RawMessage,
}

impl FakeModem {
    pub fn new(imei: impl Into<String>, firmware: impl Into<String>) -> Self {
        Self {
            imei: imei.into(),
            firmware: firmware.into(),
            evidence: Vec::new(),
            messages: Vec::new(),
            reads: Vec::new(),
            deletes: Vec::new(),
            radio_on: true,
        }
    }

    pub fn push_sms(&mut self, index: u32, tag: MessageTag, pdu: impl Into<Vec<u8>>) {
        self.messages.push(FakeSms {
            listed: ListedMessage { index, tag },
            raw: RawMessage {
                tag: Some(tag),
                format: 0x06,
                pdu: pdu.into(),
            },
        });
    }

    pub fn reads(&self) -> &[u32] {
        &self.reads
    }

    pub fn deletes(&self) -> &[u32] {
        &self.deletes
    }

    pub fn radio_on(&self) -> bool {
        self.radio_on
    }

    pub fn set_radio_on(&mut self, on: bool) {
        self.radio_on = on;
    }
}

impl ModemPort for FakeModem {
    fn transport_kind(&self) -> TransportKind {
        TransportKind::Qmi
    }

    fn imei(&mut self) -> Result<String, PortError> {
        Ok(self.imei.clone())
    }

    fn firmware(&mut self) -> Result<String, PortError> {
        Ok(self.firmware.clone())
    }

    fn registration_evidence(&mut self) -> Result<Vec<RegistrationEvidence>, PortError> {
        Ok(self.evidence.clone())
    }

    fn list_sms(&mut self) -> Result<Vec<ListedMessage>, PortError> {
        let deleted: BTreeSet<u32> = self.deletes.iter().copied().collect();
        Ok(self
            .messages
            .iter()
            .filter(|message| !deleted.contains(&message.listed.index))
            .map(|message| message.listed)
            .collect())
    }

    fn read_sms(&mut self, index: u32) -> Result<RawMessage, PortError> {
        self.reads.push(index);
        self.messages
            .iter()
            .find(|message| message.listed.index == index)
            .map(|message| message.raw.clone())
            .ok_or_else(|| PortError::Session(format!("no SMS at index {index}")))
    }

    fn delete_sms(&mut self, index: u32) -> Result<(), PortError> {
        self.deletes.push(index);
        Ok(())
    }

    fn send_pdu(&mut self, _pdu: &[u8]) -> Result<(), PortError> {
        Ok(())
    }
}
