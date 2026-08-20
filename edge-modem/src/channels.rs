use std::collections::BTreeSet;

/// Open UICC logical channels. Switch/disable must not close the eSIM channel
/// the operation itself is using (§4.6).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LogicalChannels {
    open: BTreeSet<u8>,
    esim: Option<u8>,
}

impl LogicalChannels {
    pub fn open(&mut self, channel: u8) {
        self.open.insert(channel);
    }

    pub fn set_esim(&mut self, channel: u8) {
        self.open.insert(channel);
        self.esim = Some(channel);
    }

    pub fn esim(&self) -> Option<u8> {
        self.esim
    }

    /// Close every channel except the current eSIM ISD-R channel.
    pub fn release_all_except_esim(&mut self) -> Vec<u8> {
        let keep = self.esim;
        let mut closed = Vec::new();
        self.open.retain(|&channel| {
            if Some(channel) == keep {
                true
            } else {
                closed.push(channel);
                false
            }
        });
        closed
    }

    pub fn is_open(&self, channel: u8) -> bool {
        self.open.contains(&channel)
    }
}
