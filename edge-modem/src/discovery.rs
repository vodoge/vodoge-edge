use crate::TransportKind;

/// A candidate control channel found on the host.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveredModem {
    pub kind: TransportKind,
    pub path: String,
    pub net_iface: Option<String>,
}

/// Host enumeration. Production reads sysfs; tests inject a fake list.
pub trait DeviceEnumerator {
    fn qmi_candidates(&self) -> Vec<DiscoveredModem>;
    fn mbim_candidates(&self) -> Vec<DiscoveredModem>;
    fn vid_at_candidates(&self) -> Vec<DiscoveredModem>;
}

/// QMI first, then MBIM, then VID/AT fallback. The first non-empty step wins.
pub fn discover<E: DeviceEnumerator>(enumerator: &E) -> Vec<DiscoveredModem> {
    let qmi = enumerator.qmi_candidates();
    if !qmi.is_empty() {
        return qmi;
    }
    let mbim = enumerator.mbim_candidates();
    if !mbim.is_empty() {
        return mbim;
    }
    enumerator.vid_at_candidates()
}

/// In-memory enumerator for the three-step discovery tests.
#[derive(Clone, Debug, Default)]
pub struct FakeEnumerator {
    pub qmi: Vec<DiscoveredModem>,
    pub mbim: Vec<DiscoveredModem>,
    pub at: Vec<DiscoveredModem>,
}

impl DeviceEnumerator for FakeEnumerator {
    fn qmi_candidates(&self) -> Vec<DiscoveredModem> {
        self.qmi.clone()
    }

    fn mbim_candidates(&self) -> Vec<DiscoveredModem> {
        self.mbim.clone()
    }

    fn vid_at_candidates(&self) -> Vec<DiscoveredModem> {
        self.at.clone()
    }
}
