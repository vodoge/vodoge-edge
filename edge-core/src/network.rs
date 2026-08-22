//! Readable names for the networks a modem reports.
//!
//! A panel that shows only an ICCID cannot answer the first question an
//! operator asks about a stick: whose card is this. The serving system already
//! carries MCC and MNC, so the answer costs nothing more to fetch — it only
//! has to be kept rather than discarded.
//!
//! The table covers the networks this product actually meets. Anything else
//! falls back to the numeric pair, which is still more useful than nothing and
//! is what an operator would look up anyway.

/// One network's identity as reported over the air.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Network {
    pub mcc: u16,
    pub mnc: u16,
}

impl Network {
    pub fn new(mcc: u16, mnc: u16) -> Self {
        Self { mcc, mnc }
    }

    /// `460-01` style identifier, always two digits of MNC.
    ///
    /// Three-digit MNCs exist, but not in the ranges this product operates in,
    /// and padding a two-digit MNC is what every operator tool does.
    pub fn numeric(self) -> String {
        format!("{:03}-{:02}", self.mcc, self.mnc)
    }

    /// Operator name, or the numeric pair when it is not one we know.
    pub fn label(self) -> String {
        NETWORKS
            .iter()
            .find(|(mcc, mnc, _)| *mcc == self.mcc && *mnc == self.mnc)
            .map(|(_, _, name)| (*name).to_string())
            .unwrap_or_else(|| self.numeric())
    }

    /// Country or region the MCC belongs to, when known.
    pub fn territory(self) -> Option<&'static str> {
        TERRITORIES
            .iter()
            .find(|(mcc, _)| *mcc == self.mcc)
            .map(|(_, name)| *name)
    }

    /// A single line for a card that has room for one: operator plus where the
    /// subscription is from, which together say whether a card is roaming.
    pub fn describe(self) -> String {
        match self.territory() {
            Some(territory) => format!("{} · {}", self.label(), territory),
            None => self.label(),
        }
    }
}

/// Networks this product is deployed against. Mainland China and Hong Kong are
/// covered because both appear on the bench; the rest are common roaming
/// partners seen in testing.
const NETWORKS: &[(u16, u16, &str)] = &[
    // Mainland China
    (460, 0, "中国移动"),
    (460, 2, "中国移动"),
    (460, 4, "中国移动"),
    (460, 7, "中国移动"),
    (460, 8, "中国移动"),
    (460, 1, "中国联通"),
    (460, 6, "中国联通"),
    (460, 9, "中国联通"),
    (460, 3, "中国电信"),
    (460, 5, "中国电信"),
    (460, 11, "中国电信"),
    (460, 15, "中国广电"),
    (460, 20, "中国铁通"),
    // Hong Kong
    (454, 0, "CSL"),
    (454, 2, "CSL"),
    (454, 3, "3 HK"),
    (454, 4, "3 HK"),
    (454, 6, "SmarTone"),
    (454, 10, "CSL"),
    (454, 12, "CMHK"),
    (454, 16, "CMHK"),
    (454, 19, "SmarTone"),
    // Macau and Taiwan
    (455, 1, "CTM"),
    (455, 3, "3 Macau"),
    (466, 92, "中華電信"),
    (466, 97, "台灣大哥大"),
    // Common roaming partners seen in testing
    (505, 1, "Telstra"),
    (440, 10, "NTT docomo"),
    (450, 5, "SK Telecom"),
    (525, 1, "Singtel"),
];

const TERRITORIES: &[(u16, &str)] = &[
    (460, "中国大陆"),
    (454, "中国香港"),
    (455, "中国澳门"),
    (466, "中国台湾"),
    (505, "澳大利亚"),
    (440, "日本"),
    (450, "韩国"),
    (525, "新加坡"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_known_network_is_named() {
        assert_eq!(Network::new(460, 0).label(), "中国移动");
        assert_eq!(Network::new(460, 1).label(), "中国联通");
        assert_eq!(Network::new(454, 0).label(), "CSL");
    }

    /// An unknown pair still tells the operator what to look up, which beats an
    /// empty field.
    #[test]
    fn an_unknown_network_falls_back_to_its_number() {
        assert_eq!(Network::new(999, 42).label(), "999-42");
        assert_eq!(Network::new(999, 42).territory(), None);
    }

    /// MNC 0 is a real value and must not collapse to a single digit: 460-00 is
    /// China Mobile and 460-0 is not a well-formed identifier.
    #[test]
    fn a_single_digit_mnc_is_padded() {
        assert_eq!(Network::new(460, 0).numeric(), "460-00");
        assert_eq!(Network::new(460, 11).numeric(), "460-11");
    }

    /// This is what distinguishes the two cards on the bench: both are Hong
    /// Kong subscriptions, so the territory is the part that says so.
    #[test]
    fn describe_names_the_operator_and_where_it_is_from() {
        assert_eq!(Network::new(454, 0).describe(), "CSL · 中国香港");
        assert_eq!(Network::new(460, 0).describe(), "中国移动 · 中国大陆");
    }

    #[test]
    fn describe_omits_an_unknown_territory() {
        assert_eq!(Network::new(999, 42).describe(), "999-42");
    }
}
