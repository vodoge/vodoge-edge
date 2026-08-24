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

/// Every assigned MNC is two or three digits long. A card claiming anything
/// else has been misread, and slicing an IMSI by it would name a network at
/// random.
pub const MIN_MNC_DIGITS: usize = 2;
pub const MAX_MNC_DIGITS: usize = 3;

/// Why `EF_AD` could not say how long the MNC is.
///
/// Named rather than swallowed. The fallback for either of these is today's
/// two-digit assumption, and a fallback that leaves no trace is how a US card
/// would come to report `310-26` with nothing in the log to explain it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EfAdError {
    /// The file is shorter than four bytes, so it carries no MNC length.
    NoMncLengthByte { actual: usize },
    /// Byte 4 named a length no assigned MNC has.
    ImplausibleMncLength { actual: u8 },
}

impl std::fmt::Display for EfAdError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoMncLengthByte { actual } => write!(
                formatter,
                "EF_AD is {actual} bytes, too short to state the MNC length"
            ),
            Self::ImplausibleMncLength { actual } => {
                write!(formatter, "EF_AD claims a {actual}-digit MNC")
            }
        }
    }
}

impl std::error::Error for EfAdError {}

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

    /// The home network an IMSI names, split where the card says to split it.
    ///
    /// The MCC is always the first three digits. Where the MNC ends is not
    /// fixed: two digits across most of the world, three across North
    /// America, and **only the card knows which** — `EF_AD` states it, see
    /// [`Network::mnc_digits_from_ef_ad`]. Assuming two produces a *plausible
    /// wrong* network rather than a missing one, which is the worse failure:
    /// `310260…` cut at two digits is `310-26`, an unassigned pair that falls
    /// through every table and renders as a bare string, and the same
    /// assumption feeds the ePDG FQDN `mnc026` instead of `mnc260`.
    ///
    /// Returns `None` for anything that is not an MCC followed by that many
    /// MNC digits: a short or non-numeric IMSI is a failed read, and naming a
    /// network for it would put a card on an operator it has never met.
    pub fn from_imsi(imsi: &str, mnc_digits: usize) -> Option<Self> {
        if !(MIN_MNC_DIGITS..=MAX_MNC_DIGITS).contains(&mnc_digits) {
            return None;
        }
        let mcc = imsi.get(0..3)?;
        let mnc = imsi.get(3..3 + mnc_digits)?;
        // `u16::from_str` accepts a leading `+`, which no IMSI has and which
        // would turn a corrupt read into a network number.
        if !mcc.bytes().chain(mnc.bytes()).all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        Some(Self::new(mcc.parse().ok()?, mnc.parse().ok()?))
    }

    /// How many digits of the IMSI belong to the MNC, as `EF_AD` states it.
    ///
    /// `EF_AD` (3F00/7FFF/6FAD, transparent, readable on the basic channel)
    /// is byte 1 MS operation mode, bytes 2-3 additional information, and
    /// **byte 4's low nibble is the length of the MNC in the IMSI**
    /// (3GPP TS 31.102 §4.2.18). All three bench cards answer `00 00 00 02`,
    /// sampled over both QMI UIM READ TRANSPARENT and
    /// `AT+CRSM=176,28589,0,0,4` before this was written; a North American
    /// card answers `…03`.
    ///
    /// Older cards stop at three bytes and never state it. That is an error
    /// here rather than a silent two, so a caller can say which card would
    /// not answer before it falls back.
    pub fn mnc_digits_from_ef_ad(bytes: &[u8]) -> Result<usize, EfAdError> {
        let byte = *bytes
            .get(3)
            .ok_or(EfAdError::NoMncLengthByte { actual: bytes.len() })?;
        let digits = usize::from(byte & 0x0f);
        if !(MIN_MNC_DIGITS..=MAX_MNC_DIGITS).contains(&digits) {
            return Err(EfAdError::ImplausibleMncLength { actual: byte & 0x0f });
        }
        Ok(digits)
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

    /// The capability-matrix carrier key for this network.
    ///
    /// Derived from the same table as `label`, not a second list of MNCs: two
    /// lists drift, and the one that drifts silently is the one that decides
    /// whether we claim a card can send SMS.
    ///
    /// 中国广电 and 中国铁通 ride China Mobile's radio network — Tietong is a
    /// CMCC subsidiary and Broadnet shares CMCC's network by agreement — so
    /// they behave like CN-Mobile for everything the matrix decides. Anything
    /// we cannot name is `Generic-International`, whose matrix entries are
    /// `probe`: the honest answer for a card we have never characterised.
    pub fn carrier_profile(self) -> &'static str {
        if self.mcc != 460 {
            return "Generic-International";
        }
        match self.label().as_str() {
            "中国移动" | "中国广电" | "中国铁通" => "CN-Mobile",
            "中国联通" => "CN-Unicom",
            "中国电信" => "CN-Telecom",
            _ => "Generic-International",
        }
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
    // United States. The eSIM this product exists to run is a US profile, and
    // every one of these has a three-digit MNC — which is why the split has to
    // come off the card (`from_imsi`) rather than from a fixed two.
    //
    // Nothing here has a leading zero in its MNC on purpose: `numeric()`
    // renders the MNC with a minimum width of two, so 310-004 would come back
    // out as `310-04` and match no key. Adding one would encode that
    // rendering into the table instead of fixing it.
    (310, 260, "T-Mobile"),
    (310, 410, "AT&T"),
    (310, 280, "AT&T"),
    (311, 480, "Verizon"),
    // Common roaming partners seen in testing
    (505, 1, "Telstra"),
    (440, 10, "NTT docomo"),
    (450, 5, "SK Telecom"),
    (525, 1, "Singtel"),
];

const TERRITORIES: &[(u16, &str)] = &[
    (310, "美国"),
    (311, "美国"),
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

    /// Every mainland MNC the label table knows must also land on a carrier
    /// profile. A network we can name but cannot classify would silently take
    /// the international fallback and report `unknown` capabilities for a card
    /// we actually support.
    #[test]
    fn known_mainland_networks_all_map_to_a_carrier() {
        for (mcc, mnc, name) in NETWORKS.iter().filter(|(mcc, _, _)| *mcc == 460) {
            let profile = Network::new(*mcc, *mnc).carrier_profile();
            assert_ne!(
                profile, "Generic-International",
                "{name} ({mcc}-{mnc}) fell through to the international fallback",
            );
        }
    }

    /// The card this product exists to run is a US profile, and its MNC is
    /// three digits. Sliced at two — which is what this agent did until the
    /// MNC length was read off `EF_AD` — `310260…` becomes `310-26`: not a
    /// blank, not an error, an unassigned pair that renders as a bare string
    /// and would feed the ePDG FQDN as `mnc026`.
    #[test]
    fn a_three_digit_mnc_survives_the_imsi_split() {
        let network = Network::from_imsi("310260123456789", 3).expect("split");
        assert_eq!(network.numeric(), "310-260");
        assert_eq!(network.describe(), "T-Mobile · 美国");
        assert_eq!(
            Network::from_imsi("310260123456789", 2).map(Network::numeric),
            Some("310-26".to_string()),
            "the old two-digit rule, kept here to name what it produced",
        );
    }

    /// The three cards on the bench, each with the `EF_AD` they actually
    /// answered. Their home networks must not move because a US card was
    /// taught to work.
    #[test]
    fn the_bench_cards_keep_the_networks_they_report_today() {
        for (imsi, ef_ad, expected) in [
            ("454006395021420", [0x00, 0x00, 0x00, 0x02], "454-00"),
            ("460026303803275", [0x00, 0x00, 0x00, 0x02], "460-02"),
            ("454003063217957", [0x00, 0x00, 0x00, 0x02], "454-00"),
        ] {
            let digits = Network::mnc_digits_from_ef_ad(&ef_ad).expect("EF_AD");
            let network = Network::from_imsi(imsi, digits).expect("split");
            assert_eq!(network.numeric(), expected, "{imsi}");
        }
    }

    #[test]
    fn ef_ad_states_the_mnc_length_in_the_low_nibble_of_byte_four() {
        // As sampled on the bench: mode 00, additional info 00 00, length 2.
        assert_eq!(Network::mnc_digits_from_ef_ad(&[0x00, 0x00, 0x00, 0x02]), Ok(2));
        // North America, and the high nibble is reserved -- it is not part of
        // the length and must not be read as one.
        assert_eq!(Network::mnc_digits_from_ef_ad(&[0x00, 0x00, 0x00, 0xf3]), Ok(3));
        // Trailing bytes exist on some cards and say nothing about the MNC.
        assert_eq!(
            Network::mnc_digits_from_ef_ad(&[0x00, 0x00, 0x00, 0x03, 0x00, 0x00]),
            Ok(3)
        );
    }

    /// A card that will not state the length must say so, not answer two.
    #[test]
    fn an_ef_ad_that_cannot_state_the_length_is_an_error() {
        assert_eq!(
            Network::mnc_digits_from_ef_ad(&[0x00, 0x00, 0x00]),
            Err(EfAdError::NoMncLengthByte { actual: 3 })
        );
        assert_eq!(
            Network::mnc_digits_from_ef_ad(&[]),
            Err(EfAdError::NoMncLengthByte { actual: 0 })
        );
        assert_eq!(
            Network::mnc_digits_from_ef_ad(&[0x00, 0x00, 0x00, 0x09]),
            Err(EfAdError::ImplausibleMncLength { actual: 9 })
        );
    }

    /// A failed read must not become a network. Half an IMSI split into an
    /// MCC and whatever follows would put a card on an operator at random.
    #[test]
    fn a_malformed_imsi_names_no_network() {
        assert_eq!(Network::from_imsi("3102", 3), None);
        assert_eq!(Network::from_imsi("", 2), None);
        assert_eq!(Network::from_imsi("31O260123456789", 3), None);
        // `u16::from_str` would have taken this one.
        assert_eq!(Network::from_imsi("310+60123456789", 3), None);
        // A length no card should ever state.
        assert_eq!(Network::from_imsi("310260123456789", 4), None);
        assert_eq!(Network::from_imsi("310260123456789", 1), None);
    }

    /// Every US network the table names must be reachable by the split that
    /// produces it, or the entry is decoration.
    #[test]
    fn the_us_entries_are_reachable_from_a_three_digit_split() {
        for (mcc, mnc, name) in NETWORKS
            .iter()
            .filter(|(mcc, _, _)| *mcc == 310 || *mcc == 311)
        {
            let imsi = format!("{mcc:03}{mnc:03}123456789");
            let network = Network::from_imsi(&imsi, 3)
                .unwrap_or_else(|| panic!("{name} ({mcc}-{mnc}) did not split"));
            assert_eq!(network.label(), *name);
            assert_eq!(network.territory(), Some("美国"));
        }
    }

    #[test]
    fn networks_outside_the_mainland_are_international() {
        assert_eq!(Network::new(454, 0).carrier_profile(), "Generic-International");
        assert_eq!(Network::new(310, 260).carrier_profile(), "Generic-International");
    }
}
