use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A modem family detected from the device firmware rather than a USB product ID.
///
/// `Other` keeps the matrix extensible when support for a new modem is delivered
/// as data before the edge binary receives a dedicated variant.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum ModemFamily {
    Ec20,
    Ec25Cn,
    Eg25G,
    Ufi103s,
    Other(String),
}

impl ModemFamily {
    pub const EC20: Self = Self::Ec20;
    pub const EC25_CN: Self = Self::Ec25Cn;
    pub const EG25_G: Self = Self::Eg25G;
    pub const UFI103S: Self = Self::Ufi103s;

    pub fn as_str(&self) -> &str {
        match self {
            Self::Ec20 => "EC20",
            Self::Ec25Cn => "EC25-CN",
            Self::Eg25G => "EG25-G",
            Self::Ufi103s => "UFI103S",
            Self::Other(value) => value,
        }
    }
}

impl ModemFamily {
    /// Detects the family from what the module reports about itself.
    ///
    /// The QMI model TLV on these sticks is the USB descriptor string —
    /// "QUECTEL Mobile Broadband Module" on the bench EC20s — so the model
    /// alone cannot key the capability matrix. The firmware revision is the
    /// reliable source: Quectel starts it with the model name
    /// ("EC20CEHCLGR06A08M1G_AUD"), and AT+CGMM agrees ("EC20F") when it is
    /// readable. Both are checked, model first.
    ///
    /// EC25 needs the region letter: "EC25C…" is the CN variant the matrix
    /// characterises; an EC25-E is a different radio and mapping it onto the
    /// CN rules would claim capabilities nobody measured. Unrecognised
    /// hardware stays `Other`, which the matrix answers with `probe`.
    pub fn detect(model: &str, revision: &str) -> Self {
        for source in [model, revision] {
            if source.starts_with("EG25G") || source.starts_with("EG25-G") {
                return Self::Eg25G;
            }
            if source.starts_with("EC25C") || source.starts_with("EC25-CN") {
                return Self::Ec25Cn;
            }
            if source.starts_with("EC20") {
                return Self::Ec20;
            }
            if source.starts_with("UFI103S") {
                return Self::Ufi103s;
            }
        }
        Self::Other(model.to_owned())
    }
}

impl From<&str> for ModemFamily {
    fn from(value: &str) -> Self {
        match value {
            "EC20" => Self::Ec20,
            "EC25-CN" => Self::Ec25Cn,
            "EG25-G" => Self::Eg25G,
            "UFI103S" => Self::Ufi103s,
            value => Self::Other(value.to_owned()),
        }
    }
}

impl From<String> for ModemFamily {
    fn from(value: String) -> Self {
        Self::from(value.as_str())
    }
}

impl fmt::Display for ModemFamily {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Serialize for ModemFamily {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ModemFamily {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self::from)
    }
}

/// A carrier profile derived from network identity and carrier-specific setup.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum CarrierProfile {
    CnMobile,
    CnUnicom,
    CnTelecom,
    GenericInternational,
    Other(String),
}

impl CarrierProfile {
    pub const CN_MOBILE: Self = Self::CnMobile;
    pub const CN_UNICOM: Self = Self::CnUnicom;
    pub const CN_TELECOM: Self = Self::CnTelecom;
    pub const GENERIC_INTERNATIONAL: Self = Self::GenericInternational;

    pub fn as_str(&self) -> &str {
        match self {
            Self::CnMobile => "CN-Mobile",
            Self::CnUnicom => "CN-Unicom",
            Self::CnTelecom => "CN-Telecom",
            Self::GenericInternational => "Generic-International",
            Self::Other(value) => value,
        }
    }
}

impl From<&str> for CarrierProfile {
    fn from(value: &str) -> Self {
        match value {
            "CN-Mobile" => Self::CnMobile,
            "CN-Unicom" => Self::CnUnicom,
            "CN-Telecom" => Self::CnTelecom,
            "Generic-International" => Self::GenericInternational,
            value => Self::Other(value.to_owned()),
        }
    }
}

impl From<String> for CarrierProfile {
    fn from(value: String) -> Self {
        Self::from(value.as_str())
    }
}

impl fmt::Display for CarrierProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Serialize for CarrierProfile {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for CarrierProfile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self::from)
    }
}

/// An operator-selected service line. It is deliberately not inferred from MCC.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Vertical {
    Cn,
    Intl,
    Custom(String),
}

impl Vertical {
    pub const CN: Self = Self::Cn;
    pub const INTL: Self = Self::Intl;

    pub fn as_str(&self) -> &str {
        match self {
            Self::Cn => "cn",
            Self::Intl => "intl",
            Self::Custom(value) => value,
        }
    }
}

impl From<&str> for Vertical {
    fn from(value: &str) -> Self {
        match value {
            "cn" => Self::Cn,
            "intl" => Self::Intl,
            value => Self::Custom(value.to_owned()),
        }
    }
}

impl From<String> for Vertical {
    fn from(value: String) -> Self {
        Self::from(value.as_str())
    }
}

impl fmt::Display for Vertical {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Serialize for Vertical {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Vertical {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self::from)
    }
}

/// A stable name for a vertical factory.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct VerticalId(String);

impl VerticalId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for VerticalId {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for VerticalId {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl fmt::Display for VerticalId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The bearer selected for an operation after capability and radio state checks.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Bearer {
    Cellular,
    Ims,
    Sgs,
}

impl fmt::Display for Bearer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cellular => formatter.write_str("cellular"),
            Self::Ims => formatter.write_str("ims"),
            Self::Sgs => formatter.write_str("sgs"),
        }
    }
}

/// A prior capability result. `Probe` deliberately preserves room for runtime
/// discovery without forcing higher-level policies to issue a blind send first.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BearerSupport {
    Supported(Bearer),
    Unsupported { reason: String },
    Probe,
}

impl BearerSupport {
    pub fn supported(bearer: Bearer) -> Self {
        Self::Supported(bearer)
    }

    pub fn unsupported(reason: impl Into<String>) -> Self {
        Self::Unsupported {
            reason: reason.into(),
        }
    }

    /// The value the edge-cloud contract expects for this support state.
    ///
    /// `Probe` means the matrix has no entry and nothing has been measured, so
    /// the wire value is `unknown` — not `unsupported`. Reporting a card as
    /// incapable because we never characterised it would make the cloud hide
    /// a working modem.
    pub fn wire(&self) -> &'static str {
        match self {
            Self::Supported(_) => "supported",
            Self::Unsupported { .. } => "unsupported",
            Self::Probe => "unknown",
        }
    }
}

/// Capabilities for the current modem and carrier combination.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Capability {
    pub sms_mo: BearerSupport,
    pub sms_mt: BearerSupport,
    pub data: BearerSupport,
    pub voice: BearerSupport,
}

impl Capability {
    pub fn probe_all() -> Self {
        Self::default()
    }
}

impl Default for Capability {
    fn default() -> Self {
        Self {
            sms_mo: BearerSupport::Probe,
            sms_mt: BearerSupport::Probe,
            data: BearerSupport::Probe,
            voice: BearerSupport::Probe,
        }
    }
}

/// The three axes used to resolve the policy family for a device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceContext {
    pub modem_family: ModemFamily,
    pub carrier_profile: CarrierProfile,
    pub vertical: Vertical,
}

impl DeviceContext {
    pub fn new(
        modem_family: ModemFamily,
        carrier_profile: CarrierProfile,
        vertical: Vertical,
    ) -> Self {
        Self {
            modem_family,
            carrier_profile,
            vertical,
        }
    }
}

#[cfg(test)]
mod wire_tests {
    use super::{Bearer, BearerSupport};

    /// These four strings are the contract's enum. A typo here is not a
    /// compile error anywhere — it becomes a payload the cloud stores and
    /// nobody notices until a column reads wrong.
    #[test]
    fn support_states_use_the_contract_vocabulary() {
        assert_eq!(BearerSupport::supported(Bearer::Cellular).wire(), "supported");
        assert_eq!(BearerSupport::unsupported("no_mbn").wire(), "unsupported");
        assert_eq!(BearerSupport::Probe.wire(), "unknown");
    }
}

#[cfg(test)]
mod family_detect_tests {
    use super::ModemFamily;

    /// The exact strings the bench hardware reports. The USB descriptor model
    /// is what QMI actually returns, and it must not decide anything.
    #[test]
    fn bench_ec20_is_detected_from_the_revision() {
        let family =
            ModemFamily::detect("QUECTEL Mobile Broadband Module", "EC20CEHCLGR06A08M1G_AUD");
        assert_eq!(family, ModemFamily::Ec20);
        assert_eq!(ModemFamily::detect("EC20F", "").as_str(), "EC20");
    }

    #[test]
    fn ec25_region_variants_are_kept_apart() {
        assert_eq!(
            ModemFamily::detect("", "EC25CFAR05A06M4G"),
            ModemFamily::Ec25Cn,
        );
        // The European variant must not inherit the CN matrix rules.
        assert_eq!(
            ModemFamily::detect("EC25-E", "EC25EFAR06A01M4G"),
            ModemFamily::Other("EC25-E".to_owned()),
        );
    }

    #[test]
    fn unknown_hardware_stays_other() {
        assert_eq!(
            ModemFamily::detect("QUECTEL Mobile Broadband Module", ""),
            ModemFamily::Other("QUECTEL Mobile Broadband Module".to_owned()),
        );
    }
}
