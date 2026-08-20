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
