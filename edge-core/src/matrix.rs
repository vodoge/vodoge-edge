use std::{
    collections::HashMap,
    error::Error,
    fmt,
};

use serde::Deserialize;

use crate::{Bearer, BearerSupport, Capability, CarrierProfile, ModemFamily};

const BUILTIN_MATRIX: &str = include_str!("../capabilities/capability-matrix.toml");

/// Indicates whether a matrix query used a modem/carrier-specific rule or the
/// deliberately configured fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityOrigin {
    Rule,
    Fallback,
}

/// A capability lookup together with the provenance needed for diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityQuery<'a> {
    pub capability: &'a Capability,
    pub origin: CapabilityOrigin,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct MatrixKey {
    modem_family: ModemFamily,
    carrier_profile: CarrierProfile,
}

/// A parsed, versioned capability matrix.
#[derive(Clone, Debug)]
pub struct CapabilityMatrix {
    version: String,
    rules: HashMap<MatrixKey, Capability>,
    fallback: Capability,
}

impl CapabilityMatrix {
    /// Parses a declarative TOML matrix. Missing capability fields inherit from
    /// `[fallback]`, which defaults to `probe` for every operation.
    pub fn from_toml(source: &str) -> Result<Self, MatrixError> {
        let document: MatrixDocument = toml::from_str(source).map_err(MatrixError::Parse)?;
        let fallback = document.fallback.into_capability(&Capability::probe_all());
        let mut rules = HashMap::with_capacity(document.rule.len());

        for rule in document.rule {
            let key = MatrixKey {
                modem_family: rule.modem_family,
                carrier_profile: rule.carrier,
            };
            let capability = rule.capability.into_capability(&fallback);

            if rules.insert(key.clone(), capability).is_some() {
                return Err(MatrixError::DuplicateRule {
                    modem_family: key.modem_family,
                    carrier_profile: key.carrier_profile,
                });
            }
        }

        Ok(Self {
            version: document.version.unwrap_or_else(|| "unversioned".to_owned()),
            rules,
            fallback,
        })
    }

    /// Loads the matrix compiled into the edge binary.
    pub fn builtin() -> Result<Self, MatrixError> {
        Self::from_toml(BUILTIN_MATRIX)
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    /// Returns an explicit fallback result when there is no exact matrix rule.
    pub fn query(
        &self,
        modem_family: &ModemFamily,
        carrier_profile: &CarrierProfile,
    ) -> CapabilityQuery<'_> {
        let key = MatrixKey {
            modem_family: modem_family.clone(),
            carrier_profile: carrier_profile.clone(),
        };

        match self.rules.get(&key) {
            Some(capability) => CapabilityQuery {
                capability,
                origin: CapabilityOrigin::Rule,
            },
            None => CapabilityQuery {
                capability: &self.fallback,
                origin: CapabilityOrigin::Fallback,
            },
        }
    }
}

/// Matrix load errors are intentionally descriptive because a cloud-delivered
/// update must be rejected without replacing the last known-good matrix.
#[derive(Debug)]
pub enum MatrixError {
    Parse(toml::de::Error),
    DuplicateRule {
        modem_family: ModemFamily,
        carrier_profile: CarrierProfile,
    },
}

impl fmt::Display for MatrixError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(error) => write!(formatter, "invalid capability matrix: {error}"),
            Self::DuplicateRule {
                modem_family,
                carrier_profile,
            } => write!(
                formatter,
                "duplicate capability rule for modem {modem_family} and carrier {carrier_profile}"
            ),
        }
    }
}

impl Error for MatrixError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Parse(error) => Some(error),
            Self::DuplicateRule { .. } => None,
        }
    }
}

#[derive(Deserialize)]
struct MatrixDocument {
    version: Option<String>,
    #[serde(default)]
    fallback: RawCapability,
    #[serde(default)]
    rule: Vec<RawRule>,
}

#[derive(Deserialize)]
struct RawRule {
    modem_family: ModemFamily,
    carrier: CarrierProfile,
    #[serde(flatten)]
    capability: RawCapability,
}

#[derive(Default, Deserialize)]
struct RawCapability {
    sms_mo: Option<RawBearerSupport>,
    sms_mt: Option<RawBearerSupport>,
    data: Option<RawBearerSupport>,
    voice: Option<RawBearerSupport>,
}

impl RawCapability {
    fn into_capability(self, inherited: &Capability) -> Capability {
        Capability {
            sms_mo: self.sms_mo.map(Into::into).unwrap_or_else(|| inherited.sms_mo.clone()),
            sms_mt: self.sms_mt.map(Into::into).unwrap_or_else(|| inherited.sms_mt.clone()),
            data: self.data.map(Into::into).unwrap_or_else(|| inherited.data.clone()),
            voice: self.voice.map(Into::into).unwrap_or_else(|| inherited.voice.clone()),
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum RawBearerSupport {
    Supported { bearer: Bearer },
    Unsupported { reason: String },
    Probe,
}

impl From<RawBearerSupport> for BearerSupport {
    fn from(value: RawBearerSupport) -> Self {
        match value {
            RawBearerSupport::Supported { bearer } => Self::Supported(bearer),
            RawBearerSupport::Unsupported { reason } => Self::Unsupported { reason },
            RawBearerSupport::Probe => Self::Probe,
        }
    }
}
