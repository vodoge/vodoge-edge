use std::{
    collections::HashMap,
    error::Error,
    fmt,
};

use serde::{Deserialize, Serialize};

use crate::{Bearer, BearerSupport, Capability, CarrierProfile, ModemFamily};

const BUILTIN_MATRIX: &str = include_str!("../capabilities/capability-matrix.toml");

/// Indicates whether a matrix query used a modem/carrier-specific rule or the
/// deliberately configured fallback.
///
/// 🔴 Serialisable since 2026-09-03, and lowercase on the wire because that is
/// what it has always been on the wire. `edge-panel` used to write the mapping
/// out by hand where it built its status body — `Rule => "rule"`,
/// `Fallback => "fallback"` — which is a second spelling of this enum living
/// somewhere it cannot be checked against the first. The panel's browser half
/// now deserialises into this type, so both ends read the same names and a
/// third variant added here fails to compile in both places rather than
/// silently serialising as something nobody handles.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
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
    /// Every explicitly stated rule, without the fallback.
    ///
    /// The fallback is deliberately not included. It answers "what do we do
    /// about a pair nobody wrote down", which is a different question from
    /// "what was this pair measured to do" -- and conflating them is how an
    /// untested combination comes to look supported.
    pub fn rules(&self) -> impl Iterator<Item = (&ModemFamily, &CarrierProfile, &Capability)> {
        self.rules
            .iter()
            .map(|(key, capability)| (&key.modem_family, &key.carrier_profile, capability))
    }

    /// Parses a declarative TOML matrix. Missing capability fields inherit from
    /// `[fallback]`, which defaults to `probe` for every operation.
    pub fn from_toml(source: &str) -> Result<Self, MatrixError> {
        let document: MatrixDocument = toml::from_str(source).map_err(MatrixError::Parse)?;
        Self::from_document(document)
    }

    /// Parses the same document shape as TOML, delivered as JSON in CommandDeliver.
    pub fn from_json_value(value: &serde_json::Value) -> Result<Self, MatrixError> {
        let document: MatrixDocument =
            serde_json::from_value(value.clone()).map_err(MatrixError::Json)?;
        Self::from_document(document)
    }

    fn from_document(document: MatrixDocument) -> Result<Self, MatrixError> {
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
    Json(serde_json::Error),
    DuplicateRule {
        modem_family: ModemFamily,
        carrier_profile: CarrierProfile,
    },
}

impl fmt::Display for MatrixError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(error) => write!(formatter, "invalid capability matrix: {error}"),
            Self::Json(error) => write!(formatter, "invalid capability matrix json: {error}"),
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
            Self::Json(error) => Some(error),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Bearer, BearerSupport, CarrierProfile, ModemFamily};

    #[test]
    fn json_matrix_installs_supported_sms_for_ec20_telecom() {
        let matrix = CapabilityMatrix::from_json_value(&serde_json::json!({
            "version": "hot-1",
            "fallback": {
                "sms_mo": { "kind": "probe" },
                "sms_mt": { "kind": "probe" },
                "data": { "kind": "probe" },
                "voice": { "kind": "probe" }
            },
            "rule": [{
                "modem_family": "EC20",
                "carrier": "CN-Telecom",
                "sms_mo": { "kind": "supported", "bearer": "cellular" },
                "sms_mt": { "kind": "supported", "bearer": "cellular" }
            }]
        }))
        .expect("json matrix");

        assert_eq!(matrix.version(), "hot-1");
        let query = matrix.query(&ModemFamily::EC20, &CarrierProfile::CN_TELECOM);
        assert_eq!(query.origin, CapabilityOrigin::Rule);
        assert_eq!(
            query.capability.sms_mo,
            BearerSupport::Supported(Bearer::Cellular)
        );
    }
}
