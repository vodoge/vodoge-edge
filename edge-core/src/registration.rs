use std::borrow::Cow;

/// Origin of one registration observation.
///
/// Confidence order is cell location (PLMN + nonzero cell ID), then AT `+CEREG`,
/// then QMI serving system. Serving system is last because LTE-only firmware
/// reports it as searching with an empty PLMN while the cell is already camped.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RegistrationSourceKind {
    ServingSystem,
    Cereg,
    CellLocation,
}

impl RegistrationSourceKind {
    pub fn confidence(self) -> Confidence {
        match self {
            Self::ServingSystem => Confidence::Low,
            Self::Cereg => Confidence::Medium,
            Self::CellLocation => Confidence::High,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ServingSystem => "serving_system",
            Self::Cereg => "cereg",
            Self::CellLocation => "cell_location",
        }
    }
}

/// How much a source is allowed to decide recovery policy.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

/// A public land mobile network identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Plmn {
    pub mcc: String,
    pub mnc: String,
}

impl Plmn {
    pub fn new(mcc: impl Into<String>, mnc: impl Into<String>) -> Self {
        Self {
            mcc: mcc.into(),
            mnc: mnc.into(),
        }
    }

    pub fn is_complete(&self) -> bool {
        !self.mcc.is_empty() && !self.mnc.is_empty() && self.mcc != "0" && self.mnc != "0"
    }
}

/// One source's observation. Incomplete cell-location samples are not votes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistrationEvidence {
    pub source: RegistrationSourceKind,
    pub registered: bool,
    pub plmn: Option<Plmn>,
    pub cell_id: Option<u32>,
}

impl RegistrationEvidence {
    pub fn serving_system(registered: bool, plmn: Option<Plmn>) -> Self {
        Self {
            source: RegistrationSourceKind::ServingSystem,
            registered,
            plmn,
            cell_id: None,
        }
    }

    pub fn cereg(registered: bool) -> Self {
        Self {
            source: RegistrationSourceKind::Cereg,
            registered,
            plmn: None,
            cell_id: None,
        }
    }

    /// Cell location is high-confidence registered only with a PLMN and a
    /// nonzero cell identity. Missing either field is an incomplete sample.
    pub fn cell_location(plmn: Option<Plmn>, cell_id: Option<u32>) -> Self {
        let complete = plmn
            .as_ref()
            .map(Plmn::is_complete)
            .unwrap_or(false)
            && cell_id.unwrap_or(0) != 0;
        Self {
            source: RegistrationSourceKind::CellLocation,
            registered: complete,
            plmn,
            cell_id,
        }
    }

    pub fn is_complete_cell_location(&self) -> bool {
        self.source == RegistrationSourceKind::CellLocation && self.registered
    }
}

/// The arbitrated view used by recovery policy. Recovery is allowed only when
/// every reporting source says the radio is not camped.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistrationVerdict {
    pub registered: bool,
    pub recovery_allowed: bool,
    pub trusted_source: Option<RegistrationSourceKind>,
    pub conflict: bool,
    pub reason: Cow<'static, str>,
}

/// Combine independent observations. Higher-confidence registered evidence
/// wins; contradictions are recorded rather than averaged.
pub fn arbitrate(evidence: &[RegistrationEvidence]) -> RegistrationVerdict {
    if evidence.is_empty() {
        return RegistrationVerdict {
            registered: false,
            recovery_allowed: false,
            trusted_source: None,
            conflict: false,
            reason: Cow::Borrowed("no registration sources reported"),
        };
    }

    let mut ranked = evidence.iter().collect::<Vec<_>>();
    ranked.sort_by_key(|item| std::cmp::Reverse(item.source.confidence()));

    let registered = ranked
        .iter()
        .find(|item| item.registered)
        .copied();
    let unregistered = ranked.iter().any(|item| !item.registered);
    let conflict = registered.is_some() && unregistered;

    if let Some(winner) = registered {
        return RegistrationVerdict {
            registered: true,
            recovery_allowed: false,
            trusted_source: Some(winner.source),
            conflict,
            reason: Cow::Owned(format!(
                "{} reports camped{}; recovery is suppressed",
                winner.source.as_str(),
                if conflict {
                    "; lower-confidence sources disagree"
                } else {
                    ""
                }
            )),
        };
    }

    RegistrationVerdict {
        registered: false,
        recovery_allowed: true,
        trusted_source: ranked.first().map(|item| item.source),
        conflict: false,
        reason: Cow::Borrowed("all registration sources report not camped; recovery is allowed"),
    }
}
