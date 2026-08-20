use crate::VerticalId;

/// Whether a destructive radio recovery path is allowed for this vertical.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryPreference {
    /// Prefer the cellular recovery path before touching IMS.
    CellularFirst,
    /// Prefer IMS/VoWiFi recovery before cycling cellular radio.
    ImsFirst,
    /// Observe only. Do not start a radio cycle from policy.
    ObserveOnly,
}

/// Local data-plane intent. Cloud policy may still override this later.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataIntent {
    AllowCellular,
    Deny,
}

/// Resource-release scope used when switching an eSIM profile.
///
/// `AllExceptEsimChannel` is the default because clearing every APDU session
/// during a switch drops the channel the switch itself still needs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseScope {
    All,
    AllExceptEsimChannel,
}

/// Decides how aggressively the edge may recover radio/IMS registration.
pub trait RegistrationPolicy: Send + Sync {
    fn vertical_id(&self) -> VerticalId;
    fn allow_ims(&self) -> bool;
    fn recovery_preference(&self) -> RecoveryPreference;
}

/// eSIM behavior that must stay in the same factory as SMS routing.
pub trait EsimPolicy: Send + Sync {
    fn vertical_id(&self) -> VerticalId;
    fn switch_release_scope(&self) -> ReleaseScope;
    fn allow_profile_download(&self) -> bool;
}

/// Local packet-data intent for this vertical.
pub trait EgressPolicy: Send + Sync {
    fn vertical_id(&self) -> VerticalId;
    fn data_intent(&self) -> DataIntent;
}

/// Which local conditions this vertical wants surfaced as alerts.
pub trait NotificationPolicy: Send + Sync {
    fn vertical_id(&self) -> VerticalId;
    fn surface_capability_unsupported(&self) -> bool;
    fn surface_registration_conflict(&self) -> bool;
}

/// A fixed policy object used by the built-in vertical factories.
#[derive(Clone, Debug)]
pub struct StaticRegistrationPolicy {
    vertical_id: VerticalId,
    allow_ims: bool,
    recovery_preference: RecoveryPreference,
}

impl StaticRegistrationPolicy {
    pub fn new(
        vertical_id: impl Into<VerticalId>,
        allow_ims: bool,
        recovery_preference: RecoveryPreference,
    ) -> Self {
        Self {
            vertical_id: vertical_id.into(),
            allow_ims,
            recovery_preference,
        }
    }
}

impl RegistrationPolicy for StaticRegistrationPolicy {
    fn vertical_id(&self) -> VerticalId {
        self.vertical_id.clone()
    }

    fn allow_ims(&self) -> bool {
        self.allow_ims
    }

    fn recovery_preference(&self) -> RecoveryPreference {
        self.recovery_preference
    }
}

/// A fixed eSIM policy object used by the built-in vertical factories.
#[derive(Clone, Debug)]
pub struct StaticEsimPolicy {
    vertical_id: VerticalId,
    switch_release_scope: ReleaseScope,
    allow_profile_download: bool,
}

impl StaticEsimPolicy {
    pub fn new(
        vertical_id: impl Into<VerticalId>,
        switch_release_scope: ReleaseScope,
        allow_profile_download: bool,
    ) -> Self {
        Self {
            vertical_id: vertical_id.into(),
            switch_release_scope,
            allow_profile_download,
        }
    }
}

impl EsimPolicy for StaticEsimPolicy {
    fn vertical_id(&self) -> VerticalId {
        self.vertical_id.clone()
    }

    fn switch_release_scope(&self) -> ReleaseScope {
        self.switch_release_scope
    }

    fn allow_profile_download(&self) -> bool {
        self.allow_profile_download
    }
}

/// A fixed egress policy object used by the built-in vertical factories.
#[derive(Clone, Debug)]
pub struct StaticEgressPolicy {
    vertical_id: VerticalId,
    data_intent: DataIntent,
}

impl StaticEgressPolicy {
    pub fn new(vertical_id: impl Into<VerticalId>, data_intent: DataIntent) -> Self {
        Self {
            vertical_id: vertical_id.into(),
            data_intent,
        }
    }
}

impl EgressPolicy for StaticEgressPolicy {
    fn vertical_id(&self) -> VerticalId {
        self.vertical_id.clone()
    }

    fn data_intent(&self) -> DataIntent {
        self.data_intent
    }
}

/// A fixed notification policy object used by the built-in vertical factories.
#[derive(Clone, Debug)]
pub struct StaticNotificationPolicy {
    vertical_id: VerticalId,
    surface_capability_unsupported: bool,
    surface_registration_conflict: bool,
}

impl StaticNotificationPolicy {
    pub fn new(
        vertical_id: impl Into<VerticalId>,
        surface_capability_unsupported: bool,
        surface_registration_conflict: bool,
    ) -> Self {
        Self {
            vertical_id: vertical_id.into(),
            surface_capability_unsupported,
            surface_registration_conflict,
        }
    }
}

impl NotificationPolicy for StaticNotificationPolicy {
    fn vertical_id(&self) -> VerticalId {
        self.vertical_id.clone()
    }

    fn surface_capability_unsupported(&self) -> bool {
        self.surface_capability_unsupported
    }

    fn surface_registration_conflict(&self) -> bool {
        self.surface_registration_conflict
    }
}
