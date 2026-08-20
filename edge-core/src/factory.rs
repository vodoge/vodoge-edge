use std::sync::Arc;

use crate::{
    Capability, DeviceContext, EsimPolicy, EgressPolicy, NotificationPolicy, RegistrationPolicy,
    SmsRouter, VerticalId,
};

/// One factory's complete policy family.
///
/// SMS routing, registration, eSIM, egress, and notification must come from the
/// same factory. Mixing objects from different factories produces combinations
/// that have never been tested together.
#[derive(Clone)]
pub struct PolicyFamily {
    pub vertical_id: VerticalId,
    pub sms: Arc<dyn SmsRouter>,
    pub registration: Arc<dyn RegistrationPolicy>,
    pub esim: Arc<dyn EsimPolicy>,
    pub egress: Arc<dyn EgressPolicy>,
    pub notification: Arc<dyn NotificationPolicy>,
}

impl PolicyFamily {
    /// True when every policy object in the family reports the same vertical.
    pub fn is_coherent(&self) -> bool {
        self.registration.vertical_id() == self.vertical_id
            && self.esim.vertical_id() == self.vertical_id
            && self.egress.vertical_id() == self.vertical_id
            && self.notification.vertical_id() == self.vertical_id
    }
}

/// Produces a matched family of policies for one vertical.
pub trait VerticalFactory: Send + Sync {
    fn id(&self) -> VerticalId;
    fn matches(&self, context: &DeviceContext) -> bool;
    fn sms_router(&self, capability: &Capability) -> Arc<dyn SmsRouter>;
    fn registration(&self, capability: &Capability) -> Arc<dyn RegistrationPolicy>;
    fn esim(&self) -> Arc<dyn EsimPolicy>;
    fn egress(&self) -> Arc<dyn EgressPolicy>;
    fn notification(&self) -> Arc<dyn NotificationPolicy>;

    /// Assembles the matched family so callers cannot pick policies a la carte.
    fn assemble(&self, capability: &Capability) -> PolicyFamily {
        PolicyFamily {
            vertical_id: self.id(),
            sms: self.sms_router(capability),
            registration: self.registration(capability),
            esim: self.esim(),
            egress: self.egress(),
            notification: self.notification(),
        }
    }
}

/// Factories are evaluated in insertion order. The fallback is always available
/// and is only selected when no ordered factory matches the device context.
pub struct VerticalRegistry {
    factories: Vec<Arc<dyn VerticalFactory>>,
    fallback: Arc<dyn VerticalFactory>,
}

impl VerticalRegistry {
    pub fn new(
        fallback: Arc<dyn VerticalFactory>,
        factories: Vec<Arc<dyn VerticalFactory>>,
    ) -> Self {
        Self { factories, fallback }
    }

    pub fn resolve(&self, context: &DeviceContext) -> Arc<dyn VerticalFactory> {
        self.factories
            .iter()
            .find(|factory| factory.matches(context))
            .cloned()
            .unwrap_or_else(|| Arc::clone(&self.fallback))
    }

    pub fn factory_ids(&self) -> Vec<VerticalId> {
        self.factories.iter().map(|factory| factory.id()).collect()
    }
}
