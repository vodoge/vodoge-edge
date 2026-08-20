use std::sync::Arc;

use crate::{
    Capability, DeviceContext, OrderedSmsRouter, SmsRouter, Vertical, VerticalId,
};

/// Produces a matched family of policies for one vertical.
///
/// More policy methods can be added as their domains are implemented. Keeping
/// factory selection here ensures policy objects are never chosen independently
/// from different verticals.
pub trait VerticalFactory: Send + Sync {
    fn id(&self) -> VerticalId;
    fn matches(&self, context: &DeviceContext) -> bool;
    fn sms_router(&self, capability: &Capability) -> Arc<dyn SmsRouter>;
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
}

/// A small built-in factory implementation for the two initial verticals.
/// It exists mainly to give the registry a concrete production implementation;
/// additional verticals can implement `VerticalFactory` without touching it.
pub struct VerticalSmsFactory {
    id: VerticalId,
    vertical: Vertical,
    router: Arc<dyn SmsRouter>,
}

impl VerticalSmsFactory {
    pub fn cn() -> Self {
        Self::new(VerticalId::from("cn"), Vertical::Cn, OrderedSmsRouter::cn())
    }

    pub fn intl() -> Self {
        Self::new(
            VerticalId::from("intl"),
            Vertical::Intl,
            OrderedSmsRouter::intl(),
        )
    }

    pub fn new(
        id: VerticalId,
        vertical: Vertical,
        router: impl SmsRouter + 'static,
    ) -> Self {
        Self {
            id,
            vertical,
            router: Arc::new(router),
        }
    }
}

impl VerticalFactory for VerticalSmsFactory {
    fn id(&self) -> VerticalId {
        self.id.clone()
    }

    fn matches(&self, context: &DeviceContext) -> bool {
        self.vertical == context.vertical
    }

    fn sms_router(&self, _capability: &Capability) -> Arc<dyn SmsRouter> {
        Arc::clone(&self.router)
    }
}
