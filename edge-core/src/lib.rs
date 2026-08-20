//! Hardware-independent domain logic for the Vodoge edge agent.
//!
//! This crate intentionally owns no I/O. Transport, persistence, timers, and
//! network clients belong in higher layers so capability and routing decisions
//! stay deterministic and straightforward to test.

mod capability;
mod factory;
mod matrix;
mod sms;

pub use capability::{
    Bearer, BearerSupport, Capability, CarrierProfile, DeviceContext, ModemFamily, Vertical,
    VerticalId,
};
pub use factory::{VerticalFactory, VerticalRegistry, VerticalSmsFactory};
pub use matrix::{CapabilityMatrix, CapabilityOrigin, CapabilityQuery, MatrixError};
pub use sms::{OrderedSmsRouter, RadioState, SendPlan, SmsRouter};
