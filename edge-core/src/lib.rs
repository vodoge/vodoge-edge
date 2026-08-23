//! Hardware-independent domain logic for the Vodoge edge agent.
//!
//! This crate intentionally owns no I/O. Transport, persistence, timers, and
//! network clients belong in higher layers so capability and routing decisions
//! stay deterministic and straightforward to test.

mod network;
mod capability;
mod concat;
mod gsm7;
mod pdu;
mod factory;
mod matrix;
mod policy;
mod registration;
mod signal;
mod sms;
mod verticals;

pub use network::Network;
pub use capability::{
    Bearer, BearerSupport, Capability, CarrierProfile, DeviceContext, ModemFamily, Vertical,
    VerticalId,
};
pub use concat::{assemble, AssembledSms, ConcatPart, FRAGMENT_GRACE_MS};
pub use gsm7::decode as decode_gsm7;
pub use pdu::{decode_deliver, decode_status_report, hex, Deliver, StatusReport};
pub use factory::{PolicyFamily, VerticalFactory, VerticalRegistry};
pub use matrix::{CapabilityMatrix, CapabilityOrigin, CapabilityQuery, MatrixError};
pub use registration::{
    arbitrate, Confidence, Plmn, RegistrationEvidence, RegistrationSourceKind, RegistrationVerdict,
};
pub use policy::{
    DataIntent, EsimPolicy, EgressPolicy, NotificationPolicy, RecoveryPreference,
    RegistrationPolicy, ReleaseScope, StaticEsimPolicy, StaticEgressPolicy,
    StaticNotificationPolicy, StaticRegistrationPolicy,
};
pub use signal::{parse_qcsq, Qcsq};
pub use sms::{OrderedSmsRouter, RadioState, SendPlan, SmsRouter};
pub use verticals::{builtin_registry, CnFactory, IntlFactory, LabFactory};

pub(crate) use sms::{authorized_bearer, veto_unsupported};
