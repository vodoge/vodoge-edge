//! Hardware-independent domain logic for the Vodoge edge agent.
//!
//! This crate intentionally owns no I/O. Transport, persistence, timers, and
//! network clients belong in higher layers so capability and routing decisions
//! stay deterministic and straightforward to test.

mod network;
mod alert;
mod apn;
mod at_policy;
mod sms_block;
mod strategy;
mod strategies;
mod capability;
mod concat;
mod gsm7;
mod pdu;
mod factory;
mod matrix;
mod policy;
mod registration;
mod settle;
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
pub use alert::{AlertLevel, AlertThrottle, Decision, DEFAULT_WINDOW_MS};
pub use apn::{
    merge_credentials, parse_cgdcont, parse_qicsgp, ApnAuth, ApnContext, ApnCredentials,
    SOURCE_CONFIGURED,
};
pub use settle::{
    settle_inbound, InboundFragment, InboundSettlement, SettledMessage,
};
pub use at_policy::{classify as classify_at_command, AtRisk, DisruptiveKind};
pub use sms_block::{blocked_imeis, sms_block, SmsBlock};
pub use strategy::{
    CarrierStrategy, ModemStrategy, OperatingContext, Operation, RefusedBy, Resolution, StrategyError,
    StrategyRegistry, SubscriptionCapability, Support, SupportLedger, UsbIdentity};
pub use strategies::{
    registry as builtin_strategy_registry, CnMobileStrategy, CnTelecomStrategy, CnUnicomStrategy,
    Ec200uStrategy, InternationalStrategy, QuectelEcStrategy,
};
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
