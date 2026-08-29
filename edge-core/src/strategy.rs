//! Which code runs for a given module, on a given operator's network, with a
//! given subscription.
//!
//! Three layers, resolved in this order, each able only to take capability
//! away from the one above it:
//!
//! 1. **The modem.** What this hardware can be driven to do at all, and how.
//!    Keyed on [`ModemFamily`], which is a *tested variant* rather than a
//!    product line: an EC25-E is not an EC25-CN and an EC200U is not an EC20,
//!    however similar the silicon. Several families may share one
//!    implementation where the driving really is identical -- that is what
//!    [`ModemStrategy`] being a trait object is for -- but they never share it
//!    because somebody assumed so.
//!
//! 2. **The carrier.** What that network does with the module: which bearer
//!    carries a message, what a failed registration is recovered with. Keyed
//!    on [`CarrierProfile`].
//!
//! 3. **The subscription.** What the plan on this particular card is sold as
//!    doing. Declared by an operator, per ICCID, and applied strictly as a
//!    veto: it can say a plan cannot send, never that it can. Two cards on one
//!    carrier in one module genuinely differ here -- on this bench a Club
//!    profile receives and cannot send while a Webbing profile on the same
//!    network in the same stick does both -- and no amount of reading the
//!    hardware or the network will show it, because it is a billing fact.
//!
//! **Untested is unsupported.** A `(family, carrier)` pair nobody has put in
//! front of real hardware resolves to [`Support::Unsupported`], not to "try it
//! and find out". The previous default was to probe, which is how a stick ends
//! up half-working in a way nobody can reproduce. Commissioning a new pair is
//! a deliberate act with its own path -- see [`Resolution::commissioning`] --
//! and the result of that act is a row in the ledger, not a silent success.

use std::collections::HashMap;
use std::sync::Arc;

use crate::{Bearer, BearerSupport, Capability, CarrierProfile, ModemFamily};

/// One operation a card and module can be asked to perform.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Operation {
    SmsSend,
    SmsReceive,
    Data,
    Voice,
}

impl Operation {
    pub fn wire(self) -> &'static str {
        match self {
            Self::SmsSend => "sms_mo",
            Self::SmsReceive => "sms_mt",
            Self::Data => "data",
            Self::Voice => "voice",
        }
    }

    /// This operation's field in a [`Capability`].
    pub fn of(self, capability: &Capability) -> &BearerSupport {
        match self {
            Self::SmsSend => &capability.sms_mo,
            Self::SmsReceive => &capability.sms_mt,
            Self::Data => &capability.data,
            Self::Voice => &capability.voice,
        }
    }
}

/// The answer to "may this be attempted, and over what".
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Support {
    /// Go ahead, over this bearer.
    Supported(Bearer),
    /// Do not attempt. `by` names the layer that refused, so an operator
    /// reading a refusal is told which of the three to go and change.
    Unsupported { by: RefusedBy, reason: String },
}

impl Support {
    pub fn bearer(&self) -> Option<Bearer> {
        match self {
            Self::Supported(bearer) => Some(*bearer),
            Self::Unsupported { .. } => None,
        }
    }

    pub fn is_supported(&self) -> bool {
        matches!(self, Self::Supported(_))
    }
}

/// Which layer withheld an operation.
///
/// The distinction is the whole point of naming it: "nobody has tested this
/// module on this network" and "this plan does not include sending" are fixed
/// by completely different people doing completely different things.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefusedBy {
    /// No tested rule for this `(family, carrier)` pair.
    Ledger,
    /// The hardware cannot do it, on any network.
    Modem,
    /// The network does not offer it to this module.
    Carrier,
    /// The subscription is not sold as doing it.
    Subscription,
}

impl RefusedBy {
    pub fn wire(self) -> &'static str {
        match self {
            Self::Ledger => "untested",
            Self::Modem => "modem",
            Self::Carrier => "carrier",
            Self::Subscription => "subscription",
        }
    }
}

/// What one module family can be driven to do, and how.
///
/// Implementations are shared deliberately: `EC20` and a later `EC25-CN` may
/// return the same object where the driving is identical. What they must not
/// share is *identity* -- the ledger records each family separately, so a
/// combination tested on one is not claimed for the other.
pub trait ModemStrategy: Send + Sync {
    /// Stable name for logs, receipts and the ledger.
    fn id(&self) -> &'static str;

    /// Every family this strategy is claimed to drive. Used to build the
    /// registry, and to make the sharing visible rather than implicit.
    fn families(&self) -> Vec<ModemFamily>;

    /// The ceiling this hardware imposes, before any network is considered.
    ///
    /// Default: the hardware constrains nothing, and the carrier and the
    /// ledger decide. Override only for a limit that is genuinely the
    /// module's -- a module with no voice path, say -- because a limit
    /// asserted here cannot be lifted by any later layer.
    fn ceiling(&self, _operation: Operation) -> Option<String> {
        None
    }

    /// Preferred bearer for an operation this module is driving, where the
    /// module has an opinion the carrier layer should start from.
    fn preferred_bearer(&self, _operation: Operation) -> Option<Bearer> {
        None
    }
}

/// What a carrier's network does with a module attached to it.
pub trait CarrierStrategy: Send + Sync {
    fn id(&self) -> &'static str;

    fn carriers(&self) -> Vec<CarrierProfile>;

    /// The bearer this network carries the operation over, given what the
    /// ledger measured. `None` leaves the ledger's own answer standing.
    fn bearer(&self, _operation: Operation, _measured: Bearer) -> Option<Bearer> {
        None
    }

    /// A network-level refusal, applied after the ledger and the modem.
    fn refuses(&self, _operation: Operation) -> Option<String> {
        None
    }
}

/// What an operator says this card's plan is sold as doing.
///
/// Strictly subtractive. A `false` withholds an operation the layers above
/// allowed; a `true` asserts nothing, because a subscription cannot grant a
/// capability the hardware and the network were never measured to have. That
/// asymmetry is deliberate: the field is filled in by a person reading a
/// tariff, and the worst outcome is a page that claims a stick can do
/// something nobody has ever seen it do.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SubscriptionCapability {
    pub sms_send: Option<bool>,
    pub sms_receive: Option<bool>,
    pub data: Option<bool>,
    pub voice: Option<bool>,
}

impl SubscriptionCapability {
    /// True when the operator has explicitly said this plan does not do it.
    pub fn withholds(&self, operation: Operation) -> bool {
        matches!(self.declared(operation), Some(false))
    }

    pub fn declared(&self, operation: Operation) -> Option<bool> {
        match operation {
            Operation::SmsSend => self.sms_send,
            Operation::SmsReceive => self.sms_receive,
            Operation::Data => self.data,
            Operation::Voice => self.voice,
        }
    }

    /// True when nothing has been declared at all, which is the state of every
    /// card until somebody fills the form in.
    pub fn is_empty(&self) -> bool {
        self.sms_send.is_none()
            && self.sms_receive.is_none()
            && self.data.is_none()
            && self.voice.is_none()
    }
}

/// Everything needed to decide whether one module may be asked to do
/// something, gathered from wherever those facts happen to live.
///
/// Exists so the decision and the facts can sit in different crates: the agent
/// holds the capability matrix and therefore the ledger, while the identity of
/// a module and the policy on the card in it live in the edge binary's store.
/// Passing this across the port keeps the rule in one place instead of
/// growing a second copy on whichever side has the data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatingContext {
    pub family: ModemFamily,
    pub carrier: CarrierProfile,
    pub subscription: SubscriptionCapability,
}

/// The tested `(family, carrier)` pairs and what each was measured to do.
///
/// This is the iron rule made into a data structure: a pair that is not in
/// here is not supported. Adding a row is the act of having tested something,
/// so the ledger doubles as the record of what was tried.
#[derive(Clone, Debug, Default)]
pub struct SupportLedger {
    entries: HashMap<(ModemFamily, CarrierProfile), Capability>,
}

impl SupportLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record what a pair was measured to do. Replaces any earlier finding:
    /// a re-test supersedes, it does not accumulate.
    pub fn record(
        &mut self,
        family: ModemFamily,
        carrier: CarrierProfile,
        capability: Capability,
    ) -> &mut Self {
        self.entries.insert((family, carrier), capability);
        self
    }

    /// Build a ledger from a capability matrix document.
    ///
    /// Only the explicit rules cross over; the document's `[fallback]` does
    /// not. That is the whole difference between the two structures: a matrix
    /// answers every question, including for pairs nobody has met, and a
    /// ledger answers only for what was measured. Reusing the document means
    /// the existing TOML, the cloud's `update_capability_matrix` push, and the
    /// `app.capability_matrix` table all keep working unchanged.
    ///
    /// A rule of `probe` is carried across as written and refused at
    /// resolution: "somebody should find out" is a note, not a measurement,
    /// and it must not read as one here either.
    pub fn from_matrix(matrix: &crate::CapabilityMatrix) -> Self {
        let mut ledger = Self::new();
        for (family, carrier, capability) in matrix.rules() {
            ledger.record(family.clone(), carrier.clone(), capability.clone());
        }
        ledger
    }

    pub fn get(&self, family: &ModemFamily, carrier: &CarrierProfile) -> Option<&Capability> {
        self.entries.get(&(family.clone(), carrier.clone()))
    }

    pub fn is_tested(&self, family: &ModemFamily, carrier: &CarrierProfile) -> bool {
        self.get(family, carrier).is_some()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Every tested pair, for rendering the support table.
    pub fn pairs(&self) -> Vec<(ModemFamily, CarrierProfile)> {
        let mut pairs: Vec<_> = self.entries.keys().cloned().collect();
        pairs.sort_by(|left, right| {
            left.0
                .as_str()
                .cmp(right.0.as_str())
                .then_with(|| left.1.as_str().cmp(right.1.as_str()))
        });
        pairs
    }
}

/// The registries, resolved together.
pub struct StrategyRegistry {
    modems: HashMap<ModemFamily, Arc<dyn ModemStrategy>>,
    carriers: HashMap<CarrierProfile, Arc<dyn CarrierStrategy>>,
    ledger: SupportLedger,
}

impl StrategyRegistry {
    pub fn new(ledger: SupportLedger) -> Self {
        Self {
            modems: HashMap::new(),
            carriers: HashMap::new(),
            ledger,
        }
    }

    /// Register one modem strategy for every family it claims.
    ///
    /// A family claimed twice is a programming error rather than a
    /// configuration one -- two strategies both saying they drive an EC20
    /// means the build contains two answers and picks by hash order -- so it
    /// is reported rather than resolved.
    pub fn with_modem(mut self, strategy: Arc<dyn ModemStrategy>) -> Result<Self, StrategyError> {
        for family in strategy.families() {
            if let Some(existing) = self.modems.get(&family) {
                return Err(StrategyError::DuplicateModem {
                    family: family.as_str().to_owned(),
                    first: existing.id(),
                    second: strategy.id(),
                });
            }
            self.modems.insert(family, Arc::clone(&strategy));
        }
        Ok(self)
    }

    pub fn with_carrier(
        mut self,
        strategy: Arc<dyn CarrierStrategy>,
    ) -> Result<Self, StrategyError> {
        for carrier in strategy.carriers() {
            if let Some(existing) = self.carriers.get(&carrier) {
                return Err(StrategyError::DuplicateCarrier {
                    carrier: carrier.as_str().to_owned(),
                    first: existing.id(),
                    second: strategy.id(),
                });
            }
            self.carriers.insert(carrier, Arc::clone(&strategy));
        }
        Ok(self)
    }

    pub fn ledger(&self) -> &SupportLedger {
        &self.ledger
    }

    pub fn modem(&self, family: &ModemFamily) -> Option<&Arc<dyn ModemStrategy>> {
        self.modems.get(family)
    }

    pub fn carrier(&self, carrier: &CarrierProfile) -> Option<&Arc<dyn CarrierStrategy>> {
        self.carriers.get(carrier)
    }

    /// Resolve one operation through all three layers.
    pub fn resolve(
        &self,
        family: &ModemFamily,
        carrier: &CarrierProfile,
        subscription: &SubscriptionCapability,
        operation: Operation,
    ) -> Resolution {
        let modem = self.modems.get(family).map(|strategy| strategy.id());
        let carrier_strategy = self.carriers.get(carrier).map(|strategy| strategy.id());

        // 1. The hardware, before the ledger. A ceiling holds whether or not
        //    anybody has measured the pairing, and no amount of measuring will
        //    lift it -- so answering "go and test it" first would send the
        //    reader after a measurement that cannot be taken. Found by running
        //    it: the EC200U has no QMI path in this agent, and the refusal for
        //    it read "has not been tested" while the useful sentence sat
        //    behind a check that never ran.
        if let Some(strategy) = self.modems.get(family) {
            if let Some(reason) = strategy.ceiling(operation) {
                return Resolution {
                    support: Support::Unsupported {
                        by: RefusedBy::Modem,
                        reason,
                    },
                    modem,
                    carrier_strategy,
                    tested: self.ledger.is_tested(family, carrier),
                };
            }
        }

        // 2. The ledger. Untested is unsupported, and says so by name so the
        //    reader knows the fix is a test rather than a code change.
        let Some(measured) = self.ledger.get(family, carrier) else {
            return Resolution {
                support: Support::Unsupported {
                    by: RefusedBy::Ledger,
                    reason: format!(
                        "{} on {} has not been tested; add it to the support ledger after measuring it",
                        family.as_str(),
                        carrier.as_str()
                    ),
                },
                modem,
                carrier_strategy,
                tested: false,
            };
        };

        let refuse = |by, reason: String| Resolution {
            support: Support::Unsupported { by, reason },
            modem,
            carrier_strategy,
            tested: true,
        };

        // The measurement itself can be a refusal: a pair can be tested and
        // found not to work, which is a different fact from untested and has
        // to survive as one.
        let bearer = match operation.of(measured) {
            BearerSupport::Supported(bearer) => *bearer,
            BearerSupport::Unsupported { reason } => {
                return refuse(RefusedBy::Carrier, reason.clone());
            }
            BearerSupport::Probe => {
                return refuse(
                    RefusedBy::Ledger,
                    format!(
                        "{} on {} is recorded as needing a probe, which is not a measurement",
                        family.as_str(),
                        carrier.as_str()
                    ),
                );
            }
        };

        // 3. The network.
        let mut bearer = bearer;
        if let Some(strategy) = self.carriers.get(carrier) {
            if let Some(reason) = strategy.refuses(operation) {
                return refuse(RefusedBy::Carrier, reason);
            }
            if let Some(chosen) = strategy.bearer(operation, bearer) {
                bearer = chosen;
            }
        }

        // 4. The subscription, last, and only ever subtracting.
        if subscription.withholds(operation) {
            return refuse(
                RefusedBy::Subscription,
                format!(
                    "the plan on this card is recorded as not including {}",
                    operation.wire()
                ),
            );
        }

        Resolution {
            support: Support::Supported(bearer),
            modem,
            carrier_strategy,
            tested: true,
        }
    }
}

/// One resolved answer, with the provenance a receipt needs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Resolution {
    pub support: Support,
    /// Which strategy drove the module, where one is registered.
    pub modem: Option<&'static str>,
    pub carrier_strategy: Option<&'static str>,
    /// Whether this pair is in the ledger at all.
    pub tested: bool,
}

impl Resolution {
    /// A resolution for commissioning: the deliberate act of putting an
    /// untested pair in front of hardware to find out what it does.
    ///
    /// It exists because "untested is unsupported" would otherwise make the
    /// first test of anything impossible. It is not a fallback and nothing
    /// reaches it by default -- a caller has to ask for it, the same way the
    /// AT console's `force` works -- and its whole purpose is to produce a
    /// ledger row, after which the ordinary path answers.
    pub fn commissioning(bearer: Bearer) -> Self {
        Self {
            support: Support::Supported(bearer),
            modem: None,
            carrier_strategy: None,
            tested: false,
        }
    }

    pub fn bearer(&self) -> Option<Bearer> {
        self.support.bearer()
    }

    pub fn is_supported(&self) -> bool {
        self.support.is_supported()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StrategyError {
    DuplicateModem {
        family: String,
        first: &'static str,
        second: &'static str,
    },
    DuplicateCarrier {
        carrier: String,
        first: &'static str,
        second: &'static str,
    },
}

impl std::fmt::Display for StrategyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateModem {
                family,
                first,
                second,
            } => write!(
                formatter,
                "modem family {family} is claimed by both {first} and {second}"
            ),
            Self::DuplicateCarrier {
                carrier,
                first,
                second,
            } => write!(
                formatter,
                "carrier {carrier} is claimed by both {first} and {second}"
            ),
        }
    }
}

impl std::error::Error for StrategyError {}
