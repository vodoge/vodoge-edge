use edge_core::{
    builtin_strategy_registry, Bearer, BearerSupport, Capability, CarrierProfile, ModemFamily,
    Operation, RefusedBy, SubscriptionCapability, Support, SupportLedger,
};

fn sms_both(bearer: Bearer) -> Capability {
    Capability {
        sms_mo: BearerSupport::supported(bearer),
        sms_mt: BearerSupport::supported(bearer),
        data: BearerSupport::supported(bearer),
        voice: BearerSupport::Probe,
    }
}

fn nothing_declared() -> SubscriptionCapability {
    SubscriptionCapability::default()
}

/// The iron rule. A pair nobody has measured is refused, and the refusal says
/// the fix is a test rather than a code change.
#[test]
fn an_untested_pair_is_unsupported_rather_than_attempted() {
    let registry = builtin_strategy_registry(SupportLedger::new()).expect("registry");
    let resolved = registry.resolve(
        &ModemFamily::EC20,
        &CarrierProfile::CN_MOBILE,
        &nothing_declared(),
        Operation::SmsSend,
    );

    assert!(!resolved.is_supported());
    assert!(!resolved.tested);
    match resolved.support {
        Support::Unsupported { by, ref reason } => {
            assert_eq!(by, RefusedBy::Ledger);
            assert!(
                reason.contains("has not been tested"),
                "the refusal has to name the missing test, got {reason:?}"
            );
        }
        Support::Supported(_) => panic!("an untested pair must not resolve to supported"),
    }
}

/// Recording a measurement is what makes a pair work, and nothing else is.
#[test]
fn recording_a_measurement_is_what_turns_a_pair_on() {
    let mut ledger = SupportLedger::new();
    ledger.record(
        ModemFamily::EC20,
        CarrierProfile::CN_MOBILE,
        sms_both(Bearer::Cellular),
    );
    let registry = builtin_strategy_registry(ledger).expect("registry");

    let resolved = registry.resolve(
        &ModemFamily::EC20,
        &CarrierProfile::CN_MOBILE,
        &nothing_declared(),
        Operation::SmsSend,
    );
    assert_eq!(resolved.support, Support::Supported(Bearer::Cellular));
    assert!(resolved.tested);
    assert_eq!(resolved.modem, Some("quectel-ec"));
    assert_eq!(resolved.carrier_strategy, Some("cn-mobile"));
}

/// Tested-and-found-not-to-work is a different fact from untested, and the
/// two must not collapse: one is answered by measuring, the other is the
/// measurement.
#[test]
fn a_measured_refusal_is_not_the_same_as_an_absent_measurement() {
    let mut ledger = SupportLedger::new();
    ledger.record(
        ModemFamily::EC20,
        CarrierProfile::CN_TELECOM,
        Capability {
            sms_mo: BearerSupport::unsupported("no_cdma_fallback_and_no_ct_volte_mbn"),
            ..sms_both(Bearer::Cellular)
        },
    );
    let registry = builtin_strategy_registry(ledger).expect("registry");

    let resolved = registry.resolve(
        &ModemFamily::EC20,
        &CarrierProfile::CN_TELECOM,
        &nothing_declared(),
        Operation::SmsSend,
    );
    assert!(resolved.tested, "this pair was measured");
    match resolved.support {
        Support::Unsupported { by, ref reason } => {
            assert_eq!(by, RefusedBy::Carrier);
            assert_eq!(reason, "no_cdma_fallback_and_no_ct_volte_mbn");
        }
        Support::Supported(_) => panic!("a measured refusal must survive"),
    }
}

/// The bench's whole reason for a third layer: two cards, one carrier profile,
/// one module family, different plans.
///
/// Club receives and cannot send; Webbing on the same network in the same
/// stick does both. Nothing readable from the hardware or the network
/// separates them, so the ledger cannot and the subscription must.
#[test]
fn two_plans_on_one_carrier_and_one_module_resolve_differently() {
    let mut ledger = SupportLedger::new();
    ledger.record(
        ModemFamily::EC20,
        CarrierProfile::GENERIC_INTERNATIONAL,
        sms_both(Bearer::Cellular),
    );
    let registry = builtin_strategy_registry(ledger).expect("registry");

    let club = SubscriptionCapability {
        sms_send: Some(false),
        sms_receive: Some(true),
        ..SubscriptionCapability::default()
    };
    let webbing = SubscriptionCapability {
        sms_send: Some(true),
        sms_receive: Some(true),
        ..SubscriptionCapability::default()
    };

    let club_send = registry.resolve(
        &ModemFamily::EC20,
        &CarrierProfile::GENERIC_INTERNATIONAL,
        &club,
        Operation::SmsSend,
    );
    match club_send.support {
        Support::Unsupported { by, .. } => assert_eq!(by, RefusedBy::Subscription),
        Support::Supported(_) => panic!("a plan recorded as send-less must not send"),
    }

    // Receiving is untouched by the same declaration.
    assert!(registry
        .resolve(
            &ModemFamily::EC20,
            &CarrierProfile::GENERIC_INTERNATIONAL,
            &club,
            Operation::SmsReceive,
        )
        .is_supported());

    assert!(registry
        .resolve(
            &ModemFamily::EC20,
            &CarrierProfile::GENERIC_INTERNATIONAL,
            &webbing,
            Operation::SmsSend,
        )
        .is_supported());
}

/// A subscription may only subtract.
///
/// Declaring a capability the pair was never measured to have must not create
/// it: the worst outcome available is a console claiming a stick does
/// something nobody has ever seen it do.
#[test]
fn a_subscription_cannot_grant_what_was_never_measured() {
    let registry = builtin_strategy_registry(SupportLedger::new()).expect("registry");
    let generous = SubscriptionCapability {
        sms_send: Some(true),
        sms_receive: Some(true),
        data: Some(true),
        voice: Some(true),
    };

    let resolved = registry.resolve(
        &ModemFamily::EC20,
        &CarrierProfile::CN_MOBILE,
        &generous,
        Operation::SmsSend,
    );
    assert!(
        !resolved.is_supported(),
        "an untested pair stays unsupported however the plan is described"
    );
}

/// A module ceiling cannot be lifted by a ledger row or a plan.
#[test]
fn a_hardware_ceiling_outranks_a_measurement() {
    let mut ledger = SupportLedger::new();
    ledger.record(
        ModemFamily::EC200U_CN,
        CarrierProfile::CN_TELECOM,
        Capability {
            voice: BearerSupport::supported(Bearer::Cellular),
            ..sms_both(Bearer::Cellular)
        },
    );
    let registry = builtin_strategy_registry(ledger).expect("registry");

    let resolved = registry.resolve(
        &ModemFamily::EC200U_CN,
        &CarrierProfile::CN_TELECOM,
        &nothing_declared(),
        Operation::Voice,
    );
    match resolved.support {
        Support::Unsupported { by, .. } => assert_eq!(by, RefusedBy::Modem),
        Support::Supported(_) => panic!("this agent has no voice path for the EC200U"),
    }
}

/// Sharing an implementation must not share identity: a pair tested on an
/// EC20 says nothing about an EC25-CN, even though one strategy drives both.
#[test]
fn families_that_share_a_strategy_do_not_share_a_measurement() {
    let mut ledger = SupportLedger::new();
    ledger.record(
        ModemFamily::EC20,
        CarrierProfile::CN_MOBILE,
        sms_both(Bearer::Cellular),
    );
    let registry = builtin_strategy_registry(ledger).expect("registry");

    let ec20 = registry.resolve(
        &ModemFamily::EC20,
        &CarrierProfile::CN_MOBILE,
        &nothing_declared(),
        Operation::SmsSend,
    );
    let ec25 = registry.resolve(
        &ModemFamily::EC25_CN,
        &CarrierProfile::CN_MOBILE,
        &nothing_declared(),
        Operation::SmsSend,
    );

    assert!(ec20.is_supported());
    assert!(
        !ec25.is_supported(),
        "one strategy drives both, but only the EC20 was measured"
    );
    assert_eq!(ec20.modem, ec25.modem, "and they really do share the driver");
}

/// An unregistered family still resolves, and still refuses.
///
/// A module the build has never heard of is exactly the case the ledger is
/// for; it must not panic or fall through to a default that works.
#[test]
fn an_unknown_family_is_refused_rather_than_defaulted() {
    let registry = builtin_strategy_registry(SupportLedger::new()).expect("registry");
    let resolved = registry.resolve(
        &ModemFamily::from("SIM7600G"),
        &CarrierProfile::CN_MOBILE,
        &nothing_declared(),
        Operation::SmsSend,
    );
    assert!(!resolved.is_supported());
    assert_eq!(resolved.modem, None);
}

/// The registry refuses to be built with two strategies claiming one family.
#[test]
fn one_family_cannot_be_claimed_twice() {
    use std::sync::Arc;
    use edge_core::{ModemStrategy, StrategyRegistry};

    struct Impostor;
    impl ModemStrategy for Impostor {
        fn id(&self) -> &'static str {
            "impostor"
        }
        fn families(&self) -> Vec<ModemFamily> {
            vec![ModemFamily::EC20]
        }
    }

    let built = StrategyRegistry::new(SupportLedger::new())
        .with_modem(Arc::new(edge_core::QuectelEcStrategy))
        .expect("first")
        .with_modem(Arc::new(Impostor));
    assert!(
        built.is_err(),
        "two strategies claiming EC20 means the build has two answers"
    );
}

/// A ceiling outranks an absent measurement, not just a present one.
///
/// Found by running it. The refusal used to say "has not been tested" for a
/// pairing whose measurement could not be taken at all, sending the reader
/// after work that was impossible.
///
/// Data is the operation that still cannot be driven on this module: bringing
/// the bearer up is a QMI call and the EC200U series exposes none. Messaging
/// used to be here too and no longer is -- see the test below.
#[test]
fn a_ceiling_is_reported_even_when_the_pairing_was_never_measured() {
    let registry = builtin_strategy_registry(SupportLedger::new()).expect("registry");
    let resolved = registry.resolve(
        &ModemFamily::EC200U_CN,
        &CarrierProfile::CN_TELECOM,
        &nothing_declared(),
        Operation::Data,
    );
    match resolved.support {
        Support::Unsupported { by, ref reason } => {
            assert_eq!(by, RefusedBy::Modem, "an unmeasurable pairing must not read as unmeasured");
            assert!(
                reason.contains("QMI"),
                "the refusal has to name what cannot be done, got {reason:?}"
            );
        }
        Support::Supported(_) => panic!("this agent cannot bring up a bearer on an EC200U"),
    }
}

/// A ceiling narrows when the agent gains the path it was missing.
///
/// Sending on an EC200U was refused as a hardware ceiling until there was an
/// AT path for it. Now that there is one, the same pairing has to fall through
/// to the ledger and be refused as *untested* instead -- because that is what
/// it is, and leaving the blanket ceiling would have kept a capability that
/// works switched off with a reason that had stopped being true.
#[test]
fn messaging_on_the_ec200_now_reaches_the_ledger_rather_than_a_ceiling() {
    let registry = builtin_strategy_registry(SupportLedger::new()).expect("registry");
    for operation in [Operation::SmsSend, Operation::SmsReceive] {
        let resolved = registry.resolve(
            &ModemFamily::EC200U_CN,
            &CarrierProfile::CN_TELECOM,
            &nothing_declared(),
            operation,
        );
        match resolved.support {
            Support::Unsupported { by, .. } => assert_eq!(
                by,
                RefusedBy::Ledger,
                "{} is no longer barred by the hardware, so the answer is that nobody has measured it",
                operation.wire()
            ),
            Support::Supported(_) => panic!("still untested until somebody measures it"),
        }
    }
}
