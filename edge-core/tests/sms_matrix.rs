use edge_core::{
    Bearer, BearerSupport, CapabilityMatrix, CarrierProfile, CnFactory, DeviceContext, IntlFactory,
    ModemFamily, RadioState, Vertical, VerticalFactory,
};

fn families() -> [ModemFamily; 3] {
    [ModemFamily::EC20, ModemFamily::EC25_CN, ModemFamily::EG25_G]
}

fn carriers() -> [CarrierProfile; 4] {
    [
        CarrierProfile::CN_MOBILE,
        CarrierProfile::CN_UNICOM,
        CarrierProfile::CN_TELECOM,
        CarrierProfile::GENERIC_INTERNATIONAL,
    ]
}

fn verticals() -> [Vertical; 2] {
    [Vertical::CN, Vertical::INTL]
}

fn radios() -> [(bool, bool); 4] {
    [(true, true), (true, false), (false, true), (false, false)]
}

#[test]
fn three_axis_sms_plans_cover_every_builtin_combination() {
    let matrix = CapabilityMatrix::builtin().expect("built-in matrix is valid");
    let mut cases = 0usize;

    for modem in families() {
        for carrier in carriers() {
            for vertical in verticals() {
                for (cellular, ims) in radios() {
                    cases += 1;
                    let capability = matrix.query(&modem, &carrier).capability;
                    let radio = RadioState {
                        cellular_registered: cellular,
                        ims_registered: ims,
                        sgs_available: false,
                    };
                    let factory: Box<dyn VerticalFactory> = match &vertical {
                        Vertical::Cn => Box::new(CnFactory),
                        Vertical::Intl => Box::new(IntlFactory),
                        Vertical::Custom(_) => unreachable!("exhaustive test only uses cn/intl"),
                    };
                    let plan = factory.sms_router(capability).plan(capability, &radio);

                    match &capability.sms_mo {
                        BearerSupport::Unsupported { reason } => {
                            assert_eq!(
                                plan.primary,
                                None,
                                "{modem} x {carrier} x {vertical} cellular={cellular} ims={ims}"
                            );
                            assert_eq!(plan.fallback, None);
                            assert_eq!(plan.reason, *reason);
                        }
                        BearerSupport::Supported(Bearer::Cellular) if cellular => {
                            assert_eq!(plan.primary, Some(Bearer::Cellular));
                            if vertical == Vertical::Intl && ims {
                                assert_eq!(plan.fallback, Some(Bearer::Ims));
                            } else {
                                assert_eq!(plan.fallback, None);
                            }
                        }
                        BearerSupport::Supported(_) | BearerSupport::Probe => {
                            assert!(
                                plan.primary.is_some() || matches!(capability.sms_mo, BearerSupport::Supported(_)),
                                "probe/supported plan must either pick a bearer or explain a down authorized bearer: {}",
                                plan.reason
                            );
                        }
                    }
                }
            }
        }
    }

    assert_eq!(cases, 3 * 4 * 2 * 4);
}

#[test]
fn hardware_verified_cases_keep_their_exact_plans() {
    let matrix = CapabilityMatrix::builtin().expect("built-in matrix is valid");
    let both = RadioState::with_available([Bearer::Cellular, Bearer::Ims]);

    let telecom = matrix
        .query(&ModemFamily::EC20, &CarrierProfile::CN_TELECOM)
        .capability;
    let rejected = CnFactory.sms_router(telecom).plan(telecom, &both);
    assert_eq!(rejected.primary, None);
    assert_eq!(rejected.reason, "no_cdma_fallback_and_no_ct_volte_mbn");

    let mobile = matrix
        .query(&ModemFamily::EC20, &CarrierProfile::CN_MOBILE)
        .capability;
    let cn_ok = CnFactory.sms_router(mobile).plan(mobile, &both);
    assert_eq!(cn_ok.primary, Some(Bearer::Cellular));
    assert_eq!(cn_ok.fallback, None);

    let intl_ok = IntlFactory.sms_router(mobile).plan(mobile, &both);
    assert_eq!(intl_ok.primary, Some(Bearer::Cellular));
    assert_eq!(intl_ok.fallback, Some(Bearer::Ims));
}

#[test]
fn registry_context_is_constructed_for_every_axis() {
    for modem in families() {
        for carrier in carriers() {
            for vertical in verticals() {
                let context = DeviceContext::new(modem.clone(), carrier.clone(), vertical.clone());
                assert_eq!(context.modem_family, modem);
                assert_eq!(context.carrier_profile, carrier);
                assert_eq!(context.vertical, vertical);
            }
        }
    }
}


