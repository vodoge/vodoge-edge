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



/// 作废的那些对，在内置矩阵里必须是「未测」。
///
/// 2026-09-05 定的：EC25-CN 的 4 条、EG25-G 的 4 条、EC20 × CN-Unicom 那条，
/// 从未进过云端账本 —— 也就没人说得出它们是谁在什么硬件上测的。账本的价值
/// 全在「里面写的都是量出来的」，所以它们被作废，而不是被补录。
///
/// 🔴 光在云端作废不够。内置矩阵是**还没收到推送**的边缘机所依据的那一份，
/// 它要是还留着这些规则，那台机器就会拿着已作废的结论去开纳管的闸 —— 这正是
/// 「两个真相源」的经典形状，而且是不响的那种：面板会把它报成 `rule`，
/// 读的人以为背后有一次测量。
///
/// 断言的是**后果**（查出来是 Fallback，即未测），不是文件里少了几行：
/// 规则挪个位置、改个写法都不该让这条测试变绿或变红，只有「这一对是不是
/// 还在宣称自己被测过」才该。
#[test]
fn voided_pairs_read_as_untested_in_the_builtin_matrix() {
    use edge_core::CapabilityOrigin;

    let matrix = CapabilityMatrix::builtin().expect("built-in matrix is valid");

    let voided: Vec<(ModemFamily, CarrierProfile)> = carriers()
        .into_iter()
        .flat_map(|carrier| {
            [
                (ModemFamily::EC25_CN, carrier.clone()),
                (ModemFamily::EG25_G, carrier),
            ]
        })
        .chain([(ModemFamily::EC20, CarrierProfile::CN_UNICOM)])
        .collect();
    assert_eq!(voided.len(), 9, "作废的是 9 对；数量对不上说明这条测试自己写错了");

    for (family, carrier) in voided {
        assert_eq!(
            matrix.query(&family, &carrier).origin,
            CapabilityOrigin::Fallback,
            "{family} x {carrier} 已被作废，内置矩阵不该再为它宣称一条规则"
        );
    }
}

/// 内置矩阵不许比云端账本**多声称**任何东西。
///
/// 🔴 2026-09-18 在生产上并排量过，两份在三处不一致，而且方向相反：
///
/// ```text
///                              内置        云端
///   EC20×CN-Mobile  Data       放行        拒绝(untested)
///   EC20×Generic    Data       放行        拒绝(untested)
///   EC20×Generic    SmsReceive 拒绝        放行
/// ```
///
///   而两份的版本号都写着 `2026-09-05` —— 看起来像同一份。
///
///   代价：一台**还没收到推送**的机器（新装的、或者矩阵读不出来回落的）会对两个
///   云端从没测过的组合放行数据面 —— 那是花钱的方向；同时拒绝一个云端测过的收
///   短信组合。
///
/// ⚠️ 这条断言**只管一个方向**：内置比云端多说的（`supported` 而云端没有），
///    因为那一边的代价是「拿没测过的结论去放行」。内置比云端少说的不拦 ——
///    少说只会让机器更保守，而在还没收到推送时保守正是对的。
///
/// 🔴 云端那一份是从生产库抓下来的快照（`app.support_ledger`，4 行，
///    2026-09-05T07:36:10Z）。写成夹具而不是去连库：这是一条单元测试，而它要
///    钉的是「内置这份文件里的每一条都有出处」—— 出处变了要有人来改这份快照，
///    那一刻正是该重新想一遍的时候。
#[test]
fn the_builtin_matrix_claims_nothing_the_cloud_ledger_does_not() {
    // (型号, 运营商, sms_mo, sms_mt, data) —— None = 账本里没这一项。
    let ledger: &[(&str, &str, Option<&str>, Option<&str>, Option<&str>)] = &[
        ("EC20", "CN-Mobile", Some("supported"), Some("supported"), None),
        ("EC20", "CN-Telecom", Some("unsupported"), Some("unsupported"), Some("supported")),
        ("EC20", "Generic-International", Some("probe"), Some("supported"), None),
        ("EC200U-CN", "CN-Telecom", Some("supported"), Some("supported"), None),
    ];

    let builtin = include_str!("../capabilities/capability-matrix.toml");
    let mut offenders = Vec::new();
    let mut checked = 0usize;

    // 逐条规则解析出 (family, carrier, 各项 kind)。
    for block in builtin.split("[[rule]]").skip(1) {
        let field = |name: &str| -> Option<String> {
            block.lines().find_map(|line| {
                let line = line.trim();
                let rest = line.strip_prefix(name)?.trim_start().strip_prefix('=')?;
                Some(rest.trim().trim_matches('"').to_string())
            })
        };
        let kind = |name: &str| -> Option<String> {
            let raw = field(name)?;
            let at = raw.find("kind")?;
            let rest = &raw[at..];
            let start = rest.find('"')? + 1;
            let end = rest[start..].find('"')? + start;
            Some(rest[start..end].to_string())
        };
        let (Some(family), Some(carrier)) = (field("modem_family"), field("carrier")) else {
            continue;
        };
        let row = ledger
            .iter()
            .find(|(f, c, ..)| *f == family && *c == carrier);
        let Some((_, _, l_mo, l_mt, l_data)) = row else {
            offenders.push(format!("{family} × {carrier}：整条规则在云端账本里没有出处"));
            continue;
        };
        for (name, cloud) in [("sms_mo", l_mo), ("sms_mt", l_mt), ("data", l_data)] {
            checked += 1;
            let Some(local) = kind(name) else { continue };
            // 只拦「内置说 supported 而云端没说」。见上面那段注释。
            if local == "supported" && *cloud != Some("supported") {
                offenders.push(format!(
                    "{family} × {carrier} 的 {name}：内置说 supported，云端账本是 {}",
                    cloud.unwrap_or("（没有这一项）"),
                ));
            }
        }
    }

    assert!(
        checked >= 9,
        "只检查了 {checked} 项 —— 解析坏了，不是规则变少了（3 条规则 × 3 项）",
    );
    assert_eq!(
        offenders,
        Vec::<String>::new(),
        "内置矩阵比云端账本多声称了东西。一台还没收到推送的机器会拿这些没有出处的\n\
         结论去放行 —— 而 data 那一项是花钱的方向。\n\
         要么把它从内置矩阵里删掉，要么先在云端账本里记下这次测量。",
    );
}
