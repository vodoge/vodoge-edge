//! 受支持硬件列表：`[[device]]` 段的解析与那道闸。

use edge_core::{CapabilityMatrix, DeviceGate, UsbIdentity};

const EC20: UsbIdentity = UsbIdentity::new(0x2c7c, 0x0125);
const EC200U: UsbIdentity = UsbIdentity::new(0x2c7c, 0x0901);
/// 2026-08 卡在台架上那两根高通棒子。没有任何策略驱动它们。
const UNDRIVEN: UsbIdentity = UsbIdentity::new(0x05c6, 0x90b4);

fn matrix(toml: &str) -> CapabilityMatrix {
    CapabilityMatrix::from_toml(toml).expect("parses")
}

const ONE_RULE: &str = r#"
[[rule]]
modem_family = "EC20"
carrier = "CN-Mobile"
sms_mo = { kind = "supported", bearer = "cellular" }
"#;

/// 🔴 没有 `[[device]]` 段的文档，这道闸必须**放行**。
///
/// 这是向后兼容的全部意义。线上跑着的那份矩阵（2026-09-01 推的）就没有这个段，
/// 而目录还没有任何发布方。要是「没说」等于「不行」，新 build 上线那一刻
/// 整个机队全体过不了闸 1 —— 一次纯粹的能力增强变成一次全线中断。
#[test]
fn a_document_without_a_device_section_states_nothing_and_admits() {
    let m = matrix(&format!(r#"version = "2026-09-01"{ONE_RULE}"#));
    assert_eq!(m.devices(), None, "没有段就该是 None，不是空列表");
    for usb in [EC20, EC200U, UNDRIVEN] {
        assert_eq!(m.device_gate(usb), DeviceGate::NotStated, "{usb}");
        assert!(m.device_gate(usb).admits(), "{usb} 被一份没提它的文档挡住了");
    }
}

/// 🔴 「列表里没有它」和「文档没有列表」是两回事，动作相反。
///
/// 塌缩成一个 bool，就是让「还没人写这张表」和「写了、但没写它」
/// 产生同一个后果。
#[test]
fn absent_from_a_list_is_not_the_same_as_no_list() {
    let stated = matrix(&format!(
        r#"
version = "2026-09-06"
[[device]]
usb = "2c7c:0125"
strategy = "quectel-ec"
{ONE_RULE}"#
    ));
    assert_eq!(stated.device_gate(EC20), DeviceGate::Enabled);
    assert_eq!(
        stated.device_gate(UNDRIVEN),
        DeviceGate::Absent,
        "列表存在而它不在里面，这是一句真话"
    );
    assert!(!stated.device_gate(UNDRIVEN).admits());

    // 同一个硬件，换一份没有列表的文档，答案必须不同。
    let silent = matrix(&format!(r#"version = "x"{ONE_RULE}"#));
    assert_eq!(silent.device_gate(UNDRIVEN), DeviceGate::NotStated);
    assert!(silent.device_gate(UNDRIVEN).admits());
}

/// 明确停用的要挡住 —— 而且它和「不在列表里」也是两个不同的答案，
/// 因为运维要能分清「我们停用了它」和「没人加过它」。
#[test]
fn a_disabled_device_is_refused_and_says_so_distinctly() {
    let m = matrix(&format!(
        r#"
version = "x"
[[device]]
usb = "2c7c:0125"
strategy = "quectel-ec"
enabled = false
note = "2026-09-06 发现一批固件有问题，先停用"
{ONE_RULE}"#
    ));
    assert_eq!(m.device_gate(EC20), DeviceGate::Disabled);
    assert!(!m.device_gate(EC20).admits());
    assert_ne!(m.device_gate(EC20), m.device_gate(EC200U), "停用与缺席不该同一个答案");
    assert_eq!(m.devices().unwrap()[0].note.as_deref(), Some("2026-09-06 发现一批固件有问题，先停用"));
}

/// `enabled` 缺省为真：写进这张表本身就是表态，停用得**明确**写出来。
#[test]
fn listing_a_device_is_itself_the_statement_that_it_is_supported() {
    let m = matrix(&format!(
        r#"
version = "x"
[[device]]
usb = "2c7c:0901"
strategy = "quectel-ec200u"
{ONE_RULE}"#
    ));
    assert_eq!(m.device_gate(EC200U), DeviceGate::Enabled);
    assert!(m.devices().unwrap()[0].enabled);
}

/// 🔴 同一个 USB 标识出现两次是**错**，不是「后面的赢」。
///
/// 两行 `enabled` 一真一假时，「后面的赢」会让答案取决于文件里的顺序，
/// 而没人会想到去读顺序。规则表那边已经是这个做法（DuplicateRule）。
#[test]
fn the_same_hardware_listed_twice_is_an_error_not_a_precedence_rule() {
    let err = CapabilityMatrix::from_toml(&format!(
        r#"
version = "x"
[[device]]
usb = "2c7c:0125"
strategy = "quectel-ec"
enabled = true
[[device]]
usb = "2c7c:0125"
strategy = "quectel-ec"
enabled = false
{ONE_RULE}"#
    ))
    .expect_err("重复的一条被静默接受了");
    assert!(
        err.to_string().contains("listed twice"),
        "错误没说清是重复: {err}"
    );
}

/// 写坏的 USB 标识要在解析时就炸，不能变成一条「谁都不匹配」的死条目。
#[test]
fn a_malformed_usb_identity_is_refused_at_parse_time() {
    for bad in ["2c7c", "zzzz:0125", "2c7c:", ":0125", "2c7c-0125"] {
        let err = CapabilityMatrix::from_toml(&format!(
            r#"
version = "x"
[[device]]
usb = "{bad}"
strategy = "quectel-ec"
{ONE_RULE}"#
        ))
        .expect_err(&format!("{bad:?} 被接受了"));
        assert!(
            err.to_string().contains("invalid supported device"),
            "{bad:?} 的错误不对: {err}"
        );
    }
}

/// `min_agent_version` 读得出来。
///
/// 拒不拒绝安装是调用方的事（见字段注释）——这里只保证它没被吞掉。
/// 它存在的理由是：MatrixDocument 没有 deny_unknown_fields，所以旧 build
/// 读到带 [[device]] 的新文档会**静默地**把整段丢掉，也就是没有闸 1 且不报错。
#[test]
fn the_minimum_agent_version_survives_parsing() {
    let m = matrix(&format!(r#"
version = "x"
min_agent_version = "0.2.0"
{ONE_RULE}"#));
    assert_eq!(m.min_agent_version(), Some("0.2.0"));

    let without = matrix(&format!(r#"version = "x"{ONE_RULE}"#));
    assert_eq!(without.min_agent_version(), None, "没写就该是 None，不是某个默认值");
}

/// 内置矩阵现在没有 device 段 —— 钉住它，因为一旦有人给它加了，
/// 「还没收到推送的机器」的行为就会变，而那正是最不该悄悄变的一台。
#[test]
fn the_builtin_matrix_states_nothing_about_hardware() {
    let m = CapabilityMatrix::builtin().expect("built-in matrix is valid");
    assert_eq!(m.devices(), None);
    assert_eq!(m.device_gate(EC20), DeviceGate::NotStated);
}

// ────────────────────────── min_agent_version ──────────────────────────

use edge_core::VersionCheck;

fn with_min(v: &str) -> CapabilityMatrix {
    matrix(&format!("version = \"x\"\nmin_agent_version = \"{v}\"\n{ONE_RULE}"))
}

/// 没写就不设限。
#[test]
fn a_document_without_a_minimum_does_not_gate_on_version() {
    let m = matrix(&format!(r#"version = "x"{ONE_RULE}"#));
    assert_eq!(m.version_check("0.1.0"), VersionCheck::NotRequired);
    assert!(m.version_check("0.1.0").admits());
}

/// 够格就放行，包括正好相等。
#[test]
fn an_agent_at_or_above_the_minimum_is_admitted() {
    for running in ["0.2.0", "0.2.1", "0.3.0", "1.0.0"] {
        assert_eq!(
            with_min("0.2.0").version_check(running),
            VersionCheck::Satisfied,
            "{running} 被挡住了"
        );
    }
}

/// 🔴 不够格要拒，而且要说出两边的版本。
///
/// 只说「版本太低」而不说是哪两个数，运维得去两个地方查才能知道差多少。
#[test]
fn an_older_agent_is_refused_and_the_message_names_both_versions() {
    let check = with_min("0.2.0").version_check("0.1.0");
    assert_eq!(
        check,
        VersionCheck::TooOld {
            required: "0.2.0".into(),
            running: "0.1.0".into()
        }
    );
    assert!(!check.admits());
}

/// 🔴 版本串读不出来也**拒**。无法判断不是通过。
///
/// 做成 `Option<bool>` 的话，调用方要么忘了处理 None，要么写成
/// `unwrap_or(true)` —— 而那正好让一个写错的版本号变成「不设限」，
/// 也就是这道闸存在目的的反面。
#[test]
fn an_unreadable_version_is_refused_not_waved_through() {
    for (required, running) in [
        ("0.2.0", "not-a-version"),
        ("latest", "0.1.0"),
        ("0.2.0-rc1", "0.1.0"),
        ("", "0.1.0"),
    ] {
        let check = with_min(required).version_check(running);
        assert!(
            !check.admits(),
            "required={required:?} running={running:?} 被放行了：{check:?}"
        );
        assert!(matches!(check, VersionCheck::Unreadable { .. }) || matches!(check, VersionCheck::TooOld { .. }));
    }
}

/// 位数不齐要能比。`0.2` 和 `0.2.0` 是同一个要求。
#[test]
fn a_short_version_string_compares_as_zero_padded() {
    assert_eq!(with_min("0.2").version_check("0.2.0"), VersionCheck::Satisfied);
    assert_eq!(with_min("1").version_check("1.0.0"), VersionCheck::Satisfied);
    assert!(!with_min("1").version_check("0.9.9").admits());
}

/// 按数值比，不是按字典序。`0.10.0` 比 `0.9.0` 新。
///
/// 字典序会说 "0.10.0" < "0.9.0"，于是一个本该被挡的旧 agent 会被放行。
#[test]
fn versions_compare_numerically_not_lexically() {
    assert_eq!(with_min("0.10.0").version_check("0.9.0"), VersionCheck::TooOld {
        required: "0.10.0".into(),
        running: "0.9.0".into()
    });
    assert_eq!(with_min("0.9.0").version_check("0.10.0"), VersionCheck::Satisfied);
}
