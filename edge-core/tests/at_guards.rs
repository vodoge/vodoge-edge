//! `at_guard` 的忠实度证据，脱离 JS 原文之后仍然站得住。
//!
//! 🔴 这一条比 [`crate::log_line`] 那一条更要命：日志分类判错只是把颜色标反，
//! **守卫判错会让一条危险命令绕过对话框直接打进模组** —— 而这批硬件经 USB/IP
//! 过来，没有人能物理接触。
//!
//! `at-guards.json` 里每一条的答案不是我写的，是把 `edge-panel/src/index.html`
//! 里 `GUARDED` 的 8 个正则原样抠出来、用 node 跑出来的。85 条语料覆盖到全部 8
//! 条守卫（43 条命中）外加 42 条不该命中的，命中标签和捕获组都比过。
//!
//! ⚠️ 这个测试红了，先想清楚是不是真要改行为。改松一格，就有一条命令不再先问
//! 一次了。

use edge_core::{guarded, Channel, Guarded};

#[derive(serde::Deserialize)]
struct Row {
    command: String,
    label: Option<String>,
    captured: Vec<String>,
}

fn label_of(g: Guarded) -> &'static str {
    match g {
        Guarded::Usbnet(_) => r#"AT+QCFG="usbnet",N"#,
        Guarded::CfunReset(_) => "AT+CFUN=N,1",
        Guarded::CfunDown(_) => "AT+CFUN=0 / =4 / =7",
        Guarded::Cops(_) => "AT+COPS=1,… / =2",
        Guarded::CrsmWrite(_) => "AT+CRSM=214/219/220,…",
        Guarded::Csim => "AT+CSIM=…",
        Guarded::Channel(_) => "AT+CCHO / +CGLA / +CCHC",
        Guarded::Qprtpara => "AT+QPRTPARA=…",
    }
}

fn captured(g: Guarded) -> Vec<String> {
    match g {
        Guarded::Usbnet(v)
        | Guarded::CfunReset(v)
        | Guarded::CfunDown(v)
        | Guarded::Cops(v)
        | Guarded::CrsmWrite(v) => vec![v.to_string()],
        Guarded::Csim | Guarded::Qprtpara => Vec::new(),
        Guarded::Channel(which) => vec![match which {
            Channel::Open => "ccho",
            Channel::Use => "cgla",
            Channel::Close => "cchc",
        }
        .to_string()],
    }
}

fn rows() -> Vec<Row> {
    serde_json::from_str(include_str!("at-guards.json")).expect("golden 文件不是合法 JSON")
}

#[test]
fn the_rust_matcher_guards_exactly_what_the_javascript_regexes_guarded() {
    let rows = rows();
    assert!(rows.len() >= 80, "语料只剩 {} 条，量不到什么", rows.len());

    let mut wrong = Vec::new();
    for row in &rows {
        let hit = guarded(&row.command);
        let label = hit.map(|g| label_of(g).to_string());
        let caps: Vec<String> = hit.map(captured).unwrap_or_default();
        let theirs: Vec<String> = row.captured.iter().map(|c| c.to_lowercase()).collect();
        if label != row.label || caps != theirs {
            wrong.push(format!(
                "  {:?}\n     JS  {:?} {:?}\n     RS  {:?} {:?}",
                row.command, row.label, theirs, label, caps
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} / {} 条和 JS 原文判得不一样：\n{}",
        wrong.len(),
        rows.len(),
        wrong.join("\n")
    );
}

/// 🔴 放松比收紧危险得多，所以单独钉一遍「不该拦的确实不拦、该拦的一条不漏」。
#[test]
fn the_corpus_covers_every_guard_and_a_pile_of_ordinary_commands() {
    let rows = rows();
    for label in [
        r#"AT+QCFG="usbnet",N"#,
        "AT+CFUN=N,1",
        "AT+CFUN=0 / =4 / =7",
        "AT+COPS=1,… / =2",
        "AT+CRSM=214/219/220,…",
        "AT+CSIM=…",
        "AT+CCHO / +CGLA / +CCHC",
        "AT+QPRTPARA=…",
    ] {
        assert!(
            rows.iter().any(|r| r.label.as_deref() == Some(label)),
            "语料里没有一条命中 {label}，这条守卫等于没测"
        );
    }
    let clean = rows.iter().filter(|r| r.label.is_none()).count();
    assert!(clean >= 30, "不该命中的样本只有 {clean} 条，太少了");
}

/// 代理自己每次体检都在发的那条 `AT+CRSM=176,…` 绝不能被拦。
///
/// 拦了的话，屏幕上会在守护进程自己一直在做的事情前面弹一个对话框 —— 那会
/// 让所有对话框都变得可以无视。
#[test]
fn the_read_form_the_daemon_itself_sends_is_never_guarded() {
    assert_eq!(guarded("AT+CRSM=176,28589,0,0,4"), None);
    for read in ["AT+CRSM=178,1", "AT+CRSM=192,1", "AT+CRSM=242,1"] {
        assert_eq!(guarded(read), None, "读不该拦：{read}");
    }
}

/// `AT+CFUN=1`（不带复位）不拦，`AT+CFUN=1,1`（带复位）要拦。
///
/// 这是恢复梯子的回程命令和那条唯一量到过的解药之间的区别，一个逗号。
#[test]
fn the_way_back_is_not_guarded_but_the_reset_is() {
    assert_eq!(guarded("AT+CFUN=1"), None, "回程命令不该先问一次");
    assert_eq!(guarded("AT+CFUN=1,1"), Some(Guarded::CfunReset(1)));
    assert_eq!(guarded("AT+COPS=0"), None, "自动选网是回程，不拦");
}

/// 🔴 全频段扫网发的是 `AT+COPS=?`（查询形式），手动锁网发的是
/// `AT+COPS=1,…`（写形式）。表里守的必须是后者，不能连带前者一起拦——
/// 扫网按钮自己已经有一个确认框了，AT 控制台不该再对同一条命令追加一个。
#[test]
fn the_sweep_form_of_cops_is_never_guarded_only_the_manual_selection_is() {
    for sweep in ["AT+COPS=?", "at+cops=?", "AT+COPS = ?"] {
        assert_eq!(guarded(sweep), None, "扫网的查询形式不该被拦：{sweep}");
    }
    assert_eq!(guarded("AT+COPS=1,2,\"46000\""), Some(Guarded::Cops(1)));
    assert_eq!(guarded("AT+COPS=2"), Some(Guarded::Cops(2)));
}

/// 🔴 中文输入不能把匹配器打崩。
///
/// 这一整块面板是中文的，而 `guarded()` 是「发出」按下之后走的**第一步**。
/// 早先 `strip_ci` 用 `s[..prefix.len()]` 做字节切片，只检查长度不检查字符
/// 边界；八条守卫前缀全是 7 字节，所以每条命令都先在第 7 字节切一刀——
/// 「重启模组」的第 7 字节正落在第三个汉字中间，直接 panic。三个汉字以上的
/// 输入必炸，而 AT 与 USSD 共用同一个输入框，两种模式都走这一步。
///
/// wasm 上 panic 就是 trap：操作员看不到任何错误（只有 devtools 里一行），
/// 命令也没发出去，屏幕上什么都不显示。对一块「故障时最后一道可视窗口」
/// 来说这是最坏的失败方式——而这次部署顺手删掉了旧面板，没有回退的那一份。
///
/// 这条测试不关心这些输入**判成什么**，只关心它们不炸。
#[test]
fn a_command_full_of_chinese_does_not_blow_up_the_matcher() {
    for command in [
        "重启模组",
        "你好吗",
        "查询信号",
        "信号强度怎么样",
        "AT+CSQ 信号",
        "AT+CS信号",
        "你好👋世界",
        "模组重启一下试试",
        // 两个临界点：八条守卫前缀是 7 字节，qprtpara 是 11 字节。
        "重启模",
        "重启模组信",
    ] {
        let _ = guarded(command);
    }

    // 逐个字符边界前缀扫一遍，任何一个切点都不能炸。
    let text = "重启模组信号强度AT+CSQ查询";
    for (at, _) in text.char_indices() {
        let _ = guarded(&text[..at]);
    }
    let _ = guarded(text);
}

/// 修 panic 不能顺手放松匹配。
#[test]
fn chinese_around_a_guarded_command_does_not_change_the_verdict() {
    assert_eq!(
        guarded("请发送 AT+CFUN=1,1"),
        None,
        "前面带中文就不是那条命令"
    );
    assert_eq!(guarded("AT+CFUN=1,1"), Some(Guarded::CfunReset(1)));
}
