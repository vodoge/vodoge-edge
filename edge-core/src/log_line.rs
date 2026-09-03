//! 日志行的分类：级别、话题、心跳、这一行说的是哪一根模组。
//!
//! ⚠️ **这些都不是服务端标的。** `/api/logs` 只给 `{seq, at, text}` 三个字段，
//! 没有级别、没有话题、没有模组。下面每一条都是从行文里**推断**出来的，推错
//! 是可能的。面板上那几个筛选按钮的 tooltip 必须把这句话说出来，否则操作员会
//! 以为「错 0 条」是 daemon 的结论。
//!
//! 规则从 `edge-panel/src/index.html` 里那份 JS 搬过来，一条不改。搬过来的理由
//! 和 [`crate::sms_block`] 一样：那个 HTML 文件迟早要删，而这套规则里最要紧的
//! 部分是**顺序**——顺序错了不报错，只是安静地把颜色标反。搬到这里，顺序就能
//! 被测试钉住。
//!
//! 没有引 `regex`：整个 workspace 都没有这个依赖，而这块代码要进 wasm 包。所有
//! 模式都归得到「词边界 + 子串」这一种，手写反而看得清在匹配什么。

/// 一行日志的级别。⚠️ 推断出来的，不是 daemon 标的。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    /// 失败：daemon 明说这一步没成。
    Err,
    /// 降级：跑通了，但不是该有的样子。
    Warn,
    /// 常规：包括每 10 秒三条的轮询心跳。
    Info,
}

impl Level {
    pub fn key(self) -> &'static str {
        match self {
            Self::Err => "err",
            Self::Warn => "warn",
            Self::Info => "info",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Err => "错",
            Self::Warn => "警",
            Self::Info => "信",
        }
    }

    pub fn hint(self) -> &'static str {
        match self {
            Self::Err => "失败：daemon 明说这一步没成。",
            Self::Warn => "降级：跑通了，但不是该有的样子。",
            Self::Info => "常规：包括每 10 秒三条的轮询心跳。",
        }
    }
}

/// 这一行来自哪件事。
///
/// ⚠️ 是 daemon 意义上的「来源」，**不是 HTTP 端点**：面板自己的 handler 一行
/// 日志都不打，所以「调的哪个 /api 路由」这件事根本不在这份数据里，这里也不
/// 编造。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Topic {
    Poll,
    Report,
    Sms,
    Uplink,
    Usb,
    Restart,
    At,
    Modem,
    Panel,
    Proxy,
    Command,
    Other,
}

impl Topic {
    pub fn label(self) -> &'static str {
        match self {
            Self::Poll => "轮询",
            Self::Report => "投递报告",
            Self::Sms => "短信",
            Self::Uplink => "上行",
            Self::Usb => "USB",
            Self::Restart => "重启",
            Self::At => "AT",
            Self::Modem => "模组识别",
            Self::Panel => "面板",
            Self::Proxy => "代理",
            Self::Command => "云端命令",
            Self::Other => "其他",
        }
    }
}

/// 屏幕上话题下拉框的顺序。
pub const TOPIC_ORDER: &[Topic] = &[
    Topic::Poll,
    Topic::Report,
    Topic::Sms,
    Topic::Uplink,
    Topic::Usb,
    Topic::Restart,
    Topic::At,
    Topic::Modem,
    Topic::Panel,
    Topic::Proxy,
    Topic::Command,
    Topic::Other,
];

/// 一行日志能自己交代的全部信息，到达时算一次，不在每次改筛选时重算。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Classified {
    pub level: Level,
    pub topic: Topic,
    /// 例行成功心跳。值得单独命名，因为它不是流量的一小部分 —— 它几乎就是全部。
    pub beat: bool,
    /// 行里写了 `imei=…` 时的那一根，属于确凿归属。
    pub imei: Option<String>,
    /// 没写 `imei=` 时，行里出现的裸 15 位数字。**是猜的**，所以和 `imei` 分开放。
    pub bare: Vec<String>,
    /// 行里出现的 `/dev/…` 设备路径。
    pub port: Option<String>,
}

/// 把一行日志读成上面那些字段。
pub fn classify(text: &str) -> Classified {
    let lower = text.to_lowercase();
    Classified {
        level: level_of(&lower),
        topic: topic_of(&lower),
        beat: is_heartbeat(&lower),
        imei: tagged_imei(&lower),
        bare: if tagged_imei(&lower).is_some() {
            Vec::new()
        } else {
            bare_imeis(text)
        },
        port: dev_path(text),
    }
}

/// ⚠️ **顺序是这个函数的全部内容。** 换一换不会报错，只会把颜色安静地标反。
fn level_of(lower: &str) -> Level {
    // 故意排在最前：一行说自己拿替代方案继续跑了，那是「警」，哪怕它里面
    // 有个东西失败了。「EF_AD …: QMI request rejected; assuming a 2-digit
    // MNC」否则会因为一个 "rejected" 变成红的,而一个追着红去的操作员会白跑
    // 一趟,只为发现 daemon 早就自己处理好了。
    //
    // 只留了确实表示「已恢复」的两种说法。"retrying" 故意不在这里 —— 一个
    // 将会被重试的 FAIL 仍然是 FAIL。
    if has_word(lower, "assuming") || has_word(lower, "falling back") {
        return Level::Warn;
    }

    // 整行被当成失败交上来。健康的轮询行是 "poll /dev/... ok"，从不是
    // "poll: ..."，所以锚在冒号上就能把两者分开，不必去猜尾巴 —— 尾巴是一段
    // 任意的错误字符串。
    for head in ["poll", "uplink", "panel", "command", "proxy traffic"] {
        if let Some(rest) = lower.strip_prefix(head) {
            if rest.trim_start_matches([' ', '\t']).starts_with(':') {
                return Level::Err;
            }
        }
    }

    const ERR_PREFIX: &[&str] = &["fail", "panic", "refus"];
    const ERR_WHOLE: &[&str] = &[
        "error",
        "denied",
        "rejected",
        "invalid",
        "unavailable",
        "unreachable",
        "unrecognised",
        "undecodable",
        "unidentified",
        "silent",
        "absent",
        "cannot",
        "never delivered",
        "no recipient",
        "no such",
        "not hex",
        "not numeric",
        "not deleted",
        "not recorded",
        "not started",
    ];
    if ERR_PREFIX.iter().any(|w| has_word(lower, w))
        || ERR_WHOLE.iter().any(|w| has_whole(lower, w))
    {
        return Level::Err;
    }

    // 跑得动，但不是该有的样子:"at-only" 是一个在 QMI 不应答之后改用串口
    // 应答的模组;而一次 usb recovery 是 daemon 刚刚在操作员脚下把一个口
    // 断电重上。
    const WARN_PREFIX: &[&str] = &["warn", "retry", "degrad"];
    const WARN_WHOLE: &[&str] = &[
        "at-only",
        "assuming",
        "replaced by",
        "reconnecting",
        "busy",
        "stale",
        "skipped",
        "missing",
    ];
    if WARN_PREFIX.iter().any(|w| has_word(lower, w))
        || WARN_WHOLE.iter().any(|w| has_whole(lower, w))
        || lower.starts_with("usb recovery")
        || timed_out(lower)
    {
        return Level::Warn;
    }

    Level::Info
}

/// `\btimed? ?out\b`：timeout / time out / timed out / timedout 都算。
fn timed_out(lower: &str) -> bool {
    ["timeout", "time out", "timedout", "timed out"]
        .iter()
        .any(|w| has_whole(lower, w))
}

fn topic_of(lower: &str) -> Topic {
    if starts_word(lower, "poll") {
        Topic::Poll
    } else if starts_word(lower, "status report") {
        Topic::Report
    } else if has_whole(lower, "sms") {
        Topic::Sms
    } else if starts_word(lower, "uplink") {
        Topic::Uplink
    } else if starts_word(lower, "usb") {
        Topic::Usb
    } else if starts_word(lower, "restart") {
        Topic::Restart
    } else if starts_word(lower, "at lease") || lower.starts_with("at+") {
        Topic::At
    } else if ["iccid", "ef_ad", "family"]
        .iter()
        .any(|w| starts_word(lower, w))
    {
        Topic::Modem
    } else if starts_word(lower, "panel") || starts_word(lower, "vodoge-edge panel") {
        Topic::Panel
    } else if starts_word(lower, "proxy") {
        Topic::Proxy
    } else if starts_word(lower, "command") {
        Topic::Command
    } else {
        Topic::Other
    }
}

/// `^poll /dev/\S+ imei=\d+ ok$`
///
/// 只认 "ok" 那一种。兄弟行结尾是 "at-only"，那是一个 QMI 不通之后改走串口的
/// 模组；把它一起折进去，「静音心跳」就会安静地藏起一个降级的模组 —— 而那正是
/// 操作员打开这个开关要找的东西。
fn is_heartbeat(lower: &str) -> bool {
    let rest = match lower.strip_prefix("poll ") {
        Some(rest) => rest,
        None => return false,
    };
    let mut parts = rest.split(' ');
    let (Some(port), Some(imei), Some(tail), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    port.starts_with("/dev/")
        && !port[5..].is_empty()
        && imei
            .strip_prefix("imei=")
            .is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
        && tail == "ok"
}

/// `\bimei=(\d{15})\b`
fn tagged_imei(lower: &str) -> Option<String> {
    let mut from = 0;
    while let Some(at) = lower[from..].find("imei=") {
        let start = from + at;
        if boundary_before(lower, start) {
            let digits: String = lower[start + 5..]
                .bytes()
                .take_while(u8::is_ascii_digit)
                .map(char::from)
                .collect();
            if digits.len() == 15 && boundary_after(lower, start + 5 + 15) {
                return Some(digits);
            }
        }
        from = start + 5;
    }
    None
}

/// `\b\d{15}\b`，全部出现。
fn bare_imeis(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            if i - start == 15 && boundary_before(text, start) && boundary_after(text, i) {
                found.push(text[start..i].to_string());
            }
        } else {
            i += 1;
        }
    }
    found
}

/// `/dev/[A-Za-z0-9._-]+`，第一处。
fn dev_path(text: &str) -> Option<String> {
    let at = text.find("/dev/")?;
    let tail: String = text[at + 5..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        .collect();
    if tail.is_empty() {
        None
    } else {
        Some(format!("/dev/{tail}"))
    }
}

/// JS 的 `\b`：两侧是 `[A-Za-z0-9_]` 才算词内。
fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn boundary_before(text: &str, at: usize) -> bool {
    at == 0 || !is_word_byte(text.as_bytes()[at - 1])
}

fn boundary_after(text: &str, at: usize) -> bool {
    at >= text.len() || !is_word_byte(text.as_bytes()[at])
}

/// `\bneedle` —— 前面是词边界，后面不管（对应 `\bfail`、`\bwarn` 那一类前缀）。
fn has_word(lower: &str, needle: &str) -> bool {
    let mut from = 0;
    while let Some(at) = lower[from..].find(needle) {
        let start = from + at;
        if boundary_before(lower, start) {
            return true;
        }
        from = start + 1;
    }
    false
}

/// `\bneedle\b` —— 两侧都要是词边界。
fn has_whole(lower: &str, needle: &str) -> bool {
    let mut from = 0;
    while let Some(at) = lower[from..].find(needle) {
        let start = from + at;
        if boundary_before(lower, start) && boundary_after(lower, start + needle.len()) {
            return true;
        }
        from = start + 1;
    }
    false
}

/// `^needle\b`
fn starts_word(lower: &str, needle: &str) -> bool {
    lower.starts_with(needle) && boundary_after(lower, needle.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn level(text: &str) -> Level {
        classify(text).level
    }

    /// 顺序是这套规则的全部内容，这条守着它。
    ///
    /// daemon 早就自己拿替代方案跑通了的那一行，里面带着一个 "rejected"。规则
    /// 顺序一换，它就变成红的，而追着红去的操作员会白跑一趟现场。
    #[test]
    fn a_line_that_recovered_is_not_red_just_because_something_in_it_failed() {
        assert_eq!(
            level("EF_AD 8986…: QMI request rejected; assuming a 2-digit MNC"),
            Level::Warn,
            "已经用替代方案跑通的行不该是错"
        );
        assert_eq!(
            level("iccid read failed; falling back to AT+CCID"),
            Level::Warn
        );
    }

    /// "retrying" 故意不算「已恢复」：会被重试的 FAIL 仍然是 FAIL。
    #[test]
    fn a_failure_that_will_be_retried_is_still_a_failure() {
        assert_eq!(
            level("poll /dev/cdc-wdm0: QMI allocate failed, retrying in 5s"),
            Level::Err,
            "重试不等于恢复"
        );
    }

    /// 健康的轮询行是 `poll /dev/… ok`，失败的是 `poll: …`。冒号是分界。
    #[test]
    fn the_colon_tells_a_healthy_poll_from_a_failed_one() {
        let ok = classify("poll /dev/cdc-wdm0 imei=867018069509705 ok");
        assert_eq!(ok.level, Level::Info);
        assert!(ok.beat, "这就是那条每 10 秒三条的心跳");

        let bad = classify("poll: /dev/cdc-wdm0 went away");
        assert_eq!(bad.level, Level::Err);
        assert!(!bad.beat);
    }

    /// 「静音心跳」不能顺手藏起一个降级的模组。
    ///
    /// `at-only` 是 QMI 不应答之后改走串口的模组 —— 那正是打开这个开关的人要
    /// 找的东西。它和 `ok` 行只差结尾一个词。
    #[test]
    fn silencing_the_heartbeat_does_not_silence_a_degraded_modem() {
        let degraded = classify("poll /dev/cdc-wdm0 imei=867018069509705 at-only");
        assert!(!degraded.beat, "at-only 不是心跳，否则静音会把它一起藏掉");
        assert_eq!(degraded.level, Level::Warn, "降级要看得见");
    }

    /// 确凿归属和猜测归属分开放。
    #[test]
    fn a_tagged_imei_is_not_mixed_up_with_a_number_that_merely_looks_like_one() {
        let tagged = classify("poll /dev/cdc-wdm0 imei=867018069509705 ok");
        assert_eq!(tagged.imei.as_deref(), Some("867018069509705"));
        assert!(tagged.bare.is_empty(), "写了 imei= 就不必再猜");

        let guessed = classify("sms to 867018069509705 accepted");
        assert_eq!(guessed.imei, None, "没写 imei= 就不能当成确凿的");
        assert_eq!(guessed.bare, vec!["867018069509705".to_string()]);

        let short = classify("sms to 8670180695097 accepted");
        assert!(short.bare.is_empty(), "13 位不是 IMEI");
        let long = classify("sms to 8670180695097051234 accepted");
        assert!(long.bare.is_empty(), "20 位也不是 —— 词边界要两头都对");
    }

    #[test]
    fn the_device_path_comes_out_whole() {
        assert_eq!(
            classify("poll /dev/cdc-wdm0 imei=867018069509705 ok")
                .port
                .as_deref(),
            Some("/dev/cdc-wdm0")
        );
        assert_eq!(
            classify("usb recovery on /dev/ttyUSB2: re-enumerated")
                .port
                .as_deref(),
            Some("/dev/ttyUSB2")
        );
        assert_eq!(classify("panel: listening on 0.0.0.0:8080").port, None);
    }

    #[test]
    fn topics_come_from_the_head_of_the_line() {
        let cases = [
            ("poll /dev/cdc-wdm0 imei=1 ok", Topic::Poll),
            ("status report delivered seq=41", Topic::Report),
            ("uplink connected", Topic::Uplink),
            ("usb recovery on /dev/ttyUSB2", Topic::Usb),
            ("restart requested for 867018069509705", Topic::Restart),
            ("AT+CSQ -> +CSQ: 10,99", Topic::At),
            ("at lease renewed", Topic::At),
            ("iccid 8986… read", Topic::Modem),
            ("panel: listening on 0.0.0.0:8080", Topic::Panel),
            ("proxy traffic: 12 KiB", Topic::Proxy),
            ("command accepted id=7", Topic::Command),
            ("something nobody classified", Topic::Other),
        ];
        for (text, want) in cases {
            assert_eq!(classify(text).topic, want, "话题判错了：{text}");
        }
    }

    /// 话题里的 sms 是整词：不能被 "smsc" 之类勾住。
    #[test]
    fn sms_is_matched_as_a_whole_word() {
        assert_eq!(classify("sms queued for 8613800100500").topic, Topic::Sms);
        assert_ne!(
            classify("smsc address unchanged").topic,
            Topic::Sms,
            "smsc 不是 sms"
        );
    }

    /// 词边界是真的边界：`\berror\b` 不该被 "errors" 之外的东西勾住，
    /// 而 `\bfail` 是前缀，"failed" 要算。
    #[test]
    fn word_boundaries_are_boundaries() {
        assert_eq!(level("qmi request failed"), Level::Err, "fail 是前缀匹配");
        assert_eq!(
            level("terror management"),
            Level::Info,
            "terror 里没有 error"
        );
        assert_eq!(level("cannot open port"), Level::Err);
        assert_eq!(level("scanner opened"), Level::Info, "scan 里没有 cannot");
    }

    /// timeout 的四种写法都要认出来。
    #[test]
    fn every_spelling_of_a_timeout_counts() {
        for text in [
            "qmi timeout",
            "qmi time out",
            "qmi timedout",
            "qmi timed out",
        ] {
            assert_eq!(level(text), Level::Warn, "没认出来：{text}");
        }
    }
}
