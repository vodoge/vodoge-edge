//! `log_line` 的忠实度证据，脱离 JS 原文之后仍然站得住。
//!
//! `log-classification.json` 里每一行的答案**不是我写的**，是把
//! `edge-panel/src/index.html` 里那几个规则常量原样抠出来、用 node 跑出来的。
//! 262 行语料覆盖到每一个规则词，逐字段比对过 1572 处，全同。
//!
//! ⚠️ 这个文件的意义在于 index.html 被删之后：那时 JS 原文没有了，能证明这套
//! 规则**当初就是照搬的**、而不是我凭印象写的,只剩这一份快照。所以:
//!
//! - 这个测试红了，先想清楚是不是真要改行为，而不是顺手更新期望值。
//! - 真要改规则,连同这里一起改,并在提交信息里说清楚改的是哪一条、为什么。
//!
//! 语料本身也是真的：模板来自代码里的 `log_line!` / `log_error!` 调用点。

use edge_core::{classify, Topic};

#[derive(serde::Deserialize)]
struct Row {
    text: String,
    level: String,
    topic: String,
    beat: bool,
    imei: String,
    bare: Vec<String>,
    port: String,
}

fn topic_key(t: Topic) -> &'static str {
    match t {
        Topic::Poll => "poll",
        Topic::Report => "report",
        Topic::Sms => "sms",
        Topic::Uplink => "uplink",
        Topic::Usb => "usb",
        Topic::Restart => "restart",
        Topic::At => "at",
        Topic::Modem => "modem",
        Topic::Panel => "panel",
        Topic::Proxy => "proxy",
        Topic::Command => "command",
        Topic::Other => "other",
    }
}

#[test]
fn the_rust_rules_answer_exactly_what_the_javascript_rules_answered() {
    let raw = include_str!("log-classification.json");
    let rows: Vec<Row> = serde_json::from_str(raw).expect("golden 文件不是合法 JSON");

    // 非空地板：语料掉空了的话，下面的循环是在检查空气。
    assert!(
        rows.len() >= 200,
        "语料只剩 {} 行，这个测试量不到什么了",
        rows.len()
    );

    let mut wrong = Vec::new();
    for row in &rows {
        let got = classify(&row.text);
        let mine = (
            got.level.key(),
            topic_key(got.topic),
            got.beat,
            got.imei.clone().unwrap_or_default(),
            got.bare.clone(),
            got.port.clone().unwrap_or_default(),
        );
        let theirs = (
            row.level.as_str(),
            row.topic.as_str(),
            row.beat,
            row.imei.clone(),
            row.bare.clone(),
            row.port.clone(),
        );
        if mine != theirs {
            wrong.push(format!(
                "  {}\n    JS  {theirs:?}\n    RS  {mine:?}",
                row.text
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} / {} 行和 JS 原文答得不一样：\n{}",
        wrong.len(),
        rows.len(),
        wrong.join("\n")
    );
}

/// 语料要真的碰到过每一档，否则「全同」不说明问题。
#[test]
fn the_corpus_actually_exercises_the_rules() {
    let raw = include_str!("log-classification.json");
    let rows: Vec<Row> = serde_json::from_str(raw).unwrap();

    for level in ["err", "warn", "info"] {
        assert!(
            rows.iter().any(|r| r.level == level),
            "语料里没有一行是 {level}"
        );
    }
    for topic in [
        "poll", "report", "sms", "uplink", "usb", "restart", "at", "modem", "panel", "proxy",
        "command", "other",
    ] {
        assert!(
            rows.iter().any(|r| r.topic == topic),
            "语料里没有一行是 {topic} 话题"
        );
    }
    assert!(rows.iter().any(|r| r.beat), "语料里没有心跳行");
    assert!(
        rows.iter().any(|r| !r.imei.is_empty()),
        "语料里没有带 imei= 的行"
    );
    assert!(
        rows.iter().any(|r| !r.bare.is_empty()),
        "语料里没有裸 IMEI 的行"
    );
    assert!(
        rows.iter().any(|r| !r.port.is_empty()),
        "语料里没有带 /dev/ 的行"
    );
}
