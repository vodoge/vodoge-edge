//! 一条短信会被编成什么样：GSM-7 还是 UCS-2，占几个单位，超没超。
//!
//! 🔴 **这里是这套规则的唯一一份。** 在此之前它有两份：`edge-modem/src/pdu.rs`
//! 里真正编码的那一份，和面板 HTML 里 JS 抄的一份。抄的那一份自己留了一句话：
//!
//! > ⚠ This is a copy of a rule that lives in another crate. If `pdu.rs` gains
//! > a character, this says 70 where the daemon would accept 160 — the error is
//! > in the safe direction, but it is still drift.
//!
//! 两边现在都从这里取，那句话可以删掉了：给 [`gsm7_value`] 加一个字符，屏幕上
//! 的字数表和 daemon 的编码器**同时**改变。
//!
//! ## 为什么这件事值得摆在屏幕上
//!
//! 这个编码器**不分片**。超过限额 `encode_submit` 直接返回 `TooLong`，发送被
//! 拒绝 —— 不是切成两条发出去。所以「这条会被拒掉」必须在按下按钮**之前**就
//! 看得见，而不是之后。
//!
//! 而且七位字母表是一个很小的 ASCII 子集：一个 `#`、一个括号、一个撇号或者一个
//! 换行，就足以把一条消息从 GSM-7 挪到 UCS-2，限额从 160 掉到 70。

/// GSM-7 下的最大七位字符数。
pub const GSM7_MAX_SEPTETS: usize = 160;
/// UCS-2 下的最大 UTF-16 码元数。⚠️ 是码元不是字符：一个 emoji 算两个。
pub const UCS2_MAX_CHARS: usize = 70;

/// 一个字符在这个编码器接受的七位字母表里的取值。
///
/// ⚠️ 这是一个**小得多**的子集，不是完整的 GSM 03.38 字母表。改动它会同时改变
/// daemon 的编码行为和面板上的字数表 —— 这正是它住在这里的原因。
pub fn gsm7_value(ch: char) -> Option<u8> {
    match ch {
        'A'..='Z' | 'a'..='z' | '0'..='9' | ' ' | '.' | ',' | '!' | '?' | ':' | '+' | '-' => {
            Some(ch as u8)
        }
        _ => None,
    }
}

/// 整条内容能不能走 GSM-7。
pub fn is_gsm7(body: &str) -> bool {
    body.chars().all(|ch| gsm7_value(ch).is_some())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    Gsm7,
    Ucs2,
}

impl Encoding {
    pub fn label(self) -> &'static str {
        match self {
            Self::Gsm7 => "GSM-7",
            Self::Ucs2 => "UCS-2",
        }
    }
}

/// 一条草稿会被编成什么样。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Draft {
    pub encoding: Encoding,
    /// 占用的单位数。GSM-7 数字符，UCS-2 数 UTF-16 码元。
    pub units: usize,
    pub limit: usize,
    /// 超了。⚠️ 超了就是**发不出去**，不是分成两条。
    pub over: bool,
}

pub fn draft(body: &str) -> Draft {
    let gsm7 = is_gsm7(body);
    let units = if gsm7 {
        body.chars().count()
    } else {
        // UCS-2 数的是 UTF-16 码元，不是字符：一个 emoji 是两个。
        body.encode_utf16().count()
    };
    let limit = if gsm7 {
        GSM7_MAX_SEPTETS
    } else {
        UCS2_MAX_CHARS
    };
    Draft {
        encoding: if gsm7 { Encoding::Gsm7 } else { Encoding::Ucs2 },
        units,
        limit,
        over: units > limit,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_ascii_goes_gsm7_with_the_long_limit() {
        let d = draft("Hello, world!");
        assert_eq!(d.encoding, Encoding::Gsm7);
        assert_eq!(d.units, 13);
        assert_eq!(d.limit, 160);
        assert!(!d.over);
    }

    /// 一个字母表外的字符就把整条消息挪到 UCS-2，限额从 160 掉到 70。
    ///
    /// 这条是给操作员看的那句话背后的事实：`#`、括号、撇号、换行，任何一个都够。
    #[test]
    fn one_stray_character_halves_the_message_more_than_twice_over() {
        for stray in ['#', '(', '\'', '\n', '@', '_', '\u{4f60}'] {
            let body = format!("hello{stray}");
            let d = draft(&body);
            assert_eq!(
                d.encoding,
                Encoding::Ucs2,
                "{stray:?} 不在字母表里，整条该走 UCS-2"
            );
            assert_eq!(d.limit, 70);
        }
    }

    /// UCS-2 数的是 UTF-16 码元：一个 emoji 是两个。
    #[test]
    fn an_emoji_counts_as_two() {
        let d = draft("\u{1F600}");
        assert_eq!(d.encoding, Encoding::Ucs2);
        assert_eq!(d.units, 2, "代理对是两个码元");
    }

    #[test]
    fn the_limits_are_where_the_encoder_puts_them() {
        let ascii = "a".repeat(160);
        assert!(!draft(&ascii).over, "160 个 GSM-7 字符正好到顶");
        assert!(draft(&format!("{ascii}a")).over, "161 就超了");

        let wide = "\u{4f60}".repeat(70);
        assert!(!draft(&wide).over, "70 个 UCS-2 码元正好到顶");
        assert!(draft(&format!("{wide}\u{4f60}")).over);
    }

    /// 字母表本身。写死一份清单，免得有人「顺手」加一个字符 —— 加它会同时改变
    /// daemon 的编码行为。
    #[test]
    fn the_seven_bit_alphabet_is_exactly_this_small() {
        let allowed: String = ('\u{20}'..='\u{7e}')
            .filter(|c| gsm7_value(*c).is_some())
            .collect();
        assert_eq!(
            allowed, " !+,-.0123456789:?ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "字母表变了 —— 这会同时改变 daemon 的编码，确认是有意为之"
        );
    }
}
