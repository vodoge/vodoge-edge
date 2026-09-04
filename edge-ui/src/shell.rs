//! 面板的骨架：三栏 + 中栏标签页。
//!
//! 🔴 **这是把搬迁时丢掉的布局补回来。** 旧面板是一个三栏的运维台——左边模组
//! 列表、中间按功能切标签、右边日志——而第一版 Leptos 面板把所有卡片竖着堆成
//! 了一根长条。功能一个不少，但**一屏能看到的东西少了一大半**，而这块面板存在
//! 的理由正是「故障时一眼看清现场」。
//!
//! ## 为什么是这三栏
//!
//! 每一栏回答一个不同的问题，而排障时这三个问题是**同时**要看的：
//!
//! | 左 | 有哪几根，各自什么状态 | 全局上下文：选中哪一根决定中栏所有操作的目标 |
//! | 中 | 对选中这一根做什么 | 一次只做一件事，所以可以切标签 |
//! | 右 | daemon 此刻在说什么 | 必须和中栏**同时**可见——中栏点一下，右栏就是它的回声 |
//!
//! ⚠️ 日志栏**不能**做成一个标签。旧面板把它独立成一栏是对的：操作员按下一个
//! 按钮之后要立刻看到 daemon 说了什么，两者藏在互斥的标签里就等于要来回切。
//!
//! ## 用的是 Thaw 现成的东西
//!
//! `Layout` / `LayoutSider` / `LayoutHeader` 搭骨架（`has_sider` 给一个 flex 行，
//! `Absolute` 铺满视口，而且每个 `Layout` 自带一个主题化的 `Scrollbar`——三栏各
//! 自独立滚动正是要的）；`TabList` / `Tab` 做中栏切换。这一层不自己实现组件，
//! 只有栏宽和「头部固定 + 主体滚动」这两件事是 CSS，写在 `index.html` 那唯一一块
//! 覆写里，理由记在那儿。

use leptos::prelude::*;
use thaw::*;

/// 中栏一次显示哪一块。
///
/// ⚠️ 顺序即屏幕顺序，而且是**排障顺序**：先看这一根还行不行（体检），再看它
/// 能上哪个网（网络），然后才是那些会动它的操作。控制台排在最后，因为它是
/// 唯一能把任意命令打进模组的地方。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Panel {
    Health,
    Network,
    Sms,
    Esim,
    Console,
}

impl Panel {
    pub const ALL: &'static [Panel] = &[
        Panel::Health,
        Panel::Network,
        Panel::Sms,
        Panel::Esim,
        Panel::Console,
    ];

    /// 标签上的字。
    pub fn label(self) -> &'static str {
        match self {
            Panel::Health => "体检",
            Panel::Network => "网络",
            Panel::Sms => "短信",
            Panel::Esim => "eSIM",
            Panel::Console => "控制台",
        }
    }

    /// `TabList` 用字符串做选中值，这是每一块的稳定标识。
    pub fn key(self) -> &'static str {
        match self {
            Panel::Health => "health",
            Panel::Network => "network",
            Panel::Sms => "sms",
            Panel::Esim => "esim",
            Panel::Console => "console",
        }
    }

    /// 从 `TabList` 的字符串回到枚举。
    ///
    /// ⚠️ 认不出来就落回体检——那是排障的第一站，也是唯一一块**只读**的。
    /// 落回一块会动硬件的更坏。
    pub fn from_key(key: &str) -> Panel {
        Panel::ALL
            .iter()
            .copied()
            .find(|p| p.key() == key)
            .unwrap_or(Panel::Health)
    }
}

/// 一栏（或一栏里的一块）：固定的头 + 会滚的身子。
///
/// 三栏都是这个形状，所以抽出来。头不跟着滚是要紧的——那上面是这一栏的标题、
/// 新鲜度、和这一栏的动作按钮，滚走了就要人先滚回去才能按。
#[component]
pub fn Pane(
    /// 头部左边的标题。
    #[prop(into)]
    title: String,
    /// 头部右边（新鲜度徽章、动作按钮之类）。
    #[prop(optional)]
    head: Option<Children>,
    children: Children,
) -> impl IntoView {
    view! {
        <div class="vd-pane">
            <div class="vd-pane-head">
                <Caption1Strong>{title}</Caption1Strong>
                {head.map(|h| view! { <div class="vd-pane-head-end">{h()}</div> })}
            </div>
            <div class="vd-pane-body">{children()}</div>
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 每一块都有标签和键，而且键**互不相同**——`TabList` 靠字符串认块，
    /// 撞了就会有两块永远选不中其中一块。
    #[test]
    fn every_panel_has_a_distinct_key_and_a_label() {
        let mut keys: Vec<&str> = Panel::ALL.iter().map(|p| p.key()).collect();
        let count = keys.len();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), count, "有两块用了同一个键");

        for p in Panel::ALL {
            assert!(!p.label().is_empty(), "{:?} 没有标签", p);
            assert!(!p.key().is_empty());
        }
    }

    /// 键能原样走一个来回。
    #[test]
    fn a_key_round_trips_back_to_its_panel() {
        for p in Panel::ALL {
            assert_eq!(Panel::from_key(p.key()), *p);
        }
    }

    /// 🔴 认不出来的键落回**体检**——排障的第一站，也是唯一一块只读的。
    ///
    /// 落回一块会动硬件的更坏：一个存在了很久的 URL、一次改名、一个手打错的
    /// 字符串，都不该把操作员送进控制台或 eSIM。
    #[test]
    fn an_unknown_key_falls_back_to_the_read_only_panel() {
        assert_eq!(Panel::from_key(""), Panel::Health);
        assert_eq!(Panel::from_key("nope"), Panel::Health);
        assert_eq!(Panel::from_key("CONSOLE"), Panel::Health, "键区分大小写");
    }

    /// 顺序即排障顺序：先看这一根还行不行，再看它能上哪个网，会动硬件的排后面，
    /// 控制台最后——它是唯一能把任意命令打进模组的地方。
    #[test]
    fn the_panels_are_in_triage_order_with_the_console_last() {
        assert_eq!(
            Panel::ALL.first(),
            Some(&Panel::Health),
            "第一站是只读的体检"
        );
        assert_eq!(
            Panel::ALL.last(),
            Some(&Panel::Console),
            "控制台排最后——它能把任意命令打进模组"
        );
    }
}

/// 布局接线的守卫：规则挂错元素**不会报错，只是不生效**。
///
/// 🔴 这一组测试守的是一个已经发生过的坑。`Layout has_sider=true` 不把自己变成
/// flex 容器——它把 `display:flex; flex-direction:row` 写成**行内样式**，写在内层
/// 的 `.thaw-scrollbar__content` 上；`class=` 落到的外层 div 是 `display:block`。
/// 于是三栏规则挂在 `.vd-deck` 上时，`gap` 和 `flex-direction` 一条都不生效，
/// 编译过、运行不报错、控制台干净，只有在 900px 以下才看得出后果：中栏被压成
/// 0 宽，短信 / eSIM / 控制台三个标签整个跑到视口外面被裁掉，点不到。
///
/// 而且当时我用 `documentElement.scrollWidth > clientWidth` 验的「没有横向溢出」
/// ——那个判断是**假绿**：溢出被祖先裁掉了，所以文档本身确实不滚动。
#[cfg(test)]
mod layout_wiring {
    /// 布局规则的两半：一半在 CSS 里，一半是 Leptos 传下去的 prop。
    const INDEX: &str = include_str!("../index.html");
    const LIB: &str = include_str!("lib.rs");

    /// 在 `display:block` 的元素上写了也白写的属性。
    const INERT_ON_BLOCK: &[&str] = &[
        "flex-direction",
        "flex-wrap",
        "gap:",
        "align-items",
        "justify-content",
    ];

    /// 两边的名字必须对得上：CSS 里的选择器，就是 `content_class` 传下去的那个。
    #[test]
    fn the_deck_rules_target_the_class_the_shell_actually_passes() {
        let name = LIB
            .split("content_class=\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .expect("没给 Layout 传 content_class —— 三栏规则会挂到外层那个 display:block 的 div 上，全部失效");

        assert!(
            INDEX.contains(&format!(".{name} {{")) && INDEX.contains(&format!(".{name} >")),
            "index.html 里找不到 .{name} 的规则：名字只改了一半"
        );
    }

    /// 去掉 CSS 注释。注释里出现的花括号和选择器会毒化下面的切分。
    fn strip_comments(css: &str) -> String {
        let mut out = String::with_capacity(css.len());
        let mut rest = css;
        while let Some(i) = rest.find("/*") {
            out.push_str(&rest[..i]);
            match rest[i + 2..].find("*/") {
                Some(j) => rest = &rest[i + 2 + j + 2..],
                None => {
                    rest = "";
                    break;
                }
            }
        }
        out.push_str(rest);
        out
    }

    /// 把 CSS 摊成 (选择器, 这一段声明)。
    ///
    /// ⚠️ 不能用「按 `}` 切一刀」那种写法。`@media` 是**嵌套**的：规则写在断点
    /// 里面时，那种切法会把它整段算进 `@media` 的 body，于是选择器变成
    /// `@media (…)` 而不是 `.vd-deck`——而历史上出问题的那一处**正好就在断点
    /// 里面**。第一版守卫就是这么写的，变异测试当场漏掉了它。
    fn declarations_by_selector(css: &str) -> Vec<(String, String)> {
        let css = strip_comments(css);
        let mut out = Vec::new();
        let mut mark = 0usize;
        for (i, ch) in css.char_indices() {
            match ch {
                '{' => {
                    let selector = css[mark..i].trim().to_string();
                    let body_end = css[i + 1..]
                        .find(['{', '}'])
                        .map(|j| i + 1 + j)
                        .unwrap_or(css.len());
                    out.push((selector, css[i + 1..body_end].to_string()));
                    mark = i + 1;
                }
                '}' => mark = i + 1,
                _ => {}
            }
        }
        out
    }

    /// 排布属性不许挂回外层那个 `.vd-deck`——挂上去是死的。
    #[test]
    fn no_layout_property_hangs_on_the_block_level_deck() {
        for (selector, body) in declarations_by_selector(INDEX) {
            let targets_outer = selector
                .split(',')
                .map(str::trim)
                .any(|s| s == ".vd-deck" || s.starts_with(".vd-deck "));
            if !targets_outer {
                continue;
            }
            for prop in INERT_ON_BLOCK {
                assert!(
                    !body.contains(prop),
                    "`{prop}` 挂在了 .vd-deck 上（选择器 `{selector}`）。那个元素是 \
                     display:block，这条规则不生效也不报错 —— 挂到 content_class 那一层去"
                );
            }
        }
    }

    /// 换方向必须 `!important`：行内样式否则赢不了。
    #[test]
    fn the_stacked_layout_can_outrank_the_inline_style() {
        let mq = INDEX
            .split("@media (max-width: 900px)")
            .nth(1)
            .expect("900px 断点没了——窄屏会一直挤成三栏");
        let rule = mq
            .split_once("flex-direction")
            .expect("断点里没有改方向：摊成一列全靠这一条")
            .1;
        let decl = rule.split(';').next().unwrap_or_default();
        assert!(
            decl.contains("!important"),
            "改方向没写 !important —— `has_sider` 的行内 `flex-direction: row` 会赢，\
             窄屏还是三栏，中栏被压成 0 宽"
        );
    }
}
