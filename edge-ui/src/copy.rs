//! 把文字放进剪贴板。
//!
//! 🔴 **`navigator.clipboard` 在现场根本不存在。**
//!
//! 这块面板在现场几乎总是从 `http://<lan-ip>:8743` 打开，而那**不是安全
//! 上下文**（secure context）——`navigator.clipboard` 只在 https 或
//! localhost 下才有。旧面板的注释把这件事说得很清楚：
//!
//! > The old `execCommand` path is not a legacy nicety here, it is the one
//! > that actually runs on site.
//!
//! 搬到 Leptos 时这一整类动作（复制日志、复制控制台记录）连同这条结论一起
//! 丢了。谁只按 `navigator.clipboard` 重新实现一遍，就会做出一个在开发机上
//! （localhost，安全上下文）好用、**在生产上永远静默失败**的按钮。
//!
//! ⚠️ 返回值必须被用。「已复制」的回馈只在真的复制成功时出现——一个说了
//! 「已复制」而剪贴板里什么都没有的按钮，比没有这个按钮更坏：操作员会去粘贴，
//! 粘出上一次复制的东西，然后把它当成这一次的证据。

use wasm_bindgen::JsCast;

/// 复制成功返回 `true`。
///
/// 先试异步的 `navigator.clipboard`（有的话），失败或不存在就退回
/// `document.execCommand("copy")`。两条路都试过还是不行就老实返回 `false`。
pub async fn copy_text(value: &str) -> bool {
    if clipboard_write(value).await {
        return true;
    }
    exec_command_copy(value)
}

/// 安全上下文下的那条路。不存在时**不能 panic**——不存在是常态，不是异常。
async fn clipboard_write(value: &str) -> bool {
    let Some(window) = web_sys::window() else {
        return false;
    };
    let navigator = window.navigator();
    // ⚠️ 用 Reflect 探一下再取。`web_sys` 的 `Navigator::clipboard()` 在
    //    非安全上下文里拿到的是 `undefined`，直接当对象用会 panic，
    //    而 wasm 上的 panic 就是 trap：操作员屏幕上什么都不会显示。
    let has = js_sys::Reflect::get(&navigator, &"clipboard".into())
        .map(|v| !v.is_undefined() && !v.is_null())
        .unwrap_or(false);
    if !has {
        return false;
    }
    let promise = navigator.clipboard().write_text(value);
    wasm_bindgen_futures::JsFuture::from(promise).await.is_ok()
}

/// 现场真正会走的那条路。
///
/// 造一个屏幕外的 `<textarea>`，选中，`execCommand("copy")`，然后拆掉。
/// ⚠️ 元素必须**加进文档**才能被 select —— 游离节点上的 select 是空操作。
fn exec_command_copy(value: &str) -> bool {
    let Some(document) = web_sys::window().and_then(|w| w.document()) else {
        return false;
    };
    let Some(body) = document.body() else {
        return false;
    };
    let Ok(element) = document.create_element("textarea") else {
        return false;
    };
    let Ok(holder) = element.dyn_into::<web_sys::HtmlTextAreaElement>() else {
        return false;
    };
    holder.set_value(value);
    let _ = holder.set_attribute("readonly", "");
    // 放到屏幕外而不是 `display:none`：隐藏的元素选不中。
    let _ = holder.set_attribute("style", "position:fixed;top:0;left:-9999px;opacity:0");
    if body.append_child(&holder).is_err() {
        return false;
    }
    holder.select();
    // ⚠️ `exec_command` 挂在 `HtmlDocument` 上，不在 `Document` 上——
    //    转不过去就老实返回 false，不能 panic（wasm 上 panic 是 trap，
    //    屏幕上什么都不会显示）。
    let copied = document
        .dyn_ref::<web_sys::HtmlDocument>()
        .and_then(|d| d.exec_command("copy").ok())
        .unwrap_or(false);
    let _ = body.remove_child(&holder);
    copied
}

/// 复制之后给操作员的那句话。
///
/// 🔴 失败必须说失败。这块面板通篇的规矩是「没做成的事不许画成做成了」，
/// 而剪贴板是最容易违反它的地方：屏幕上写「已复制」，剪贴板里是上一次的
/// 内容，操作员粘出来当成这一次的证据。
pub fn copy_note(ok: bool, what: &str) -> String {
    if ok {
        format!("已复制{what}")
    } else {
        "复制失败 —— 浏览器不让这个页面写剪贴板，请手动选中".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::copy_note;

    /// 🔴 失败不许画成成功。
    #[test]
    fn a_failed_copy_never_says_it_copied() {
        assert!(copy_note(true, "3 行").contains("已复制"));
        let bad = copy_note(false, "3 行");
        assert!(
            !bad.contains("已复制"),
            "失败的回馈里不能出现「已复制」：{bad}"
        );
        assert!(
            bad.contains("手动"),
            "失败时要给下一步，否则操作员只知道没成、不知道怎么办：{bad}"
        );
    }
}
