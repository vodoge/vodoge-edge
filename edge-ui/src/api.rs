//! The panel's HTTP client, typed at both ends.
//!
//! 🔴 **Every call goes through [`Load`], and that is the point of this module.**
//!
//! A survey of the panel being replaced found the same defect in five of its
//! six areas: **a failed request renders as an empty result.** The inbox's
//! fetch does not check `response.ok`, so a 500 parses into `messages: []` and
//! the freshness chip stays green. A failed health report leaves `report` null,
//! which draws "not run yet". A failed scan draws "not scanned yet". A failed
//! eSIM read draws an empty profile list. A failed first `/api/status` is
//! indistinguishable from a machine with no modems attached.
//!
//! On a panel whose whole job is to be the last visible window during a
//! failure, "the request failed" rendering as "there is nothing here" is the
//! worst available answer — it is the screen that tells an operator to stop
//! looking.
//!
//! So the return type is not `Result<T, E>` that a caller may `unwrap_or_default`
//! into emptiness. It is a three-state that has to be matched, and the empty
//! case is a fourth thing the *caller* decides from the data — never from the
//! absence of it.

use serde::{de::DeserializeOwned, Serialize};

/// How a request turned out, with failure impossible to mistake for absence.
#[derive(Clone, Debug, PartialEq)]
pub enum Load<T> {
    /// In flight. Distinct from `Failed` and from an empty `Ready`.
    Loading,
    /// The request did not produce an answer. Carries what to tell the operator.
    Failed(String),
    /// The agent answered. Whether the answer is *empty* is a question about
    /// `T`, asked by whoever renders it — not something this type decides.
    Ready(T),
}

impl<T> Load<T> {
    /// ⚠️ 暂时没有调用者：状态页直接 `match`，用不上它。留着是给后面几个功能区
    /// 用的——体检、eSIM、扫网都需要「有结果就取，没有就不动」这个形状。
    #[allow(dead_code)]
    pub fn ready(&self) -> Option<&T> {
        match self {
            Load::Ready(value) => Some(value),
            _ => None,
        }
    }
}

/// Turn a response into `Load`, checking the things the old panel did not.
///
/// ⚠️ The status check is the half that was missing. `gloo_net` resolves
/// happily on a 500; without `response.ok()` the body is parsed anyway, and a
/// JSON error body like `{"error":"store unavailable"}` deserialises into a
/// struct full of defaults on some shapes and fails confusingly on others.
async fn finish<T: DeserializeOwned>(
    result: Result<gloo_net::http::Response, gloo_net::Error>,
    what: &str,
) -> Load<T> {
    let response = match result {
        Ok(response) => response,
        Err(error) => return Load::Failed(format!("{what}：连不上 agent（{error}）")),
    };
    if !response.ok() {
        // The agent explains itself in `{"error": …}` where it can. Prefer its
        // words to a bare status code — it knows which of its parts is missing.
        let status = response.status();
        let detail = response
            .json::<ApiError>()
            .await
            .ok()
            .map(|body| body.error)
            .unwrap_or_else(|| format!("HTTP {status}"));
        return Load::Failed(format!("{what}：{detail}"));
    }
    match response.json::<T>().await {
        Ok(value) => Load::Ready(value),
        // Reaching here means the agent answered 2xx with a body this build
        // cannot read — the exact drift the shared types exist to prevent, so
        // it is worth saying plainly rather than folding into "failed".
        Err(error) => Load::Failed(format!("{what}：agent 的应答解析不了（{error}）")),
    }
}

#[derive(serde::Deserialize)]
struct ApiError {
    error: String,
}

/// `GET` one of the panel's read endpoints.
pub async fn get<T: DeserializeOwned>(path: &str, what: &str) -> Load<T> {
    finish(gloo_net::http::Request::get(path).send().await, what).await
}

/// `POST` a typed body to one of the panel's action endpoints.
///
/// Every action on this panel is a POST with a JSON body, including the ones
/// whose body is empty — `/api/rescan` needs `{}` because the server asks for
/// JSON. Callers pass the request type from `edge-panel-api`, so a field
/// renamed on the server stops this crate compiling.
pub async fn post<B: Serialize, T: DeserializeOwned>(path: &str, body: &B, what: &str) -> Load<T> {
    let request = match gloo_net::http::Request::post(path).json(body) {
        Ok(request) => request,
        Err(error) => return Load::Failed(format!("{what}：请求构造失败（{error}）")),
    };
    finish(request.send().await, what).await
}

/// 🔴 请求体也必须走共享类型 —— 这个 crate 的立身之本只兑现了一半。
///
/// crate 头上写着：「把 agent 的答复反序列化成 `edge_panel_api` 的类型 ——
/// **服务端序列化时用的同一批类型** —— 改字段名会让两边一起编译失败。」
///
/// **答复方向确实成立**（文档说的就是「答复」），但请求方向长期形同虚设：
/// 2026-09-04 盘点时，14 个 POST 调用点里有 12 个用 `serde_json::json!` 手拼
/// 请求体，而 `edge-panel-api` 里 9 个请求类型就定义在那儿没人用。改一个请求
/// 字段名，编译器一声不吭，服务端 400，屏幕上是一句看不出根因的失败。
#[cfg(test)]
mod request_bodies_are_typed {
    /// ⚠️ **加了新模块要加进来。** 下面那条测试拿 `lib.rs` 的 `mod` 数量对账，
    /// 少收一个就会红 —— 「搬走了代码，守卫就瞎了」这个坑在这个仓库里已经踩过
    /// 两次（`PANEL_SOURCES` 漏掉 `shell.rs`、CSS 守卫漏掉断点里的规则）。
    ///
    /// ⚠️ **`api.rs` 自己不在里面。** 它是传输层、不造请求体，而且守卫就住在
    /// 这个文件里 —— 扫自己会被自己代码里的字符串字面量 `"api::post("` 绊倒。
    /// 这个自指的坑在这个仓库里也踩过一次（守卫被它自己要守的那条注释绊倒）。
    const SOURCES: &[(&str, &str)] = &[
        ("candidates.rs", include_str!("candidates.rs")),
        ("console.rs", include_str!("console.rs")),
        ("copy.rs", include_str!("copy.rs")),
        ("danger.rs", include_str!("danger.rs")),
        ("esim.rs", include_str!("esim.rs")),
        ("gate.rs", include_str!("gate.rs")),
        ("health.rs", include_str!("health.rs")),
        ("logs.rs", include_str!("logs.rs")),
        ("scan.rs", include_str!("scan.rs")),
        ("shell.rs", include_str!("shell.rs")),
        ("sms.rs", include_str!("sms.rs")),
        ("status.rs", include_str!("status.rs")),
        ("trace.rs", include_str!("trace.rs")),
    ];

    const LIB: &str = include_str!("lib.rs");

    /// `/api/rescan` 的 handler 只取 `State`，**根本不收 body**。给它编一个
    /// 类型出来会凭空造出一个服务端并不读的契约。
    const NO_BODY_ENDPOINTS: &[&str] = &["/api/rescan"];

    fn code_only(rust: &str) -> String {
        rust.lines()
            .map(|l| match l.find("//") {
                Some(i) => &l[..i],
                None => l,
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// 守卫扫的是这些文件；`lib.rs` 声明了几个模块就得收几个。
    #[test]
    fn the_guard_sees_every_module_in_the_crate() {
        let declared = code_only(LIB)
            .lines()
            .filter(|l| l.trim_start().starts_with("mod ") && l.trim_end().ends_with(';'))
            .count();
        assert_eq!(
            declared,
            SOURCES.len() + 1,
            "lib.rs 声明了 {declared} 个模块，守卫收了 {}（另加不扫的 api.rs）\
             —— 新模块要加进 SOURCES，否则它里面手拼的请求体没人管",
            SOURCES.len()
        );
    }

    /// 🔴 请求体不许用 `json!` 手拼。
    #[test]
    fn no_request_body_is_hand_built_with_json() {
        for (name, src) in SOURCES {
            for (n, line) in code_only(src).lines().enumerate() {
                let t = line.trim();
                let builds_body = t.starts_with("let body =") || t.starts_with("let payload =");
                assert!(
                    !(builds_body && t.contains("json!")),
                    "{name}:{} 用 json! 手拼请求体：{t}\n\
                     —— 用 edge-panel-api 里的类型，那才是服务端反序列化时用的同一份",
                    n + 1
                );
            }
        }
    }

    /// 内联的 `json!` 只允许出现在服务端确实不收 body 的那几个端点上。
    #[test]
    fn an_inline_json_body_is_only_allowed_where_the_server_reads_none() {
        for (name, src) in SOURCES {
            for (n, line) in code_only(src).lines().enumerate() {
                if !line.contains("api::post(") || !line.contains("json!") {
                    continue;
                }
                let path = line
                    .split('"')
                    .nth(1)
                    .expect("api::post 的第一个参数是路径字面量");
                assert!(
                    NO_BODY_ENDPOINTS.contains(&path),
                    "{name}:{} 给 {path} 内联了一个 json! 请求体，\
                     而那个端点是收 body 的 —— 用共享类型",
                    n + 1
                );
            }
        }
    }
}
