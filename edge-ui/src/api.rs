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
#[allow(dead_code)] // 状态页只读；第一个写操作（认领候选）会用到它。
pub async fn post<B: Serialize, T: DeserializeOwned>(path: &str, body: &B, what: &str) -> Load<T> {
    let request = match gloo_net::http::Request::post(path).json(body) {
        Ok(request) => request,
        Err(error) => return Load::Failed(format!("{what}：请求构造失败（{error}）")),
    };
    finish(request.send().await, what).await
}
