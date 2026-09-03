//! The panel's browser half, in Leptos.
//!
//! 🔴 **What this crate is for, in one sentence:** it deserialises the agent's
//! answers into `edge_panel_api`'s types — *the same types the server
//! serialises from* — so that renaming a field on the server stops this crate
//! compiling instead of silently emptying a column in the browser.
//!
//! That guarantee is the whole reason the panel is being rewritten in Rust
//! rather than in anything else. It is checked: renaming `ModemBody.network`
//! fails both halves at compile time.
//!
//! ## Where this sits during the migration
//!
//! Served at `/next` while the existing panel keeps `/`. Not a rewrite in
//! place: this panel is the last visible window during a failure, and a
//! wholesale swap would leave it worse than it is for however long the
//! migration takes — which is exactly when it is needed most. See
//! `docs/frontend-rebuild/edge-leptos.md`.
//!
//! ## The defect this migration exists to fix, beyond types
//!
//! A survey of the panel being replaced found the same structural bug in five
//! of its six areas: **a failed request renders as an empty result.** Inbox,
//! health report, network scan, eSIM profile list and the modem list itself
//! all draw "there is nothing here" when the truth is "I could not find out".
//! `api::Load` makes that shape impossible to write by accident, and every
//! area ported here must keep the four screens apart: loading, failed, empty,
//! and data.

mod api;
mod status;

use leptos::prelude::*;
use thaw::*;

use status::{StatusPage, StatusState, STATUS_EVERY_MS};

#[component]
pub fn Panel() -> impl IntoView {
    let state = StatusState::new();

    // 首次拉取。
    {
        let state = state;
        leptos::task::spawn_local(async move { status::poll(state).await });
    }

    // 轮询。⚠️ 间隔是 10 秒，而且**不要**和别的定时器合并——原版里重扫后 +1s、
    // 认领后 +10s 各有各的理由，注释写明了：立刻读会拿到旧缓存，而认领只是给下
    // 一轮轮询上膛，HTTP 回执不是模组身份。
    {
        let state = state;
        set_interval(
            move || {
                let state = state;
                leptos::task::spawn_local(async move { status::poll(state).await });
            },
            std::time::Duration::from_millis(STATUS_EVERY_MS),
        );
    }

    // 每秒一跳，只为让相对时间会走。不跳的话「N 秒前」会冻在数据到达那一刻。
    {
        let now = state.now;
        set_interval(
            move || now.set(status::now_ms()),
            std::time::Duration::from_secs(1),
        );
    }

    view! {
        <ConfigProvider>
            <StatusPage state=state />
        </ConfigProvider>
    }
}

/// trunk's entry point.
#[wasm_bindgen::prelude::wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
    leptos::mount::mount_to_body(Panel);
}
