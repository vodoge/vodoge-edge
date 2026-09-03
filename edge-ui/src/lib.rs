//! The panel's browser half, in Leptos.
//!
//! 🔴 **What this crate is for, in one sentence:** it deserialises
//! `/api/status` into `edge_panel_api::StatusBody` — the *same type the server
//! serialises from* — so that renaming a field on the server stops this
//! crate compiling instead of silently emptying a column in the browser.
//!
//! That guarantee is the whole reason the panel is being rewritten in Rust
//! rather than in anything else, and it is the acceptance condition for this
//! stage. The old panel parses the same JSON in hand-written Alpine.js, where
//! a renamed field is a blank cell nobody notices.
//!
//! ## Where this sits during the migration
//!
//! Served at `/next` while the existing panel keeps `/`. Not a rewrite in
//! place: this panel is the last visible window during a failure, and a
//! wholesale swap would leave it worse than it is for however long the
//! migration takes — which is exactly when it is needed most. See
//! `docs/frontend-rebuild/edge-leptos.md`.

use edge_panel_api::{PanelMode, StatusBody};
use leptos::prelude::*;
use thaw::*;

/// How a finished fetch turned out.
///
/// 🔴 Three screens, not two, and they are kept apart on purpose: **loading**
/// is `Suspense`'s fallback, **failed** says what failed, and **empty** is a
/// fact about the machine said in its own words. None of them may be drawn as
/// another. The cloud console carries a docblock about the day it drew
/// "Nothing recorded yet" over a full audit log — this is that lesson arriving
/// before the defect instead of after it.
///
/// There is no `Waiting` variant because there is nothing for it to mean: the
/// value only exists once the future has resolved.
#[derive(Clone, Debug)]
enum Load {
    Failed(String),
    Ready(StatusBody),
}

/// Fetch the status once, with the shared types on both ends of the wire.
async fn fetch_status() -> Load {
    match gloo_net::http::Request::get("/api/status").send().await {
        Err(error) => Load::Failed(format!("无法连接到 agent：{error}")),
        Ok(response) if !response.ok() => {
            Load::Failed(format!("agent 返回 {}", response.status()))
        }
        // The deserialise that carries the guarantee. `StatusBody` is
        // `edge-panel-api`'s, not a shape declared here.
        Ok(response) => match response.json::<StatusBody>().await {
            Ok(body) => Load::Ready(body),
            Err(error) => Load::Failed(format!("agent 的应答解析不了：{error}")),
        },
    }
}

#[component]
fn ModemTable(body: StatusBody) -> impl IntoView {
    let modems = body.modems;
    if modems.is_empty() {
        // Empty is a fact about the machine, not a failure — and it is said
        // in its own words rather than by drawing nothing.
        return view! { <Text>"这台机器上没有已纳管的模组。"</Text> }.into_any();
    }
    view! {
        <Table>
            <TableHeader>
                <TableRow>
                    <TableHeaderCell>"IMEI"</TableHeaderCell>
                    <TableHeaderCell>"型号"</TableHeaderCell>
                    <TableHeaderCell>"状态"</TableHeaderCell>
                    <TableHeaderCell>"驻留网络"</TableHeaderCell>
                    <TableHeaderCell>"能力来源"</TableHeaderCell>
                </TableRow>
            </TableHeader>
            <TableBody>
                {modems
                    .into_iter()
                    .map(|m| {
                        // `capability_origin` is `edge_core::CapabilityOrigin`
                        // itself. Adding a variant to that enum makes this
                        // `match` non-exhaustive — which is the point.
                        let origin = match m.capability_origin {
                            edge_panel_api::CapabilityOrigin::Rule => "规则",
                            edge_panel_api::CapabilityOrigin::Fallback => "回退",
                        };
                        view! {
                            <TableRow>
                                <TableCell>{m.imei}</TableCell>
                                <TableCell>{m.family}</TableCell>
                                <TableCell>{m.state}</TableCell>
                                <TableCell>
                                    {m.network.unwrap_or_else(|| "—".to_string())}
                                </TableCell>
                                <TableCell>{origin}</TableCell>
                            </TableRow>
                        }
                    })
                    .collect_view()}
            </TableBody>
        </Table>
    }
    .into_any()
}

#[component]
pub fn Panel() -> impl IntoView {
    let status = LocalResource::new(fetch_status);

    view! {
        <ConfigProvider>
            <Card>
                <CardHeader>
                    <Body1><b>"模组"</b></Body1>
                </CardHeader>
                <Suspense fallback=move || view! { <Text>"正在读取 agent…"</Text> }>
                    {move || {
                        status
                            .get()
                            .map(|load| match load.take() {
                                Load::Failed(why) => {
                                    // A failure says what failed. It does not
                                    // render as an empty modem list.
                                    view! { <MessageBar intent=MessageBarIntent::Error>
                                        <MessageBarBody>{why}</MessageBarBody>
                                    </MessageBar> }
                                        .into_any()
                                }
                                Load::Ready(body) => {
                                    let mode = match body.mode {
                                        PanelMode::Cloud => "已连上云端",
                                        PanelMode::Local => "本地模式（无上行）",
                                    };
                                    view! {
                                        <Text>{mode}</Text>
                                        <ModemTable body=body />
                                    }
                                        .into_any()
                                }
                            })
                    }}
                </Suspense>
            </Card>
        </ConfigProvider>
    }
}

/// trunk's entry point.
#[wasm_bindgen::prelude::wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
    leptos::mount::mount_to_body(Panel);
}
