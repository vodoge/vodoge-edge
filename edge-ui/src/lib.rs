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
mod candidates;
mod console;
mod danger;
mod esim;
mod health;
mod logs;
mod scan;
mod shell;
mod sms;
mod status;
mod trace;

use leptos::prelude::*;
use thaw::*;

use candidates::{CandidatesPage, ClaimState, RescanState};
use console::{ConsolePage, ConsoleState};
use danger::{DangerState, DangerZone};
use esim::{EsimPage, EsimState};
use health::{Health, HealthPage};
use logs::{LogState, LogsPage, LOGS_EVERY_MS};
use scan::{ScanPage, ScanState};
use shell::{Pane, Panel};
use sms::{SmsPage, SmsState, INBOX_EVERY_MS};
use status::{Freshness, ModeLabel, ModemRail, StatusState, STATUS_EVERY_MS};

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

    // 日志有自己的一套：游标、2 秒一轮、暂停缓冲。⚠️ 间隔和状态页的 10 秒
    // **故意不一样**，也不合并 —— 日志要跟得上手上的操作，10 秒太钝；而状态
    // 每 2 秒问一次是在给一台边缘小机器找麻烦。
    let claims = ClaimState::new();
    let rescan_state = RescanState::new();
    let scan = ScanState::new();
    let console = ConsoleState::new();
    let danger = DangerState::new();
    let esim = EsimState::new();
    // 本地短信：10 秒一轮，跟状态页同频。
    let sms = SmsState::new();
    {
        let sms = sms;
        leptos::task::spawn_local(async move { sms::poll(sms).await });
        set_interval(
            move || {
                let sms = sms;
                leptos::task::spawn_local(async move { sms::poll(sms).await });
            },
            std::time::Duration::from_millis(INBOX_EVERY_MS),
        );
    }

    let logs = LogState::new();
    {
        let logs = logs;
        leptos::task::spawn_local(async move { logs::poll(logs).await });
        set_interval(
            move || {
                let logs = logs;
                leptos::task::spawn_local(async move { logs::poll(logs).await });
            },
            std::time::Duration::from_millis(LOGS_EVERY_MS),
        );
    }

    // 每秒一跳，只为让相对时间会走。不跳的话「N 秒前」会冻在数据到达那一刻。
    {
        let now = state.now;
        let log_now = logs.now;
        set_interval(
            move || {
                let at = status::now_ms();
                now.set(at);
                log_now.set(at);
                // 扫网的进度条靠这一跳走。三分钟里它是唯一还在动的东西。
                scan.now.set(at);
            },
            std::time::Duration::from_secs(1),
        );
    }

    // 体检的状态住在这里而不是页里：切换模组要清掉它（原版 select() 就是这么做的），
    // 而「切换模组」是状态页的事。
    let health = RwSignal::new(Health::Idle);

    // 🔴 **换模组时的清场。加新页面的人：你的状态也要在这里清一次。**
    //
    // 原版 `select()` 做的就是这件事，注释写得很直白：「一次判决是关于一张卡的。
    // 留在另一根模组旁边，它就被读成那一根的了。」搬迁时我只搬了体检那一条，
    // 其余五处全漏了——2026-09-04 部署前的审查一次抓出五条，全是同一个根因：
    //
    //   eSIM      profile 表和切换回执跨模组残留，而表里的按钮会拿着**上一张卡的
    //             ICCID** 和**当前选中的 IMEI** 去发真正的 ES10c 写操作
    //   扫网      B 的名下画着 A 三分钟前扫到的运营商表，而扫网正是用来判断
    //             「这一根为什么注册不上」的——读反了结论正好相反
    //   危险区    A 的「射频已关闭。」挂在 B 的标题下，配着一个写「关射频」的按钮
    //   短信      一条「已提交给代理」留在另一根旁边，读起来就是那一根发出去了
    //   USSD      会话标记跨模组泄漏，「取消会话」把 AT+CUSD=2 发给一根没有会话
    //             的模组，而真正开着的那个被丢在那里
    //
    // 这批硬件没有人能物理接触。把一根模组的状态安在另一根头上，代价是有人去
    // 救错的那一根。
    //
    // ⚠️ 每个 `forget_modem()` 自己决定清什么、**留什么**——比如危险区按 IMEI
    // 记的射频状态要留、控制台的记录和历史要留、短信正在打的号码和内容要留。
    // 理由写在各自的方法上。
    Effect::new(move |_| {
        let _ = state.active.get();
        health.set(Health::Idle);
        esim.forget_modem();
        scan.forget_modem();
        danger.forget_modem();
        sms.forget_modem();
        console.forget_modem();
    });

    // 中栏当前显示哪一块。`TabList` 用字符串，`Panel` 负责两边的翻译。
    let tab = RwSignal::new(Panel::Health.key().to_string());

    view! {
        <ConfigProvider>
            // ⚠️ 布局规则挂在 `content_class` 上，不是 `class` 上。`Layout` 的
            // `class` 落到外层那个 `display:block` 的 div，flex 属性挂上去是
            // 死的——2026-09-04 因为这个，窄屏下三个标签跑到了视口外面。
            // `shell.rs` 的 `layout_wiring` 守着这件事。
            <Layout position=LayoutPosition::Absolute content_class="vd-shell">
                // ── 顶栏 ───────────────────────────────────────────────────
                // 全局的三样：这是什么、连没连上云端、数据多新。⚠️ 新鲜度必须
                // 在**任何**一栏之上，它说的是整块屏幕的年龄。
                <LayoutHeader class="vd-top">
                    <span class="vd-brand">"VoDoge 边缘面板"</span>
                    <ModeLabel state=state />
                    <span class="vd-top-end">
                        <Freshness state=state />
                    </span>
                </LayoutHeader>

                // ⚠️ `content_class` 不是装饰：`has_sider` 把 flex 行内样式写在
                // 内层滚动节点上，`class` 落到的外层 div 是 display:block。
                // 三栏的排布规则必须挂到 `vd-deck-flow` 上才有效——
                // 改名要两边一起改，`shell.rs` 里有一条测试守着这件事。
                // 🔴 这里**故意不用** `Layout has_sider=true`。
                //
                // 它有两个毛病：① 把 flex 写成行内样式塞在内层滚动节点上，
                // 外面只能靠 `!important` 掰；② 在外壳和三栏之间多插一层
                // 滚动容器——而我要的恰恰是**三栏各滚各的**，中间那层一插，
                // 就变成了整块一起滚。
                //
                // 一起滚的后果实测过：翻日志翻到 1200px，顶栏、模组列表、
                // 标签栏全部滚出屏幕，中栏是一片空白，而危险区那三个按钮
                // 还留在原地——「关射频」按钮孤零零挂在那儿，唯一能说明
                // 它对准哪一根的模组列表已经不在屏幕上了。
                //
                // 三栏也都是普通 div。`LayoutSider` 自带的 `Scrollbar` 滚的是
                // **整个栏子**，包括 pane 的头——于是往日志历史里翻的时候，
                // 级别筛选、搜索框、连「暂停」按钮都一起滚出屏幕，想暂停得先
                // 滚回顶部。`.vd-pane` 那段注释写着「头不动，身子滚」，但一直
                // 不是这样。改成让 `.vd-pane-body` 自己滚，那句话才成立。
                <div class="vd-deck">
                    // ── 左栏：有哪几根 ─────────────────────────────────────
                    // 选中哪一根是这块面板唯一的全局上下文：中栏每一个操作都
                    // 瞄准它。所以它常驻，不做成标签。
                    <div class="vd-rail">
                        <Pane title="模组">
                            <ModemRail state=state />
                        </Pane>
                        <Pane title="USB 候选">
                            <CandidatesPage
                                state=state
                                claims=claims
                                rescan_state=rescan_state
                            />
                        </Pane>
                        // 危险区钉在左栏底部，跟着选中的模组走——它是关于
                        // **这一根**的，不是关于中栏当前那一块的。
                        <div class="vd-rail-foot">
                            <DangerZone status=state state=danger />
                        </div>
                    </div>

                    // ── 中栏：对选中这一根做什么 ───────────────────────────
                    <div class="vd-main">
                        <div class="vd-pane">
                            <div class="vd-pane-head vd-tabs">
                                <TabList selected_value=tab>
                                    {Panel::ALL
                                        .iter()
                                        .map(|p| {
                                            view! {
                                                <Tab value=p.key()>{p.label()}</Tab>
                                            }
                                        })
                                        .collect_view()}
                                </TabList>
                            </div>
                            <div class="vd-pane-body">
                                {move || match Panel::from_key(&tab.get()) {
                                    Panel::Health => {
                                        view! { <HealthPage active=state.active state=health /> }
                                            .into_any()
                                    }
                                    Panel::Network => {
                                        view! { <ScanPage active=state.active state=scan /> }
                                            .into_any()
                                    }
                                    Panel::Sms => {
                                        view! { <SmsPage state=sms status=state /> }.into_any()
                                    }
                                    Panel::Esim => {
                                        view! {
                                            <EsimPage
                                                active=state.active
                                                state=esim
                                                status=state
                                            />
                                        }
                                            .into_any()
                                    }
                                    Panel::Console => {
                                        view! { <ConsolePage active=state.active state=console /> }
                                            .into_any()
                                    }
                                }}
                            </div>
                        </div>
                    </div>

                    // ── 右栏：daemon 此刻在说什么 ──────────────────────────
                    // ⚠️ **不能**做成一个标签。中栏按下一个按钮之后要立刻看到
                    // daemon 说了什么；把两者藏进互斥的标签里，就等于每做一步
                    // 都要来回切一次。旧面板把它独立成一栏是对的。
                    <div class="vd-logs">
                        <Pane title="日志">
                            <LogsPage state=logs />
                        </Pane>
                    </div>
                </div>
            </Layout>
        </ConfigProvider>
    }
}

/// 等一会儿。
///
/// ⚠️ 有一处非等不可：切换 eSIM profile 之后要给卡片 REFRESH 留 8 秒，然后才
/// 去问它。读得更早，问到的是还没走完的那个状态 —— 而这一栏的全部意义就是
/// **以回读为准**。
pub async fn sleep(ms: u64) {
    // 直接用浏览器的 setTimeout 包一个 Promise，不为这一处引 `futures`。
    let promise = js_sys::Promise::new(&mut |resolve, _reject| {
        if let Some(window) = web_sys::window() {
            let _ =
                window.set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, ms as i32);
        }
    });
    let _ = wasm_bindgen_futures::JsFuture::from(promise).await;
}

/// trunk's entry point.
#[wasm_bindgen::prelude::wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
    leptos::mount::mount_to_body(Panel);
}
