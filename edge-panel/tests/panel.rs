use std::sync::Arc;

use std::sync::Mutex;

use edge_panel::{
    router, router_with_actions, Actions, AtResult, CandidateClaimResult, LogRing, MemoryInbox,
    PanelError, ProfileBody, ProfilesResult, ReportResult, RescanResult, ScanResult,
    ScannedOperatorBody, UsbResetResult, UssdResult,
};
use edge_store::{LocalMessage, LocalModem, LocalModemDiscovery};
use http_body_util::BodyExt;
use tower::ServiceExt;

/// Fetch the panel page the way a browser would.
async fn panel_page() -> String {
    page_at("/").await
}

async fn page_at(path: &str) -> String {
    let app = router(Arc::new(MemoryInbox::default()));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .uri(path)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

/// Every `<name ...>` opening tag in the markup, as written.
fn opening_tags<'a>(markup: &'a str, name: &str) -> Vec<&'a str> {
    let needle = format!("<{name}");
    let mut found = Vec::new();
    let mut rest = markup;
    while let Some(start) = rest.find(&needle) {
        let tag = &rest[start..];
        let end = tag.find('>').map(|at| at + 1).unwrap_or(tag.len());
        found.push(&tag[..end]);
        rest = &tag[end..];
    }
    found
}

/// The panel must load nothing from anywhere.
///
/// It is served over the site LAN to a machine that may have no route to the
/// internet at all. A linked stylesheet or a CDN script is not a dependency
/// here, it is an outage: the operator standing next to a wedged modem would
/// get an unstyled page with no behaviour at exactly the moment the panel is
/// the only tool they have.
///
/// 🔴 **This is the first guard the migration had to rewrite rather than keep,
/// and what it gave up is written down here rather than discovered later.**
///
/// The single-file panel this replaced could satisfy a stricter rule — every
/// `<link>` is a `data:` URI, no `src=` anywhere — because it was one file
/// with nothing to fetch. A wasm panel cannot fit that: the bundle is 600 KB,
/// and base64 in the HTML would make the page a megabyte of text the browser
/// must parse before it can start. So the page fetches two things,
/// `edge-ui.js` and `edge-ui_bg.wasm`, from the `/next/` prefix those bundle
/// files still live under.
///
/// ⚠️ **What that costs.** The old panel makes *zero* requests once its HTML
/// arrives; this one makes two. They are same-origin, served by the very
/// process that just served the HTML, so the window where they can fail is
/// narrow — but it is not closed, and "narrow" is not "none". That is the
/// trade, made deliberately.
///
/// What is preserved is the property the original rule existed for: **nothing
/// comes from another host.** This panel is served over the site LAN to a
/// machine that may have no route to the internet at all; a CDN script here is
/// not a dependency, it is an outage at exactly the moment the panel is the
/// only tool the operator has.
///
/// So the rule becomes: every reference is either a `data:` URI or an absolute
/// same-origin path. A scheme, a host, or a protocol-relative `//` fails.
#[tokio::test]
async fn the_panel_loads_nothing_from_another_machine() {
    let page = panel_page().await;
    let markup = page.to_lowercase();

    // Not vacuous: this page really does carry the references being checked.
    let links = opening_tags(&markup, "link");
    assert!(
        links.len() >= 2,
        "no <link> tags found on /next, so the loop below is scanning air"
    );

    for tag in opening_tags(&markup, "script") {
        if let Some(src) = attribute(&tag, "src") {
            assert!(
                same_machine(&src),
                "script on /next loads from another host: {src}"
            );
        }
    }
    for tag in &links {
        let href = attribute(tag, "href").unwrap_or_default();
        assert!(
            same_machine(&href),
            "link on /next points at another host: {href}"
        );
    }

    assert!(!markup.contains("@import"), "css imports another sheet");
    assert!(
        !markup.contains("src=\"//"),
        "protocol-relative script source"
    );
    assert!(
        !markup.contains("href=\"//"),
        "protocol-relative link target"
    );

    let mut rest = markup.as_str();
    while let Some(at) = rest.find("url(") {
        let argument = rest[at + 4..].trim_start_matches(['"', '\'']);
        assert!(
            same_machine(argument),
            "a stylesheet on /next pulls a resource from another host"
        );
        rest = &rest[at + 4..];
    }
}

/// `/next` 引用的每一个 bundle 文件，这个进程都要真的能给出来。
///
/// 这条守的是一个**不出错误、只出黑屏**的失误：trunk 默认把 `/edge-ui.js`
/// 写成根路径，而路由挂在 `/next/` 下面。HTML 照样 200，wasm 404，页面一片
/// 漆黑，没有任何一处报错说明为什么。`edge-ui/Trunk.toml` 里的 `public_url`
/// 是修法，这条测试是安全网：构建方式退回默认，这里红。
#[tokio::test]
async fn the_panel_asks_for_its_own_bundle() {
    let page = panel_page().await;
    let markup = page.to_lowercase();

    let mut asked: Vec<String> = Vec::new();
    for tag in opening_tags(&markup, "script") {
        if let Some(src) = attribute(&tag, "src") {
            asked.push(src);
        }
    }
    for tag in opening_tags(&markup, "link") {
        let href = attribute(&tag, "href").unwrap_or_default();
        if href.ends_with(".js") || href.ends_with(".wasm") {
            asked.push(href);
        }
    }
    asked.retain(|u| !u.starts_with("data:"));

    // 非空地板：引用一个都没扫到的话，下面的循环是在检查空气。
    assert!(
        asked.len() >= 2,
        "/next 上没找到 js/wasm 引用，这条测试什么也没量到"
    );

    for url in &asked {
        assert!(
            url.starts_with("/next/"),
            "/next 去 {url} 取 bundle，可路由只挂在 /next/ 下面 —— \
             页面会 200 但一片漆黑。八成是 trunk 构建时没读到 edge-ui/Trunk.toml"
        );
        let status = router(Arc::new(MemoryInbox::default()))
            .oneshot(
                axum::http::Request::builder()
                    .uri(url.as_str())
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status();
        assert_eq!(status, 200, "/next 引用了 {url}，这个进程却给不出来");
    }
}

/// A reference that cannot leave this machine: an inline `data:` URI, or an
/// absolute path served by the same process.
///
/// ⚠️ Deliberately rejects anything with a scheme and anything starting `//`.
/// A relative path would also be same-origin, but nothing here emits one and
/// accepting them would make the rule harder to read than the thing it guards.
fn same_machine(reference: &str) -> bool {
    let reference = reference.trim();
    reference.starts_with("data:") || (reference.starts_with('/') && !reference.starts_with("//"))
}

/// One attribute's value out of an opening tag, if it has one.
fn attribute(tag: &str, name: &str) -> Option<String> {
    let needle = format!("{name}=\"");
    let at = tag.find(&needle)? + needle.len();
    let rest = &tag[at..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// 所有 `edge-ui`（`/next` 那个 Leptos 面板）的源文件。⚠️ `include_str!`
/// 是编译期常量，新增一个会调 `/api/*` 的模块却忘了加进这张表，这条测试量
/// 到的东西不会变多——所以每加一个新页面模块，先把它加进这张表。
/// ⚠️ **加了新模块要加进来。** 下面 `the_audit_sees_every_module_in_the_panel`
/// 拿 `lib.rs` 的 `mod` 数量对账，漏一个就红——这份名单在 2026-09-04 的盘点里
/// 被抓到漏了 `shell.rs`（后来又漏了 `trace.rs` 和 `copy.rs`）：**搬走了代码，
/// 守卫就瞎了**，而它不会报错，只是安静地少扫几个文件。
const PANEL_SOURCES: &[&str] = &[
    include_str!("../../edge-ui/src/lib.rs"),
    include_str!("../../edge-ui/src/api.rs"),
    include_str!("../../edge-ui/src/copy.rs"),
    include_str!("../../edge-ui/src/shell.rs"),
    include_str!("../../edge-ui/src/trace.rs"),
    include_str!("../../edge-ui/src/status.rs"),
    include_str!("../../edge-ui/src/health.rs"),
    include_str!("../../edge-ui/src/logs.rs"),
    include_str!("../../edge-ui/src/candidates.rs"),
    include_str!("../../edge-ui/src/sms.rs"),
    include_str!("../../edge-ui/src/scan.rs"),
    include_str!("../../edge-ui/src/console.rs"),
    include_str!("../../edge-ui/src/esim.rs"),
    include_str!("../../edge-ui/src/danger.rs"),
    include_str!("../../edge-ui/src/gate.rs"),
];

/// 剥掉 Rust 行注释。守卫要看的是代码，不是注释里的举例。
fn code_only(rust: &str) -> String {
    rust.lines()
        .map(|line| match line.find("//") {
            Some(i) => &line[..i],
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// 🔴 审计必须覆盖 `edge-ui` 的每一个模块。
///
/// 这份名单靠手写维护，而它守的两件事（端点覆盖、不许硬编码 URL）**漏扫一个
/// 文件不会报错，只会安静地少检查一些代码**。2026-09-04 的盘点抓到它漏了
/// `shell.rs`；补的时候发现 `trace.rs`、`copy.rs` 也在外面。
#[test]
fn the_audit_sees_every_module_in_the_panel() {
    let lib = include_str!("../../edge-ui/src/lib.rs");
    let declared = code_only(lib)
        .lines()
        .filter(|l| l.trim_start().starts_with("mod ") && l.trim_end().ends_with(';'))
        .count();
    assert_eq!(
        declared,
        PANEL_SOURCES.len() - 1,
        "edge-ui 声明了 {declared} 个模块，PANEL_SOURCES 收了 {}（含 lib.rs 自己）\
         —— 漏掉的那个文件里调了什么端点、有没有硬编码 URL，没有任何人在看",
        PANEL_SOURCES.len()
    );
}

/// 在一份 Rust 源码里找 `"/api/...` 这个形状的字符串字面量，问号之前那一段。
/// 覆盖两种写法：`api::get("/api/x", ...)` 和 `api::get(&format!("/api/x?...`。
fn panel_call_sites(code: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = code;
    while let Some(at) = rest.find("\"/api/") {
        let tail = &rest[at + 1..];
        let end = tail.find(['"', '{']).unwrap_or(tail.len());
        found.push(tail[..end].split('?').next().unwrap_or("").to_string());
        rest = &tail[end.max(1)..];
    }
    found
}

/// `/next` 那个 Leptos 面板版本的端点覆盖审计。
///
/// 和下面那条 `every_endpoint_the_panel_used_is_still_reachable_from_the_page`
/// 是同一件事的两份：旧面板扫 HTML/JS 源码字符串，这一条扫 Rust 源码字符串。
/// `/next` 完全覆盖旧面板的功能之后，旧那一条会连同 `index.html` 一起删掉，
/// 到时这一条是唯一还在守「页面调用的每个端点，daemon 都必须提供」这件事的。
///
/// 这条测试曾经因为 `/api/rescan` 被漏搬而应该红——写这条测试的时候顺手把
/// 那个缺口也补上了，所以现在看到的是绿。
#[tokio::test]
async fn every_endpoint_the_panel_calls_is_registered_on_the_router() {
    let sites: Vec<String> = PANEL_SOURCES
        .iter()
        .flat_map(|code| panel_call_sites(code))
        .collect();
    assert!(
        sites.len() >= 15,
        "只扫到 {} 处调用，比端点数还少——扫描已经失效",
        sites.len()
    );

    const KNOWN: &[&str] = &[
        "/api/status",
        "/api/logs",
        "/api/messages",
        "/api/send",
        "/api/at",
        "/api/report",
        "/api/esim",
        "/api/esim/switch",
        "/api/scan",
        "/api/ussd",
        "/api/ussd/cancel",
        "/api/radio",
        "/api/usb-reset",
        "/api/rescan",
        "/api/discoveries/claim",
        "/api/modems/register",
        "/api/modems/unregister",
    ];
    for endpoint in KNOWN {
        assert!(
            sites.iter().any(|path| path == endpoint),
            "/next 面板没有一处调用 {endpoint}：扫到的 {} 处是 {sites:?}",
            sites.len()
        );
    }

    // 反过来也要查：扫到的每一处调用都得是路由表上真的有的路径，否则某个
    // 操作员按下按钮的那一刻，答案是 404。
    for site in &sites {
        assert!(
            KNOWN.contains(&site.as_str()),
            "/next 面板调用了 {site}，但它不在已知端点表里——要么路由表没有\
             这一条，要么是上面 KNOWN 那张表没跟上"
        );
    }

    // 🔴 `/api/restart` 必须缺席——它在 `Actions` trait 上存在，但没有一个
    // `/next` 页面调用它。理由和旧面板那条一样：`panel.rs` 有测试钉住它不许
    // 在旧面板出现，`/next` 完全接管之后这一条守的是同一件事。
    assert!(
        !sites.iter().any(|s| s == "/api/restart"),
        "/next 面板出现了对 /api/restart 的调用——这个端点是刻意缺席的"
    );
}

/// 🔴 面板服务的目标机器可能没有出网路由。一个外部脚本、字体、样式表，
/// 不是「性能问题」——是一次故障：操作员在一根卡死的模组旁边打开这个页面，
/// 拿到的是一个没有样式、没有行为的空白页，而这正是这个面板唯一存在的理由。
///
/// 旧面板靠扫 HTML/JS 源码字符串守这条规则（`the_panel_asks_the_browser_for_
/// nothing_outside_the_page` 等四条，随 index.html 一起退休）。`/next` 没有
/// 那种源码可扫——trunk 把一切编译进 `edge-ui.js` 和 `.wasm`——所以这条测试
/// 换一种问法：扫已编译产物的**文本**部分（JS 胶水层可读，Rust 源码本来就是
/// 文本），wasm 二进制留给 `strings` 这类工具人工偶尔复核，不做成自动断言。
#[tokio::test]
async fn the_panel_carries_no_external_dependency() {
    // 编译产物真的有实质内容——防止「没有外部依赖」是靠「什么都没打包」
    // 侥幸满足的。
    let js = page_at("/next/edge-ui.js").await;
    assert!(
        js.len() > 10_000,
        "edge-ui.js 只有 {} 字节，框架看起来没有真的打包进去",
        js.len()
    );

    // JS 胶水层里不能有硬编码的外部主机。wasm-bindgen 生成的胶水偶尔会在
    // 注释里带一个文档链接，所以这里只查真正会被执行到的取值形状：
    // fetch(...)、new URL(...)、协议相对的 //host。
    for needle in [
        "fetch(\"http",
        "fetch('http",
        "new URL(\"http",
        "src=\"//",
        "href=\"//",
    ] {
        assert!(
            !js.contains(needle),
            "edge-ui.js 里有一处看起来会连到外部主机的调用：{needle}"
        );
    }

    // 我们自己写的 Rust 源码。零容忍：这段代码从一开始就不该有硬编码的
    // 网络地址——本机地址走的是相对路径 `/api/...`，不需要拼主机名。
    //
    // ⚠️ **先剥注释。** 守卫要管的是代码，不是散文。`copy.rs` 的文档里正当地
    //    引用了 `http://<lan-ip>:8743` 来解释「那不是安全上下文、所以
    //    `navigator.clipboard` 不存在」——把这种解释判成违规，只会逼下一个人
    //    把该写的理由删掉。这个仓库已经因为「守卫扫到了注释」踩过两次。
    for code in PANEL_SOURCES {
        let code = code_only(code);
        assert!(
            !code.contains("http://") && !code.contains("https://"),
            "edge-ui 的 Rust 源码里出现了一处硬编码的 URL"
        );
    }
}

/// The process-wide log ring is shared by every test in this binary, so the two
/// tests that write to it take turns. Without this, the six hundred lines one
/// of them pushes evict the single line the other is looking for.
static LOG_RING_TURN: Mutex<()> = Mutex::new(());

/// Read the panel's `/api/logs` the way the column does.
async fn read_logs(after: u64) -> serde_json::Value {
    let app = router(Arc::new(MemoryInbox::default()));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .uri(format!("/api/logs?after={after}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

/// The premise the whole log column rests on: a served line carries a sequence
/// number, a timestamp and text, and nothing else.
///
/// `log_line` and `log_error` push into the same ring and the distinction is
/// dropped there, so severity, which module a line is about and which endpoint
/// produced it are all absent from the wire. The column therefore infers them
/// from the text. If this ever stops being true — if `logs.rs` grows a `level`
/// — this test fails and says so, which is the signal to delete the guessing
/// rather than to leave two sources of truth disagreeing.
#[tokio::test]
async fn a_served_log_line_carries_no_level_module_or_endpoint() {
    let _turn = LOG_RING_TURN
        .lock()
        .unwrap_or_else(|held| held.into_inner());
    let marker = "panel-test-marker line for the shape assertion";
    LogRing::global().push(marker);

    let body = read_logs(0).await;
    let line = body["lines"]
        .as_array()
        .expect("lines")
        .iter()
        .find(|line| line["text"] == marker)
        .expect("the line just pushed is not in the ring");

    let mut fields: Vec<&str> = line
        .as_object()
        .expect("a line is an object")
        .keys()
        .map(String::as_str)
        .collect();
    fields.sort_unstable();
    assert_eq!(
        fields,
        ["at", "seq", "text"],
        "the served shape changed; the column's inferred level/module/source \
         should be replaced by the real field instead of layered on top"
    );
}

#[tokio::test]
async fn panel_serves_embedded_html_and_local_json() {
    let inbox = Arc::new(MemoryInbox {
        messages: vec![LocalMessage {
            seq: 1,
            peer: "10086".into(),
            body: "hello".into(),
            bearer: "cellular".into(),
            direction: "inbound".into(),
            received_at: 1_700_000_000_000,
            modem_imei: Some("867018069509705".into()),
        }],
        modems: vec![LocalModem {
            imei: "867018069509705".into(),
            family: "EC20".into(),
            firmware: None,
            msisdn: None,
            msisdn_iccid: None,
            apn_contexts: None,
            iccid: None,
            state: "registered".into(),
            last_seen: Some(1_700_000_000_000),
            mcc: Some(460),
            mnc: Some(0),
            home_mcc: None,
            home_mnc: None,
            imsi: None,
            discovery: "qmi".into(),
            manageable: true,
            control_port: Some("/dev/cdc-wdm0".into()),
        }],
        discoveries: vec![LocalModemDiscovery {
            candidate_key: "qmi:usb:2-4.1".into(),
            usb_device: Some("2-4.1".into()),
            transport: "qmi".into(),
            control_port: "/dev/cdc-wdm1".into(),
            vendor_id: Some("2c7c".into()),
            product_id: Some("0125".into()),
            state: "probe_failed".into(),
            imei: None,
            detail: "POLLERR".into(),
            last_seen: 1_700_000_000_000,
        }],
    });
    let app = router(inbox);

    let html = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(html.status(), 200);
    let page = String::from_utf8(
        html.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    // 这条测的是路由服务了这个页面、并且两个本地读接口能答对下面两次请求。
    // ⚠️ CSR（客户端渲染）之后，这里能查的只有初始外壳——真正的表格、按钮、
    // 命令框都是 wasm 在浏览器里跑起来之后才画出来的，这次 HTTP 往返看不到
    // 它们。所以这里只查外壳自己该有的两样东西：确实是那份 HTML，而且
    // 确实接了启动 wasm 的那段脚本。「页面真的把每个端点都调用到了」由
    // `every_endpoint_the_panel_calls_is_registered_on_the_router`
    // 去扫 Rust 源码守，这里不重复扫一遍。
    assert!(
        page.to_lowercase().contains("<!doctype html>"),
        "served page is not html at all"
    );
    assert!(
        page.contains("edge-ui_bg.wasm"),
        "the page does not wire up the wasm bundle that mounts the panel"
    );

    let status = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/api/status")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(status.status(), 200);
    let status_json: serde_json::Value =
        serde_json::from_slice(&status.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(status_json["mode"], "local");
    assert_eq!(status_json["modems"][0]["family"], "EC20");
    assert_eq!(status_json["modems"][0]["discovery"], "qmi");
    assert_eq!(status_json["modems"][0]["manageable"], true);
    assert_eq!(status_json["discoveries"][0]["state"], "probe_failed");
    assert_eq!(status_json["discoveries"][0]["detail"], "POLLERR");

    let messages = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/api/messages")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let inbox_json: serde_json::Value =
        serde_json::from_slice(&messages.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(inbox_json["messages"][0]["body"], "hello");
}

/// A modem reports `fallback` only when the matrix has no entry for its
/// (family, carrier) pair -- the pair the agent itself looks up.
///
/// This is what decides whether a human is interrupted, so the two ways of
/// being wrong both matter. A recognised family is not enough: `UFI103S` is a
/// `ModemFamily` variant with no rules in the built-in matrix. And a rule that
/// says `probe` is still a rule: `EC20` outside China resolves to
/// `Generic-International`, which somebody characterised as "find out", and
/// that is a decision rather than an open question.
#[tokio::test]
async fn a_modem_says_whether_the_matrix_has_heard_of_its_combination() {
    fn modem(imei: &str, family: &str, home_mcc: u16, home_mnc: u16) -> LocalModem {
        LocalModem {
            imei: imei.into(),
            family: family.into(),
            firmware: None,
            msisdn: None,
            msisdn_iccid: None,
            apn_contexts: None,
            iccid: None,
            state: "registered".into(),
            last_seen: Some(1_700_000_000_000),
            mcc: Some(home_mcc),
            mnc: Some(home_mnc),
            home_mcc: Some(home_mcc),
            home_mnc: Some(home_mnc),
            imsi: None,
            discovery: "qmi".into(),
            manageable: true,
            control_port: Some("/dev/cdc-wdm0".into()),
        }
    }

    let app = router(Arc::new(MemoryInbox {
        modems: vec![
            // Measured on the bench and carried in the built-in matrix.
            modem("867018069509705", "EC20", 460, 0),
            // Also a rule, and one that says probe: outside China every
            // carrier resolves to Generic-International, which EC20 has an
            // entry for. Not an open question, so not a badge.
            modem("867018069514820", "EC20", 310, 260),
            // A recognised family with no rules at all in the matrix.
            modem("862547055142811", "UFI103S", 460, 0),
            // Hardware the matrix has never heard of.
            modem("867018069509706", "SIM7600G", 460, 0),
        ],
        ..MemoryInbox::default()
    }));

    let status = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/api/status")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(status.status(), 200);
    let body: serde_json::Value =
        serde_json::from_slice(&status.into_body().collect().await.unwrap().to_bytes()).unwrap();

    assert_eq!(body["modems"][0]["capability_origin"], "rule");
    assert_eq!(body["modems"][0]["carrier_profile"], "CN-Mobile");

    assert_eq!(
        body["modems"][1]["capability_origin"], "rule",
        "a rule that says probe is still a rule and must not raise a flag"
    );
    assert_eq!(
        body["modems"][1]["carrier_profile"],
        "Generic-International"
    );

    assert_eq!(
        body["modems"][2]["capability_origin"], "fallback",
        "a recognised family with no rules is exactly the case worth reporting"
    );

    assert_eq!(body["modems"][3]["capability_origin"], "fallback");
    // The pair a new rule has to be keyed on has to survive to the operator.
    assert_eq!(body["modems"][3]["family"], "SIM7600G");
    assert_eq!(body["modems"][3]["carrier_profile"], "CN-Mobile");
}

/// ⚠️ 那几条「会写」的记录里都带着 `Option<String>` 的 IMEI，是为了让回执测试
/// 能问一个别的地方问不到的问题：**回执上写的那一根，是不是就是真正打到
/// `Actions` 上的那一根**。只记方向的话，一个把 IMEI 弄丢或者自己编一个出来的
/// handler 照样能让测试全绿。
struct RecordingActions {
    sent: Mutex<Vec<(String, String)>>,
    at: Mutex<Vec<String>>,
    switched: Mutex<Vec<(Option<String>, String, bool)>>,
    ussd: Mutex<Vec<String>>,
    cancelled: Mutex<Vec<Option<String>>>,
    radio: Mutex<Vec<(Option<String>, bool)>>,
    restarted: Mutex<Vec<String>>,
    rescans: Mutex<usize>,
    claims: Mutex<Vec<String>>,
}

impl RecordingActions {
    fn new() -> Self {
        Self {
            sent: Mutex::new(Vec::new()),
            at: Mutex::new(Vec::new()),
            switched: Mutex::new(Vec::new()),
            ussd: Mutex::new(Vec::new()),
            cancelled: Mutex::new(Vec::new()),
            radio: Mutex::new(Vec::new()),
            restarted: Mutex::new(Vec::new()),
            rescans: Mutex::new(0),
            claims: Mutex::new(Vec::new()),
        }
    }
}

impl Actions for RecordingActions {
    fn rescan_modems(&self) -> Result<RescanResult, PanelError> {
        *self.rescans.lock().expect("rescans") += 1;
        Ok(RescanResult {
            found: 2,
            control_ports: vec!["/dev/cdc-wdm0".into(), "/dev/ttyUSB8".into()],
        })
    }

    fn claim_modem_candidate(
        &self,
        candidate_key: String,
    ) -> Result<CandidateClaimResult, PanelError> {
        self.claims
            .lock()
            .expect("claims")
            .push(candidate_key.clone());
        Ok(CandidateClaimResult { candidate_key })
    }

    fn send_sms(
        &self,
        to: String,
        body: String,
        _imei: Option<String>,
        _commission: bool,
    ) -> Result<(), PanelError> {
        self.sent.lock().expect("sent").push((to, body));
        Ok(())
    }

    fn restart_modem(&self, imei: String) -> Result<(), PanelError> {
        self.restarted.lock().expect("restarted").push(imei);
        Ok(())
    }

    fn at_command(
        &self,
        _imei: Option<String>,
        command: String,
        _force: bool,
    ) -> Result<AtResult, PanelError> {
        self.at.lock().expect("at").push(command.clone());
        Ok(AtResult {
            port: "/dev/ttyUSB2".into(),
            command,
            lines: vec!["+CSQ: 24,99".into()],
            terminator: "OK".into(),
            ok: true,
            elapsed_ms: 7,
        })
    }

    fn usb_reset(&self, _imei: Option<String>) -> Result<UsbResetResult, PanelError> {
        Ok(UsbResetResult {
            device: "2-4.1".into(),
            node: "/dev/bus/usb/002/052".into(),
        })
    }

    fn modem_report(&self, imei: Option<String>) -> Result<ReportResult, PanelError> {
        Ok(ReportResult {
            imei,
            port: "/dev/ttyUSB2".into(),
            signal_dbm: Some(-65),
            operator: Some("CHN-UNICOM".into()),
            ..ReportResult::default()
        })
    }

    fn list_profiles(&self, imei: Option<String>) -> Result<ProfilesResult, PanelError> {
        Ok(ProfilesResult {
            imei,
            profiles: vec![ProfileBody {
                iccid: "89852351225042214201".into(),
                label: "WEBBING".into(),
                enabled: true,
                provider: Some("Saily".into()),
                name: Some("WEBBING".into()),
                nickname: None,
                class: Some(2),
                isdp_aid: None,
            }],
        })
    }

    fn switch_profile(
        &self,
        imei: Option<String>,
        iccid: String,
        enable: bool,
    ) -> Result<(), PanelError> {
        self.switched
            .lock()
            .expect("switched")
            .push((imei, iccid, enable));
        Ok(())
    }

    fn scan_operators(&self, imei: Option<String>) -> Result<ScanResult, PanelError> {
        Ok(ScanResult {
            imei,
            elapsed_ms: 42_000,
            operators: vec![ScannedOperatorBody {
                numeric: "46001".into(),
                long_name: "CHN-UNICOM".into(),
                short_name: "UNICOM".into(),
                status: "current".into(),
                access_technology: Some("LTE".into()),
            }],
        })
    }

    fn ussd(&self, _imei: Option<String>, code: String) -> Result<UssdResult, PanelError> {
        self.ussd.lock().expect("ussd").push(code.clone());
        Ok(UssdResult {
            code,
            stage: "complete".into(),
            text: "余额 12.30".into(),
            dcs: Some(72),
            expects_reply: false,
            elapsed_ms: 3200,
        })
    }

    fn ussd_cancel(&self, imei: Option<String>) -> Result<(), PanelError> {
        self.cancelled.lock().expect("cancelled").push(imei);
        Ok(())
    }

    fn set_radio(&self, imei: Option<String>, online: bool) -> Result<(), PanelError> {
        self.radio.lock().expect("radio").push((imei, online));
        Ok(())
    }
}

#[tokio::test]
async fn panel_sends_sms_locally() {
    let actions = Arc::new(RecordingActions::new());
    let app = router_with_actions(Arc::new(MemoryInbox::default()), Some(actions.clone()));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/send")
                .header("content-type", "application/json")
                // ⚠️ 指名了模组。这条测试原先不带 `imei`，而现在不指名模组是要
                // 被拒的 —— 代理在没有 IMEI 时会取 modem map 里的第一条，本机有
                // 模组在封禁表里（见 `an_unnamed_send_cannot_be_used_to_reach_a_
                // blocked_modem`）。这条测试要问的是「面板会不会把发送转给本地
                // actions」，指名一根没被封的模组之后，问的还是同一件事。
                .body(axum::body::Body::from(
                    r#"{"to":"10086","body":"hi","imei":"860000000000001"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        actions.sent.lock().expect("sent").as_slice(),
        &[("10086".into(), "hi".into())]
    );
}

#[tokio::test]
async fn panel_requests_an_immediate_modem_rescan() {
    let actions = Arc::new(RecordingActions::new());
    let app = router_with_actions(Arc::new(MemoryInbox::default()), Some(actions.clone()));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/rescan")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["status"], "requested");
    assert_eq!(body["found"], 2);
    assert_eq!(body["control_ports"][1], "/dev/ttyUSB8");
    assert_eq!(*actions.rescans.lock().expect("rescans"), 1);
}

/// 发一条短信，返回 (状态码, 响应体)。
/// 用一份**注入的**封禁表发一次。
///
/// 🔴 生产表在 2026-09-04 之后是空的（见 `edge_core::sms_block` 的模块开头）。
/// 而这道门是真正拦 `curl` 的地方 —— 表一空，它的接线在 HTTP 层面就一条测试
/// 都覆盖不到了。所以这几条用 `SAMPLE_BLOCKS` 跑：测的是**门还在不在**，
/// 不是「表里恰好有谁」。
async fn post_send_blocked(payload: &str) -> (u16, serde_json::Value) {
    post_send_in(payload, edge_core::SAMPLE_BLOCKS).await
}

async fn post_send_in(
    payload: &str,
    blocks: &'static [(&'static str, edge_core::SmsBlock)],
) -> (u16, serde_json::Value) {
    let actions = Arc::new(RecordingActions::new());
    let app = edge_panel::router_with_blocks(
        Arc::new(MemoryInbox::default()),
        Some(actions.clone()),
        blocks,
    );
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/send")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, body)
}

async fn post_send(payload: &str) -> (u16, serde_json::Value) {
    let actions = Arc::new(RecordingActions::new());
    let app = router_with_actions(Arc::new(MemoryInbox::default()), Some(actions.clone()));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/send")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status().as_u16();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, body)
}

/// 🔴 封禁表必须在**服务端**生效，不能只在浏览器里。
///
/// 表里记的是实测出来的硬件事实：那一根每一次 MO 短信提交都会掉出 USB 总线
/// 几十秒。一个只活在 JS/wasm 里的拦截，对一个 `curl` 毫无作用。
#[tokio::test]
async fn a_blocked_modem_cannot_be_made_to_send_by_curl() {
    let imei = edge_core::SAMPLE_BLOCKS[0].0;
    let (status, body) =
        post_send_blocked(&format!(r#"{{"to":"12345","body":"hi","imei":"{imei}"}}"#)).await;
    assert_eq!(status, 403, "被封禁的模组必须被拒");
    let error = body["error"].as_str().unwrap_or_default();
    assert!(error.contains(imei), "要指名是哪一根：{error}");
    assert!(
        error.contains("总线") || error.contains("bus") || error.contains("QMI"),
        "要说清为什么，而不是只说不许：{error}"
    );
}

/// 🔴 生产表现在是空的 —— 那道门不该再拦任何人。
///
/// 上面那条测的是「门还在」，这条测的是「门现在是开的」。两件事要分开，
/// 否则谁往表里悄悄加一条，屏幕上没有任何地方会说。
#[tokio::test]
async fn with_the_production_table_empty_nobody_is_refused() {
    let (status, _) = post_send_in(
        r#"{"to":"12345","body":"hi","imei":"867018069509705"}"#,
        edge_core::sms_blocks(),
    )
    .await;
    assert_eq!(
        status, 200,
        "867018069509705 在 2026-09-04 解除了 —— 见 edge_core::sms_block 模块开头"
    );
}

/// 不指名模组同样要拒 —— 否则上面那条检查绕一下就没了。
///
/// 代理在没有 IMEI 时会取 modem map 里的第一条，本机只要有一根被封，
/// `curl -d '{"to":"x","body":"y"}'` 就可能打中它。
#[tokio::test]
async fn an_unnamed_send_cannot_be_used_to_reach_a_blocked_modem() {
    let (status, body) = post_send_blocked(r#"{"to":"12345","body":"hi"}"#).await;
    assert_eq!(status, 403);
    let error = body["error"].as_str().unwrap_or_default();
    assert!(
        error.contains("imei is required"),
        "要说清缺的是什么：{error}"
    );
}

/// `commission` 是唯一的越过路径，而且必须真的越得过 —— 封禁表本身就是这样
/// 量出来的，复测做不到的话这张表就再也无法被修正。
#[tokio::test]
async fn commissioning_is_the_one_way_past_the_block() {
    let imei = edge_core::SAMPLE_BLOCKS[0].0;
    let (status, _) = post_send_blocked(&format!(
        r#"{{"to":"12345","body":"hi","imei":"{imei}","commission":true}}"#
    ))
    .await;
    assert_eq!(status, 200, "明确写了 commission 就该放行");

    let (status, _) = post_send_blocked(r#"{"to":"12345","body":"hi","commission":true}"#).await;
    assert_eq!(status, 200, "commission 也越过「必须指名」这一条");
}

/// 没被封的模组照常能发 —— 别把拦截写成了拦所有人。
#[tokio::test]
async fn an_ordinary_modem_still_sends() {
    let (status, _) = post_send(r#"{"to":"12345","body":"hi","imei":"860000000000001"}"#).await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn panel_claims_only_a_discovery_key() {
    let actions = Arc::new(RecordingActions::new());
    let app = router_with_actions(Arc::new(MemoryInbox::default()), Some(actions.clone()));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/discoveries/claim")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"candidate_key":"serial:usb:2-4.2:port:/dev/ttyUSB8"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["status"], "claimed");
    assert_eq!(
        actions.claims.lock().expect("claims").as_slice(),
        &["serial:usb:2-4.2:port:/dev/ttyUSB8"]
    );
}

#[tokio::test]
async fn panel_rejects_an_empty_discovery_claim() {
    let actions = Arc::new(RecordingActions::new());
    let app = router_with_actions(Arc::new(MemoryInbox::default()), Some(actions.clone()));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/discoveries/claim")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"candidate_key":"  "}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    assert!(actions.claims.lock().expect("claims").is_empty());
}

#[tokio::test]
async fn panel_runs_an_at_command() {
    let actions = Arc::new(RecordingActions::new());
    let app = router_with_actions(Arc::new(MemoryInbox::default()), Some(actions.clone()));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/at")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"command":"AT+CSQ"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["terminator"], "OK");
    assert_eq!(body["lines"][0], "+CSQ: 24,99");
    assert_eq!(actions.at.lock().expect("at").as_slice(), &["AT+CSQ"]);
}

/// A module that answers `+CME ERROR` has answered. The console must show that
/// as the module's reply, not as a transport failure.
#[tokio::test]
async fn panel_reports_a_rejected_at_command_as_a_reply() {
    struct Rejecting;
    impl Actions for Rejecting {
        fn send_sms(
            &self,
            _: String,
            _: String,
            _: Option<String>,
            _commission: bool,
        ) -> Result<(), PanelError> {
            Ok(())
        }
        fn restart_modem(&self, _: String) -> Result<(), PanelError> {
            Ok(())
        }
        fn at_command(
            &self,
            _: Option<String>,
            command: String,
            _force: bool,
        ) -> Result<AtResult, PanelError> {
            Ok(AtResult {
                port: "/dev/ttyUSB2".into(),
                command,
                lines: Vec::new(),
                terminator: "+CME ERROR: 10".into(),
                ok: false,
                elapsed_ms: 3,
            })
        }

        fn usb_reset(&self, _imei: Option<String>) -> Result<UsbResetResult, PanelError> {
            Ok(UsbResetResult {
                device: "2-4.1".into(),
                node: "/dev/bus/usb/002/052".into(),
            })
        }

        fn modem_report(&self, _: Option<String>) -> Result<ReportResult, PanelError> {
            Ok(ReportResult::default())
        }

        fn list_profiles(&self, imei: Option<String>) -> Result<ProfilesResult, PanelError> {
            Ok(ProfilesResult {
                imei,
                profiles: Vec::new(),
            })
        }

        fn switch_profile(&self, _: Option<String>, _: String, _: bool) -> Result<(), PanelError> {
            Ok(())
        }

        fn scan_operators(&self, imei: Option<String>) -> Result<ScanResult, PanelError> {
            Ok(ScanResult {
                imei,
                elapsed_ms: 0,
                operators: Vec::new(),
            })
        }

        fn ussd(&self, _: Option<String>, code: String) -> Result<UssdResult, PanelError> {
            Ok(UssdResult {
                code,
                stage: "complete".into(),
                text: String::new(),
                dcs: None,
                expects_reply: false,
                elapsed_ms: 0,
            })
        }

        fn ussd_cancel(&self, _: Option<String>) -> Result<(), PanelError> {
            Ok(())
        }
        fn set_radio(&self, _: Option<String>, _: bool) -> Result<(), PanelError> {
            Ok(())
        }
    }

    let app = router_with_actions(Arc::new(MemoryInbox::default()), Some(Arc::new(Rejecting)));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/at")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"command":"AT+CPIN?"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["ok"], false);
    assert_eq!(body["terminator"], "+CME ERROR: 10");
}

#[tokio::test]
async fn panel_rejects_an_empty_at_command() {
    let actions = Arc::new(RecordingActions::new());
    let app = router_with_actions(Arc::new(MemoryInbox::default()), Some(actions.clone()));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/at")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"command":"   "}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    assert!(actions.at.lock().expect("at").is_empty());
}

#[tokio::test]
async fn panel_reports_modem_diagnostics() {
    let actions = Arc::new(RecordingActions::new());
    let app = router_with_actions(Arc::new(MemoryInbox::default()), Some(actions.clone()));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/report")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"imei":"867018069514820"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["imei"], "867018069514820");
    assert_eq!(body["signal_dbm"], -65);
    assert_eq!(body["operator"], "CHN-UNICOM");
}

#[tokio::test]
async fn panel_lists_euicc_profiles() {
    let actions = Arc::new(RecordingActions::new());
    let app = router_with_actions(Arc::new(MemoryInbox::default()), Some(actions.clone()));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/esim")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"imei":"867018069514820"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["profiles"][0]["label"], "WEBBING");
    assert_eq!(body["profiles"][0]["enabled"], true);
}

#[tokio::test]
async fn panel_switches_a_profile_by_iccid() {
    let actions = Arc::new(RecordingActions::new());
    let app = router_with_actions(Arc::new(MemoryInbox::default()), Some(actions.clone()));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/esim/switch")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"iccid":"89852351225042214201","enable":true}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        actions.switched.lock().expect("switched").as_slice(),
        &[(None, "89852351225042214201".to_string(), true)]
    );
}

/// Switching takes the modem off its network, so an unnamed profile must be
/// refused rather than guessed at.
#[tokio::test]
async fn panel_refuses_a_switch_without_an_iccid() {
    let actions = Arc::new(RecordingActions::new());
    let app = router_with_actions(Arc::new(MemoryInbox::default()), Some(actions.clone()));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/esim/switch")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"iccid":"  ","enable":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    assert!(actions.switched.lock().expect("switched").is_empty());
}

#[tokio::test]
async fn panel_scans_for_operators() {
    let actions = Arc::new(RecordingActions::new());
    let app = router_with_actions(Arc::new(MemoryInbox::default()), Some(actions.clone()));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/scan")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"imei":"867018069514820"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["operators"][0]["numeric"], "46001");
    assert_eq!(body["operators"][0]["status"], "current");
}

/// A modem mid-scan stops answering the poll loop for longer than the
/// staleness window. Reporting that as offline sends the operator looking for
/// a fault that is not there.
#[tokio::test]
async fn panel_reports_a_busy_modem_as_busy_not_offline() {
    struct Busy;
    impl Actions for Busy {
        fn send_sms(
            &self,
            _: String,
            _: String,
            _: Option<String>,
            _commission: bool,
        ) -> Result<(), PanelError> {
            Ok(())
        }
        fn restart_modem(&self, _: String) -> Result<(), PanelError> {
            Ok(())
        }
        fn at_command(
            &self,
            _: Option<String>,
            command: String,
            _force: bool,
        ) -> Result<AtResult, PanelError> {
            Ok(AtResult {
                port: "/dev/ttyUSB2".into(),
                command,
                lines: Vec::new(),
                terminator: "OK".into(),
                ok: true,
                elapsed_ms: 1,
            })
        }
        fn usb_reset(&self, _: Option<String>) -> Result<UsbResetResult, PanelError> {
            Ok(UsbResetResult {
                device: "2-4.1".into(),
                node: "/dev/bus/usb/002/052".into(),
            })
        }
        fn modem_report(&self, _: Option<String>) -> Result<ReportResult, PanelError> {
            Ok(ReportResult::default())
        }
        fn list_profiles(&self, imei: Option<String>) -> Result<ProfilesResult, PanelError> {
            Ok(ProfilesResult {
                imei,
                profiles: Vec::new(),
            })
        }
        fn switch_profile(&self, _: Option<String>, _: String, _: bool) -> Result<(), PanelError> {
            Ok(())
        }
        fn scan_operators(&self, imei: Option<String>) -> Result<ScanResult, PanelError> {
            Ok(ScanResult {
                imei,
                elapsed_ms: 0,
                operators: Vec::new(),
            })
        }
        fn ussd(&self, _: Option<String>, code: String) -> Result<UssdResult, PanelError> {
            Ok(UssdResult {
                code,
                stage: "complete".into(),
                text: String::new(),
                dcs: None,
                expects_reply: false,
                elapsed_ms: 0,
            })
        }

        fn ussd_cancel(&self, _: Option<String>) -> Result<(), PanelError> {
            Ok(())
        }
        fn set_radio(&self, _: Option<String>, _: bool) -> Result<(), PanelError> {
            Ok(())
        }

        fn busy_modems(&self) -> Vec<String> {
            vec!["867018069509705".into()]
        }
    }

    // last_seen far in the past, so without the busy marker this is "Offline".
    let inbox = Arc::new(MemoryInbox {
        messages: Vec::new(),
        modems: vec![LocalModem {
            imei: "867018069509705".into(),
            family: "EC20".into(),
            firmware: None,
            msisdn: None,
            msisdn_iccid: None,
            apn_contexts: None,
            iccid: None,
            state: "Registered".into(),
            last_seen: Some(1_700_000_000_000),
            mcc: None,
            mnc: None,
            home_mcc: None,
            home_mnc: None,
            imsi: None,
            discovery: "qmi".into(),
            manageable: true,
            control_port: Some("/dev/cdc-wdm0".into()),
        }],
        discoveries: Vec::new(),
    });
    let app = router_with_actions(inbox, Some(Arc::new(Busy)));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/api/status")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["modems"][0]["state"], "Busy");
}

#[tokio::test]
async fn panel_runs_a_ussd_session() {
    let actions = Arc::new(RecordingActions::new());
    let app = router_with_actions(Arc::new(MemoryInbox::default()), Some(actions.clone()));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/ussd")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"code":"*100#"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["text"], "余额 12.30");
    assert_eq!(body["expects_reply"], false);
    assert_eq!(actions.ussd.lock().expect("ussd").as_slice(), &["*100#"]);
}

#[tokio::test]
async fn panel_rejects_an_empty_ussd_code() {
    let actions = Arc::new(RecordingActions::new());
    let app = router_with_actions(Arc::new(MemoryInbox::default()), Some(actions.clone()));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/ussd")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"code":"  "}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    assert!(actions.ussd.lock().expect("ussd").is_empty());
}

/* ── 「会写」端点的回执 ──────────────────────────────────────────────
 *
 * `/api/radio`、`/api/ussd/cancel`、`/api/esim/switch`、`/api/restart` 四条
 * 以前是 handler 用 `serde_json::json!` 现拼 `{"status": ...}` 回的，那个字段
 * 在任何类型里都不存在。下面这几条测试守两件事：线上那个 `status` 字面量
 * 一个都没变（浏览器那半边收 `serde_json::Value`，读的就是它），以及回执上
 * 写的那一根确实是打到 `Actions` 上的那一根。
 */

/// POST 一条 JSON，回 (状态码, 响应体)。
async fn post_json(
    actions: Arc<RecordingActions>,
    uri: &str,
    payload: &str,
) -> (u16, serde_json::Value) {
    let app = router_with_actions(Arc::new(MemoryInbox::default()), Some(actions));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status().as_u16();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&body).unwrap())
}

/// 🔴 这一条守的是一次**安静的**回归。浏览器那半边这四条收的都是
/// `Load<serde_json::Value>`，靠 `status` 认结果；换成结构体的时候只要哪个
/// 字面量写错，前端不会报错，它会照常渲染而那一格永远是空的。
///
/// 四条一起写在一个测试里，是因为它们守的是同一件事，而且失败信息里带着
/// 端点名——哪一条断了一眼能看见。
#[tokio::test]
async fn the_four_writing_endpoints_still_answer_with_the_status_word_they_always_did() {
    for (uri, payload, expected) in [
        (
            "/api/radio",
            r#"{"online":true,"imei":"867018069514820"}"#,
            "ok",
        ),
        (
            "/api/ussd/cancel",
            r#"{"imei":"867018069514820"}"#,
            "cancelled",
        ),
        (
            "/api/esim/switch",
            r#"{"iccid":"89852351225042214201","enable":true}"#,
            "ok",
        ),
        ("/api/restart", r#"{"imei":"867018069514820"}"#, "restarted"),
    ] {
        let (code, body) = post_json(Arc::new(RecordingActions::new()), uri, payload).await;
        assert_eq!(code, 200, "{uri} 没有回 200");
        assert_eq!(
            body["status"], expected,
            "{uri} 的 status 变了：浏览器读的就是这个字段，改掉它前端会安静地变空"
        );
    }
}

/// 回执上的 IMEI 必须是**真正打到硬件上**的那一个。
///
/// 🔴 这批模组没有人能物理接触。一条把脱网操作记到错模组头上的回执，会让人
/// 去救错的那一根——所以这里不只是问「回执里有没有 imei」，而是拿它和
/// `Actions` 收到的那个值对。
#[tokio::test]
async fn a_radio_receipt_names_the_modem_that_was_actually_taken_down() {
    let actions = Arc::new(RecordingActions::new());
    let (code, body) = post_json(
        actions.clone(),
        "/api/radio",
        r#"{"online":false,"imei":"867018069514820"}"#,
    )
    .await;
    assert_eq!(code, 200);
    assert_eq!(
        actions.radio.lock().expect("radio").as_slice(),
        &[(Some("867018069514820".to_string()), false)]
    );
    assert_eq!(body["imei"], "867018069514820");
    // 方向回的是**请求的**方向。射频真的到位要几十秒，这个端点不回读，
    // 所以字段名是 `requested_online` 而不是 `online`。
    assert_eq!(body["requested_online"], false);
}

/// 🔴 不点名不是「所有模组」，是「不知道是哪一根」：代理这时取的是它 modem
/// map 里的第一条。回执把 `null` 原样带回去，而不是编一个 IMEI 出来——
/// 编出来的那个会被当成事实。
#[tokio::test]
async fn an_unnamed_radio_request_comes_back_unnamed_rather_than_guessed_at() {
    let actions = Arc::new(RecordingActions::new());
    let (code, body) = post_json(actions.clone(), "/api/radio", r#"{"online":true}"#).await;
    assert_eq!(code, 200);
    assert_eq!(
        actions.radio.lock().expect("radio").as_slice(),
        &[(None, true)]
    );
    assert!(
        body["imei"].is_null(),
        "不点名的射频请求回了一个 IMEI：{body}"
    );
}

/// 🔴 **这条端点的 ok 是面板明文规定不采信的那一个。** 它在没发生的切换上回过
/// ok，也在发生了的切换上回过 error。所以这个回执必须**说不出**「卡换了」：
/// `seen` 是回读出来的状态，而这条路上根本没有回读，只能是 `null`。
///
/// 谁哪天让它变成 `true`，必须是因为服务端真加了回读，而不是因为顺手。
#[tokio::test]
async fn a_switch_receipt_never_claims_the_card_did_what_was_asked() {
    let actions = Arc::new(RecordingActions::new());
    let (code, body) = post_json(
        actions.clone(),
        "/api/esim/switch",
        r#"{"iccid":"89852351225042214201","enable":true,"imei":"867018069514820"}"#,
    )
    .await;
    assert_eq!(code, 200);
    assert!(
        body.get("seen").is_some_and(|seen| seen.is_null()),
        "切换回执声称知道卡现在的状态：{body}"
    );
    // 该带的三件事：哪根、哪条 ICCID、往哪个方向。少一件，操作员就没法把
    // 这张回执和自己刚按的那个按钮对上。
    assert_eq!(body["imei"], "867018069514820");
    assert_eq!(body["iccid"], "89852351225042214201");
    assert_eq!(body["requested_enable"], true);
    assert_eq!(
        actions.switched.lock().expect("switched").as_slice(),
        &[(
            Some("867018069514820".to_string()),
            "89852351225042214201".to_string(),
            true
        )]
    );
}

/// 回执自己要说得出下一步。模组卡死的时候手上常常只剩 `curl`——那时候
/// 「等 8 秒、读 /api/esim」写在 wasm 里是够不着的。
///
/// ⚠️ 回读目标必须是路由表上真有的那条**读**端点。指回 `/api/esim/switch`
/// 就是让人再切一次。
#[tokio::test]
async fn a_switch_receipt_says_where_and_when_to_read_the_card_back() {
    let (code, body) = post_json(
        Arc::new(RecordingActions::new()),
        "/api/esim/switch",
        r#"{"iccid":"89852351225042214201","enable":false}"#,
    )
    .await;
    assert_eq!(code, 200);
    assert_eq!(body["readback_after_ms"], edge_panel_api::ESIM_SETTLE_MS);
    assert_ne!(
        body["readback_with"], "/api/esim/switch",
        "指回切换端点就是让人再切一次"
    );

    // 🔴 **照着回执说的那条路真打一次。** 原来这里只 `assert_ne!` 了一下，
    //    于是「回读目标必须是路由表上真有的那条读端点」这句话是空的：路径写错
    //    一个字母、或者指向一条不存在的路由，都能一路绿着上线——而这条指令
    //    存在的全部理由，就是操作员在只剩 curl 的时候照着它做。
    let target = body["readback_with"].as_str().expect("回执要给出回读路径");
    let (readback_code, readback_body) =
        post_json(Arc::new(RecordingActions::new()), target, "{}").await;
    assert_eq!(
        readback_code, 200,
        "回执让人去打 {target}，而那条路答的是 {readback_code} —— \
         一条在紧急情况下第一次就失败的「下一步」，比不写更坏"
    );
    assert!(
        readback_body.get("profiles").is_some(),
        "{target} 答了 200，但里面没有 profile 列表 —— 那不是回读卡片的那条路"
    );
}

/// 🔴 服务端宣称的等待时长，必须**就是**面板自己等的那一个。
///
/// 这个数字以前有两份：`edge-panel-api::ESIM_SETTLE_MS` 和 `edge-ui/src/esim.rs`
/// 里自己的 `const SETTLE_MS`。两份漂开的话，回执告诉操作员「等 8 秒」而面板
/// 等 3 秒，面板就会在卡片 REFRESH 中途回读，然后给出一个**错的判决**——
/// 而这一栏存在的全部理由就是「不采信端点的 ok，以回读为准」。
///
/// 现在前端 `use edge_panel_api::ESIM_SETTLE_MS as SETTLE_MS`，一份。这条测试
/// 守的是数字本身不许被「优化」掉：读得太早等于没读。
#[test]
fn the_readback_wait_is_long_enough_to_be_worth_waiting_for() {
    assert!(
        edge_panel_api::ESIM_SETTLE_MS >= 5_000,
        "回读等待被压到了 {} ms —— 卡片 REFRESH 还没走完，ISD-R 通道是关的，\
         这时候读到的状态是上一个，而屏幕上会把它当成切换的结果",
        edge_panel_api::ESIM_SETTLE_MS
    );
    assert!(
        edge_panel_api::ESIM_SETTLE_MS <= 30_000,
        "等 {} ms 太久了 —— 久到操作员会以为面板卡住，然后手动再切一次",
        edge_panel_api::ESIM_SETTLE_MS
    );
    // 前端不许再留一份本地副本。
    let ui = include_str!("../../edge-ui/src/esim.rs");
    assert!(
        !ui.contains("const SETTLE_MS"),
        "edge-ui 又自己留了一份等待时长 —— 两份数字会漂开"
    );
}

/// 取消是这四条里唯一给不出回读路径的：面板没有任何端点能回答「这根模组上
/// 现在还有没有开着的 USSD 会话」。
///
/// 🔴 所以回执里不许出现任何声称会话已经结束的字段。给不出就不给——原版
/// 前端 `.catch(() => {})` 吞掉失败照画「已取消」，就是这么来的。
#[tokio::test]
async fn a_ussd_cancel_receipt_does_not_claim_the_session_is_closed() {
    let actions = Arc::new(RecordingActions::new());
    let (code, body) = post_json(
        actions.clone(),
        "/api/ussd/cancel",
        r#"{"imei":"867018069514820"}"#,
    )
    .await;
    assert_eq!(code, 200);
    assert_eq!(body["status"], "cancelled");
    assert_eq!(body["imei"], "867018069514820");
    assert_eq!(
        actions.cancelled.lock().expect("cancelled").as_slice(),
        &[Some("867018069514820".to_string())]
    );
    // 回执只有 status 和 imei 两个字段。多出来的任何一个都是在替网络说话。
    assert_eq!(
        body.as_object().expect("对象").len(),
        2,
        "取消回执多了字段：{body}——这条路上没有任何东西能确认会话真的关了"
    );
}

/// 重启回执回的是**实际交给 `restart_modem` 的那个字符串**。
///
/// ⚠️ handler 只用 `trim()` 判断「是不是全是空白」，传下去的一直是原样的值。
/// 回执要是回一个规整过的漂亮版本，操作员看到的就不是真正打到硬件上的那个。
#[tokio::test]
async fn a_restart_receipt_repeats_the_imei_that_reached_the_hardware() {
    let actions = Arc::new(RecordingActions::new());
    let (code, body) = post_json(
        actions.clone(),
        "/api/restart",
        r#"{"imei":" 867018069514820 "}"#,
    )
    .await;
    assert_eq!(code, 200);
    let reached = actions.restarted.lock().expect("restarted").clone();
    assert_eq!(reached.as_slice(), &[" 867018069514820 ".to_string()]);
    assert_eq!(body["imei"], reached[0]);
    assert_eq!(body["status"], "restarted");
}
