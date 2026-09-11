//! 面板那道访问闸，端到端。
//!
//! 🔴 这些断言不只看状态码，还看**动作有没有真的发生**。一道只改状态码的闸
//!    和没有闸的区别，在生产上是零 —— 2026-09-10 实测到的那次就是：
//!    `POST http://192.168.6.83:8743/api/modems/unregister` 回 422，
//!    那是**业务校验**的报错，说明请求已经进了处理器。
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::extract::ConnectInfo;
use edge_panel::guard::{Guard, PanelToken, COOKIE, SESSION_PATH};
use edge_panel::{
    Actions, AtResult, MemoryInbox, PanelError, ProfilesResult, RegistrationResult, ReportResult,
    RescanResult, ScanResult, UsbResetResult, UssdResult,
};
use http_body_util::BodyExt;
use tower::ServiceExt;

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// 只记录，不做事 —— 断言要能看出「动作有没有发生」。
#[derive(Default)]
struct Spy {
    unregistered: Mutex<Vec<String>>,
    rescans: Mutex<usize>,
}

impl Actions for Spy {
    fn unregister_modem(&self, imei: String) -> Result<RegistrationResult, PanelError> {
        self.unregistered.lock().expect("unregistered").push(imei.clone());
        Ok(RegistrationResult {
            imei,
            registered: false,
            changed: true,
        })
    }

    fn rescan_modems(&self) -> Result<RescanResult, PanelError> {
        *self.rescans.lock().expect("rescans") += 1;
        Ok(RescanResult {
            found: 0,
            control_ports: Vec::new(),
        })
    }

    // 剩下的这些这些测试不碰。**返回错误而不是 todo!()**：panic 会让一个
    // 「闸放行了、动作却炸了」的失败读起来像闸坏了，而这里要区分的正是
    // 「有没有进到处理器」。
    fn send_sms(&self, _: String, _: String, _: Option<String>, _: bool) -> Result<(), PanelError> {
        Err(unused())
    }
    fn restart_modem(&self, _: String) -> Result<(), PanelError> {
        Err(unused())
    }
    fn at_command(&self, _: Option<String>, _: String, _: bool) -> Result<AtResult, PanelError> {
        Err(unused())
    }
    fn usb_reset(&self, _: Option<String>) -> Result<UsbResetResult, PanelError> {
        Err(unused())
    }
    fn modem_report(&self, _: Option<String>) -> Result<ReportResult, PanelError> {
        Err(unused())
    }
    fn list_profiles(&self, _: Option<String>) -> Result<ProfilesResult, PanelError> {
        Err(unused())
    }
    fn switch_profile(&self, _: Option<String>, _: String, _: bool) -> Result<(), PanelError> {
        Err(unused())
    }
    fn scan_operators(&self, _: Option<String>) -> Result<ScanResult, PanelError> {
        Err(unused())
    }
    fn ussd(&self, _: Option<String>, _: String) -> Result<UssdResult, PanelError> {
        Err(unused())
    }
    fn ussd_cancel(&self, _: Option<String>) -> Result<(), PanelError> {
        Err(unused())
    }
    fn set_radio(&self, _: Option<String>, _: bool) -> Result<(), PanelError> {
        Err(unused())
    }
}

fn unused() -> PanelError {
    PanelError::Action("这个测试不使用这个动作".into())
}

fn guarded(spy: Arc<Spy>) -> axum::Router {
    edge_panel::router_guarded(
        Arc::new(MemoryInbox::default()),
        Some(spy),
        Arc::new(std::sync::atomic::AtomicBool::new(false)),
        Arc::new(Mutex::new(
            edge_core::CapabilityMatrix::builtin().expect("built-in matrix"),
        )),
        Arc::new(Guard::new(
            PanelToken::from_value(TOKEN),
            std::path::PathBuf::from("/etc/vodoge-edge/panel-token"),
        )),
    )
}

/// 一次请求。`from` 是对端地址（`None` = 服务端认不出对面是谁）。
async fn post(
    app: axum::Router,
    path: &str,
    body: &str,
    from: Option<&str>,
    header: Option<(&str, &str)>,
) -> (u16, String) {
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json");
    if let Some((name, value)) = header {
        request = request.header(name, value);
    }
    let mut request = request.body(axum::body::Body::from(body.to_string())).expect("请求");
    if let Some(address) = from {
        let address: SocketAddr = address.parse().expect("地址");
        request.extensions_mut().insert(ConnectInfo(address));
    }
    let response = app.oneshot(request).await.expect("响应");
    let status = response.status().as_u16();
    let bytes = response.into_body().collect().await.expect("body").to_bytes();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

/// 🔴 局域网上不带 token：拒，**而且那根模组没有被取消纳管**。
///
/// 这条就是那次实测的形状。只断言状态码是不够的：一道闸最坏的失败方式是
/// 「拒绝了，但事情已经做了」。
#[tokio::test]
async fn a_lan_request_cannot_unregister_a_modem() {
    let spy = Arc::new(Spy::default());
    let (status, body) = post(
        guarded(spy.clone()),
        "/api/modems/unregister",
        r#"{"imei":"867018069509705"}"#,
        Some("192.168.6.83:51000"),
        None,
    )
    .await;

    assert_eq!(status, 401, "局域网上不带 token 的请求没有被拒: {body}");
    assert!(
        spy.unregistered.lock().expect("spy").is_empty(),
        "闸回了 401，但那根模组已经被取消纳管了 —— 拒绝发生在动作之后"
    );
    assert!(
        body.contains("panel-token"),
        "401 没说 token 在哪，运维只会看到一句「未授权」: {body}"
    );
}

/// 带对了 token，从局域网也能做事。
#[tokio::test]
async fn the_right_token_lets_the_action_through() {
    let spy = Arc::new(Spy::default());
    let (status, body) = post(
        guarded(spy.clone()),
        "/api/modems/unregister",
        r#"{"imei":"867018069509705"}"#,
        Some("192.168.6.83:51000"),
        Some(("authorization", &format!("Bearer {TOKEN}"))),
    )
    .await;

    assert_eq!(status, 200, "带对了 token 却被拒: {body}");
    assert_eq!(
        spy.unregistered.lock().expect("spy").as_slice(),
        ["867018069509705".to_string()],
        "带对了 token，动作却没有发生"
    );
}

/// 回环放行 —— 那个人已经有 shell 了。
#[tokio::test]
async fn loopback_still_works_without_a_token() {
    let spy = Arc::new(Spy::default());
    let (status, body) = post(
        guarded(spy.clone()),
        "/api/rescan",
        "{}",
        Some("127.0.0.1:51000"),
        None,
    )
    .await;
    assert_eq!(status, 200, "本机访问被拦住了，运维平时那扇窗户关了: {body}");
    assert_eq!(*spy.rescans.lock().expect("spy"), 1);
}

/// 🔴 认不出对端地址时拒，不许当成本机。
///
/// 这一条同时钉住了一个接线错误：`serve()` 少写
/// `into_make_service_with_connect_info` 的话，每个请求都落进这一支。
/// 那时症状是「本机也进不去」——难受，但方向是安全的那一边。
#[tokio::test]
async fn an_unknown_peer_is_refused() {
    let spy = Arc::new(Spy::default());
    let (status, _) = post(guarded(spy.clone()), "/api/rescan", "{}", None, None).await;
    assert_eq!(status, 401, "认不出对面是谁却放行了 —— 那等于把「不知道」当成「是本机」");
    assert_eq!(*spy.rescans.lock().expect("spy"), 0);
}

/// 用 token 换 cookie，然后用 cookie 从局域网做事。
#[tokio::test]
async fn a_session_cookie_can_be_exchanged_and_then_used() {
    let spy = Arc::new(Spy::default());

    // ① 换 cookie。这个端点在闸外面。
    let app = guarded(spy.clone());
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(SESSION_PATH)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(format!(r#"{{"token":"{TOKEN}"}}"#)))
        .expect("请求");
    let response = app.oneshot(request).await.expect("响应");
    assert_eq!(response.status().as_u16(), 200, "换 cookie 失败");
    let cookie = response
        .headers()
        .get(axum::http::header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .expect("没有 Set-Cookie")
        .to_string();
    assert!(cookie.contains("HttpOnly"), "{cookie}");
    assert!(cookie.contains("SameSite=Strict"), "{cookie}");

    // ② 带着它从局域网做事。
    let jar = cookie.split(';').next().expect("cookie 值").to_string();
    assert!(jar.starts_with(&format!("{COOKIE}=")), "{jar}");
    let (status, body) = post(
        guarded(spy.clone()),
        "/api/rescan",
        "{}",
        Some("192.168.6.83:51000"),
        Some(("cookie", &jar)),
    )
    .await;
    assert_eq!(status, 200, "带着刚换来的 cookie 却被拒: {body}");
    assert_eq!(*spy.rescans.lock().expect("spy"), 1);
}

/// 换 cookie 时 token 不对：401，而且**不发 cookie**。
#[tokio::test]
async fn a_wrong_token_gets_no_cookie() {
    let spy = Arc::new(Spy::default());
    let app = guarded(spy);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(SESSION_PATH)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(r#"{"token":"wrong"}"#))
        .expect("请求");
    let response = app.oneshot(request).await.expect("响应");
    assert_eq!(response.status().as_u16(), 401);
    assert!(
        response.headers().get(axum::http::header::SET_COOKIE).is_none(),
        "token 不对却发了 cookie"
    );
}

/// 浏览器来要页面（不带 token）时给一张登录页，而不是一段 JSON。
///
/// ⚠️ 给 JSON 的后果是运维打开面板看到一行 `{"error":...}`，而那句话里
///    虽然写着 token 在哪，但没有可以粘贴的地方 —— 他得去翻文档才知道
///    下一步是什么。
#[tokio::test]
async fn a_browser_gets_a_login_page_rather_than_json() {
    let spy = Arc::new(Spy::default());
    let app = guarded(spy);
    let mut request = axum::http::Request::builder()
        .method("GET")
        .uri("/")
        .header("accept", "text/html")
        .body(axum::body::Body::empty())
        .expect("请求");
    request
        .extensions_mut()
        .insert(ConnectInfo("192.168.6.83:51000".parse::<SocketAddr>().expect("地址")));
    let response = app.oneshot(request).await.expect("响应");
    assert_eq!(response.status().as_u16(), 401);
    let bytes = response.into_body().collect().await.expect("body").to_bytes();
    let page = String::from_utf8_lossy(&bytes);
    assert!(page.contains("<form"), "没有可以粘贴 token 的地方: {}", &page[..page.len().min(200)]);
    assert!(page.contains("panel-token"), "登录页没说 token 在哪");
}

/// 读接口也在闸后面。
///
/// 🔴 `/api/status` 不改任何东西，但它回的是这台机器的整个状态：IMEI、
///    ICCID、本机号码、日志。把闸只挂在写接口上，等于把机队的清单交给局域网。
#[tokio::test]
async fn reading_the_machine_state_also_needs_the_token() {
    let spy = Arc::new(Spy::default());
    let app = guarded(spy);
    let mut request = axum::http::Request::builder()
        .method("GET")
        .uri("/api/status")
        .body(axum::body::Body::empty())
        .expect("请求");
    request
        .extensions_mut()
        .insert(ConnectInfo("192.168.6.83:51000".parse::<SocketAddr>().expect("地址")));
    let response = app.oneshot(request).await.expect("响应");
    assert_eq!(
        response.status().as_u16(),
        401,
        "/api/status 没有被拦 —— 它回的是 IMEI、卡号、号码和日志"
    );
}
