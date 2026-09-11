//! 面板的访问闸。
//!
//! 🔴 这道闸存在的理由是一个**当时正在发生**的暴露面。2026-09-10 在生产边缘机
//!    上实测：
//!
//!    ```text
//!    LISTEN 0 128 0.0.0.0:8743   users:(("vodoge-edge",...))
//!    POST http://192.168.6.83:8743/api/modems/unregister  →  422 missing field `imei`
//!    ```
//!
//!    422 是**业务校验**的报错，不是 401 —— 也就是说局域网上任何人都能对 19 个
//!    改动型端点发请求：取消纳管、手工建模组、发短信（计费）、复位 USB、
//!    切 eSIM 配置文件。一条认证都没有。
//!
//! ## 边界画在哪，为什么
//!
//! **回环放行。** 能在这台机器上访问 127.0.0.1 的人，已经有一个 shell；
//! 他能读 token 文件、能改 unit、能直接重启 agent。放行不给他任何新权力，
//! 而拦住他的代价是把运维平时用的那扇窗户也关上。
//!
//! **非回环必须带 token。** 这是这次要堵的那一半。
//!
//! ⚠️ 面板跑在明文 HTTP 上，所以 token 在局域网上是可嗅探的。这道闸解决的是
//! 「未认证就能动手」，**不是**保密性 —— 真要保密就走 SSH 隧道。把这句话写在
//! 这里，是因为一道闸最危险的时刻是别人以为它比实际做得更多。
//!
//! ## token 从哪来
//!
//! `<证书目录>/panel-token`，首次启动时自己生成（0600）。日志里只打**路径**，
//! 不打值 —— 那个环 500 行、二十分钟滚一轮，而它会被贴进工单。
//!
//! 🔴 非回环监听 + 拿不到 token 时**拒绝服务整个面板**，而不是降级成放行。
//!    「凭据读不出来」塌陷成「不需要凭据」，正是这个仓库反复在防的形状，
//!    而这一处塌陷的方向是把机队交给局域网。
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use axum::extract::{ConnectInfo, Request};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Response};

/// 浏览器那一侧带 token 的 cookie 名。
pub const COOKIE: &str = "vodoge_panel";

/// 拿到 token 之后换 cookie 的那个端点。它**不经过**这道闸。
pub const SESSION_PATH: &str = "/api/session";

/// 这台机器的面板 token。
#[derive(Clone, Debug)]
pub struct PanelToken(String);

impl PanelToken {
    /// 从文件读，没有就生成一个并写下去。
    ///
    /// ⚠️ 生成用的是 `getrandom`（rustls 那条链里已经有 ring，但这里只要
    ///    32 字节随机）。**不要**退化成时间戳或 pid：一个可以猜的 token
    ///    和没有 token 在效果上是同一件事，只是更难发现。
    pub fn load_or_create(path: &Path) -> std::io::Result<Self> {
        if let Ok(raw) = std::fs::read_to_string(path) {
            let token = raw.trim().to_string();
            if token.len() >= 16 {
                return Ok(Self(token));
            }
            // 太短的当成没有：一个 3 个字符的 token 是一次误操作留下的，
            // 而不是一个决定。
        }
        let token = generate();
        write_private(path, token.as_bytes())?;
        Ok(Self(token))
    }

    /// 测试和内存 fixture 用。
    pub fn from_value(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// 常量时间比较。
    ///
    /// 🔴 用 `==` 比 token 会按首个不同字节提前返回，于是响应时间泄露前缀 ——
    ///    而这个端点可以被局域网无限次调用。
    pub fn matches(&self, candidate: &str) -> bool {
        let expected = self.0.as_bytes();
        let given = candidate.as_bytes();
        if expected.len() != given.len() {
            return false;
        }
        let mut diff = 0u8;
        for (a, b) in expected.iter().zip(given.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }

    pub fn value(&self) -> &str {
        &self.0
    }
}

fn generate() -> String {
    // /dev/urandom 直接读 32 字节。这台机器上一定有它，为 32 字节随机多引一个
    // 依赖不值得。
    //
    // ⚠️ 不能用 `fs::read`（它会读整个「文件」——那是个无穷流）。
    //    `read_exact` 到一个定长数组上。
    use std::io::Read as _;
    let mut bytes = [0u8; 32];
    let mut file = std::fs::File::open("/dev/urandom").expect("/dev/urandom");
    file.read_exact(&mut bytes).expect("read /dev/urandom");
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("tmp");
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&temporary, path)
}

/// 这道闸的配置。
#[derive(Clone, Debug)]
pub struct Guard {
    token: PanelToken,
    /// token 文件在哪 —— 拒绝的时候要告诉人去哪拿。
    pub token_path: PathBuf,
}

impl Guard {
    pub fn new(token: PanelToken, token_path: PathBuf) -> Self {
        Self { token, token_path }
    }

    /// 校验一个出示的 token。常量时间。
    pub fn token_matches(&self, candidate: &str) -> bool {
        self.token.matches(candidate)
    }

    /// 这次请求放不放行。
    ///
    /// 抽成纯函数（不碰 `Request`）好测：这道闸的每一条规则都要能单独钉住。
    pub fn admits(&self, peer: Option<SocketAddr>, presented: Option<&str>) -> Verdict {
        if let Some(token) = presented {
            return if self.token.matches(token) {
                Verdict::Allowed
            } else {
                Verdict::WrongToken
            };
        }
        match peer {
            // 回环：放行，理由见模块开头。
            Some(address) if address.ip().is_loopback() => Verdict::Loopback,
            // 🔴 认不出对端地址时**拒**。没有 ConnectInfo 的情形只有一种是
            //    正常的（进程内测试），而生产上它意味着我们不知道对面是谁 ——
            //    那时候放行就是把「不知道」当成了「是本机」。
            _ => Verdict::NeedsToken,
        }
    }
}

/// 一次判定的结果。带名字而不是 `bool`：拒绝的两种原因要对人说不同的话。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verdict {
    /// 带了正确的 token。
    Allowed,
    /// 来自回环，放行。
    Loopback,
    /// 不是回环，也没带 token。
    NeedsToken,
    /// 带了 token，但不对。
    WrongToken,
}

impl Verdict {
    pub fn admits(self) -> bool {
        matches!(self, Self::Allowed | Self::Loopback)
    }
}

/// 从请求头里取出对方出示的 token：`Authorization: Bearer` 或那个 cookie。
///
/// ⚠️ 刻意**不看** query string。放在 URL 里的凭据会进 access log、进浏览器
/// 历史、进 Referer —— 而这个面板本来就是给人在浏览器里点的。
pub fn presented_token(headers: &HeaderMap) -> Option<String> {
    if let Some(value) = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        if let Some(token) = value.strip_prefix("Bearer ") {
            let token = token.trim();
            if !token.is_empty() {
                return Some(token.to_string());
            }
        }
    }
    let cookies = headers.get(header::COOKIE).and_then(|v| v.to_str().ok())?;
    cookie_value(cookies, COOKIE)
}

/// 从一行 Cookie 头里挑出一个名字。
pub fn cookie_value(header_line: &str, name: &str) -> Option<String> {
    for part in header_line.split(';') {
        let part = part.trim();
        let (key, value) = part.split_once('=')?;
        if key.trim() == name {
            let value = value.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// axum 中间件。
pub async fn gate(
    axum::extract::State(guard): axum::extract::State<std::sync::Arc<Guard>>,
    connect: Option<ConnectInfo<SocketAddr>>,
    request: Request,
    next: Next,
) -> Response {
    // 换 cookie 那个端点自己不能被这道闸拦住 —— 否则没有 cookie 的人永远
    // 拿不到 cookie。它自己校验 token。
    if request.uri().path() == SESSION_PATH {
        return next.run(request).await;
    }
    let peer = connect.map(|ConnectInfo(address)| address);
    let presented = presented_token(request.headers());
    let verdict = guard.admits(peer, presented.as_deref());
    if verdict.admits() {
        return next.run(request).await;
    }
    // 浏览器来要页面时给一张登录页；程序来调 API 时给 401 和一句话。
    let wants_page = request.uri().path() == "/"
        || request
            .headers()
            .get(header::ACCEPT)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|accept| accept.contains("text/html"));
    if wants_page {
        return (StatusCode::UNAUTHORIZED, Html(login_page(&guard.token_path))).into_response();
    }
    (
        StatusCode::UNAUTHORIZED,
        [(header::CONTENT_TYPE, "application/json")],
        format!(
            "{{\"error\":\"面板需要 token。它在这台机器的 {} 里（0600）。\
             用 Authorization: Bearer <token>，或先 POST {SESSION_PATH} 换一个 cookie。\
             从这台机器本机访问（127.0.0.1，例如 SSH 隧道）不需要 token。\"}}",
            guard.token_path.display().to_string().replace('"', "")
        ),
    )
        .into_response()
}

/// 一张最小的登录页。
///
/// 🔴 由 agent 直接吐 HTML，**两个面板一行都不用改**。老面板（`/`）和新的
///    wasm 面板都在这道闸后面，而它们各自的登录界面要各写一遍 —— 而这次要
///    解决的是一个正在暴露的洞，不是一次界面改造。
///
/// ⚠️ 不用现成 UI 框架：这一页必须在 wasm 还没被允许下载的时候就能显示。
fn login_page(token_path: &Path) -> String {
    format!(
        r#"<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VoDoge 边缘面板 · 需要 token</title>
<style>
  body {{ font: 14px/1.6 system-ui, sans-serif; max-width: 34rem; margin: 8vh auto; padding: 0 1rem;
          color: #111; background: #fff; }}
  @media (prefers-color-scheme: dark) {{ body {{ color: #eee; background: #111; }} code {{ background:#222; }} }}
  h1 {{ font-size: 1.25rem; }}
  code {{ background: #f2f2f2; padding: .1rem .3rem; border-radius: 3px; }}
  input {{ font: inherit; width: 100%; padding: .5rem; box-sizing: border-box; }}
  button {{ font: inherit; padding: .5rem 1rem; margin-top: .5rem; }}
  p.why {{ color: #666; }}
  @media (prefers-color-scheme: dark) {{ p.why {{ color: #999; }} }}
</style>
<h1>这个面板需要一个 token</h1>
<p>它在这台边缘机上：<code>{path}</code>（0600）。登上那台机器 <code>cat</code> 一下，
把内容贴进来。</p>
<form id="f">
  <input id="t" type="password" autocomplete="off" placeholder="panel token" autofocus>
  <button type="submit">进入</button>
</form>
<p id="msg"></p>
<p class="why">从这台机器本机访问不需要 token（SSH 隧道就算本机）。面板跑在明文 HTTP 上，
所以 token 在局域网上是可嗅探的 —— 这道闸挡的是「未认证就能动手」，要保密请走隧道。</p>
<script>
document.getElementById('f').addEventListener('submit', async (event) => {{
  event.preventDefault();
  const message = document.getElementById('msg');
  message.textContent = '正在验证…';
  const response = await fetch('{session}', {{
    method: 'POST',
    headers: {{ 'Content-Type': 'application/json' }},
    body: JSON.stringify({{ token: document.getElementById('t').value }}),
  }});
  if (response.ok) {{ location.reload(); return; }}
  message.textContent = response.status === 401
    ? 'token 不对。它在这台机器的 {path} 里。'
    : '验证失败（HTTP ' + response.status + '）。';
}});
</script>
"#,
        path = token_path.display(),
        session = SESSION_PATH,
    )
}

/// `POST /api/session` 的响应：把 token 换成一个 cookie。
///
/// `HttpOnly` 让页面脚本读不到它，`SameSite=Strict` 挡住跨站发起的写操作 ——
/// 这个面板每一个改动型端点都是 POST，没有它，别的站点可以在运维的浏览器里
/// 替他取消纳管。
pub fn session_cookie(token: &str) -> String {
    format!("{COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard() -> Guard {
        Guard::new(
            PanelToken::from_value("0123456789abcdef0123456789abcdef"),
            PathBuf::from("/etc/vodoge-edge/panel-token"),
        )
    }

    fn peer(text: &str) -> Option<SocketAddr> {
        Some(text.parse().expect("地址"))
    }

    /// 🔴 局域网上不带 token 的请求必须被拒。
    ///
    /// 这就是 2026-09-10 实测到的那个洞：`POST /api/modems/unregister`
    /// 从 192.168.6.83 打进去，回的是 422（业务校验），说明根本没有闸。
    #[test]
    fn a_lan_request_without_a_token_is_refused() {
        assert_eq!(
            guard().admits(peer("192.168.6.83:51000"), None),
            Verdict::NeedsToken
        );
        assert!(!guard()
            .admits(peer("192.168.6.83:51000"), None)
            .admits());
    }

    /// 回环放行 —— 那个人已经有 shell 了。
    #[test]
    fn loopback_is_admitted_without_a_token() {
        assert_eq!(guard().admits(peer("127.0.0.1:51000"), None), Verdict::Loopback);
        assert_eq!(guard().admits(peer("[::1]:51000"), None), Verdict::Loopback);
        assert!(guard().admits(peer("127.0.0.1:1"), None).admits());
    }

    /// 带对了 token，从哪来都行。
    #[test]
    fn the_right_token_is_admitted_from_anywhere() {
        let token = "0123456789abcdef0123456789abcdef";
        assert_eq!(
            guard().admits(peer("10.0.0.9:51000"), Some(token)),
            Verdict::Allowed
        );
    }

    /// 🔴 认不出对端地址时**拒**，不许当成本机。
    ///
    /// 把「不知道对面是谁」塌陷成「是本机」，方向正好是把机队交给局域网。
    #[test]
    fn an_unknown_peer_is_refused_rather_than_assumed_local() {
        assert_eq!(guard().admits(None, None), Verdict::NeedsToken);
        assert!(!guard().admits(None, None).admits());
    }

    /// 带错的 token 和不带 token 要分开说。
    #[test]
    fn a_wrong_token_says_something_different_from_no_token() {
        assert_eq!(
            guard().admits(peer("10.0.0.9:1"), Some("nope")),
            Verdict::WrongToken
        );
        assert_ne!(
            guard().admits(peer("10.0.0.9:1"), Some("nope")),
            guard().admits(peer("10.0.0.9:1"), None)
        );
    }

    /// ⚠️ 带了错 token 的**回环**请求也要拒。
    ///
    /// 出示了凭据就按凭据判，不要在它错了之后再去看来源 —— 那等于「猜错了
    /// 也没关系」，而这条路会让一个脚本无限次试 token 而毫无代价。
    #[test]
    fn a_wrong_token_is_not_rescued_by_being_local() {
        assert_eq!(
            guard().admits(peer("127.0.0.1:1"), Some("nope")),
            Verdict::WrongToken
        );
    }

    /// token 从 `Authorization: Bearer` 或 cookie 里取，**不从 query string**。
    #[test]
    fn the_token_is_read_from_the_header_or_the_cookie_only() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer abc123".parse().unwrap());
        assert_eq!(presented_token(&headers).as_deref(), Some("abc123"));

        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, "other=1; vodoge_panel=abc123".parse().unwrap());
        assert_eq!(presented_token(&headers).as_deref(), Some("abc123"));

        // 空的不算出示。
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer   ".parse().unwrap());
        assert_eq!(presented_token(&headers), None);

        assert_eq!(presented_token(&HeaderMap::new()), None);
    }

    /// 比较必须是常量时间。
    ///
    /// 🔴 `==` 会在首个不同字节提前返回，于是响应时间泄露前缀 —— 而这个端点
    ///    可以被局域网无限次调用。这里断言的是**行为**（长度不同也不短路到
    ///    一个可区分的路径上），实现里那个循环是真正的保证。
    #[test]
    fn the_comparison_does_not_leak_the_prefix() {
        let token = PanelToken::from_value("0123456789abcdef0123456789abcdef");
        assert!(token.matches("0123456789abcdef0123456789abcdef"));
        // 只差最后一个字节
        assert!(!token.matches("0123456789abcdef0123456789abcdee"));
        // 只差第一个字节
        assert!(!token.matches("1123456789abcdef0123456789abcdef"));
        // 正确的前缀，长度不够
        assert!(!token.matches("0123456789abcdef"));
        assert!(!token.matches(""));
    }

    /// cookie 必须是 HttpOnly + SameSite=Strict。
    ///
    /// 🔴 面板每一个改动型端点都是 POST。少了 `SameSite=Strict`，别的站点
    ///    可以在运维的浏览器里替他取消纳管、发短信。
    #[test]
    fn the_session_cookie_cannot_be_read_or_sent_cross_site() {
        let cookie = session_cookie("abc");
        assert!(cookie.contains("HttpOnly"), "{cookie}");
        assert!(cookie.contains("SameSite=Strict"), "{cookie}");
        assert!(cookie.starts_with("vodoge_panel=abc;"), "{cookie}");
    }

    /// 换 cookie 那个端点自己不能被闸拦住。
    #[test]
    fn the_session_endpoint_is_outside_the_gate() {
        assert_eq!(SESSION_PATH, "/api/session");
        // 它在 gate() 里被显式放过；这里钉住路径本身不变，
        // 免得改了路径而 gate 里那个判断还指着旧的。
    }

    /// 拒绝的话必须说清 token 在哪。
    #[test]
    fn the_refusal_says_where_the_token_is() {
        let page = login_page(Path::new("/etc/vodoge-edge/panel-token"));
        assert!(page.contains("/etc/vodoge-edge/panel-token"), "登录页没说 token 在哪");
        assert!(page.contains("SSH"), "没说本机访问不需要 token");
        assert!(page.contains("明文 HTTP"), "没说这道闸不解决保密性");
    }

    /// 太短的 token 文件当成没有。
    #[test]
    fn a_too_short_token_file_is_replaced() {
        let dir = std::env::temp_dir().join(format!("vodoge-token-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("目录");
        let path = dir.join("panel-token");
        std::fs::write(&path, "abc").expect("写短 token");
        let token = PanelToken::load_or_create(&path).expect("加载");
        assert!(
            token.value().len() >= 32,
            "3 个字符的 token 被当成了一个决定，而它是一次误操作"
        );
        assert!(!token.matches("abc"));
        let _ = std::fs::remove_file(&path);
    }

    /// 生成的 token 每次都不一样，而且够长。
    #[test]
    fn a_generated_token_is_random_and_long() {
        let first = generate();
        let second = generate();
        assert_eq!(first.len(), 64, "32 字节的十六进制");
        assert_ne!(first, second, "两次生成拿到了同一个 token");
    }
}
