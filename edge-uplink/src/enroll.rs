//! 装机：用一次性码换一张设备证书。
//!
//! 🔴 这个模块存在的理由是一个到今天为止**没有出路**的状态：换盘重装之后
//!    `/etc/vodoge-edge/device.key` 没了，而这个仓库里**没有任何代码会造 CSR**
//!    —— 现役那张证书是 2026-09-01 手工签进那个目录的。云端的
//!    `POST /v1/enroll` 一直是活的（CA 已配、真处理器挂着），
//!    `app.device_certificates` 却是 0 行：签发端从来没有被用过。
//!
//!    后果有两层。近的一层：任何一次换盘、任何一台新机器，都要一次人工签发。
//!    远的一层：吊销**无从下手** —— 表里有 `revoked_at`，可没有一行记录对应
//!    现役的那张证书，机器丢了收不回来。链头是这里：只要证书是这条路发出来的，
//!    云端就自然有了那一行。
//!
//! ## 装机时人要放两样东西
//!
//! ```text
//!   /etc/vodoge-edge/ca.crt       网关的 CA —— 拿它验对面是不是我们的网关
//!   /etc/vodoge-edge/enroll-code  租户 id 和一次性码，空白分隔（控制台上生成）
//! ```
//!
//! 租户 id 和码要放在**一起**：云端 `Enroll` 要求两者匹配（`TestEnrollRejectsWrongTenant`
//! 钉着这条），而装机的这一刻设备还没有证书 —— 租户 id 平时是从证书的 O 字段
//! 读出来的，此刻那个来源还不存在。分成两个文件只会多一次「放了一个忘了另一个」。
//!
//! agent 自己产出 `device.key` 和 `device.crt`，然后删掉那个码。
//!
//! ⚠️ 码放在**文件**里而不是环境变量里：环境变量会出现在 `systemctl show`、
//! `/proc/<pid>/environ` 和 unit 文件里，而且删不掉；文件可以是 0600，用完就删。
//!
//! ## CSR 里的 subject 不重要
//!
//! 云端 `SignCSR` 的注释写得很清楚：**subject 被忽略**，身份来自被消费的那个码
//! （租户、设备、区域）。所以这边只需要一个合法的公钥和一次自签名 —— 不要在
//! CSR 里编造 device_id，那只会让人以为那个值有意义。
use std::io::{Read as _, Write as _};
use std::net::{TcpStream, ToSocketAddrs as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};

/// 一次装机的耗时上限。TLS 握手 + 一次签发，不该超过这个数量级。
const ENROLL_TIMEOUT: Duration = Duration::from_secs(20);

/// 响应体的上限。一张 leaf 证书 PEM 是几百字节。
const MAX_RESPONSE_BYTES: u64 = 64 * 1024;

/// 这台机器现在处在装机的哪一步。
///
/// 🔴 做成一个有名字的枚举而不是 `bool`：其中一个状态（有私钥、没有证书）
///    的含义是「那个一次性码已经被云端消费掉了，而结果没落盘」——
///    它和「什么都还没开始」在屏幕上必须说不同的话，因为运维要做的事不同
///    （一个是去拿一个新码，一个是把码放进来）。
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Stage {
    /// 证书和私钥都在，什么都不用做。
    Enrolled,
    /// 两样都没有，等一个一次性码。
    Fresh,
    /// 有私钥、没有证书 —— 上一次装机在签发之后、落盘之前断了。
    ///
    /// ⚠️ 那个码**已经被消费**了，重试同一个码只会被拒。必须换一个新码，
    ///    而且要换一把新密钥（旧密钥没有对应的证书，留着没有意义）。
    KeyWithoutCertificate,
}

#[derive(Clone, Debug)]
pub enum EnrollError {
    /// 没有身份，也没有码。带上要放哪两个文件。
    NeedsCode { code_path: PathBuf },
    /// 没有 CA，验不了对面是谁。**不降级成不验证**。
    NeedsTrustAnchor { ca_path: PathBuf },
    Io(String),
    Tls(String),
    /// 云端拒了。带上状态码和它自己那句话 —— 那句话是给人读的。
    Refused { status: u16, message: String },
    /// 响应不是我们能用的东西。
    BadResponse(String),
    Crypto(String),
}

impl std::fmt::Display for EnrollError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NeedsCode { code_path } => write!(
                formatter,
                "这台机器还没有设备证书，也没有可用的装机凭据。在控制台上生成一个装机码，\
                 把**租户 id 和码**空白分隔写进 {} （0600），\
                 agent 会自己换回证书并删掉它。只写码、不写租户 id 也算缺 —— \
                 云端两样都要，缺一个回的那句话读起来像「码不对」",
                code_path.display()
            ),
            Self::NeedsTrustAnchor { ca_path } => write!(
                formatter,
                "缺 {}：没有网关的 CA 就验不出对面是不是我们的网关，而装机这一步\
                 正是把私钥交出去之前唯一能确认对方的机会 —— 这里不会降级成不验证",
                ca_path.display()
            ),
            Self::Io(why) => write!(formatter, "装机 io: {why}"),
            Self::Tls(why) => write!(formatter, "装机 tls: {why}"),
            Self::Refused { status, message } => {
                write!(formatter, "云端拒绝装机（HTTP {status}）: {message}")
            }
            Self::BadResponse(why) => write!(formatter, "装机响应无法使用: {why}"),
            Self::Crypto(why) => write!(formatter, "装机生成密钥或 CSR 失败: {why}"),
        }
    }
}

impl std::error::Error for EnrollError {}

/// 三个文件的位置，都在同一个目录下。
#[derive(Clone, Debug)]
pub struct Paths {
    pub ca: PathBuf,
    pub certificate: PathBuf,
    pub key: PathBuf,
    pub code: PathBuf,
    /// 装机拿到的 device_id。
    ///
    /// 🔴 必须落盘。云端的身份来自**证书的 CN**（`identity.FromCertificate`），
    ///    而上行每一帧还会自报一个 device_id，网关逐帧比对：
    ///    `serve.go` 里 `envelope device_id does not match certificate` 就是
    ///    对不上时的那句话。agent 此前把 device_id 写成了一个硬编码常量
    ///    （`edge-bin` 里 6 处引用、没有 env 覆盖），所以一台**刚装机成功**的
    ///    机器会带着旧 id 去连，然后被逐帧拒掉 —— 装机看起来成功了，
    ///    上行永远连不上。这个文件就是为了让那两个值出自同一次装机。
    pub device_id: PathBuf,
}

impl Paths {
    pub fn in_dir(dir: impl AsRef<Path>) -> Self {
        let dir = dir.as_ref();
        Self {
            ca: dir.join("ca.crt"),
            certificate: dir.join("device.crt"),
            key: dir.join("device.key"),
            code: dir.join("enroll-code"),
            device_id: dir.join("device-id"),
        }
    }

    /// 只看文件在不在，不读内容 —— 这一步只回答「装机到哪了」。
    pub fn stage(&self) -> Stage {
        match (self.certificate.exists(), self.key.exists()) {
            (true, true) => Stage::Enrolled,
            (false, true) => Stage::KeyWithoutCertificate,
            _ => Stage::Fresh,
        }
    }
}

/// 一次装机产出的两份 PEM。
#[derive(Clone, Debug)]
pub struct Issued {
    pub device_id: String,
    pub certificate_pem: String,
    pub key_pem: String,
}

/// 生成一把新密钥和一份 CSR。
///
/// subject 清空（`SignCSR` 会忽略它，见下面那段注释）。不写 SAN、不写扩展：
/// 这份 CSR 唯一的作用是把公钥和一次自签名交给 CA。
pub fn new_key_and_csr() -> Result<(String, String), EnrollError> {
    let key = rcgen::KeyPair::generate().map_err(|err| EnrollError::Crypto(err.to_string()))?;
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())
        .map_err(|err| EnrollError::Crypto(err.to_string()))?;
    // 🔴 把 rcgen 的默认 DN 清空。它默认塞一个 `CN=rcgen self signed cert`
    //    （rcgen 0.13 的 CertificateParams::default），而 `SignCSR` 会忽略
    //    subject —— 于是那个字符串会以「身份」的样子出现在网关日志和任何看
    //    CSR 的地方，指向一个不存在的东西。真正的身份来自那个一次性码。
    params.distinguished_name = rcgen::DistinguishedName::new();
    let csr = params
        .serialize_request(&key)
        .map_err(|err| EnrollError::Crypto(err.to_string()))?;
    let csr_pem = csr
        .pem()
        .map_err(|err| EnrollError::Crypto(err.to_string()))?;
    Ok((key.serialize_pem(), csr_pem))
}

/// 请求体。抽成纯函数好测，也让「送了哪三个字段」一眼看得见。
pub fn request_body(tenant_id: &str, code: &str, csr_pem: &str) -> String {
    serde_json::json!({
        "tenant_id": tenant_id,
        "code": code,
        "csr": csr_pem,
    })
    .to_string()
}

/// 拆一份 HTTP/1.1 响应：状态码 + body。
///
/// ⚠️ 只认 `\r\n\r\n` 作为头体分界。宽松地也认 `\n\n` 会让一个畸形响应被
/// 当成正常的 —— 而这一步之后我们要把 body 当成证书写进磁盘。
pub fn split_response(raw: &str) -> Result<(u16, &str), EnrollError> {
    let (head, body) = raw
        .split_once("\r\n\r\n")
        .ok_or_else(|| EnrollError::BadResponse("响应里没有头体分界".into()))?;
    let status_line = head
        .lines()
        .next()
        .ok_or_else(|| EnrollError::BadResponse("响应没有状态行".into()))?;
    let code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|token| token.parse::<u16>().ok())
        .ok_or_else(|| {
            EnrollError::BadResponse(format!("状态行读不出状态码: {status_line:?}"))
        })?;
    Ok((code, body))
}

/// 解析签发结果。
///
/// 🔴 两个字段都必须**非空**才算成功。一张空证书写进磁盘之后，下一次启动会
///    看到「证书和私钥都在」（`Stage::Enrolled`），于是再也不会重试装机 ——
///    而上行会永远握手失败。空字符串在这里塌陷成一个合法状态，代价是永久锁死。
pub fn parse_issued(body: &str, key_pem: String) -> Result<Issued, EnrollError> {
    let value: serde_json::Value = serde_json::from_str(body)
        .map_err(|err| EnrollError::BadResponse(format!("不是 JSON: {err}")))?;
    let device_id = value
        .get("device_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string();
    let certificate_pem = value
        .get("certificate")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string();
    if device_id.is_empty() {
        return Err(EnrollError::BadResponse("device_id 是空的".into()));
    }
    if !certificate_pem.contains("BEGIN CERTIFICATE") {
        return Err(EnrollError::BadResponse(
            "certificate 不是一份 PEM 证书".into(),
        ));
    }
    Ok(Issued {
        device_id,
        certificate_pem,
        key_pem,
    })
}

/// 云端那句话。拒绝的时候它是给人读的，原样带出来。
fn refusal_message(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("error")
                .or_else(|| value.get("message"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| body.trim().chars().take(200).collect())
}

/// `https://host[:port]/path` 拆成三段。
fn parse_https(url: &str) -> Result<(String, String, String), EnrollError> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| EnrollError::BadResponse(format!("装机地址必须是 https://: {url}")))?;
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority.to_string(), format!("/{path}")),
        None => (rest.to_string(), "/".to_string()),
    };
    let host = authority
        .rsplit_once(':')
        .map(|(host, _)| host.to_string())
        .unwrap_or_else(|| authority.clone());
    let target = if authority.contains(':') {
        authority
    } else {
        format!("{host}:443")
    };
    Ok((host, target, path))
}

/// 发一次 `POST`，拿回状态码和 body。TLS 1.3、单向验服务端。
fn post(
    url: &str,
    body: &str,
    tls: Arc<ClientConfig>,
) -> Result<(u16, String), EnrollError> {
    let (host, target, path) = parse_https(url)?;
    let address = target
        .to_socket_addrs()
        .map_err(|err| EnrollError::Io(err.to_string()))?
        .next()
        .ok_or_else(|| EnrollError::Io(format!("解析不出地址: {target}")))?;
    let tcp = TcpStream::connect_timeout(&address, ENROLL_TIMEOUT)
        .map_err(|err| EnrollError::Io(err.to_string()))?;
    tcp.set_read_timeout(Some(ENROLL_TIMEOUT))
        .map_err(|err| EnrollError::Io(err.to_string()))?;
    tcp.set_write_timeout(Some(ENROLL_TIMEOUT))
        .map_err(|err| EnrollError::Io(err.to_string()))?;
    let server_name = ServerName::try_from(host.clone())
        .map_err(|_| EnrollError::Tls(format!("服务器名不可用: {host}")))?;
    let connection =
        ClientConnection::new(tls, server_name).map_err(|err| EnrollError::Tls(err.to_string()))?;
    let mut stream = StreamOwned::new(connection, tcp);
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|err| EnrollError::Io(err.to_string()))?;
    stream
        .flush()
        .map_err(|err| EnrollError::Io(err.to_string()))?;
    let mut raw = String::new();
    std::io::Read::take(&mut stream, MAX_RESPONSE_BYTES)
        .read_to_string(&mut raw)
        .map_err(|err| EnrollError::Io(err.to_string()))?;
    let (status, response_body) = split_response(&raw)?;
    Ok((status, response_body.to_string()))
}

/// 装机阶段的 TLS：验服务端，**不**带客户端证书（那时还没有）。
fn bootstrap_tls(ca_pem: &[u8]) -> Result<Arc<ClientConfig>, EnrollError> {
    let anchors = crate::tls::certificates_from_pem(ca_pem)
        .map_err(|err| EnrollError::Tls(err.to_string()))?;
    if anchors.is_empty() {
        return Err(EnrollError::Tls("ca.crt 里没有证书".into()));
    }
    crate::tls::bootstrap_config(anchors).map_err(|err| EnrollError::Tls(err.to_string()))
}

/// 把两份 PEM 落盘。私钥 0600，证书 0644。
///
/// 🔴 先写临时文件再 rename，而且**私钥先落**。中途断电的话得到的是
///    「有私钥、没有证书」——`Stage::KeyWithoutCertificate`，那个状态会说出
///    「码已经被消费了，去拿一个新的」。反过来（证书先落）得到的是
///    「证书和私钥都在」，下一次启动会认为装机完成，而那张证书没有对应的私钥，
///    上行永远握手失败 —— 一个看起来正常的永久故障。
fn write_identity(paths: &Paths, issued: &Issued) -> Result<(), EnrollError> {
    write_private(&paths.key, issued.key_pem.as_bytes())?;
    write_public(&paths.certificate, issued.certificate_pem.as_bytes())?;
    // device_id 和证书一起落。它不是秘密（就在证书的 CN 里），落盘只是为了
    // 让 agent 自报的那个值和证书出自同一次装机。
    write_public(&paths.device_id, issued.device_id.as_bytes())?;
    Ok(())
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), EnrollError> {
    write_atomic(path, bytes, 0o600)
}

fn write_public(path: &Path, bytes: &[u8]) -> Result<(), EnrollError> {
    write_atomic(path, bytes, 0o644)
}

fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<(), EnrollError> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let temporary = path.with_extension("tmp");
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&temporary)
            .map_err(|err| EnrollError::Io(format!("{}: {err}", temporary.display())))?;
        file.write_all(bytes)
            .map_err(|err| EnrollError::Io(err.to_string()))?;
        // fsync：rename 保证的是原子替换，不保证内容已经落到盘上。
        file.sync_all()
            .map_err(|err| EnrollError::Io(err.to_string()))?;
    }
    std::fs::rename(&temporary, path)
        .map_err(|err| EnrollError::Io(format!("{}: {err}", path.display())))?;
    Ok(())
}

/// 读装机凭据：租户 id 和一次性码，空白分隔（同一行或分两行都行）。
///
/// ⚠️ 只有一个 token 时**不猜**。把它当成码、租户留空的话，云端会回一个
/// 「tenant_id and code are required」——那句话在装机现场读起来像「码不对」，
/// 而运维手上的码是好的，他会一直换码。
pub fn parse_credential(raw: &str) -> Option<(String, String)> {
    let mut tokens = raw.split_whitespace();
    let tenant = tokens.next()?.to_string();
    let code = tokens.next()?.to_string();
    if tenant.is_empty() || code.is_empty() || tokens.next().is_some() {
        return None;
    }
    Some((tenant, code))
}

fn read_credential(path: &Path) -> Option<(String, String)> {
    parse_credential(&std::fs::read_to_string(path).ok()?)
}

/// 从上行地址推出装机地址。
///
/// 🔴 不另设一个环境变量。两个地址分两处配，就会有一天它们指向不同的部署 ——
///    而那一天的症状是「装机成功了，但上行连不上」，两条路各自都看起来正常。
///    装机和上行在同一个监听上（444，客户端证书是 VerifyClientCertIfGiven，
///    装机这一步按定义还没有证书）。
pub fn enroll_url_from_uplink(uplink: &str) -> Option<String> {
    let rest = uplink.strip_prefix("wss://")?;
    let authority = rest.split('/').next()?;
    if authority.is_empty() {
        return None;
    }
    Some(format!("https://{authority}/v1/enroll"))
}

/// 这台机器上行时该自报哪个 device_id。
///
/// 🔴 网关逐帧比对自报值和证书的 CN，对不上就断（`serve.go` 的
///    `envelope device_id does not match certificate`）。所以这个值**不能**是
///    一个编译期常量：一台刚装机的机器拿到的是新 UUID，而常量还是旧的。
///
/// 优先读 `device-id`（装机时写的）；没有就用调用方给的回落值 —— 那是
/// 手工装机时代的常量，对现役那台机器是对的（它那张手签证书的 CN 就是它）。
///
/// ⚠️ 用之前**核一遍**：这个 id 的字节必须真的出现在 device.crt 里。
///    这不是完整的 X.509 解析（这个 crate 里没有解析器），但它是一个不会
///    误杀的必要条件 —— CN 就是以这串字节存在证书里的。它挡住的是最现实的
///    那个事故：把一台机器的 device-id 或证书单独拷到另一台上。
pub fn device_id(dir: impl AsRef<Path>, fallback: &str) -> Result<String, EnrollError> {
    let paths = Paths::in_dir(dir);
    let chosen = std::fs::read_to_string(&paths.device_id)
        .ok()
        .map(|raw| raw.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| fallback.to_string());
    let pem = std::fs::read(&paths.certificate)
        .map_err(|err| EnrollError::Io(format!("{}: {err}", paths.certificate.display())))?;
    // 🔴 必须先解成 DER 再找。
    //
    // 这一行是拿一次 21 小时的上行停摆换来的（2026-09-10 10:42 → 2026-09-11
    // 07:32 UTC）。第一版直接在 `device.crt` 的字节里找那串 UUID —— 而
    // `device.crt` 是 **PEM**，内容是 base64，UUID 的字面字节从来不出现在
    // 里面。于是这道「核对」**每一次都触发**：uplink_loop 打一行 identity
    // 错误、睡 60 秒、continue，上行一次都没跑起来。
    //
    // ⚠️ 一道永远触发的检查不是「严格」，它是坏的。而这一次它坏的方向最糟：
    //    它挡住的是正常那条路，而日志上那句话说的是「这两个文件多半来自不同
    //    的机器」—— 一句把人引向完全错误方向的话。
    let der = certificates_der(&pem);
    if der.is_empty() {
        return Err(EnrollError::BadResponse(format!(
            "{} 里读不出证书",
            paths.certificate.display()
        )));
    }
    if !der.iter().any(|block| contains(block, chosen.as_bytes())) {
        return Err(EnrollError::BadResponse(format!(
            "device_id {chosen} 不在 {} 里 —— 自报的身份和证书对不上，\
             网关会逐帧拒掉这条连接（envelope device_id does not match certificate）。\
             这两个文件多半来自不同的机器",
            paths.certificate.display()
        )));
    }
    Ok(chosen)
}

/// 把一份 PEM 里所有 CERTIFICATE 块解成 DER。
///
/// 用 `crate::tls::certificates_from_pem` —— 上行那一侧读同一个文件用的就是
/// 它。自己写第二个解析器的话，两边对「什么算一份证书」的看法会分家。
fn certificates_der(pem: &[u8]) -> Vec<Vec<u8>> {
    crate::tls::certificates_from_pem(pem)
        .map(|certificates| {
            certificates
                .into_iter()
                .map(|certificate| certificate.as_ref().to_vec())
                .collect()
        })
        .unwrap_or_default()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|window| window == needle)
}

/// 确保这台机器有身份可用。
///
/// 已经有了就什么都不做。没有就用那个一次性码换一张，落盘，并删掉码。
///
/// 返回 `Ok(None)` 表示本来就有身份；`Ok(Some(id))` 表示这次刚装好。
pub fn ensure(dir: impl AsRef<Path>, url: &str) -> Result<Option<String>, EnrollError> {
    let paths = Paths::in_dir(dir);
    match paths.stage() {
        Stage::Enrolled => return Ok(None),
        Stage::KeyWithoutCertificate => {
            // 上一次在签发之后断了。那把旧密钥没有对应的证书，留着只会让
            // 下面的 stage() 一直报同一个状态 —— 删掉，从新密钥重来。
            let _ = std::fs::remove_file(&paths.key);
        }
        Stage::Fresh => {}
    }

    let (tenant_id, code) =
        read_credential(&paths.code).ok_or_else(|| EnrollError::NeedsCode {
            code_path: paths.code.clone(),
        })?;
    let ca_pem = std::fs::read(&paths.ca).map_err(|_| EnrollError::NeedsTrustAnchor {
        ca_path: paths.ca.clone(),
    })?;
    let tls = bootstrap_tls(&ca_pem)?;

    let (key_pem, csr_pem) = new_key_and_csr()?;
    let (status, body) = post(url, &request_body(&tenant_id, &code, &csr_pem), tls)?;
    if status != 200 {
        return Err(EnrollError::Refused {
            status,
            message: refusal_message(&body),
        });
    }
    let issued = parse_issued(&body, key_pem)?;
    write_identity(&paths, &issued)?;
    // 码是一次性的，而且已经被消费。留着它是一份没用的凭据，还会让人以为
    // 装机没完成。删不掉只落一条日志：身份已经好了，不该因此失败。
    if let Err(err) = std::fs::remove_file(&paths.code) {
        return Ok(Some(format!(
            "{} （注意：{} 删除失败: {err}，请手工删掉）",
            issued.device_id,
            paths.code.display()
        )));
    }
    Ok(Some(issued.device_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 生成的 CSR 必须是一份云端认得的 PEM。
    ///
    /// ⚠️ 云端 `ParseCSR` 只接受 `CERTIFICATE REQUEST` 这个 PEM 标签，并且会
    ///    验自签名。这里能在进程内断言的是标签和密钥格式；签名有效性由
    ///    `edge-uplink/tests/enroll_csr.rs` 那条跨语言测试对着网关的
    ///    真实解析器验（见那个文件的注释）。
    #[test]
    fn the_csr_carries_the_label_the_cloud_requires() {
        let (key_pem, csr_pem) = new_key_and_csr().expect("生成 CSR");
        assert!(
            csr_pem.contains("-----BEGIN CERTIFICATE REQUEST-----"),
            "云端只认 CERTIFICATE REQUEST 这个标签，实际是: {}",
            csr_pem.lines().next().unwrap_or("")
        );
        assert!(
            key_pem.contains("-----BEGIN PRIVATE KEY-----"),
            "上行那边用 PKCS#8 读私钥（private_key_from_pkcs8），标签必须是 PRIVATE KEY"
        );
    }

    /// 🔴 签名算法必须是 ECDSA P-256 / SHA-256。
    ///
    /// 这条和网关那边的 `TestParseCSRAcceptsTheAlgorithmTheEdgeEmits` 是**一对**：
    /// 一边钉住我们发的是什么，一边钉住云端收得下什么。两条都在，换算法的那天
    /// 必须同时改两处 —— 而只改一边的后果是装机在现场 400，且那句 400 读起来
    /// 像「码不对」。
    #[test]
    fn the_signature_algorithm_is_the_one_the_cloud_parses() {
        let key = rcgen::KeyPair::generate().expect("密钥");
        assert_eq!(
            key.algorithm(),
            &rcgen::PKCS_ECDSA_P256_SHA256,
            "换了签名算法。网关那边有一条成对的测试，两处要一起改"
        );
    }

    /// CSR 里不许留一个看起来像身份的 CN。
    ///
    /// ⚠️ rcgen 默认会塞 `CN=rcgen self signed cert`。`SignCSR` 忽略 subject，
    ///    所以它不影响签发 —— 但它会出现在网关日志和任何看 CSR 的地方，
    ///    指向一个不存在的东西。实测确认过：清空之前网关解析出来的 subject
    ///    就是那句话。
    #[test]
    fn the_csr_carries_no_pretend_identity() {
        let (_, csr_pem) = new_key_and_csr().expect("生成 CSR");
        let der = csr_pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<String>();
        let bytes = base64_decode(&der).expect("CSR 是 base64");
        let needle = b"rcgen self signed cert";
        assert!(
            !bytes.windows(needle.len()).any(|window| window == needle),
            "CSR 里留着 rcgen 的默认 CN —— 它会以身份的样子出现在网关日志里"
        );
    }

    /// 只为上面那条断言写的最小 base64 解码。
    fn base64_decode(input: &str) -> Option<Vec<u8>> {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = Vec::new();
        let mut buffer = 0u32;
        let mut bits = 0u32;
        for byte in input.bytes() {
            if byte == b'=' {
                break;
            }
            let value = TABLE.iter().position(|candidate| *candidate == byte)? as u32;
            buffer = (buffer << 6) | value;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push(((buffer >> bits) & 0xff) as u8);
            }
        }
        Some(out)
    }

    /// 每次装机都要一把新密钥。
    #[test]
    fn every_enrolment_gets_a_fresh_key() {
        let (first, _) = new_key_and_csr().expect("第一把");
        let (second, _) = new_key_and_csr().expect("第二把");
        assert_ne!(first, second, "两次装机拿到了同一把私钥");
    }

    /// 请求体必须带齐云端要的三个字段。
    ///
    /// 🔴 少一个的后果不是报错而是 400，而 400 在装机现场读起来像「码不对」。
    #[test]
    fn the_request_carries_all_three_fields() {
        let body = request_body("a0000000-0000-4000-8000-00000000000a", "CODE-1", "PEM");
        let value: serde_json::Value = serde_json::from_str(&body).expect("请求体是 JSON");
        for field in ["tenant_id", "code", "csr"] {
            assert!(
                value.get(field).and_then(serde_json::Value::as_str).is_some(),
                "请求体少了 {field}"
            );
        }
    }

    /// 🔴 空证书不许当成成功。
    ///
    /// 写进磁盘之后，下一次启动会看到「证书和私钥都在」，于是**再也不会重试
    /// 装机**，而上行会永远握手失败。空字符串在这里塌陷成一个合法状态，
    /// 代价是永久锁死 —— 这正是这个仓库反复在防的形状。
    #[test]
    fn an_empty_certificate_is_not_a_successful_enrolment() {
        let err = parse_issued(r#"{"device_id":"d","certificate":""}"#, "k".into())
            .expect_err("空证书被当成了签发成功");
        assert!(matches!(err, EnrollError::BadResponse(_)), "{err:?}");

        let err = parse_issued(r#"{"device_id":"","certificate":"-----BEGIN CERTIFICATE-----"}"#, "k".into())
            .expect_err("空 device_id 被当成了签发成功");
        assert!(matches!(err, EnrollError::BadResponse(_)), "{err:?}");

        // 不是 PEM 的东西也不行：写进去之后同样是永久锁死。
        let err = parse_issued(r#"{"device_id":"d","certificate":"not a pem"}"#, "k".into())
            .expect_err("非 PEM 被当成了证书");
        assert!(matches!(err, EnrollError::BadResponse(_)), "{err:?}");
    }

    /// 三种装机阶段各有各的说法。
    ///
    /// 🔴 「有私钥、没有证书」必须和「什么都没有」分开：前者意味着那个一次性码
    ///    **已经被云端消费掉了**，重试同一个码只会被拒。合成一句的话，运维会
    ///    反复重启 agent 等一个永远不会来的结果。
    #[test]
    fn a_consumed_code_looks_different_from_a_fresh_machine() {
        let dir = std::env::temp_dir().join(format!("vodoge-enroll-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("临时目录");
        let paths = Paths::in_dir(&dir);
        let _ = std::fs::remove_file(&paths.key);
        let _ = std::fs::remove_file(&paths.certificate);

        assert_eq!(paths.stage(), Stage::Fresh);

        std::fs::write(&paths.key, "k").expect("写私钥");
        assert_eq!(
            paths.stage(),
            Stage::KeyWithoutCertificate,
            "有私钥没证书被当成了一台全新机器 —— 那个码其实已经被消费了"
        );

        std::fs::write(&paths.certificate, "c").expect("写证书");
        assert_eq!(paths.stage(), Stage::Enrolled);

        let _ = std::fs::remove_file(&paths.key);
        let _ = std::fs::remove_file(&paths.certificate);
    }

    /// 已经有身份的机器不该再去装机。
    ///
    /// ⚠️ 会去的后果不是多一次请求：它会消费掉一个码，并且用一把新密钥覆盖
    ///    现役私钥 —— 一台正在服务的机器被自己的启动流程踢下线。
    #[test]
    fn an_enrolled_machine_does_not_enrol_again() {
        let dir = std::env::temp_dir().join(format!("vodoge-enrolled-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("临时目录");
        let paths = Paths::in_dir(&dir);
        std::fs::write(&paths.key, "k").expect("写私钥");
        std::fs::write(&paths.certificate, "c").expect("写证书");
        // 地址故意是个不可能连上的端口：真去连了这条断言就会失败。
        let outcome = ensure(&dir, "https://127.0.0.1:1/v1/enroll");
        assert!(
            matches!(outcome, Ok(None)),
            "已经装机过的机器又去装了一次: {outcome:?}"
        );
        let _ = std::fs::remove_file(&paths.key);
        let _ = std::fs::remove_file(&paths.certificate);
    }

    /// 没有码的时候，说的是「去哪拿、放哪里」。
    #[test]
    fn a_machine_without_a_code_says_where_to_put_one() {
        let dir = std::env::temp_dir().join(format!("vodoge-nocode-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("临时目录");
        let err = ensure(&dir, "https://127.0.0.1:1/v1/enroll")
            .expect_err("没有码却装机成功了");
        match &err {
            EnrollError::NeedsCode { code_path } => {
                assert!(code_path.ends_with("enroll-code"), "{code_path:?}");
            }
            other => panic!("应当是 NeedsCode: {other:?}"),
        }
        let said = err.to_string();
        assert!(said.contains("enroll-code"), "没说码放哪个文件: {said}");
        assert!(said.contains("控制台"), "没说去哪生成: {said}");
    }

    /// 缺 CA 的时候**不降级成不验证**。
    ///
    /// 🔴 装机是把私钥交出去之前唯一能确认对方身份的机会。这里一旦回落到
    ///    「不验证服务端」，一个能抢到那个地址的人就能签发一张自己的证书。
    #[test]
    fn a_missing_ca_is_refused_rather_than_skipped() {
        let dir = std::env::temp_dir().join(format!("vodoge-noca-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("临时目录");
        let paths = Paths::in_dir(&dir);
        std::fs::write(&paths.code, "a0000000-0000-4000-8000-00000000000a CODE-1").expect("写凭据");
        let _ = std::fs::remove_file(&paths.ca);
        let err = ensure(&dir, "https://127.0.0.1:1/v1/enroll")
            .expect_err("没有 CA 却继续装机了");
        assert!(
            matches!(err, EnrollError::NeedsTrustAnchor { .. }),
            "缺 CA 时没有停下来: {err:?}"
        );
        let _ = std::fs::remove_file(&paths.code);
    }

    /// 🔴 自报的 device_id 必须来自这次装机，不能是编译期常量。
    ///
    /// 网关逐帧比对自报值和证书的 CN（`serve.go` 的
    /// `envelope device_id does not match certificate`）。而 agent 此前把它
    /// 写成一个硬编码常量、6 处引用、没有 env 覆盖 —— 于是一台**刚装机成功**
    /// 的机器会带着旧 id 去连，然后每一帧被拒。
    ///
    /// ⚠️ 这条断言喂的是**一份真证书**，不是一段含有 UUID 字样的假字符串。
    ///    第一版喂的是 `"junk CN=b0000000-old junk"`，于是它完全没有发现
    ///    `device.crt` 是 PEM（base64）——那道核对在生产上每一次都触发，
    ///    上行被自己的守卫挡了 21 小时（2026-09-10 10:42 → 09-11 07:32 UTC）。
    ///    一个用假数据喂出来的绿灯，比没有这条断言更坏。
    #[test]
    fn the_reported_device_id_comes_from_this_enrolment() {
        let dir = std::env::temp_dir().join(format!("vodoge-devid-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("临时目录");
        let paths = Paths::in_dir(&dir);

        // 真造两张证书，CN 分别是两个 id。
        let old_id = "b0000000-0000-4000-8000-00000000000b";
        let new_id = "b2099b3f-25de-4299-aae0-dfb7e4ea5637";
        let old_pem = self_signed_pem(old_id);
        let new_pem = self_signed_pem(new_id);

        // 手工装机时代：没有 device-id 文件，证书的 CN 就是那个回落常量。
        std::fs::write(&paths.certificate, &old_pem).expect("写证书");
        let _ = std::fs::remove_file(&paths.device_id);
        assert_eq!(
            device_id(&dir, old_id).expect("回落"),
            old_id,
            "没有 device-id 文件时应当回落到常量"
        );

        // 装机之后：device-id 文件说了话，而且证书里确实是它。
        std::fs::write(&paths.certificate, &new_pem).expect("写证书");
        std::fs::write(&paths.device_id, format!("{new_id}\n")).expect("写 id");
        assert_eq!(
            device_id(&dir, old_id).expect("读文件"),
            new_id,
            "装机写下的 id 没有覆盖掉那个常量 —— 那台机器会带着旧 id 去连"
        );

        // 🔴 两个文件来自不同机器时，停下来。
        std::fs::write(&paths.certificate, &old_pem).expect("写证书");
        std::fs::write(&paths.device_id, new_id).expect("写 id");
        let err = device_id(&dir, old_id).expect_err("身份不一致却继续了");
        let said = err.to_string();
        assert!(
            said.contains("对不上") && said.contains("不同的机器"),
            "没说清是身份对不上、也没说清多半是文件拷错了: {said}"
        );

        for path in [&paths.certificate, &paths.device_id] {
            let _ = std::fs::remove_file(path);
        }
    }

    /// 造一张 CN 是 `common_name` 的自签证书，PEM 形式 —— 和生产上那个文件
    /// 同一种格式。
    fn self_signed_pem(common_name: &str) -> Vec<u8> {
        let key = rcgen::KeyPair::generate().expect("密钥");
        let mut params =
            rcgen::CertificateParams::new(Vec::<String>::new()).expect("参数");
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, common_name);
        params
            .self_signed(&key)
            .expect("自签")
            .pem()
            .into_bytes()
    }

    /// 装机凭据只有一个 token 时，不许猜。
    ///
    /// 🔴 把它当成码、租户留空的话，云端回的是「tenant_id and code are required」
    ///    —— 那句话在装机现场读起来像「码不对」，而运维手上的码是好的。
    ///    他会去换码，换多少个都一样。
    #[test]
    fn a_credential_missing_the_tenant_is_not_guessed_at() {
        assert_eq!(
            parse_credential("a0000000-0000-4000-8000-00000000000a CODE-1"),
            Some((
                "a0000000-0000-4000-8000-00000000000a".to_string(),
                "CODE-1".to_string()
            ))
        );
        // 分两行也行 —— 复制粘贴很容易带上换行。
        assert!(parse_credential("tenant\nCODE-1").is_some());
        // 只有码：拒。
        assert_eq!(parse_credential("CODE-1"), None, "只有一个 token 却被当成了完整凭据");
        assert_eq!(parse_credential(""), None);
        assert_eq!(parse_credential("   "), None);
        // 多出来的东西也拒：三个 token 说明格式理解错了，而猜错的那一半是租户。
        assert_eq!(parse_credential("tenant CODE-1 extra"), None);
    }

    /// 装机地址从上行地址推出来，不另配一个。
    ///
    /// ⚠️ 分两处配的后果是有一天它们指向不同的部署，而症状是「装机成功了，
    ///    但上行连不上」—— 两条路各自都看起来正常。
    #[test]
    fn the_enrol_url_comes_from_the_uplink_url() {
        assert_eq!(
            enroll_url_from_uplink("wss://43.108.53.126:444/v1/edge").as_deref(),
            Some("https://43.108.53.126:444/v1/enroll")
        );
        assert_eq!(
            enroll_url_from_uplink("wss://gw.example.com/v1/edge").as_deref(),
            Some("https://gw.example.com/v1/enroll")
        );
        // 不是 wss 的就说不知道，不要凑一个出来。
        assert_eq!(enroll_url_from_uplink("https://x/v1/edge"), None);
        assert_eq!(enroll_url_from_uplink("wss:///v1/edge"), None);
    }

    /// HTTP 响应拆不出头体分界时，不许猜。
    #[test]
    fn a_malformed_response_is_refused() {
        assert!(split_response("HTTP/1.1 200 OK\n\n{}").is_err(), "认了 \\n\\n");
        assert!(split_response("garbage").is_err());
        let (status, body) = split_response("HTTP/1.1 403 Forbidden\r\n\r\n{\"error\":\"no\"}")
            .expect("正常响应");
        assert_eq!(status, 403);
        assert_eq!(body, "{\"error\":\"no\"}");
    }

    /// 云端拒绝时那句话要原样带出来。
    #[test]
    fn the_cloud_refusal_is_passed_through() {
        assert_eq!(refusal_message(r#"{"error":"code already used"}"#), "code already used");
        assert_eq!(refusal_message("plain text refusal"), "plain text refusal");
    }
}
