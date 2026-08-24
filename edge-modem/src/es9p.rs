//! ES9+: the HTTPS interface between this device and an SM-DP+.
//!
//! Only `InitiateAuthentication` lives here so far, and that is a deliberate
//! boundary rather than an unfinished one. It is the single ES9+ function that
//! needs no activation code and has no effect on anyone's account: it hands an
//! SM-DP+ a challenge the chip just generated and gets back a signed answer.
//! Everything it exercises — DNS, TLS against the GSMA CI, the ES9+ envelope,
//! and the chip's own `GetEUICCChallenge`/`GetEUICCInfo1` — is the part of a
//! profile download that can be proven against a production server today.
//!
//! ## Why this is on the edge and not in the cloud
//!
//! The eUICC is here. An RSP session is a synchronous conversation in which
//! every server answer is bound to a challenge the chip produced moments
//! earlier, and the profile package that ends it has to be fed to the card in
//! 255-byte `STORE DATA` blocks. Running the HTTPS half in the cloud would
//! turn each of those steps into a round trip over the command relay, whose
//! dispatch-execute-receipt model is asynchronous by design. SGP.22 puts ES9+
//! and ES10 in the same component for the same reason.
//!
//! ## Trust
//!
//! An SM-DP+ does not present a browser-trusted certificate. The bench server
//! answers with a Thales certificate issued directly by *GSM Association -
//! RSP2 Root CI1*, and a system trust store rejects it with "self-signed
//! certificate in certificate chain". So the CI roots are supplied as files
//! rather than compiled in: they expire, they rotate, and a fleet that has to
//! be rebuilt to accept a new CI is a fleet that stops downloading profiles on
//! a date nobody wrote down. See [`trust_dir`].
//!
//! Turning verification off is not an option this module offers. There is no
//! flag for it, because the whole value of reaching a real SM-DP+ is that the
//! chain held.

use std::fmt;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

/// Where the GSMA CI roots live when nothing overrides it.
///
/// Outside the binary on purpose: a CI root is an asset with an expiry date,
/// and replacing one should be dropping a file next to the others rather than
/// a release.
pub const DEFAULT_TRUST_DIR: &str = "/etc/vodoge/rsp-trust";

/// Environment variable that moves the trust directory, for tests and for a
/// bring-up box that is not laid out like the fleet.
pub const TRUST_DIR_ENV: &str = "VODOGE_RSP_TRUST_DIR";

/// SGP.22 ES9+ path for `InitiateAuthentication`.
pub const INITIATE_AUTHENTICATION_PATH: &str = "/gsma/rsp2/es9plus/initiateAuthentication";

/// The `X-Admin-Protocol` an SGP.22 v2.2 LPA announces.
pub const ADMIN_PROTOCOL: &str = "gsma/rsp/v2.2.0";

/// The `User-Agent` SGP.22 section 6.1 prescribes for an LPA in the device.
pub const USER_AGENT: &str = "gsma-rsp-lpad";

const HTTPS_PORT: u16 = 443;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const IO_TIMEOUT: Duration = Duration::from_secs(30);
/// A refusal from an SM-DP+ is small and a signed answer is a couple of
/// kilobytes. Anything past this is not an ES9+ answer.
const MAX_RESPONSE_BYTES: usize = 1 << 20;

/// SGP.22 tags inside `ServerSigned1`.
const TAG_TRANSACTION_ID: &[u8] = &[0x80];
const TAG_ECHOED_CHALLENGE: &[u8] = &[0x81];
const TAG_SERVER_ADDRESS: &[u8] = &[0x83];
const TAG_SERVER_CHALLENGE: &[u8] = &[0x84];
/// `[APPLICATION 55]`, the wrapper SGP.22 puts around a raw ECDSA signature.
const TAG_SIGNATURE: &[u8] = &[0x5f, 0x37];
/// An ECDSA P-256 signature as `r || s`.
const P256_SIGNATURE_BYTES: usize = 64;

/// Everything that can go wrong between here and an SM-DP+.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Es9pError {
    /// No CI roots on disk. Reported by name so the fix is obvious.
    NoTrustAnchors { dir: String },
    TrustDirUnreadable { dir: String, reason: String },
    /// A file in the trust directory is not a certificate.
    TrustAnchorUnusable { file: String, reason: String },
    InvalidHost { host: String },
    ResolveFailed { host: String, reason: String },
    ConnectFailed { host: String, reason: String },
    /// The TLS handshake failed. On this path that usually means the server
    /// certificate did not chain to any CI root we hold, which is the check
    /// working rather than the network being broken.
    TlsFailed { host: String, reason: String },
    IoFailed { reason: String },
    /// The response was not HTTP the way this client can read it.
    MalformedHttp { reason: String },
    HttpStatus { status: u16, body: String },
    MalformedJson { reason: String },
    /// The SM-DP+ understood the request and refused it.
    FunctionFailed {
        status: String,
        subject_code: Option<String>,
        reason_code: Option<String>,
        message: Option<String>,
    },
    MissingField { name: &'static str },
    BadBase64 { field: &'static str },
    /// The `ServerSigned1` structure did not decode.
    MalformedServerSigned { reason: String },
    /// The server echoed a challenge that is not the one this chip produced.
    ///
    /// A replayed answer from an earlier session would pass every other check
    /// here, so this one is what ties the exchange to this card, right now.
    ChallengeMismatch { sent: String, echoed: String },
    /// The server signed an address other than the one we asked.
    AddressMismatch { asked: String, signed: String },
    /// The signing certificate names an authority that is not among the CI
    /// roots we trust.
    UntrustedCertificateAuthority { authority_key_id: String },
    /// A certificate could not be read far enough to check it.
    MalformedCertificate { reason: String },
    /// The CI root did not sign this certificate.
    CertificateSignatureInvalid,
    /// The certificate's key did not sign `ServerSigned1`.
    ServerSignatureInvalid,
}

impl fmt::Display for Es9pError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoTrustAnchors { dir } => write!(
                formatter,
                "no GSMA CI root certificates in {dir}; an SM-DP+ cannot be verified without one"
            ),
            Self::TrustDirUnreadable { dir, reason } => {
                write!(formatter, "cannot read trust directory {dir}: {reason}")
            }
            Self::TrustAnchorUnusable { file, reason } => {
                write!(formatter, "trust anchor {file}: {reason}")
            }
            Self::InvalidHost { host } => write!(formatter, "{host} is not a usable host name"),
            Self::ResolveFailed { host, reason } => {
                write!(formatter, "cannot resolve {host}: {reason}")
            }
            Self::ConnectFailed { host, reason } => {
                write!(formatter, "cannot connect to {host}: {reason}")
            }
            Self::TlsFailed { host, reason } => write!(
                formatter,
                "TLS to {host} failed against the GSMA CI roots: {reason}"
            ),
            Self::IoFailed { reason } => write!(formatter, "transfer failed: {reason}"),
            Self::MalformedHttp { reason } => write!(formatter, "malformed HTTP response: {reason}"),
            Self::HttpStatus { status, body } => {
                write!(formatter, "SM-DP+ answered HTTP {status}: {body}")
            }
            Self::MalformedJson { reason } => write!(formatter, "malformed ES9+ JSON: {reason}"),
            Self::FunctionFailed {
                status,
                subject_code,
                reason_code,
                message,
            } => {
                write!(formatter, "SM-DP+ refused the request: {status}")?;
                if let Some(code) = subject_code {
                    write!(formatter, " subject {code}")?;
                }
                if let Some(code) = reason_code {
                    write!(formatter, " reason {code}")?;
                }
                if let Some(text) = message {
                    write!(formatter, " ({text})")?;
                }
                Ok(())
            }
            Self::MissingField { name } => write!(formatter, "ES9+ answer has no {name}"),
            Self::BadBase64 { field } => write!(formatter, "{field} is not valid base64"),
            Self::MalformedServerSigned { reason } => {
                write!(formatter, "malformed serverSigned1: {reason}")
            }
            Self::ChallengeMismatch { sent, echoed } => write!(
                formatter,
                "SM-DP+ echoed challenge {echoed}, this eUICC produced {sent}"
            ),
            Self::AddressMismatch { asked, signed } => write!(
                formatter,
                "SM-DP+ signed the address {signed} for a request sent to {asked}"
            ),
            Self::UntrustedCertificateAuthority { authority_key_id } => write!(
                formatter,
                "SM-DP+ certificate names CI key {authority_key_id}, which is not among the roots we hold"
            ),
            Self::MalformedCertificate { reason } => {
                write!(formatter, "malformed certificate: {reason}")
            }
            Self::CertificateSignatureInvalid => {
                formatter.write_str("the GSMA CI root did not sign the SM-DP+ certificate")
            }
            Self::ServerSignatureInvalid => {
                formatter.write_str("serverSignature1 does not match serverSigned1")
            }
        }
    }
}

impl std::error::Error for Es9pError {}

/// One GSMA CI root, with the facts an operator needs to recognise it.
///
/// The fingerprint and expiry are carried rather than derived at the point of
/// use so the console can render *which* root a session was verified against.
/// "TLS succeeded" without naming the anchor is the kind of green tick that
/// survives someone quietly adding a root nobody meant to trust.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustAnchor {
    /// File name it was loaded from.
    pub label: String,
    /// SHA-256 of the DER, lowercase hex.
    pub sha256: String,
    /// Subject key identifier, uppercase hex. This is the value an eUICC
    /// reports in `euiccCiPKIdListForVerification` and an SM-DP+ returns as
    /// `euiccCiPKIdToBeUsed`, so it is what makes the three agree or not.
    pub key_id: String,
    /// `notAfter` as ASN.1 wrote it, for example `20520221235959Z`.
    pub not_after: String,
    pub der: CertificateDer<'static>,
}

/// The trust directory in force: `VODOGE_RSP_TRUST_DIR`, else the default.
pub fn trust_dir() -> PathBuf {
    match std::env::var(TRUST_DIR_ENV) {
        Ok(value) if !value.trim().is_empty() => PathBuf::from(value),
        _ => PathBuf::from(DEFAULT_TRUST_DIR),
    }
}

/// Read every PEM certificate in `dir`.
///
/// An unreadable or non-certificate file is an error rather than a skip. A
/// trust directory that silently ignored the file someone just installed
/// would fail later, at a server, with a message about TLS.
pub fn load_trust_anchors(dir: &Path) -> Result<Vec<TrustAnchor>, Es9pError> {
    let entries = std::fs::read_dir(dir).map_err(|error| Es9pError::TrustDirUnreadable {
        dir: dir.display().to_string(),
        reason: error.to_string(),
    })?;
    let mut files: Vec<PathBuf> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| Es9pError::TrustDirUnreadable {
            dir: dir.display().to_string(),
            reason: error.to_string(),
        })?;
        let path = entry.path();
        let is_pem = path
            .extension()
            .and_then(|value| value.to_str())
            .map(|value| value.eq_ignore_ascii_case("pem") || value.eq_ignore_ascii_case("crt"))
            .unwrap_or(false);
        if path.is_file() && is_pem {
            files.push(path);
        }
    }
    files.sort();

    let mut anchors = Vec::new();
    for path in files {
        let label = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("?")
            .to_string();
        let bytes = std::fs::read(&path).map_err(|error| Es9pError::TrustAnchorUnusable {
            file: label.clone(),
            reason: error.to_string(),
        })?;
        for der in pem_certificates(&bytes, &label)? {
            anchors.push(describe_anchor(label.clone(), der)?);
        }
    }
    if anchors.is_empty() {
        return Err(Es9pError::NoTrustAnchors {
            dir: dir.display().to_string(),
        });
    }
    Ok(anchors)
}

fn pem_certificates(bytes: &[u8], label: &str) -> Result<Vec<CertificateDer<'static>>, Es9pError> {
    let mut reader = std::io::BufReader::new(bytes);
    let mut out = Vec::new();
    for item in rustls_pemfile::certs(&mut reader) {
        out.push(item.map_err(|error| Es9pError::TrustAnchorUnusable {
            file: label.to_string(),
            reason: error.to_string(),
        })?);
    }
    if out.is_empty() {
        return Err(Es9pError::TrustAnchorUnusable {
            file: label.to_string(),
            reason: "no CERTIFICATE block".into(),
        });
    }
    Ok(out)
}

fn describe_anchor(label: String, der: CertificateDer<'static>) -> Result<TrustAnchor, Es9pError> {
    let parsed = Certificate::parse(der.as_ref())?;
    Ok(TrustAnchor {
        label,
        sha256: sha256_hex(der.as_ref()),
        key_id: parsed
            .subject_key_id
            .clone()
            .unwrap_or_else(|| "unknown".into()),
        not_after: parsed.not_after.clone(),
        der,
    })
}

/// A blocking ES9+ client pinned to a set of GSMA CI roots.
pub struct Es9pClient {
    anchors: Vec<TrustAnchor>,
    tls: Arc<ClientConfig>,
}

impl Es9pClient {
    /// Build a client that will only talk to servers these roots vouch for.
    pub fn new(anchors: Vec<TrustAnchor>) -> Result<Self, Es9pError> {
        if anchors.is_empty() {
            return Err(Es9pError::NoTrustAnchors {
                dir: "(none supplied)".into(),
            });
        }
        let mut roots = RootCertStore::empty();
        for anchor in &anchors {
            roots
                .add(anchor.der.clone())
                .map_err(|error| Es9pError::TrustAnchorUnusable {
                    file: anchor.label.clone(),
                    reason: error.to_string(),
                })?;
        }
        // TLS 1.2 stays enabled. SGP.22 requires 1.2 as the floor and some
        // SM-DP+ deployments still stop there; the bench server negotiates
        // 1.3 and would not notice either way.
        let mut config = ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|error| Es9pError::TlsFailed {
            host: "(configuration)".into(),
            reason: error.to_string(),
        })?
        .with_root_certificates(roots)
        .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            anchors,
            tls: Arc::new(config),
        })
    }

    /// Build a client from the trust directory in force.
    pub fn from_trust_dir(dir: &Path) -> Result<Self, Es9pError> {
        Self::new(load_trust_anchors(dir)?)
    }

    pub fn anchors(&self) -> &[TrustAnchor] {
        &self.anchors
    }

    /// ES9+ `InitiateAuthentication` against a real SM-DP+.
    ///
    /// Read-only at both ends: the chip supplied the challenge before this was
    /// called, and the server is being asked to identify itself, not to
    /// prepare or release anything.
    pub fn initiate_authentication(
        &self,
        host: &str,
        euicc_challenge: &[u8],
        euicc_info1: &[u8],
    ) -> Result<AuthenticationStart, Es9pError> {
        let body = initiate_authentication_request(host, euicc_challenge, euicc_info1);
        let started = Instant::now();
        let response = self.post_json(host, INITIATE_AUTHENTICATION_PATH, body.as_bytes())?;
        let elapsed_ms = started.elapsed().as_millis() as u64;
        let mut start = parse_initiate_authentication(&response.body)?;
        start.smdp_address = host.to_string();
        start.http_status = response.status;
        start.admin_protocol = response.header("x-admin-protocol");
        start.elapsed_ms = elapsed_ms;
        start.negotiated_tls = response.tls_version.clone();
        let verified = verify_server_credentials(&start, host, euicc_challenge, &self.anchors)?;
        start.verification = verified;
        Ok(start)
    }

    /// POST a JSON body over TLS and read the whole answer.
    pub fn post_json(&self, host: &str, path: &str, body: &[u8]) -> Result<HttpResponse, Es9pError> {
        let server_name = ServerName::try_from(host.to_string()).map_err(|_| {
            Es9pError::InvalidHost {
                host: host.to_string(),
            }
        })?;
        let address = (host, HTTPS_PORT)
            .to_socket_addrs()
            .map_err(|error| Es9pError::ResolveFailed {
                host: host.to_string(),
                reason: error.to_string(),
            })?
            .next()
            .ok_or_else(|| Es9pError::ResolveFailed {
                host: host.to_string(),
                reason: "no addresses".into(),
            })?;
        let socket = TcpStream::connect_timeout(&address, CONNECT_TIMEOUT).map_err(|error| {
            Es9pError::ConnectFailed {
                host: host.to_string(),
                reason: error.to_string(),
            }
        })?;
        socket
            .set_read_timeout(Some(IO_TIMEOUT))
            .and_then(|()| socket.set_write_timeout(Some(IO_TIMEOUT)))
            .map_err(|error| Es9pError::IoFailed {
                reason: error.to_string(),
            })?;

        let connection =
            ClientConnection::new(Arc::clone(&self.tls), server_name).map_err(|error| {
                Es9pError::TlsFailed {
                    host: host.to_string(),
                    reason: error.to_string(),
                }
            })?;
        let mut stream = StreamOwned::new(connection, socket);

        let mut request = Vec::with_capacity(body.len() + 256);
        // `Connection: close` on purpose: one exchange per session, and the
        // server closing is what marks the end of the body when a proxy
        // decides to answer without a Content-Length.
        request.extend_from_slice(
            format!(
                "POST {path} HTTP/1.1\r\n\
                 Host: {host}\r\n\
                 User-Agent: {USER_AGENT}\r\n\
                 X-Admin-Protocol: {ADMIN_PROTOCOL}\r\n\
                 Content-Type: application/json\r\n\
                 Accept: application/json\r\n\
                 Content-Length: {length}\r\n\
                 Connection: close\r\n\r\n",
                length = body.len()
            )
            .as_bytes(),
        );
        request.extend_from_slice(body);
        stream
            .write_all(&request)
            .and_then(|()| stream.flush())
            .map_err(|error| tls_or_io(host, error))?;

        let mut raw = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(read) => {
                    raw.extend_from_slice(&chunk[..read]);
                    if raw.len() > MAX_RESPONSE_BYTES {
                        return Err(Es9pError::MalformedHttp {
                            reason: format!("answer exceeded {MAX_RESPONSE_BYTES} bytes"),
                        });
                    }
                }
                // A peer that closes without close_notify is not an error once
                // the whole answer is already here, and Kong in front of this
                // SM-DP+ does exactly that on `Connection: close`.
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(error) => return Err(tls_or_io(host, error)),
            }
        }
        let tls_version = stream
            .conn
            .protocol_version()
            .map(|version| format!("{version:?}"));
        let mut response = HttpResponse::parse(&raw)?;
        response.tls_version = tls_version;
        if response.status != 200 {
            return Err(Es9pError::HttpStatus {
                status: response.status,
                body: String::from_utf8_lossy(&response.body)
                    .chars()
                    .take(400)
                    .collect(),
            });
        }
        Ok(response)
    }
}

fn tls_or_io(host: &str, error: std::io::Error) -> Es9pError {
    // rustls reports a rejected certificate through the io::Error the first
    // read or write produces, so the distinction has to be made by looking.
    let text = error.to_string();
    if text.contains("certificate")
        || text.contains("CaUsedAsEndEntity")
        || text.contains("UnknownIssuer")
        || text.contains("invalid peer")
        || text.contains("HandshakeFailure")
    {
        return Es9pError::TlsFailed {
            host: host.to_string(),
            reason: text,
        };
    }
    Es9pError::IoFailed { reason: text }
}

/// The ES9+ request body, exactly the three fields SGP.22 defines.
pub fn initiate_authentication_request(
    host: &str,
    euicc_challenge: &[u8],
    euicc_info1: &[u8],
) -> String {
    format!(
        "{{\"euiccChallenge\":\"{challenge}\",\"euiccInfo1\":\"{info1}\",\"smdpAddress\":\"{host}\"}}",
        challenge = BASE64.encode(euicc_challenge),
        info1 = BASE64.encode(euicc_info1),
    )
}

/// A parsed HTTP/1.1 answer.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HttpResponse {
    pub status: u16,
    /// Lowercased header names to values.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub tls_version: Option<String>,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<String> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    }

    /// Parse status line, headers and body.
    ///
    /// Chunked bodies are decoded here rather than refused: the SM-DP+ on the
    /// bench answers with a Content-Length, but it sits behind a gateway that
    /// is free to reframe, and an undecoded chunked body reaches the JSON
    /// parser as a hex length followed by a brace.
    pub fn parse(raw: &[u8]) -> Result<Self, Es9pError> {
        let split = raw
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .ok_or_else(|| Es9pError::MalformedHttp {
                reason: "no header terminator".into(),
            })?;
        let head = String::from_utf8_lossy(&raw[..split]).to_string();
        let mut lines = head.split("\r\n");
        let status_line = lines.next().unwrap_or_default();
        let status = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse::<u16>().ok())
            .ok_or_else(|| Es9pError::MalformedHttp {
                reason: format!("unreadable status line {status_line:?}"),
            })?;
        let mut headers = Vec::new();
        for line in lines {
            if let Some((name, value)) = line.split_once(':') {
                headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
            }
        }
        let mut body = raw[split + 4..].to_vec();
        let chunked = headers
            .iter()
            .any(|(name, value)| name == "transfer-encoding" && value.contains("chunked"));
        if chunked {
            body = dechunk(&body)?;
        } else if let Some(length) = headers
            .iter()
            .find(|(name, _)| name == "content-length")
            .and_then(|(_, value)| value.parse::<usize>().ok())
        {
            if body.len() < length {
                return Err(Es9pError::MalformedHttp {
                    reason: format!("body is {} bytes, Content-Length says {length}", body.len()),
                });
            }
            body.truncate(length);
        }
        Ok(Self {
            status,
            headers,
            body,
            tls_version: None,
        })
    }
}

fn dechunk(body: &[u8]) -> Result<Vec<u8>, Es9pError> {
    let mut out = Vec::new();
    let mut rest = body;
    loop {
        let line_end = rest
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| Es9pError::MalformedHttp {
                reason: "chunk size without terminator".into(),
            })?;
        let header = String::from_utf8_lossy(&rest[..line_end]);
        let size_text = header.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_text, 16).map_err(|_| Es9pError::MalformedHttp {
            reason: format!("unreadable chunk size {size_text:?}"),
        })?;
        rest = &rest[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if rest.len() < size + 2 {
            return Err(Es9pError::MalformedHttp {
                reason: "chunk shorter than its declared size".into(),
            });
        }
        out.extend_from_slice(&rest[..size]);
        rest = &rest[size + 2..];
    }
}

/// What an SM-DP+ returns from `InitiateAuthentication`, plus what we checked.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AuthenticationStart {
    /// The host this was asked of.
    pub smdp_address: String,
    /// The identifier that names this RSP session at the server, uppercase hex.
    pub transaction_id: String,
    /// `ServerSigned1`, the signed bytes verbatim.
    pub server_signed1: Vec<u8>,
    /// `ServerSignature1` including its `5F37` wrapper.
    pub server_signature1: Vec<u8>,
    /// `CERT.DPauth.ECDSA`, DER.
    pub server_certificate: Vec<u8>,
    /// The CI key the server expects this eUICC to verify with, uppercase hex.
    pub euicc_ci_pkid_to_be_used: String,
    /// The address inside the signed structure.
    pub server_address: String,
    /// The server's own random, uppercase hex.
    pub server_challenge: String,
    /// The eUICC challenge as the server echoed it, uppercase hex.
    pub echoed_euicc_challenge: String,
    pub http_status: u16,
    pub admin_protocol: Option<String>,
    pub negotiated_tls: Option<String>,
    pub elapsed_ms: u64,
    pub verification: Verification,
}

/// The checks that were made on the answer, each one named.
///
/// A boolean called `verified` would be the wrong shape here. Three separate
/// things are being asserted — the CI signed the certificate, the certificate
/// signed the answer, and the answer is about this chip's challenge — and
/// collapsing them means a failure of any one reads as a failure of all.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Verification {
    /// Label of the CI root the certificate chained to.
    pub trust_anchor_label: String,
    /// That root's key identifier, uppercase hex.
    pub trust_anchor_key_id: String,
    /// The certificate's own key identifier.
    pub certificate_key_id: String,
    /// The authority key identifier it names.
    pub certificate_authority_key_id: String,
    pub certificate_sha256: String,
    pub certificate_not_after: String,
    /// The CI root's key verified the certificate's signature.
    pub certificate_signed_by_ci: bool,
    /// The certificate's key verified `serverSignature1`.
    pub server_signature_valid: bool,
    /// The echoed challenge is the one this chip produced.
    pub challenge_echoed: bool,
}

/// Read the JSON an SM-DP+ returns, without checking any signature yet.
pub fn parse_initiate_authentication(body: &[u8]) -> Result<AuthenticationStart, Es9pError> {
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|error| Es9pError::MalformedJson {
            reason: error.to_string(),
        })?;
    if let Some(status) = value
        .pointer("/header/functionExecutionStatus/status")
        .and_then(|status| status.as_str())
    {
        if status != "Executed-Success" {
            let error = value.pointer("/header/functionExecutionStatus/statusCodeData");
            return Err(Es9pError::FunctionFailed {
                status: status.to_string(),
                subject_code: string_at(error, "subjectCode"),
                reason_code: string_at(error, "reasonCode"),
                message: string_at(error, "message"),
            });
        }
    } else {
        return Err(Es9pError::MissingField {
            name: "header.functionExecutionStatus.status",
        });
    }

    let transaction_id = required_string(&value, "transactionId")?;
    let server_signed1 = required_base64(&value, "serverSigned1")?;
    let server_signature1 = required_base64(&value, "serverSignature1")?;
    let server_certificate = required_base64(&value, "serverCertificate")?;
    let ci_pkid = required_base64(&value, "euiccCiPKIdToBeUsed")?;

    let signed = ServerSigned1::parse(&server_signed1)?;
    Ok(AuthenticationStart {
        smdp_address: String::new(),
        transaction_id: transaction_id.to_ascii_uppercase(),
        server_signed1,
        server_signature1,
        server_certificate,
        // The field arrives as a DER OCTET STRING around the twenty-byte key
        // identifier. Reported unwrapped so it can be compared against what
        // GetEUICCInfo1 reports without either side knowing about the wrapper.
        euicc_ci_pkid_to_be_used: unwrap_key_identifier(&ci_pkid),
        server_address: signed.server_address,
        server_challenge: hex_upper(&signed.server_challenge),
        echoed_euicc_challenge: hex_upper(&signed.euicc_challenge),
        http_status: 0,
        admin_protocol: None,
        negotiated_tls: None,
        elapsed_ms: 0,
        verification: Verification::default(),
    })
}

fn string_at(value: Option<&serde_json::Value>, key: &str) -> Option<String> {
    value
        .and_then(|value| value.get(key))
        .and_then(|value| value.as_str())
        .map(|value| value.to_string())
}

fn required_string<'a>(
    value: &'a serde_json::Value,
    key: &'static str,
) -> Result<&'a str, Es9pError> {
    value
        .get(key)
        .and_then(|value| value.as_str())
        .ok_or(Es9pError::MissingField { name: key })
}

fn required_base64(value: &serde_json::Value, key: &'static str) -> Result<Vec<u8>, Es9pError> {
    let text = required_string(value, key)?;
    BASE64
        .decode(text)
        .map_err(|_| Es9pError::BadBase64 { field: key })
}

/// The four fields SGP.22 puts in `ServerSigned1`.
struct ServerSigned1 {
    #[allow(dead_code)]
    transaction_id: Vec<u8>,
    euicc_challenge: Vec<u8>,
    server_address: String,
    server_challenge: Vec<u8>,
}

impl ServerSigned1 {
    fn parse(bytes: &[u8]) -> Result<Self, Es9pError> {
        let (sequence, _) = read_der(bytes).map_err(malformed_signed)?;
        if sequence.tag != [0x30] {
            return Err(Es9pError::MalformedServerSigned {
                reason: format!("expected a SEQUENCE, got tag {}", hex_upper(&sequence.tag)),
            });
        }
        let mut transaction_id = None;
        let mut euicc_challenge = None;
        let mut server_address = None;
        let mut server_challenge = None;
        let mut rest = sequence.value;
        while !rest.is_empty() {
            let (field, tail) = read_der(rest).map_err(malformed_signed)?;
            rest = tail;
            match field.tag {
                TAG_TRANSACTION_ID => transaction_id = Some(field.value.to_vec()),
                TAG_ECHOED_CHALLENGE => euicc_challenge = Some(field.value.to_vec()),
                TAG_SERVER_ADDRESS => {
                    server_address = Some(String::from_utf8_lossy(field.value).to_string())
                }
                TAG_SERVER_CHALLENGE => server_challenge = Some(field.value.to_vec()),
                _ => {}
            }
        }
        Ok(Self {
            transaction_id: transaction_id.ok_or(Es9pError::MissingField {
                name: "serverSigned1.transactionId",
            })?,
            euicc_challenge: euicc_challenge.ok_or(Es9pError::MissingField {
                name: "serverSigned1.euiccChallenge",
            })?,
            server_address: server_address.ok_or(Es9pError::MissingField {
                name: "serverSigned1.serverAddress",
            })?,
            server_challenge: server_challenge.ok_or(Es9pError::MissingField {
                name: "serverSigned1.serverChallenge",
            })?,
        })
    }
}

fn malformed_signed(reason: String) -> Es9pError {
    Es9pError::MalformedServerSigned { reason }
}

/// Check the answer end to end: CI root, certificate, signature, challenge.
///
/// Every step is fatal. The alternative — reporting an unverified answer with
/// a flag saying so — produces a console page that looks like a success and a
/// field nobody reads.
pub fn verify_server_credentials(
    start: &AuthenticationStart,
    host: &str,
    euicc_challenge: &[u8],
    anchors: &[TrustAnchor],
) -> Result<Verification, Es9pError> {
    let certificate = Certificate::parse(&start.server_certificate)?;
    let authority = certificate
        .authority_key_id
        .clone()
        .ok_or_else(|| Es9pError::MalformedCertificate {
            reason: "no authority key identifier".into(),
        })?;
    let anchor = anchors
        .iter()
        .find(|anchor| anchor.key_id == authority)
        .ok_or_else(|| Es9pError::UntrustedCertificateAuthority {
            authority_key_id: authority.clone(),
        })?;

    let root = Certificate::parse(anchor.der.as_ref())?;
    // The certificate SGP.22 calls CERT.DPauth is not the one TLS presented;
    // it is a separate credential the eUICC itself will check in the next
    // step. Checking it here means the download slice inherits a chain that
    // was already proven rather than discovering at the card that it was not.
    ring::signature::UnparsedPublicKey::new(
        &ring::signature::ECDSA_P256_SHA256_ASN1,
        root.public_key.as_slice(),
    )
    .verify(&certificate.tbs, &certificate.signature)
    .map_err(|_| Es9pError::CertificateSignatureInvalid)?;

    let raw_signature = unwrap_signature(&start.server_signature1)?;
    ring::signature::UnparsedPublicKey::new(
        &ring::signature::ECDSA_P256_SHA256_FIXED,
        certificate.public_key.as_slice(),
    )
    .verify(&start.server_signed1, &raw_signature)
    .map_err(|_| Es9pError::ServerSignatureInvalid)?;

    let sent = hex_upper(euicc_challenge);
    if sent != start.echoed_euicc_challenge {
        return Err(Es9pError::ChallengeMismatch {
            sent,
            echoed: start.echoed_euicc_challenge.clone(),
        });
    }
    if !start.server_address.eq_ignore_ascii_case(host) {
        return Err(Es9pError::AddressMismatch {
            asked: host.to_string(),
            signed: start.server_address.clone(),
        });
    }

    Ok(Verification {
        trust_anchor_label: anchor.label.clone(),
        trust_anchor_key_id: anchor.key_id.clone(),
        certificate_key_id: certificate
            .subject_key_id
            .clone()
            .unwrap_or_else(|| "unknown".into()),
        certificate_authority_key_id: authority,
        certificate_sha256: sha256_hex(&start.server_certificate),
        certificate_not_after: certificate.not_after.clone(),
        certificate_signed_by_ci: true,
        server_signature_valid: true,
        challenge_echoed: true,
    })
}

/// Strip the `5F37` wrapper SGP.22 puts around `r || s`.
fn unwrap_signature(signature: &[u8]) -> Result<Vec<u8>, Es9pError> {
    let (field, _) = read_der(signature).map_err(|reason| Es9pError::MalformedServerSigned {
        reason: format!("serverSignature1: {reason}"),
    })?;
    let body = if field.tag == TAG_SIGNATURE {
        field.value
    } else {
        // Some servers send the bare pair. Accepting both is safe because the
        // length is what actually decides, and a wrong guess fails the
        // signature check rather than passing it.
        signature
    };
    if body.len() != P256_SIGNATURE_BYTES {
        return Err(Es9pError::MalformedServerSigned {
            reason: format!(
                "serverSignature1 carries {} bytes, expected {P256_SIGNATURE_BYTES}",
                body.len()
            ),
        });
    }
    Ok(body.to_vec())
}

/// A DER OCTET STRING around a key identifier, or the identifier itself.
fn unwrap_key_identifier(bytes: &[u8]) -> String {
    match read_der(bytes) {
        Ok((field, _)) if field.tag == [0x04] => hex_upper(field.value),
        _ => hex_upper(bytes),
    }
}

// ---------------------------------------------------------------------------
// The smallest X.509 reader that answers the four questions asked above.
// ---------------------------------------------------------------------------

/// The parts of a certificate this module needs.
///
/// Hand-rolled rather than handed to the webpki that rustls already carries,
/// and the reason is specific: the Thales SM-DP+ signing certificate marks its
/// `certificatePolicies` extension critical, and webpki rejects any critical
/// extension it does not implement. That rejection is correct for a TLS
/// server certificate and wrong here — this credential is not a TLS
/// certificate, it is the one the eUICC verifies under SGP.22 rules, and
/// SGP.22 says which extensions matter. TLS itself still goes through rustls
/// and webpki untouched.
struct Certificate {
    /// `tbsCertificate` including its own tag and length: the signed bytes.
    tbs: Vec<u8>,
    /// ECDSA signature over `tbs`, DER encoded.
    signature: Vec<u8>,
    /// Uncompressed EC point from `subjectPublicKeyInfo`.
    public_key: Vec<u8>,
    subject_key_id: Option<String>,
    authority_key_id: Option<String>,
    not_after: String,
}

impl Certificate {
    fn parse(der: &[u8]) -> Result<Self, Es9pError> {
        let (certificate, _) = read_der(der).map_err(malformed_certificate)?;
        let parts = children(certificate.value).map_err(malformed_certificate)?;
        let [tbs, _algorithm, signature] = parts.as_slice() else {
            return Err(Es9pError::MalformedCertificate {
                reason: format!("certificate has {} top-level fields, expected 3", parts.len()),
            });
        };
        let signature = bit_string(signature)?;
        let fields = children(tbs.value).map_err(malformed_certificate)?;
        // The version is an optional `[0]`. Everything after it shifts, so the
        // offset is decided by looking rather than assumed.
        let base = usize::from(fields.first().map(|field| field.tag == [0xa0]).unwrap_or(false));
        let validity = fields
            .get(base + 3)
            .ok_or_else(|| Es9pError::MalformedCertificate {
                reason: "no validity".into(),
            })?;
        let spki = fields
            .get(base + 5)
            .ok_or_else(|| Es9pError::MalformedCertificate {
                reason: "no subjectPublicKeyInfo".into(),
            })?;
        let validity_fields = children(validity.value).map_err(malformed_certificate)?;
        let not_after = validity_fields
            .get(1)
            .map(|field| String::from_utf8_lossy(field.value).to_string())
            .ok_or_else(|| Es9pError::MalformedCertificate {
                reason: "no notAfter".into(),
            })?;
        let spki_fields = children(spki.value).map_err(malformed_certificate)?;
        let public_key = spki_fields
            .get(1)
            .ok_or_else(|| Es9pError::MalformedCertificate {
                reason: "no public key".into(),
            })
            .and_then(bit_string)?;

        let mut subject_key_id = None;
        let mut authority_key_id = None;
        if let Some(extensions) = fields.iter().skip(base + 6).find(|field| field.tag == [0xa3]) {
            let (list, _) = read_der(extensions.value).map_err(malformed_certificate)?;
            for extension in children(list.value).map_err(malformed_certificate)? {
                let parts = children(extension.value).map_err(malformed_certificate)?;
                let Some(oid) = parts.first() else { continue };
                let Some(payload) = parts.last() else { continue };
                match oid.value {
                    // id-ce-subjectKeyIdentifier: OCTET STRING wrapping an
                    // OCTET STRING wrapping the identifier.
                    [0x55, 0x1d, 0x0e] => {
                        subject_key_id = read_der(payload.value)
                            .ok()
                            .map(|(inner, _)| hex_upper(inner.value));
                    }
                    // id-ce-authorityKeyIdentifier: the identifier is `[0]`
                    // inside a SEQUENCE, alongside optional issuer and serial.
                    [0x55, 0x1d, 0x23] => {
                        authority_key_id = read_der(payload.value).ok().and_then(|(inner, _)| {
                            children(inner.value)
                                .ok()?
                                .into_iter()
                                .find(|field| field.tag == [0x80])
                                .map(|field| hex_upper(field.value))
                        });
                    }
                    _ => {}
                }
            }
        }

        Ok(Self {
            tbs: tbs.total.to_vec(),
            signature,
            public_key,
            subject_key_id,
            authority_key_id,
            not_after,
        })
    }
}

fn malformed_certificate(reason: String) -> Es9pError {
    Es9pError::MalformedCertificate { reason }
}

/// A BIT STRING's payload, minus the unused-bit count.
fn bit_string(field: &Der<'_>) -> Result<Vec<u8>, Es9pError> {
    if field.tag != [0x03] {
        return Err(Es9pError::MalformedCertificate {
            reason: format!("expected a BIT STRING, got tag {}", hex_upper(&field.tag)),
        });
    }
    field
        .value
        .split_first()
        .map(|(_unused, bytes)| bytes.to_vec())
        .ok_or_else(|| Es9pError::MalformedCertificate {
            reason: "empty BIT STRING".into(),
        })
}

struct Der<'a> {
    tag: &'a [u8],
    value: &'a [u8],
    /// Tag, length and value together: what a signature is computed over.
    total: &'a [u8],
}

fn read_der(bytes: &[u8]) -> Result<(Der<'_>, &[u8]), String> {
    let first = *bytes.first().ok_or_else(|| "truncated tag".to_string())?;
    let mut cursor = 1;
    if first & 0x1f == 0x1f {
        loop {
            let next = *bytes
                .get(cursor)
                .ok_or_else(|| "truncated multi-byte tag".to_string())?;
            cursor += 1;
            if next & 0x80 == 0 {
                break;
            }
        }
    }
    let tag = &bytes[..cursor];
    let length_byte = *bytes
        .get(cursor)
        .ok_or_else(|| "truncated length".to_string())?;
    cursor += 1;
    let length = if length_byte & 0x80 == 0 {
        usize::from(length_byte)
    } else {
        let count = usize::from(length_byte & 0x7f);
        if count == 0 || count > 4 {
            return Err(format!("unsupported length form 0x{length_byte:02x}"));
        }
        let mut value = 0usize;
        for _ in 0..count {
            let byte = *bytes
                .get(cursor)
                .ok_or_else(|| "truncated long length".to_string())?;
            cursor += 1;
            value = (value << 8) | usize::from(byte);
        }
        value
    };
    let end = cursor
        .checked_add(length)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| format!("value of {length} bytes runs past the buffer"))?;
    Ok((
        Der {
            tag,
            value: &bytes[cursor..end],
            total: &bytes[..end],
        },
        &bytes[end..],
    ))
}

fn children(mut bytes: &[u8]) -> Result<Vec<Der<'_>>, String> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let (field, tail) = read_der(bytes)?;
        bytes = tail;
        out.push(field);
    }
    Ok(out)
}

fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
