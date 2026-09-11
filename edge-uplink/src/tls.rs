//! TLS 1.3-only mTLS client configuration for the edge-initiated WSS uplink.

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, RootCertStore};

/// Errors when building the uplink TLS client.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TlsError {
    EmptyTrustAnchors,
    EmptyClientCertificate,
    InvalidPrivateKey,
    InvalidClientAuth(String),
}

impl std::fmt::Display for TlsError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyTrustAnchors => formatter.write_str("at least one gateway CA is required"),
            Self::EmptyClientCertificate => formatter.write_str("device certificate is required"),
            Self::InvalidPrivateKey => formatter.write_str("device private key is invalid"),
            Self::InvalidClientAuth(reason) => write!(formatter, "client certificate: {reason}"),
        }
    }
}

impl std::error::Error for TlsError {}

/// Builds a TLS 1.3-only client that presents the device certificate and
/// verifies the gateway. Early data is disabled.
pub fn client_config(
    trust_anchors: Vec<CertificateDer<'static>>,
    device_chain: Vec<CertificateDer<'static>>,
    device_key: PrivateKeyDer<'static>,
) -> Result<Arc<ClientConfig>, TlsError> {
    if trust_anchors.is_empty() {
        return Err(TlsError::EmptyTrustAnchors);
    }
    if device_chain.is_empty() {
        return Err(TlsError::EmptyClientCertificate);
    }

    let mut roots = RootCertStore::empty();
    for certificate in trust_anchors {
        roots
            .add(certificate)
            .map_err(|err| TlsError::InvalidClientAuth(err.to_string()))?;
    }

    let mut config = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("TLS 1.3 is supported by the ring provider")
    .with_root_certificates(roots)
    .with_client_auth_cert(device_chain, device_key)
    .map_err(|err| TlsError::InvalidClientAuth(err.to_string()))?;
    config.enable_early_data = false;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// 装机阶段的 TLS：验服务端，**不带客户端证书**。
///
/// 🔴 和 `client_config` 分开而不是给它加一个 `Option` 参数：那两个场景对
///    「没有客户端证书」的正确反应正好相反。上行少了客户端证书是配置坏了，
///    必须拒（`EmptyClientCertificate`）；装机时按定义还没有证书 —— 那正是
///    这一步要去换的东西。合成一个函数，早晚有人为了让装机跑通而把上行那条
///    检查放宽掉。
///
/// ⚠️ 服务端仍然要验。装机是把私钥交出去之前唯一能确认对方是谁的机会，
///    这里没有「跳过验证」这个选项。
pub fn bootstrap_config(
    trust_anchors: Vec<CertificateDer<'static>>,
) -> Result<Arc<ClientConfig>, TlsError> {
    if trust_anchors.is_empty() {
        return Err(TlsError::EmptyTrustAnchors);
    }
    let mut roots = RootCertStore::empty();
    for certificate in trust_anchors {
        roots
            .add(certificate)
            .map_err(|err| TlsError::InvalidClientAuth(err.to_string()))?;
    }
    let mut config = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("TLS 1.3 is supported by the ring provider")
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.enable_early_data = false;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// 从一份 PEM 里读出所有证书。
pub fn certificates_from_pem(bytes: &[u8]) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let mut cursor = std::io::Cursor::new(bytes);
    rustls_pemfile::certs(&mut cursor)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| TlsError::InvalidClientAuth(err.to_string()))
}

/// Parses a PKCS#8 device key.
pub fn private_key_from_pkcs8(der: Vec<u8>) -> Result<PrivateKeyDer<'static>, TlsError> {
    if der.is_empty() {
        return Err(TlsError::InvalidPrivateKey);
    }
    Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der)))
}
