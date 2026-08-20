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

/// Parses a PKCS#8 device key.
pub fn private_key_from_pkcs8(der: Vec<u8>) -> Result<PrivateKeyDer<'static>, TlsError> {
    if der.is_empty() {
        return Err(TlsError::InvalidPrivateKey);
    }
    Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der)))
}
