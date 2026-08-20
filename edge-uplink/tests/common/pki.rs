use std::sync::Arc;

use rcgen::{BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};

pub fn install_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub struct IssuedCert {
    pub cert: CertificateDer<'static>,
    pub key: PrivateKeyDer<'static>,
}

pub struct Pki {
    pub ca: CertificateDer<'static>,
    pub server: IssuedCert,
    pub device: IssuedCert,
}

pub fn pki() -> Pki {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.distinguished_name.push(DnType::CommonName, "vodoge-test-ca");
    let ca_key = KeyPair::generate().expect("ca key");
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");

    let mut server_params = CertificateParams::new(vec!["localhost".into()]).expect("server params");
    server_params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    server_params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    let server_key = KeyPair::generate().expect("server key");
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .expect("server cert");

    let mut device_params = CertificateParams::new(Vec::<String>::new()).expect("device params");
    device_params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ClientAuth);
    device_params
        .distinguished_name
        .push(DnType::CommonName, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
    device_params
        .distinguished_name
        .push(DnType::OrganizationName, "11111111-1111-1111-1111-111111111111");
    device_params
        .distinguished_name
        .push(DnType::OrganizationalUnitName, "cn");
    let device_key = KeyPair::generate().expect("device key");
    let device_cert = device_params
        .signed_by(&device_key, &ca_cert, &ca_key)
        .expect("device cert");

    Pki {
        ca: CertificateDer::from(ca_cert.der().to_vec()),
        server: IssuedCert {
            cert: CertificateDer::from(server_cert.der().to_vec()),
            key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
        },
        device: IssuedCert {
            cert: CertificateDer::from(device_cert.der().to_vec()),
            key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(device_key.serialize_der())),
        },
    }
}

pub fn clone_key(key: &PrivateKeyDer<'static>) -> PrivateKeyDer<'static> {
    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.secret_der().to_vec()))
}

pub fn server_config(
    pki: &Pki,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Arc<ServerConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(pki.ca.clone()).expect("ca");
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .expect("client verifier");
    let mut config = ServerConfig::builder_with_protocol_versions(versions)
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![pki.server.cert.clone()], clone_key(&pki.server.key))
        .expect("server config");
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}
