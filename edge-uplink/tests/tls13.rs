use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use edge_uplink::tls::{client_config, private_key_from_pkcs8, TlsError};
use rcgen::{BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConnection, RootCertStore, ServerConfig, ServerConnection, Stream};

fn install_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

struct IssuedCert {
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

struct Pki {
    ca: CertificateDer<'static>,
    server: IssuedCert,
    device: IssuedCert,
}

fn pki() -> Pki {
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

fn server_config(pki: &Pki, versions: &[&'static rustls::SupportedProtocolVersion]) -> Arc<ServerConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(pki.ca.clone()).expect("ca");
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .expect("client verifier");
    let config = ServerConfig::builder_with_protocol_versions(versions)
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![pki.server.cert.clone()], clone_key(&pki.server.key))
        .expect("server config");
    Arc::new(config)
}

fn clone_key(key: &PrivateKeyDer<'static>) -> PrivateKeyDer<'static> {
    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.secret_der().to_vec()))
}

fn handshake(client: Arc<rustls::ClientConfig>, server: Arc<ServerConfig>) -> std::io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(false)?;
    let addr = listener.local_addr()?;
    let server_thread = thread::spawn(move || {
        let (mut tcp, _) = listener.accept().expect("accept");
        tcp.set_read_timeout(Some(Duration::from_secs(2))).ok();
        tcp.set_write_timeout(Some(Duration::from_secs(2))).ok();
        let mut tls = ServerConnection::new(server).expect("server conn");
        let mut stream = Stream::new(&mut tls, &mut tcp);
        let mut buf = [0u8; 5];
        let _ = stream.read(&mut buf);
    });

    let mut tcp = TcpStream::connect(addr)?;
    tcp.set_read_timeout(Some(Duration::from_secs(2)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(2)))?;
    let name = ServerName::try_from("localhost").unwrap();
    let mut tls = ClientConnection::new(client, name).expect("client conn");
    let result = {
        let mut stream = Stream::new(&mut tls, &mut tcp);
        stream.write_all(b"hello").and_then(|_| stream.flush())
    };
    let _ = server_thread.join();
    result
}

#[test]
fn client_config_rejects_empty_trust_and_device_material() {
    install_provider();
    let key = private_key_from_pkcs8(vec![1, 2, 3]).expect("non-empty key bytes");
    assert!(matches!(
        client_config(Vec::new(), Vec::new(), clone_key(&key)),
        Err(TlsError::EmptyTrustAnchors)
    ));
}

#[test]
fn tls13_mtls_handshake_succeeds_and_disables_early_data() {
    install_provider();
    let pki = pki();
    let client = client_config(
        vec![pki.ca.clone()],
        vec![pki.device.cert.clone()],
        clone_key(&pki.device.key),
    )
    .expect("client config");
    assert!(!client.enable_early_data);
    assert_eq!(client.alpn_protocols, vec![b"http/1.1".to_vec()]);

    handshake(client, server_config(&pki, &[&rustls::version::TLS13])).expect("tls 1.3 handshake");
}

#[test]
fn tls12_server_cannot_negotiate() {
    install_provider();
    let pki = pki();
    let client = client_config(
        vec![pki.ca.clone()],
        vec![pki.device.cert.clone()],
        clone_key(&pki.device.key),
    )
    .expect("client config");

    let err = handshake(client, server_config(&pki, &[&rustls::version::TLS12]));
    assert!(err.is_err(), "tls 1.2 server must not negotiate");
}
