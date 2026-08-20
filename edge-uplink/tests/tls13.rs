use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use edge_uplink::tls::{client_config, private_key_from_pkcs8, TlsError};
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, ServerConnection, Stream};

mod common;

fn handshake(
    client: Arc<rustls::ClientConfig>,
    server: Arc<rustls::ServerConfig>,
) -> std::io::Result<()> {
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
    common::pki::install_provider();
    let key = private_key_from_pkcs8(vec![1, 2, 3]).expect("non-empty key bytes");
    assert!(matches!(
        client_config(Vec::new(), Vec::new(), common::pki::clone_key(&key)),
        Err(TlsError::EmptyTrustAnchors)
    ));
}

#[test]
fn tls13_mtls_handshake_succeeds_and_disables_early_data() {
    common::pki::install_provider();
    let material = common::pki::pki();
    let client = client_config(
        vec![material.ca.clone()],
        vec![material.device.cert.clone()],
        common::pki::clone_key(&material.device.key),
    )
    .expect("client config");
    assert!(!client.enable_early_data);
    assert_eq!(client.alpn_protocols, vec![b"http/1.1".to_vec()]);

    handshake(
        client,
        common::pki::server_config(&material, &[&rustls::version::TLS13]),
    )
    .expect("tls 1.3 handshake");
}

#[test]
fn tls12_server_cannot_negotiate() {
    common::pki::install_provider();
    let material = common::pki::pki();
    let client = client_config(
        vec![material.ca.clone()],
        vec![material.device.cert.clone()],
        common::pki::clone_key(&material.device.key),
    )
    .expect("client config");

    let err = handshake(
        client,
        common::pki::server_config(&material, &[&rustls::version::TLS12]),
    );
    assert!(err.is_err(), "tls 1.2 server must not negotiate");
}
