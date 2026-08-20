use std::net::TcpListener;
use std::thread;
use std::time::{Duration, Instant};

use edge_uplink::codec::encode_json;
use edge_uplink::dial::{DialError, Socket};
use edge_uplink::session::{Inbound, LinkConfig, LinkSession, ResumeSnapshot};
use edge_uplink::tls::client_config;
use rustls::ServerConnection;
use rustls::StreamOwned;
use tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tungstenite::http::header::SEC_WEBSOCKET_PROTOCOL;
use tungstenite::http::HeaderValue;
use tungstenite::{accept_hdr, Message};
use vodoge_contract::{Envelope, MessageKind, ResumeAckPayload, ResumePayload, WS_SUBPROTOCOL};

mod common;

fn snapshot() -> ResumeSnapshot {
    ResumeSnapshot {
        last_assigned_seq: 0,
        last_acked_seq: 0,
        lowest_retained_seq: None,
        pending_gap_ids: Vec::new(),
        capability_matrix_version: "1".into(),
        edge_version: None,
        queue_records: None,
        queue_bytes: None,
    }
}

#[test]
fn connect_rejects_plaintext() {
    common::pki::install_provider();
    let material = common::pki::pki();
    let tls = client_config(
        vec![material.ca.clone()],
        vec![material.device.cert.clone()],
        common::pki::clone_key(&material.device.key),
    )
    .expect("tls");
    match Socket::connect("ws://localhost/v1/edge", tls) {
        Err(DialError::PlaintextRejected) => {}
        Err(err) => panic!("unexpected error {err}"),
        Ok(_) => panic!("plaintext dial succeeded"),
    }
}

#[test]
fn resume_over_wss_mtls() {
    common::pki::install_provider();
    let material = common::pki::pki();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server_tls = common::pki::server_config(&material, &[&rustls::version::TLS13]);

    let server = thread::spawn(move || {
        listener.set_nonblocking(false).ok();
        let (tcp, _) = listener.accept().expect("accept");
        tcp.set_read_timeout(Some(Duration::from_secs(3))).ok();
        tcp.set_write_timeout(Some(Duration::from_secs(3))).ok();
        let conn = ServerConnection::new(server_tls).expect("server conn");
        let stream = StreamOwned::new(conn, tcp);
        let mut ws = accept_hdr(stream, |request: &Request, mut response: Response| {
            if request
                .headers()
                .get(SEC_WEBSOCKET_PROTOCOL)
                .and_then(|value| value.to_str().ok())
                != Some(WS_SUBPROTOCOL)
            {
                return Err(ErrorResponse::new(Some("subprotocol required".into())));
            }
            response
                .headers_mut()
                .insert(SEC_WEBSOCKET_PROTOCOL, HeaderValue::from_static(WS_SUBPROTOCOL));
            Ok(response)
        })
        .expect("accept websocket");

        let Message::Binary(bytes) = ws.read().expect("resume frame") else {
            panic!("first frame must be binary");
        };
        let resume: Envelope = serde_json::from_slice(&bytes).expect("resume json");
        assert_eq!(resume.kind, MessageKind::Resume);
        let payload: ResumePayload = serde_json::from_value(resume.payload).expect("payload");
        let ack = Envelope {
            v: 1,
            kind: MessageKind::ResumeAck,
            id: "ack".into(),
            ts: 1,
            device_id: resume.device_id,
            seq: None,
            trace_id: None,
            payload: serde_json::to_value(ResumeAckPayload {
                connection_id: payload.connection_id,
                committed_through: 0,
                missing_ranges: Vec::new(),
                more_missing: false,
                max_in_flight: 32,
                server_time: 1,
            })
            .unwrap(),
        };
        ws.send(Message::Binary(encode_json(&ack).expect("encode")))
            .expect("write ack");
        let _ = ws.close(None);
    });

    let tls = client_config(
        vec![material.ca.clone()],
        vec![material.device.cert.clone()],
        common::pki::clone_key(&material.device.key),
    )
    .expect("client tls");
    let url = format!("wss://localhost:{}/v1/edge", addr.port());
    let mut socket = Socket::connect(&url, tls).expect("dial");
    let mut session = LinkSession::new(LinkConfig::new("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", snapshot()).expect("config"));
    match socket
        .resume(&mut session, "conn-1", Instant::now())
        .expect("resume")
    {
        Inbound::ResumeAck(ack) => {
            assert_eq!(ack.connection_id, "conn-1");
            assert_eq!(ack.committed_through, 0);
        }
        other => panic!("unexpected {other:?}"),
    }
    let _ = socket.close();
    server.join().expect("server");
}
