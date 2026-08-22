//! Drives a real listener with a real SOCKS5 client over loopback.
//!
//! The one thing not covered is the interface binding, which needs a cellular
//! interface and privileges a workstation does not have. Everything else — the
//! handshake, authentication, CONNECT, the relay, the counters, upstream
//! chaining — is exercised against the code that actually runs on the device.

use std::sync::Arc;

use edge_proxy::{InstanceSpec, InterfaceResolver, ProxyManager, UpstreamSpec};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Claims every modem is on loopback, so a listener can start without
/// hardware. The manager refuses to start one with no interface at all, which
/// is the behaviour under test elsewhere.
struct Loopback;

impl InterfaceResolver for Loopback {
    fn interface_for(&self, _modem_imei: &str) -> Option<String> {
        Some("lo".to_string())
    }
}

/// Resolves nothing, standing in for a modem whose data session is down.
struct NoInterface;

impl InterfaceResolver for NoInterface {
    fn interface_for(&self, _modem_imei: &str) -> Option<String> {
        None
    }
}

fn spec(port: u16) -> InstanceSpec {
    InstanceSpec {
        id: "instance-1".into(),
        name: "test".into(),
        modem_imei: "867018069514820".into(),
        protocol: "socks5".into(),
        listen_addr: "127.0.0.1".into(),
        listen_port: port,
        enabled: true,
        ..InstanceSpec::default()
    }
}

/// An echo server standing in for whatever the client wanted to reach.
async fn echo_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0u8; 1024];
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(read) => {
                            if stream.write_all(&buffer[..read]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    port
}

/// Performs a SOCKS5 CONNECT and returns the connected stream.
async fn socks5_connect(
    proxy_port: u16,
    target_port: u16,
    credentials: Option<(&str, &str)>,
) -> Result<TcpStream, String> {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .map_err(|error| error.to_string())?;

    match credentials {
        Some(_) => stream.write_all(&[0x05, 1, 0x02]).await,
        None => stream.write_all(&[0x05, 1, 0x00]).await,
    }
    .map_err(|error| error.to_string())?;

    let mut chosen = [0u8; 2];
    stream
        .read_exact(&mut chosen)
        .await
        .map_err(|error| error.to_string())?;
    if chosen[1] == 0xFF {
        return Err("no acceptable auth".into());
    }

    if let Some((username, password)) = credentials {
        let mut request = vec![0x01, username.len() as u8];
        request.extend_from_slice(username.as_bytes());
        request.push(password.len() as u8);
        request.extend_from_slice(password.as_bytes());
        stream
            .write_all(&request)
            .await
            .map_err(|error| error.to_string())?;
        let mut status = [0u8; 2];
        stream
            .read_exact(&mut status)
            .await
            .map_err(|error| error.to_string())?;
        if status[1] != 0 {
            return Err("credentials rejected".into());
        }
    }

    let mut request = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    request.extend_from_slice(&target_port.to_be_bytes());
    stream
        .write_all(&request)
        .await
        .map_err(|error| error.to_string())?;

    let mut reply = [0u8; 10];
    stream
        .read_exact(&mut reply)
        .await
        .map_err(|error| error.to_string())?;
    if reply[1] != 0x00 {
        return Err(format!("connect refused with code {}", reply[1]));
    }
    Ok(stream)
}

// Binding a connection to an interface is Linux-only, and the manager refuses
// to serve without it rather than silently taking the default route. So every
// test that carries traffic runs on Linux — which is the only platform the
// edge is deployed on — while the tests that check what happens when a
// listener cannot start run anywhere.
#[tokio::test]
#[cfg(target_os = "linux")]
async fn a_client_reaches_its_target_through_the_proxy() {
    let target = echo_server().await;
    let manager = ProxyManager::new(Arc::new(Loopback));
    let status = manager.start(spec(0)).await;
    assert!(status.listening, "listener did not start: {:?}", status.error);
    let proxy_port: u16 = status.listen_addr.rsplit(':').next().unwrap().parse().unwrap();

    let mut stream = socks5_connect(proxy_port, target, None)
        .await
        .expect("connect through the proxy");
    stream.write_all(b"hello through the proxy").await.unwrap();
    let mut buffer = [0u8; 23];
    stream.read_exact(&mut buffer).await.unwrap();
    assert_eq!(&buffer, b"hello through the proxy");

    // The traffic counters are what the cloud bills and graphs from, so they
    // have to reflect a connection that actually carried bytes.
    drop(stream);
    tokio::time::sleep(std::time::Duration::from_millis(120)).await;
    let after = manager.status_of("instance-1").await.expect("status");
    assert_eq!(after.counters.connections, 1);
    assert_eq!(after.counters.bytes_up, 23, "bytes sent by the client");
    assert_eq!(after.counters.bytes_down, 23, "bytes returned to it");
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn a_proxy_with_credentials_refuses_a_client_without_them() {
    let target = echo_server().await;
    let manager = ProxyManager::new(Arc::new(Loopback));
    let mut guarded = spec(0);
    guarded.auth_enabled = true;
    guarded.username = "operator".into();
    guarded.password = "correct-horse".into();
    let status = manager.start(guarded).await;
    let proxy_port: u16 = status.listen_addr.rsplit(':').next().unwrap().parse().unwrap();

    // Offering "no authentication" must not be accepted just because the
    // client asked: that would make the credential decorative.
    let anonymous = socks5_connect(proxy_port, target, None).await;
    assert!(anonymous.is_err(), "an unauthenticated client got through");

    let wrong = socks5_connect(proxy_port, target, Some(("operator", "wrong"))).await;
    assert!(wrong.is_err(), "a wrong password got through");

    let right = socks5_connect(proxy_port, target, Some(("operator", "correct-horse"))).await;
    assert!(right.is_ok(), "the correct credential was refused: {right:?}");
}

#[tokio::test]
async fn a_modem_with_no_interface_reports_why_rather_than_listening() {
    let manager = ProxyManager::new(Arc::new(NoInterface));
    let status = manager.start(spec(0)).await;

    // Silently using the default route would send traffic out of the wrong
    // connection while looking correct on the page.
    assert!(!status.listening);
    let reason = status.error.expect("a reason");
    assert!(
        reason.contains("867018069514820"),
        "the reason should name the modem: {reason}",
    );
}

#[tokio::test]
async fn applying_desired_state_starts_stops_and_leaves_alone() {
    let manager = ProxyManager::new(Arc::new(Loopback));

    let first = manager.apply(vec![spec(0)], vec![]).await;
    assert_eq!(first.len(), 1);
    assert!(first[0].listening);
    let address = first[0].listen_addr.clone();

    // Re-applying the same specification must not restart the listener: a
    // restart drops every connection through it, and the cloud re-sends the
    // whole desired state on every change to anything.
    let again = manager.apply(vec![spec(0)], vec![]).await;
    assert_eq!(again[0].listen_addr, address, "the listener was restarted");

    // An instance no longer in the desired state stops.
    let emptied = manager.apply(vec![], vec![]).await;
    assert!(emptied.is_empty());
    assert!(manager.status_of("instance-1").await.is_none());
}

#[tokio::test]
async fn a_disabled_instance_is_reported_but_not_listening() {
    let manager = ProxyManager::new(Arc::new(Loopback));
    let mut disabled = spec(0);
    disabled.enabled = false;

    let statuses = manager.apply(vec![disabled], vec![]).await;
    assert_eq!(statuses.len(), 1, "a disabled instance still has a status");
    assert!(!statuses[0].listening);
    // Disabled is not an error: nothing went wrong, it was switched off.
    assert!(statuses[0].error.is_none());
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn traffic_goes_through_an_upstream_when_one_is_configured() {
    let target = echo_server().await;

    // A minimal SOCKS5 upstream: accepts anything, connects onwards, relays.
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = upstream_listener.local_addr().unwrap().port();
    let saw_upstream = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = Arc::clone(&saw_upstream);
    tokio::spawn(async move {
        while let Ok((mut client, _)) = upstream_listener.accept().await {
            counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tokio::spawn(async move {
                let mut greeting = [0u8; 3];
                client.read_exact(&mut greeting).await.ok();
                client.write_all(&[0x05, 0x00]).await.ok();
                let mut head = [0u8; 4];
                client.read_exact(&mut head).await.ok();
                let mut rest = [0u8; 6];
                client.read_exact(&mut rest).await.ok();
                let port = u16::from_be_bytes([rest[4], rest[5]]);
                client
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await
                    .ok();
                if let Ok(server) = TcpStream::connect(("127.0.0.1", port)).await {
                    let (mut cr, mut cw) = client.into_split();
                    let (mut sr, mut sw) = server.into_split();
                    tokio::join!(
                        async {
                            tokio::io::copy(&mut cr, &mut sw).await.ok();
                        },
                        async {
                            tokio::io::copy(&mut sr, &mut cw).await.ok();
                        }
                    );
                }
            });
        }
    });

    let manager = ProxyManager::new(Arc::new(Loopback));
    let mut chained = spec(0);
    chained.upstream_id = "up-1".into();
    let status = manager
        .apply(
            vec![chained],
            vec![UpstreamSpec {
                id: "up-1".into(),
                name: "test upstream".into(),
                address: format!("127.0.0.1:{upstream_port}"),
                protocol: "socks5".into(),
                enabled: true,
                ..UpstreamSpec::default()
            }],
        )
        .await;
    assert!(status[0].listening, "{:?}", status[0].error);
    let proxy_port: u16 = status[0].listen_addr.rsplit(':').next().unwrap().parse().unwrap();

    let mut stream = socks5_connect(proxy_port, target, None)
        .await
        .expect("connect through the chain");
    stream.write_all(b"chained").await.unwrap();
    let mut buffer = [0u8; 7];
    stream.read_exact(&mut buffer).await.unwrap();
    assert_eq!(&buffer, b"chained");

    assert_eq!(
        saw_upstream.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "the connection did not go through the upstream",
    );
}

/// The probe reports the stage it reached, because "cannot connect" and
/// "connects but rejects the credentials" have completely different fixes.
mod probing {
    use std::time::Duration;

    use edge_proxy::probe::{probe, Stage};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn a_closed_port_fails_at_the_connection() {
        // Bound and dropped, so the port is known to be free.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let result = probe(
            &format!("127.0.0.1:{port}"),
            "",
            "",
            None,
            Duration::from_millis(500),
        )
        .await;
        assert!(!result.ok);
        assert_eq!(result.stage, Stage::TcpConnect);
        assert!(result.hint.is_some(), "a connection failure has an obvious next step");
    }

    #[tokio::test]
    async fn something_that_is_not_socks5_fails_at_the_handshake() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut scratch = [0u8; 8];
                stream.read(&mut scratch).await.ok();
                // An HTTP proxy, which is the usual thing to find here by
                // mistake.
                stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await.ok();
            }
        });

        let result = probe(
            &format!("127.0.0.1:{port}"),
            "",
            "",
            None,
            Duration::from_millis(500),
        )
        .await;
        assert!(!result.ok);
        assert_eq!(result.stage, Stage::Handshake);
    }

    #[tokio::test]
    async fn wrong_credentials_fail_at_authentication_not_at_the_handshake() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut greeting = [0u8; 3];
                stream.read_exact(&mut greeting).await.ok();
                stream.write_all(&[0x05, 0x02]).await.ok();
                let mut scratch = [0u8; 64];
                stream.read(&mut scratch).await.ok();
                // Non-zero status means refused.
                stream.write_all(&[0x01, 0x01]).await.ok();
            }
        });

        let result = probe(
            &format!("127.0.0.1:{port}"),
            "operator",
            "wrong",
            None,
            Duration::from_millis(500),
        )
        .await;
        assert!(!result.ok);
        assert_eq!(
            result.stage,
            Stage::Authentication,
            "the stage is what tells an operator which thing to fix",
        );
    }

    #[tokio::test]
    async fn a_working_proxy_reports_ok() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut greeting = [0u8; 3];
                stream.read_exact(&mut greeting).await.ok();
                stream.write_all(&[0x05, 0x00]).await.ok();
            }
        });

        let result = probe(
            &format!("127.0.0.1:{port}"),
            "",
            "",
            None,
            Duration::from_millis(500),
        )
        .await;
        assert!(result.ok, "{result:?}");
        assert_eq!(result.stage, Stage::Ok);
        assert!(result.error.is_none());
    }
}
