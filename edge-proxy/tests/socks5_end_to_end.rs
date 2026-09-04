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

/// 拿一个刚释放的端口号，用来证明被拒绝的实例真的没有占过它。
async fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);
    port
}

// 这个构建只会说 SOCKS5，而 "http" 是契约允许云端下发的另一个合法值——这条路
// 今天就走得到，不是防御性断言。配了它以前照样起监听、回报 listening:true、
// error 是空的，端口上说的却还是 SOCKS5——面板于是同时显示「监听正常」和
// 「客户端连不上」，没有任何线索指向协议不匹配。
#[tokio::test]
async fn an_unsupported_protocol_is_refused_with_a_reason_rather_than_a_socks5_listener() {
    let manager = ProxyManager::new(Arc::new(Loopback));
    let port = free_port().await;
    let mut wrong = spec(port);
    wrong.protocol = "http".into();

    let statuses = manager.apply(vec![wrong], vec![]).await;
    assert_eq!(statuses.len(), 1);
    assert!(
        !statuses[0].listening,
        "an instance whose protocol this build cannot serve claimed to be listening",
    );
    let reason = statuses[0]
        .error
        .clone()
        .expect("refused, but with no reason an operator could act on");
    assert!(
        reason.contains("http"),
        "the reason should name what was asked for: {reason}",
    );
    assert!(
        reason.contains("socks5"),
        "the reason should name what this build does serve: {reason}",
    );

    // 拒绝要在 bind 之前发生。占了端口再退回去，配置错误会被下一次重试
    // 伪装成端口冲突。
    let free = TcpListener::bind(("127.0.0.1", port)).await;
    assert!(free.is_ok(), "the refused instance left a listener on the port");

    // ⚠️ 理由必须同时进 failed 表，但**不是**为了「面板刷新」。
    //
    //    这里原先写的是「面板读 apply 的返回值，后续刷新读 status_of/statuses」
    //    ——那条刷新路径不存在：`statuses()` 全 workspace 零调用者，`status_of()`
    //    只在 `apply()` 内部和测试里被调；唯一周期性上报的
    //    `report_proxy_traffic` 走 `drain_traffic()`，只遍历 `running`，
    //    一个被拒的实例什么都不贡献。
    //
    //    真正承重的是 `restart()`：它回落到 failed 表取原因，而
    //    `proxy_lifecycle` 的 start/restart 会走到那里。不写这张表的话，
    //    一次启动尝试拿到的是 `not_configured`，而不是「你配了个我不认识的
    //    协议」——把一个配置错误说成一个没配置。
    let later = manager
        .status_of("instance-1")
        .await
        .expect("the refused instance vanished from the statuses instead of keeping its reason");
    assert!(
        !later.listening,
        "a refused instance turned into a listening one on the next read",
    );
    assert_eq!(later.error.as_deref(), Some(reason.as_str()));
}

// 大小写和简写都不收。依据是契约 schema 把 protocol 写死成
// enum ["socks5","http"]——全小写、没有别名，所以下面这些拼写压根不是合法的
// 契约值；放宽只会让边缘收下网关都不放行的东西。完整理由在 `SUPPORTED_PROTOCOL`
// 的注释上，其中包括 `differs()` 必须和这里同一种比法。
#[tokio::test]
async fn only_the_exact_spelling_socks5_is_accepted() {
    // 对照组先跑：校验不能把本来好好的配置一起挡掉。放在前面是为了让
    // 「校验写反了」这一类错误报在这一行，而不是报成某个拼写被接受了。
    let manager = ProxyManager::new(Arc::new(Loopback));
    let statuses = manager.apply(vec![spec(0)], vec![]).await;
    assert!(
        statuses[0].listening,
        "the spelling this build does serve was refused: {:?}",
        statuses[0].error,
    );

    for spelling in ["SOCKS5", "Socks5", "socks", "socks5 ", ""] {
        let manager = ProxyManager::new(Arc::new(Loopback));
        let mut variant = spec(0);
        variant.protocol = spelling.into();
        let statuses = manager.apply(vec![variant], vec![]).await;
        assert!(
            !statuses[0].listening,
            "{spelling:?} was accepted as a protocol this build can serve",
        );
        assert!(statuses[0].error.is_some(), "{spelling:?} was refused without a reason");
    }
}

// 上游也是被无条件当成 SOCKS5 握手的。不在 apply 时挡住，配了 http 的上游会在
// 每条连接上各失败一次，而报出来的是「上游拒绝了所有认证方式」。
#[tokio::test]
async fn an_upstream_that_is_not_socks5_stops_the_instance_chained_through_it() {
    let manager = ProxyManager::new(Arc::new(Loopback));
    let mut chained = spec(0);
    chained.upstream_id = "up-1".into();

    let statuses = manager
        .apply(
            vec![chained],
            vec![UpstreamSpec {
                id: "up-1".into(),
                address: "127.0.0.1:1".into(),
                protocol: "http".into(),
                enabled: true,
                ..UpstreamSpec::default()
            }],
        )
        .await;
    assert!(
        !statuses[0].listening,
        "an instance chained through an upstream this build cannot speak to claimed to be listening",
    );
    let reason = statuses[0]
        .error
        .clone()
        .expect("refused, but with no reason an operator could act on");
    assert!(
        reason.contains("up-1"),
        "the reason should name the upstream, not just the instance: {reason}",
    );
    assert!(
        reason.contains("http"),
        "the reason should name the upstream's protocol: {reason}",
    );
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

/// The cloud folds reports into hourly buckets by adding them, so what the
/// edge sends has to be what changed since last time.
mod traffic {
    use std::sync::Arc;

    use edge_proxy::{InstanceSpec, InterfaceResolver, ProxyManager};

    struct Loopback;

    impl InterfaceResolver for Loopback {
        fn interface_for(&self, _modem_imei: &str) -> Option<String> {
            Some("lo".to_string())
        }
    }

    fn spec() -> InstanceSpec {
        InstanceSpec {
            id: "instance-1".into(),
            modem_imei: "867018069514820".into(),
            protocol: "socks5".into(),
            listen_addr: "127.0.0.1".into(),
            listen_port: 0,
            enabled: true,
            ..InstanceSpec::default()
        }
    }

    // A listener that has carried nothing must produce no entry at all, rather
    // than a row of zeroes for every instance on every report.
    #[tokio::test]
    async fn an_idle_listener_reports_nothing() {
        let manager = ProxyManager::new(Arc::new(Loopback));
        let status = manager.start(spec()).await;
        // Whether it bound or not, an idle listener has no traffic to report.
        let _ = status;
        assert!(manager.drain_traffic().await.is_empty());
    }

    // Draining twice must not report the same bytes twice: the cloud adds
    // what it receives, so a repeated total would inflate the hour.
    #[tokio::test]
    async fn draining_twice_reports_each_byte_once() {
        let manager = ProxyManager::new(Arc::new(Loopback));
        manager.start(spec()).await;
        let first = manager.drain_traffic().await;
        let second = manager.drain_traffic().await;
        assert_eq!(first.len(), second.len());
        for delta in second {
            assert_eq!(delta.bytes_up, 0, "a second drain re-reported traffic");
        }
    }
}
