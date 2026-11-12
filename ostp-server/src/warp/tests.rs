//! The server's own outbound code against the real WARP proxy, whose WireGuard
//! peer is a local stand-in for Cloudflare (`ostp_warp::testpeer`): two
//! `boringtun` tunnels over loopback, no Cloudflare, no registration.

use crate::outbound::{connect_target, connect_udp_target, OutboundAction, OutboundConfig, OutboundRule};
use base64::Engine;
use ostp_warp::api::Device;
use ostp_warp::store::{self, WarpState};
use ostp_warp::testpeer::{FakeCloudflare, FakeConfig};
use ostp_warp::{WarpConfig, WarpMode};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

const RESERVED: [u8; 3] = [9, 8, 7];

/// A TCP echo server and a UDP echo server on loopback; the first counts the
/// connections it accepts, so that "nothing went out directly" is something
/// the test can see.
struct Targets {
    tcp: SocketAddr,
    udp: SocketAddr,
    accepted: Arc<AtomicUsize>,
}

async fn targets() -> Targets {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp = l.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let n = accepted.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { return };
            n.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut b = [0u8; 4096];
                while let Ok(k) = s.read(&mut b).await {
                    if k == 0 || s.write_all(&b[..k]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    let u = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp = u.local_addr().unwrap();
    tokio::spawn(async move {
        let mut b = [0u8; 2048];
        while let Ok((k, from)) = u.recv_from(&mut b).await {
            let _ = u.send_to(&b[..k], from).await;
        }
    });
    Targets { tcp, udp, accepted }
}

struct Rig {
    fake: FakeCloudflare,
    _warp: ostp_warp::Running,
    proxy: SocketAddr,
    dir: std::path::PathBuf,
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn public_of(private: &[u8; 32]) -> [u8; 32] {
    *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*private)).as_bytes()
}

fn free_port() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap()
}

/// What a registration would have stored, with the stand-in's key.
fn write_state(dir: &std::path::Path, client_private: &[u8; 32], peer_public: &[u8; 32], client_id: Option<&str>) -> std::path::PathBuf {
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut config = serde_json::json!({
        "interface": { "addresses": { "v4": "172.16.0.2", "v6": "2606:4700:110:8000::2" } },
        "peers": [ { "public_key": b64.encode(peer_public), "endpoint": { "host": "engage.invalid:2408" } } ]
    });
    if let Some(id) = client_id {
        config["client_id"] = serde_json::json!(id);
    }
    let dev: Device = serde_json::from_value(serde_json::json!({ "id": "dev", "token": "tok", "config": config })).unwrap();
    std::fs::create_dir_all(dir).unwrap();
    let config_path = dir.join("config.json");
    let st = WarpState::from_device(store::encode_key(client_private), &dev, "2026-11-12T00:00:00.000Z".into()).unwrap();
    store::save(&store::path_for(&config_path), &st).unwrap();
    config_path
}

async fn rig(t: &Targets, tag: &str, mode: WarpMode) -> Rig {
    let client_private: [u8; 32] = rand::random();
    let server_private: [u8; 32] = rand::random();
    let fake = FakeCloudflare::start(FakeConfig {
        server_private,
        client_public: public_of(&client_private),
        reserved: RESERVED,
        tcp_target: t.tcp,
        udp_target: t.udp,
        names: vec![("echo.test".into(), vec!["203.0.113.7".parse().unwrap()])],
        bind: "127.0.0.1:0".parse().unwrap(),
    })
    .await
    .unwrap();
    let dir = std::env::temp_dir().join(format!("ostp-warp-it-{}-{tag}", std::process::id()));
    let id = base64::engine::general_purpose::STANDARD.encode(RESERVED);
    let config_path = write_state(&dir, &client_private, &fake.server_public, Some(&id));
    let proxy = free_port();
    let cfg = WarpConfig { enabled: true, mode, listen: proxy.to_string(), endpoint: fake.endpoint.to_string() };
    let warp = ostp_warp::start(&cfg, &config_path).await.unwrap();
    for _ in 0..100 {
        if warp.tunnel.is_up() {
            return Rig { fake, _warp: warp, proxy, dir };
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the tunnel did not come up against the local peer");
}

fn outbound(proxy: SocketAddr, rules: Vec<OutboundRule>, default_action: OutboundAction) -> OutboundConfig {
    OutboundConfig {
        enabled: true,
        protocol: "socks5".into(),
        address: proxy.ip().to_string(),
        port: proxy.port(),
        username: String::new(),
        password: String::new(),
        rules,
        default_action,
    }
}

async fn echo(mut s: tokio::net::TcpStream, msg: &[u8]) {
    s.write_all(msg).await.unwrap();
    let mut got = vec![0u8; msg.len()];
    tokio::time::timeout(Duration::from_secs(10), s.read_exact(&mut got)).await.expect("echo timed out").unwrap();
    assert_eq!(got, msg);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn all_mode_sends_tcp_and_udp_through_the_tunnel_and_names_are_resolved_inside_it() {
    let t = targets().await;
    let rig = rig(&t, "all", WarpMode::All).await;
    let ob = outbound(rig.proxy, vec![], OutboundAction::Proxy);

    // TCP by name: the name is resolved by the peer's resolver, and the
    // connection reaches the target only through the peer.
    let s = connect_target("echo.test:7000", Some(&ob), None, false, None).await.expect("connect by name");
    echo(s, b"hello through warp").await;
    // TCP by address, IPv4 and IPv6.
    let s = connect_target("198.51.100.9:443", Some(&ob), None, false, None).await.expect("connect by v4 address");
    echo(s, b"v4").await;
    let s = connect_target("[2001:db8::1]:443", Some(&ob), None, false, None).await.expect("connect by v6 address");
    echo(s, b"v6").await;
    {
        let dsts = rig.fake.seen.tcp_dsts.lock().unwrap();
        assert!(dsts.contains(&"203.0.113.7:7000".parse().unwrap()), "a name must have been resolved in the tunnel: {dsts:?}");
        assert!(dsts.contains(&"198.51.100.9:443".parse().unwrap()), "{dsts:?}");
        assert!(dsts.contains(&"[2001:db8::1]:443".parse().unwrap()), "{dsts:?}");
    }
    assert!(rig.fake.seen.dns_queries.lock().unwrap().iter().any(|q| q == "echo.test"), "the resolver in the tunnel was asked");
    assert_eq!(t.accepted.load(Ordering::SeqCst), 3, "all three arrived via the peer");

    // The peer saw the reserved bytes on every datagram the client sent.
    let seen = rig.fake.seen.reserved.lock().unwrap().clone();
    assert!(!seen.is_empty() && seen.iter().all(|r| *r == RESERVED), "reserved bytes on the wire: {seen:?}");

    // UDP through UDP ASSOCIATE.
    let server_udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let up = connect_udp_target("203.0.113.8:5300", Some(&ob), None, false, server_udp.clone()).await.expect("udp associate");
    up.send_to(b"udp datagram", "203.0.113.8:5300").await.unwrap();
    let mut buf = [0u8; 2048];
    let (n, from) = tokio::time::timeout(Duration::from_secs(10), up.recv_from(&mut buf)).await.expect("udp echo timed out").unwrap();
    assert_eq!(&buf[..n], b"udp datagram");
    assert_eq!(from, "203.0.113.8:5300", "the reply carries the address the datagram was sent to");
    assert!(rig.fake.seen.udp_dsts.lock().unwrap().contains(&"203.0.113.8:5300".parse().unwrap()));
    // A domain target over UDP is resolved in the tunnel too.
    up.send_to(b"by name", "echo.test:5301").await.unwrap();
    let (n, _) = tokio::time::timeout(Duration::from_secs(10), up.recv_from(&mut buf)).await.expect("udp echo by name timed out").unwrap();
    assert_eq!(&buf[..n], b"by name");
    assert!(rig.fake.seen.udp_dsts.lock().unwrap().contains(&"203.0.113.7:5301".parse().unwrap()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rules_mode_proxies_only_what_the_rules_say() {
    let t = targets().await;
    let rig = rig(&t, "rules", WarpMode::Rules).await;
    let rules = vec![OutboundRule {
        domain_suffix: vec!["echo.test".into()],
        ip_cidr: vec![],
        protocol: None,
        action: OutboundAction::Proxy,
        send_from: None,
    }];
    let ob = outbound(rig.proxy, rules, OutboundAction::Direct);
    // Matches the rule: through WARP.
    let s = connect_target("echo.test:7000", Some(&ob), None, false, None).await.unwrap();
    echo(s, b"via warp").await;
    assert_eq!(rig.fake.seen.tcp_dsts.lock().unwrap().len(), 1);
    // Does not match: leaves directly, as the operator wrote it; the peer never sees it.
    let s = connect_target(&t.tcp.to_string(), Some(&ob), None, false, None).await.unwrap();
    echo(s, b"direct").await;
    assert_eq!(rig.fake.seen.tcp_dsts.lock().unwrap().len(), 1, "the direct connection did not enter the tunnel");
    assert_eq!(t.accepted.load(Ordering::SeqCst), 2);
}

/// A tunnel that was up and whose peer is gone: with the rules asking for
/// WARP, connections fail. The target is reachable directly (loopback), so a
/// connection that got through would be a leak, and the target counts what it
/// accepts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dead_tunnel_fails_closed_for_tcp_and_udp() {
    let t = targets().await;
    let mut rig = rig(&t, "dead", WarpMode::All).await;
    let ob = outbound(rig.proxy, vec![], OutboundAction::Proxy);
    let s = connect_target(&t.tcp.to_string(), Some(&ob), None, false, None).await.unwrap();
    echo(s, b"alive").await;
    assert_eq!(t.accepted.load(Ordering::SeqCst), 1);

    rig.fake.stop();
    // TCP: the SYN goes to a peer that no longer answers.
    let r = connect_target(&t.tcp.to_string(), Some(&ob), None, false, None).await;
    assert!(r.is_err(), "a connection must not succeed with the peer gone");
    assert_eq!(t.accepted.load(Ordering::SeqCst), 1, "nothing reached the target directly");

    // UDP: the association is made (the proxy is up) but nothing comes back.
    let server_udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let up = connect_udp_target(&t.udp.to_string(), Some(&ob), None, false, server_udp).await.unwrap();
    up.send_to(b"x", &t.udp.to_string()).await.unwrap();
    let mut buf = [0u8; 64];
    assert!(
        tokio::time::timeout(Duration::from_secs(2), up.recv_from(&mut buf)).await.is_err(),
        "no UDP answer may arrive with the peer gone (the UDP echo is reachable directly)"
    );
}

/// Nothing answers at the peer's address from the start: the tunnel never
/// comes up, and every connection is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tunnel_that_never_came_up_refuses_connections() {
    let t = targets().await;
    let dead_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap(); // listens, never answers
    let client_private: [u8; 32] = rand::random();
    let peer_public = public_of(&rand::random::<[u8; 32]>());
    let dir = std::env::temp_dir().join(format!("ostp-warp-it-{}-never", std::process::id()));
    let config_path = write_state(&dir, &client_private, &peer_public, None);
    let proxy = free_port();
    let cfg = WarpConfig { enabled: true, mode: WarpMode::All, listen: proxy.to_string(), endpoint: dead_peer.local_addr().unwrap().to_string() };
    let warp = ostp_warp::start(&cfg, &config_path).await.unwrap();
    let ob = outbound(proxy, vec![], OutboundAction::Proxy);
    let r = connect_target(&t.tcp.to_string(), Some(&ob), None, false, None).await;
    let e = r.err().expect("the connection must fail").to_string();
    assert!(e.contains("SOCKS5 connect failed"), "the proxy refused: {e}");
    assert_eq!(t.accepted.load(Ordering::SeqCst), 0);
    assert!(!warp.tunnel.is_up());
    drop(warp);
    let _ = std::fs::remove_dir_all(&dir);
}
