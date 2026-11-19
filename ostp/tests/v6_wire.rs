//! End to end for protocol v6: a real server built from a `protocol` section,
//! a real client bridge built from a link, and an echo target.
//!
//! What is checked: a profile with `pk` connects to a server with that key
//! (UDP and UoT); the transitional mode serves a v5 client; and a v6 profile
//! that meets a server without v6, or with another key, ends in the clear
//! error instead of a bare timeout.
//!
//! The session layer (stage 2) is checked through the whole chain: a SOCKS5
//! client talks to the real local proxy, which feeds the real bridge, which
//! talks to the real server and a target: half-close, thousands of streams in
//! one session, the stream limit, a UDP flow whose lost datagram is not
//! resent, and an abort that reaches the program as a reset.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use ostp_client::app::{BridgeCommand, UiEvent};
use ostp_client::bridge::{Bridge, BridgeMetrics};
use ostp_client::config::{ClientConfig, ProtocolCfg, ServerConfig};
use ostp_client::tunnel::{ProxyEvent, ProxyToClientMsg};
use ostp_core::share_link::ShareLink;
use portable_atomic::{AtomicU32, AtomicU64, AtomicU8};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch};
use tokio::time::timeout;

const KEY: &str = "v6-wire-e2e-key";
const STREAM: u32 = 7;

fn free_port() -> u16 {
    loop {
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = tcp.local_addr().unwrap().port();
        if std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

/// A server whose wire settings come from a config's `protocol` section, the
/// way `ostp` reads them. `None`: a config without the section.
async fn start_server(protocol: Option<serde_json::Value>) -> SocketAddr {
    start_server_bound(protocol, None).await
}

/// `bind_ip`: the address the server's own outgoing sockets use. The UDP
/// tests need `127.0.0.1`: without it the association's socket is `[::]`,
/// which on Windows is IPv6-only and cannot send to an IPv4 target.
async fn start_server_bound(protocol: Option<serde_json::Value>, bind_ip: Option<&str>) -> SocketAddr {
    start_server_full(protocol, bind_ip, None, None).await
}

const API_TOKEN: &str = "v6-wire-e2e-token";

/// `config_path`: the file the server watches for access-key changes (hot
/// reload, polled every 5 s). `api`: where the management API listens (token
/// `API_TOKEN`), to read the server's own count of live sessions.
async fn start_server_full(
    protocol: Option<serde_json::Value>,
    bind_ip: Option<&str>,
    config_path: Option<std::path::PathBuf>,
    api: Option<SocketAddr>,
) -> SocketAddr {
    let addr: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
    let mut cfg = serde_json::json!({
        "listen": addr.to_string(),
        "access_keys": [KEY],
    });
    if let Some(p) = protocol {
        cfg["protocol"] = p;
    }
    let cfg: ServerConfig = serde_json::from_value(cfg).unwrap();
    let wire = match &cfg.protocol {
        Some(p) => ostp_server::WireSettings { server_key: p.private_key().unwrap(), accept_v5: p.accept_v5 },
        None => ostp_server::WireSettings { server_key: None, accept_v5: true },
    };
    let params = ostp_server::ServerParams {
        bind_addrs: vec![addr.to_string()],
        server_public_ip: None,
        bind_ip: bind_ip.map(str::to_string),
        access_keys: vec![(KEY.to_string(), ostp_server::api::UserMeta { name: None, limit_bytes: None, max_devices: None })],
        outbound: None,
        api_config: api.map(|a| ostp_server::api::ApiConfig {
            enabled: true,
            bind: a.to_string(),
            token: Some(API_TOKEN.to_string()),
            webpath: String::new(),
            username: String::new(),
            password_hash: String::new(),
        }),
        fallback_config: None,
        privacy: ostp_core::logpriv::Privacy::Normal,
        dns_config: None,
        config_path,
        tls: None,
        subscription: None,
        overnet: None,
        warp: None,
        local_access: true,
        wire,
    };
    tokio::spawn(async move {
        if let Err(e) = ostp_server::run_server(params).await {
            panic!("server failed: {e}");
        }
    });
    for _ in 0..100 {
        if TcpStream::connect(addr).await.is_ok() {
            return addr;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("server did not start on {addr}");
}

async fn start_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16 * 1024];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

struct Client {
    cmd: mpsc::Sender<BridgeCommand>,
    proxy_ev: mpsc::Sender<ProxyEvent>,
    to_app: mpsc::UnboundedReceiver<(u32, ProxyToClientMsg)>,
    logs: Arc<Mutex<Vec<String>>>,
    _shutdown: watch::Sender<bool>,
    metrics: Arc<BridgeMetrics>,
    /// When the bridge reported that the server closed the session, and what
    /// it told the user.
    closed: Arc<Mutex<Option<(std::time::Instant, String)>>>,
    /// `TunnelStopped` was reported.
    stopped: Arc<AtomicBool>,
}

impl Client {
    /// A client from a link, the way `ostp --import` turns one into a config.
    async fn from_link(link: &ShareLink, mode: &str) -> Client {
        let mut cfg = ClientConfig::default();
        cfg.ostp.server_addr = link.server();
        cfg.ostp.access_key = link.key.clone();
        cfg.ostp.server_pk = link.pk.as_ref().map(ostp_core::server_key::encode_key);
        cfg.transport.mode = mode.to_string();
        cfg.multiplex.enabled = false;
        let metrics = Arc::new(BridgeMetrics {
            bytes_sent: AtomicU64::new(0),
            bytes_recv: AtomicU64::new(0),
            connection_state: AtomicU8::new(0),
            rtt_ms: AtomicU32::new(0),
            queue_ms: AtomicU32::new(0),
        });
        let bridge = Bridge::new(&cfg, metrics.clone()).unwrap();
        let (ui_tx, mut ui_rx) = mpsc::channel(4096);
        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (proxy_ev_tx, proxy_ev_rx) = mpsc::channel(256);
        let (to_app_tx, to_app_rx) = mpsc::unbounded_channel();
        tokio::spawn(bridge.run(ui_tx, cmd_rx, shutdown_rx, proxy_ev_rx, to_app_tx));
        let logs = Arc::new(Mutex::new(Vec::new()));
        let closed = Arc::new(Mutex::new(None));
        let stopped = Arc::new(AtomicBool::new(false));
        {
            let (logs, closed, stopped) = (logs.clone(), closed.clone(), stopped.clone());
            tokio::spawn(async move {
                while let Some(ev) = ui_rx.recv().await {
                    match ev {
                        UiEvent::Log(line) => logs.lock().unwrap().push(line),
                        UiEvent::ServerClosed(message) => *closed.lock().unwrap() = Some((std::time::Instant::now(), message)),
                        UiEvent::TunnelStopped => stopped.store(true, Ordering::Relaxed),
                        _ => {}
                    }
                }
            });
        }
        cmd_tx.send(BridgeCommand::ToggleTunnel).await.unwrap();
        Client { cmd: cmd_tx, proxy_ev: proxy_ev_tx, to_app: to_app_rx, logs, _shutdown: shutdown_tx, metrics, closed, stopped }
    }

    async fn wait_log(&self, needle: &str, within: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + within;
        while tokio::time::Instant::now() < deadline {
            if self.logs.lock().unwrap().iter().any(|l| l.contains(needle)) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        false
    }

    fn log_text(&self) -> String {
        self.logs.lock().unwrap().join("\n")
    }

    async fn echo_through(&mut self, target: SocketAddr, data: &[u8]) {
        self.proxy_ev.send(ProxyEvent::NewStream { stream_id: STREAM, target: target.to_string() }).await.unwrap();
        match timeout(Duration::from_secs(5), self.to_app.recv()).await {
            // A v6 stream says so in its ConnectOk.
            Ok(Some((STREAM, ProxyToClientMsg::ConnectOk | ProxyToClientMsg::ConnectOkV6))) => {}
            _ => panic!("no ConnectOk; log:\n{}", self.log_text()),
        }
        self.proxy_ev.send(ProxyEvent::Data { stream_id: STREAM, payload: Bytes::copy_from_slice(data) }).await.unwrap();
        let mut got = Vec::new();
        while got.len() < data.len() {
            match timeout(Duration::from_secs(5), self.to_app.recv()).await {
                Ok(Some((STREAM, ProxyToClientMsg::Data(c)))) => got.extend_from_slice(&c),
                Ok(Some((STREAM, ProxyToClientMsg::Window(_)))) => {}
                _ => panic!("no echo; log:\n{}", self.log_text()),
            }
        }
        assert_eq!(got, data);
    }
}

/// A `protocol` section as `ostp key server new` writes it, and its public key.
fn section(accept_v5: bool) -> (serde_json::Value, [u8; 32]) {
    let (private, public) = ostp_core::crypto::noise::generate_server_key();
    (
        serde_json::json!({ "server_key": ostp_core::server_key::encode_key(&private), "accept_v5": accept_v5 }),
        public,
    )
}

/// The link the server would hand out, as text, parsed back: what an app holds.
fn link_to(server: SocketAddr, pk: Option<[u8; 32]>) -> ShareLink {
    let uri = ShareLink::new(KEY, server.ip().to_string(), server.port()).with_pk(pk).to_uri();
    ShareLink::parse(&uri).unwrap()
}

async fn v6_profile_works(mode: &str) {
    let (protocol, public) = section(false);
    let server = start_server(Some(protocol)).await;
    let echo = start_echo().await;
    let mut client = Client::from_link(&link_to(server, Some(public)), mode).await;
    assert!(client.wait_log("Connection established", Duration::from_secs(10)).await, "log:\n{}", client.log_text());
    client.echo_through(echo, b"hello over v6").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_v6_profile_connects_to_a_v6_only_server_over_udp() {
    v6_profile_works("udp").await;
}

/// The RTT the apps read is the path's, taken from ACKs: it is there once the
/// session has carried data, on an idle loopback path the queue delay is nil,
/// and the in-tunnel ping that feeds the queue delay has been answered.
#[tokio::test(flavor = "multi_thread")]
async fn the_apps_rtt_is_the_path_round_trip_and_the_queue_delay_stays_small_when_idle() {
    let (protocol, public) = section(false);
    let server = start_server(Some(protocol)).await;
    let echo = start_echo().await;
    let mut client = Client::from_link(&link_to(server, Some(public)), "udp").await;
    assert!(client.wait_log("Connection established", Duration::from_secs(10)).await, "log:\n{}", client.log_text());
    client.echo_through(echo, b"hello").await;
    // The metrics tick runs once a second.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    while client.metrics.rtt_ms.load(Ordering::Relaxed) == 0 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let rtt = client.metrics.rtt_ms.load(Ordering::Relaxed);
    let queue = client.metrics.queue_ms.load(Ordering::Relaxed);
    assert!(rtt >= 1, "no path RTT published");
    assert!(rtt < 500, "a loopback path has no {rtt} ms RTT");
    assert!(queue <= 200, "an idle path has no {queue} ms queue");
}

/// A UDP forwarder between one client and the server that drops datagrams
/// above `limit` bytes, as a path with a small MTU does, and keeps what it
/// saw: the sizes it dropped and the largest it passed.
struct SmallMtuPath {
    addr: SocketAddr,
    dropped: Arc<Mutex<Vec<usize>>>,
    largest_passed: Arc<std::sync::atomic::AtomicUsize>,
}

async fn small_mtu_path(server: SocketAddr, limit: usize) -> SmallMtuPath {
    let front = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = front.local_addr().unwrap();
    let back = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    back.connect(server).await.unwrap();
    let dropped = Arc::new(Mutex::new(Vec::new()));
    let largest_passed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let judge = {
        let (dropped, largest) = (dropped.clone(), largest_passed.clone());
        move |n: usize| {
            if n > limit {
                dropped.lock().unwrap().push(n);
                false
            } else {
                largest.fetch_max(n, Ordering::Relaxed);
                true
            }
        }
    };
    {
        let (front, back, client, judge) = (front.clone(), back.clone(), client.clone(), judge.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                // A datagram sent to a closed port makes the next receive fail
                // on Windows (WSAECONNRESET); the socket is fine.
                let Ok((n, from)) = front.recv_from(&mut buf).await else { continue };
                *client.lock().unwrap() = Some(from);
                if judge(n) {
                    let _ = back.send(&buf[..n]).await;
                }
            }
        });
    }
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let Ok(n) = back.recv(&mut buf).await else { continue };
            let to = *client.lock().unwrap();
            if let (Some(to), true) = (to, judge(n)) {
                let _ = front.send_to(&buf[..n], to).await;
            }
        }
    });
    SmallMtuPath { addr, dropped, largest_passed }
}

/// `mtu` left out is auto. Over a path that carries at most 1300 bytes per
/// datagram, a v6 client and server find 1280 by themselves: the probes of
/// 1350 are the only datagrams lost, a 300 KB echo (server chunking follows
/// the size) arrives whole, and the largest datagram that went through is
/// exactly the discovered size.
#[tokio::test(flavor = "multi_thread")]
async fn the_datagram_size_is_found_by_the_session_over_a_path_that_carries_1300_bytes() {
    let (protocol, public) = section(false);
    let server = start_server(Some(protocol)).await;
    let echo = start_echo().await;
    let path = small_mtu_path(server, 1300).await;
    let mut client = Client::from_link(&link_to(path.addr, Some(public)), "udp").await;
    assert!(client.wait_log("Connection established", Duration::from_secs(10)).await, "log:\n{}", client.log_text());

    // Three lost probes of the rung per side end the climb (a probe is given
    // up after at least a second, and the next waits half a second).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while path.dropped.lock().unwrap().len() < 6 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let dropped = path.dropped.lock().unwrap().clone();
    assert_eq!(dropped, vec![1350; 6], "only the probes of the rung above the path are lost");

    let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    client.echo_through(echo, &data).await;
    assert_eq!(path.dropped.lock().unwrap().len(), 6, "no data frame was lost to the size");
    assert_eq!(path.largest_passed.load(Ordering::Relaxed), 1280, "data filled datagrams of the discovered size, no more");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_v6_profile_connects_to_a_v6_only_server_over_uot() {
    v6_profile_works("uot").await;
}

/// The transitional mode: a link without pk is a v5 profile and the same
/// server, which has a key, still serves it.
#[tokio::test(flavor = "multi_thread")]
async fn the_transitional_mode_serves_a_v5_profile() {
    let (protocol, _) = section(true);
    let server = start_server(Some(protocol)).await;
    let echo = start_echo().await;
    let mut client = Client::from_link(&link_to(server, None), "udp").await;
    assert!(client.wait_log("Connection established", Duration::from_secs(10)).await, "log:\n{}", client.log_text());
    client.echo_through(echo, b"hello over v5").await;
}

async fn assert_clear_v6_error(client: &Client) {
    assert!(client.wait_log("Connection failed", Duration::from_secs(40)).await, "log:\n{}", client.log_text());
    let log = client.log_text();
    assert!(!log.contains("Connection established"), "{log}");
    assert!(log.contains("did not answer the protocol v6 handshake"), "{log}");
    assert!(log.contains("older than 0.5.0") && log.contains("key has changed") && log.contains("new link"), "{log}");
}

/// A v6 profile against a server that has no key (a 0.4.x server behaves the
/// same: it cannot read the handshake and stays silent).
#[tokio::test(flavor = "multi_thread")]
async fn a_v6_profile_against_a_server_without_v6_ends_in_a_clear_error() {
    let server = start_server(None).await;
    let (_, public) = section(true);
    let client = Client::from_link(&link_to(server, Some(public)), "udp").await;
    assert_clear_v6_error(&client).await;
}

/// The server's key was replaced after the link was made.
#[tokio::test(flavor = "multi_thread")]
async fn a_v6_profile_against_a_server_with_another_key_ends_in_a_clear_error() {
    let (protocol, _new_public) = section(true);
    let server = start_server(Some(protocol)).await;
    let (_, old_public) = section(true);
    let client = Client::from_link(&link_to(server, Some(old_public)), "udp").await;
    assert_clear_v6_error(&client).await;
}

/// A protocol section with a damaged key is refused when it is read, and the
/// refusal does not contain the key.
#[test]
fn a_damaged_server_key_is_refused_without_echoing_it() {
    let p: ProtocolCfg = serde_json::from_value(serde_json::json!({ "server_key": "SECRETSECRET", "accept_v5": true })).unwrap();
    let e = p.private_key().unwrap_err().to_string();
    assert!(!e.contains("SECRETSECRET"), "{e}");
}

// ── The session layer through the whole chain ────────────────────────────────

/// A SOCKS5 listener (the real local proxy), the real bridge and, behind it,
/// whatever server address it is given.
struct Tunnel {
    socks: SocketAddr,
    logs: Arc<Mutex<Vec<String>>>,
    _cmd: mpsc::Sender<BridgeCommand>,
    _shutdown: watch::Sender<bool>,
    _exclusions: watch::Sender<ostp_client::config::ExclusionConfig>,
}

impl Tunnel {
    async fn start(server: SocketAddr, pk: Option<[u8; 32]>) -> Tunnel {
        let link = link_to(server, pk);
        let socks: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
        let mut cfg = ClientConfig::default();
        // Not "proxy": that would point the system's proxy setting at the test.
        cfg.mode = "tun".to_string();
        cfg.local_proxy.bind_addr = socks.to_string();
        cfg.ostp.server_addr = link.server();
        cfg.ostp.access_key = link.key.clone();
        cfg.ostp.server_pk = link.pk.as_ref().map(ostp_core::server_key::encode_key);
        cfg.transport.mode = "udp".to_string();
        cfg.multiplex.enabled = false;
        let metrics = Arc::new(BridgeMetrics {
            bytes_sent: AtomicU64::new(0),
            bytes_recv: AtomicU64::new(0),
            connection_state: AtomicU8::new(0),
            rtt_ms: AtomicU32::new(0),
            queue_ms: AtomicU32::new(0),
        });
        let bridge = Bridge::new(&cfg, metrics).unwrap();
        let (ui_tx, mut ui_rx) = mpsc::channel(65536);
        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (proxy_ev_tx, proxy_ev_rx) = mpsc::channel(256);
        let (to_app_tx, to_app_rx) = mpsc::unbounded_channel();
        let (excl_tx, excl_rx) = watch::channel(cfg.exclusions.clone());
        tokio::spawn(bridge.run(ui_tx, cmd_rx, shutdown_rx.clone(), proxy_ev_rx, to_app_tx));
        tokio::spawn(ostp_client::tunnel::run_local_socks5_proxy(
            cfg.local_proxy.clone(),
            cfg.ostp.clone(),
            excl_rx,
            false,
            shutdown_rx,
            proxy_ev_tx,
            to_app_rx,
        ));
        let logs = Arc::new(Mutex::new(Vec::new()));
        {
            let logs = logs.clone();
            tokio::spawn(async move {
                while let Some(ev) = ui_rx.recv().await {
                    if let UiEvent::Log(line) = ev {
                        logs.lock().unwrap().push(line);
                    }
                }
            });
        }
        cmd_tx.send(BridgeCommand::ToggleTunnel).await.unwrap();
        let t = Tunnel { socks, logs, _cmd: cmd_tx, _shutdown: shutdown_tx, _exclusions: excl_tx };
        assert!(t.wait_log("Connection established", Duration::from_secs(10)).await, "log:\n{}", t.log_text());
        for _ in 0..100 {
            if TcpStream::connect(socks).await.is_ok() {
                return t;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("the local proxy did not start on {socks}");
    }

    async fn wait_log(&self, needle: &str, within: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + within;
        while tokio::time::Instant::now() < deadline {
            if self.logs.lock().unwrap().iter().any(|l| l.contains(needle)) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        false
    }

    fn log_text(&self) -> String {
        self.logs.lock().unwrap().join("\n")
    }

    /// A connection to `target` through the tunnel, as a SOCKS5 client makes
    /// it. `Err` is the SOCKS reply code of a refusal.
    async fn connect(&self, target: SocketAddr) -> Result<TcpStream, u8> {
        // Thousands of short connections can use up the machine's ephemeral
        // ports (Windows keeps closed ones for two minutes): wait for one.
        let mut s = {
            let mut tries = 0;
            loop {
                match TcpStream::connect(self.socks).await {
                    Ok(s) => break s,
                    Err(e) if e.kind() == std::io::ErrorKind::AddrInUse && tries < 100 => {
                        tries += 1;
                        tokio::time::sleep(Duration::from_millis(250)).await;
                    }
                    Err(e) => panic!("cannot connect to the local proxy: {e}"),
                }
            }
        };
        s.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0u8; 2];
        s.read_exact(&mut method).await.unwrap();
        let ip = match target.ip() {
            std::net::IpAddr::V4(ip) => ip.octets(),
            _ => panic!("IPv4 targets only"),
        };
        let mut req = vec![5, 1, 0, 1];
        req.extend_from_slice(&ip);
        req.extend_from_slice(&target.port().to_be_bytes());
        s.write_all(&req).await.unwrap();
        let mut rep = [0u8; 10];
        match timeout(Duration::from_secs(20), s.read_exact(&mut rep)).await {
            Ok(Ok(_)) if rep[1] == 0 => Ok(s),
            Ok(Ok(_)) => Err(rep[1]),
            _ => Err(255),
        }
    }
}

async fn v6_tunnel() -> (Tunnel, SocketAddr) {
    let (protocol, public) = section(false);
    let server = start_server(Some(protocol)).await;
    (Tunnel::start(server, Some(public)).await, server)
}

/// Reads to the end of the stream, then answers with the number of bytes it
/// got (8 bytes) and `reply_len` bytes of a pattern, then closes: what a
/// request/response server does after a client that has shut its write side.
async fn start_reply_after_eof(reply_len: usize) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut got = 0u64;
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => got += n as u64,
                        Err(_) => return,
                    }
                }
                let mut reply = got.to_be_bytes().to_vec();
                reply.extend((0..reply_len).map(|i| (i % 251) as u8));
                let _ = s.write_all(&reply).await;
                let _ = s.shutdown().await;
            });
        }
    });
    addr
}

/// The app sends a request, shuts down its write side and still receives the
/// whole reply. Before the half-close a program's end of stream closed the
/// stream and the reply was lost.
#[tokio::test(flavor = "multi_thread")]
async fn half_close_the_app_shuts_its_write_side_and_still_gets_the_whole_reply() {
    let (tunnel, _) = v6_tunnel().await;
    let reply_len = 400_000;
    let target = start_reply_after_eof(reply_len).await;
    let mut app = tunnel.connect(target).await.unwrap_or_else(|c| panic!("refused ({c}); log:\n{}", tunnel.log_text()));

    let request: Vec<u8> = (0..300_000).map(|i| (i % 241) as u8).collect();
    app.write_all(&request).await.unwrap();
    app.shutdown().await.unwrap(); // FIN: "I will write no more"

    let mut reply = Vec::new();
    timeout(Duration::from_secs(30), app.read_to_end(&mut reply))
        .await
        .unwrap_or_else(|_| panic!("the reply did not arrive; got {} bytes; log:\n{}", reply.len(), tunnel.log_text()))
        .unwrap_or_else(|e| panic!("an orderly end of stream was expected, got {e}; got {} bytes; log:\n{}", reply.len(), tunnel.log_text()));
    assert_eq!(reply.len(), 8 + reply_len, "the whole reply");
    assert_eq!(u64::from_be_bytes(reply[..8].try_into().unwrap()), request.len() as u64, "the target got the whole request before its end");
    assert!(reply[8..].iter().enumerate().all(|(i, b)| *b == (i % 251) as u8), "the reply is intact");
}

/// The other direction: the target finishes first, the app still writes.
#[tokio::test(flavor = "multi_thread")]
async fn half_close_the_target_finishes_and_the_app_may_still_write() {
    let (tunnel, _) = v6_tunnel().await;
    // Sends its greeting and closes its write side; then reads what the app
    // sends until the app is done, and reports how much that was.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    let (done_tx, mut done_rx) = mpsc::unbounded_channel::<usize>();
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        s.write_all(b"greeting").await.unwrap();
        s.shutdown().await.unwrap();
        let mut total = 0;
        let mut buf = vec![0u8; 16 * 1024];
        while let Ok(n) = s.read(&mut buf).await {
            if n == 0 {
                break;
            }
            total += n;
        }
        let _ = done_tx.send(total);
    });
    let mut app = tunnel.connect(target).await.unwrap();
    let mut greeting = [0u8; 8];
    timeout(Duration::from_secs(10), app.read_exact(&mut greeting)).await.unwrap().unwrap();
    assert_eq!(&greeting, b"greeting");
    // The target's end of stream arrives as an end of stream, and the app can still write.
    let mut rest = Vec::new();
    timeout(Duration::from_secs(10), app.read_to_end(&mut rest)).await.unwrap().unwrap();
    assert!(rest.is_empty());
    app.write_all(&vec![9u8; 100_000]).await.unwrap();
    app.shutdown().await.unwrap();
    let total = timeout(Duration::from_secs(10), done_rx.recv()).await.unwrap().unwrap();
    assert_eq!(total, 100_000, "the write after the target's end of stream reached it");
}

/// One session carries far more streams than the receiver tracks at once
/// (2048): finished streams are released. Without that, the streams after the
/// 2048th get no answer. (Each stream is two short TCP connections of the
/// machine, so running this twice within two minutes can wait on the
/// ephemeral ports.)
#[tokio::test(flavor = "multi_thread")]
async fn more_than_3000_streams_in_one_session() {
    let (tunnel, _) = v6_tunnel().await;
    let echo = start_echo().await;
    let tunnel = Arc::new(tunnel);
    let mut workers = Vec::new();
    for w in 0..8u8 {
        let tunnel = tunnel.clone();
        workers.push(tokio::spawn(async move {
            for i in 0..400u32 {
                let mut app = tunnel.connect(echo).await.unwrap_or_else(|c| panic!("worker {w} stream {i} refused ({c}); log:\n{}", tunnel.log_text()));
                let msg = [w, (i >> 8) as u8, i as u8, 1, 2, 3, 4, 5];
                app.write_all(&msg).await.unwrap();
                let mut back = [0u8; 8];
                timeout(Duration::from_secs(10), app.read_exact(&mut back))
                    .await
                    .unwrap_or_else(|_| panic!("worker {w} stream {i}: no echo; log:\n{}", tunnel.log_text()))
                    .unwrap();
                assert_eq!(back, msg);
                // Dropped: its end of stream finishes the stream on both sides.
            }
        }));
    }
    for h in workers {
        timeout(Duration::from_secs(240), h).await.expect("3200 streams in time").unwrap();
    }
    assert!(!tunnel.log_text().contains("refused"), "no stream was refused:\n{}", tunnel.log_text());
    // And the session still takes a new one.
    let mut app = tunnel.connect(echo).await.unwrap();
    app.write_all(b"still here").await.unwrap();
    let mut back = [0u8; 10];
    timeout(Duration::from_secs(10), app.read_exact(&mut back)).await.unwrap().unwrap();
    assert_eq!(&back, b"still here");
}

/// At the limit of open streams the new connection is refused at once with a
/// clear error; a stream that ends gives its slot back.
#[tokio::test(flavor = "multi_thread")]
async fn the_1024_open_streams_limit_refuses_the_next_connection_and_frees_with_the_end() {
    let (tunnel, _) = v6_tunnel().await;
    let echo = start_echo().await;
    let mut open = Vec::new();
    for i in 0..ostp_core::streams::MAX_OPEN_STREAMS {
        match tunnel.connect(echo).await {
            Ok(s) => open.push(s),
            Err(c) => panic!("connection {i} refused ({c}) below the limit; log:\n{}", tunnel.log_text()),
        }
    }
    let started = std::time::Instant::now();
    let refused = tunnel.connect(echo).await.err().expect("the 1025th connection is refused");
    assert_ne!(refused, 0);
    assert!(started.elapsed() < Duration::from_secs(5), "refused at once, not after a timeout");
    assert!(
        tunnel.wait_log("too many open streams", Duration::from_secs(2)).await,
        "the reason is logged; log tail:\n{}",
        tunnel.log_text().lines().rev().take(5).collect::<Vec<_>>().join("\n")
    );
    // Some end; their slots come back.
    drop(open.drain(..20));
    let mut ok = false;
    for _ in 0..50 {
        if tunnel.connect(echo).await.is_ok() {
            ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ok, "a finished stream frees its slot; log:\n{}", tunnel.log_text());
}

/// What the program sees when the target's connection is reset: a reset, not
/// a quiet end of stream that looks like a complete reply.
#[tokio::test(flavor = "multi_thread")]
async fn an_aborted_stream_reaches_the_app_as_a_reset() {
    let (tunnel, _) = v6_tunnel().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut b = [0u8; 1];
        let _ = s.read(&mut b).await;
        s.write_all(b"partial reply").await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        #[allow(deprecated)] // the test wants exactly the reset
        s.set_linger(Some(Duration::ZERO)).unwrap();
        drop(s); // RST to the server
    });
    let mut app = tunnel.connect(target).await.unwrap();
    app.write_all(b"x").await.unwrap();
    let mut got = Vec::new();
    let mut buf = [0u8; 64];
    let end = loop {
        match timeout(Duration::from_secs(10), app.read(&mut buf)).await {
            Ok(Ok(0)) => break Ok(()),
            Ok(Ok(n)) => got.extend_from_slice(&buf[..n]),
            Ok(Err(e)) => break Err(e),
            Err(_) => panic!("neither a reset nor an end; log:\n{}", tunnel.log_text()),
        }
    };
    assert_eq!(&got, b"partial reply");
    let e = end.expect_err("the program must see a reset, not an orderly end");
    assert_eq!(e.kind(), std::io::ErrorKind::ConnectionReset, "{e}");
}

/// A UDP relay that can be told to drop everything, standing in for a path
/// that loses packets: client -> relay -> server.
async fn start_lossy_relay(server: SocketAddr, blackout: Arc<AtomicBool>) -> SocketAddr {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap();
    let to_server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    {
        let (sock, to_server, client, blackout) = (sock.clone(), to_server.clone(), client.clone(), blackout.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            while let Ok((n, from)) = sock.recv_from(&mut buf).await {
                *client.lock().unwrap() = Some(from);
                if !blackout.load(Ordering::Relaxed) {
                    let _ = to_server.send_to(&buf[..n], server).await;
                }
            }
        });
    }
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        while let Ok((n, _)) = to_server.recv_from(&mut buf).await {
            let to = *client.lock().unwrap();
            if let (Some(to), false) = (to, blackout.load(Ordering::Relaxed)) {
                let _ = sock.send_to(&buf[..n], to).await;
            }
        }
    });
    addr
}

/// A UDP target that echoes and remembers everything it was sent.
async fn start_udp_echo() -> (SocketAddr, Arc<Mutex<Vec<Vec<u8>>>>) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        while let Ok((n, from)) = sock.recv_from(&mut buf).await {
            log.lock().unwrap().push(buf[..n].to_vec());
            let _ = sock.send_to(&buf[..n], from).await;
        }
    });
    (addr, seen)
}

/// A SOCKS5 UDP association through the tunnel.
struct UdpFlow {
    _control: TcpStream,
    sock: UdpSocket,
    relay: SocketAddr,
}

impl UdpFlow {
    async fn open(tunnel: &Tunnel) -> UdpFlow {
        let mut control = TcpStream::connect(tunnel.socks).await.unwrap();
        control.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0u8; 2];
        control.read_exact(&mut method).await.unwrap();
        control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
        let mut rep = [0u8; 10];
        control.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep[1], 0, "UDP ASSOCIATE accepted");
        let relay = SocketAddr::from(([127, 0, 0, 1], u16::from_be_bytes([rep[8], rep[9]])));
        UdpFlow { _control: control, sock: UdpSocket::bind("127.0.0.1:0").await.unwrap(), relay }
    }

    async fn send(&self, target: SocketAddr, payload: &[u8]) {
        let ip = match target.ip() {
            std::net::IpAddr::V4(ip) => ip.octets(),
            _ => unreachable!(),
        };
        let mut packet = vec![0, 0, 0, 1];
        packet.extend_from_slice(&ip);
        packet.extend_from_slice(&target.port().to_be_bytes());
        packet.extend_from_slice(payload);
        self.sock.send_to(&packet, self.relay).await.unwrap();
    }

    async fn recv(&self, within: Duration) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; 65535];
        match timeout(within, self.sock.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) if n > 10 => Some(buf[10..n].to_vec()),
            _ => None,
        }
    }
}

/// UDP rides in datagrams: it works over a v6 session, and a datagram lost on
/// the path is lost, not resent when the path comes back, while stream data
/// sent in the same blackout is delivered (it is resent). (The give-up and
/// reset of a stream after minutes of loss is checked in ostp-core: it cannot
/// be waited for here.)
#[tokio::test(flavor = "multi_thread")]
async fn a_udp_flow_works_and_a_datagram_lost_on_the_path_is_not_resent() {
    let (protocol, public) = section(false);
    let server = start_server_bound(Some(protocol), Some("127.0.0.1")).await;
    let blackout = Arc::new(AtomicBool::new(false));
    let relay = start_lossy_relay(server, blackout.clone()).await;
    let tunnel = Tunnel::start(relay, Some(public)).await;
    let (udp_target, seen) = start_udp_echo().await;
    let tcp_target = start_echo().await;

    // The flows work.
    let flow = UdpFlow::open(&tunnel).await;
    flow.send(udp_target, b"warm-up").await;
    assert_eq!(flow.recv(Duration::from_secs(5)).await.as_deref(), Some(&b"warm-up"[..]), "UDP echo; log:\n{}", tunnel.log_text());
    for i in 0..20u8 {
        flow.send(udp_target, &[i; 100]).await;
        assert_eq!(flow.recv(Duration::from_secs(5)).await.as_deref(), Some(&[i; 100][..]));
    }
    let mut tcp = tunnel.connect(tcp_target).await.unwrap();

    // A blackout: nothing gets through in either direction.
    blackout.store(true, Ordering::Relaxed);
    flow.send(udp_target, b"lost-in-the-blackout").await;
    tcp.write_all(b"stream-data-in-the-blackout").await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    blackout.store(false, Ordering::Relaxed);

    // The stream data is resent and arrives (echoed back).
    let mut back = vec![0u8; "stream-data-in-the-blackout".len()];
    timeout(Duration::from_secs(20), tcp.read_exact(&mut back))
        .await
        .unwrap_or_else(|_| panic!("the stream data was not resent; log:\n{}", tunnel.log_text()))
        .unwrap();
    assert_eq!(&back, b"stream-data-in-the-blackout");

    // The datagram is not: give every retransmission a chance, then look.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        !seen.lock().unwrap().iter().any(|p| p == b"lost-in-the-blackout"),
        "a lost datagram was delivered after the path came back, so it was resent"
    );
    assert!(flow.recv(Duration::from_millis(200)).await.is_none(), "and no echo of it either");

    // The flow goes on.
    flow.send(udp_target, b"after").await;
    assert_eq!(flow.recv(Duration::from_secs(5)).await.as_deref(), Some(&b"after"[..]));
}

// ── The session Close (stage 3) ──────────────────────────────────────────────

/// The server's own count of live sessions, from its management API.
async fn live_sessions(api: SocketAddr) -> Option<u64> {
    let mut s = TcpStream::connect(api).await.ok()?;
    let req = format!(
        "GET /panel/api/server/status HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {API_TOKEN}\r\nConnection: close\r\n\r\n"
    );
    s.write_all(req.as_bytes()).await.ok()?;
    let mut raw = Vec::new();
    timeout(Duration::from_secs(2), s.read_to_end(&mut raw)).await.ok()?.ok()?;
    let text = String::from_utf8_lossy(&raw);
    let body = &text[text.find('{')?..=text.rfind('}')?];
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    v["data"]["connections"].as_u64()
}

async fn wait_live_sessions(api: SocketAddr, want: u64, within: Duration) -> Option<std::time::Instant> {
    let deadline = tokio::time::Instant::now() + within;
    while tokio::time::Instant::now() < deadline {
        if live_sessions(api).await == Some(want) {
            return Some(std::time::Instant::now());
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    None
}

fn config_with_keys(keys: &[&str]) -> String {
    serde_json::json!({ "mode": "server", "access_keys": keys }).to_string()
}

/// The server drops the key (hot reload of its config): the v6 client is told
/// at once, stops within a second of that, says why, and does not reconnect.
#[tokio::test(flavor = "multi_thread")]
async fn removing_the_key_closes_the_session_with_a_reason_and_the_client_stops_without_reconnecting() {
    let dir = std::env::temp_dir().join(format!("ostp-v6-close-{}", free_port()));
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("config.json");
    std::fs::write(&config, config_with_keys(&[KEY])).unwrap();
    let api: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
    let (protocol, public) = section(false);
    let server = start_server_full(Some(protocol), None, Some(config.clone()), Some(api)).await;
    let echo = start_echo().await;
    let mut client = Client::from_link(&link_to(server, Some(public)), "udp").await;
    assert!(client.wait_log("Connection established", Duration::from_secs(10)).await, "log:\n{}", client.log_text());
    client.echo_through(echo, b"before the key is removed").await;
    assert!(wait_live_sessions(api, 1, Duration::from_secs(5)).await.is_some(), "the server counts the session");

    // The key goes. The server notices within its 5 s poll; what is measured is
    // what happens after it drops the session.
    std::fs::write(&config, config_with_keys(&[])).unwrap();
    let dropped_at = wait_live_sessions(api, 0, Duration::from_secs(20))
        .await
        .unwrap_or_else(|| panic!("the server did not drop the session; log:\n{}", client.log_text()));

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while client.closed.lock().unwrap().is_none() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let (closed_at, message) = client
        .closed
        .lock()
        .unwrap()
        .clone()
        .unwrap_or_else(|| panic!("the client was not told; log:\n{}", client.log_text()));
    assert!(
        closed_at.saturating_duration_since(dropped_at) < Duration::from_secs(1),
        "the client stopped {:?} after the server dropped the session (silence detection would take 10 s)",
        closed_at.saturating_duration_since(dropped_at)
    );
    assert!(message.starts_with("The server closed the connection: your key was revoked"), "{message}");
    assert!(message.contains("Ask the server owner"), "{message}");
    assert!(client.stopped.load(Ordering::Relaxed), "the tunnel is reported stopped");
    assert_eq!(client.metrics.connection_state.load(Ordering::Relaxed), 0, "and the state is `stopped`");

    // No reconnect by itself, and not through the failure path.
    tokio::time::sleep(Duration::from_secs(6)).await;
    let log = client.log_text();
    assert_eq!(log.matches("Connection established").count(), 1, "no second connection:\n{log}");
    assert!(!log.to_lowercase().contains("reconnect"), "{log}");
    assert!(!log.contains("No answer from the server"), "{log}");
    assert!(!log.contains("control stream was lost"), "{log}");
    assert_eq!(client.metrics.connection_state.load(Ordering::Relaxed), 0);
    assert_eq!(live_sessions(api).await, Some(0));
    let _ = std::fs::remove_dir_all(&dir);
}

/// The client stops on purpose: the server frees the session at once, not
/// after its ten minutes of idle time.
#[tokio::test(flavor = "multi_thread")]
async fn a_client_that_stops_frees_its_session_on_the_server_at_once() {
    let api: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
    let (protocol, public) = section(false);
    let server = start_server_full(Some(protocol), None, None, Some(api)).await;
    let echo = start_echo().await;
    let mut client = Client::from_link(&link_to(server, Some(public)), "udp").await;
    assert!(client.wait_log("Connection established", Duration::from_secs(10)).await, "log:\n{}", client.log_text());
    client.echo_through(echo, b"hello").await;
    assert!(wait_live_sessions(api, 1, Duration::from_secs(5)).await.is_some(), "the server counts the session");

    let stop = std::time::Instant::now();
    client.cmd.send(BridgeCommand::ToggleTunnel).await.unwrap();
    let freed = wait_live_sessions(api, 0, Duration::from_secs(3)).await.expect("the session is not freed");
    assert!(freed.duration_since(stop) < Duration::from_secs(1), "freed after {:?}", freed.duration_since(stop));
}

/// A 0.4.x profile against the transitional server: the old behaviour, through
/// the same proxy. Its streams use 16-bit ids, a program's end of stream is a
/// `Close`, and UDP is a stream message.
#[tokio::test(flavor = "multi_thread")]
async fn a_v5_profile_through_the_proxy_behaves_as_before() {
    let (protocol, _) = section(true);
    let server = start_server_bound(Some(protocol), Some("127.0.0.1")).await;
    let tunnel = Tunnel::start(server, None).await;
    let echo = start_echo().await;
    let (udp_target, _) = start_udp_echo().await;

    // Many streams in a row, a larger transfer, and UDP.
    for i in 0..300u32 {
        let mut app = tunnel.connect(echo).await.unwrap_or_else(|c| panic!("stream {i} refused ({c}); log:\n{}", tunnel.log_text()));
        let msg = i.to_be_bytes();
        app.write_all(&msg).await.unwrap();
        let mut back = [0u8; 4];
        timeout(Duration::from_secs(10), app.read_exact(&mut back)).await.unwrap().unwrap();
        assert_eq!(back, msg);
    }
    let mut app = tunnel.connect(echo).await.unwrap();
    let data: Vec<u8> = (0..500_000).map(|i| (i % 253) as u8).collect();
    let (mut rd, mut wr) = app.split();
    let send = async { wr.write_all(&data).await.unwrap() };
    let recv = async {
        let mut got = vec![0u8; data.len()];
        rd.read_exact(&mut got).await.unwrap();
        got
    };
    let (_, got) = timeout(Duration::from_secs(30), async { tokio::join!(send, recv) }).await.expect("the transfer");
    assert_eq!(got, data);

    let flow = UdpFlow::open(&tunnel).await;
    flow.send(udp_target, b"v5 udp").await;
    assert_eq!(flow.recv(Duration::from_secs(5)).await.as_deref(), Some(&b"v5 udp"[..]));
    let log = tunnel.log_text();
    assert!(!log.contains("refused") && !log.contains("reset"), "{log}");
}
