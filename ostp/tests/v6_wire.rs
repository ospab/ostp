//! End to end for protocol v6: a real server built from a `protocol` section,
//! a real client bridge built from a link, and an echo target.
//!
//! What is checked: a profile with `pk` connects to a server with that key
//! (UDP and UoT); the transitional mode serves a v5 client; and a v6 profile
//! that meets a server without v6, or with another key, ends in the clear
//! error instead of a bare timeout.

use std::net::SocketAddr;
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
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio::time::timeout;

const KEY: &str = "v6-wire-e2e-key";
const STREAM: u16 = 7;

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
        bind_ip: None,
        access_keys: vec![(KEY.to_string(), ostp_server::api::UserMeta { name: None, limit_bytes: None, max_devices: None })],
        outbound: None,
        api_config: None,
        fallback_config: None,
        debug: false,
        dns_config: None,
        config_path: None,
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
    _cmd: mpsc::Sender<BridgeCommand>,
    proxy_ev: mpsc::Sender<ProxyEvent>,
    to_app: mpsc::UnboundedReceiver<(u16, ProxyToClientMsg)>,
    logs: Arc<Mutex<Vec<String>>>,
    _shutdown: watch::Sender<bool>,
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
        });
        let bridge = Bridge::new(&cfg, metrics).unwrap();
        let (ui_tx, mut ui_rx) = mpsc::channel(4096);
        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (proxy_ev_tx, proxy_ev_rx) = mpsc::channel(256);
        let (to_app_tx, to_app_rx) = mpsc::unbounded_channel();
        tokio::spawn(bridge.run(ui_tx, cmd_rx, shutdown_rx, proxy_ev_rx, to_app_tx));
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
        Client { _cmd: cmd_tx, proxy_ev: proxy_ev_tx, to_app: to_app_rx, logs, _shutdown: shutdown_tx }
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

    async fn echo_through(&mut self, target: SocketAddr, data: &'static [u8]) {
        self.proxy_ev.send(ProxyEvent::NewStream { stream_id: STREAM, target: target.to_string() }).await.unwrap();
        match timeout(Duration::from_secs(5), self.to_app.recv()).await {
            Ok(Some((STREAM, ProxyToClientMsg::ConnectOk))) => {}
            _ => panic!("no ConnectOk; log:\n{}", self.log_text()),
        }
        self.proxy_ev.send(ProxyEvent::Data { stream_id: STREAM, payload: Bytes::from_static(data) }).await.unwrap();
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
