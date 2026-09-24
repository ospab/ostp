//! End-to-end: a real server, a real client bridge and an echo target, with a
//! controllable relay between client and server. The relay stands in for the
//! network: it can drop UDP (a blocked carrier) or send everything to another
//! server (one that does not know the session).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use ostp_client::app::{BridgeCommand, UiEvent};
use ostp_client::bridge::{Bridge, BridgeMetrics};
use ostp_client::config::ClientConfig;
use ostp_client::tunnel::{ProxyEvent, ProxyToClientMsg};
use portable_atomic::{AtomicU32, AtomicU64, AtomicU8};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch};
use tokio::time::timeout;

const KEY: &str = "roaming-e2e-key";
const STREAM: u16 = 7;

fn free_port() -> u16 {
    // UDP and TCP on the same port: the server binds both.
    loop {
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = tcp.local_addr().unwrap().port();
        if std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

async fn start_server() -> SocketAddr {
    let port = free_port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let params = ostp_server::ServerParams {
        bind_addrs: vec![addr.to_string()],
        server_public_ip: None,
        bind_ip: None,
        access_keys: vec![(KEY.to_string(), ostp_server::api::UserMeta { name: None, limit_bytes: None })],
        outbound: None,
        api_config: None,
        fallback_config: None,
        debug: false,
        dns_config: None,
        config_path: None,
        tls: None,
        subscription: None,
    };
    tokio::spawn(async move {
        if let Err(e) = ostp_server::run_server(params).await {
            panic!("server failed: {e}");
        }
    });
    // Wait for the TCP side to accept.
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
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

/// UDP and TCP forwarder on one port, towards a switchable upstream.
struct Relay {
    addr: SocketAddr,
    upstream: Arc<Mutex<SocketAddr>>,
    block_udp: Arc<AtomicBool>,
    tcp_conns: Arc<Mutex<Vec<tokio::task::AbortHandle>>>,
}

impl Relay {
    /// Drops every TCP connection going through the relay, as a reset on the
    /// path would.
    fn reset_tcp(&self) {
        for conn in self.tcp_conns.lock().unwrap().drain(..) {
            conn.abort();
        }
    }
}

async fn start_relay(upstream: SocketAddr) -> Relay {
    let port = free_port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let upstream = Arc::new(Mutex::new(upstream));
    let block_udp = Arc::new(AtomicBool::new(false));

    // UDP: one upstream socket per (client address, upstream).
    let front = Arc::new(UdpSocket::bind(addr).await.unwrap());
    {
        let front = front.clone();
        let upstream = upstream.clone();
        let block_udp = block_udp.clone();
        tokio::spawn(async move {
            let flows: Arc<Mutex<std::collections::HashMap<(SocketAddr, SocketAddr), Arc<UdpSocket>>>> = Default::default();
            let mut buf = vec![0u8; 65535];
            loop {
                let (n, client) = front.recv_from(&mut buf).await.unwrap();
                if block_udp.load(Ordering::SeqCst) {
                    continue;
                }
                let target = *upstream.lock().unwrap();
                let existing = flows.lock().unwrap().get(&(client, target)).cloned();
                let back = match existing {
                    Some(sock) => sock,
                    None => {
                        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
                        sock.connect(target).await.unwrap();
                        flows.lock().unwrap().insert((client, target), sock.clone());
                        let (sock2, front2, block2) = (sock.clone(), front.clone(), block_udp.clone());
                        tokio::spawn(async move {
                            let mut b = vec![0u8; 65535];
                            while let Ok(n) = sock2.recv(&mut b).await {
                                if !block2.load(Ordering::SeqCst) {
                                    let _ = front2.send_to(&b[..n], client).await;
                                }
                            }
                        });
                        sock
                    }
                };
                let _ = back.send(&buf[..n]).await;
            }
        });
    }

    // TCP: plain splice to the current upstream.
    let listener = TcpListener::bind(addr).await.unwrap();
    let tcp_conns: Arc<Mutex<Vec<tokio::task::AbortHandle>>> = Default::default();
    {
        let upstream = upstream.clone();
        let tcp_conns = tcp_conns.clone();
        tokio::spawn(async move {
            loop {
                let (mut inbound, _) = listener.accept().await.unwrap();
                let target = *upstream.lock().unwrap();
                let conn = tokio::spawn(async move {
                    if let Ok(mut outbound) = TcpStream::connect(target).await {
                        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                    }
                });
                tcp_conns.lock().unwrap().push(conn.abort_handle());
            }
        });
    }

    Relay { addr, upstream, block_udp, tcp_conns }
}

struct Client {
    cmd: mpsc::Sender<BridgeCommand>,
    proxy_ev: mpsc::Sender<ProxyEvent>,
    to_app: mpsc::UnboundedReceiver<(u16, ProxyToClientMsg)>,
    logs: Arc<Mutex<Vec<String>>>,
    _shutdown: watch::Sender<bool>,
}

impl Client {
    async fn start(server: SocketAddr, mode: &str) -> Client {
        let mut cfg = ClientConfig::default();
        cfg.ostp.server_addr = server.to_string();
        cfg.ostp.access_key = KEY.to_string();
        cfg.transport.mode = mode.to_string();
        cfg.transport.junk_pc = [0, 0];
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

        let client = Client { cmd: cmd_tx, proxy_ev: proxy_ev_tx, to_app: to_app_rx, logs, _shutdown: shutdown_tx };
        client.cmd.send(BridgeCommand::ToggleTunnel).await.unwrap();
        client.wait_log("Connection established", Duration::from_secs(10)).await;
        client
    }

    fn has_log(&self, needle: &str) -> bool {
        self.logs.lock().unwrap().iter().any(|l| l.contains(needle))
    }

    async fn wait_log(&self, needle: &str, within: Duration) {
        let deadline = tokio::time::Instant::now() + within;
        while tokio::time::Instant::now() < deadline {
            if self.has_log(needle) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("no log line containing {needle:?}; log:\n{}", self.logs.lock().unwrap().join("\n"));
    }

    async fn open_stream(&mut self, target: SocketAddr) {
        self.proxy_ev
            .send(ProxyEvent::NewStream { stream_id: STREAM, target: target.to_string() })
            .await
            .unwrap();
        match timeout(Duration::from_secs(5), self.to_app.recv()).await {
            Ok(Some((STREAM, ProxyToClientMsg::ConnectOk))) => {}
            other => panic!("expected ConnectOk, got {:?}", other.map(|o| o.map(|(id, m)| (id, describe(&m))))),
        }
    }

    /// Sends `data` on the stream and waits for the echo. Any Close or Error
    /// in between means the stream did not survive.
    async fn echo(&mut self, data: &'static [u8], within: Duration) {
        self.proxy_ev
            .send(ProxyEvent::Data { stream_id: STREAM, payload: Bytes::from_static(data) })
            .await
            .unwrap();
        let mut got = Vec::new();
        let deadline = tokio::time::Instant::now() + within;
        while got.len() < data.len() {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            match timeout(left, self.to_app.recv()).await {
                Ok(Some((STREAM, ProxyToClientMsg::Data(chunk)))) => got.extend_from_slice(&chunk),
                Ok(Some((id, msg))) => panic!(
                    "stream did not survive: got {} on stream {id}; log:\n{}",
                    describe(&msg),
                    self.logs.lock().unwrap().join("\n")
                ),
                _ => panic!("no echo within {within:?}; log:\n{}", self.logs.lock().unwrap().join("\n")),
            }
        }
        assert_eq!(got, data);
    }
}

fn client_handshakes(client: &Client) -> usize {
    client.logs.lock().unwrap().iter().filter(|l| l.contains("Connecting to remote server:")).count()
}

fn describe(msg: &ProxyToClientMsg) -> String {
    match msg {
        ProxyToClientMsg::ConnectOk => "ConnectOk".into(),
        ProxyToClientMsg::Data(d) => format!("Data({} bytes)", d.len()),
        ProxyToClientMsg::UdpData(t, d) => format!("UdpData({t}, {} bytes)", d.len()),
        ProxyToClientMsg::Close => "Close".into(),
        ProxyToClientMsg::Error(e) => format!("Error({e})"),
    }
}

async fn roams_on_network_change(mode: &str) {
    let server = start_server().await;
    let echo = start_echo().await;
    let mut client = Client::start(server, mode).await;
    client.open_stream(echo).await;
    client.echo(b"before the move", Duration::from_secs(5)).await;

    client.cmd.send(BridgeCommand::NetworkChanged).await.unwrap();
    client.wait_log("Session moved to the new path", Duration::from_secs(10)).await;
    client.echo(b"after the move, same stream", Duration::from_secs(5)).await;

    assert!(!client.has_log("reconnect successful"), "a full reconnect happened instead of a move");
}

#[tokio::test(flavor = "multi_thread")]
async fn udp_session_moves_to_a_new_socket_and_keeps_its_streams() {
    roams_on_network_change("udp").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn uot_session_moves_to_a_new_connection_and_keeps_its_streams() {
    roams_on_network_change("uot").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn unanswered_move_is_reported_and_starts_nothing_else() {
    let first = start_server().await;
    let second = start_server().await;
    let relay = start_relay(first).await;
    let echo = start_echo().await;
    let mut client = Client::start(relay.addr, "udp").await;
    client.open_stream(echo).await;

    let before = client_handshakes(&client);

    // The path now leads to a server that has never seen this session.
    *relay.upstream.lock().unwrap() = second;
    client.cmd.send(BridgeCommand::NetworkChanged).await.unwrap();
    client.wait_log("did not answer on the new path", Duration::from_secs(10)).await;

    // No automatic transport switch or reconnect follows the failed move.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(!client.has_log("reconnect successful"), "a reconnect was started automatically");
    assert_eq!(client_handshakes(&client), before, "a handshake was started automatically");
    assert!(client.to_app.try_recv().is_err(), "the apps' streams were touched");
}

#[tokio::test(flavor = "multi_thread")]
async fn closed_uot_connection_is_replaced_without_dropping_streams() {
    let server = start_server().await;
    let relay = start_relay(server).await;
    let echo = start_echo().await;
    let mut client = Client::start(relay.addr, "uot").await;
    client.open_stream(echo).await;
    client.echo(b"before the reset", Duration::from_secs(5)).await;

    relay.reset_tcp();
    client.wait_log("Session moved to the new path", Duration::from_secs(10)).await;
    client.echo(b"same stream after the reset", Duration::from_secs(5)).await;
}
