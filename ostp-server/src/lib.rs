use anyhow::Result;
use bytes::Bytes;
use std::collections::HashMap;
use std::net::IpAddr;

use dispatcher::{DispatchOutcome, Dispatcher};
use ostp_core::relay::RelayMessage;
use signal::wait_for_shutdown_signal;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration, Instant};

mod dispatcher;
pub mod outbound;
pub mod api;
pub mod fallback;
pub mod transport;
pub mod relay_node;
mod relay;
mod signal;
pub mod dns;

pub use outbound::{OutboundAction, OutboundConfig, OutboundRule};
pub use api::ApiConfig;
pub use fallback::FallbackConfig;
pub use relay_node::RelayConfig;

#[derive(Debug, Clone)]
pub struct RealityServerConfig {
    pub dest: String,
    pub private_key: String,
    pub pbk: String,
    pub sid: String,
    pub sni_list: Vec<String>,
}

// ── Internal event types ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
#[allow(dead_code)]
enum UiCommand {
    CreateClientKey,
    Shutdown,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) enum UiEvent {
    #[allow(dead_code)]
    PeerSeen { peer: IpAddr },
    #[allow(dead_code)] Rx { peer: IpAddr, bytes: usize },
    #[allow(dead_code)] Tx { peer: IpAddr, bytes: usize },
    UnauthorizedProbe { peer: IpAddr, bytes: usize },
    KeyCreated { key: String },
    Log(String),
    #[allow(dead_code)]
    KeyCount(usize),
}

pub(crate) struct RemoteState {
    pub data_tx: mpsc::UnboundedSender<Bytes>,
    pub udp_tx: Option<mpsc::UnboundedSender<(String, Bytes)>>,
    pub cancel_tx: mpsc::Sender<()>,
    #[allow(dead_code)]
    pub is_dns: bool,
}

// ── Public API ───────────────────────────────────────────────────────────────

pub async fn run_server(
    bind_addrs: Vec<String>,
    server_public_ip: Option<String>,
    access_keys: Vec<(String, crate::api::UserMeta)>,
    outbound: Option<OutboundConfig>,
    api_config: Option<ApiConfig>,
    fallback_config: Option<FallbackConfig>,
    debug: bool,
    reality_query: Option<String>,
    reality_config: Option<RealityServerConfig>,
    dns_config: Option<dns::DnsConfig>,
    config_path: Option<std::path::PathBuf>,
) -> Result<()> {
    let mut keys_map = HashMap::new();
    for (key, meta) in access_keys {
        keys_map.insert(key, meta);
    }
    let shared_keys = std::sync::Arc::new(std::sync::RwLock::new(keys_map));

    let mut sockets = Vec::new();
    for bind_addr in &bind_addrs {
        let addr = bind_addr.parse::<std::net::SocketAddr>()
            .map_err(|e| anyhow::anyhow!("invalid bind addr '{}': {}", bind_addr, e))?;
        let domain = if addr.is_ipv6() { socket2::Domain::IPV6 } else { socket2::Domain::IPV4 };
        let sock = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
        let _ = sock.set_recv_buffer_size(33554432);
        let _ = sock.set_send_buffer_size(33554432);
        sock.bind(&addr.into())?;
        sock.set_nonblocking(true)?;
        let udp_sock = UdpSocket::from_std(sock.into())?;
        tracing::info!("UDP socket bound to {}", bind_addr);
        sockets.push(std::sync::Arc::new(udp_sock));
    }
    if sockets.is_empty() { anyhow::bail!("no bind addresses specified"); }
    let primary_socket = sockets[0].clone();

    use ostp_core::{NoiseRole, PaddingStrategy, ProtocolConfig};
    let protocol_config = ProtocolConfig {
        role: NoiseRole::Responder,
        psk: [0u8; 32],
        session_id: 0,
        handshake_payload: vec![],
        max_padding: 256,
        padding_strategy: PaddingStrategy::Adaptive,
        obfuscation_key: [0u8; 8],
        max_reorder: 16384,
        max_reorder_buffer: 8192,
        ack_delay_ms: 5,
        rto_ms: 100,
        max_retries: 8,
        max_sent_history: 32768,
        // Defaults -- overridden per-session by dispatcher using derive_all_secrets()
        handshake_pad_min: 32,
        handshake_pad_max: 128,
        mtu: 1350,
    };

    let dispatcher = Dispatcher::new(protocol_config, shared_keys.clone());

    // Background config hot-reloader for access keys
    let shared_keys_clone = shared_keys.clone();
    let user_stats_clone = dispatcher.user_stats_ref();
    let config_path_clone = config_path.clone();
    tokio::spawn(async move {
        let path_to_watch = if let Some(p) = config_path_clone {
            p
        } else {
            let exe = match std::env::current_exe() {
                Ok(e) => e,
                Err(_) => return,
            };
            let dir = match exe.parent() {
                Some(d) => d,
                None => return,
            };
            dir.join("config.json")
        };
        
        let path_to_watch = match std::fs::canonicalize(&path_to_watch) {
            Ok(p) => p,
            Err(_) => path_to_watch,
        };

        tracing::info!("Watching configuration file for hot-reload: {:?}", path_to_watch);

        let mut last_mtime = None;
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            if let Ok(metadata) = std::fs::metadata(&path_to_watch) {
                if let Ok(mtime) = metadata.modified() {
                    if last_mtime != Some(mtime) {
                        last_mtime = Some(mtime);
                        match std::fs::read_to_string(&path_to_watch) {
                            Ok(content) => {
                                #[derive(serde::Deserialize)]
                                #[serde(untagged)]
                                enum ReloadUser {
                                    Detailed { access_key: String, name: Option<String>, limit_bytes: Option<u64> },
                                    KeyOnly(String),
                                }
                                #[derive(serde::Deserialize)]
                                struct ServerReloadConfig {
                                    mode: String,
                                    #[serde(default)]
                                    access_keys: Vec<ReloadUser>,
                                }
                                
                                let mut stripped = json_comments::StripComments::new(content.as_bytes());
                                let mut content_str = String::new();
                                use std::io::Read;
                                if let Err(e) = stripped.read_to_string(&mut content_str) {
                                    tracing::error!("Failed to strip comments from config during hot-reload: {}", e);
                                    continue;
                                }

                                match serde_json::from_str::<ServerReloadConfig>(&content_str) {
                                    Ok(cfg) => {
                                        if cfg.mode == "server" {
                                            let mut new_keys = HashMap::new();
                                            for uc in cfg.access_keys {
                                                let (k, m) = match uc {
                                                    ReloadUser::Detailed { access_key, name, limit_bytes } => (access_key, crate::api::UserMeta { name, limit_bytes }),
                                                    ReloadUser::KeyOnly(k) => (k, crate::api::UserMeta { name: None, limit_bytes: None }),
                                                };
                                                new_keys.insert(k, m);
                                            }
                                            
                                            // 1. Update shared_keys
                                            let mut keys_lock = shared_keys_clone.write().unwrap();
                                            *keys_lock = new_keys.clone();
                                            
                                            // 2. Synchronize user_stats limits & cleanup deleted keys
                                            let mut stats_lock = user_stats_clone.write().unwrap();
                                            stats_lock.retain(|k, _| new_keys.contains_key(k));
                                            
                                            for (k, meta) in &new_keys {
                                                let entry_info = stats_lock.get(k).map(|e| {
                                                    (
                                                        e.limit_bytes,
                                                        e.bytes_up.load(std::sync::atomic::Ordering::Relaxed),
                                                        e.bytes_down.load(std::sync::atomic::Ordering::Relaxed),
                                                        e.connections.load(std::sync::atomic::Ordering::Relaxed),
                                                        e.created_at,
                                                    )
                                                });
                                                if let Some((limit_bytes, bytes_up, bytes_down, connections, created_at)) = entry_info {
                                                    if limit_bytes != meta.limit_bytes {
                                                        stats_lock.insert(k.clone(), std::sync::Arc::new(dispatcher::UserStats {
                                                            bytes_up: portable_atomic::AtomicU64::new(bytes_up),
                                                            bytes_down: portable_atomic::AtomicU64::new(bytes_down),
                                                            connections: portable_atomic::AtomicU64::new(connections),
                                                            limit_bytes: meta.limit_bytes,
                                                            created_at,
                                                        }));
                                                    }
                                                } else {
                                                    stats_lock.insert(k.clone(), std::sync::Arc::new(dispatcher::UserStats::new(meta.limit_bytes)));
                                                }
                                            }
                                            
                                            tracing::info!("Hot-reloaded {} access keys from {:?}", keys_lock.len(), path_to_watch);
                                        }
                                    }
                                    Err(e) => {
                                        tracing::error!("Failed to parse config file during hot-reload: {}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::error!("Failed to read config file during hot-reload: {}", e);
                            }
                        }
                    }
                }
            }
        }
    });

    // Initialize DNS server
    let dns_server = dns::DnsServer::new(dns_config.unwrap_or_default());

    // Spawn Management API if configured
    if let Some(api_cfg) = api_config {
        if api_cfg.enabled {
            let api_keys = shared_keys.clone();
            let api_stats = dispatcher.user_stats_ref();
            // Extract host:port from primary listen address for subscription links
            let primary = bind_addrs.first().cloned().unwrap_or_else(|| "0.0.0.0:50000".to_string());
            let parts: Vec<&str> = primary.rsplitn(2, ':').collect();
            let server_port: u16 = parts.first().and_then(|p| p.parse().ok()).unwrap_or(50000);
            let server_host = server_public_ip.unwrap_or_else(|| parts.get(1).unwrap_or(&"0.0.0.0").to_string());
            let rq = reality_query.clone().unwrap_or_default();
            let config_path_api = config_path.clone();
            let dns_server_api = dns_server.clone();
            tokio::spawn(async move {
                api::start_api_server(api_cfg, api_keys, api_stats, server_host, server_port, rq, config_path_api, dns_server_api).await;
            });
        }
    }

    // Spawn Fallback TCP proxy if configured
    if let Some(fb_cfg) = fallback_config {
        if fb_cfg.enabled {
            tokio::spawn(async move {
                fallback::start_fallback_server(fb_cfg).await;
            });
        }
    }

    let (_ui_cmd_tx, ui_cmd_rx) = mpsc::unbounded_channel::<UiCommand>();
    let (ui_event_tx, mut ui_event_rx) = mpsc::unbounded_channel::<UiEvent>();

    // Headless event logger
    tokio::spawn(async move {
        while let Some(ev) = ui_event_rx.recv().await {
            match ev {
                UiEvent::Log(msg) => {
                    // Essential logs always visible; debug logs gated behind flag
                    let is_essential = msg.starts_with("Client ")
                        || msg.starts_with("Listening")
                        || msg.starts_with("Shutdown")
                        || msg.starts_with("Session ")
                        || msg.starts_with("Relay CONNECT")
                        || msg.starts_with("Relay CLOSE")
                        || msg.starts_with("Relay error");
                    if debug || is_essential {
                        tracing::info!("{msg}");
                    }
                }
                UiEvent::KeyCreated { key } => {
                    tracing::info!("Access key created: {key}");
                }
                UiEvent::UnauthorizedProbe { peer, bytes } => {
                    if debug {
                        tracing::debug!("Unauthorized probe from {peer} ({bytes} bytes)");
                    }
                }
                UiEvent::PeerSeen { .. } => {}
                _ => {}
            }
        }
    });

    let key_count = shared_keys.read().unwrap().len();
    tracing::info!(listeners = bind_addrs.len(), keys = key_count, "server started");
    tracing::info!("ARQ config: max_reorder=16384, reorder_buf=8192, sent_history=32768, rto=100ms");
    let tls_config = if let Some(rc) = reality_config {
        let subject_alt_names = rc.sni_list.clone();
        let cert = rcgen::generate_simple_self_signed(subject_alt_names)?;
        let cert_der = cert.cert.der().to_vec();
        let priv_key = cert.key_pair.serialize_der();
        
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![rustls::pki_types::CertificateDer::from(cert_der)],
                rustls::pki_types::PrivatePkcs8KeyDer::from(priv_key).into(),
            )?;
        Some(std::sync::Arc::new(server_config))
    } else {
        None
    };

    tokio::select! {
        res = run_server_loop(bind_addrs.clone(), primary_socket, sockets, dispatcher, ui_cmd_rx, ui_event_tx, shared_keys, outbound, debug, tls_config, dns_server) => {
            if let Err(e) = res {
                tracing::error!("Server error: {e}");
            }
        }
        _ = wait_for_shutdown_signal() => {
            tracing::info!("Shutdown signal received");
        }
    }

    Ok(())
}

// ── Server main loop ─────────────────────────────────────────────────────────

async fn run_server_loop(
    bind_addrs: Vec<String>,
    primary_socket: std::sync::Arc<UdpSocket>,
    sockets: Vec<std::sync::Arc<UdpSocket>>,
    mut dispatcher: Dispatcher,
    mut ui_cmd_rx: mpsc::UnboundedReceiver<UiCommand>,
    ui_event_tx: mpsc::UnboundedSender<UiEvent>,
    shared_keys: std::sync::Arc<std::sync::RwLock<HashMap<String, crate::api::UserMeta>>>,
    outbound: Option<OutboundConfig>,
    debug: bool,
    tls_config: Option<std::sync::Arc<rustls::ServerConfig>>,
    dns_server: std::sync::Arc<dns::DnsServer>,
) -> Result<()> {
    let mut remotes: HashMap<(u32, u16), RemoteState> = HashMap::new();
    let (stream_tx, mut stream_rx) = mpsc::unbounded_channel::<(u32, u16, Vec<u8>)>();
    let (udp_reply_tx, mut udp_reply_rx) = mpsc::unbounded_channel::<(u32, u16, String, Vec<u8>)>();
    let (connect_tx, mut connect_rx) = mpsc::unbounded_channel::<(u32, u16, String, Result<(tokio::net::tcp::OwnedWriteHalf, mpsc::Sender<()>), String>)>();

    let tcp_map = std::sync::Arc::new(tokio::sync::RwLock::new(HashMap::new()));

    let socket = primary_socket;
    // Spawn a recv task for each socket, all feeding into the same channel
    let (udp_tx, mut udp_rx) = mpsc::channel(100000);
    for sock in &sockets {
        let sock_clone = sock.clone();
        let tx = udp_tx.clone();
        tokio::spawn(async move {
            let mut buf = vec![0_u8; 65535];
            loop {
                match sock_clone.recv_from(&mut buf).await {
                    Ok((size, peer)) => {
                        let packet = Bytes::copy_from_slice(&buf[..size]);
                        if tx.send((packet, peer)).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
    }

    // Spawn UoT (TCP) listeners
    for bind_addr in &bind_addrs {
        let addr = bind_addr.parse::<std::net::SocketAddr>().unwrap();
        let tcp_map_clone = tcp_map.clone();
        let shared_keys_clone = shared_keys.clone();
        let udp_tx_clone = udp_tx.clone();

        let tls_cfg = tls_config.clone();
        tokio::spawn(async move {
            if let Ok(listener) = tokio::net::TcpListener::bind(&addr).await {
                tracing::info!("TCP (UoT) listener bound to {}", addr);

                // Rate limiter: track connection attempts per IP
                // Map<IP, (count, window_start)>
                let rate_map: std::sync::Arc<tokio::sync::Mutex<std::collections::HashMap<std::net::IpAddr, (u32, std::time::Instant)>>> =
                    std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
                const RATE_WINDOW_SECS: u64 = 10;
                const RATE_MAX_CONNS: u32 = 10;

                loop {
                    if let Ok((stream, peer_addr)) = listener.accept().await {
                        // Rate limit check
                        let peer_ip = peer_addr.ip();
                        let allowed = {
                            let mut map = rate_map.lock().await;
                            let now = std::time::Instant::now();
                            let entry = map.entry(peer_ip).or_insert((0, now));
                            if now.duration_since(entry.1).as_secs() >= RATE_WINDOW_SECS {
                                // Reset window
                                *entry = (1, now);
                                true
                            } else {
                                entry.0 += 1;
                                entry.0 <= RATE_MAX_CONNS
                            }
                        };

                        if !allowed {
                            tracing::debug!("UoT rate limit exceeded for {}, dropping connection", peer_ip);
                            continue;
                        }

                        let tm = tcp_map_clone.clone();
                        let keys = shared_keys_clone.clone();
                        let tx = udp_tx_clone.clone();
                        let tls = tls_cfg.clone();
                        tokio::spawn(async move {
                            if let Some(cfg) = tls {
                                let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
                                match acceptor.accept(stream).await {
                                    Ok(tls_stream) => {
                                        if let Err(e) = crate::transport::uot::handle_tcp_connection(tls_stream, peer_addr, keys, tx, tm).await {
                                            tracing::warn!("UoT TLS connection from {} closed: {}", peer_addr, e);
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!("UoT TLS handshake from {} failed: {}", peer_addr, e);
                                    }
                                }
                            } else {
                                if let Err(e) = crate::transport::uot::handle_tcp_connection(stream, peer_addr, keys, tx, tm).await {
                                    tracing::warn!("UoT connection from {} closed: {}", peer_addr, e);
                                }
                            }
                        });
                    }
                }
            } else {
                tracing::warn!("Failed to bind TCP (UoT) listener to {}", addr);
            }
        });
    }

    drop(udp_tx); // Drop the original sender so the channel closes when all tasks end

    if debug {
        let _ = ui_event_tx.send(UiEvent::Log("Server loop started".to_string()));
        let _ = ui_event_tx.send(UiEvent::KeyCount(shared_keys.read().unwrap().len()));
    }

    let mut retransmit_tick = interval(Duration::from_millis(10));
    let mut last_empty_app_log = Instant::now() - Duration::from_secs(10);
    let mut peer_last_seen: HashMap<IpAddr, Instant> = HashMap::new();
    let mut peer_available: HashMap<IpAddr, bool> = HashMap::new();
    let peer_timeout = Duration::from_secs(45);

    loop {
        tokio::select! {
            cmd = ui_cmd_rx.recv() => {
                match cmd {
                    Some(UiCommand::CreateClientKey) => {
                        let key = format!("ostp_key_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs());
                        shared_keys.write().unwrap().insert(key.clone(), crate::api::UserMeta { name: None, limit_bytes: None });
                        let _ = ui_event_tx.send(UiEvent::KeyCreated { key });
                    }
                    Some(UiCommand::Shutdown) | None => {
                        let _ = ui_event_tx.send(UiEvent::Log("Shutdown command received".to_string()));
                        break;
                    }
                }
            }
            received = udp_rx.recv() => {
                if let Some((packet, peer)) = received {
                    let size = packet.len();
                    match dispatcher.on_datagram(peer, packet) {
                        Ok(DispatchOutcome::Unauthorized) => {
                            let _ = ui_event_tx.send(UiEvent::UnauthorizedProbe { peer: peer.ip(), bytes: size });
                        }
                        Ok(DispatchOutcome::Accepted { responses, app_payloads, peer_addr }) => {
                            let peer_ip = peer_addr.ip();
                            let now = Instant::now();
                            peer_last_seen.insert(peer_ip, now);
                            if !peer_available.get(&peer_ip).copied().unwrap_or(false) {
                                peer_available.insert(peer_ip, true);
                                let is_tcp = tcp_map.read().await.contains_key(&peer_addr);
                                let proto = if is_tcp { "TCP (UoT)" } else { "UDP" };
                                let _ = ui_event_tx.send(UiEvent::Log(format!("Client {peer_ip} connected via {proto}")));
                            }

                            if app_payloads.is_empty() && now.duration_since(last_empty_app_log) > Duration::from_secs(5) {
                                last_empty_app_log = now;
                                let _ = ui_event_tx.send(UiEvent::Log(format!(
                                    "Accepted datagrams from {peer_ip} with no app payloads (responses={})",
                                    responses.len()
                                )));
                            }
                            let _ = ui_event_tx.send(UiEvent::Rx { peer: peer_ip, bytes: size });

                            for resp in responses {
                                let resp_len = resp.len();
                                let mut sent_tcp = false;
                                {
                                    let map = tcp_map.read().await;
                                    if let Some(tx) = map.get(&peer_addr) {
                                        let _ = tx.try_send(resp.clone());
                                        sent_tcp = true;
                                    }
                                }
                                if !sent_tcp {
                                    let _ = socket.send_to(&resp, peer_addr).await?;
                                }
                                let _ = ui_event_tx.send(UiEvent::Tx { peer: peer_ip, bytes: resp_len });
                            }

                            for (session_id, stream_id, payload) in app_payloads {
                                let _ = ui_event_tx.send(UiEvent::Log(format!(
                                    "Deliver app payload sid={session_id} stream={stream_id} bytes={}",
                                    payload.len()
                                )));
                                relay::handle_relay_message(
                                    peer_addr,
                                    session_id,
                                    stream_id,
                                    payload,
                                    &mut dispatcher,
                                    &socket,
                                    &mut remotes,
                                    &ui_event_tx,
                                    stream_tx.clone(),
                                    udp_reply_tx.clone(),
                                    connect_tx.clone(),
                                    outbound.clone(),
                                    dns_server.clone(),
                                    debug,
                                    &tcp_map,
                                ).await?;
                            }
                        }
                        Err(err) => {
                            let _ = ui_event_tx.send(UiEvent::Log(format!("Protocol error for {peer}: {err}")));
                        }
                    }
                }
            }
            Some((session_id, stream_id, data)) = stream_rx.recv() => {
                if data.is_empty() {
                    let _ = relay::send_relay_to_stream(session_id, stream_id, RelayMessage::Close, &mut dispatcher, &socket, &ui_event_tx, &tcp_map).await;
                    if let Some(state) = remotes.remove(&(session_id, stream_id)) {
                        let _ = state.cancel_tx.try_send(());
                    }
                } else {
                    let _ = relay::send_relay_to_stream(session_id, stream_id, RelayMessage::Data(data), &mut dispatcher, &socket, &ui_event_tx, &tcp_map).await;
                }
            }
            Some((session_id, stream_id, target, data)) = udp_reply_rx.recv() => {
                let _ = relay::send_relay_to_stream(session_id, stream_id, RelayMessage::UdpData(target, data), &mut dispatcher, &socket, &ui_event_tx, &tcp_map).await;
            }
            Some((session_id, stream_id, target, res)) = connect_rx.recv() => {
                match res {
                    Ok((writer, cancel_tx)) => {
                        let (data_tx, mut data_rx) = mpsc::unbounded_channel::<Bytes>();
                        let mut writer_task = writer;
                        tokio::spawn(async move {
                            while let Some(data) = data_rx.recv().await {
                                if tokio::io::AsyncWriteExt::write_all(&mut writer_task, &data).await.is_err() {
                                    break;
                                }
                            }
                        });
                        remotes.insert((session_id, stream_id), RemoteState { data_tx, udp_tx: None, cancel_tx, is_dns: false });
                        let _ = relay::send_relay_to_stream(session_id, stream_id, RelayMessage::ConnectOk, &mut dispatcher, &socket, &ui_event_tx, &tcp_map).await;
                        let _ = ui_event_tx.send(UiEvent::Log(format!("Relay CONNECT ok for [{session_id}:{stream_id}] -> {target}")));
                    }
                    Err(err) => {
                        let _ = ui_event_tx.send(UiEvent::Log(format!("Relay CONNECT failed for [{session_id}:{stream_id}] -> {target}: {err}")));
                        let _ = relay::send_relay_to_stream(session_id, stream_id, RelayMessage::Error(format!("connect failed: {err}")), &mut dispatcher, &socket, &ui_event_tx, &tcp_map).await;
                    }
                }
            }
            _ = retransmit_tick.tick() => {
                let now = Instant::now();
                for (peer_ip, last_seen) in peer_last_seen.iter() {
                    let is_available = peer_available.get(peer_ip).copied().unwrap_or(false);
                    if is_available && now.duration_since(*last_seen) > peer_timeout {
                        peer_available.insert(*peer_ip, false);
                        let _ = ui_event_tx.send(UiEvent::Log(format!("Client {peer_ip} disconnected (timeout)")));
                    }
                }
                let (frames, dropped_sessions) = dispatcher.on_tick();
                for (frame, peer_addr) in frames {
                    let mut sent_tcp = false;
                    {
                        let map = tcp_map.read().await;
                        if let Some(tx) = map.get(&peer_addr) {
                            let _ = tx.try_send(frame.clone());
                            sent_tcp = true;
                        }
                    }
                    if !sent_tcp {
                        let _ = socket.send_to(&frame, peer_addr).await?;
                    }
                }
                for sid in dropped_sessions {
                    let _ = ui_event_tx.send(UiEvent::Log(format!("Session {sid} expired, releasing resources")));
                    let mut streams_to_cancel = Vec::new();
                    for &(session_id, stream_id) in remotes.keys() {
                        if session_id == sid {
                            streams_to_cancel.push((session_id, stream_id));
                        }
                    }
                    for key in streams_to_cancel {
                        if let Some(state) = remotes.remove(&key) {
                            let _ = state.cancel_tx.try_send(());
                        }
                    }
                }
            }
        }
    }

    Ok(())
}
