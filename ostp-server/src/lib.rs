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
mod relay;
mod signal;

pub use outbound::{OutboundAction, OutboundConfig, OutboundRule};
pub use api::ApiConfig;
pub use fallback::FallbackConfig;

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
    pub cancel_tx: mpsc::Sender<()>,
}

// ── Public API ───────────────────────────────────────────────────────────────

pub async fn run_server(
    bind_addrs: Vec<String>,
    access_keys: Vec<String>,
    outbound: Option<OutboundConfig>,
    api_config: Option<ApiConfig>,
    fallback_config: Option<FallbackConfig>,
    debug: bool,
) -> Result<()> {
    let mut keys_map = HashMap::new();
    for key in access_keys {
        keys_map.insert(key, ());
    }
    let shared_keys = std::sync::Arc::new(std::sync::RwLock::new(keys_map));

    // Background config hot-reloader for access keys
    let shared_keys_clone = shared_keys.clone();
    tokio::spawn(async move {
        let mut last_mtime = None;
        let exe = match std::env::current_exe() {
            Ok(e) => e,
            Err(_) => return,
        };
        let dir = match exe.parent() {
            Some(d) => d,
            None => return,
        };
        let config_path = dir.join("config.json");

        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            if let Ok(metadata) = std::fs::metadata(&config_path) {
                if let Ok(mtime) = metadata.modified() {
                    if last_mtime != Some(mtime) {
                        last_mtime = Some(mtime);
                        if let Ok(content) = std::fs::read_to_string(&config_path) {
                            #[derive(serde::Deserialize)]
                            struct ServerReloadConfig {
                                mode: String,
                                #[serde(default)]
                                access_keys: Vec<String>,
                            }
                            if let Ok(cfg) = serde_json::from_str::<ServerReloadConfig>(&content) {
                                if cfg.mode == "server" {
                                    let mut new_keys = HashMap::new();
                                    for key in cfg.access_keys {
                                        new_keys.insert(key, ());
                                    }
                                    let mut keys_lock = shared_keys_clone.write().unwrap();
                                    *keys_lock = new_keys;
                                    tracing::info!("Hot-reloaded {} access keys from config.json", keys_lock.len());
                                }
                            }
                        }
                    }
                }
            }
        }
    });

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

    // Spawn Management API if configured
    if let Some(api_cfg) = api_config {
        if api_cfg.enabled {
            let api_keys = shared_keys.clone();
            let api_stats = dispatcher.user_stats_ref();
            // Extract host:port from primary listen address for subscription links
            let primary = bind_addrs.first().cloned().unwrap_or_else(|| "0.0.0.0:50000".to_string());
            let parts: Vec<&str> = primary.rsplitn(2, ':').collect();
            let server_port: u16 = parts.first().and_then(|p| p.parse().ok()).unwrap_or(50000);
            let server_host = parts.get(1).unwrap_or(&"0.0.0.0").to_string();
            tokio::spawn(async move {
                api::start_api_server(api_cfg, api_keys, api_stats, server_host, server_port).await;
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
    tokio::select! {
        res = run_server_loop(bind_addrs.clone(), primary_socket, sockets, dispatcher, ui_cmd_rx, ui_event_tx, shared_keys, outbound, debug) => {
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
    shared_keys: std::sync::Arc<std::sync::RwLock<HashMap<String, ()>>>,
    outbound: Option<OutboundConfig>,
    debug: bool,
) -> Result<()> {
    let mut remotes: HashMap<(u32, u16), RemoteState> = HashMap::new();
    let (stream_tx, mut stream_rx) = mpsc::unbounded_channel::<(u32, u16, Vec<u8>)>();
    let (connect_tx, mut connect_rx) = mpsc::unbounded_channel::<(u32, u16, String, Result<(tokio::net::tcp::OwnedWriteHalf, mpsc::Sender<()>), String>)>();

    let tcp_map = std::sync::Arc::new(tokio::sync::RwLock::new(HashMap::new()));

    let socket = primary_socket;
    // Spawn a recv task for each socket, all feeding into the same channel
    let (udp_tx, mut udp_rx) = mpsc::channel(10000);
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
                        tokio::spawn(async move {
                            if let Err(e) = crate::transport::uot::handle_tcp_connection(stream, peer_addr, keys, tx, tm).await {
                                tracing::warn!("UoT connection from {} closed: {}", peer_addr, e);
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

    let mut retransmit_tick = interval(Duration::from_millis(50));
    let mut last_empty_app_log = Instant::now() - Duration::from_secs(10);
    let mut peer_last_seen: HashMap<IpAddr, Instant> = HashMap::new();
    let mut peer_available: HashMap<IpAddr, bool> = HashMap::new();
    let peer_timeout = Duration::from_secs(15);

    loop {
        tokio::select! {
            cmd = ui_cmd_rx.recv() => {
                match cmd {
                    Some(UiCommand::CreateClientKey) => {
                        let key = format!("ostp_key_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs());
                        shared_keys.write().unwrap().insert(key.clone(), ());
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
                                    connect_tx.clone(),
                                    outbound.clone(),
                                    debug,
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
                    let _ = relay::send_relay_to_stream(session_id, stream_id, RelayMessage::Close, &mut dispatcher, &socket, &ui_event_tx).await;
                    if let Some(state) = remotes.remove(&(session_id, stream_id)) {
                        let _ = state.cancel_tx.try_send(());
                    }
                } else {
                    let _ = relay::send_relay_to_stream(session_id, stream_id, RelayMessage::Data(data), &mut dispatcher, &socket, &ui_event_tx).await;
                }
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
                        remotes.insert((session_id, stream_id), RemoteState { data_tx, cancel_tx });
                        let _ = relay::send_relay_to_stream(session_id, stream_id, RelayMessage::ConnectOk, &mut dispatcher, &socket, &ui_event_tx).await;
                        let _ = ui_event_tx.send(UiEvent::Log(format!("Relay CONNECT ok for [{session_id}:{stream_id}] -> {target}")));
                    }
                    Err(err) => {
                        let _ = ui_event_tx.send(UiEvent::Log(format!("Relay CONNECT failed for [{session_id}:{stream_id}] -> {target}: {err}")));
                        let _ = relay::send_relay_to_stream(session_id, stream_id, RelayMessage::Error(format!("connect failed: {err}")), &mut dispatcher, &socket, &ui_event_tx).await;
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
