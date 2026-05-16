mod dispatcher;
mod signal;

use anyhow::Result;
use bytes::Bytes;
use std::collections::HashMap;
use std::net::IpAddr;

use dispatcher::{DispatchOutcome, Dispatcher};
use ostp_core::relay::RelayMessage;
use ostp_core::{NoiseRole, PaddingStrategy, ProtocolConfig};
use signal::wait_for_shutdown_signal;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{tcp::OwnedWriteHalf, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::time::{interval, Duration, Instant};

#[derive(Debug, Clone)]
#[allow(dead_code)]
enum UiCommand {
    CreateClientKey,
    Shutdown,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
enum UiEvent {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundAction {
    Proxy,
    Direct,
}

#[derive(Debug, Clone)]
pub struct OutboundRule {
    pub domain_suffix: Vec<String>,
    pub ip_cidr: Vec<String>,
    pub action: OutboundAction,
}

#[derive(Debug, Clone)]
pub struct OutboundConfig {
    pub enabled: bool,
    pub protocol: String,
    pub address: String,
    pub port: u16,
    pub rules: Vec<OutboundRule>,
    pub default_action: OutboundAction,
}

pub async fn run_server(
    bind_addr: String,
    access_keys: Vec<String>,
    outbound: Option<OutboundConfig>,
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
                                    println!("[ostp-server] Hot-reloaded {} access keys from config.json", keys_lock.len());
                                }
                            }
                        }
                    }
                }
            }
        }
    });

    let socket = UdpSocket::bind(&bind_addr).await?;
    let protocol_config = ProtocolConfig {
        role: NoiseRole::Responder,
        psk: [0u8; 32],
        session_id: 0,
        handshake_payload: vec![],
        max_padding: 256,
        padding_strategy: PaddingStrategy::Adaptive,
        obfuscation_key: [0u8; 8],
        max_reorder: 262144,
        max_reorder_buffer: 32768,
        ack_delay_ms: 5,   // Reduced to 5ms for drastically faster ACK loopback throughput
        rto_ms: 100,       // Reduced to 100ms for aggressive, low-latency packet recovery
        max_retries: 8,
        max_sent_history: 65536,
    };

    let dispatcher = Dispatcher::new(protocol_config, shared_keys.clone());

    let (_ui_cmd_tx, ui_cmd_rx) = mpsc::unbounded_channel::<UiCommand>();
    let (ui_event_tx, mut ui_event_rx) = mpsc::unbounded_channel::<UiEvent>();

    let max_datagram_size = 65535;

    // Headless event logger
    tokio::spawn(async move {
        while let Some(ev) = ui_event_rx.recv().await {
            match ev {
                UiEvent::Log(msg) => {
                    if debug || msg.starts_with("Listening on ") || msg.starts_with("Hot-reloaded ") {
                        println!("[ostp-server] {msg}");
                    }
                }
                UiEvent::KeyCreated { key } => {
                    if debug {
                        println!("[ostp-server] New access key created: {key}");
                    }
                }
                UiEvent::UnauthorizedProbe { peer, bytes } => {
                    if debug {
                        println!("[ostp-server] WARNING: unauthorized probe from {peer} ({bytes} bytes)");
                    }
                }
                UiEvent::PeerSeen { .. } => {}
                _ => {}
            }
        }
    });

    println!("[ostp-server] Listening on {bind_addr}");
    tokio::select! {
        res = run_server_loop(socket, dispatcher, max_datagram_size, ui_cmd_rx, ui_event_tx, shared_keys, outbound, debug) => {
            if let Err(e) = res {
                eprintln!("[ostp-server] error: {e}");
            }
        }
        _ = wait_for_shutdown_signal() => {
            println!("[ostp-server] shutdown signal received");
        }
    }

    Ok(())
}

struct RemoteState {
    data_tx: mpsc::UnboundedSender<Bytes>,
    cancel_tx: mpsc::Sender<()>,
}

async fn run_server_loop(
    socket: UdpSocket,
    mut dispatcher: Dispatcher,
    _max_datagram_size: usize,
    mut ui_cmd_rx: mpsc::UnboundedReceiver<UiCommand>,
    ui_event_tx: mpsc::UnboundedSender<UiEvent>,
    shared_keys: std::sync::Arc<std::sync::RwLock<HashMap<String, ()>>>,
    outbound: Option<OutboundConfig>,
    debug: bool,
) -> Result<()> {
    let mut remotes: HashMap<(u32, u16), RemoteState> = HashMap::new();
    let (stream_tx, mut stream_rx) = mpsc::channel::<(u32, u16, Vec<u8>)>(10000);
    let (connect_tx, mut connect_rx) = mpsc::unbounded_channel::<(u32, u16, String, Result<(tokio::net::tcp::OwnedWriteHalf, mpsc::Sender<()>), String>)>();

    let socket = std::sync::Arc::new(socket);
    let (udp_tx, mut udp_rx) = mpsc::channel(10000);
    let socket_clone = socket.clone();
    tokio::spawn(async move {
        let mut buf = vec![0_u8; 65535];
        loop {
            match socket_clone.recv_from(&mut buf).await {
                Ok((size, peer)) => {
                    let packet = Bytes::copy_from_slice(&buf[..size]);
                    if udp_tx.send((packet, peer)).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

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
                                let _ = ui_event_tx.send(UiEvent::Log(format!("Client {peer_ip} connected")));
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
                                let _ = socket.send_to(&resp, peer_addr).await?;
                                let _ = ui_event_tx.send(UiEvent::Tx { peer: peer_ip, bytes: resp_len });
                            }

                            for (session_id, stream_id, payload) in app_payloads {
                                let _ = ui_event_tx.send(UiEvent::Log(format!(
                                    "Deliver app payload sid={session_id} stream={stream_id} bytes={}",
                                    payload.len()
                                )));
                                handle_relay_message(
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
                    let _ = send_relay_to_stream(session_id, stream_id, RelayMessage::Close, &mut dispatcher, &socket, &ui_event_tx).await;
                    if let Some(state) = remotes.remove(&(session_id, stream_id)) {
                        let _ = state.cancel_tx.try_send(());
                    }
                } else {
                    let _ = send_relay_to_stream(session_id, stream_id, RelayMessage::Data(data), &mut dispatcher, &socket, &ui_event_tx).await;
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
                        let _ = send_relay_to_stream(session_id, stream_id, RelayMessage::ConnectOk, &mut dispatcher, &socket, &ui_event_tx).await;
                        let _ = ui_event_tx.send(UiEvent::Log(format!("Relay CONNECT ok for [{session_id}:{stream_id}] -> {target}")));
                    }
                    Err(err) => {
                        let _ = ui_event_tx.send(UiEvent::Log(format!("Relay CONNECT failed for [{session_id}:{stream_id}] -> {target}: {err}")));
                        let _ = send_relay_to_stream(session_id, stream_id, RelayMessage::Error(format!("connect failed: {err}")), &mut dispatcher, &socket, &ui_event_tx).await;
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
                    let _ = socket.send_to(&frame, peer_addr).await?;
                }
                for sid in dropped_sessions {
                    let _ = ui_event_tx.send(UiEvent::Log(format!("Cleaning up resources for expired session {sid}")));
                    let mut streams_to_cancel = Vec::new();
                    for (&(session_id, stream_id), _) in &remotes {
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

async fn handle_relay_message(
    _peer_addr: std::net::SocketAddr,
    session_id: u32,
    stream_id: u16,
    payload: Bytes,
    dispatcher: &mut Dispatcher,
    socket: &UdpSocket,
    remotes: &mut HashMap<(u32, u16), RemoteState>,
    ui_event_tx: &mpsc::UnboundedSender<UiEvent>,
    stream_tx: mpsc::Sender<(u32, u16, Vec<u8>)>,
    connect_tx: mpsc::UnboundedSender<(u32, u16, String, Result<(tokio::net::tcp::OwnedWriteHalf, mpsc::Sender<()>), String>)>,
    outbound: Option<OutboundConfig>,
    debug: bool,
) -> Result<()> {
    match RelayMessage::decode(&payload)? {
        RelayMessage::Connect(target) => {
            let _ = ui_event_tx.send(UiEvent::Log(format!("Relay CONNECT start for [{session_id}:{stream_id}] -> {target}")));
            let target_clone = target.clone();
            let connect_tx_clone = connect_tx.clone();
            let stream_tx_clone = stream_tx.clone();
            let outbound_clone = outbound.clone();
            tokio::spawn(async move {
                let stream_res = connect_target(&target_clone, outbound_clone.as_ref(), debug).await;
                match stream_res {
                    Ok(stream) => {
                        let (mut reader, writer) = stream.into_split();
                        let (cancel_tx, mut cancel_rx) = mpsc::channel::<()>(1);
                        tokio::spawn(async move {
                            let mut buf = [0_u8; 4096];
                            loop {
                                tokio::select! {
                                    _ = cancel_rx.recv() => break,
                                    read_res = reader.read(&mut buf) => {
                                        match read_res {
                                            Ok(0) | Err(_) => {
                                                let _ = stream_tx_clone.send((session_id, stream_id, Vec::new())).await;
                                                break;
                                            }
                                            Ok(n) => {
                                                if stream_tx_clone.send((session_id, stream_id, buf[..n].to_vec())).await.is_err() {
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        });
                        let _ = connect_tx_clone.send((session_id, stream_id, target_clone, Ok((writer, cancel_tx))));
                    }
                    Err(e) => {
                        let _ = connect_tx_clone.send((session_id, stream_id, target_clone, Err(e.to_string())));
                    }
                }
            });
        }
        RelayMessage::Data(data) => {
            if let Some(remote) = remotes.get_mut(&(session_id, stream_id)) {
                let _ = remote.data_tx.send(bytes::Bytes::from(data));
            } else {
                let _ = ui_event_tx.send(UiEvent::Log(format!("Relay DATA for unknown stream [{session_id}:{stream_id}] ({})", data.len())));
            }
        }
        RelayMessage::KeepAlive => {}
        RelayMessage::Close => {
            if let Some(state) = remotes.remove(&(session_id, stream_id)) {
                let _ = state.cancel_tx.try_send(());
            }
        }
        RelayMessage::ConnectOk => {}
        RelayMessage::Error(msg) => {
            let _ = ui_event_tx.send(UiEvent::Log(format!("Relay error from [{session_id}:{stream_id}]: {msg}")));
        }
        RelayMessage::Ping(ts) => {
            send_relay_to_stream(session_id, stream_id, RelayMessage::Pong(ts), dispatcher, socket, ui_event_tx).await?;
        }
        RelayMessage::Pong(_) => {}
    }
    Ok(())
}

async fn send_relay_to_stream(
    session_id: u32,
    stream_id: u16,
    msg: RelayMessage,
    dispatcher: &mut Dispatcher,
    socket: &UdpSocket,
    ui_event_tx: &mpsc::UnboundedSender<UiEvent>,
) -> Result<()> {
    let payload = Bytes::from(msg.encode());
    if let Some((frame, peer_addr)) = dispatcher.outbound_to_session(session_id, stream_id, payload)? {
        let response_len = frame.len();
        let _ = socket.send_to(&frame, peer_addr).await?;
        let _ = ui_event_tx.send(UiEvent::Tx {
            peer: peer_addr.ip(),
            bytes: response_len,
        });
    }
    Ok(())
}

async fn connect_target(
    target: &str,
    outbound: Option<&OutboundConfig>,
    debug: bool,
) -> Result<TcpStream> {
    if let Some(outbound) = outbound {
        if outbound.enabled {
            let action = select_outbound_action(target, outbound, debug).await;
            if action == OutboundAction::Proxy {
                let proxy_addr = format!("{}:{}", outbound.address, outbound.port);
                return match outbound.protocol.as_str() {
                    "socks5" => connect_via_socks5(&proxy_addr, target).await,
                    "http" => connect_via_http(&proxy_addr, target).await,
                    _ => TcpStream::connect(target).await.map_err(Into::into),
                };
            }
        }
    }

    TcpStream::connect(target).await.map_err(Into::into)
}

async fn select_outbound_action(
    target: &str,
    outbound: &OutboundConfig,
    debug: bool,
) -> OutboundAction {
    let (host, port) = match split_host_port(target) {
        Some(v) => v,
        None => return outbound.default_action,
    };

    let mut matched = None;
    for rule in &outbound.rules {
        if rule.domain_suffix.is_empty() && rule.ip_cidr.is_empty() {
            continue;
        }
        if match_domain_rule(&host, &rule.domain_suffix) {
            matched = Some(rule.action);
            break;
        }
        if match_ip_rule(&host, port, &rule.ip_cidr).await {
            matched = Some(rule.action);
            break;
        }
    }

    let action = matched.unwrap_or(outbound.default_action);
    if debug {
        println!("[ostp-server] outbound decision target={target} action={action:?}");
    }
    action
}

fn match_domain_rule(host: &str, suffixes: &[String]) -> bool {
    if suffixes.is_empty() {
        return false;
    }
    let host = host.trim_end_matches('.').to_lowercase();
    suffixes.iter().any(|suffix| {
        let suffix = suffix.trim().trim_start_matches('.').to_lowercase();
        !suffix.is_empty() && (host == suffix || host.ends_with(&format!(".{suffix}")))
    })
}

async fn match_ip_rule(host: &str, port: u16, cidrs: &[String]) -> bool {
    if cidrs.is_empty() {
        return false;
    }
    let parsed: Vec<Cidr> = cidrs.iter().filter_map(|c| parse_cidr(c)).collect();
    if parsed.is_empty() {
        return false;
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return parsed.iter().any(|cidr| cidr.contains(&ip));
    }

    match tokio::net::lookup_host((host, port)).await {
        Ok(addrs) => addrs.into_iter().any(|addr| parsed.iter().any(|cidr| cidr.contains(&addr.ip()))),
        Err(_) => false,
    }
}

async fn connect_via_socks5(proxy_addr: &str, target: &str) -> Result<TcpStream> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = TcpStream::connect(proxy_addr).await?;
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await?;
    if reply != [0x05, 0x00] {
        anyhow::bail!("SOCKS5 auth not accepted");
    }

    let (host, port) = split_host_port(target).ok_or_else(|| anyhow::anyhow!("invalid target"))?;
    let mut req = Vec::new();
    req.extend_from_slice(&[0x05, 0x01, 0x00]);
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(v4) => {
                req.push(0x01);
                req.extend_from_slice(&v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                req.push(0x04);
                req.extend_from_slice(&v6.octets());
            }
        }
    } else {
        req.push(0x03);
        req.push(host.len() as u8);
        req.extend_from_slice(host.as_bytes());
    }
    req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&req).await?;

    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    if header[1] != 0x00 {
        anyhow::bail!("SOCKS5 connect failed: 0x{:02x}", header[1]);
    }

    let addr_len = match header[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            len[0] as usize
        }
        _ => 0,
    };
    if addr_len > 0 {
        let mut skip = vec![0u8; addr_len + 2];
        stream.read_exact(&mut skip).await?;
    }

    Ok(stream)
}

async fn connect_via_http(proxy_addr: &str, target: &str) -> Result<TcpStream> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = TcpStream::connect(proxy_addr).await?;
    let request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
    stream.write_all(request.as_bytes()).await?;

    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).await?;
    let response = String::from_utf8_lossy(&buf[..n]);
    if !response.starts_with("HTTP/1.1 200") && !response.starts_with("HTTP/1.0 200") {
        anyhow::bail!("HTTP CONNECT failed: {response}");
    }
    Ok(stream)
}

enum Cidr {
    V4(u32, u8),
    V6(u128, u8),
}

impl Cidr {
    fn contains(&self, ip: &std::net::IpAddr) -> bool {
        match (self, ip) {
            (Cidr::V4(net, bits), std::net::IpAddr::V4(addr)) => {
                let mask = if *bits == 0 { 0 } else { u32::MAX << (32 - bits) };
                let ip = u32::from_be_bytes(addr.octets());
                (ip & mask) == (*net & mask)
            }
            (Cidr::V6(net, bits), std::net::IpAddr::V6(addr)) => {
                let mask = if *bits == 0 { 0 } else { u128::MAX << (128 - bits) };
                let ip = u128::from_be_bytes(addr.octets());
                (ip & mask) == (*net & mask)
            }
            _ => false,
        }
    }
}

fn parse_cidr(value: &str) -> Option<Cidr> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if let Some((addr_str, bits_str)) = value.split_once('/') {
        let bits: u8 = bits_str.parse().ok()?;
        if let Ok(addr) = addr_str.parse::<std::net::IpAddr>() {
            return match addr {
                std::net::IpAddr::V4(v4) => Some(Cidr::V4(u32::from_be_bytes(v4.octets()), bits.min(32))),
                std::net::IpAddr::V6(v6) => Some(Cidr::V6(u128::from_be_bytes(v6.octets()), bits.min(128))),
            };
        }
    }
    if let Ok(addr) = value.parse::<std::net::IpAddr>() {
        return match addr {
            std::net::IpAddr::V4(v4) => Some(Cidr::V4(u32::from_be_bytes(v4.octets()), 32)),
            std::net::IpAddr::V6(v6) => Some(Cidr::V6(u128::from_be_bytes(v6.octets()), 128)),
        };
    }
    None
}

fn split_host_port(target: &str) -> Option<(String, u16)> {
    if let Some((host, port)) = target.rsplit_once(':') {
        if host.starts_with('[') && host.ends_with(']') {
            let host = host.trim_start_matches('[').trim_end_matches(']').to_string();
            let port = port.parse().ok()?;
            return Some((host, port));
        }
        if host.contains(':') {
            return None;
        }
        let port = port.parse().ok()?;
        return Some((host.to_string(), port));
    }
    None
}
