use std::time::{Duration, SystemTime};
use std::sync::atomic::Ordering;
use portable_atomic::{AtomicU64, AtomicU8};
use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::Bytes;
use ostp_core::relay::RelayMessage;
use ostp_core::{NoiseRole, OstpEvent, PaddingStrategy, ProtocolAction, ProtocolConfig, ProtocolMachine, TrafficProfile};
use rand::Rng;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio::time::{interval, timeout, Instant};

use crate::app::{BridgeCommand, ConnectionStatus, UiEvent};
use crate::config::ClientConfig;
use crate::tunnel::{ProxyEvent, ProxyToClientMsg};

static SOCKET_PROTECTOR: std::sync::OnceLock<Box<dyn Fn(i32) -> bool + Send + Sync>> = std::sync::OnceLock::new();

pub fn set_socket_protector<F>(f: F)
where
    F: Fn(i32) -> bool + Send + Sync + 'static,
{
    let _ = SOCKET_PROTECTOR.set(Box::new(f));
}

pub fn protect_socket(fd: i32) -> bool {
    if let Some(f) = SOCKET_PROTECTOR.get() {
        return f(fd);
    }
    true
}

pub struct BridgeMetrics {
    pub bytes_sent: AtomicU64,
    pub bytes_recv: AtomicU64,
    pub connection_state: AtomicU8,
}

async fn send_datagram(socket: &UdpSocket, frame: &Bytes, turn_enabled: bool) -> std::io::Result<usize> {
    if turn_enabled {
        let mut out = bytes::BytesMut::with_capacity(4 + frame.len());
        bytes::BufMut::put_u16(&mut out, 0x4000);
        bytes::BufMut::put_u16(&mut out, frame.len() as u16);
        out.extend_from_slice(frame);
        socket.send(&out).await
    } else {
        socket.send(frame).await
    }
}

struct SessionState {
    socket: Arc<UdpSocket>,
    machine: ProtocolMachine,
}

pub struct Bridge {
    running: bool,
    pub debug: bool,
    profile: TrafficProfile,
    server_addr: String,
    local_bind_addr: String,
    proxy_addr: String,
    access_key: Bytes,
    handshake_timeout_ms: u64,
    io_timeout_ms: u64,

    pub turn_enabled: bool,
    pub turn_server: String,
    pub turn_username: String,
    pub turn_password: String,
    pub mode: String,
    pub mux_enabled: bool,
    pub mux_sessions: usize,

    metrics: Arc<BridgeMetrics>,
    sample_sent: u64,
    sample_recv: u64,
    last_rtt_ms: f64,
    last_sample_at: Instant,
    last_valid_recv: Instant,
}

impl Bridge {
    pub fn new(config: &ClientConfig, metrics: Arc<BridgeMetrics>) -> Result<Self> {
        Ok(Self {
            running: false,
            debug: config.debug,
            profile: TrafficProfile::JsonRpc,
            server_addr: config.ostp.server_addr.clone(),
            local_bind_addr: config.ostp.local_bind_addr.clone(),
            proxy_addr: config.local_proxy.bind_addr.clone(),
            access_key: Bytes::from(config.ostp.access_key.clone()),
            handshake_timeout_ms: config.ostp.handshake_timeout_ms,
            io_timeout_ms: config.ostp.io_timeout_ms,

            turn_enabled: config.turn.enabled,
            turn_server: config.turn.server_addr.clone(),
            turn_username: config.turn.username.clone(),
            turn_password: config.turn.access_key.clone(),
            mode: config.mode.clone(),
            mux_enabled: config.multiplex.enabled,
            mux_sessions: config.multiplex.sessions.max(1),

            metrics,
            sample_sent: 0,
            sample_recv: 0,
            last_rtt_ms: 0.0,
            last_sample_at: Instant::now(),
            last_valid_recv: Instant::now(),
        })
    }

    pub async fn run(
        mut self,
        tx: mpsc::Sender<UiEvent>,
        mut bridge_rx: mpsc::Receiver<BridgeCommand>,
        mut shutdown: watch::Receiver<bool>,
        mut proxy_rx: mpsc::Receiver<ProxyEvent>,
        proxy_tx: mpsc::UnboundedSender<(u16, ProxyToClientMsg)>,
    ) -> Result<()> {
        let mut metrics_tick = interval(Duration::from_millis(500));
        let mut keepalive_tick = tokio::time::interval(Duration::from_secs(5));
        let mut retransmit_tick = tokio::time::interval(Duration::from_millis(50));
        let init_msg = if self.mode == "tun" {
            "Bridge initialized (TUN mode)".to_string()
        } else {
            "Bridge initialized (proxy mode)".to_string()
        };
        tx.send(UiEvent::Log(init_msg)).await.ok();

        let mut sessions_opt: Option<Vec<SessionState>> = None;
        let mut udp_rx_opt: Option<mpsc::Receiver<(usize, Bytes)>> = None;
        let mut _proxy_guard: Option<crate::sysproxy::WindowsProxyGuard> = None;
        let mut stream_map: std::collections::HashMap<u16, usize> = std::collections::HashMap::new();

        loop {
            tokio::select! {
                biased;
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        self.running = false;
                        self.metrics.connection_state.store(0, Ordering::Relaxed);
                        _proxy_guard = None;
                        break;
                    }
                }
                udp_msg = async {
                    match udp_rx_opt.as_mut() {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                }, if self.running => {
                    match udp_msg {
                        Some((session_index, inbound)) => {
                            self.metrics.bytes_recv.fetch_add(inbound.len() as u64, Ordering::Relaxed);
                            self.last_valid_recv = Instant::now();
                            if let Some(sessions) = sessions_opt.as_mut() {
                                if session_index < sessions.len() {
                                    let session = &mut sessions[session_index];
                                    let initial_action = match session.machine.on_event(OstpEvent::Inbound(inbound)) {
                                        Ok(a) => a,
                                        Err(e) => {
                                            let _ = tx.send(UiEvent::Log(format!("Protocol decrypt error: {e}"))).await;
                                            tracing::warn!("Inbound protocol error (session {}): {}", session_index, e);
                                            continue;
                                        }
                                    };

                                    let mut actions_queue = std::collections::VecDeque::new();
                                    actions_queue.push_back(initial_action);

                                    while let Some(current_action) = actions_queue.pop_front() {
                                        match current_action {
                                            ProtocolAction::Multiple(nested) => {
                                                for a in nested {
                                                    actions_queue.push_back(a);
                                                }
                                            }
                                            ProtocolAction::DeliverApp(stream_id, dec_payload) => {
                                                match RelayMessage::decode(&dec_payload) {
                                                    Ok(relay_msg) => {
                                                        match relay_msg {
                                                            RelayMessage::ConnectOk => {
                                                                let _ = tx.send(UiEvent::Log(format!("Relay CONNECT OK stream_id={stream_id}"))).await;
                                                                let _ = proxy_tx.send((stream_id, ProxyToClientMsg::ConnectOk));
                                                            }
                                                            RelayMessage::Data(data) => {
                                                                let _ = proxy_tx.send((stream_id, ProxyToClientMsg::Data(Bytes::from(data))));
                                                            }
                                                            RelayMessage::Close => {
                                                                let _ = proxy_tx.send((stream_id, ProxyToClientMsg::Close));
                                                            }
                                                            RelayMessage::Error(msg) => {
                                                                let _ = tx.send(UiEvent::Log(format!("Relay error for stream {stream_id}: {msg}"))).await;
                                                                let _ = proxy_tx.send((stream_id, ProxyToClientMsg::Error(msg)));
                                                            }
                                                            RelayMessage::Pong(ts) => {
                                                                let now = SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
                                                                self.last_rtt_ms = now.saturating_sub(ts) as f64;
                                                            }
                                                            RelayMessage::KeepAlive | RelayMessage::Ping(_) | RelayMessage::Connect(_) => {}
                                                        }
                                                    }
                                                    Err(err) => {
                                                        let _ = tx.send(UiEvent::Log(format!("Relay decode error for stream {stream_id}: {err}"))).await;
                                                        let _ = proxy_tx.send((stream_id, ProxyToClientMsg::Error("relay decode failed".to_string())));
                                                    }
                                                }
                                            }
                                            ProtocolAction::SendDatagram(frame) => {
                                                let _ = send_datagram(&session.socket, &frame, self.turn_enabled).await;
                                                self.metrics.bytes_sent.fetch_add(frame.len() as u64, Ordering::Relaxed);
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                            }
                        }
                        None => {
                            let _ = tx.send(UiEvent::Log("UDP channel closed, resetting connection".to_string())).await;
                            self.running = false;
                            crate::sysproxy::disable_windows_proxy();
                            sessions_opt = None;
                            udp_rx_opt = None;
                            stream_map.clear();
                            self.reset_proxy_streams(&tx, &proxy_tx, "udp reader closed");
                            let _ = tx.send(UiEvent::TunnelStopped).await;
                        }
                    }
                }
                cmd = bridge_rx.recv() => {
                    match cmd {
                        Some(BridgeCommand::ToggleTunnel) => {
                            if self.running {
                                self.running = false;
                                self.metrics.connection_state.store(0, Ordering::Relaxed);
                                _proxy_guard = None;
                                sessions_opt = None;
                                udp_rx_opt = None;
                                stream_map.clear();
                                self.reset_proxy_streams(&tx, &proxy_tx, "manual stop");
                                tx.send(UiEvent::TunnelStopped).await.ok();
                                let stop_msg = if self.mode == "tun" { "TUN tunnel stopped" } else { "Bridge stopped" };
                                tx.send(UiEvent::Log(stop_msg.to_string())).await.ok();
                            } else {
                                 tx.send(UiEvent::Log("Connecting to remote server...".to_string())).await.ok();
                                tx.send(UiEvent::Metrics { status: ConnectionStatus::Handshaking, rtt_ms: 0.0, throughput_bps: 0 }).await.ok();
                                self.metrics.connection_state.store(1, Ordering::Relaxed);
                                
                                let session_count = if self.mux_enabled { self.mux_sessions.max(1) } else { 1 };
                                let (udp_tx, udp_rx) = mpsc::channel(100000); // Increased for high-speed traffic stability
                                let mut sessions = Vec::with_capacity(session_count);
                                let mut rtt_sum = 0.0;
                                let mut successful_sessions = 0;

                                for idx in 0..session_count {
                                    let session_id: u32 = rand::thread_rng().gen();
                                    match self.perform_handshake_with_id(&tx, session_id).await {
                                        Ok((sock, mach, rtt)) => {
                                            let session_index = sessions.len();
                                            let socket = Arc::new(sock);
                                            let socket_clone = socket.clone();
                                            let udp_tx_clone = udp_tx.clone();
                                            let is_turn = self.turn_enabled;
                                            tokio::spawn(async move {
                                                let mut buf = vec![0_u8; 65535];
                                                loop {
                                                     match socket_clone.recv(&mut buf).await {
                                                         Ok(n) => {
                                                             let inbound = if is_turn && n >= 4 && buf[0] == 0x40 && buf[1] == 0x00 {
                                                                 let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
                                                                 if 4 + len <= n {
                                                                     Bytes::copy_from_slice(&buf[4..4+len])
                                                                 } else {
                                                                     Bytes::copy_from_slice(&buf[..n])
                                                                 }
                                                             } else {
                                                                 Bytes::copy_from_slice(&buf[..n])
                                                             };
                                                             if udp_tx_clone.send((session_index, inbound)).await.is_err() {
                                                                 break;
                                                             }
                                                         }
                                                         Err(e) => {
                                                             // Under Windows/Winsock, transient UDP socket errors (like WSAECONNRESET) are returned
                                                             // as Err(ConnectionReset). We MUST NOT break the loop on transient errors, otherwise the
                                                             // download path will be permanently killed while the upload path keeps running.
                                                             tracing::warn!("UDP socket recv error (session {}): {}", session_index, e);
                                                             tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                                                         }
                                                     }
                                                }
                                            });

                                            sessions.push(SessionState { socket, machine: mach });
                                            rtt_sum += rtt;
                                            successful_sessions += 1;
                                        }
                                        Err(err) => {
                                            tx.send(UiEvent::Log(format!("Multiplex session {}/{} handshake failed: {}. Continuing with remaining sessions...", idx + 1, session_count, err))).await.ok();
                                        }
                                    }
                                }

                                if sessions.is_empty() {
                                    _proxy_guard = None;
                                    tx.send(UiEvent::Log("All multiplexed handshake attempts failed. Connection aborted.".to_string())).await.ok();
                                    tx.send(UiEvent::TunnelStopped).await.ok();
                                    self.metrics.connection_state.store(0, Ordering::Relaxed);
                                    continue;
                                }

                                udp_rx_opt = Some(udp_rx);
                                sessions_opt = Some(sessions);
                                self.last_rtt_ms = rtt_sum / successful_sessions as f64;
                                self.running = true;
                                self.last_sample_at = Instant::now();
                                self.last_valid_recv = Instant::now();
                                
                                let sys_proxy_addr = self.proxy_addr.replace("0.0.0.0:", "127.0.0.1:");
                                _proxy_guard = Some(crate::sysproxy::WindowsProxyGuard::enable(&sys_proxy_addr));

                                tx.send(UiEvent::Metrics {
                                    status: ConnectionStatus::Established,
                                    rtt_ms: self.last_rtt_ms,
                                    throughput_bps: 0,
                                }).await.ok();
                                self.metrics.connection_state.store(2, Ordering::Relaxed);
                                let start_msg = if self.mode == "tun" { "TUN tunnel established" } else { "Connection established" };
                                tx.send(UiEvent::Log(start_msg.to_string())).await.ok();
                            }
                        }
                        Some(BridgeCommand::NextProfile) => {
                            self.profile = next_profile(self.profile);
                            tx.send(UiEvent::ProfileChanged(self.profile)).await.ok();
                            tx.send(UiEvent::Log(format!("Obfuscation profile switched to {:?}", self.profile))).await.ok();
                        }
                        Some(BridgeCommand::NetworkChanged) => {
                            if self.running {
                                // Network changed (e.g. WiFi→LTE): IP address changed, existing UDP
                                // socket is dead. Trigger immediate reconnect without waiting for stall.
                                let _ = tx.send(UiEvent::Log("Network changed — starting immediate reconnect".to_string())).await;
                                self.metrics.connection_state.store(1, Ordering::Relaxed);
                                self.last_valid_recv = Instant::now() - Duration::from_secs(100); // force stall path

                                let session_count = if self.mux_enabled { self.mux_sessions.max(1) } else { 1 };
                                let (udp_tx, udp_rx) = mpsc::channel(100000);
                                let mut new_sessions = Vec::with_capacity(session_count);
                                let mut successful_sessions = 0;
                                let mut rtt_sum = 0.0;

                                for idx in 0..session_count {
                                    let session_id: u32 = rand::thread_rng().gen();
                                    match self.perform_handshake_with_id(&tx, session_id).await {
                                        Ok((sock, mach, rtt)) => {
                                            let session_index = new_sessions.len();
                                            let socket = Arc::new(sock);
                                            let socket_clone = socket.clone();
                                            let udp_tx_clone = udp_tx.clone();
                                            let is_turn = self.turn_enabled;
                                            tokio::spawn(async move {
                                                let mut buf = vec![0_u8; 65535];
                                                loop {
                                                    match socket_clone.recv(&mut buf).await {
                                                        Ok(n) => {
                                                            let inbound = if is_turn && n >= 4 && buf[0] == 0x40 && buf[1] == 0x00 {
                                                                let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
                                                                if 4 + len <= n { Bytes::copy_from_slice(&buf[4..4+len]) } else { Bytes::copy_from_slice(&buf[..n]) }
                                                            } else {
                                                                Bytes::copy_from_slice(&buf[..n])
                                                            };
                                                            if udp_tx_clone.send((session_index, inbound)).await.is_err() { break; }
                                                        }
                                                        Err(e) => {
                                                            tracing::warn!("UDP recv error (network-change session {}): {}", session_index, e);
                                                            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                                                        }
                                                    }
                                                }
                                            });
                                            new_sessions.push(SessionState { socket, machine: mach });
                                            rtt_sum += rtt;
                                            successful_sessions += 1;
                                        }
                                        Err(err) => {
                                            let _ = tx.send(UiEvent::Log(format!("NetworkChanged reconnect session {}/{} failed: {}", idx + 1, session_count, err))).await;
                                        }
                                    }
                                }

                                if !new_sessions.is_empty() {
                                    sessions_opt = Some(new_sessions);
                                    udp_rx_opt = Some(udp_rx);
                                    self.last_rtt_ms = rtt_sum / successful_sessions as f64;
                                    self.last_valid_recv = Instant::now();
                                    stream_map.clear();
                                    self.reset_proxy_streams(&tx, &proxy_tx, "network changed");
                                    self.metrics.connection_state.store(2, Ordering::Relaxed);
                                    let _ = tx.send(UiEvent::Log("NetworkChanged reconnect successful!".to_string())).await;
                                } else {
                                    let _ = tx.send(UiEvent::Log("NetworkChanged reconnect failed — will retry on keepalive tick".to_string())).await;
                                }
                            }
                        }
                        Some(BridgeCommand::ReloadConfig) => {
                            match ClientConfig::reload_from_json_near_binary() {
                                Ok(cfg) => {
                                    self.apply_runtime_config(&cfg);
                                    tx.send(UiEvent::Log("Runtime config reloaded".to_string())).await.ok();
                                    if self.running {
                                        self.running = false;
                                        self.metrics.connection_state.store(0, Ordering::Relaxed);
                                        _proxy_guard = None;
                                        sessions_opt = None;
                                        stream_map.clear();
                                        self.reset_proxy_streams(&tx, &proxy_tx, "config reload");
                                        // User logic handles UI restart
                                        let _ = tx.send(UiEvent::TunnelStopped).await;
                                    }
                                }
                                Err(err) => {
                                    let _ = tx.send(UiEvent::Log(format!("Config reload failed: {err}"))).await;
                                }
                            }
                        }
                        Some(BridgeCommand::Shutdown) | None => {
                            self.running = false;
                            _proxy_guard = None;
                            break;
                        }
                    }
                }
                _ = metrics_tick.tick() => {
                    if self.running {
                        self.emit_metrics(&tx).await;
                    }
                }
                _ = keepalive_tick.tick() => {
                    if self.running {
                        // 1. Connection Liveness Check & Silent Background Reconnect
                        if self.last_valid_recv.elapsed().as_secs() > 8 {
                            let elapsed = self.last_valid_recv.elapsed().as_secs();
                            if elapsed > 180 {
                                // Hard timeout after 3 minutes of total silence
                                let _ = tx.send(UiEvent::Log("Connection permanently lost (3-minute hard timeout). Stopping tunnel.".into())).await;
                                self.running = false;
                                _proxy_guard = None;
                                sessions_opt = None;
                                stream_map.clear();
                                self.reset_proxy_streams(&tx, &proxy_tx, "keepalive hard timeout");
                                let _ = tx.send(UiEvent::TunnelStopped).await;
                                self.metrics.connection_state.store(0, Ordering::Relaxed);
                                continue;
                            }

                            let _ = tx.send(UiEvent::Log(format!("Connection stall detected ({}s silence). Attempting background reconnect...", elapsed))).await;
                            self.metrics.connection_state.store(1, Ordering::Relaxed); // State: Connecting (Handshake)

                            let session_count = if self.mux_enabled { self.mux_sessions.max(1) } else { 1 };
                            let (udp_tx, udp_rx) = mpsc::channel(100000);
                            let mut new_sessions = Vec::with_capacity(session_count);
                            let mut successful_sessions = 0;
                            let mut rtt_sum = 0.0;

                            for idx in 0..session_count {
                                let session_id: u32 = rand::thread_rng().gen();
                                match self.perform_handshake_with_id(&tx, session_id).await {
                                    Ok((sock, mach, rtt)) => {
                                        let session_index = new_sessions.len();
                                        let socket = Arc::new(sock);
                                        let socket_clone = socket.clone();
                                        let udp_tx_clone = udp_tx.clone();
                                        let is_turn = self.turn_enabled;
                                        tokio::spawn(async move {
                                            let mut buf = vec![0_u8; 65535];
                                            loop {
                                                match socket_clone.recv(&mut buf).await {
                                                    Ok(n) => {
                                                        let inbound = if is_turn && n >= 4 && buf[0] == 0x40 && buf[1] == 0x00 {
                                                            let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
                                                            if 4 + len <= n {
                                                                Bytes::copy_from_slice(&buf[4..4+len])
                                                            } else {
                                                                Bytes::copy_from_slice(&buf[..n])
                                                            }
                                                        } else {
                                                            Bytes::copy_from_slice(&buf[..n])
                                                        };
                                                        if udp_tx_clone.send((session_index, inbound)).await.is_err() {
                                                            break;
                                                        }
                                                    }
                                                    Err(e) => {
                                                        tracing::warn!("UDP socket recv error (reconnect session {}): {}", session_index, e);
                                                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                                                    }
                                                }
                                            }
                                        });

                                        new_sessions.push(SessionState { socket, machine: mach });
                                        rtt_sum += rtt;
                                        successful_sessions += 1;
                                    }
                                    Err(err) => {
                                        let _ = tx.send(UiEvent::Log(format!("Background reconnect session {}/{} failed: {}", idx + 1, session_count, err))).await;
                                    }
                                }
                            }

                            if !new_sessions.is_empty() {
                                sessions_opt = Some(new_sessions);
                                udp_rx_opt = Some(udp_rx);
                                self.last_rtt_ms = rtt_sum / successful_sessions as f64;
                                self.last_valid_recv = Instant::now();
                                self.metrics.connection_state.store(2, Ordering::Relaxed); // State: Connected
                                let _ = tx.send(UiEvent::Log("Background reconnect successful! Connection restored.".into())).await;
                            } else {
                                let _ = tx.send(UiEvent::Log("Background reconnect failed. Will retry on next tick...".into())).await;
                            }
                        }

                        // 2. Active Keep-Alive / Heartbeat
                        if let Some(sessions) = sessions_opt.as_mut() {
                            for session in sessions.iter_mut() {
                                // Send Ping (Internal RTT Metric)
                                let ts = SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
                                let ping_payload = Bytes::from(RelayMessage::Ping(ts).encode());
                                if let Ok(ProtocolAction::SendDatagram(frame)) = session.machine.on_event(OstpEvent::Outbound(0, ping_payload)) {
                                    // Must go through send_datagram() for TURN-mode wrapping;
                                    // raw socket.send() bypasses the ChannelData header and breaks RTT in TURN.
                                    let _ = send_datagram(&session.socket, &frame, self.turn_enabled).await;
                                    self.metrics.bytes_sent.fetch_add(frame.len() as u64, Ordering::Relaxed);
                                }

                                // Send Relay KeepAlive (Force NAT/Server Persistence)
                                let ka_payload = Bytes::from(RelayMessage::KeepAlive.encode());
                                if let Ok(ProtocolAction::SendDatagram(frame)) = session.machine.on_event(OstpEvent::Outbound(0, ka_payload)) {
                                    let _ = send_datagram(&session.socket, &frame, self.turn_enabled).await;
                                    self.metrics.bytes_sent.fetch_add(frame.len() as u64, Ordering::Relaxed);
                                }
                            }
                        }
                    }
                }
                _ = retransmit_tick.tick() => {
                    if self.running {
                        let mut fatal_err = None;
                        if let Some(sessions) = sessions_opt.as_mut() {
                            for session in sessions.iter_mut() {
                                match session.machine.on_event(OstpEvent::Tick) {
                                    Ok(action) => {
                                        let mut queue = vec![action];
                                        while let Some(current_action) = queue.pop() {
                                            match current_action {
                                                ProtocolAction::Multiple(nested) => {
                                                    for a in nested {
                                                        queue.push(a);
                                                    }
                                                }
                                                ProtocolAction::SendDatagram(frame) => {
                                                    let _ = send_datagram(&session.socket, &frame, self.turn_enabled).await;
                                                    self.metrics.bytes_sent.fetch_add(frame.len() as u64, Ordering::Relaxed);
                                                }
                                                _ => {}
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        fatal_err = Some(e);
                                        break;
                                    }
                                }
                            }
                        }

                        if let Some(e) = fatal_err {
                            let _ = tx.send(UiEvent::Log(format!("Protocol tick fatal error: {e}"))).await;
                            self.running = false;
                            _proxy_guard = None;
                            sessions_opt = None;
                            udp_rx_opt = None;
                            stream_map.clear();
                            self.reset_proxy_streams(&tx, &proxy_tx, "protocol fatal error");
                            let _ = tx.send(UiEvent::TunnelStopped).await;
                            self.metrics.connection_state.store(0, Ordering::Relaxed);
                        }
                    }
                }
                proxy_ev = proxy_rx.recv(), if self.running && sessions_opt.as_ref().map(|s| {
                    // Backpressure: suspend proxy reads when ARQ window is saturated
                    s.iter().all(|ses| ses.machine.in_flight_count() < 256)
                }).unwrap_or(true) => {
                    if let Some(ev) = proxy_ev {
                        if let Some(sessions) = sessions_opt.as_mut() {
                            if sessions.is_empty() {
                                if let ProxyEvent::NewStream { stream_id, .. } = ev {
                                    let _ = proxy_tx.send((stream_id, ProxyToClientMsg::Error("tunnel stopped".into())));
                                }
                                continue;
                            }
                            let (stream_id, relay_msg, is_close) = match ev {
                                ProxyEvent::NewStream { stream_id, target } => {
                                    let _ = tx.send(UiEvent::Log(format!("Proxy CONNECT stream_id={stream_id} target={target}"))).await;
                                    (stream_id, RelayMessage::Connect(target), false)
                                }
                                ProxyEvent::Data { stream_id, payload } => (stream_id, RelayMessage::Data(payload.to_vec()), false),
                                ProxyEvent::Close { stream_id } => {
                                    let _ = tx.send(UiEvent::Log(format!("Proxy CLOSE stream_id={stream_id}"))).await;
                                    (stream_id, RelayMessage::Close, true)
                                }
                            };
                            let len = sessions.len();
                            let session_index = *stream_map.entry(stream_id).or_insert_with(|| {
                                // §8 FIX: Load balance multiplexed streams randomly across available connection sockets
                                rand::thread_rng().gen_range(0..len)
                            });
                            if is_close {
                                stream_map.remove(&stream_id);
                            }
                            let session = &mut sessions[session_index];
                            let out_payload = Bytes::from(relay_msg.encode());
                            match session.machine.on_event(OstpEvent::Outbound(stream_id, out_payload)) {
                                Ok(ProtocolAction::SendDatagram(frame)) => {
                                    if send_datagram(&session.socket, &frame, self.turn_enabled).await.is_ok() {
                                        self.metrics.bytes_sent.fetch_add(frame.len() as u64, Ordering::Relaxed);
                                        if self.debug {
                                            let _ = tx.send(UiEvent::Log(format!(
                                                "Outbound datagram sent stream_id={stream_id} bytes={}",
                                                frame.len()
                                            ))).await;
                                        }
                                    }
                                }
                                Ok(ProtocolAction::Multiple(list)) => {
                                    let mut sent = 0usize;
                                    for item in list {
                                        if let ProtocolAction::SendDatagram(frame) = item {
                                            if send_datagram(&session.socket, &frame, self.turn_enabled).await.is_ok() {
                                                self.metrics.bytes_sent.fetch_add(frame.len() as u64, Ordering::Relaxed);
                                                sent += 1;
                                            }
                                        }
                                    }
                                    if self.debug {
                                        let _ = tx.send(UiEvent::Log(format!(
                                            "Outbound datagram batch stream_id={stream_id} sent={sent}"
                                        ))).await;
                                    }
                                }
                                Ok(ProtocolAction::Noop) => {
                                    if self.debug {
                                        let _ = tx.send(UiEvent::Log(format!(
                                            "Outbound datagram noop stream_id={stream_id}"
                                        ))).await;
                                    }
                                }
                                Ok(_) => {
                                    if self.debug {
                                        let _ = tx.send(UiEvent::Log(format!(
                                            "Outbound datagram unexpected action stream_id={stream_id}"
                                        ))).await;
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!("Protocol error packing outbound stream_id={}: {}", stream_id, e);
                                    let _ = tx.send(UiEvent::Log(format!("Protocol error packing TCP: {e}"))).await;
                                }
                            }
                        } else {
                            // Drop it, not connected
                            if let ProxyEvent::NewStream { stream_id, .. } = ev {
                                let _ = proxy_tx.send((stream_id, ProxyToClientMsg::Error("tunnel stopped".into())));
                            }
                        }
                    }
                }


            }
        }

        tx.send(UiEvent::Log("Bridge stopped".to_string())).await.ok();
        Ok(())
    }

    fn reset_proxy_streams(
        &self,
        tx: &mpsc::Sender<UiEvent>,
        proxy_tx: &mpsc::UnboundedSender<(u16, ProxyToClientMsg)>,
        reason: &str,
    ) {
        if proxy_tx
            .send((0, ProxyToClientMsg::Close))
            .is_err()
        {
            let tx_clone = tx.clone();
            let reason_str = reason.to_string();
            tokio::spawn(async move {
                let _ = tx_clone
                    .send(UiEvent::Log(format!(
                        "Failed to reset local proxy streams ({reason_str})"
                    )))
                    .await;
            });
        }
    }

    async fn emit_metrics(&mut self, tx: &mpsc::Sender<UiEvent>) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_sample_at).as_secs_f64().max(0.001);
        self.last_sample_at = now;

        let cur_sent = self.metrics.bytes_sent.load(Ordering::Relaxed);
        let cur_recv = self.metrics.bytes_recv.load(Ordering::Relaxed);

        let sent_delta = cur_sent.saturating_sub(self.sample_sent);
        let recv_delta = cur_recv.saturating_sub(self.sample_recv);
        
        self.sample_sent = cur_sent;
        self.sample_recv = cur_recv;

        let outgoing = (sent_delta as f64 / elapsed) as u64;
        let incoming = (recv_delta as f64 / elapsed) as u64;
        let throughput = incoming.saturating_add(outgoing);

        tx.send(UiEvent::Traffic { incoming_bps: incoming, outgoing_bps: outgoing }).await.ok();

        // Dynamically report connection status based on whether we have received server packets recently (last 10 seconds)
        let is_healthy = self.last_valid_recv.elapsed() < Duration::from_secs(10);
        let status = if is_healthy {
            self.metrics.connection_state.store(2, Ordering::Relaxed);
            ConnectionStatus::Established
        } else {
            self.metrics.connection_state.store(1, Ordering::Relaxed);
            ConnectionStatus::Handshaking
        };

        tx.send(UiEvent::Metrics {
            status,
            rtt_ms: self.last_rtt_ms,
            throughput_bps: throughput,
        }).await.ok();
    }

    async fn perform_handshake_with_id(
        &mut self,
        tx: &mpsc::Sender<UiEvent>,
        session_id: u32,
    ) -> Result<(UdpSocket, ProtocolMachine, f64)> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut handshake_payload = Vec::with_capacity(8 + 4 + self.access_key.len());
        handshake_payload.extend_from_slice(&timestamp.to_be_bytes());
        handshake_payload.extend_from_slice(&session_id.to_be_bytes());
        handshake_payload.extend_from_slice(&self.access_key);

        let secrets = ostp_core::crypto::derive_all_secrets(&self.access_key);

        let mut machine = ProtocolMachine::new(ProtocolConfig {
            role: NoiseRole::Initiator,
            psk: secrets.psk,
            session_id,
            handshake_payload,
            max_padding: 1280, // Safe MTU size to avoid UDP fragmentation on Windows/PPPoE
            padding_strategy: PaddingStrategy::Profile(self.profile),
            obfuscation_key: secrets.obfuscation_key,
            max_reorder: 16384,          // Max gap between expected and received nonce
            max_reorder_buffer: 8192,    // Max buffered out-of-order frames
            ack_delay_ms: 5,
            rto_ms: 100,
            max_retries: 8,
            max_sent_history: 32768,     // Reduced: gap recovery handles unrecoverable frames
            handshake_pad_min: secrets.handshake_pad_min,
            handshake_pad_max: secrets.handshake_pad_max,
        })?;

        let resolved_addrs: Vec<std::net::SocketAddr> = match tokio::net::lookup_host(&self.server_addr).await {
            Ok(addrs) => addrs.collect(),
            Err(e) => return Err(anyhow::anyhow!("failed to resolve server address {}: {}", self.server_addr, e)),
        };
        let target_addr = resolved_addrs.first().ok_or_else(|| anyhow::anyhow!("no IP addresses resolved for {}", self.server_addr))?;
        let target_ip = target_addr.ip();
        let port = target_addr.port();

        tx.send(UiEvent::Log(format!("Connecting to remote server: {}...", target_addr))).await.ok();

        let socket = match self.try_connect_socket(target_ip, port).await {
            Ok(sock) => sock,
            Err(e) => {
                if let std::net::IpAddr::V4(ipv4) = target_ip {
                    tx.send(UiEvent::Log(format!("Direct IPv4 connection failed: {}. Trying NAT64 fallback...", e))).await.ok();
                    let nat64_ipv6 = synthesize_nat64(ipv4);
                    match self.try_connect_socket(std::net::IpAddr::V6(nat64_ipv6), port).await {
                        Ok(sock) => sock,
                        Err(fallback_err) => {
                            return Err(anyhow::anyhow!("Direct IPv4 failed: {}. NAT64 fallback failed: {}", e, fallback_err));
                        }
                    }
                } else {
                    return Err(e);
                }
            }
        };

        if self.turn_enabled {
            let turn_addr = if self.turn_server.contains(':') {
                self.turn_server.clone()
            } else {
                format!("{}:3478", self.turn_server)
            };
            tx.send(UiEvent::Log(format!("Allocating TURN relay via {}", turn_addr))).await.ok();

            match crate::turn::perform_turn_allocation(&socket, &turn_addr, &self.turn_username, &self.turn_password, &self.server_addr).await {
                Ok(relay_addr) => {
                    tx.send(UiEvent::Log(format!("TURN relay allocated ({})", relay_addr))).await.ok();
                    
                    let resolved_turn: Vec<std::net::SocketAddr> = tokio::net::lookup_host(&turn_addr).await
                        .map_err(|e| anyhow::anyhow!("failed to resolve TURN {}: {}", turn_addr, e))?
                        .collect();
                    let turn_target = resolved_turn.first().ok_or_else(|| anyhow::anyhow!("no IP resolved for TURN {}", turn_addr))?;
                    
                    let connect_ip = if socket.local_addr().map(|a| a.is_ipv6()).unwrap_or(false) && turn_target.is_ipv4() {
                        if let std::net::IpAddr::V4(ipv4) = turn_target.ip() {
                            std::net::IpAddr::V6(synthesize_nat64(ipv4))
                        } else {
                            turn_target.ip()
                        }
                    } else {
                        turn_target.ip()
                    };
                    
                    let connect_addr = std::net::SocketAddr::new(connect_ip, turn_target.port());
                    socket
                        .connect(connect_addr)
                        .await
                        .with_context(|| format!("failed to re-connect to TURN {}", connect_addr))?;
                }
                Err(e) => {
                    tx.send(UiEvent::Log(format!("TURN allocation failed: {}. Using direct UDP.", e))).await.ok();
                    let connect_ip = if socket.local_addr().map(|a| a.is_ipv6()).unwrap_or(false) && target_ip.is_ipv4() {
                        if let std::net::IpAddr::V4(ipv4) = target_ip {
                            std::net::IpAddr::V6(synthesize_nat64(ipv4))
                        } else {
                            target_ip
                        }
                    } else {
                        target_ip
                    };
                    let connect_addr = std::net::SocketAddr::new(connect_ip, port);
                    socket
                        .connect(connect_addr)
                        .await
                        .with_context(|| format!("failed to connect udp to {}", connect_addr))?;
                }
            }
        }

        // Connection to remote is handled inside the TURN/direct branches above

        let start = Instant::now();
        let action = machine.on_event(OstpEvent::Start)?;
        let handshake_frame = match action {
            ProtocolAction::SendDatagram(frame) => frame,
            _ => anyhow::bail!("protocol did not emit handshake datagram"),
        };
        let mut buf = vec![0_u8; 4096];
        let mut size = 0;
        let mut success = false;

        // Retransmit handshake up to 4 times with 1200ms timeout to survive packet loss on mobile
        for attempt in 0..4 {
            if attempt > 0 {
                tx.send(UiEvent::Log(format!("Handshake attempt {} lost. Retransmitting...", attempt))).await.ok();
            }
            send_datagram(&socket, &handshake_frame, self.turn_enabled).await?;
            self.metrics.bytes_sent.fetch_add(handshake_frame.len() as u64, Ordering::Relaxed);

            match timeout(Duration::from_millis(1200), socket.recv(&mut buf)).await {
                Ok(Ok(n)) => {
                    size = n;
                    success = true;
                    break;
                }
                _ => {} // retry on timeout or error
            }
        }

        let (final_socket, size) = if success {
            (socket, size)
        } else {
            if let std::net::IpAddr::V4(ipv4) = target_ip {
                tx.send(UiEvent::Log("Direct IPv4 handshake timed out. Trying NAT64 fallback...".to_string())).await.ok();
                let nat64_ipv6 = synthesize_nat64(ipv4);
                match self.try_connect_socket(std::net::IpAddr::V6(nat64_ipv6), port).await {
                    Ok(fallback_socket) => {
                        let mut fallback_success = false;
                        for attempt in 0..4 {
                            if attempt > 0 {
                                tx.send(UiEvent::Log(format!("NAT64 handshake attempt {} lost. Retransmitting...", attempt))).await.ok();
                            }
                            send_datagram(&fallback_socket, &handshake_frame, self.turn_enabled).await?;
                            match timeout(Duration::from_millis(1200), fallback_socket.recv(&mut buf)).await {
                                Ok(Ok(n)) => {
                                    size = n;
                                    fallback_success = true;
                                    break;
                                }
                                _ => {}
                            }
                        }
                        if fallback_success {
                            tx.send(UiEvent::Log("NAT64 fallback handshake successful!".to_string())).await.ok();
                            (fallback_socket, size)
                        } else {
                            return Err(anyhow::anyhow!("NAT64 handshake failed after 3 attempts"));
                        }
                    }
                    Err(e) => return Err(anyhow::anyhow!("NAT64 fallback socket creation failed: {}", e)),
                }
            } else {
                return Err(anyhow::anyhow!("Direct handshake failed after 3 attempts"));
            }
        };
        let socket = final_socket;
        self.metrics.bytes_recv.fetch_add(size as u64, Ordering::Relaxed);
        tracing::info!("Handshake response received: {} bytes", size);

        let inbound = if self.turn_enabled && size >= 4 && buf[0] == 0x40 && buf[1] == 0x00 {
            let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
            if 4 + len <= size {
                Bytes::copy_from_slice(&buf[4..4+len])
            } else {
                Bytes::copy_from_slice(&buf[..size])
            }
        } else {
            Bytes::copy_from_slice(&buf[..size])
        };
        machine.on_event(OstpEvent::Inbound(inbound))?;
        let rtt_ms = start.elapsed().as_secs_f64() * 1000.0;
        tracing::info!("Handshake complete: session={:#010x} rtt={:.1}ms", session_id, rtt_ms);

        Ok((socket, machine, rtt_ms))
    }

    fn apply_runtime_config(&mut self, cfg: &ClientConfig) {
        self.server_addr = cfg.ostp.server_addr.clone();
        self.local_bind_addr = cfg.ostp.local_bind_addr.clone();
        self.proxy_addr = cfg.local_proxy.bind_addr.clone();
        self.access_key = Bytes::from(cfg.ostp.access_key.clone());
        self.handshake_timeout_ms = cfg.ostp.handshake_timeout_ms;
        self.io_timeout_ms = cfg.ostp.io_timeout_ms;
        self.mode = cfg.mode.clone(); // Bug fix: mode was never updated on hot-reload
        self.turn_enabled = cfg.turn.enabled;
        self.turn_server = cfg.turn.server_addr.clone();
        self.turn_username = cfg.turn.username.clone();
        self.turn_password = cfg.turn.access_key.clone();
        self.mux_enabled = cfg.multiplex.enabled;
        self.mux_sessions = cfg.multiplex.sessions.max(1);
    }

    async fn try_connect_socket(
        &self,
        target_ip: std::net::IpAddr,
        port: u16,
    ) -> Result<UdpSocket> {
        let is_ipv6 = target_ip.is_ipv6();
        let domain = if is_ipv6 { socket2::Domain::IPV6 } else { socket2::Domain::IPV4 };
        let bind_addr = if is_ipv6 {
            std::net::SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)
        } else {
            std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
        };

        let sock = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            protect_socket(sock.as_raw_fd());
        }
        let _ = sock.set_recv_buffer_size(33554432); // 32MB
        let _ = sock.set_send_buffer_size(33554432); // 32MB
        let actual_recv = sock.recv_buffer_size().unwrap_or(0);
        let actual_send = sock.send_buffer_size().unwrap_or(0);
        tracing::info!("UDP socket buffers: recv={}KB send={}KB", actual_recv / 1024, actual_send / 1024);
        sock.bind(&bind_addr.into())?;
        sock.set_nonblocking(true)?;
        let socket = UdpSocket::from_std(sock.into())?;

        let connect_addr = std::net::SocketAddr::new(target_ip, port);
        socket.connect(connect_addr).await.with_context(|| format!("failed to connect udp to {}", connect_addr))?;
        Ok(socket)
    }
}

fn next_profile(current: TrafficProfile) -> TrafficProfile {
    match current {
        TrafficProfile::JsonRpc => TrafficProfile::HttpsBurst,
        TrafficProfile::HttpsBurst => TrafficProfile::VideoStream,
        TrafficProfile::VideoStream => TrafficProfile::JsonRpc,
    }
}

fn synthesize_nat64(ip: std::net::Ipv4Addr) -> std::net::Ipv6Addr {
    let octets = ip.octets();
    std::net::Ipv6Addr::new(
        0x0064, 0xff9b, 0, 0, 0, 0,
        ((octets[0] as u16) << 8) | octets[1] as u16,
        ((octets[2] as u16) << 8) | octets[3] as u16,
    )
}

