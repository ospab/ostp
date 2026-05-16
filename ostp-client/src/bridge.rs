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
            "Bridge & TUN Tunnel Manager initialized".to_string()
        } else {
            "Bridge & SOCKS5 Proxy initialized".to_string()
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
                            let _ = tx.send(UiEvent::Log("UDP reader channel closed".to_string())).await;
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
                                let stop_msg = if self.mode == "tun" { "TUN Tunnel stopped" } else { "Bridge stopped" };
                                tx.send(UiEvent::Log(stop_msg.to_string())).await.ok();
                            } else {
                                 tx.send(UiEvent::Log("Connecting to remote server...".to_string())).await.ok();
                                tx.send(UiEvent::Metrics { status: ConnectionStatus::Handshaking, rtt_ms: 0.0, throughput_bps: 0 }).await.ok();
                                self.metrics.connection_state.store(1, Ordering::Relaxed);
                                
                                let session_count = if self.mux_enabled { self.mux_sessions.max(1) } else { 1 };
                                let (udp_tx, udp_rx) = mpsc::channel(100000); // Increased for high-speed traffic stability
                                let mut sessions = Vec::with_capacity(session_count);
                                let mut rtt_sum = 0.0;

                                let mut handshake_error = None;
                                for idx in 0..session_count {
                                    let session_id: u32 = rand::thread_rng().gen();
                                    match self.perform_handshake_with_id(&tx, session_id).await {
                                        Ok((sock, mach, rtt)) => {
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
                                                            if udp_tx_clone.send((idx, inbound)).await.is_err() {
                                                                eprintln!("[bridge] UDP receiver task exiting: bridge channel full or closed");
                                                                break;
                                                            }
                                                        }
                                                        Err(e) => {
                                                            eprintln!("[bridge] UDP socket recv error: {e}");
                                                            break;
                                                        }
                                                    }
                                                }
                                            });

                                            sessions.push(SessionState { socket, machine: mach });
                                            rtt_sum += rtt;
                                        }
                                        Err(err) => {
                                            handshake_error = Some(err);
                                            break;
                                        }
                                    }
                                }

                                if let Some(err) = handshake_error {
                                    _proxy_guard = None;
                                    tx.send(UiEvent::Log(format!("Connection failed: {err}"))).await.ok();
                                    tx.send(UiEvent::TunnelStopped).await.ok();
                                    self.metrics.connection_state.store(0, Ordering::Relaxed);
                                    continue;
                                }

                                udp_rx_opt = Some(udp_rx);
                                sessions_opt = Some(sessions);
                                self.last_rtt_ms = rtt_sum / session_count as f64;
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
                                let start_msg = if self.mode == "tun" { "TUN Tunnel established" } else { "Connection established" };
                                tx.send(UiEvent::Log(start_msg.to_string())).await.ok();
                            }
                        }
                        Some(BridgeCommand::NextProfile) => {
                            self.profile = next_profile(self.profile);
                            tx.send(UiEvent::ProfileChanged(self.profile)).await.ok();
                            tx.send(UiEvent::Log(format!("Obfuscation profile switched to {:?}", self.profile))).await.ok();
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
                        // 1. Connection Liveness Check
                        if self.last_valid_recv.elapsed().as_secs() > 30 {
                            let _ = tx.send(UiEvent::Log("Connection lost (timeout). Reconnecting...".into())).await;
                            self.running = false;
                            _proxy_guard = None;
                            sessions_opt = None;
                            stream_map.clear();
                            self.reset_proxy_streams(&tx, &proxy_tx, "keepalive timeout");
                            let _ = tx.send(UiEvent::TunnelStopped).await;
                            self.metrics.connection_state.store(0, Ordering::Relaxed);
                            continue;
                        }

                        // 2. Active Keep-Alive / Heartbeat
                        if let Some(sessions) = sessions_opt.as_mut() {
                            for session in sessions.iter_mut() {
                                // Send Ping (Internal Metric)
                                let ts = SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
                                let ping_payload = Bytes::from(RelayMessage::Ping(ts).encode());
                                if let Ok(ProtocolAction::SendDatagram(frame)) = session.machine.on_event(OstpEvent::Outbound(0, ping_payload)) {
                                    let _ = session.socket.send(&frame).await;
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
                    // §3 FIX: Apply backpressure. Suspend pulling from local proxy if ARQ buffers exceed 1024 unacked frames
                    s.iter().all(|ses| ses.machine.in_flight_count() < 1024)
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
        tx.send(UiEvent::Metrics {
            status: ConnectionStatus::Established,
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

        let obf_key = ostp_core::crypto::derive_obfuscation_key(&self.access_key);
        let psk = ostp_core::crypto::derive_psk(&self.access_key);

        let mut machine = ProtocolMachine::new(ProtocolConfig {
            role: NoiseRole::Initiator,
            psk,
            session_id,
            handshake_payload,
            max_padding: 1280, // Safe MTU size to avoid UDP fragmentation on Windows/PPPoE
            padding_strategy: PaddingStrategy::Profile(self.profile),
            obfuscation_key: obf_key,
            max_reorder: 262144,
            max_reorder_buffer: 8192,
            ack_delay_ms: 5,   // Reduced from 20ms to 5ms for rapid ACK unblocking and throughput acceleration
            rto_ms: 100,       // Reduced from 200ms to 100ms for faster recovery on packet loss
            max_retries: 8,
            max_sent_history: 16384,
        })?;

        let socket = UdpSocket::bind(&self.local_bind_addr)
            .await
            .with_context(|| format!("failed to bind local udp {}", self.local_bind_addr))?;

        if self.turn_enabled {
            let turn_addr = if self.turn_server.contains(':') {
                self.turn_server.clone()
            } else {
                format!("{}:3478", self.turn_server)
            };
            tx.send(UiEvent::Log(format!("TURN: Allocating relay via {}", turn_addr))).await.ok();

            match perform_turn_allocation(&socket, &turn_addr, &self.turn_username, &self.turn_password, &self.server_addr).await {
                Ok(relay_addr) => {
                    tx.send(UiEvent::Log(format!("TURN: Relay allocated. Traffic tunnelled via {}", relay_addr))).await.ok();
                    // Re-connect the UDP socket to the TURN server so all sends go through it.
                    // The TURN server forwards ChannelData to the OSTP server transparently.
                    socket
                        .connect(&turn_addr)
                        .await
                        .with_context(|| format!("failed to re-connect to TURN {}", turn_addr))?;
                }
                Err(e) => {
                    tx.send(UiEvent::Log(format!("TURN allocation failed: {e}. Falling back to direct UDP."))).await.ok();
                    socket
                        .connect(&self.server_addr)
                        .await
                        .with_context(|| format!("failed to connect udp to {}", self.server_addr))?;
                }
            }
        } else {
            tx.send(UiEvent::Log(format!("Connected UDP directly to {}", self.server_addr))).await.ok();
            socket
                .connect(&self.server_addr)
                .await
                .with_context(|| format!("failed to connect udp to {}", self.server_addr))?;
        }

        // Connection to remote is handled inside the TURN/direct branches above

        let start = Instant::now();
        let action = machine.on_event(OstpEvent::Start)?;
        let handshake_frame = match action {
            ProtocolAction::SendDatagram(frame) => frame,
            _ => anyhow::bail!("protocol did not emit handshake datagram"),
        };
        send_datagram(&socket, &handshake_frame, self.turn_enabled).await?;
        self.metrics.bytes_sent.fetch_add(handshake_frame.len() as u64, Ordering::Relaxed);

        let mut buf = vec![0_u8; 4096];
        let size = timeout(
            Duration::from_millis(self.handshake_timeout_ms.max(1)),
            socket.recv(&mut buf),
        )
        .await
        .context("handshake timeout waiting server response")??;
        self.metrics.bytes_recv.fetch_add(size as u64, Ordering::Relaxed);

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
        
        // Success
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
}

fn next_profile(current: TrafficProfile) -> TrafficProfile {
    match current {
        TrafficProfile::JsonRpc => TrafficProfile::HttpsBurst,
        TrafficProfile::HttpsBurst => TrafficProfile::VideoStream,
        TrafficProfile::VideoStream => TrafficProfile::JsonRpc,
    }
}

/// Real RFC-5766 TURN allocation with HMAC-SHA1 long-term credentials.
///
/// Flow:
///   1. Send Allocate (unauthenticated) → get 401 with realm + nonce
///   2. Compute HMAC-SHA1 key = MD5(username:realm:password)
///   3. Re-send Allocate with MESSAGE-INTEGRITY
///   4. Extract XOR-RELAYED-ADDRESS from success response
///   5. Send ChannelBind to bind channel 0x4000 to the OSTP server addr
///
/// Returns the relay address string like "1.2.3.4:12345".
async fn perform_turn_allocation(
    socket: &UdpSocket,
    turn_addr: &str,
    username: &str,
    password: &str,
    ostp_server_addr: &str,
) -> anyhow::Result<String> {
    use std::net::ToSocketAddrs;

    let turn_sock: std::net::SocketAddr = turn_addr
        .to_socket_addrs()
        .map_err(|e| anyhow::anyhow!("TURN DNS resolution failed: {e}"))?
        .next()
        .ok_or_else(|| anyhow::anyhow!("TURN addr resolved to nothing"))?;

    let transaction_id = {
        use rand::Rng;
        let mut id = [0u8; 12];
        rand::thread_rng().fill(&mut id);
        id
    };

    // Helper: build a minimal STUN/TURN message
    fn build_stun_msg(msg_type: u16, tx_id: &[u8; 12], attrs: &[u8]) -> Vec<u8> {
        let mut msg = Vec::with_capacity(20 + attrs.len());
        msg.extend_from_slice(&msg_type.to_be_bytes());
        msg.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
        msg.extend_from_slice(&0x2112A442_u32.to_be_bytes()); // Magic Cookie
        msg.extend_from_slice(tx_id);
        msg.extend_from_slice(attrs);
        msg
    }

    // Helper: encode a STUN attribute (type, length-padded value)
    fn stun_attr(attr_type: u16, value: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&attr_type.to_be_bytes());
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        out.extend_from_slice(value);
        // Pad to 4-byte boundary
        let pad = (4 - (value.len() % 4)) % 4;
        out.extend(std::iter::repeat(0u8).take(pad));
        out
    }

    // ── Step 1: unauthenticated Allocate ─────────────────────────────
    // REQUESTED-TRANSPORT attr: 0x0019, value = 17 (UDP) + 3 reserved bytes
    let req_transport = stun_attr(0x0019, &[17u8, 0, 0, 0]);
    let alloc_req = build_stun_msg(0x0003, &transaction_id, &req_transport);

    socket.send_to(&alloc_req, turn_sock).await
        .map_err(|e| anyhow::anyhow!("TURN send Allocate failed: {e}"))?;

    let mut buf = [0u8; 2048];
    let (n, _) = timeout(Duration::from_millis(3000), socket.recv_from(&mut buf))
        .await
        .map_err(|_| anyhow::anyhow!("TURN Allocate response timed out"))?
        .map_err(|e| anyhow::anyhow!("TURN recv failed: {e}"))?;

    let resp = &buf[..n];
    if resp.len() < 20 {
        anyhow::bail!("TURN response too short");
    }

    let msg_type = u16::from_be_bytes([resp[0], resp[1]]);

    // 0x0113 = Allocate Error Response
    if msg_type != 0x0113 {
        anyhow::bail!("Expected TURN 401 error response, got type 0x{:04x}", msg_type);
    }

    // Parse realm and nonce from the error response attributes
    let mut realm: Option<String> = None;
    let mut nonce: Option<String> = None;
    {
        let mut idx = 20usize;
        while idx + 4 <= n {
            let atype = u16::from_be_bytes([resp[idx], resp[idx + 1]]);
            let alen = u16::from_be_bytes([resp[idx + 2], resp[idx + 3]]) as usize;
            idx += 4;
            if idx + alen > n { break; }
            let val = &resp[idx..idx + alen];
            match atype {
                0x0014 => realm = Some(String::from_utf8_lossy(val).to_string()), // REALM
                0x0015 => nonce = Some(String::from_utf8_lossy(val).to_string()), // NONCE
                _ => {}
            }
            idx += alen;
            let pad = (4 - (alen % 4)) % 4;
            idx += pad;
        }
    }

    let realm = realm.ok_or_else(|| anyhow::anyhow!("TURN 401: no REALM in response"))?;
    let nonce = nonce.ok_or_else(|| anyhow::anyhow!("TURN 401: no NONCE in response"))?;

    // ── Step 2: Compute long-term credential key per RFC 5389 §15.4 ──
    // key = MD5(username ":" realm ":" password)
    let key_input = format!("{}:{}:{}", username, realm, password);
    let key = md5_hash(key_input.as_bytes());

    // HMAC-SHA1 of the message (MESSAGE-INTEGRITY attribute, RFC 5389 §15.4)
    // We build the message without the integrity attr, compute HMAC, then append.
    let mut attrs2 = Vec::new();
    attrs2.extend_from_slice(&stun_attr(0x0006, username.as_bytes())); // USERNAME
    attrs2.extend_from_slice(&stun_attr(0x0014, realm.as_bytes()));    // REALM
    attrs2.extend_from_slice(&stun_attr(0x0015, nonce.as_bytes()));    // NONCE
    attrs2.extend_from_slice(&req_transport);                           // REQUESTED-TRANSPORT

    // For MESSAGE-INTEGRITY we need the full message length including the MI attr (24 bytes)
    let mi_placeholder_len = attrs2.len() + 4 + 20; // +4 header, +20 HMAC-SHA1
    let mut msg_for_hmac = build_stun_msg(0x0003, &transaction_id, &attrs2);
    // Set length field to include the upcoming MI attr
    let new_len = (mi_placeholder_len - 20) as u16; // total attrs length including MI
    msg_for_hmac[2..4].copy_from_slice(&new_len.to_be_bytes());
    // Append MI header (without value)
    msg_for_hmac.extend_from_slice(&0x0008_u16.to_be_bytes()); // attr type
    msg_for_hmac.extend_from_slice(&20_u16.to_be_bytes());      // attr len

    let hmac = hmac_sha1(&key, &msg_for_hmac);
    let mut final_attrs = attrs2.clone();
    final_attrs.extend_from_slice(&stun_attr(0x0008, &hmac)); // MESSAGE-INTEGRITY

    let alloc_req2 = build_stun_msg(0x0003, &transaction_id, &final_attrs);

    socket.send_to(&alloc_req2, turn_sock).await
        .map_err(|e| anyhow::anyhow!("TURN authenticated Allocate send failed: {e}"))?;

    let (n2, _) = timeout(Duration::from_millis(5000), socket.recv_from(&mut buf))
        .await
        .map_err(|_| anyhow::anyhow!("TURN authenticated Allocate timed out"))?
        .map_err(|e| anyhow::anyhow!("TURN recv2 failed: {e}"))?;

    let resp2 = &buf[..n2];
    if resp2.len() < 20 {
        anyhow::bail!("TURN auth response too short");
    }
    let msg_type2 = u16::from_be_bytes([resp2[0], resp2[1]]);
    // 0x0103 = Allocate Success Response
    if msg_type2 != 0x0103 {
        anyhow::bail!("TURN Allocate auth failed, response type 0x{:04x}", msg_type2);
    }

    // ── Step 3: Parse XOR-RELAYED-ADDRESS ────────────────────────────
    let relay_addr_str = {
        let mut relayed: Option<String> = None;
        let mut idx = 20usize;
        while idx + 4 <= n2 {
            let atype = u16::from_be_bytes([resp2[idx], resp2[idx + 1]]);
            let alen = u16::from_be_bytes([resp2[idx + 2], resp2[idx + 3]]) as usize;
            idx += 4;
            if idx + alen > n2 { break; }
            let val = &resp2[idx..idx + alen];
            if atype == 0x0016 && alen >= 8 { // XOR-RELAYED-ADDRESS
                let x_port = u16::from_be_bytes([val[2], val[3]]) ^ 0x2112;
                let x_ip = [val[4], val[5], val[6], val[7]];
                let ip = std::net::Ipv4Addr::new(
                    x_ip[0] ^ 0x21, x_ip[1] ^ 0x12, x_ip[2] ^ 0xA4, x_ip[3] ^ 0x42,
                );
                relayed = Some(format!("{}:{}", ip, x_port));
            }
            idx += alen;
            let pad = (4 - (alen % 4)) % 4;
            idx += pad;
        }
        relayed.ok_or_else(|| anyhow::anyhow!("TURN: no XOR-RELAYED-ADDRESS in response"))?
    };

    // ── Step 4: ChannelBind to the OSTP server ────────────────────────
    // ChannelBind binds channel 0x4000 to the peer (OSTP server).
    // After this, all UDP data we send as ChannelData (4 bytes header + payload)
    // will be forwarded by the TURN server to the OSTP server transparently.
    let ostp_sock: std::net::SocketAddr = ostp_server_addr
        .to_socket_addrs()
        .map_err(|e| anyhow::anyhow!("OSTP server DNS resolution failed: {e}"))?
        .next()
        .ok_or_else(|| anyhow::anyhow!("OSTP server addr resolved to nothing"))?;

    let channel_number: u16 = 0x4000;
    let mut peer_addr_attr = Vec::new();
    peer_addr_attr.push(0u8); // reserved
    peer_addr_attr.push(0x01u8); // family IPv4
    peer_addr_attr.extend_from_slice(&(ostp_sock.port() ^ 0x2112).to_be_bytes()); // XOR port
    if let std::net::IpAddr::V4(ipv4) = ostp_sock.ip() {
        let octets = ipv4.octets();
        peer_addr_attr.push(octets[0] ^ 0x21);
        peer_addr_attr.push(octets[1] ^ 0x12);
        peer_addr_attr.push(octets[2] ^ 0xA4);
        peer_addr_attr.push(octets[3] ^ 0x42);
    } else {
        anyhow::bail!("TURN ChannelBind: IPv6 OSTP server not yet supported");
    }

    let mut cb_attrs = Vec::new();
    // CHANNEL-NUMBER attr: 0x000C
    cb_attrs.extend_from_slice(&stun_attr(0x000C, &[
        (channel_number >> 8) as u8, channel_number as u8, 0, 0
    ]));
    // XOR-PEER-ADDRESS attr: 0x0012
    cb_attrs.extend_from_slice(&stun_attr(0x0012, &peer_addr_attr));
    cb_attrs.extend_from_slice(&stun_attr(0x0006, username.as_bytes()));
    cb_attrs.extend_from_slice(&stun_attr(0x0014, realm.as_bytes()));
    cb_attrs.extend_from_slice(&stun_attr(0x0015, nonce.as_bytes()));

    // Compute MESSAGE-INTEGRITY for ChannelBind too
    let mi_len2 = cb_attrs.len() + 4 + 20;
    let mut cb_for_hmac = build_stun_msg(0x0009, &transaction_id, &cb_attrs);
    cb_for_hmac[2..4].copy_from_slice(&((mi_len2 - 20) as u16).to_be_bytes());
    cb_for_hmac.extend_from_slice(&0x0008_u16.to_be_bytes());
    cb_for_hmac.extend_from_slice(&20_u16.to_be_bytes());
    let cb_hmac = hmac_sha1(&key, &cb_for_hmac);
    cb_attrs.extend_from_slice(&stun_attr(0x0008, &cb_hmac));

    let cb_req = build_stun_msg(0x0009, &transaction_id, &cb_attrs);
    socket.send_to(&cb_req, turn_sock).await
        .map_err(|e| anyhow::anyhow!("TURN ChannelBind send failed: {e}"))?;

    let (n3, _) = timeout(Duration::from_millis(3000), socket.recv_from(&mut buf))
        .await
        .map_err(|_| anyhow::anyhow!("TURN ChannelBind response timed out"))?
        .map_err(|e| anyhow::anyhow!("TURN ChannelBind recv failed: {e}"))?;

    let resp3 = &buf[..n3];
    if resp3.len() < 4 {
        anyhow::bail!("TURN ChannelBind response too short");
    }
    let cb_resp_type = u16::from_be_bytes([resp3[0], resp3[1]]);
    // 0x0109 = ChannelBind Success Response
    if cb_resp_type != 0x0109 {
        anyhow::bail!("TURN ChannelBind failed, response type 0x{:04x}", cb_resp_type);
    }

    Ok(relay_addr_str)
}

/// Pure-Rust MD5 hash (16 bytes). Used for TURN long-term credential key derivation.
fn md5_hash(input: &[u8]) -> [u8; 16] {
    // RFC 1321 MD5 constants
    const S: [u32; 64] = [
        7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
        5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
        4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
        6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21,
    ];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
        0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
        0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
        0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
        0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    ];

    let msg_len = input.len();
    let bit_len = (msg_len as u64) * 8;

    let mut padded = input.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_le_bytes());

    let mut a0: u32 = 0x67452301;
    let mut b0: u32 = 0xefcdab89;
    let mut c0: u32 = 0x98badcfe;
    let mut d0: u32 = 0x10325476;

    for chunk in padded.chunks(64) {
        let mut m = [0u32; 16];
        for (i, item) in m.iter_mut().enumerate() {
            *item = u32::from_le_bytes([chunk[i*4], chunk[i*4+1], chunk[i*4+2], chunk[i*4+3]]);
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64usize {
            let (f, g) = match i {
                0..=15  => ((b & c) | (!b & d),              i),
                16..=31 => ((d & b) | (!d & c),              (5*i + 1) % 16),
                32..=47 => (b ^ c ^ d,                        (3*i + 5) % 16),
                _       => (c ^ (b | !d),                     (7*i) % 16),
            };
            let temp = d;
            d = c;
            c = b;
            b = b.wrapping_add((a.wrapping_add(f).wrapping_add(K[i]).wrapping_add(m[g])).rotate_left(S[i]));
            a = temp;
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut result = [0u8; 16];
    result[0..4].copy_from_slice(&a0.to_le_bytes());
    result[4..8].copy_from_slice(&b0.to_le_bytes());
    result[8..12].copy_from_slice(&c0.to_le_bytes());
    result[12..16].copy_from_slice(&d0.to_le_bytes());
    result
}

/// HMAC-SHA1 for TURN MESSAGE-INTEGRITY (RFC 2104 + RFC 5389 §15.4).
fn hmac_sha1(key: &[u8], message: &[u8]) -> [u8; 20] {
    const BLOCK_SIZE: usize = 64;

    let mut k = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let h = sha1_hash(key);
        k[..20].copy_from_slice(&h);
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0u8; BLOCK_SIZE];
    let mut opad = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5C;
    }

    let mut inner = ipad.to_vec();
    inner.extend_from_slice(message);
    let inner_hash = sha1_hash(&inner);

    let mut outer = opad.to_vec();
    outer.extend_from_slice(&inner_hash);
    sha1_hash(&outer)
}

/// Pure-Rust SHA-1 (RFC 3174).
fn sha1_hash(input: &[u8]) -> [u8; 20] {
    let msg_len = input.len();
    let bit_len = (msg_len as u64) * 8;
    let mut padded = input.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

    for chunk in padded.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[i*4], chunk[i*4+1], chunk[i*4+2], chunk[i*4+3]]);
        }
        for i in 16..80 {
            w[i] = (w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for i in 0..80usize {
            let (f, k) = match i {
                0..=19  => ((b & c) | (!b & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d,           0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _       => (b ^ c ^ d,           0xCA62C1D6),
            };
            let temp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(w[i]);
            e = d; d = c; c = b.rotate_left(30); b = a; a = temp;
        }
        h[0] = h[0].wrapping_add(a); h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c); h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let mut out = [0u8; 20];
    for (i, &v) in h.iter().enumerate() {
        out[i*4..(i+1)*4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

