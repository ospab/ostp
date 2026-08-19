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
use tokio::time::{interval, timeout, Instant, MissedTickBehavior};

use crate::app::{BridgeCommand, ConnectionStatus, UiEvent};
use crate::config::ClientConfig;
use crate::tunnel::{ProxyEvent, ProxyToClientMsg};

/// Per-address ceiling on the UoT/TCP connect attempt. Long enough that a
/// genuinely slow mobile path still completes its handshake, short enough that
/// a blackholed address (typically IPv6 advertised without a working route)
/// costs seconds instead of the kernel's full SYN-retry budget before the next
/// candidate address is tried.
const UOT_CONNECT_TIMEOUT: Duration = Duration::from_secs(4);

/// How long to keep retrying a resume-triggered reconnect before handing the
/// problem back to the ordinary stall path. That path is what releases the
/// system proxy, so this is really a bound on how long the machine may be left
/// with no working internet at all after waking.
const RESUME_RECONNECT_GIVE_UP: Duration = Duration::from_secs(45);

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
    pub rtt_ms: portable_atomic::AtomicU32,
}

async fn send_datagram(socket: &crate::transport::Transport, frame: &Bytes, _webrtc_masquerade: bool) -> std::io::Result<usize> {
    socket.send(frame).await
}

struct SessionState {
    socket: crate::transport::Transport,
    machine: ProtocolMachine,
    /// Handle to this session's spawned receiver task. Held so the task is
    /// aborted when the session is dropped (e.g. replaced on reconnect).
    /// Otherwise, on a dead connection the task blocks forever in recv() while
    /// keeping the old socket alive — leaking a task + socket on every
    /// reconnect, which piles up across sleep/resume cycles.
    rx_task: tokio::task::AbortHandle,
}

impl Drop for SessionState {
    fn drop(&mut self) {
        self.rx_task.abort();
    }
}

/// Spawn the per-session receiver loop that reads inbound datagrams from the
/// transport and forwards them to the bridge, returning an AbortHandle so the
/// task is torn down when its `SessionState` is dropped. Consolidates the three
/// previously-duplicated inline copies (initial connect, network-change, and
/// keepalive reconnect).
fn spawn_session_receiver(
    socket: crate::transport::Transport,
    session_index: usize,
    udp_tx: mpsc::Sender<(usize, Bytes)>,
) -> tokio::task::AbortHandle {
    tokio::spawn(async move {
        let mut buf = vec![0_u8; 65535];
        let is_uot = matches!(socket, crate::transport::Transport::Uot { .. });
        loop {
            match socket.recv(&mut buf).await {
                Ok(n) => {
                    let inbound = Bytes::copy_from_slice(&buf[..n]);
                    if udp_tx.send((session_index, inbound)).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    if is_uot {
                        // TCP transport is dead; exit so the bridge sees the
                        // channel close and reconnects.
                        tracing::debug!("UoT session {} disconnected: {}", session_index, e);
                        break;
                    } else {
                        tracing::warn!("UDP socket recv error (session {}): {}", session_index, e);
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                }
            }
        }
    })
    .abort_handle()
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

    pub keepalive_interval_sec: u64,
    pub mode: String,
    pub mux_enabled: bool,
    pub mux_sessions: usize,

    pub transport_mode: String,
    pub tcp_fragmentation: bool,
    pub frag_chunk: usize,
    pub frag_sleep: u64,
    pub junk_pc: [usize; 2],
    pub junk_ps: [usize; 2],
    pub ttl_desync: bool,
    pub ttl_desync_ttl: u8,
    pub ttl_desync_count: u8,
    pub mtu: usize,
    pub kill_switch: bool,
    pub reload_tx: Option<watch::Sender<crate::config::ExclusionConfig>>,

    metrics: Arc<BridgeMetrics>,
    sample_sent: u64,
    sample_recv: u64,
    last_rtt_ms: f64,
    last_sample_at: Instant,
    last_valid_recv: Instant,
    /// Set when a suspend/resume is detected, cleared once a reconnect actually
    /// succeeds. Waking is precisely when the network is least likely to be
    /// ready — Wi-Fi has not reassociated yet — so a single attempt fired
    /// milliseconds after resume usually fails, and a one-shot forced reconnect
    /// then fell back to the ordinary 25s stall heuristic. That heuristic keys
    /// off a monotonic clock which does not advance while the machine is
    /// asleep, so it could take a further 25s of real uptime to fire, or not
    /// fire at all. Retrying until success removes the dependency on either.
    forced_reconnect_pending: bool,
    last_forced_reconnect_try: Instant,
    /// Wall-clock start of the current resume-reconnect campaign, used to bound
    /// it. Wall clock rather than Instant because the monotonic clock does not
    /// advance across suspend on Windows, so it cannot measure anything that
    /// begins at wake.
    forced_reconnect_started: Option<SystemTime>,
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

            keepalive_interval_sec: config.ostp.keepalive_interval_sec,
            mode: config.mode.clone(),
            mux_enabled: config.multiplex.enabled,
            mux_sessions: config.multiplex.sessions.max(1),

            transport_mode: config.transport.mode.clone(),
            tcp_fragmentation: config.transport.tcp_fragmentation,
            frag_chunk: config.transport.frag_chunk,
            frag_sleep: config.transport.frag_sleep,
            junk_pc: config.transport.junk_pc,
            junk_ps: config.transport.junk_ps,
            ttl_desync: config.transport.ttl_desync,
            ttl_desync_ttl: config.transport.ttl_desync_ttl,
            ttl_desync_count: config.transport.ttl_desync_count,
            mtu: config.ostp.mtu,
            kill_switch: config.kill_switch,
            reload_tx: None,

            metrics,
            sample_sent: 0,
            sample_recv: 0,
            last_rtt_ms: 0.0,
            last_sample_at: Instant::now(),
            last_valid_recv: Instant::now(),
            forced_reconnect_pending: false,
            last_forced_reconnect_try: Instant::now(),
            forced_reconnect_started: None,
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
        let mut keepalive_tick = tokio::time::interval(Duration::from_secs(self.keepalive_interval_sec.max(1)));
        let mut retransmit_tick = tokio::time::interval(Duration::from_millis(10));
        // CRITICAL for suspend/resume: the default MissedTickBehavior is `Burst`,
        // which after a laptop sleep or a phone backgrounding the app fires ALL
        // the ticks that "should" have happened during the gap back-to-back. For
        // the 10ms retransmit tick that is tens of thousands of instant ticks on
        // resume — a CPU storm that hangs the bridge and manifests as the app
        // freezing or getting stuck "Connecting". Skip missed ticks instead.
        metrics_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        keepalive_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        retransmit_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

        // Wall-clock anchor for suspend/resume detection. tokio's timers run on a
        // monotonic clock; comparing it against wall-clock lets us notice that
        // the machine slept (or the app was frozen in the background) and force
        // one clean reconnect instead of trying to resume a long-dead session.
        let mut last_wall_check = SystemTime::now();
        let init_msg = if self.mode == "tun" {
            "Bridge initialized (TUN mode)".to_string()
        } else {
            "Bridge initialized (proxy mode)".to_string()
        };
        tx.send(UiEvent::Log(init_msg)).await.ok();

        let mut sessions_opt: Option<Vec<SessionState>> = None;
        let mut udp_rx_opt: Option<mpsc::Receiver<(usize, Bytes)>> = None;
        let mut proxy_guard: Option<crate::sysproxy::SystemProxyGuard> = None;
        let mut stream_map: std::collections::HashMap<u16, usize> = std::collections::HashMap::new();

        loop {
            tokio::select! {
                biased;
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        self.running = false;
                        self.metrics.connection_state.store(0, Ordering::Relaxed);
                        #[allow(unused_assignments)]
                        { proxy_guard = None; }
                        stream_map.clear();
                        self.reset_proxy_streams(&tx, &proxy_tx, "manual stop");
                        break;
                    }
                }
                udp_msg = async {
                    match udp_rx_opt.as_mut() {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                }, if self.running => {
                    self.handle_inbound_udp(udp_msg, &mut sessions_opt, &mut udp_rx_opt, &mut proxy_guard, &mut stream_map, &tx, &proxy_tx).await;
                }
                cmd = bridge_rx.recv() => {
                    if !self.handle_bridge_cmd(cmd, &mut bridge_rx, &mut sessions_opt, &mut udp_rx_opt, &mut proxy_guard, &mut stream_map, &tx, &proxy_tx).await {
                        break;
                    }
                }
                _ = metrics_tick.tick() => {
                    // Suspend/resume detection: the wall clock jumps forward on
                    // wake even when the monotonic timer clock does not, so a
                    // large gap here means the machine slept / the app was frozen.
                    // The session is almost certainly dead (the server evicts
                    // idle sessions after 10 min), so force one clean reconnect
                    // rather than waiting on stale-session heuristics.
                    let wall_gap = last_wall_check.elapsed().unwrap_or_default();
                    last_wall_check = SystemTime::now();
                    if self.running && wall_gap > Duration::from_secs(15) {
                        let _ = tx.send(UiEvent::Log(format!(
                            "Resumed after ~{}s suspend — forcing clean reconnect", wall_gap.as_secs()
                        ))).await;
                        self.forced_reconnect_pending = true;
                        self.forced_reconnect_started = Some(SystemTime::now());
                        self.last_forced_reconnect_try = Instant::now() - Duration::from_secs(60);
                    }

                    // Give up if resume reconnects keep failing. Retrying forever
                    // looks harmless but is not: the system proxy stays pointed at
                    // our local listener the whole time, so the machine has NO
                    // working internet — not merely no tunnel — while the UI sits
                    // on "connecting". Handing the retry to the ordinary keepalive
                    // path restores the proxy through its hard-timeout branch,
                    // which force=true deliberately skips.
                    //
                    // Measured on the wall clock: Instant does not advance across
                    // suspend on Windows (QPC stops), so a monotonic deadline can
                    // not bound anything that starts at wake.
                    if self.forced_reconnect_pending {
                        let pending_for = self
                            .forced_reconnect_started
                            .and_then(|t| t.elapsed().ok())
                            .unwrap_or_default();
                        if pending_for > RESUME_RECONNECT_GIVE_UP {
                            self.forced_reconnect_pending = false;
                            self.forced_reconnect_started = None;
                            let _ = tx.send(UiEvent::Log(format!(
                                "Reconnect after suspend failed for {}s — releasing the system \
                                 proxy so normal traffic works; will keep retrying in the \
                                 background",
                                pending_for.as_secs()
                            ))).await;
                            // Make the ordinary stall path fire on the next
                            // keepalive tick: it is the one that tears the proxy
                            // back down (or, with kill switch on, deliberately
                            // keeps blocking).
                            self.last_valid_recv = Instant::now()
                                .checked_sub(Duration::from_secs(3600))
                                .unwrap_or_else(Instant::now);
                        }
                    }

                    // Keep retrying a resume-triggered reconnect until one lands.
                    // The first attempt fires within half a second of waking, when
                    // the NIC is typically still reassociating, so treating it as
                    // one-shot left the tunnel dead until some other timer noticed.
                    if self.running
                        && self.forced_reconnect_pending
                        && self.last_forced_reconnect_try.elapsed() >= Duration::from_secs(3)
                    {
                        self.last_forced_reconnect_try = Instant::now();
                        self.handle_keepalive(true, &mut sessions_opt, &mut udp_rx_opt, &mut proxy_guard, &mut stream_map, &tx, &proxy_tx, &mut proxy_rx).await;
                        // handle_keepalive refreshes last_valid_recv only when a
                        // session was actually established, so this is a real
                        // success check rather than "we tried".
                        if self.last_valid_recv.elapsed() < Duration::from_secs(3) {
                            self.forced_reconnect_pending = false;
                            self.forced_reconnect_started = None;
                            let _ = tx.send(UiEvent::Log("Reconnected after suspend".into())).await;
                        }
                    }
                    if self.running {
                        self.emit_metrics(&tx).await;
                    }
                }
                _ = keepalive_tick.tick() => {
                    if self.running {
                        self.handle_keepalive(false, &mut sessions_opt, &mut udp_rx_opt, &mut proxy_guard, &mut stream_map, &tx, &proxy_tx, &mut proxy_rx).await;
                    }
                }
                _ = retransmit_tick.tick() => {
                    if self.running {
                        self.handle_retransmit(&mut sessions_opt, &mut udp_rx_opt, &mut proxy_guard, &mut stream_map, &tx, &proxy_tx).await;
                    }
                }
                proxy_ev = proxy_rx.recv(), if self.running && sessions_opt.as_ref().map(|s| {
                    // Upper bound matches MAX_CWND_PACKETS in ostp-core's congestion
                    // controller. The old 16384 ceiling let ~20 MB sit in flight,
                    // which on a mobile uplink is minutes of buffered queue rather
                    // than throughput — the app kept handing over data long after
                    // the path had stopped draining it.
                    // Two independent gates. cwnd bounds how much may be in
                    // flight; pacing bounds how FAST it is released. Without the
                    // second, a full window goes out back-to-back and lands in
                    // the bottleneck's buffer as standing queue rather than
                    // throughput — the thing that produced multi-second RTT.
                    s.iter().any(|ses| {
                        ses.machine.in_flight_count() < ses.machine.cwnd_packets().clamp(16, 1024)
                            && ses.machine.can_pace_packet()
                    })
                }).unwrap_or(true) => {
                    self.handle_proxy_event(proxy_ev, &mut sessions_opt, &mut stream_map, &tx, &proxy_tx).await;
                }
            }
        }

        tx.send(UiEvent::Log("Bridge stopped".to_string())).await.ok();
        Ok(())
    }

    async fn handle_inbound_udp(
        &mut self,
        udp_msg: Option<(usize, Bytes)>,
        sessions_opt: &mut Option<Vec<SessionState>>,
        udp_rx_opt: &mut Option<mpsc::Receiver<(usize, Bytes)>>,
        _proxy_guard: &mut Option<crate::sysproxy::SystemProxyGuard>,
        stream_map: &mut std::collections::HashMap<u16, usize>,
        tx: &mpsc::Sender<UiEvent>,
        proxy_tx: &mpsc::UnboundedSender<(u16, ProxyToClientMsg)>,
    ) {
        match udp_msg {
            Some((session_index, inbound)) => {
                // Raw byte counter — every datagram that reached the socket counts.
                self.metrics.bytes_recv.fetch_add(inbound.len() as u64, Ordering::Relaxed);
                if let Some(sessions) = sessions_opt.as_mut() {
                    if session_index < sessions.len() {
                        let session = &mut sessions[session_index];
                        let initial_action = match session.machine.on_event(OstpEvent::Inbound(inbound)) {
                            Ok(a) => a,
                            Err(e) => {
                                let _ = tx.send(UiEvent::Log(format!("Protocol decrypt error: {e}"))).await;
                                tracing::warn!("Inbound protocol error (session {}): {}", session_index, e);
                                return;
                            }
                        };

                        // Only NOW, after the datagram actually authenticated and
                        // decrypted, does it count as a sign of life. This used to
                        // be set above, before any validation — so a datagram that
                        // failed to decrypt still reset the stall detector on its
                        // way to the `return` above. Anything arriving at this port
                        // (frames from a session the server already evicted, stale
                        // retransmits, or plain garbage from an off-path source that
                        // knows the ip:port) kept the client convinced the tunnel
                        // was healthy: the 25s background reconnect in
                        // handle_keepalive never fired and the tunnel sat dead at
                        // 0 b/s until the user reconnected by hand. It also made
                        // `is_healthy` (see emit_metrics) lie in the UI, and handed
                        // any off-path sender a trivial way to pin a client in a
                        // dead session indefinitely.
                        self.last_valid_recv = Instant::now();

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
                                                    self.metrics.rtt_ms.store(self.last_rtt_ms as u32, Ordering::Relaxed);
                                                }
                                                RelayMessage::UdpAssociate => {}
                                                RelayMessage::UdpData(target, data) => {
                                                    let _ = proxy_tx.send((stream_id, ProxyToClientMsg::UdpData(target, Bytes::from(data))));
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
                                    let _ = send_datagram(&session.socket, &frame, self.transport_mode == "udp" ).await;
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
                crate::sysproxy::disable_system_proxy();
                *sessions_opt = None;
                *udp_rx_opt = None;
                stream_map.clear();
                self.reset_proxy_streams(&tx, &proxy_tx, "udp reader closed");
                let _ = tx.send(UiEvent::TunnelStopped).await;
            }
        }
    }

    async fn handle_bridge_cmd(
        &mut self,
        cmd: Option<BridgeCommand>,
        bridge_rx: &mut mpsc::Receiver<BridgeCommand>,
        sessions_opt: &mut Option<Vec<SessionState>>,
        udp_rx_opt: &mut Option<mpsc::Receiver<(usize, Bytes)>>,
        proxy_guard: &mut Option<crate::sysproxy::SystemProxyGuard>,
        stream_map: &mut std::collections::HashMap<u16, usize>,
        tx: &mpsc::Sender<UiEvent>,
        proxy_tx: &mpsc::UnboundedSender<(u16, ProxyToClientMsg)>,
    ) -> bool {
        match cmd {
            Some(BridgeCommand::ToggleTunnel) => {
                if self.running {
                    self.running = false;
                    self.metrics.connection_state.store(0, Ordering::Relaxed);
                    *proxy_guard = None;
                    *sessions_opt = None;
                    *udp_rx_opt = None;
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
                    let (udp_tx, udp_rx) = mpsc::channel(1024);
                    let mut sessions = Vec::with_capacity(session_count);
                    let mut rtt_sum = 0.0;
                    let mut successful_sessions = 0;

                    for idx in 0..session_count {
                        let session_id: u32 = rand::thread_rng().gen();
                        match self.perform_handshake_with_id(&tx, session_id).await {
                            Ok((sock, mach, rtt)) => {
                                let session_index = sessions.len();
                                let rx_task = spawn_session_receiver(sock.clone(), session_index, udp_tx.clone());

                                sessions.push(SessionState { socket: sock, machine: mach, rx_task });
                                rtt_sum += rtt;
                                successful_sessions += 1;
                            }
                            Err(err) => {
                                tx.send(UiEvent::Log(format!("Multiplex session {}/{} handshake failed: {}. Continuing with remaining sessions...", idx + 1, session_count, err))).await.ok();
                            }
                        }
                    }

                    if sessions.is_empty() {
                        *proxy_guard = None;
                        tx.send(UiEvent::Log("All multiplexed handshake attempts failed. Connection aborted.".to_string())).await.ok();
                        tx.send(UiEvent::TunnelStopped).await.ok();
                        self.metrics.connection_state.store(0, Ordering::Relaxed);
                        return true;
                    }

                    *udp_rx_opt = Some(udp_rx);
                    *sessions_opt = Some(sessions);
                    self.last_rtt_ms = rtt_sum / successful_sessions as f64;
                    self.running = true;
                    self.last_sample_at = Instant::now();
                    self.last_valid_recv = Instant::now();
                    
                    let sys_proxy_addr = self.proxy_addr.replace("0.0.0.0:", "127.0.0.1:");
                    *proxy_guard = Some(crate::sysproxy::SystemProxyGuard::enable(&sys_proxy_addr));

                    tx.send(UiEvent::Metrics {
                        status: ConnectionStatus::Established,
                        rtt_ms: self.last_rtt_ms,
                        throughput_bps: 0,
                    }).await.ok();
                    self.metrics.connection_state.store(2, Ordering::Relaxed);
                    let start_msg = if self.mode == "tun" { "TUN tunnel established" } else { "Connection established" };
                    tx.send(UiEvent::Log(start_msg.to_string())).await.ok();

                    for session in sessions_opt.as_mut().unwrap().iter_mut() {
                        let ts = SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
                        let ping_payload = Bytes::from(RelayMessage::Ping(ts).encode());
                        if let Ok(ProtocolAction::SendDatagram(frame)) = session.machine.on_event(OstpEvent::Outbound(0, ping_payload)) {
                            let _ = send_datagram(&session.socket, &frame, self.transport_mode == "udp").await;
                            self.metrics.bytes_sent.fetch_add(frame.len() as u64, Ordering::Relaxed);
                        }
                    }
                }
            }
            Some(BridgeCommand::NextProfile) => {
                self.profile = next_profile(self.profile);
                tx.send(UiEvent::ProfileChanged(self.profile)).await.ok();
                tx.send(UiEvent::Log(format!("Obfuscation profile switched to {:?}", self.profile))).await.ok();
            }
            Some(BridgeCommand::NetworkChanged) => {
                // A real network handoff (Wi-Fi <-> cellular) commonly fires
                // onLost + onAvailable within milliseconds of each other on
                // Android, queuing several NetworkChanged commands back to
                // back. Each reconnect below is a full sequential handshake
                // (up to ~1.2s x 4 attempts x mux_sessions) run synchronously
                // in this select-loop iteration, so without coalescing, the
                // first attempt often races the OS's own network switch and
                // fails on the now-dead interface, then the SECOND queued
                // NetworkChanged only starts its own full reconnect after
                // that first one finishes - multiplying a sub-second handoff
                // into many seconds of extra outage. Drain same-kind repeats
                // so a burst collapses into one reconnect on the freshest
                // signal; a different command found while draining is
                // handled immediately rather than dropped.
                while let Ok(next) = bridge_rx.try_recv() {
                    if !matches!(next, BridgeCommand::NetworkChanged) {
                        let more = Box::pin(self.handle_bridge_cmd(
                            Some(next), bridge_rx, sessions_opt, udp_rx_opt, proxy_guard, stream_map, tx, proxy_tx,
                        )).await;
                        if !more {
                            return false;
                        }
                        break;
                    }
                }

                if self.running {
                    let _ = tx.send(UiEvent::Log("Network changed — starting immediate reconnect".to_string())).await;
                    self.metrics.connection_state.store(1, Ordering::Relaxed);
                    self.last_valid_recv = Instant::now() - Duration::from_secs(100);

                    let session_count = if self.mux_enabled { self.mux_sessions.max(1) } else { 1 };
                    let (udp_tx, udp_rx) = mpsc::channel(1024);
                    let mut new_sessions = Vec::with_capacity(session_count);
                    let mut successful_sessions = 0;
                    let mut rtt_sum = 0.0;

                    for idx in 0..session_count {
                        let session_id: u32 = rand::thread_rng().gen();
                        match self.perform_handshake_with_id(&tx, session_id).await {
                            Ok((sock, mach, rtt)) => {
                                let session_index = new_sessions.len();
                                let rx_task = spawn_session_receiver(sock.clone(), session_index, udp_tx.clone());
                                new_sessions.push(SessionState { socket: sock, machine: mach, rx_task });
                                rtt_sum += rtt;
                                successful_sessions += 1;
                            }
                            Err(err) => {
                                let _ = tx.send(UiEvent::Log(format!("NetworkChanged reconnect session {}/{} failed: {}", idx + 1, session_count, err))).await;
                            }
                        }
                    }

                    if !new_sessions.is_empty() {
                        *sessions_opt = Some(new_sessions);
                        *udp_rx_opt = Some(udp_rx);
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
                        let old_server = self.server_addr.clone();
                        let old_mode = self.mode.clone();
                        let old_transport = self.transport_mode.clone();
                        
                        self.apply_runtime_config(&cfg);
                        
                        let requires_restart = self.server_addr != old_server || 
                                               self.mode != old_mode || 
                                               self.transport_mode != old_transport;
                                               
                        if !requires_restart {
                            if let Some(tx_watch) = &self.reload_tx {
                                let _ = tx_watch.send(cfg.exclusions.clone());
                            }
                            tx.send(UiEvent::Log("Exclusions updated in real-time (hot reload)".to_string())).await.ok();
                        } else {
                            tx.send(UiEvent::Log("Runtime config reloaded. Restarting tunnel due to critical parameter changes.".to_string())).await.ok();
                            if self.running {
                                self.running = false;
                                self.metrics.connection_state.store(0, Ordering::Relaxed);
                                *proxy_guard = None;
                                *sessions_opt = None;
                                stream_map.clear();
                                self.reset_proxy_streams(&tx, &proxy_tx, "config reload");
                                let _ = tx.send(UiEvent::TunnelStopped).await;
                            }
                        }
                    }
                    Err(err) => {
                        let _ = tx.send(UiEvent::Log(format!("Config reload failed: {err}"))).await;
                    }
                }
            }
            Some(BridgeCommand::Shutdown) | None => {
                self.running = false;
                *proxy_guard = None;
                return false;
            }
        }
        true
    }

    async fn handle_keepalive(
        &mut self,
        force: bool,
        sessions_opt: &mut Option<Vec<SessionState>>,
        udp_rx_opt: &mut Option<mpsc::Receiver<(usize, Bytes)>>,
        proxy_guard: &mut Option<crate::sysproxy::SystemProxyGuard>,
        stream_map: &mut std::collections::HashMap<u16, usize>,
        tx: &mpsc::Sender<UiEvent>,
        proxy_tx: &mpsc::UnboundedSender<(u16, ProxyToClientMsg)>,
        proxy_rx: &mut mpsc::Receiver<ProxyEvent>,
    ) {
        if force || self.last_valid_recv.elapsed().as_secs() > 25 {
            let elapsed = self.last_valid_recv.elapsed().as_secs();
            // On a forced (post-resume) reconnect the monotonic clock may not
            // have advanced, so `elapsed` can be small — never treat a forced
            // reconnect as a hard timeout; we specifically want to re-establish.
            if !force && elapsed > 180 {
                if self.kill_switch {
                    let _ = tx.send(UiEvent::Log(format!("Connection stall ({}s). Kill Switch is ON, retrying reconnect indefinitely...", elapsed))).await;
                } else {
                    let _ = tx.send(UiEvent::Log("Connection permanently lost (3-minute hard timeout). Stopping tunnel.".into())).await;
                    self.running = false;
                    *proxy_guard = None;
                    *sessions_opt = None;
                    stream_map.clear();
                    self.reset_proxy_streams(&tx, &proxy_tx, "keepalive hard timeout");
                    let _ = tx.send(UiEvent::TunnelStopped).await;
                    self.metrics.connection_state.store(0, Ordering::Relaxed);
                    return;
                }
            } else {
                let _ = tx.send(UiEvent::Log(format!("Connection stall detected ({}s silence). Attempting background reconnect...", elapsed))).await;
            }

            self.metrics.connection_state.store(1, Ordering::Relaxed);

            let session_count = if self.mux_enabled { self.mux_sessions.max(1) } else { 1 };
            let (udp_tx, udp_rx) = mpsc::channel(1024);
            let mut new_sessions = Vec::with_capacity(session_count);
            let mut successful_sessions = 0;
            let mut rtt_sum = 0.0;

            for idx in 0..session_count {
                let session_id: u32 = rand::thread_rng().gen();
                match self.perform_handshake_with_id(&tx, session_id).await {
                    Ok((sock, mach, rtt)) => {
                        let session_index = new_sessions.len();
                        let rx_task = spawn_session_receiver(sock.clone(), session_index, udp_tx.clone());

                        new_sessions.push(SessionState { socket: sock, machine: mach, rx_task });
                        rtt_sum += rtt;
                        successful_sessions += 1;
                    }
                    Err(err) => {
                        let _ = tx.send(UiEvent::Log(format!("Background reconnect session {}/{} failed: {}", idx + 1, session_count, err))).await;
                    }
                }
            }

            if !new_sessions.is_empty() {
                *sessions_opt = Some(new_sessions);
                *udp_rx_opt = Some(udp_rx);
                self.last_rtt_ms = rtt_sum / successful_sessions as f64;
                self.last_valid_recv = Instant::now();
                self.metrics.connection_state.store(2, Ordering::Relaxed);
                let _ = tx.send(UiEvent::Log("Background reconnect successful! Connection restored.".into())).await;

                for session in sessions_opt.as_mut().unwrap().iter_mut() {
                    let ts = SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
                    let ping_payload = Bytes::from(RelayMessage::Ping(ts).encode());
                    if let Ok(ProtocolAction::SendDatagram(frame)) = session.machine.on_event(OstpEvent::Outbound(0, ping_payload)) {
                        let _ = send_datagram(&session.socket, &frame, self.transport_mode == "udp").await;
                        self.metrics.bytes_sent.fetch_add(frame.len() as u64, Ordering::Relaxed);
                    }
                }
                
                stream_map.clear();
                self.reset_proxy_streams(&tx, &proxy_tx, "background reconnect");

                let mut flushed = 0;
                while let Ok(stale) = proxy_rx.try_recv() {
                    if let ProxyEvent::NewStream { stream_id, .. } = stale {
                        let _ = proxy_tx.send((stream_id, ProxyToClientMsg::Error("connection reset".into())));
                    }
                    flushed += 1;
                }
                if flushed > 0 {
                    let _ = tx.send(UiEvent::Log(format!("Flushed {} stale proxy messages to prevent UDP burst", flushed))).await;
                }
            } else {
                let _ = tx.send(UiEvent::Log("Background reconnect failed. Will retry on next tick...".into())).await;
            }
        }

        if let Some(sessions) = sessions_opt.as_mut() {
            for session in sessions.iter_mut() {
                let ts = SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
                let ping_payload = Bytes::from(RelayMessage::Ping(ts).encode());
                if let Ok(ProtocolAction::SendDatagram(frame)) = session.machine.on_event(OstpEvent::Outbound(0, ping_payload)) {
                    let _ = send_datagram(&session.socket, &frame, self.transport_mode == "udp" ).await;
                    self.metrics.bytes_sent.fetch_add(frame.len() as u64, Ordering::Relaxed);
                }

                let ka_payload = Bytes::from(RelayMessage::KeepAlive.encode());
                if let Ok(ProtocolAction::SendDatagram(frame)) = session.machine.on_event(OstpEvent::Outbound(0, ka_payload)) {
                    let _ = send_datagram(&session.socket, &frame, self.transport_mode == "udp" ).await;
                    self.metrics.bytes_sent.fetch_add(frame.len() as u64, Ordering::Relaxed);
                }
            }
        }
    }

    async fn handle_retransmit(
        &mut self,
        sessions_opt: &mut Option<Vec<SessionState>>,
        udp_rx_opt: &mut Option<mpsc::Receiver<(usize, Bytes)>>,
        proxy_guard: &mut Option<crate::sysproxy::SystemProxyGuard>,
        stream_map: &mut std::collections::HashMap<u16, usize>,
        tx: &mpsc::Sender<UiEvent>,
        proxy_tx: &mpsc::UnboundedSender<(u16, ProxyToClientMsg)>,
    ) {
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
                                    let _ = send_datagram(&session.socket, &frame, self.transport_mode == "udp" ).await;
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
            *proxy_guard = None;
            *sessions_opt = None;
            *udp_rx_opt = None;
            stream_map.clear();
            self.reset_proxy_streams(&tx, &proxy_tx, "protocol fatal error");
            let _ = tx.send(UiEvent::TunnelStopped).await;
            self.metrics.connection_state.store(0, Ordering::Relaxed);
        }
    }

    async fn handle_proxy_event(
        &mut self,
        proxy_ev: Option<ProxyEvent>,
        sessions_opt: &mut Option<Vec<SessionState>>,
        stream_map: &mut std::collections::HashMap<u16, usize>,
        tx: &mpsc::Sender<UiEvent>,
        proxy_tx: &mpsc::UnboundedSender<(u16, ProxyToClientMsg)>,
    ) {
        if let Some(ev) = proxy_ev {
            if let Some(sessions) = sessions_opt.as_mut() {
                if sessions.is_empty() {
                    if let ProxyEvent::NewStream { stream_id, .. } = ev {
                        let _ = proxy_tx.send((stream_id, ProxyToClientMsg::Error("tunnel stopped".into())));
                    }
                    return;
                }
                let (stream_id, relay_msg, is_close) = match ev {
                    ProxyEvent::NewStream { stream_id, target } => {
                        let _ = tx.send(UiEvent::Log(format!("Proxy CONNECT stream_id={stream_id} target={target}"))).await;
                        (stream_id, RelayMessage::Connect(target), false)
                    }
                    ProxyEvent::UdpAssociate { stream_id } => {
                        let _ = tx.send(UiEvent::Log(format!("Proxy UDP ASSOCIATE stream_id={stream_id}"))).await;
                        (stream_id, RelayMessage::UdpAssociate, false)
                    }
                    ProxyEvent::UdpData { stream_id, target, payload } => {
                        (stream_id, RelayMessage::UdpData(target, payload.to_vec()), false)
                    }
                    ProxyEvent::Data { stream_id, payload } => (stream_id, RelayMessage::Data(payload.to_vec()), false),
                    ProxyEvent::Close { stream_id } => {
                        let _ = tx.send(UiEvent::Log(format!("Proxy CLOSE stream_id={stream_id}"))).await;
                        (stream_id, RelayMessage::Close, true)
                    }
                };
                let len = sessions.len();
                let session_index = *stream_map.entry(stream_id).or_insert_with(|| {
                    rand::thread_rng().gen_range(0..len)
                });
                if is_close {
                    stream_map.remove(&stream_id);
                }
                let session = &mut sessions[session_index];
                let out_payload = Bytes::from(relay_msg.encode());
                match session.machine.on_event(OstpEvent::Outbound(stream_id, out_payload)) {
                    Ok(ProtocolAction::SendDatagram(frame)) => {
                        if send_datagram(&session.socket, &frame, self.transport_mode == "udp" ).await.is_ok() {
                            self.metrics.bytes_sent.fetch_add(frame.len() as u64, Ordering::Relaxed);
                            tracing::trace!("Outbound datagram sent stream_id={stream_id} bytes={}", frame.len());
                        }
                    }
                    Ok(ProtocolAction::Multiple(list)) => {
                        let mut sent = 0usize;
                        for item in list {
                            if let ProtocolAction::SendDatagram(frame) = item {
                                if send_datagram(&session.socket, &frame, self.transport_mode == "udp" ).await.is_ok() {
                                    self.metrics.bytes_sent.fetch_add(frame.len() as u64, Ordering::Relaxed);
                                    sent += 1;
                                }
                            }
                        }
                        tracing::trace!("Outbound datagram batch stream_id={stream_id} sent={sent}");
                    }
                    Ok(ProtocolAction::Noop) => {
                        tracing::trace!("Outbound datagram noop stream_id={stream_id}");
                    }
                    Ok(_) => {
                        tracing::trace!("Outbound datagram unexpected action stream_id={stream_id}");
                    }
                    Err(e) => {
                        tracing::warn!("Protocol error packing outbound stream_id={}: {}", stream_id, e);
                        let _ = tx.send(UiEvent::Log(format!("Protocol error packing TCP: {e}"))).await;
                    }
                }
            } else {
                if let ProxyEvent::NewStream { stream_id, .. } = ev {
                    let _ = proxy_tx.send((stream_id, ProxyToClientMsg::Error("tunnel stopped".into())));
                }
            }
        }
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
    ) -> Result<(crate::transport::Transport, ProtocolMachine, f64)> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut handshake_payload = Vec::with_capacity(8 + 4 + self.access_key.len());
        handshake_payload.extend_from_slice(&timestamp.to_be_bytes());
        handshake_payload.extend_from_slice(&session_id.to_be_bytes());
        handshake_payload.extend_from_slice(&self.access_key);

        let secrets = ostp_core::crypto::derive_all_secrets(&self.access_key);

        let mut resolved_addrs: Vec<std::net::SocketAddr> = match tokio::net::lookup_host(&self.server_addr).await {
            Ok(addrs) => addrs.collect(),
            Err(e) => return Err(anyhow::anyhow!("failed to resolve server address {}: {}", self.server_addr, e)),
        };
        // IPv4 first. Addresses are tried strictly in order, each burning its
        // full retry budget before the next is touched, so this ordering decides
        // how long a bad family stalls the whole connect. Mobile carriers
        // routinely hand out IPv6 with no working route and BLACKHOLE it rather
        // than rejecting, so every IPv6 candidate costs the full timeout budget
        // — with several AAAA records the working IPv4 address was not reached
        // for tens of seconds. (The same ordering bug was already fixed on the
        // server's outbound path and in the UoT connect.)
        resolved_addrs.sort_by_key(|addr| if addr.is_ipv6() { 1 } else { 0 });

        // NAT64 is a fallback for IPv6-only networks. Retrying it per failing
        // address multiplied an already-long connect: each attempt re-runs a DNS
        // lookup and another full round of handshake retries, for a path that
        // either works for the whole network or for none of it.
        let mut nat64_attempted = false;

        let mut last_err = anyhow::anyhow!("no IP addresses resolved for {}", self.server_addr);

        for target_addr in resolved_addrs {
            let target_ip = target_addr.ip();
            let port = target_addr.port();

            tx.send(UiEvent::Log(format!("Connecting to remote server: {}...", target_addr))).await.ok();

            let socket = match self.try_connect_transport(target_ip, port).await {
                Ok(sock) => sock,
                Err(e) => {
                    if let (std::net::IpAddr::V4(ipv4), false) = (target_ip, nat64_attempted) {
                        nat64_attempted = true;
                        tx.send(UiEvent::Log(format!("Direct IPv4 connection failed: {}. Trying NAT64 fallback...", e))).await.ok();
                        let nat64_ipv6 = synthesize_nat64(ipv4).await;
                        match self.try_connect_transport(std::net::IpAddr::V6(nat64_ipv6), port).await {
                            Ok(sock) => sock,
                            Err(fallback_err) => {
                                last_err = anyhow::anyhow!("Direct IPv4 failed: {}. NAT64 fallback failed: {}", e, fallback_err);
                                continue;
                            }
                        }
                    } else {
                        last_err = anyhow::anyhow!("Connection to {} failed: {}", target_addr, e);
                        continue;
                    }
                }
            };

            let mut machine = ProtocolMachine::new(ProtocolConfig {
                role: NoiseRole::Initiator,
                psk: secrets.psk,
                session_id,
                handshake_payload: handshake_payload.clone(),
                padding_strategy: PaddingStrategy::Profile(self.profile),
                obfuscation_key: secrets.obfuscation_key,
                max_reorder: 16384,
                max_reorder_buffer: 8192,
                ack_delay_ms: 5,
                rto_ms: 100,
                max_retries: 8,
                max_sent_history: 32768,
                handshake_pad_min: secrets.handshake_pad_min,
                handshake_pad_max: secrets.handshake_pad_max,
                mtu: self.mtu,
                max_padding: self.mtu.saturating_sub(48).max(256),
            })?;

            let start = Instant::now();
            let action = match machine.on_event(OstpEvent::Start) {
                Ok(a) => a,
                Err(e) => {
                    last_err = anyhow::anyhow!("protocol start error: {}", e);
                    continue;
                }
            };

            let handshake_frame = match action {
                ProtocolAction::SendDatagram(frame) => frame,
                _ => {
                    last_err = anyhow::anyhow!("protocol did not emit handshake datagram");
                    continue;
                }
            };
            
            let mut buf = vec![0_u8; 4096];
            let mut size = 0;
            let mut success = false;

            let is_uot = matches!(socket, crate::transport::Transport::Uot { .. });
            let (attempt_limit, attempt_timeout_ms) = if is_uot { (1, 8000) } else { (4, 1200) };

            // TTL-desync (UDP only, opt-in): fire decoy datagrams that reach an
            // on-path DPI box but expire before the server, so the box classifies
            // the flow on the decoys rather than the real handshake that follows.
            // Each carries the key's junk marker, so any decoy that does reach
            // the server is dropped there silently.
            if self.ttl_desync && !is_uot && self.ttl_desync_count > 0 {
                let marker = ostp_core::crypto::derive_junk_marker(
                    &self.access_key,
                    ostp_core::crypto::current_junk_window(),
                );
                let decoys: Vec<bytes::Bytes> = {
                    let mut rng = rand::thread_rng();
                    let [min_s, max_s] = self.junk_ps;
                    let min_s = min_s.max(4);
                    let max_s = max_s.max(min_s);
                    (0..self.ttl_desync_count)
                        .map(|_| {
                            let len = rng.gen_range(min_s..=max_s);
                            let mut b = vec![0u8; len];
                            rng.fill(&mut b[..]);
                            b[..4].copy_from_slice(&marker);
                            bytes::Bytes::from(b)
                        })
                        .collect()
                };
                socket.send_ttl_decoys(&decoys, self.ttl_desync_ttl).await;
            }

            for attempt in 0..attempt_limit {
                if attempt > 0 {
                    tx.send(UiEvent::Log(format!("Handshake attempt {} lost. Retransmitting...", attempt))).await.ok();
                }
                if send_datagram(&socket, &handshake_frame, self.transport_mode == "udp").await.is_ok() {
                    self.metrics.bytes_sent.fetch_add(handshake_frame.len() as u64, Ordering::Relaxed);
                }

                match timeout(Duration::from_millis(attempt_timeout_ms), socket.recv(&mut buf)).await {
                    Ok(Ok(n)) => {
                        size = n;
                        success = true;
                        break;
                    }
                    _ => {} 
                }
            }

            let (final_socket, size) = if success {
                (socket, size)
            } else {
                if let (std::net::IpAddr::V4(ipv4), false) = (target_ip, nat64_attempted) {
                    nat64_attempted = true;
                    tx.send(UiEvent::Log("Direct IPv4 handshake timed out. Trying NAT64 fallback...".to_string())).await.ok();
                    let nat64_ipv6 = synthesize_nat64(ipv4).await;
                    match self.try_connect_transport(std::net::IpAddr::V6(nat64_ipv6), port).await {
                        Ok(fallback_socket) => {
                            let mut fallback_success = false;
                            for attempt in 0..4 {
                                if attempt > 0 {
                                    tx.send(UiEvent::Log(format!("NAT64 handshake attempt {} lost. Retransmitting...", attempt))).await.ok();
                                }
                                if send_datagram(&fallback_socket, &handshake_frame, self.transport_mode == "udp").await.is_ok() {
                                    self.metrics.bytes_sent.fetch_add(handshake_frame.len() as u64, Ordering::Relaxed);
                                }
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
                                last_err = anyhow::anyhow!("NAT64 handshake failed after 4 attempts");
                                continue;
                            }
                        }
                        Err(e) => {
                            last_err = anyhow::anyhow!("NAT64 fallback socket creation failed: {}", e);
                            continue;
                        }
                    }
                } else {
                    last_err = anyhow::anyhow!("Direct handshake failed after attempts");
                    continue;
                }
            };

            let socket = final_socket;
            self.metrics.bytes_recv.fetch_add(size as u64, Ordering::Relaxed);
            tracing::info!("Handshake response received: {} bytes", size);

            let inbound = Bytes::copy_from_slice(&buf[..size]);
            if let Err(e) = machine.on_event(OstpEvent::Inbound(inbound)) {
                last_err = anyhow::anyhow!("Protocol invalid response: {}", e);
                continue;
            }
            let rtt_ms = start.elapsed().as_secs_f64() * 1000.0;
            tracing::info!("Handshake complete: session={:#010x} rtt={:.1}ms", session_id, rtt_ms);

            return Ok((socket, machine, rtt_ms));
        }

        Err(last_err)
    }

    fn apply_runtime_config(&mut self, cfg: &ClientConfig) {
        self.server_addr = cfg.ostp.server_addr.clone();
        self.local_bind_addr = cfg.ostp.local_bind_addr.clone();
        self.proxy_addr = cfg.local_proxy.bind_addr.clone();
        self.access_key = Bytes::from(cfg.ostp.access_key.clone());
        self.handshake_timeout_ms = cfg.ostp.handshake_timeout_ms;
        self.io_timeout_ms = cfg.ostp.io_timeout_ms;
        self.mode = cfg.mode.clone(); // Bug fix: mode was never updated on hot-reload
        self.mux_enabled = cfg.multiplex.enabled;
        self.mux_sessions = cfg.multiplex.sessions.max(1);
        self.transport_mode = cfg.transport.mode.clone();
        self.tcp_fragmentation = cfg.transport.tcp_fragmentation;
        self.frag_chunk = cfg.transport.frag_chunk.max(1);
        self.frag_sleep = cfg.transport.frag_sleep;
        self.junk_pc = cfg.transport.junk_pc;
        self.junk_ps = cfg.transport.junk_ps;
        self.ttl_desync = cfg.transport.ttl_desync;
        self.ttl_desync_ttl = cfg.transport.ttl_desync_ttl;
        self.ttl_desync_count = cfg.transport.ttl_desync_count;
        self.mtu = cfg.ostp.mtu;
        self.keepalive_interval_sec = cfg.ostp.keepalive_interval_sec;
        self.kill_switch = cfg.kill_switch;
    }

    async fn try_connect_transport(
        &self,
        target_ip: std::net::IpAddr,
        port: u16,
    ) -> Result<crate::transport::Transport> {
        let mode = self.transport_mode.to_lowercase();
        if mode == "uot" || mode == "tcp" {
            // Bound the TCP connect. Without this it inherits the kernel's SYN
            // retry budget, which is tens of seconds (and can reach ~2 minutes).
            // That is exactly what made UoT appear to hang on mobile: callers
            // resolve every address for the server and try IPv6 first (see the
            // sort in perform_handshake_with_id), and a mobile network that
            // advertises IPv6 without a working route blackholes the SYN rather
            // than rejecting it — so the client sat through the full retry
            // budget before it ever reached the IPv4 address that would have
            // connected immediately. UDP never showed this because connect() on
            // a UDP socket only sets the default peer and returns at once.
            let stream = tokio::time::timeout(
                UOT_CONNECT_TIMEOUT,
                tokio::net::TcpStream::connect((target_ip, port)),
            )
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "TCP connect to {target_ip}:{port} timed out after {:?}",
                    UOT_CONNECT_TIMEOUT
                )
            })??;
            let _ = stream.set_nodelay(true);
            let (mut read_half, mut write_half) = stream.into_split();

            let tcp_fragmentation = self.tcp_fragmentation;
            let frag_chunk = self.frag_chunk;
            let frag_sleep = self.frag_sleep;
            let [junk_pc_min, junk_pc_max] = self.junk_pc;
            let [junk_ps_min, junk_ps_max] = self.junk_ps;
            // Time-rotating per-key junk marker — NOT a global constant and NOT
            // even a static per-user value: it changes every window, so junk
            // carries no fixed DPI signature on the wire. All frames in this
            // burst are sent within milliseconds, so one window applies to all.
            let junk_marker = ostp_core::crypto::derive_junk_marker(
                &self.access_key,
                ostp_core::crypto::current_junk_window(),
            );

            {
                use tokio::io::AsyncWriteExt;
                // Build all junk frames up front so ThreadRng isn't held across an
                // await point (keeps this future Send).
                let junk_frames: Vec<Vec<u8>> = {
                    let mut rng = rand::thread_rng();
                    let min_c = junk_pc_min;
                    let max_c = junk_pc_max.max(min_c);
                    let num_junk = rng.gen_range(min_c..=max_c);
                    (0..num_junk)
                        .map(|_| {
                            let min_s = junk_ps_min.max(1);
                            let max_s = junk_ps_max.max(min_s);
                            let junk_len = rng.gen_range(min_s..=max_s);
                            let mut frame = Vec::with_capacity(2 + junk_len);
                            frame.extend_from_slice(&(junk_len as u16).to_be_bytes());
                            let start = frame.len();
                            frame.resize(start + junk_len, 0);
                            rng.fill(&mut frame[start..]);
                            // Stamp this key's derived junk marker so the server drops it silently.
                            if junk_len >= 4 {
                                frame[start..start+4].copy_from_slice(&junk_marker);
                            }
                            frame
                        })
                        .collect()
                };
                for frame in junk_frames {
                    if write_half.write_all(&frame).await.is_err() { break; }
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
            }

            let (tx_out, mut rx_out) = tokio::sync::mpsc::channel::<bytes::Bytes>(1024);
            let (tx_in, rx_in) = tokio::sync::mpsc::channel::<bytes::Bytes>(1024);

            // Writer: length-prefix each frame. With tcp_fragmentation on, split
            // the FIRST real frame (the handshake — junk above was written
            // directly, so it doesn't count) into tiny TCP segments with short
            // gaps so DPI can't reassemble/classify the handshake from one read.
            tokio::spawn(async move {
                use tokio::io::AsyncWriteExt;
                let mut first_packet = true;
                while let Some(data) = rx_out.recv().await {
                    let len_buf = (data.len() as u16).to_be_bytes();
                    if first_packet && tcp_fragmentation {
                        first_packet = false;
                        if write_half.write_all(&len_buf[0..1]).await.is_err() { break; }
                        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                        if write_half.write_all(&len_buf[1..2]).await.is_err() { break; }
                        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                        let mut broke = false;
                        for chunk in data.chunks(frag_chunk) {
                            if write_half.write_all(chunk).await.is_err() { broke = true; break; }
                            tokio::time::sleep(std::time::Duration::from_millis(frag_sleep)).await;
                        }
                        if broke { break; }
                    } else {
                        if write_half.write_all(&len_buf).await.is_err() { break; }
                        if write_half.write_all(&data).await.is_err() { break; }
                    }
                }
            });
            
            // Task to read from tcp stream to tx_in
            let tx_in_clone = tx_in.clone();
            tokio::spawn(async move {
                use tokio::io::AsyncReadExt;
                loop {
                    let mut len_buf = [0u8; 2];
                    if read_half.read_exact(&mut len_buf).await.is_err() { break; }
                    let len = u16::from_be_bytes(len_buf) as usize;
                    let mut data = vec![0u8; len];
                    if read_half.read_exact(&mut data).await.is_err() { break; }
                    if tx_in_clone.send(bytes::Bytes::from(data)).await.is_err() { break; }
                }
            });
            
            Ok(crate::transport::Transport::Uot { tx: tx_out, rx: std::sync::Arc::new(tokio::sync::Mutex::new(rx_in)) })
        } else {
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
            Ok(crate::transport::Transport::Udp(Arc::new(socket)))
        }
    }
}

fn next_profile(current: TrafficProfile) -> TrafficProfile {
    match current {
        TrafficProfile::JsonRpc => TrafficProfile::HttpsBurst,
        TrafficProfile::HttpsBurst => TrafficProfile::VideoStream,
        TrafficProfile::VideoStream => TrafficProfile::JsonRpc,
    }
}

async fn synthesize_nat64(ip: std::net::Ipv4Addr) -> std::net::Ipv6Addr {
    // Well-known prefix (RFC 6052), used if discovery doesn't answer in time.
    let mut prefix = [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0];
    // Bound the discovery lookup. This runs on exactly the networks that are
    // already misbehaving, where the resolver can hang for tens of seconds
    // before giving up — unbounded, it was a large part of why connecting over
    // a broken mobile network took minutes. Falling back to the well-known
    // prefix is strictly better than waiting.
    let discovery = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::net::lookup_host("ipv4only.arpa:80"),
    )
    .await;
    if let Ok(Ok(addrs)) = discovery {
        for addr in addrs {
            if let std::net::SocketAddr::V6(v6) = addr {
                let octets = v6.ip().octets();
                prefix.copy_from_slice(&octets[0..12]);
                break;
            }
        }
    }
    let octets = ip.octets();
    std::net::Ipv6Addr::new(
        ((prefix[0] as u16) << 8) | prefix[1] as u16,
        ((prefix[2] as u16) << 8) | prefix[3] as u16,
        ((prefix[4] as u16) << 8) | prefix[5] as u16,
        ((prefix[6] as u16) << 8) | prefix[7] as u16,
        ((prefix[8] as u16) << 8) | prefix[9] as u16,
        ((prefix[10] as u16) << 8) | prefix[11] as u16,
        ((octets[0] as u16) << 8) | octets[1] as u16,
        ((octets[2] as u16) << 8) | octets[3] as u16,
    )
}


