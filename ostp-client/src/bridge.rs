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
use crate::debug_preview::describe_foreign_bytes;
use crate::tunnel::{ProxyEvent, ProxyToClientMsg};

/// Per-address ceiling on the UoT/TCP connect attempt. Long enough that a
/// genuinely slow mobile path still completes its handshake, short enough that
/// a blackholed address (typically IPv6 advertised without a working route)
/// costs seconds instead of the kernel's full SYN-retry budget before the next
/// candidate address is tried.
const UOT_CONNECT_TIMEOUT: Duration = Duration::from_secs(4);

/// Silence after which the path is considered dead and recovery starts. Raised
/// above two keepalive intervals when those are long.
const STALL_AFTER: Duration = Duration::from_secs(10);

/// How long a moved session gets to show a sign of life on its new path.
const MIGRATION_TIMEOUT_MIN: Duration = Duration::from_secs(4);

/// Parallel sessions the multiplexer opens at most; the config value is the
/// user's, and each session is a socket, a task and a handshake in sequence.
const MAX_MUX_SESSIONS: usize = 32;

/// Minimum gap between log lines about packets that fail to authenticate.
const INBOUND_ERROR_LOG_EVERY: Duration = Duration::from_secs(5);

/// A ping answered later than this is not an RTT sample: the clock moved.
const MAX_PLAUSIBLE_RTT_MS: u64 = 60_000;

/// Ceiling on the wait for a moved session to show life, whatever the RTT.
const MIGRATION_TIMEOUT_MAX: Duration = Duration::from_secs(30);

/// Resolving the server's name must not hold the bridge loop (and with it
/// the stop button) for as long as a dead resolver likes.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(8);

/// All sockets of a move, or the move is given up for a full handshake,
/// which can be interrupted; the move itself runs on the bridge loop.
const MIGRATION_CONNECT_BUDGET: Duration = Duration::from_secs(20);

/// How long a session is kept through an outage. The server keeps an idle
/// session for 10 minutes; while ours is kept, coming back means moving it to
/// a new path with every app connection intact, instead of a new session that
/// resets them all.
const KEEP_SESSION_THROUGH_OUTAGE: Duration = Duration::from_secs(300);

/// Pause after a failed full-handshake attempt, by attempt number; the last
/// value repeats until the user stops the tunnel.
const RETRY_BACKOFF_SECS: [u64; 6] = [1, 2, 5, 10, 20, 30];

/// Outage after which the system proxy is released (proxy mode, no kill switch)
/// so the machine has internet while the tunnel keeps reconnecting.
const PROXY_RELEASE_AFTER: Duration = Duration::from_secs(45);

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

fn collect_datagrams(action: ProtocolAction, out: &mut Vec<Bytes>) {
    match action {
        ProtocolAction::SendDatagram(frame) => out.push(frame),
        ProtocolAction::Multiple(list) => {
            for item in list {
                collect_datagrams(item, out);
            }
        }
        _ => {}
    }
}

struct SessionState {
    socket: crate::transport::Transport,
    machine: ProtocolMachine,
    /// Aborted on drop: on a dead connection the task would otherwise block in
    /// recv() forever and leak itself and its socket on every reconnect.
    rx_task: tokio::task::AbortHandle,
    /// Last authenticated datagram from the server on this session.
    last_recv: Instant,
}

impl Drop for SessionState {
    fn drop(&mut self) {
        self.rx_task.abort();
    }
}

/// Build a fresh, valid handshake datagram for the TTL-desync hop probe. Each
/// call uses a new session id and timestamp so the server's anti-replay does not
/// drop it as a duplicate. Returns an empty vec on the (unexpected) construction
/// error — the probe simply treats that TTL step as unanswered.
fn build_probe_handshake(
    secrets: &ostp_core::crypto::DerivedSecrets,
    access_key: &[u8],
    profile: TrafficProfile,
    mtu: usize,
) -> Vec<u8> {
    let session_id: u32 = rand::random();
    let handshake_payload = ostp_core::build_handshake_payload(access_key, session_id);

    let mut machine = match ProtocolMachine::new(ProtocolConfig {
        psk: secrets.psk,
        session_id,
        handshake_payload,
        padding_strategy: PaddingStrategy::Profile(profile),
        obfuscation_key: secrets.obfuscation_key,
        handshake_pad_min: secrets.handshake_pad_min,
        handshake_pad_max: secrets.handshake_pad_max,
        ..ProtocolConfig::with_defaults(NoiseRole::Initiator, mtu)
    }) {
        Ok(m) => m,
        Err(_) => return Vec::new(),
    };
    match machine.on_event(OstpEvent::Start) {
        Ok(ProtocolAction::SendDatagram(frame)) => frame.to_vec(),
        _ => Vec::new(),
    }
}

/// Spawns the per-session receiver loop that forwards inbound datagrams to the
/// bridge. The returned handle lets the task be torn down with its
/// `SessionState`.
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

/// Where the tunnel is. One state, one policy: `Up` goes to `Moving` when the
/// path looks dead (the session is carried to a new socket, streams kept), and
/// to `Down` when that fails; `Down` retries a full handshake to the same
/// server over the same transport until it works or the user stops.
#[derive(Clone, Copy, PartialEq)]
enum Link {
    /// Stopped by the user.
    Idle,
    Up,
    /// Sockets are swapped; done once every session has had an authenticated
    /// datagram after `started`. `outage` is set when the move is one of the
    /// tries of an outage that is still going: (since, attempt) to go back to.
    Moving { started: Instant, outage: Option<(Instant, u32)> },
    /// No working path. The sessions are kept (see KEEP_SESSION_THROUGH_OUTAGE):
    /// a try moves them to a new path, or, with `handshake_next`, does a full
    /// handshake to learn whether the server answers at all.
    Down { since: Instant, attempt: u32, next_try: Instant, handshake_next: bool },
}

/// Sessions that finished their handshake, not yet installed.
struct Established {
    sessions: Vec<SessionState>,
    udp_rx: mpsc::Receiver<(usize, Bytes)>,
    rtt_ms: f64,
}

/// What cut a connection attempt short.
enum Interrupt {
    NetworkChanged,
    Command(Option<BridgeCommand>),
    Shutdown,
}

pub struct Bridge {
    profile: TrafficProfile,
    server_addr: String,
    local_bind_addr: String,
    proxy_addr: String,
    access_key: Bytes,
    handshake_timeout_ms: u64,
    io_timeout_ms: u64,
    pub debug: bool,

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
    pub ttl_desync_auto: bool,
    pub tls: bool,
    pub tls_sni: Option<String>,
    pub tls_insecure: bool,
    pub ws_path: Option<String>,
    /// Hop-distance measurement for TTL-desync, cached so the sweep does not run
    /// on every (re)connect; cleared when the network changes.
    ttl_desync_measured: Option<u8>,
    pub mtu: usize,
    pub kill_switch: bool,
    pub reload_tx: Option<watch::Sender<crate::config::ExclusionConfig>>,

    metrics: Arc<BridgeMetrics>,
    sample_sent: u64,
    sample_recv: u64,
    last_rtt_ms: f64,
    last_sample_at: Instant,

    last_inbound_error_log: Option<Instant>,
    /// New sessions from a handshake that got through during an outage, held
    /// while the kept session is moved: if it answers they are closed and no
    /// app connection is lost, otherwise they replace it.
    standby: Option<Established>,

    link: Link,
    sessions: Vec<SessionState>,
    udp_rx: Option<mpsc::Receiver<(usize, Bytes)>>,
    stream_map: std::collections::HashMap<u16, usize>,
    proxy_guard: Option<crate::sysproxy::SystemProxyGuard>,
    /// Whether this run has been connected before, to word the logs and to
    /// clear stale proxy events only on a reconnect.
    established_once: bool,
}

impl Bridge {
    pub fn new(config: &ClientConfig, metrics: Arc<BridgeMetrics>) -> Result<Self> {
        Ok(Self {
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
            mux_sessions: config.multiplex.sessions.clamp(1, MAX_MUX_SESSIONS),

            transport_mode: config.transport.mode.clone(),
            tcp_fragmentation: config.transport.tcp_fragmentation,
            frag_chunk: config.transport.frag_chunk,
            frag_sleep: config.transport.frag_sleep,
            junk_pc: config.transport.junk_pc,
            junk_ps: config.transport.junk_ps,
            ttl_desync: config.transport.ttl_desync,
            ttl_desync_ttl: config.transport.ttl_desync_ttl,
            ttl_desync_count: config.transport.ttl_desync_count,
            ttl_desync_auto: config.transport.ttl_desync_auto,
            tls: config.transport.tls,
            tls_sni: config.transport.tls_sni.clone(),
            tls_insecure: config.transport.tls_insecure,
            ws_path: config.transport.ws_path.clone(),
            ttl_desync_measured: None,
            mtu: config.ostp.mtu,
            kill_switch: config.kill_switch,
            reload_tx: None,

            metrics,
            sample_sent: 0,
            sample_recv: 0,
            last_rtt_ms: 0.0,
            last_sample_at: Instant::now(),

            last_inbound_error_log: None,
            standby: None,

            link: Link::Idle,
            sessions: Vec::new(),
            udp_rx: None,
            stream_map: std::collections::HashMap::new(),
            proxy_guard: None,
            established_once: false,
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
        let mut keepalive_tick = interval(Duration::from_secs(self.keepalive_interval_sec.clamp(1, 3600)));
        let mut retransmit_tick = interval(Duration::from_millis(10));
        // The default `Burst` replays every tick missed during a suspend, which
        // for the 10 ms retransmit tick is a CPU storm right after waking.
        metrics_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        keepalive_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        retransmit_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

        // tokio's clock does not advance while the machine sleeps on Windows,
        // so a suspend is only visible as a jump of the wall clock.
        let mut last_wall_check = SystemTime::now();
        let init_msg = if self.mode == "tun" {
            "Bridge initialized (TUN mode)".to_string()
        } else {
            "Bridge initialized (proxy mode)".to_string()
        };
        tx.send(UiEvent::Log(init_msg)).await.ok();

        loop {
            // Upload is held back when the window has room but the pacing
            // bucket is empty this instant; wake exactly when it refills.
            let pace_wait = self
                .sessions
                .iter()
                .filter(|ses| ses.machine.in_flight_count() < ses.machine.cwnd_packets() && !ses.machine.can_pace_packet())
                .map(|ses| ses.machine.time_to_pace())
                .min();
            let next_try = match self.link {
                Link::Down { next_try, .. } => Some(next_try),
                _ => None,
            };
            tokio::select! {
                biased;
                _ = tokio::time::sleep(pace_wait.unwrap_or_default()), if pace_wait.is_some() => {}
                changed = shutdown.changed() => {
                    // A dropped sender is a shutdown too: `changed()` would
                    // otherwise return an error at once, on every pass.
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                udp_msg = async {
                    match self.udp_rx.as_mut() {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                }, if self.udp_rx.is_some() => {
                    self.handle_inbound_udp(udp_msg, &tx, &proxy_tx).await;
                }
                cmd = bridge_rx.recv() => {
                    if !self.handle_bridge_cmd(cmd, &mut bridge_rx, &tx, &proxy_tx).await {
                        break;
                    }
                }
                _ = tokio::time::sleep_until(next_try.unwrap_or_else(Instant::now)), if next_try.is_some() => {
                    if !self.reconnect_attempt(&mut bridge_rx, &mut shutdown, &tx, &proxy_tx, &mut proxy_rx).await {
                        break;
                    }
                }
                _ = metrics_tick.tick() => {
                    let wall_gap = last_wall_check.elapsed().unwrap_or_default();
                    last_wall_check = SystemTime::now();
                    if wall_gap > Duration::from_secs(15) && self.link != Link::Idle {
                        let _ = tx.send(UiEvent::Log(format!(
                            "Resumed after ~{}s suspend", wall_gap.as_secs()
                        ))).await;
                        self.recover_now("Resumed after suspend", &tx, &proxy_tx).await;
                    }
                    self.check_link(&tx, &proxy_tx).await;
                    if self.link != Link::Idle {
                        self.emit_metrics(&tx).await;
                    }
                }
                _ = keepalive_tick.tick() => {
                    self.send_keepalives().await;
                }
                _ = retransmit_tick.tick() => {
                    self.handle_retransmit(&tx, &proxy_tx).await;
                }
                proxy_ev = proxy_rx.recv(), if self.link != Link::Idle && (self.sessions.is_empty() || self.sessions.iter().any(|ses| {
                    // Two independent gates. cwnd bounds how much may be in
                    // flight (the controller caps it at MAX_CWND_PACKETS);
                    // pacing bounds how FAST it is released. Without the
                    // second, a full window goes out back-to-back and lands in
                    // the bottleneck's buffer as standing queue rather than
                    // throughput. The `pace_wait` branch wakes the loop when
                    // pacing allows the next packet.
                    ses.machine.in_flight_count() < ses.machine.cwnd_packets()
                        && ses.machine.can_pace_packet()
                })) => {
                    self.handle_proxy_event(proxy_ev, &tx, &proxy_tx).await;
                }
            }
        }

        self.close_sessions().await;
        self.reset_proxy_streams(&tx, &proxy_tx, "bridge stopped");
        tx.send(UiEvent::Log("Bridge stopped".to_string())).await.ok();
        Ok(())
    }

    async fn handle_inbound_udp(
        &mut self,
        udp_msg: Option<(usize, Bytes)>,
        tx: &mpsc::Sender<UiEvent>,
        proxy_tx: &mpsc::UnboundedSender<(u16, ProxyToClientMsg)>,
    ) {
        let Some((session_index, inbound)) = udp_msg else {
            // Every receiver ended: with UoT the TCP connections were closed or
            // reset (a DPI reset included).
            self.udp_rx = None;
            match self.link {
                Link::Up => self.recover_now("Connection to the server closed", tx, proxy_tx).await,
                Link::Moving { .. } => self.begin_reconnect("The new connection closed", true, tx, proxy_tx).await,
                Link::Idle | Link::Down { .. } => {}
            }
            return;
        };

        self.metrics.bytes_recv.fetch_add(inbound.len() as u64, Ordering::Relaxed);
        let Some(session) = self.sessions.get_mut(session_index) else { return };
        let authenticated_before = session.machine.authenticated_recv_count();
        let initial_action = match session.machine.on_event(OstpEvent::Inbound(inbound)) {
            Ok(a) => a,
            Err(e) => {
                // Anyone who can send to this socket can make this happen once
                // per packet; one line every few seconds is enough to see it,
                // and a full UI channel must not hold the loop for each one.
                if self.last_inbound_error_log.map_or(true, |t| t.elapsed() >= INBOUND_ERROR_LOG_EVERY) {
                    self.last_inbound_error_log = Some(Instant::now());
                    let _ = tx.send(UiEvent::Log(format!("Protocol decrypt error: {e}"))).await;
                    tracing::warn!("Inbound protocol error (session {}): {}", session_index, e);
                } else {
                    tracing::trace!("Inbound protocol error (session {}): {}", session_index, e);
                }
                return;
            }
        };

        // Only a datagram that authenticated and decrypted proves the server is
        // there: `on_event` also returns Ok for duplicates and for datagrams
        // outside the window. Counting anything else lets frames from an evicted
        // session, stale retransmits or an off-path sender keep a dead tunnel
        // looking alive. This is also what confirms a session move.
        if session.machine.authenticated_recv_count() != authenticated_before {
            session.last_recv = Instant::now();
        }

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
                                    let now = SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
                                    // The ping carries the wall clock, so a clock step
                                    // between ping and pong reads as an RTT of hours
                                    // (and stretches the move deadline with it).
                                    let rtt = now.saturating_sub(ts);
                                    if rtt <= MAX_PLAUSIBLE_RTT_MS {
                                        self.last_rtt_ms = rtt as f64;
                                        self.metrics.rtt_ms.store(rtt as u32, Ordering::Relaxed);
                                    }
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
                    let _ = send_datagram(&session.socket, &frame, false).await;
                    self.metrics.bytes_sent.fetch_add(frame.len() as u64, Ordering::Relaxed);
                }
                _ => {}
            }
        }
    }

    /// Returns false when the bridge should stop.
    async fn handle_bridge_cmd(
        &mut self,
        cmd: Option<BridgeCommand>,
        bridge_rx: &mut mpsc::Receiver<BridgeCommand>,
        tx: &mpsc::Sender<UiEvent>,
        proxy_tx: &mpsc::UnboundedSender<(u16, ProxyToClientMsg)>,
    ) -> bool {
        match cmd {
            Some(BridgeCommand::ToggleTunnel) => {
                if self.link != Link::Idle {
                    self.close_sessions().await;
                    self.reset_proxy_streams(tx, proxy_tx, "manual stop");
                    tx.send(UiEvent::TunnelStopped).await.ok();
                    let stop_msg = if self.mode == "tun" { "TUN tunnel stopped" } else { "Bridge stopped" };
                    tx.send(UiEvent::Log(stop_msg.to_string())).await.ok();
                } else {
                    tx.send(UiEvent::Log("Connecting to remote server...".to_string())).await.ok();
                    tx.send(UiEvent::Metrics { status: ConnectionStatus::Handshaking, rtt_ms: 0.0, throughput_bps: 0 }).await.ok();
                    self.metrics.connection_state.store(1, Ordering::Relaxed);
                    self.last_sample_at = Instant::now();
                    let now = Instant::now();
                    self.link = Link::Down { since: now, attempt: 0, next_try: now, handshake_next: true };
                }
            }
            Some(BridgeCommand::NextProfile) => {
                self.profile = next_profile(self.profile);
                tx.send(UiEvent::ProfileChanged(self.profile)).await.ok();
                tx.send(UiEvent::Log(format!("Obfuscation profile switched to {:?}", self.profile))).await.ok();
            }
            Some(BridgeCommand::NetworkChanged) => {
                // A handoff often fires several of these within milliseconds;
                // one recovery on the freshest signal is enough. Another command
                // found while draining is handled right away, not dropped.
                while let Ok(next) = bridge_rx.try_recv() {
                    if !matches!(next, BridgeCommand::NetworkChanged) {
                        let keep_going = Box::pin(self.handle_bridge_cmd(Some(next), bridge_rx, tx, proxy_tx)).await;
                        if !keep_going {
                            return false;
                        }
                        break;
                    }
                }
                self.recover_now("Network changed", tx, proxy_tx).await;
            }
            Some(BridgeCommand::ReloadConfig) => {
                match ClientConfig::reload_from_json_near_binary() {
                    Ok(cfg) => {
                        let old_server = self.server_addr.clone();
                        let old_mode = self.mode.clone();
                        let old_transport = self.transport_mode.clone();
                        let old_carrier = (self.tls, self.tls_sni.clone(), self.tls_insecure, self.ws_path.clone());

                        self.apply_runtime_config(&cfg);

                        let requires_restart = self.server_addr != old_server ||
                                               self.mode != old_mode ||
                                               self.transport_mode != old_transport ||
                                               (self.tls, self.tls_sni.clone(), self.tls_insecure, self.ws_path.clone()) != old_carrier;

                        if !requires_restart {
                            if let Some(tx_watch) = &self.reload_tx {
                                let _ = tx_watch.send(cfg.exclusions.clone());
                            }
                            tx.send(UiEvent::Log("Exclusions updated in real-time (hot reload)".to_string())).await.ok();
                        } else {
                            tx.send(UiEvent::Log("Runtime config reloaded. Reconnecting with the new settings.".to_string())).await.ok();
                            if self.link != Link::Idle {
                                self.begin_reconnect("Settings changed", false, tx, proxy_tx).await;
                            }
                        }
                    }
                    Err(err) => {
                        let _ = tx.send(UiEvent::Log(format!("Config reload failed: {err}"))).await;
                    }
                }
            }
            Some(BridgeCommand::Shutdown) | None => return false,
        }
        true
    }

    /// Ends the tunnel: tells the server to free the sessions (so reconnects do
    /// not pile up as live sessions of this user until its idle timeout), drops
    /// everything and releases the system proxy. Bounded, so a dead TCP path
    /// cannot hold up the stop.
    async fn close_sessions(&mut self) {
        for session in self.sessions.iter_mut() {
            if let Ok(ProtocolAction::SendDatagram(frame)) = session.machine.on_event(OstpEvent::Close) {
                let send = send_datagram(&session.socket, &frame, false);
                let _ = tokio::time::timeout(Duration::from_millis(300), send).await;
            }
        }
        self.sessions.clear();
        self.standby = None;
        self.udp_rx = None;
        self.stream_map.clear();
        self.proxy_guard = None;
        self.link = Link::Idle;
        self.established_once = false;
        self.metrics.connection_state.store(0, Ordering::Relaxed);
    }

    /// Longest silence a healthy path may show. Pings go out on every keepalive
    /// tick and are answered within an RTT, so two ticks of silence mean the
    /// path is gone or blocked.
    fn stall_after(&self) -> Duration {
        STALL_AFTER.max(Duration::from_secs(self.keepalive_interval_sec.clamp(1, 3600) * 2))
    }

    /// Silence of the quietest session. A session that stopped answering must
    /// not be hidden by one that still does: streams are spread across all.
    fn silence(&self) -> Duration {
        self.sessions.iter().map(|s| s.last_recv.elapsed()).max().unwrap_or_default()
    }

    /// The one place that notices a bad link: a stalled path, a move that got
    /// no answer, a long outage.
    async fn check_link(
        &mut self,
        tx: &mpsc::Sender<UiEvent>,
        proxy_tx: &mpsc::UnboundedSender<(u16, ProxyToClientMsg)>,
    ) {
        match self.link {
            Link::Up => {
                let silence = self.silence();
                if silence > self.stall_after() {
                    let reason = format!("No answer from the server for {}s", silence.as_secs());
                    self.recover_now(&reason, tx, proxy_tx).await;
                }
            }
            Link::Moving { started, outage } => {
                if self.sessions.iter().all(|s| s.last_recv >= started) {
                    if let Some(mut standby) = self.standby.take() {
                        // Not needed after all: free them on the server now
                        // rather than at its idle timeout.
                        for session in standby.sessions.iter_mut() {
                            if let Ok(ProtocolAction::SendDatagram(frame)) = session.machine.on_event(OstpEvent::Close) {
                                let _ = send_datagram(&session.socket, &frame, false).await;
                            }
                        }
                    }
                    self.link = Link::Up;
                    self.metrics.connection_state.store(2, Ordering::Relaxed);
                    let msg = match outage {
                        Some((since, _)) => format!(
                            "Connection restored after {} s, no connection was dropped",
                            since.elapsed().as_secs()
                        ),
                        None => format!(
                            "Session moved to the new path in {} ms, no connection was dropped",
                            started.elapsed().as_millis()
                        ),
                    };
                    tx.send(UiEvent::Log(msg)).await.ok();
                    return;
                }
                let deadline = MIGRATION_TIMEOUT_MIN
                    .max(Duration::from_millis((self.last_rtt_ms * 4.0) as u64))
                    .min(MIGRATION_TIMEOUT_MAX);
                if started.elapsed() >= deadline {
                    // The server stays silent to unknown sessions on purpose, so
                    // "session expired" and "path blocked" look the same here.
                    // A full handshake tells them apart: it gets through only
                    // when the server is reachable.
                    if let Some(standby) = self.standby.take() {
                        self.install_sessions(standby, tx, proxy_tx, None).await;
                        return;
                    }
                    if let Some((since, attempt)) = outage {
                        self.link = Link::Down { since, attempt, next_try: Instant::now(), handshake_next: true };
                        return;
                    }
                    let reason = format!(
                        "The server did not answer on the new path within {} s (session expired, or this \
                         transport is blocked on this network)",
                        deadline.as_secs()
                    );
                    self.begin_reconnect(&reason, true, tx, proxy_tx).await;
                }
            }
            Link::Down { since, .. } => {
                // The old path came back by itself and the kept session answered.
                if !self.sessions.is_empty() && self.sessions.iter().all(|s| s.last_recv >= since) {
                    self.link = Link::Up;
                    self.metrics.connection_state.store(2, Ordering::Relaxed);
                    tx.send(UiEvent::Log(format!(
                        "Connection restored after {} s, no connection was dropped",
                        since.elapsed().as_secs()
                    ))).await.ok();
                    return;
                }
                // The system proxy points at our listener, which cannot carry
                // anything now: without a kill switch give the machine its own
                // internet back while we keep retrying.
                if self.proxy_guard.is_some() && !self.kill_switch && since.elapsed() >= PROXY_RELEASE_AFTER {
                    self.proxy_guard = None;
                    tx.send(UiEvent::Log(format!(
                        "No connection for {}s: released the system proxy, still reconnecting",
                        since.elapsed().as_secs()
                    ))).await.ok();
                }
            }
            Link::Idle => {}
        }
    }

    /// Recovery, step one: carry the session to a new socket (no handshake,
    /// apps keep their connections). If no socket can be opened at all, step two
    /// right away. A recovery already in progress is replaced or sped up.
    async fn recover_now(
        &mut self,
        reason: &str,
        tx: &mpsc::Sender<UiEvent>,
        proxy_tx: &mpsc::UnboundedSender<(u16, ProxyToClientMsg)>,
    ) {
        // The hop count to the server may differ on the new network.
        self.ttl_desync_measured = None;
        match self.link {
            Link::Idle => {}
            Link::Down { since, attempt, .. } => {
                self.link = Link::Down { since, attempt, next_try: Instant::now(), handshake_next: false };
            }
            Link::Up | Link::Moving { .. } => {
                if !self.try_migrate(reason, tx).await {
                    self.begin_reconnect(reason, true, tx, proxy_tx).await;
                }
            }
        }
    }

    /// Recovery, step two: no path works. With `keep_session` (the path was
    /// lost) the sessions and their app connections are kept, and the tries
    /// alternate between moving them and a full handshake; without it (new
    /// settings, a protocol error) they are dropped now.
    async fn begin_reconnect(
        &mut self,
        reason: &str,
        keep_session: bool,
        tx: &mpsc::Sender<UiEvent>,
        proxy_tx: &mpsc::UnboundedSender<(u16, ProxyToClientMsg)>,
    ) {
        if !keep_session {
            self.drop_sessions(tx, proxy_tx);
        }
        let now = Instant::now();
        match self.link {
            Link::Idle => return,
            Link::Down { since, attempt, .. } => {
                self.link = Link::Down { since, attempt, next_try: now, handshake_next: true };
                return;
            }
            Link::Up | Link::Moving { .. } => {}
        }
        tx.send(UiEvent::Log(format!("{reason}: reconnecting to the server"))).await.ok();
        self.metrics.connection_state.store(1, Ordering::Relaxed);
        self.link = Link::Down { since: now, attempt: 0, next_try: now, handshake_next: true };
    }

    /// The sessions cannot continue: their app connections are reset.
    fn drop_sessions(
        &mut self,
        tx: &mpsc::Sender<UiEvent>,
        proxy_tx: &mpsc::UnboundedSender<(u16, ProxyToClientMsg)>,
    ) {
        self.standby = None;
        if self.sessions.is_empty() {
            return;
        }
        self.sessions.clear();
        self.udp_rx = None;
        self.stream_map.clear();
        self.reset_proxy_streams(tx, proxy_tx, "reconnect");
    }

    /// One full-handshake attempt while `Down`. Stays responsive: a stop,
    /// shutdown or settings change cancels it, a network change restarts it.
    /// Returns false when the bridge should stop.
    async fn reconnect_attempt(
        &mut self,
        bridge_rx: &mut mpsc::Receiver<BridgeCommand>,
        shutdown: &mut watch::Receiver<bool>,
        tx: &mpsc::Sender<UiEvent>,
        proxy_tx: &mpsc::UnboundedSender<(u16, ProxyToClientMsg)>,
        proxy_rx: &mut mpsc::Receiver<ProxyEvent>,
    ) -> bool {
        let Link::Down { since, attempt, handshake_next, .. } = self.link else { return true };
        refresh_routes(tx).await;

        if !self.sessions.is_empty() && since.elapsed() >= KEEP_SESSION_THROUGH_OUTAGE {
            tx.send(UiEvent::Log(format!(
                "No connection for {} s: giving up the old session",
                since.elapsed().as_secs()
            ))).await.ok();
            self.drop_sessions(tx, proxy_tx);
        }
        // Cheap and keeps every app connection: try it before a handshake.
        if !handshake_next && !self.sessions.is_empty() {
            match self.start_migration(tx).await {
                Ok(()) => {
                    self.link = Link::Moving { started: Instant::now(), outage: Some((since, attempt)) };
                    return true;
                }
                Err(e) => {
                    tx.send(UiEvent::Log(format!("Could not move the session: {e}"))).await.ok();
                }
            }
        }

        let outcome = {
            let establish = self.establish_sessions(tx);
            tokio::pin!(establish);
            loop {
                tokio::select! {
                    result = &mut establish => break Ok(result),
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            break Err(Interrupt::Shutdown);
                        }
                    }
                    cmd = bridge_rx.recv() => {
                        break Err(match cmd {
                            Some(BridgeCommand::NetworkChanged) => Interrupt::NetworkChanged,
                            other => Interrupt::Command(other),
                        });
                    }
                }
            }
        };

        match outcome {
            Err(Interrupt::Shutdown) => false,
            Err(Interrupt::NetworkChanged) => {
                self.ttl_desync_measured = None;
                self.link = Link::Down { since, attempt, next_try: Instant::now(), handshake_next: false };
                true
            }
            Err(Interrupt::Command(cmd)) => self.handle_bridge_cmd(cmd, bridge_rx, tx, proxy_tx).await,
            Ok(Ok(established)) => {
                // The server answers again. The kept session may still be
                // alive there: moving it keeps every app connection.
                if !self.sessions.is_empty() && self.start_migration(tx).await.is_ok() {
                    self.standby = Some(established);
                    self.link = Link::Moving { started: Instant::now(), outage: Some((since, attempt)) };
                    return true;
                }
                self.install_sessions(established, tx, proxy_tx, Some(proxy_rx)).await;
                true
            }
            Ok(Err(err)) => {
                if attempt == 0 && self.transport_mode == "udp" {
                    tx.send(UiEvent::Log(udp_failure_diagnosis(&self.server_addr).await)).await.ok();
                }
                // A first connection that fails is most often a wrong key,
                // address or transport: retrying would not fix it, so stop and
                // let the user decide. Only a link that once worked is retried.
                if !self.established_once {
                    tx.send(UiEvent::Log(format!("Connection failed: {err}"))).await.ok();
                    self.close_sessions().await;
                    self.reset_proxy_streams(tx, proxy_tx, "connection failed");
                    tx.send(UiEvent::TunnelStopped).await.ok();
                    return true;
                }
                let wait = RETRY_BACKOFF_SECS[(attempt as usize).min(RETRY_BACKOFF_SECS.len() - 1)];
                tx.send(UiEvent::Log(format!(
                    "Reconnect attempt {} failed: {err}. Next try in {wait}s", attempt + 1
                ))).await.ok();
                // The server did not answer a handshake: the network is down,
                // so the kept session may still be moved when it comes back.
                self.link = Link::Down {
                    since,
                    attempt: attempt + 1,
                    next_try: Instant::now() + Duration::from_secs(wait),
                    handshake_next: false,
                };
                true
            }
        }
    }

    /// Handshakes every mux session; the single place sessions are created.
    /// Fails only when not one session got through.
    async fn establish_sessions(&mut self, tx: &mpsc::Sender<UiEvent>) -> Result<Established> {
        let count = if self.mux_enabled { self.mux_sessions.max(1) } else { 1 };
        let (udp_tx, udp_rx) = mpsc::channel(1024);
        let mut sessions: Vec<SessionState> = Vec::with_capacity(count);
        let mut rtt_sum = 0.0;

        for idx in 0..count {
            let session_id: u32 = rand::thread_rng().gen();
            match self.perform_handshake_with_id(tx, session_id).await {
                Ok((socket, machine, rtt)) => {
                    let rx_task = spawn_session_receiver(socket.clone(), sessions.len(), udp_tx.clone());
                    sessions.push(SessionState { socket, machine, rx_task, last_recv: Instant::now() });
                    rtt_sum += rtt;
                }
                // All sessions use the same server and path: when none has got
                // through yet, the rest would only fail the same way.
                Err(err) if sessions.is_empty() => return Err(err),
                Err(err) => {
                    tx.send(UiEvent::Log(format!(
                        "Multiplex session {}/{} handshake failed: {err}. Continuing with the others", idx + 1, count
                    ))).await.ok();
                }
            }
        }
        let rtt_ms = rtt_sum / sessions.len() as f64;
        Ok(Established { sessions, udp_rx, rtt_ms })
    }

    async fn install_sessions(
        &mut self,
        established: Established,
        tx: &mpsc::Sender<UiEvent>,
        proxy_tx: &mpsc::UnboundedSender<(u16, ProxyToClientMsg)>,
        proxy_rx: Option<&mut mpsc::Receiver<ProxyEvent>>,
    ) {
        self.standby = None;
        self.sessions = established.sessions;
        self.udp_rx = Some(established.udp_rx);
        self.last_rtt_ms = established.rtt_ms;
        self.link = Link::Up;
        self.last_sample_at = Instant::now();
        self.stream_map.clear();

        if self.established_once {
            // Streams of the lost session are gone, and so are the requests
            // queued for it while the attempt blocked the loop.
            self.reset_proxy_streams(tx, proxy_tx, "reconnect");
            if let Some(proxy_rx) = proxy_rx {
                while let Ok(stale) = proxy_rx.try_recv() {
                    if let ProxyEvent::NewStream { stream_id, .. } = stale {
                        let _ = proxy_tx.send((stream_id, ProxyToClientMsg::Error("connection reset".into())));
                    }
                }
            }
        }
        self.established_once = true;

        // The system proxy is for proxy mode; in TUN mode the TUN device
        // carries the traffic and setting it too hides a TUN that never came up.
        if self.mode != "tun" && self.proxy_guard.is_none() {
            let sys_proxy_addr = self.proxy_addr.replace("0.0.0.0:", "127.0.0.1:");
            self.proxy_guard = Some(crate::sysproxy::SystemProxyGuard::enable(&sys_proxy_addr));
            // Enabling resets the bypass list; put the exclusions back.
            if let Some(reload) = &self.reload_tx {
                let ex = reload.borrow();
                crate::sysproxy::update_proxy_bypass_list(&ex.domains, &ex.ips);
            }
        }

        tx.send(UiEvent::Metrics {
            status: ConnectionStatus::Established,
            rtt_ms: self.last_rtt_ms,
            throughput_bps: 0,
        }).await.ok();
        self.metrics.connection_state.store(2, Ordering::Relaxed);
        tx.send(UiEvent::Log("Connection established".to_string())).await.ok();
        self.send_keepalives().await;
    }

    /// A ping and a keepalive per session. The ping's answer is the liveness
    /// signal the stall detection relies on.
    async fn send_keepalives(&mut self) {
        for session in self.sessions.iter_mut() {
            let ts = SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
            for msg in [RelayMessage::Ping(ts), RelayMessage::KeepAlive] {
                let payload = Bytes::from(msg.encode());
                if let Ok(ProtocolAction::SendDatagram(frame)) = session.machine.on_event(OstpEvent::Outbound(0, payload)) {
                    let _ = send_datagram(&session.socket, &frame, false).await;
                    self.metrics.bytes_sent.fetch_add(frame.len() as u64, Ordering::Relaxed);
                }
            }
        }
    }

    async fn handle_retransmit(
        &mut self,
        tx: &mpsc::Sender<UiEvent>,
        proxy_tx: &mpsc::UnboundedSender<(u16, ProxyToClientMsg)>,
    ) {
        let mut fatal_err = None;
        for session in self.sessions.iter_mut() {
            match session.machine.on_event(OstpEvent::Tick) {
                Ok(action) => {
                    let mut frames = Vec::new();
                    collect_datagrams(action, &mut frames);
                    for frame in frames {
                        let _ = send_datagram(&session.socket, &frame, false).await;
                        self.metrics.bytes_sent.fetch_add(frame.len() as u64, Ordering::Relaxed);
                    }
                }
                Err(e) => {
                    fatal_err = Some(e);
                    break;
                }
            }
        }

        if let Some(e) = fatal_err {
            let _ = tx.send(UiEvent::Log(format!("Protocol tick fatal error: {e}"))).await;
            self.begin_reconnect("Protocol error", false, tx, proxy_tx).await;
        }
    }


    async fn handle_proxy_event(
        &mut self,
        proxy_ev: Option<ProxyEvent>,
        tx: &mpsc::Sender<UiEvent>,
        proxy_tx: &mpsc::UnboundedSender<(u16, ProxyToClientMsg)>,
    ) {
        let Some(ev) = proxy_ev else { return };
        // No session while reconnecting: fail new streams at once so the apps
        // retry instead of waiting on a tunnel that cannot carry them.
        if self.sessions.is_empty() {
            if let ProxyEvent::NewStream { stream_id, .. } = ev {
                let _ = proxy_tx.send((stream_id, ProxyToClientMsg::Error("reconnecting".into())));
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
        let len = self.sessions.len();
        let session_index = *self.stream_map.entry(stream_id).or_insert_with(|| {
            rand::thread_rng().gen_range(0..len)
        });
        if is_close {
            self.stream_map.remove(&stream_id);
        }
        let session = &mut self.sessions[session_index];
        // Stream data goes out in datagrams that fit the MTU: reads from
        // local apps are up to 64 KiB, which as one datagram was a burst of
        // IP fragments over UDP and, past 65535 bytes, a truncated payload
        // and a broken length prefix over TCP and TLS.
        let messages: Vec<RelayMessage> = match relay_msg {
            RelayMessage::Data(data) => ostp_core::relay::data_chunks(&data, session.machine.max_payload())
                .map(|c| RelayMessage::Data(c.to_vec()))
                .collect(),
            other => vec![other],
        };
        for relay_msg in messages {
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

        // "Connected" means the server answered recently, not that sockets exist.
        let is_healthy = self.link == Link::Up && self.silence() <= self.stall_after();
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
        let handshake_payload = ostp_core::build_handshake_payload(&self.access_key, session_id);

        let secrets = ostp_core::crypto::derive_all_secrets(&self.access_key);

        let mut resolved_addrs: Vec<std::net::SocketAddr> = match timeout(RESOLVE_TIMEOUT, tokio::net::lookup_host(&self.server_addr)).await {
            Ok(Ok(addrs)) => addrs.collect(),
            Ok(Err(e)) => return Err(anyhow::anyhow!("failed to resolve server address {}: {}", self.server_addr, e)),
            Err(_) => return Err(anyhow::anyhow!("resolving server address {} timed out", self.server_addr)),
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

            let socket = match self.try_connect_transport(target_ip, port, tx).await {
                Ok(sock) => sock,
                Err(e) => {
                    if let (std::net::IpAddr::V4(ipv4), false) = (target_ip, nat64_attempted) {
                        nat64_attempted = true;
                        tx.send(UiEvent::Log(format!("Direct IPv4 connection failed: {}. Trying NAT64 fallback...", e))).await.ok();
                        let nat64_ipv6 = synthesize_nat64(ipv4).await;
                        match self.try_connect_transport(std::net::IpAddr::V6(nat64_ipv6), port, tx).await {
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
                psk: secrets.psk,
                session_id,
                handshake_payload: handshake_payload.clone(),
                padding_strategy: PaddingStrategy::Profile(self.profile),
                obfuscation_key: secrets.obfuscation_key,
                handshake_pad_min: secrets.handshake_pad_min,
                handshake_pad_max: secrets.handshake_pad_max,
                ..ProtocolConfig::with_defaults(NoiseRole::Initiator, self.mtu)
            })?;
            // UoT and TLS ride TCP: no timer-driven resends (TCP over TCP).
            machine.set_reliable_carrier(self.transport_mode != "udp");

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
            // UDP: more, shorter retransmit windows over the SAME total budget
            // (6×800ms ≈ the old 4×1200ms), so a lost handshake on a mobile link
            // recovers faster and there are more chances before giving up.
            let (attempt_limit, attempt_timeout_ms) = if is_uot { (1, 8000) } else { (6, 800) };

            // TTL-desync (UDP only, opt-in): fire decoy datagrams that reach an
            // on-path DPI box but expire before the server, so the box classifies
            // the flow on the decoys rather than the real handshake that follows.
            // Each carries the key's junk marker, so any decoy that does reach
            // the server is dropped there silently.
            if self.ttl_desync && !is_uot && self.ttl_desync_count > 0 {
                // Auto-calibrate the decoy TTL to the hop distance to this server,
                // measured once (cached). The server answers only a valid
                // handshake, so the sweep is inherently key-gated and needs no
                // server-side probe endpoint. On measurement failure we fall back
                // to the configured fixed TTL rather than skipping desync.
                let effective_ttl = if self.ttl_desync_auto {
                    if self.ttl_desync_measured.is_none() {
                        let sec = secrets.clone();
                        let key = self.access_key.clone();
                        let profile = self.profile;
                        let mtu = self.mtu;
                        let make_hs = move || build_probe_handshake(&sec, &key, profile, mtu);
                        if let Some(hops) = crate::ttl_probe::measure_hops(target_addr, make_hs).await {
                            let t = crate::ttl_probe::decoy_ttl_for(hops);
                            self.ttl_desync_measured = Some(t);
                            tx.send(UiEvent::Log(format!(
                                "TTL-desync: server ~{hops} hops, decoy TTL {t}"
                            ))).await.ok();
                        }
                    }
                    self.ttl_desync_measured.unwrap_or(self.ttl_desync_ttl)
                } else {
                    self.ttl_desync_ttl
                };

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
                socket.send_ttl_decoys(&decoys, effective_ttl).await;
            }

            for attempt in 0..attempt_limit {
                if attempt > 0 {
                    tx.send(UiEvent::Log(format!("Handshake attempt {} lost. Retransmitting...", attempt))).await.ok();
                }
                // Send the handshake twice on UDP: a single dropped datagram
                // otherwise costs a whole retransmit window, which on a lossy
                // mobile link is the gap between a sub-second connect and a
                // multi-second one. The duplicate is harmless — whichever copy
                // arrives first is processed, and the server's anti-replay drops
                // the other. UoT rides reliable TCP, so one send there.
                let sends = if is_uot { 1 } else { 2 };
                for _ in 0..sends {
                    if send_datagram(&socket, &handshake_frame, self.transport_mode == "udp").await.is_ok() {
                        self.metrics.bytes_sent.fetch_add(handshake_frame.len() as u64, Ordering::Relaxed);
                    }
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
                    match self.try_connect_transport(std::net::IpAddr::V6(nat64_ipv6), port, tx).await {
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
                // A frame that reaches here and still fails to validate (bad
                // session id, truncated noise payload, ...) did not come from
                // the real ostp server responding to our handshake — the real
                // server always echoes our session id. Surface the raw bytes
                // only in debug mode, and only on this failure path: a
                // successfully-validated handshake response is genuine server
                // traffic and is never dumped.
                if self.debug {
                    tx.send(UiEvent::Log(format!(
                        "[debug] handshake response failed validation ({}) — does not look \
                         like an ostp server reply, possible operator/DPI interference: {}",
                        e,
                        describe_foreign_bytes(&buf[..size])
                    ))).await.ok();
                }
                last_err = anyhow::anyhow!("Protocol invalid response: {}", e);
                continue;
            }
            let rtt_ms = start.elapsed().as_secs_f64() * 1000.0;
            tracing::info!("Handshake complete: session={:#010x} rtt={:.1}ms", session_id, rtt_ms);

            return Ok((socket, machine, rtt_ms));
        }

        Err(last_err)
    }

    /// Opens a connection to the server over the configured transport,
    /// trying the resolved addresses IPv4-first and NAT64 once, as the
    /// handshake path does.
    async fn connect_server(&self, tx: &mpsc::Sender<UiEvent>) -> Result<crate::transport::Transport> {
        let mut addrs: Vec<std::net::SocketAddr> = timeout(RESOLVE_TIMEOUT, tokio::net::lookup_host(&self.server_addr))
            .await
            .map_err(|_| anyhow::anyhow!("resolving server address {} timed out", self.server_addr))?
            .with_context(|| format!("failed to resolve server address {}", self.server_addr))?
            .collect();
        addrs.sort_by_key(|addr| addr.is_ipv6());

        let mut last_err = anyhow::anyhow!("no IP addresses resolved for {}", self.server_addr);
        let mut nat64_attempted = false;
        for addr in addrs {
            match self.try_connect_transport(addr.ip(), addr.port(), tx).await {
                Ok(sock) => return Ok(sock),
                Err(e) => last_err = anyhow::anyhow!("{addr}: {e}"),
            }
            if let (std::net::IpAddr::V4(ipv4), false) = (addr.ip(), nat64_attempted) {
                nat64_attempted = true;
                let nat64 = std::net::IpAddr::V6(synthesize_nat64(ipv4).await);
                match self.try_connect_transport(nat64, addr.port(), tx).await {
                    Ok(sock) => return Ok(sock),
                    Err(e) => last_err = anyhow::anyhow!("{last_err}; NAT64: {e}"),
                }
            }
        }
        Err(last_err)
    }



    /// Moves every live session onto a fresh connection of the configured
    /// transport, with no new handshake: keys, nonces and streams stay, so the
    /// apps behind the tunnel keep their connections. The server moves the
    /// session to the new address on the first authenticated packet with a
    /// fresh nonce.
    ///
    /// Only the sockets are swapped here; `check_link` settles the move. The
    /// transport and the server are never changed.
    async fn start_migration(&mut self, tx: &mpsc::Sender<UiEvent>) -> Result<()> {
        let count = self.sessions.len();
        if count == 0 {
            anyhow::bail!("no session to move");
        }
        if self.sessions.iter().any(|ses| ses.machine.state() != ostp_core::OstpState::Established) {
            anyhow::bail!("a session is not established");
        }

        refresh_routes(tx).await;

        // Connect everything before touching the sessions, so a failure leaves
        // them as they were.
        let mut sockets = Vec::with_capacity(count);
        let connect_all = async {
            for _ in 0..count {
                sockets.push(self.connect_server(tx).await?);
            }
            Ok::<_, anyhow::Error>(())
        };
        timeout(MIGRATION_CONNECT_BUDGET, connect_all)
            .await
            .map_err(|_| anyhow::anyhow!("no connection to the server within {} s", MIGRATION_CONNECT_BUDGET.as_secs()))??;

        let (udp_tx, udp_rx) = mpsc::channel(1024);
        for (index, (session, socket)) in self.sessions.iter_mut().zip(sockets).enumerate() {
            session.rx_task.abort();
            session.rx_task = spawn_session_receiver(socket.clone(), index, udp_tx.clone());
            session.socket = socket;
            session.machine.on_path_change();

            // A fresh nonce first: retransmits carry old nonces, and the server
            // only moves the session on a packet newer than any it has seen.
            let ts = SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
            let ping = Bytes::from(RelayMessage::Ping(ts).encode());
            let mut frames = Vec::new();
            if let Ok(action) = session.machine.on_event(OstpEvent::Outbound(0, ping)) {
                collect_datagrams(action, &mut frames);
            }
            if let Ok(action) = session.machine.on_event(OstpEvent::Tick) {
                collect_datagrams(action, &mut frames);
            }
            for frame in frames {
                if send_datagram(&session.socket, &frame, false).await.is_ok() {
                    self.metrics.bytes_sent.fetch_add(frame.len() as u64, Ordering::Relaxed);
                }
            }
        }
        self.udp_rx = Some(udp_rx);

        self.link = Link::Moving { started: Instant::now(), outage: None };
        self.metrics.connection_state.store(1, Ordering::Relaxed);
        tx.send(UiEvent::Log(
            "Moving the session to a new connection (no reconnect, streams kept)...".to_string(),
        )).await.ok();
        Ok(())
    }

    /// Starts a move; false if no new connection could be opened.
    async fn try_migrate(&mut self, reason: &str, tx: &mpsc::Sender<UiEvent>) -> bool {
        tx.send(UiEvent::Log(format!("{reason}: moving the session to a new path"))).await.ok();
        match self.start_migration(tx).await {
            Ok(()) => true,
            Err(e) => {
                tx.send(UiEvent::Log(format!("Could not move the session: {e}"))).await.ok();
                false
            }
        }
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
        self.mux_sessions = cfg.multiplex.sessions.clamp(1, MAX_MUX_SESSIONS);
        self.transport_mode = cfg.transport.mode.clone();
        self.tcp_fragmentation = cfg.transport.tcp_fragmentation;
        self.frag_chunk = cfg.transport.frag_chunk.max(1);
        self.frag_sleep = cfg.transport.frag_sleep;
        self.junk_pc = cfg.transport.junk_pc;
        self.junk_ps = cfg.transport.junk_ps;
        self.ttl_desync = cfg.transport.ttl_desync;
        self.ttl_desync_ttl = cfg.transport.ttl_desync_ttl;
        self.ttl_desync_count = cfg.transport.ttl_desync_count;
        self.ttl_desync_auto = cfg.transport.ttl_desync_auto;
        self.tls = cfg.transport.tls;
        self.tls_sni = cfg.transport.tls_sni.clone();
        self.tls_insecure = cfg.transport.tls_insecure;
        self.ws_path = cfg.transport.ws_path.clone();
        self.ttl_desync_measured = None; // re-measure after a config change
        self.mtu = cfg.ostp.mtu;
        self.keepalive_interval_sec = cfg.ostp.keepalive_interval_sec;
        self.kill_switch = cfg.kill_switch;
    }

    async fn try_connect_transport(
        &self,
        target_ip: std::net::IpAddr,
        port: u16,
        tx: &mpsc::Sender<UiEvent>,
    ) -> Result<crate::transport::Transport> {
        let mode = self.transport_mode.to_lowercase();
        // TLS and the upgrade path only exist on the TCP carrier.
        if mode == "uot" || mode == "tcp" || self.tls || self.ws_path.is_some() {
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
            let (transport, mut foreign_rx) = crate::transport::connect_uot(
                target_ip,
                port,
                crate::transport::UotOptions {
                    tcp_fragmentation: self.tcp_fragmentation,
                    frag_chunk: self.frag_chunk,
                    frag_sleep: self.frag_sleep,
                    junk_pc: self.junk_pc,
                    junk_ps: self.junk_ps,
                    access_key: self.access_key.clone(),
                    ttl: None,
                    connect_timeout: UOT_CONNECT_TIMEOUT,
                    // Name, not the resolved IP: the certificate and the web
                    // server's vhost are for the domain, on every resolved
                    // address and on the NAT64 fallback alike.
                    tls: self.tls.then(|| crate::transport::TlsClientOptions {
                        sni: self.tls_sni.clone().unwrap_or_else(|| server_host(&self.server_addr)),
                        insecure: self.tls_insecure,
                    }),
                    ws_path: self.ws_path.clone(),
                    http_host: self.tls_sni.clone().unwrap_or_else(|| server_host(&self.server_addr)),
                },
            ).await?;

            // Forward foreign-bytes findings into the UI log, but only in debug
            // mode — a successfully-validated ostp frame is genuine server
            // traffic and never reaches this channel in the first place, so
            // this is purely "does not look like it came from the ostp
            // server" diagnostics, not a dump of real traffic.
            if self.debug {
                let ui_tx = tx.clone();
                tokio::spawn(async move {
                    while let Some(msg) = foreign_rx.recv().await {
                        ui_tx.send(UiEvent::Log(format!("[debug] {msg}"))).await.ok();
                    }
                });
            }

            Ok(transport)
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

pub(crate) async fn synthesize_nat64(ip: std::net::Ipv4Addr) -> std::net::Ipv6Addr {
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

/// Host part of "host:port" / "[v6]:port", without resolving it.
pub(crate) fn server_host(server_addr: &str) -> String {
    if let Some(rest) = server_addr.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest).to_string();
    }
    match server_addr.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') && port.parse::<u16>().is_ok() => host.to_string(),
        _ => server_addr.to_string(),
    }
}

/// Why a UDP handshake got no answer, told apart by a TCP connect to the
/// same port (the server takes both on it) made around the tunnel.
async fn udp_failure_diagnosis(server_addr: &str) -> String {
    let lookup = tokio::time::timeout(RESOLVE_TIMEOUT, tokio::net::lookup_host(server_addr)).await;
    let addr = match lookup.ok().and_then(|r| r.ok()).and_then(|mut a| a.next()) {
        Some(a) => a,
        None => return format!("{server_addr} does not resolve"),
    };
    match crate::path_probe::bypass_tcp_connect(addr, Duration::from_secs(4)).await {
        Ok(_) => format!(
            "The server answers on TCP {addr} but not over UDP: UDP to it is dropped on the way \
             (provider or censor) or by the server's firewall. Connect with this server's TLS or TCP profile, \
             or check on the server that UDP port {} is open.",
            addr.port()
        ),
        Err(e) => format!("No answer on TCP {addr} either ({e}): the server is down or unreachable from this network."),
    }
}


/// In TUN mode the server is reached through a route via the physical gateway
/// set up at start. After a network change that gateway is gone and every new
/// socket would go nowhere, which only a manual restart used to fix: move the
/// routes to the current gateway before each recovery step.
async fn refresh_routes(tx: &mpsc::Sender<UiEvent>) {
    let moved = tokio::task::spawn_blocking(ostp_tun::refresh_bypass_routes).await.unwrap_or(false);
    if moved {
        tx.send(UiEvent::Log("Network changed: routes to the server now use the new network".to_string())).await.ok();
    }
}

#[cfg(test)]
mod server_host_tests {
    use super::server_host;

    #[test]
    fn strips_port_and_brackets() {
        assert_eq!(server_host("vpn.example.com:443"), "vpn.example.com");
        assert_eq!(server_host("1.2.3.4:50000"), "1.2.3.4");
        assert_eq!(server_host("[2001:db8::1]:443"), "2001:db8::1");
        assert_eq!(server_host("vpn.example.com"), "vpn.example.com");
    }
}
