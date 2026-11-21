use anyhow::Result;
use bytes::Bytes;
use ostp_core::{CloseReason, OstpEvent, OstpState, ProtocolAction, ProtocolConfig, ProtocolMachine};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::sync::atomic::Ordering;
use portable_atomic::AtomicU64;

/// Maximum number of concurrent authenticated sessions.
/// Excess handshake attempts are silently dropped -- no response, no state allocated.
const MAX_SESSIONS: usize = 1024;

/// Cap on the anti-replay handshake cache. When reached, expired entries are
/// reclaimed (and if needed the oldest is evicted) rather than rejecting new
/// handshakes globally — see the eviction logic in on_datagram.
const REPLAY_CACHE_MAX: usize = 50_000;

pub enum DispatchOutcome {
    Unauthorized,
    /// Packet matched a registered key's per-key junk marker — drop silently.
    Junk,
    Accepted {
        responses: Vec<Bytes>,
        app_payloads: Vec<(u32, u32, Bytes)>, // session_id, stream_id, payload
        /// v6: unsequenced payloads (UDP), same shape as `app_payloads`.
        datagrams: Vec<(u32, u32, Bytes)>,
        /// v6: streams the peer reset (session_id, stream_id).
        resets: Vec<(u32, u32)>,
        peer_addr: SocketAddr,
    },
}

/// Per-user traffic statistics.
pub struct UserStats {
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
    /// Sessions of this user alive right now (not a running total): up on a
    /// handshake, down when the session is dropped.
    pub connections: AtomicU64,
    pub limit_bytes: Option<u64>,
    pub created_at: std::time::SystemTime,
}

impl UserStats {
    pub fn new(limit: Option<u64>) -> Self {
        Self {
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
            connections: AtomicU64::new(0),
            limit_bytes: limit,
            created_at: std::time::SystemTime::now(),
        }
    }

    pub fn is_over_limit(&self) -> bool {
        if let Some(limit) = self.limit_bytes {
            let total = self.bytes_up.load(Ordering::Relaxed)
                + self.bytes_down.load(Ordering::Relaxed);
            total >= limit
        } else {
            false
        }
    }
}

/// Snapshot of user stats for API responses.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UserStatsSnapshot {
    pub access_key: String,
    pub name: Option<String>,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub connections: u64,
    pub limit_bytes: Option<u64>,
    pub online: bool,
    pub last_seen: Option<u64>,
    /// When the key stops working, Unix seconds (UTC); `None` = never.
    #[serde(default)]
    pub expires_at: Option<u64>,
}

pub struct PeerState {
    pub machine: ProtocolMachine,
    pub last_addr: SocketAddr,
    pub obfuscation_key: [u8; 8],
    pub last_seen: std::time::Instant,
    pub access_key: String,
    /// The client announced FEATURE_FLOW_CONTROL: its new streams get windows.
    pub flow_control: bool,
    /// v6: the streams of this session by id (the client's odd ids), to hold
    /// the limit and refuse a reused id. Unused by a v5 session.
    pub streams: ostp_core::streams::StreamIds,
    /// When this session was last sent its `ServerInfo` (see `allow_info_request`).
    pub last_info: Option<std::time::Instant>,
}

/// A session gets its `ServerInfo` at most this often.
pub const INFO_REQUEST_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

pub struct Dispatcher {
    peer_machines: HashMap<u32, PeerState>,
    addr_to_session: HashMap<SocketAddr, u32>,
    machine_config: ProtocolConfig,
    access_keys: Arc<RwLock<HashMap<String, crate::api::UserMeta>>>,
    user_stats: Arc<RwLock<HashMap<String, Arc<UserStats>>>>,
    replay_cache: std::collections::HashMap<Vec<u8>, u64>,
    /// Scanning the sessions for one that roamed to a new address, per
    /// source; see `admission`.
    roaming: crate::admission::Admission,
    /// Cache of per-key derived secrets (obf key / psk / padding). These are a
    /// pure function of the access key + PROTOCOL_VERSION, so they never change
    /// for a given key — computing the HKDF on every unknown datagram, for every
    /// registered key, was pure waste and an attacker-amplified CPU sink.
    secrets_cache: HashMap<String, ostp_core::crypto::DerivedSecrets>,
    /// Cache of each key's junk markers for the current time window. The marker
    /// rotates every window, so the cached `(window, m_now, m_prev)` is refreshed
    /// when the window rolls; within a window it's an HMAC we compute once, not
    /// twice per key per packet.
    junk_cache: HashMap<String, (u64, [u8; 4], [u8; 4])>,
    /// Trying every key on a would-be handshake (an X25519 operation per key),
    /// per source with a server-wide cap that sources which authenticated
    /// recently skip; see `admission`.
    trials: crate::admission::Admission,
    /// Open connections (TCP streams, UDP associations) per key; see
    /// `stream_permit`.
    stream_limits: HashMap<String, Arc<tokio::sync::Semaphore>>,
    /// Sessions removed by `drop_session` since the last tick.
    dropped: Vec<u32>,
    /// The server's static private key. `Some`: v6 handshakes are accepted.
    server_key: Option<[u8; 32]>,
    /// The transitional mode: v5 handshakes are accepted as well.
    accept_v5: bool,
    v6_secrets_cache: HashMap<String, ostp_core::crypto::V6Secrets>,
    /// The reply to each accepted v6 handshake, by the SHA-256 of its Noise
    /// message (not of the datagram: nonce and padding vary between copies),
    /// with the handshake's timestamp. A client whose reply was lost sends the
    /// handshake again; it gets the same reply instead of silence (the replay
    /// check would drop it). Kept as long as the replay
    /// cache keeps the handshake. The reply is encrypted to the client's
    /// ephemeral key, so resending it to someone who replays a captured
    /// handshake gives them nothing.
    hs_replies: HashMap<[u8; 32], (u64, Bytes)>,
    /// Streams the core reset on a tick (this side gave up on a frame), for the
    /// server loop to close their targets; see `take_resets`.
    pending_resets: Vec<(u32, u32)>,
    /// v6 sessions the server ended with a `Close` (reason known): kept apart
    /// from the live ones only to resend the `Close` until the client
    /// acknowledges it, at most `CLOSE_GRACE`. They carry no streams and take
    /// no part in anything else.
    closing: HashMap<u32, ClosingSession>,
    /// `Close` frames built since the last tick, sent by it.
    pending_frames: Vec<(Bytes, SocketAddr)>,
    /// Set when the server is stopping: no new session is accepted, only the
    /// acknowledgements of the `Close` frames are read.
    closing_only: bool,
    /// Target connections being set up, by stream, with the token of the
    /// attempt (`begin_connect`). An entry goes when the stream ends or its
    /// session does, so a connect that completes afterwards is dropped.
    connecting: HashMap<(u32, u32), u64>,
    next_connect: u64,
    /// Session ids taken over by a new handshake while the old session's
    /// streams may still be open (`take_replaced`).
    replaced: Vec<u32>,
    /// Addresses a session roamed away from, and when (`take_vacated`).
    vacated: Vec<(SocketAddr, std::time::Instant)>,
    /// The last slow pass of `on_tick` (`HOUSEKEEPING_INTERVAL`); `None`:
    /// the next tick makes one.
    last_housekeeping: Option<std::time::Instant>,
}

/// How often `on_tick` purges the replay caches and checks sessions for
/// expiry, a removed key or a used-up limit. Every 10 ms tick did it: a scan
/// of up to 50,000 cache entries and two locks and a lookup per session,
/// 100 times a second, on the packet loop. None of it needs to be prompt to
/// the millisecond: the drift window is 300 s, the idle timeout 10 min.
const HOUSEKEEPING_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
/// Addresses vacated but not yet reported, at most.
const MAX_VACATED: usize = 4096;

/// A session that was sent a `Close`, until it is acknowledged.
struct ClosingSession {
    machine: ProtocolMachine,
    addr: SocketAddr,
    obfuscation_key: [u8; 8],
    since: std::time::Instant,
}

/// How long a `Close` is resent before the server gives up on it. The core
/// resends after 0.1, 0.2, 0.4, 0.8, 1.6 s ...: five or six copies in this
/// time. A client that is really gone never acknowledges; it is not waited for.
const CLOSE_GRACE: std::time::Duration = std::time::Duration::from_secs(5);
/// Sessions kept for `Close` retransmission at once; more are sent once only.
const MAX_CLOSING: usize = 256;

/// Server-wide key trials per second for sources not seen authenticating.
/// It bounds what a flood costs: TRIAL_RATE × number of keys X25519 a second.
const TRIAL_RATE: f64 = 100.0;
/// Per source: a real client sends one handshake and a few retries.
const TRIAL_SOURCE_RATE: f64 = 5.0;
const TRIAL_SOURCE_BURST: f64 = 20.0;
/// Session scans for a roamed client (one HMAC per session each).
const ROAMING_RATE: f64 = 200.0;
const ROAMING_SOURCE_RATE: f64 = 20.0;
const ROAMING_SOURCE_BURST: f64 = 50.0;
/// Sessions one key may hold. A client that reconnects leaves the old session
/// until it times out, so the oldest is dropped rather than the new refused;
/// one key can no longer take all MAX_SESSIONS slots.
const MAX_SESSIONS_PER_KEY: usize = 32;
/// The send budget covers this long: the packet loop's tick, the longest the
/// readers go without an update when no ACK arrives.
const SEND_BUDGET_HORIZON: std::time::Duration = std::time::Duration::from_millis(10);
/// Connections one key may hold open at once. The process has 65535 file
/// descriptors (LimitNOFILE); without this one key could take them all.
const MAX_STREAMS_PER_KEY: usize = 4096;

/// Short, non-reversible fingerprint of an access key for logs. The access key
/// is a shared secret, so it must never be written to logs verbatim; this lets
/// an operator correlate events without exposing the key itself.
pub(crate) fn key_fp(access_key: &str) -> String {
    use sha2::{Digest, Sha256};
    let h = Sha256::digest(access_key.as_bytes());
    format!("{:02x}{:02x}{:02x}", h[0], h[1], h[2])
}

#[allow(dead_code)]
impl Dispatcher {
    pub fn new(machine_config: ProtocolConfig, access_keys: Arc<RwLock<HashMap<String, crate::api::UserMeta>>>) -> Self {
        let mut initial_stats = HashMap::new();
        for (key, meta) in access_keys.read().unwrap_or_else(|e| e.into_inner()).iter() {
            initial_stats.insert(key.clone(), Arc::new(UserStats::new(meta.limit_bytes)));
        }
        Self {
            peer_machines: HashMap::new(),
            addr_to_session: HashMap::new(),
            machine_config,
            access_keys,
            user_stats: Arc::new(RwLock::new(initial_stats)),
            replay_cache: std::collections::HashMap::new(),
            roaming: crate::admission::Admission::new(ROAMING_SOURCE_RATE, ROAMING_SOURCE_BURST, ROAMING_RATE),
            secrets_cache: HashMap::new(),
            junk_cache: HashMap::new(),
            trials: crate::admission::Admission::new(TRIAL_SOURCE_RATE, TRIAL_SOURCE_BURST, TRIAL_RATE),
            stream_limits: HashMap::new(),
            dropped: Vec::new(),
            server_key: None,
            accept_v5: true,
            v6_secrets_cache: HashMap::new(),
            hs_replies: HashMap::new(),
            pending_resets: Vec::new(),
            closing: HashMap::new(),
            pending_frames: Vec::new(),
            closing_only: false,
            connecting: HashMap::new(),
            next_connect: 0,
            replaced: Vec::new(),
            vacated: Vec::new(),
            last_housekeeping: None,
        }
    }

    /// Which wire versions this server speaks. With a server key it accepts
    /// v6; `accept_v5` keeps v5 clients working next to it (the transitional
    /// mode). Without a key only v5 can work, whatever `accept_v5` says.
    pub fn set_wire_versions(&mut self, server_key: Option<[u8; 32]>, accept_v5: bool) {
        self.accept_v5 = accept_v5 || server_key.is_none();
        self.server_key = server_key;
    }

    fn cached_v6_secrets(&mut self, key: &str) -> ostp_core::crypto::V6Secrets {
        if let Some(s) = self.v6_secrets_cache.get(key) {
            return s.clone();
        }
        let s = ostp_core::crypto::derive_v6_secrets(key.as_bytes());
        self.v6_secrets_cache.insert(key.to_string(), s.clone());
        s
    }

    /// Fetch this key's derived secrets from cache, computing (and caching) them
    /// on first sight. Pure function of the key, so the entry never goes stale.
    fn cached_secrets(&mut self, key: &str) -> ostp_core::crypto::DerivedSecrets {
        if let Some(s) = self.secrets_cache.get(key) {
            return s.clone();
        }
        let s = ostp_core::crypto::derive_all_secrets(key.as_bytes());
        self.secrets_cache.insert(key.to_string(), s.clone());
        s
    }

    /// Fetch this key's `(m_now, m_prev)` junk markers for `window`, recomputing
    /// only when the cached window has rolled.
    fn cached_junk_markers(&mut self, key: &str, window: u64) -> ([u8; 4], [u8; 4]) {
        if let Some(&(w, m_now, m_prev)) = self.junk_cache.get(key) {
            if w == window {
                return (m_now, m_prev);
            }
        }
        let m_now = ostp_core::crypto::derive_junk_marker(key.as_bytes(), window);
        let m_prev = ostp_core::crypto::derive_junk_marker(key.as_bytes(), window.wrapping_sub(1));
        self.junk_cache.insert(key.to_string(), (window, m_now, m_prev));
        (m_now, m_prev)
    }

    /// Returns a shared reference to user stats for the Management API.
    pub fn user_stats_ref(&self) -> Arc<RwLock<HashMap<String, Arc<UserStats>>>> {
        self.user_stats.clone()
    }

    /// Snapshot all user stats for API responses.
    pub fn snapshot_all_users(&self) -> Vec<UserStatsSnapshot> {
        let stats = self.user_stats.read().unwrap_or_else(|e| e.into_inner());
        let mut online_keys: HashMap<String, std::time::Instant> = HashMap::new();
        for ps in self.peer_machines.values() {
            let key = ps.access_key.clone();
            if let Some(existing) = online_keys.get(&key) {
                if ps.last_seen > *existing {
                    online_keys.insert(key, ps.last_seen);
                }
            } else {
                online_keys.insert(key, ps.last_seen);
            }
        }
        
        let now = std::time::Instant::now();
        let current_sys_time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();

        stats.iter().map(|(key, us)| {
            let last_seen_unix = online_keys.get(key).map(|&instant| {
                let diff = now.duration_since(instant).as_secs();
                current_sys_time.saturating_sub(diff)
            });
            
            UserStatsSnapshot {
                access_key: key.clone(),
                name: None,
                bytes_up: us.bytes_up.load(Ordering::Relaxed),
                bytes_down: us.bytes_down.load(Ordering::Relaxed),
                connections: us.connections.load(Ordering::Relaxed),
                limit_bytes: us.limit_bytes,
                online: online_keys.contains_key(key),
                last_seen: last_seen_unix,
                expires_at: None,
            }
        }).collect()
    }

    /// Get or create stats entry for a user key.
    fn get_or_create_user_stats(&self, key: &str) -> Arc<UserStats> {
        let stats = self.user_stats.read().unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = stats.get(key) {
            return existing.clone();
        }
        drop(stats);
        
        let limit_bytes = self.access_keys.read().unwrap_or_else(|e| e.into_inner()).get(key).and_then(|m| m.limit_bytes);
        
        let mut stats = self.user_stats.write().unwrap_or_else(|e| e.into_inner());
        stats.entry(key.to_string())
            .or_insert_with(|| Arc::new(UserStats::new(limit_bytes)))
            .clone()
    }

    /// Set traffic limit for a user.
    pub fn set_user_limit(&self, key: &str, limit: Option<u64>) {
        let mut stats = self.user_stats.write().unwrap_or_else(|e| e.into_inner());
        let entry = stats.entry(key.to_string())
            .or_insert_with(|| Arc::new(UserStats::new(limit)));
        // Replace the entry with new limit (stats reset)
        *entry = Arc::new(UserStats {
            bytes_up: AtomicU64::new(entry.bytes_up.load(Ordering::Relaxed)),
            bytes_down: AtomicU64::new(entry.bytes_down.load(Ordering::Relaxed)),
            connections: AtomicU64::new(entry.connections.load(Ordering::Relaxed)),
            limit_bytes: limit,
            created_at: entry.created_at,
        });
    }

    /// Tells the session now reachable at `peer` whether it rides TCP (UoT,
    /// TLS) or UDP. On TCP the core stops timer-driven resends: see
    /// `ProtocolMachine::set_reliable_carrier`. Cheap; called per packet, so
    /// a session that moves between carriers follows along.
    pub fn set_carrier_reliable(&mut self, peer: SocketAddr, reliable: bool) {
        if let Some(sid) = self.addr_to_session.get(&peer) {
            if let Some(ps) = self.peer_machines.get_mut(sid) {
                ps.machine.set_reliable_carrier(reliable);
            }
        }
    }

    /// Active session count.
    pub fn active_sessions(&self) -> usize {
        self.peer_machines.len()
    }

    /// Per-session download-direction send budget, in frames:
    /// `(session_id, frames)` the congestion window and the pacing rate allow
    /// until the next tick (`ProtocolMachine::send_budget`).
    ///
    /// Consumed by the relay's per-target-connection reader tasks (see
    /// `relay::handle_relay_message`'s Connect handler and `send_gate`) so a
    /// fast target (e.g. a CDN) is read no faster than the client-facing
    /// session can carry. Over the whole tick, not "is the pacing bucket
    /// empty this instant": that read zero after every burst and stopped
    /// sending until the next tick.
    pub fn snapshot_backpressure(&self) -> Vec<(u32, SocketAddr, i64)> {
        self.peer_machines
            .iter()
            .map(|(&sid, ps)| (sid, ps.last_addr, ps.machine.send_budget(SEND_BUDGET_HORIZON) as i64))
            .collect()
    }

    /// Frames the session's TCP/TLS send queue takes before the next tick
    /// (`None` on UDP); its retransmissions are held to it.
    pub fn set_carrier_room(&mut self, sid: u32, room: Option<usize>) {
        if let Some(ps) = self.peer_machines.get_mut(&sid) {
            ps.machine.set_carrier_room(room);
        }
    }

    /// The send budget of the session a datagram from `addr` belongs to,
    /// right after it was processed (an ACK may have opened the window).
    pub fn budget_for_addr(&self, addr: SocketAddr) -> Option<(u32, i64)> {
        let sid = *self.addr_to_session.get(&addr)?;
        let ps = self.peer_machines.get(&sid)?;
        Some((sid, ps.machine.send_budget(SEND_BUDGET_HORIZON) as i64))
    }

    pub fn on_datagram(&mut self, peer: SocketAddr, packet: Bytes) -> Result<DispatchOutcome> {
        if packet.len() < 4 {
            return Ok(DispatchOutcome::Unauthorized);
        }

        let mut session_id_opt = None;

        if let Some(&sid) = self.addr_to_session.get(&peer) {
            if let Some(peer_state) = self.peer_machines.get(&sid) {
                let mut header = [0u8; 12];
                if packet.len() >= 12 {
                    header.copy_from_slice(&packet[0..12]);
                    let ciphertext = &packet[12..];
                    ostp_core::crypto::deobfuscate_header_inplace(&mut header, ciphertext, &peer_state.obfuscation_key, false);
                    let candidate_sid = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
                    if candidate_sid == sid {
                        session_id_opt = Some(sid);
                    }
                }
            }
        }

        if session_id_opt.is_none() {
            // Rate-limited per source: each scan is one HMAC per session.
            if self.roaming.admit(peer.ip()) {

                // Try seamless roaming over all peers
                for (&sid, peer_state) in &self.peer_machines {
                    if packet.len() >= 12 {
                        let mut header = [0u8; 12];
                        header.copy_from_slice(&packet[0..12]);
                        let ciphertext = &packet[12..];
                        ostp_core::crypto::deobfuscate_header_inplace(&mut header, ciphertext, &peer_state.obfuscation_key, false);
                        let candidate_sid = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
                        if candidate_sid == sid {
                            session_id_opt = Some(sid);
                            break;
                        }
                    }
                }
            }
        }

        if let Some(session_id) = session_id_opt {
            let key_opt = self.peer_machines.get(&session_id).map(|ps| ps.access_key.clone());
            if let Some(access_key) = key_opt {
                // Check if key is still valid, not expired and not over limit
                let (key_valid, expired) = match self.access_keys.read().unwrap_or_else(|e| e.into_inner()).get(&access_key) {
                    Some(meta) => (true, meta.is_expired(ostp_core::access_keys::unix_now())),
                    None => (false, false),
                };
                let user_stats = self.get_or_create_user_stats(&access_key);
                if !key_valid || expired || user_stats.is_over_limit() {
                    tracing::info!("Dropping session {} for key {} (valid={}, expired={}, over_limit={})",
                        session_id, key_fp(&access_key), key_valid, expired, user_stats.is_over_limit());
                    let reason = if !key_valid {
                        CloseReason::KeyRevoked
                    } else if expired {
                        CloseReason::KeyExpired
                    } else {
                        CloseReason::TrafficLimit
                    };
                    self.drop_session_with(session_id, reason);
                    return Ok(DispatchOutcome::Unauthorized);
                }
            }

            if let Some(peer_state) = self.peer_machines.get_mut(&session_id) {
                // Track inbound bytes per user
                let key = peer_state.access_key.clone();
                track_user_bytes_up(&self.user_stats, &self.access_keys, &key, packet.len() as u64);

                let highest_before = peer_state.machine.highest_authenticated_recv_nonce();
                let action = match peer_state.machine.on_event(OstpEvent::Inbound(packet)) {
                    Ok(a) => a,
                    Err(e) => {
                        // Per packet, and anyone who can spoof the client's address
                        // can send packets that get this far: not a warning.
                        tracing::debug!("Protocol error for session {}: {}", session_id, e);
                        return Ok(DispatchOutcome::Unauthorized);
                    }
                };

                // Session state moves only after the packet authenticated. The
                // address moves only on a packet that also raised the highest
                // authenticated nonce: a copy of an already-seen packet, replayed
                // from another address, would otherwise redirect the session's
                // traffic there. Anything else from a non-current address (a
                // replay, a late packet from the old path) is processed, but its
                // responses go to the address the session is actually on.
                let highest_after = peer_state.machine.highest_authenticated_recv_nonce();
                let raised_highest = highest_after.is_some() && highest_after != highest_before;
                if peer_state.last_addr != peer && raised_highest {
                    crate::logs::roamed(session_id, peer_state.last_addr, peer);
                    if self.addr_to_session.get(&peer_state.last_addr) == Some(&session_id) {
                        self.addr_to_session.remove(&peer_state.last_addr);
                        if self.vacated.len() < MAX_VACATED {
                            self.vacated.push((peer_state.last_addr, std::time::Instant::now()));
                        }
                    }
                    peer_state.last_addr = peer;
                    self.addr_to_session.insert(peer, session_id);
                    self.trials.mark_known(peer.ip());
                    self.roaming.mark_known(peer.ip());
                    // What the server learned about the old path does not
                    // describe the new one, as on the client's side of a move.
                    peer_state.machine.on_path_change();
                }
                if peer_state.last_addr == peer {
                    peer_state.last_seen = std::time::Instant::now();
                }
                let reply_addr = peer_state.last_addr;

                let mut responses = Vec::new();
                let mut app_payloads = Vec::new();
                let mut datagrams = Vec::new();
                let mut resets = Vec::new();

                fn collect_action(
                    act: ProtocolAction,
                    sid: u32,
                    resps: &mut Vec<Bytes>,
                    loads: &mut Vec<(u32, u32, Bytes)>,
                    dgrams: &mut Vec<(u32, u32, Bytes)>,
                    resets: &mut Vec<(u32, u32)>,
                ) {
                    match act {
                        ProtocolAction::SendDatagram(frame) => {
                            resps.push(frame);
                        }
                        // A v5 session's ids are 16 bits already: the core
                        // read them from a 16-bit header field.
                        ProtocolAction::DeliverApp(stream_id, data) => loads.push((sid, stream_id, data)),
                        ProtocolAction::DeliverDatagram(stream_id, data) => dgrams.push((sid, stream_id, data)),
                        ProtocolAction::StreamReset(stream_id, _reason) => resets.push((sid, stream_id)),
                        ProtocolAction::Multiple(list) => {
                            for item in list {
                                collect_action(item, sid, resps, loads, dgrams, resets);
                            }
                        }
                        _ => {}
                    }
                }

                collect_action(action, session_id, &mut responses, &mut app_payloads, &mut datagrams, &mut resets);

                return Ok(DispatchOutcome::Accepted {
                    responses,
                    app_payloads,
                    datagrams,
                    resets,
                    peer_addr: reply_addr,
                });
            }
        }

        // A session that was sent a Close: its acknowledgement is read, nothing
        // else is answered.
        if !self.closing.is_empty() && self.feed_closing(peer, &packet) {
            return Ok(DispatchOutcome::Junk);
        }
        if self.closing_only {
            return Ok(DispatchOutcome::Unauthorized);
        }

        // Not an existing session — this is the expensive O(N_keys) trial path.
        // Gate it behind a token bucket so a garbage/spoofed-source flood cannot
        // force unbounded per-packet crypto work. Existing sessions (fast path
        // above) and roaming are unaffected. Regenerate at TRIAL_RATE/sec.
        if !self.trials.admit(peer.ip()) {
            // Out of budget: drop silently (no response, no state, no log spam).
            return Ok(DispatchOutcome::Unauthorized);
        }

        let keys_snapshot: Vec<String> = self.access_keys.read().unwrap_or_else(|e| e.into_inner()).keys().cloned().collect();

        // Junk marker rotates per time window; check the current and previous
        // window so a client whose clock is up to ~1 window behind/ahead is still
        // recognised. Computed once per datagram, not per candidate key.
        let junk_window = ostp_core::crypto::current_junk_window();

        // v6 first for every key (a tag check, one HMAC), then v5 for every
        // key (the transitional mode).
        let mut attempts: Vec<(String, bool)> = Vec::with_capacity(keys_snapshot.len() * 2);
        if self.server_key.is_some() {
            attempts.extend(keys_snapshot.iter().map(|k| (k.clone(), true)));
        }
        if self.accept_v5 {
            attempts.extend(keys_snapshot.into_iter().map(|k| (k, false)));
        }

        for (candidate_key, is_v6) in attempts {
            let mut noise_hash: Option<[u8; 32]> = None;
            let (secrets, v6_cfg, candidate_session_id) = if is_v6 {
                let v6 = self.cached_v6_secrets(&candidate_key);
                let Some((sid, hash)) = ostp_core::protocol::v6_handshake_identity(&v6.hs, &packet) else {
                    continue;
                };
                // A handshake this server already answered, sent again because
                // the reply was lost: the same reply, no second session. It is
                // found by the Noise message, not the whole datagram: the
                // padding is not authenticated, so a damaged copy that was
                // accepted must not hide the clean one, and a resend sealed
                // anew (other nonce, other padding) is the same handshake.
                if let Some((_, reply)) = self.hs_replies.get(&hash) {
                    return Ok(DispatchOutcome::Accepted {
                        responses: vec![reply.clone()],
                        app_payloads: Vec::new(),
                        datagrams: Vec::new(),
                        resets: Vec::new(),
                        peer_addr: peer,
                    });
                }
                noise_hash = Some(hash);
                let Some(private) = self.server_key else { continue };
                let handshake = ostp_core::protocol::V6Handshake {
                    server: ostp_core::crypto::ServerStatic::Private(private),
                    hs: v6.hs,
                };
                (v6.base, Some(handshake), sid)
            } else {
                let secrets = self.cached_secrets(&candidate_key);

                // Junk frames carry this key's time-rotating marker (no global
                // constant, no static per-user signature). Drop silently.
                if packet.len() >= 4 {
                    let (m_now, m_prev) = self.cached_junk_markers(&candidate_key, junk_window);
                    if packet[0..4] == m_now || packet[0..4] == m_prev {
                        return Ok(DispatchOutcome::Junk);
                    }
                }

                // Decode the session_id using this key's obfuscation
                // The handshake mask is derived from the Noise payload at bytes [6..],
                // so we must deobfuscate the full packet, not just the header.
                if packet.len() < 7 { continue; }
                let mut trial = packet.to_vec();
                ostp_core::crypto::deobfuscate_packet_inplace(&mut trial, &secrets.obfuscation_key, true);
                let sid = u32::from_be_bytes([trial[0], trial[1], trial[2], trial[3]]);
                (secrets, None, sid)
            };

            let mut cfg = self.machine_config.clone();
            cfg.v6 = v6_cfg;
            cfg.session_id = candidate_session_id;
            cfg.psk = secrets.psk;
            cfg.handshake_payload = vec![];
            cfg.obfuscation_key = secrets.obfuscation_key;
            cfg.handshake_pad_min = secrets.handshake_pad_min;
            cfg.handshake_pad_max = secrets.handshake_pad_max;

            let mut machine = match ProtocolMachine::new(cfg) {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!("Failed to create protocol machine for key trial: {}", e);
                    continue;
                }
            };
            let action = match machine.on_event(OstpEvent::Inbound(packet.clone())) {
                Ok(a) => a,
                Err(_) => continue,
            };

            if let ProtocolAction::HandshakePayload(payload, response_opt) = action {
                if payload.len() >= 12 {
                    let mut ts_bytes = [0_u8; 8];
                    ts_bytes.copy_from_slice(&payload[..8]);
                    let ts = u64::from_be_bytes(ts_bytes);

                    let mut sid_bytes = [0_u8; 4];
                    sid_bytes.copy_from_slice(&payload[8..12]);
                    let sid_from_payload = u32::from_be_bytes(sid_bytes);

                    if sid_from_payload != candidate_session_id {
                        continue;
                    }

                    let key_bytes = &payload[12..];
                    if let Ok(key_from_payload) = std::str::from_utf8(key_bytes) {
                        // The key embedded in the payload must match the candidate key we decoded with
                        if key_from_payload != candidate_key {
                            continue;
                        }

                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();

                        // ts is attacker-chosen: a signed subtraction overflows for
                        // far-off values and the wrapped result can look small.
                        let drift = now.abs_diff(ts);
                        if drift > 300 {
                            crate::logs::handshake_drift(drift, peer);
                            continue;
                        }

                        if !self.replay_cache.contains_key(&payload.to_vec()) {
                            if self.replay_cache.len() >= REPLAY_CACHE_MAX {
                                // Don't globally reject new handshakes when full —
                                // that would let one flooding key-holder deny
                                // service to everyone. Reclaim space instead:
                                // first drop entries already past the drift
                                // window, then, if still full, evict the single
                                // oldest. A replay is still caught because it can
                                // only be accepted while within the 300s drift
                                // window, and an entry that young is never the
                                // one evicted before the cache genuinely holds
                                // 50k sub-300s handshakes.
                                self.replay_cache.retain(|_, &mut cached_ts| {
                                    now.abs_diff(cached_ts) <= 300
                                });
                                if self.replay_cache.len() >= REPLAY_CACHE_MAX {
                                    if let Some(oldest) = self.replay_cache
                                        .iter()
                                        .min_by_key(|(_, &ts)| ts)
                                        .map(|(k, _)| k.clone())
                                    {
                                        self.replay_cache.remove(&oldest);
                                    }
                                    tracing::warn!("Replay cache full ({} entries), evicting oldest", REPLAY_CACHE_MAX);
                                }
                            }
                            if self.peer_machines.len() >= MAX_SESSIONS {
                                crate::logs::max_sessions(MAX_SESSIONS, peer);
                                return Ok(DispatchOutcome::Unauthorized);
                            }

                            self.replay_cache.insert(payload.to_vec(), ts);

                            // The session id is the client's choice. Inserting over a
                            // live id would silently replace another user's session
                            // (and skip its counter); only the same key may reuse one.
                            if let Some(existing) = self.peer_machines.get(&candidate_session_id) {
                                if existing.access_key != candidate_key {
                                    return Ok(DispatchOutcome::Unauthorized);
                                }
                                self.drop_session(candidate_session_id);
                            }

                            // An expired key: a v5 client is refused as for a used-up
                            // limit; a v6 one gets its session and at once a
                            // `Close(KeyExpired)`, so the reason reaches it only
                            // inside the authenticated tunnel. It takes no slot
                            // from the key's other sessions.
                            let expired = self
                                .access_keys
                                .read()
                                .unwrap_or_else(|e| e.into_inner())
                                .get(&candidate_key)
                                .is_some_and(|m| m.is_expired(now));
                            if expired && !is_v6 {
                                crate::logs::key_expired(&key_fp(&candidate_key), peer);
                                return Ok(DispatchOutcome::Unauthorized);
                            }

                            // This key's oldest session makes room.
                            let mine: Vec<(u32, std::time::Instant)> = self
                                .peer_machines
                                .iter()
                                .filter(|(_, ps)| ps.access_key == candidate_key)
                                .map(|(&sid, ps)| (sid, ps.last_seen))
                                .collect();
                            if !expired && mine.len() >= MAX_SESSIONS_PER_KEY {
                                if let Some(&(oldest, _)) = mine.iter().min_by_key(|(_, seen)| *seen) {
                                    tracing::info!("Key {} has {} sessions, dropping the oldest ({})", key_fp(&candidate_key), mine.len(), oldest);
                                    self.drop_session_with(oldest, CloseReason::TooManySessions);
                                }
                            }

                            machine.set_session_keys(candidate_session_id, secrets.obfuscation_key);

                            let user_stats = self.get_or_create_user_stats(&candidate_key);

                            // Check traffic limit before accepting
                            if user_stats.is_over_limit() {
                                crate::logs::over_limit(&key_fp(&candidate_key), peer);
                                return Ok(DispatchOutcome::Unauthorized);
                            }

                            self.peer_machines.insert(candidate_session_id, PeerState {
                                machine,
                                last_addr: peer,
                                obfuscation_key: secrets.obfuscation_key,
                                last_seen: std::time::Instant::now(),
                                access_key: candidate_key.clone(),
                                flow_control: false,
                                streams: ostp_core::streams::StreamIds::new(ostp_core::streams::Side::Server),
                                last_info: None,
                            });
                            self.addr_to_session.insert(peer, candidate_session_id);
                            // The id belonged to a session dropped since the
                            // last tick (replaced just above, or ended): the
                            // tick would not report it any more, since the id
                            // is live again, and the old session's streams
                            // would keep writing into this one. The server
                            // loop closes them before anything else arrives.
                            if self.dropped.contains(&candidate_session_id) && !self.replaced.contains(&candidate_session_id) {
                                self.replaced.push(candidate_session_id);
                            }
                            user_stats.connections.fetch_add(1, Ordering::Relaxed);
                            self.trials.mark_known(peer.ip());
                            self.roaming.mark_known(peer.ip());

                            crate::logs::new_session(candidate_session_id, peer, is_v6, self.peer_machines.len(), self.replay_cache.len());

                            if let (Some(hash), Some(reply)) = (noise_hash, response_opt.as_ref()) {
                                if self.hs_replies.len() >= REPLAY_CACHE_MAX {
                                    self.hs_replies.retain(|_, (cached_ts, _)| now.abs_diff(*cached_ts) <= 300);
                                }
                                // Still full: this reply is not kept, and a lost
                                // one costs that client a new handshake.
                                if self.hs_replies.len() < REPLAY_CACHE_MAX {
                                    self.hs_replies.insert(hash, (ts, reply.clone()));
                                }
                            }

                            // The handshake reply goes out now, the `Close` with
                            // the next tick, after it.
                            if expired {
                                crate::logs::key_expired(&key_fp(&candidate_key), peer);
                                self.drop_session_with(candidate_session_id, CloseReason::KeyExpired);
                            }

                            return Ok(DispatchOutcome::Accepted {
                                responses: response_opt.into_iter().collect(),
                                app_payloads: Vec::new(),
                                datagrams: Vec::new(),
                                resets: Vec::new(),
                                peer_addr: peer,
                            });
                        }
                    }
                }
            }
        }

        Ok(DispatchOutcome::Unauthorized)
    }

    /// Whether the streams of this session have flow-control windows: always
    /// in v6, in v5 only when the client announced it (FEATURE_FLOW_CONTROL).
    pub fn flow_control(&self, session_id: u32) -> bool {
        self.peer_machines.get(&session_id).is_some_and(|ps| ps.flow_control || ps.machine.is_v6())
    }

    /// Whether this session may be sent its `ServerInfo` now: once per
    /// `INFO_REQUEST_INTERVAL`, so a client cannot make the server do the
    /// work (and send the bytes) in a loop. A yes counts as the send.
    pub fn allow_info_request(&mut self, session_id: u32) -> bool {
        let now = std::time::Instant::now();
        let Some(ps) = self.peer_machines.get_mut(&session_id) else { return false };
        if ps.last_info.is_some_and(|t| now.duration_since(t) < INFO_REQUEST_INTERVAL) {
            return false;
        }
        ps.last_info = Some(now);
        true
    }

    /// The `key` part of this session's `ServerInfo`: its key's traffic,
    /// limit, expiry and device limit.
    pub fn key_info(&self, session_id: u32) -> Option<serde_json::Value> {
        let key = &self.peer_machines.get(&session_id)?.access_key;
        let meta = self.access_keys.read().unwrap_or_else(|e| e.into_inner()).get(key).cloned()?;
        let used = self
            .user_stats
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(key)
            .map(|s| s.bytes_up.load(Ordering::Relaxed) + s.bytes_down.load(Ordering::Relaxed))
            .unwrap_or(0);
        Some(crate::server_info::key_value(used, meta.limit_bytes, meta.expires_at, meta.max_devices))
    }

    pub fn set_flow_control(&mut self, session_id: u32) {
        if let Some(ps) = self.peer_machines.get_mut(&session_id) {
            ps.flow_control = true;
        }
    }

    /// Whether the session speaks protocol v6 (false for an unknown one).
    pub fn is_v6(&self, session_id: u32) -> bool {
        self.peer_machines.get(&session_id).is_some_and(|ps| ps.machine.is_v6())
    }

    /// The largest payload one datagram of this session carries.
    pub fn max_payload(&self, session_id: u32) -> Option<usize> {
        self.peer_machines.get(&session_id).map(|ps| ps.machine.max_payload())
    }

    /// The same, shared: it follows the datagram size the session discovers
    /// (`ProtocolMachine::max_payload_handle`), for readers that chunk stream
    /// data without holding the dispatcher.
    pub fn max_payload_handle(&self, session_id: u32) -> Option<Arc<std::sync::atomic::AtomicUsize>> {
        self.peer_machines.get(&session_id).map(|ps| ps.machine.max_payload_handle())
    }

    /// v6: the client opens a stream. Refused (the reason is for the client)
    /// when the id is not an odd one, was used before, or 1024 are open.
    pub fn open_stream(&mut self, session_id: u32, stream_id: u32) -> Result<(), ostp_core::streams::StreamError> {
        match self.peer_machines.get_mut(&session_id) {
            Some(ps) => ps.streams.accept_remote(stream_id),
            None => Err(ostp_core::streams::StreamError::NotOpen),
        }
    }

    /// v6: the stream is over on this side (both `Fin`, or a `Close` or reset):
    /// its state is released, and later frames of it are dropped. A no-op for
    /// a v5 session and for a stream that is not open.
    pub fn release_stream(&mut self, session_id: u32, stream_id: u32) {
        // A connect still under way is no longer wanted (v5 and v6).
        self.connecting.remove(&(session_id, stream_id));
        if let Some(ps) = self.peer_machines.get_mut(&session_id) {
            if !ps.machine.is_v6() {
                return;
            }
            let _ = ps.streams.close(stream_id);
            let _ = ps.machine.on_event(OstpEvent::ReleaseStream(stream_id));
        }
    }

    /// A target connection for this stream is being set up; the token goes
    /// with it to `finish_connect`.
    pub fn begin_connect(&mut self, session_id: u32, stream_id: u32) -> u64 {
        self.next_connect += 1;
        self.connecting.insert((session_id, stream_id), self.next_connect);
        self.next_connect
    }

    /// The connect with this token completed: whether its stream is still
    /// wanted. False when the stream was closed or reset meanwhile, the
    /// session ended, or a newer attempt (or session) took the stream's place.
    pub fn finish_connect(&mut self, session_id: u32, stream_id: u32, token: u64) -> bool {
        if self.connecting.get(&(session_id, stream_id)) != Some(&token) {
            return false;
        }
        self.connecting.remove(&(session_id, stream_id));
        self.peer_machines.contains_key(&session_id)
    }

    /// Session ids whose old session was dropped and the id taken by a new
    /// handshake since the last call: the old session's streams must be
    /// closed now, before the new session opens its own.
    pub fn take_replaced(&mut self) -> Vec<u32> {
        std::mem::take(&mut self.replaced)
    }

    /// Addresses that a session left (it roamed) at least `grace` ago and
    /// that no session uses now: a TCP/TLS connection from one of them carries
    /// nothing any more. Each is reported once.
    pub fn take_vacated(&mut self, grace: std::time::Duration) -> Vec<SocketAddr> {
        if self.vacated.is_empty() {
            return Vec::new();
        }
        let now = std::time::Instant::now();
        let mut out = Vec::new();
        let addr_to_session = &self.addr_to_session;
        self.vacated.retain(|&(addr, since)| {
            if addr_to_session.contains_key(&addr) {
                return false;
            }
            if now.duration_since(since) < grace {
                return true;
            }
            out.push(addr);
            false
        });
        out
    }

    /// Streams the core reset on its own tick since the last call.
    pub fn take_resets(&mut self) -> Vec<(u32, u32)> {
        std::mem::take(&mut self.pending_resets)
    }

    pub fn outbound_to_session(&mut self, session_id: u32, stream_id: u32, payload: Bytes) -> Result<Option<(Bytes, SocketAddr)>> {
        let peer_state = if let Some(existing) = self.peer_machines.get_mut(&session_id) {
            existing
        } else {
            return Ok(None);
        };

        let addr = peer_state.last_addr;
        let key = peer_state.access_key.clone();
        match peer_state.machine.on_event(OstpEvent::Outbound(stream_id, payload))? {
            ProtocolAction::SendDatagram(frame) => {
                // Track outbound bytes per user
                track_user_bytes_down(&self.user_stats, &self.access_keys, &key, frame.len() as u64);
                Ok(Some((frame, addr)))
            }
            _ => Ok(None),
        }
    }

    /// v6: a payload that is not retransmitted or ordered (UDP).
    pub fn datagram_to_session(&mut self, session_id: u32, stream_id: u32, payload: Bytes) -> Result<Option<(Bytes, SocketAddr)>> {
        let Some(peer_state) = self.peer_machines.get_mut(&session_id) else {
            return Ok(None);
        };
        let addr = peer_state.last_addr;
        let key = peer_state.access_key.clone();
        match peer_state.machine.on_event(OstpEvent::OutboundDatagram(stream_id, payload))? {
            ProtocolAction::SendDatagram(frame) => {
                track_user_bytes_down(&self.user_stats, &self.access_keys, &key, frame.len() as u64);
                Ok(Some((frame, addr)))
            }
            _ => Ok(None),
        }
    }

    pub fn on_tick(&mut self) -> (Vec<(Bytes, SocketAddr)>, Vec<u32>) {
        let now = std::time::Instant::now();
        let housekeeping = self.last_housekeeping.map_or(true, |last| now.duration_since(last) >= HOUSEKEEPING_INTERVAL);
        if housekeeping {
            self.last_housekeeping = Some(now);
            // Purge expired handshakes from replay cache (older than 5 min drift allowance)
            let current_sys_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            self.replay_cache.retain(|_, &mut ts| current_sys_time.abs_diff(ts) <= 300);
            self.hs_replies.retain(|_, (ts, _)| current_sys_time.abs_diff(*ts) <= 300);

            // Drop cached secrets/junk-markers for keys that have been deleted, so the
            // caches can't grow without bound as keys churn.
            let keys = self.access_keys.read().unwrap_or_else(|e| e.into_inner());
            self.secrets_cache.retain(|k, _| keys.contains_key(k));
            self.junk_cache.retain(|k, _| keys.contains_key(k));
            self.stream_limits.retain(|k, _| keys.contains_key(k));
        }

        let mut dropped_earlier = std::mem::take(&mut self.dropped);
        let mut frames = Vec::new();
        let mut expired = Vec::new();
        let timeout_dur = std::time::Duration::from_secs(600); // 10 minute session timeout (mobile NAT can be up to 5-10min)

        // Gather expired or invalid sessions: one closed by its client on
        // every tick, the rest on the slow pass, with each lock taken once
        // (the order the hot reload takes them in: keys, then stats).
        {
            let keys = housekeeping.then(|| self.access_keys.read().unwrap_or_else(|e| e.into_inner()));
            let stats = housekeeping.then(|| self.user_stats.read().unwrap_or_else(|e| e.into_inner()));
            let unix_now = ostp_core::access_keys::unix_now();
            for (&sid, peer_state) in &self.peer_machines {
                if peer_state.machine.state() == OstpState::Closed {
                    expired.push(sid);
                    continue;
                }
                let (Some(keys), Some(stats)) = (&keys, &stats) else { continue };
                let meta = keys.get(&peer_state.access_key);
                let key_valid = meta.is_some();
                let key_expired = meta.is_some_and(|m| m.is_expired(unix_now));
                // No entry yet: nothing counted, so nothing over the limit.
                let over_limit = stats.get(&peer_state.access_key).is_some_and(|s| s.is_over_limit());
                if now.duration_since(peer_state.last_seen) > timeout_dur || !key_valid || key_expired || over_limit {
                    expired.push(sid);
                }
            }
        }

        // Clear expired/invalid sessions from internal state
        for sid in &expired {
            let peer_state_opt = self.peer_machines.get(sid);
            // Only a key that is gone or a limit that is used up is told to
            // the client; a session closed by the client or idle for ten
            // minutes has nobody to tell.
            let (reason, close) = if let Some(ps) = peer_state_opt {
                let (key_valid, key_expired) = match self.access_keys.read().unwrap_or_else(|e| e.into_inner()).get(&ps.access_key) {
                    Some(meta) => (true, meta.is_expired(ostp_core::access_keys::unix_now())),
                    None => (false, false),
                };
                let user_stats = self.get_or_create_user_stats(&ps.access_key);
                if ps.machine.state() == OstpState::Closed {
                    ("closed by the client", None)
                } else if now.duration_since(ps.last_seen) > timeout_dur {
                    ("inactive >10min", None)
                } else if !key_valid {
                    ("key deleted", Some(CloseReason::KeyRevoked))
                } else if key_expired {
                    ("key expired", Some(CloseReason::KeyExpired))
                } else if user_stats.is_over_limit() {
                    ("traffic limit exceeded", Some(CloseReason::TrafficLimit))
                } else {
                    ("unknown", None)
                }
            } else {
                ("unknown", None)
            };
            tracing::info!("Session {} closed ({}), releasing", sid, reason);
            match close {
                Some(close) => self.drop_session_with(*sid, close),
                None => self.drop_session(*sid),
            }
        }

        // The Close frames of sessions dropped since the last tick, then the
        // resends of those not yet acknowledged.
        frames.append(&mut self.pending_frames);
        let mut finished = Vec::new();
        for (&sid, c) in self.closing.iter_mut() {
            if c.machine.state() == OstpState::Closed || now.duration_since(c.since) > CLOSE_GRACE {
                finished.push(sid);
                continue;
            }
            let mut queue = vec![c.machine.on_event(OstpEvent::Tick)];
            while let Some(current) = queue.pop() {
                match current {
                    Ok(ProtocolAction::Multiple(list)) => queue.extend(list.into_iter().map(Ok)),
                    Ok(ProtocolAction::SendDatagram(frame)) => frames.push((frame, c.addr)),
                    _ => {}
                }
            }
            // The tick may have seen the acknowledgement.
            if c.machine.state() == OstpState::Closed {
                finished.push(sid);
            }
        }
        for sid in finished {
            self.closing.remove(&sid);
        }

        // Drive ticks for remaining active sessions
        for (&sid, peer_state) in self.peer_machines.iter_mut() {
            let action = match peer_state.machine.on_event(OstpEvent::Tick) {
                Ok(a) => a,
                Err(e) => {
                    tracing::warn!("Tick error for session: {}", e);
                    continue;
                }
            };

            let mut queue = vec![action];
            while let Some(current) = queue.pop() {
                match current {
                    ProtocolAction::Multiple(list) => {
                        for item in list {
                            queue.push(item);
                        }
                    }
                    ProtocolAction::SendDatagram(frame) => {
                        frames.push((frame, peer_state.last_addr));
                    }
                    // This side gave up on a frame of the stream (v6).
                    ProtocolAction::StreamReset(stream_id, _reason) => {
                        self.pending_resets.push((sid, stream_id));
                    }
                    _ => {}
                }
            }
        }

        // Sessions dropped between ticks (evicted for a key's cap, key removed, limit
        // reached) are reported too, so the relay closes their streams; an id that
        // a newer session has taken since is not theirs to close.
        self.dropped.clear();
        dropped_earlier.retain(|sid| !self.peer_machines.contains_key(sid) && !expired.contains(sid));
        expired.extend(dropped_earlier);
        (frames, expired)
    }

    /// A slot for one more connection of this session's key, held until the
    /// connection ends; `None` when the key has MAX_STREAMS_PER_KEY open.
    pub fn stream_permit(&mut self, session_id: u32) -> Option<tokio::sync::OwnedSemaphorePermit> {
        let key = self.peer_machines.get(&session_id)?.access_key.clone();
        let sem = self
            .stream_limits
            .entry(key)
            .or_insert_with(|| Arc::new(tokio::sync::Semaphore::new(MAX_STREAMS_PER_KEY)))
            .clone();
        sem.try_acquire_owned().ok()
    }

    /// Forgets the session without a word to the client (it is gone, idle,
    /// closed by itself, or a v5 one).
    pub fn drop_session(&mut self, session_id: u32) {
        let _ = self.remove_session(session_id);
    }

    /// Forgets the session and, if it is an established v6 one, tells the
    /// client why with an authenticated `Close`. The frame goes out with the
    /// next tick and is resent until acknowledged (`CLOSE_GRACE`). A v5
    /// session gets nothing, as before.
    pub fn drop_session_with(&mut self, session_id: u32, reason: CloseReason) {
        let Some(mut state) = self.remove_session(session_id) else { return };
        if !state.machine.is_v6() {
            return;
        }
        if let Ok(ProtocolAction::SendDatagram(frame)) = state.machine.on_event(OstpEvent::CloseWith(reason, String::new())) {
            self.pending_frames.push((frame, state.last_addr));
            if self.closing.len() < MAX_CLOSING {
                self.closing.insert(
                    session_id,
                    ClosingSession {
                        machine: state.machine,
                        addr: state.last_addr,
                        obfuscation_key: state.obfuscation_key,
                        since: std::time::Instant::now(),
                    },
                );
            }
        }
    }

    /// The server is stopping: every v6 session is told (`reason`), and from
    /// here on no new session is accepted. The frames go out with the next
    /// ticks, which the caller keeps running for a moment (`closing_pending`).
    pub fn close_all(&mut self, reason: CloseReason) {
        self.closing_only = true;
        let sids: Vec<u32> = self.peer_machines.keys().copied().collect();
        for sid in sids {
            self.drop_session_with(sid, reason);
        }
    }

    /// Sessions whose `Close` is not yet acknowledged.
    pub fn closing_pending(&self) -> usize {
        self.closing.len() + self.pending_frames.len()
    }

    /// An authenticated packet of a session that was sent a `Close` (its
    /// acknowledgement). Whether the packet belonged to one.
    fn feed_closing(&mut self, peer: SocketAddr, packet: &Bytes) -> bool {
        if packet.len() < 12 {
            return false;
        }
        for (&sid, c) in self.closing.iter_mut() {
            if c.addr != peer {
                continue;
            }
            let mut header = [0u8; 12];
            header.copy_from_slice(&packet[0..12]);
            ostp_core::crypto::deobfuscate_header_inplace(&mut header, &packet[12..], &c.obfuscation_key, false);
            if u32::from_be_bytes([header[0], header[1], header[2], header[3]]) == sid {
                // Authenticated by the machine; what it answers is dropped.
                let _ = c.machine.on_event(OstpEvent::Inbound(packet.clone()));
                return true;
            }
        }
        false
    }

    fn remove_session(&mut self, session_id: u32) -> Option<PeerState> {
        let state = self.peer_machines.remove(&session_id)?;
        // Its connects under way are not wanted any more.
        self.connecting.retain(|&(sid, _), _| sid != session_id);
        // A newer session of the same client may have taken this address;
        // removing its entry would push every packet of it onto the slow
        // roaming scan.
        if self.addr_to_session.get(&state.last_addr) == Some(&session_id) {
            self.addr_to_session.remove(&state.last_addr);
        }
        self.dropped.push(session_id);
        let stats = self.get_or_create_user_stats(&state.access_key);
        let _ = stats.connections.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| Some(n.saturating_sub(1)));
        Some(state)
    }
}

// Free functions to avoid borrow-checker conflicts when tracking stats
// while holding a mutable reference to peer_machines.

fn get_or_create_stats(
    user_stats: &Arc<RwLock<HashMap<String, Arc<UserStats>>>>,
    access_keys: &Arc<RwLock<HashMap<String, crate::api::UserMeta>>>,
    key: &str,
) -> Arc<UserStats> {
    {
        let stats = user_stats.read().unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = stats.get(key) {
            return existing.clone();
        }
    }
    
    let limit_bytes = access_keys.read().unwrap_or_else(|e| e.into_inner()).get(key).and_then(|m| m.limit_bytes);
    
    let mut stats = user_stats.write().unwrap_or_else(|e| e.into_inner());
    stats.entry(key.to_string())
        .or_insert_with(|| Arc::new(UserStats::new(limit_bytes)))
        .clone()
}

fn track_user_bytes_up(
    user_stats: &Arc<RwLock<HashMap<String, Arc<UserStats>>>>,
    access_keys: &Arc<RwLock<HashMap<String, crate::api::UserMeta>>>,
    key: &str,
    bytes: u64,
) {
    let stats = get_or_create_stats(user_stats, access_keys, key);
    stats.bytes_up.fetch_add(bytes, Ordering::Relaxed);
}

fn track_user_bytes_down(
    user_stats: &Arc<RwLock<HashMap<String, Arc<UserStats>>>>,
    access_keys: &Arc<RwLock<HashMap<String, crate::api::UserMeta>>>,
    key: &str,
    bytes: u64,
) {
    let stats = get_or_create_stats(user_stats, access_keys, key);
    stats.bytes_down.fetch_add(bytes, Ordering::Relaxed);
}

#[cfg(test)]
mod roaming_tests {
    use super::*;
    use ostp_core::{NoiseRole};

    const KEY: &str = "roaming-test-key";
    const SID: u32 = 0x1234_5678;

    fn base_config(role: NoiseRole) -> ProtocolConfig {
        ProtocolConfig {
            max_padding: 256,
            ..ProtocolConfig::with_defaults(role, 1350)
        }
    }

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn first_datagram(action: ProtocolAction) -> Bytes {
        match action {
            ProtocolAction::SendDatagram(d) => d,
            ProtocolAction::Multiple(list) => list
                .into_iter()
                .find_map(|a| match a {
                    ProtocolAction::SendDatagram(d) => Some(d),
                    _ => None,
                })
                .expect("no datagram in actions"),
            _ => panic!("expected a datagram"),
        }
    }

    /// A dispatcher and a client with an established session on `home`.
    fn established(home: SocketAddr) -> (Dispatcher, ProtocolMachine) {
        let keys = Arc::new(RwLock::new(HashMap::from([(KEY.to_string(), crate::api::UserMeta { name: None, limit_bytes: None, max_devices: None, expires_at: None })])));
        let mut dispatcher = Dispatcher::new(base_config(NoiseRole::Responder), keys);

        let secrets = ostp_core::crypto::derive_all_secrets(KEY.as_bytes());
        let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let mut payload = ts.to_be_bytes().to_vec();
        payload.extend_from_slice(&SID.to_be_bytes());
        payload.extend_from_slice(KEY.as_bytes());
        let mut cfg = base_config(NoiseRole::Initiator);
        cfg.session_id = SID;
        cfg.psk = secrets.psk;
        cfg.obfuscation_key = secrets.obfuscation_key;
        cfg.handshake_pad_min = secrets.handshake_pad_min;
        cfg.handshake_pad_max = secrets.handshake_pad_max;
        cfg.handshake_payload = payload;
        let mut client = ProtocolMachine::new(cfg).unwrap();

        let msg1 = first_datagram(client.on_event(OstpEvent::Start).unwrap());
        let msg2 = match dispatcher.on_datagram(home, msg1).unwrap() {
            DispatchOutcome::Accepted { mut responses, .. } => responses.remove(0),
            _ => panic!("handshake not accepted"),
        };
        client.on_event(OstpEvent::Inbound(msg2)).unwrap();
        (dispatcher, client)
    }

    fn send(client: &mut ProtocolMachine, data: &'static [u8]) -> Bytes {
        first_datagram(client.on_event(OstpEvent::Outbound(1, Bytes::from_static(data))).unwrap())
    }

    fn new_dispatcher() -> Dispatcher {
        let keys = Arc::new(RwLock::new(HashMap::from([(KEY.to_string(), crate::api::UserMeta { name: None, limit_bytes: None, max_devices: None, expires_at: None })])));
        Dispatcher::new(base_config(NoiseRole::Responder), keys)
    }

    fn handshake_payload() -> Vec<u8> {
        let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let mut payload = ts.to_be_bytes().to_vec();
        payload.extend_from_slice(&SID.to_be_bytes());
        payload.extend_from_slice(KEY.as_bytes());
        payload
    }

    /// A v6 client that knows `server_public`, and its first datagram.
    fn v6_client(server_public: [u8; 32]) -> (ProtocolMachine, Bytes) {
        let v6 = ostp_core::crypto::derive_v6_secrets(KEY.as_bytes());
        let mut cfg = base_config(NoiseRole::Initiator);
        cfg.session_id = SID;
        cfg.psk = v6.base.psk;
        cfg.obfuscation_key = v6.base.obfuscation_key;
        cfg.handshake_pad_min = v6.base.handshake_pad_min;
        cfg.handshake_pad_max = v6.base.handshake_pad_max;
        cfg.handshake_payload = handshake_payload();
        cfg.v6 = Some(ostp_core::protocol::V6Handshake {
            server: ostp_core::crypto::ServerStatic::Public(server_public),
            hs: v6.hs,
        });
        let mut client = ProtocolMachine::new(cfg).unwrap();
        let msg1 = first_datagram(client.on_event(OstpEvent::Start).unwrap());
        (client, msg1)
    }

    fn accepted_reply(outcome: DispatchOutcome) -> Option<Bytes> {
        match outcome {
            DispatchOutcome::Accepted { mut responses, .. } if !responses.is_empty() => Some(responses.remove(0)),
            _ => None,
        }
    }

    #[test]
    fn a_v6_client_connects_and_its_data_arrives() {
        let (private, public) = ostp_core::crypto::noise::generate_server_key();
        let mut dispatcher = new_dispatcher();
        dispatcher.set_wire_versions(Some(private), true);
        let (mut client, msg1) = v6_client(public);
        let home = addr("203.0.113.5:4000");
        let reply = accepted_reply(dispatcher.on_datagram(home, msg1).unwrap()).expect("the v6 handshake is accepted");
        client.on_event(OstpEvent::Inbound(reply)).unwrap();
        assert_eq!(client.state(), OstpState::Established);
        match dispatcher.on_datagram(home, send(&mut client, b"hello")).unwrap() {
            DispatchOutcome::Accepted { app_payloads, .. } => {
                assert_eq!(app_payloads.len(), 1);
                assert_eq!(&app_payloads[0].2[..], b"hello");
            }
            _ => panic!("the data was not accepted"),
        }
    }

    fn connected_v6() -> (Dispatcher, ProtocolMachine, SocketAddr) {
        let (private, public) = ostp_core::crypto::noise::generate_server_key();
        let mut dispatcher = new_dispatcher();
        dispatcher.set_wire_versions(Some(private), true);
        let (mut client, msg1) = v6_client(public);
        let home = addr("203.0.113.5:4000");
        let reply = accepted_reply(dispatcher.on_datagram(home, msg1).unwrap()).expect("the v6 handshake is accepted");
        client.on_event(OstpEvent::Inbound(reply)).unwrap();
        (dispatcher, client, home)
    }

    #[test]
    fn a_v6_session_has_windows_and_a_stream_limit_and_releases_streams() {
        let (mut dispatcher, _client, _) = connected_v6();
        assert!(dispatcher.is_v6(SID));
        assert!(dispatcher.flow_control(SID), "v6 streams have windows without the FEATURE message");
        for i in 0..ostp_core::streams::MAX_OPEN_STREAMS as u32 {
            dispatcher.open_stream(SID, 2 * i + 1).unwrap();
        }
        assert_eq!(dispatcher.open_stream(SID, 5001), Err(ostp_core::streams::StreamError::TooManyOpen));
        assert_eq!(dispatcher.open_stream(SID, 1), Err(ostp_core::streams::StreamError::Reused), "an open id");
        assert_eq!(dispatcher.open_stream(SID, 2), Err(ostp_core::streams::StreamError::WrongParity), "the server's parity");
        dispatcher.release_stream(SID, 1);
        dispatcher.open_stream(SID, 5001).expect("a released stream frees a slot");
        assert_eq!(dispatcher.open_stream(SID, 1), Err(ostp_core::streams::StreamError::Reused), "a released id is not reusable");
    }

    #[test]
    fn a_v5_session_has_no_flow_control_until_announced_and_no_stream_rules() {
        let (private, _) = ostp_core::crypto::noise::generate_server_key();
        let mut dispatcher = new_dispatcher();
        dispatcher.set_wire_versions(Some(private), true);
        let secrets = ostp_core::crypto::derive_all_secrets(KEY.as_bytes());
        let mut cfg = base_config(NoiseRole::Initiator);
        cfg.session_id = SID;
        cfg.psk = secrets.psk;
        cfg.obfuscation_key = secrets.obfuscation_key;
        cfg.handshake_pad_min = secrets.handshake_pad_min;
        cfg.handshake_pad_max = secrets.handshake_pad_max;
        cfg.handshake_payload = handshake_payload();
        let mut client = ProtocolMachine::new(cfg).unwrap();
        let msg1 = first_datagram(client.on_event(OstpEvent::Start).unwrap());
        accepted_reply(dispatcher.on_datagram(addr("203.0.113.5:4000"), msg1).unwrap()).expect("v5 accepted");
        assert!(!dispatcher.is_v6(SID));
        assert!(!dispatcher.flow_control(SID));
        dispatcher.set_flow_control(SID);
        assert!(dispatcher.flow_control(SID));
        dispatcher.release_stream(SID, 7); // a no-op, not an error
    }

    #[test]
    fn a_v6_datagram_arrives_as_a_datagram_in_both_directions() {
        let (mut dispatcher, mut client, home) = connected_v6();
        let dgram = datagram_frame(&mut client, 9, b"udp payload");
        match dispatcher.on_datagram(home, dgram).unwrap() {
            DispatchOutcome::Accepted { app_payloads, datagrams, .. } => {
                assert!(app_payloads.is_empty(), "a datagram is not stream data");
                assert_eq!(datagrams.len(), 1);
                assert_eq!((datagrams[0].0, datagrams[0].1, &datagrams[0].2[..]), (SID, 9, &b"udp payload"[..]));
            }
            _ => panic!("the datagram was not accepted"),
        }
        // A datagram goes back the same way.
        let (frame, to) = dispatcher.datagram_to_session(SID, 9, Bytes::from_static(b"reply")).unwrap().expect("sent");
        assert_eq!(to, home);
        fn find(a: ProtocolAction) -> Option<Bytes> {
            match a {
                ProtocolAction::DeliverDatagram(9, p) => Some(p),
                ProtocolAction::Multiple(list) => list.into_iter().find_map(find),
                _ => None,
            }
        }
        let got = find(client.on_event(OstpEvent::Inbound(frame)).unwrap()).expect("the client got the datagram");
        assert_eq!(&got[..], b"reply");
    }

    /// What the server does with a reset (the peer's, or this side giving up on
    /// a frame): the target is closed and the stream released; a reset of
    /// stream 0 ends the session.
    #[test]
    fn a_stream_reset_closes_its_target_and_stream_0_ends_the_session() {
        let (mut dispatcher, _client, _) = connected_v6();
        let (ui_tx, _ui_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut remotes = HashMap::new();
        dispatcher.open_stream(SID, 3).unwrap();
        let (cancel_tx, mut cancel_rx) = tokio::sync::mpsc::channel(1);
        remotes.insert(
            (SID, 3),
            crate::RemoteState {
                data_tx: None,
                halves: Default::default(),
                queued: Default::default(),
                udp_tx: None,
                cancel_tx,
                is_dns: false,
                window: None,
            },
        );
        crate::relay::reset_stream(SID, 3, &mut remotes, &mut dispatcher, &ui_tx);
        assert!(remotes.is_empty(), "the stream's target is dropped");
        assert!(cancel_rx.try_recv().is_ok(), "its reader is told to stop");
        assert_eq!(dispatcher.open_stream(SID, 3), Err(ostp_core::streams::StreamError::Reused), "the id is spent");
        assert_eq!(dispatcher.active_sessions(), 1, "another stream's reset does not end the session");

        crate::relay::reset_stream(SID, 0, &mut remotes, &mut dispatcher, &ui_tx);
        assert_eq!(dispatcher.active_sessions(), 0, "without the control stream the session is over");
    }

    fn datagram_frame(client: &mut ProtocolMachine, stream: u32, payload: &'static [u8]) -> Bytes {
        match client.on_event(OstpEvent::OutboundDatagram(stream, Bytes::from_static(payload))).unwrap() {
            ProtocolAction::SendDatagram(d) => d,
            _ => panic!("no datagram"),
        }
    }

    /// The transitional mode: the same server serves a 0.4.x client.
    #[test]
    fn a_v5_client_connects_only_while_v5_is_accepted() {
        let (private, _) = ostp_core::crypto::noise::generate_server_key();
        let v5_msg1 = || {
            let secrets = ostp_core::crypto::derive_all_secrets(KEY.as_bytes());
            let mut cfg = base_config(NoiseRole::Initiator);
            cfg.session_id = SID;
            cfg.psk = secrets.psk;
            cfg.obfuscation_key = secrets.obfuscation_key;
            cfg.handshake_pad_min = secrets.handshake_pad_min;
            cfg.handshake_pad_max = secrets.handshake_pad_max;
            cfg.handshake_payload = handshake_payload();
            let mut client = ProtocolMachine::new(cfg).unwrap();
            first_datagram(client.on_event(OstpEvent::Start).unwrap())
        };
        let home = addr("203.0.113.5:4000");

        let mut both = new_dispatcher();
        both.set_wire_versions(Some(private), true);
        assert!(accepted_reply(both.on_datagram(home, v5_msg1()).unwrap()).is_some());

        let mut v6_only = new_dispatcher();
        v6_only.set_wire_versions(Some(private), false);
        assert!(matches!(v6_only.on_datagram(home, v5_msg1()).unwrap(), DispatchOutcome::Unauthorized));
    }

    /// A client that knows another server key gets silence, like any stranger.
    #[test]
    fn a_v6_client_with_another_server_key_gets_no_answer() {
        let (private, _) = ostp_core::crypto::noise::generate_server_key();
        let (_, other_public) = ostp_core::crypto::noise::generate_server_key();
        let mut dispatcher = new_dispatcher();
        dispatcher.set_wire_versions(Some(private), false);
        let (_, msg1) = v6_client(other_public);
        assert!(matches!(dispatcher.on_datagram(addr("203.0.113.5:4000"), msg1).unwrap(), DispatchOutcome::Unauthorized));
        assert_eq!(dispatcher.active_sessions(), 0);
    }

    /// The reply was lost and the client sends its handshake again: the same
    /// reply comes back, the session is not created twice, and the reply
    /// still completes the client's handshake.
    #[test]
    fn a_repeated_v6_handshake_gets_the_same_reply() {
        let (private, public) = ostp_core::crypto::noise::generate_server_key();
        let mut dispatcher = new_dispatcher();
        dispatcher.set_wire_versions(Some(private), false);
        let (mut client, msg1) = v6_client(public);
        let home = addr("203.0.113.5:4000");
        let first = accepted_reply(dispatcher.on_datagram(home, msg1.clone()).unwrap()).expect("accepted");
        let again = accepted_reply(dispatcher.on_datagram(home, msg1.clone()).unwrap()).expect("answered again");
        assert_eq!(first, again);
        assert_eq!(dispatcher.active_sessions(), 1);
        // From another address too (the client's NAT mapping changed): the
        // answer goes there, the session stays where it was.
        let elsewhere = addr("198.51.100.9:5000");
        match dispatcher.on_datagram(elsewhere, msg1).unwrap() {
            DispatchOutcome::Accepted { responses, peer_addr, .. } => {
                assert_eq!(responses, vec![first.clone()]);
                assert_eq!(peer_addr, elsewhere);
            }
            _ => panic!("no answer to the repeated handshake"),
        }
        assert_eq!(dispatcher.active_sessions(), 1);
        client.on_event(OstpEvent::Inbound(again)).unwrap();
        assert_eq!(client.state(), OstpState::Established);
    }

    /// Found in wirelab (hs-corrupt, seeds 1, 5, 10): the padding is not
    /// authenticated, so a copy with a flipped padding bit is accepted; when
    /// its reply is lost the clean copy (another datagram hash) used to miss
    /// the cache and die in the replay check. The cache keys on the Noise
    /// message now.
    #[test]
    fn a_damaged_padding_copy_does_not_block_the_clean_one() {
        let (private, public) = ostp_core::crypto::noise::generate_server_key();
        let mut dispatcher = new_dispatcher();
        dispatcher.set_wire_versions(Some(private), false);
        let (mut client, msg1) = v6_client(public);
        let home = addr("203.0.113.5:4000");

        let mut damaged = msg1.to_vec();
        *damaged.last_mut().unwrap() ^= 1; // a bit of the padding
        assert_ne!(&damaged[..], &msg1[..]);
        // Accepted, and its reply is "lost": the client never sees it.
        let lost = accepted_reply(dispatcher.on_datagram(home, Bytes::from(damaged)).unwrap()).expect("the damaged copy is accepted");
        assert_eq!(dispatcher.active_sessions(), 1);

        let answered = accepted_reply(dispatcher.on_datagram(home, msg1).unwrap()).expect("the clean copy is answered");
        assert_eq!(answered, lost);
        assert_eq!(dispatcher.active_sessions(), 1, "no second session");
        client.on_event(OstpEvent::Inbound(answered)).unwrap();
        assert_eq!(client.state(), OstpState::Established);
    }

    /// A resend sealed anew (other nonce, other padding) is the same handshake.
    #[test]
    fn a_resealed_handshake_gets_the_cached_reply() {
        let (private, public) = ostp_core::crypto::noise::generate_server_key();
        let mut dispatcher = new_dispatcher();
        dispatcher.set_wire_versions(Some(private), false);
        let (mut client, msg1) = v6_client(public);
        let home = addr("203.0.113.5:4000");
        let first = accepted_reply(dispatcher.on_datagram(home, msg1.clone()).unwrap()).expect("accepted");
        for _ in 0..5 {
            let again = client.handshake_resend().unwrap().expect("a v6 resend");
            assert_ne!(again, msg1);
            let reply = accepted_reply(dispatcher.on_datagram(home, again).unwrap()).expect("answered from the cache");
            assert_eq!(reply, first);
        }
        assert_eq!(dispatcher.active_sessions(), 1);
        client.on_event(OstpEvent::Inbound(first)).unwrap();
        assert_eq!(client.state(), OstpState::Established);
    }

    // ── The session Close (v6) ───────────────────────────────────────────────

    /// What a client does with `frames`: the Close it was told, and the
    /// datagrams it answers with.
    fn client_reads(client: &mut ProtocolMachine, frames: &[Bytes]) -> (Option<(CloseReason, String)>, Vec<Bytes>) {
        fn walk(a: ProtocolAction, closed: &mut Option<(CloseReason, String)>, out: &mut Vec<Bytes>) {
            match a {
                ProtocolAction::PeerClosed(r, t) => *closed = Some((r, t)),
                ProtocolAction::SendDatagram(d) => out.push(d),
                ProtocolAction::Multiple(l) => l.into_iter().for_each(|x| walk(x, closed, out)),
                _ => {}
            }
        }
        let mut closed = None;
        let mut out = Vec::new();
        for f in frames {
            if let Ok(a) = client.on_event(OstpEvent::Inbound(f.clone())) {
                walk(a, &mut closed, &mut out);
            }
        }
        (closed, out)
    }

    fn frames_to(frames: &[(Bytes, SocketAddr)], to: SocketAddr) -> Vec<Bytes> {
        frames.iter().filter(|(_, a)| *a == to).map(|(f, _)| f.clone()).collect()
    }

    fn remove_key(dispatcher: &Dispatcher) {
        dispatcher.access_keys.write().unwrap().remove(KEY);
    }

    #[test]
    fn removing_a_key_sends_close_2_to_its_v6_session_which_is_resent_until_acknowledged() {
        let (mut dispatcher, mut client, home) = connected_v6();
        remove_key(&dispatcher);
        let (frames, dropped) = dispatcher.on_tick();
        assert_eq!(dropped, vec![SID]);
        assert_eq!(dispatcher.active_sessions(), 0, "the session is forgotten at once");
        let to_client = frames_to(&frames, home);
        assert_eq!(to_client.len(), 1);

        // Lost: after the retransmit wait the same Close comes again.
        std::thread::sleep(std::time::Duration::from_millis(300));
        let (again, _) = dispatcher.on_tick();
        assert!(!frames_to(&again, home).is_empty(), "an unacknowledged Close is resent");
        assert_eq!(dispatcher.closing_pending(), 1);

        let (closed, answers) = client_reads(&mut client, &to_client);
        assert_eq!(closed, Some((CloseReason::KeyRevoked, String::new())));
        // The acknowledgement ends the resending; it is not an unknown packet.
        for a in answers {
            assert!(matches!(dispatcher.on_datagram(home, a).unwrap(), DispatchOutcome::Junk));
        }
        let (rest, _) = dispatcher.on_tick();
        assert!(frames_to(&rest, home).is_empty());
        assert_eq!(dispatcher.closing_pending(), 0);
    }

    #[test]
    fn removing_a_key_sends_nothing_to_a_v5_session() {
        let home = addr("198.51.100.1:40000");
        let (mut dispatcher, _client) = established(home);
        remove_key(&dispatcher);
        let (frames, dropped) = dispatcher.on_tick();
        assert_eq!(dropped, vec![SID]);
        assert!(frames_to(&frames, home).is_empty(), "a v5 client is left in silence, as before");
        assert_eq!(dispatcher.closing_pending(), 0);
    }

    /// The first datagram of a v5 client that uses `key`.
    fn v5_first_datagram(key: &str, sid: u32) -> Bytes {
        let secrets = ostp_core::crypto::derive_all_secrets(key.as_bytes());
        let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let mut payload = ts.to_be_bytes().to_vec();
        payload.extend_from_slice(&sid.to_be_bytes());
        payload.extend_from_slice(key.as_bytes());
        let mut cfg = base_config(NoiseRole::Initiator);
        cfg.session_id = sid;
        cfg.psk = secrets.psk;
        cfg.obfuscation_key = secrets.obfuscation_key;
        cfg.handshake_pad_min = secrets.handshake_pad_min;
        cfg.handshake_pad_max = secrets.handshake_pad_max;
        cfg.handshake_payload = payload;
        let mut client = ProtocolMachine::new(cfg).unwrap();
        first_datagram(client.on_event(OstpEvent::Start).unwrap())
    }

    /// A transitional server (a server key and `accept_v5`) whose list holds
    /// only another key.
    fn transitional_with_other_key_only() -> (Dispatcher, [u8; 32]) {
        let keys = Arc::new(RwLock::new(HashMap::from([(
            "some-other-key-0123456789abcdef".to_string(),
            crate::api::UserMeta { name: None, limit_bytes: None, max_devices: None, expires_at: None },
        )])));
        let mut dispatcher = Dispatcher::new(base_config(NoiseRole::Responder), keys);
        let (private, public) = ostp_core::crypto::noise::generate_server_key();
        dispatcher.set_wire_versions(Some(private), true);
        (dispatcher, public)
    }

    #[test]
    fn a_v5_client_whose_key_is_not_listed_is_refused_in_the_transitional_mode() {
        let (mut dispatcher, _) = transitional_with_other_key_only();
        let home = addr("198.51.100.7:40000");
        let outcome = dispatcher.on_datagram(home, v5_first_datagram(KEY, SID)).unwrap();
        assert!(accepted_reply(outcome).is_none(), "an unlisted key must not get a handshake reply");
        assert_eq!(dispatcher.active_sessions(), 0);
    }

    #[test]
    fn a_v6_client_whose_key_is_not_listed_is_refused() {
        let (mut dispatcher, public) = transitional_with_other_key_only();
        let (_client, msg1) = v6_client(public);
        let outcome = dispatcher.on_datagram(addr("198.51.100.8:40000"), msg1).unwrap();
        assert!(accepted_reply(outcome).is_none(), "an unlisted key must not get a handshake reply");
        assert_eq!(dispatcher.active_sessions(), 0);
    }

    #[test]
    fn a_removed_v5_key_cannot_start_a_new_session() {
        let home = addr("198.51.100.9:40000");
        let (mut dispatcher, _client) = established(home);
        let (private, _) = ostp_core::crypto::noise::generate_server_key();
        dispatcher.set_wire_versions(Some(private), true);
        remove_key(&dispatcher);
        let (_, dropped) = dispatcher.on_tick();
        assert_eq!(dropped, vec![SID]);
        // The client reconnects with the same key: a new handshake, new session id.
        let outcome = dispatcher.on_datagram(home, v5_first_datagram(KEY, SID + 1)).unwrap();
        assert!(accepted_reply(outcome).is_none(), "a removed key must not open a session again");
        assert_eq!(dispatcher.active_sessions(), 0);
    }

    #[test]
    fn the_traffic_limit_sends_close_3() {
        let (mut dispatcher, mut client, home) = connected_v6();
        // A packet is counted; a limit of one byte is then used up.
        let d = datagram_frame(&mut client, 9, b"x");
        dispatcher.on_datagram(home, d).unwrap();
        dispatcher.set_user_limit(KEY, Some(1));
        let (frames, _) = dispatcher.on_tick();
        let (closed, _) = client_reads(&mut client, &frames_to(&frames, home));
        assert_eq!(closed.map(|c| c.0), Some(CloseReason::TrafficLimit));
        assert_eq!(dispatcher.active_sessions(), 0);
    }

    #[test]
    fn server_info_is_rate_limited_and_carries_the_key() {
        let (mut dispatcher, _client, _) = connected_v6();
        {
            let mut keys = dispatcher.access_keys.write().unwrap();
            let m = keys.get_mut(KEY).unwrap();
            m.limit_bytes = Some(1000);
            m.expires_at = Some(1_767_225_599);
            m.max_devices = Some(2);
        }
        let k = dispatcher.key_info(SID).unwrap();
        assert_eq!(k["limit_bytes"], 1000);
        assert_eq!(k["expires_at"], 1_767_225_599u64);
        assert_eq!(k["max_devices"], 2);
        assert!(k["used_bytes"].is_u64());
        assert!(dispatcher.allow_info_request(SID));
        assert!(!dispatcher.allow_info_request(SID), "one per interval");
        assert!(!dispatcher.allow_info_request(SID + 1), "no such session");
        assert!(dispatcher.key_info(SID + 1).is_none());
    }

    fn set_expiry(dispatcher: &Dispatcher, expires_at: Option<u64>) {
        dispatcher.access_keys.write().unwrap().get_mut(KEY).unwrap().expires_at = expires_at;
    }

    #[test]
    fn an_expiring_key_sends_close_6_to_its_live_session() {
        let (mut dispatcher, mut client, home) = connected_v6();
        // Not yet: the session stays.
        set_expiry(&dispatcher, Some(ostp_core::access_keys::unix_now() + 3600));
        let (_, dropped) = dispatcher.on_tick();
        assert!(dropped.is_empty());
        assert_eq!(dispatcher.active_sessions(), 1);
        // Past: the next slow pass closes it with the reason.
        set_expiry(&dispatcher, Some(1));
        dispatcher.last_housekeeping = None;
        let (frames, dropped) = dispatcher.on_tick();
        assert_eq!(dropped, vec![SID]);
        let (closed, _) = client_reads(&mut client, &frames_to(&frames, home));
        assert_eq!(closed.map(|c| c.0), Some(CloseReason::KeyExpired));
        assert_eq!(dispatcher.active_sessions(), 0);
    }

    #[test]
    fn an_expired_v6_key_completes_the_handshake_and_is_told_inside_the_tunnel() {
        let (private, public) = ostp_core::crypto::noise::generate_server_key();
        let mut dispatcher = new_dispatcher();
        dispatcher.set_wire_versions(Some(private), true);
        set_expiry(&dispatcher, Some(1));
        let (mut client, msg1) = v6_client(public);
        let home = addr("203.0.113.6:4000");
        let reply = accepted_reply(dispatcher.on_datagram(home, msg1).unwrap()).expect("the handshake is answered");
        client.on_event(OstpEvent::Inbound(reply)).unwrap();
        assert_eq!(client.state(), OstpState::Established);
        assert_eq!(dispatcher.active_sessions(), 0, "no session is kept for an expired key");
        let (frames, _) = dispatcher.on_tick();
        let (closed, _) = client_reads(&mut client, &frames_to(&frames, home));
        assert_eq!(closed.map(|c| c.0), Some(CloseReason::KeyExpired));
        let stats = dispatcher.user_stats_ref();
        assert_eq!(stats.read().unwrap()[KEY].connections.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn an_expired_v5_key_is_refused_like_a_used_up_limit() {
        let mut dispatcher = new_dispatcher();
        set_expiry(&dispatcher, Some(1));
        let outcome = dispatcher.on_datagram(addr("198.51.100.20:40000"), v5_first_datagram(KEY, SID)).unwrap();
        assert!(accepted_reply(outcome).is_none());
        assert_eq!(dispatcher.active_sessions(), 0);
    }

    fn v6_client_with_sid(server_public: [u8; 32], sid: u32) -> (ProtocolMachine, Bytes) {
        let v6 = ostp_core::crypto::derive_v6_secrets(KEY.as_bytes());
        let mut cfg = base_config(NoiseRole::Initiator);
        cfg.session_id = sid;
        cfg.psk = v6.base.psk;
        cfg.obfuscation_key = v6.base.obfuscation_key;
        cfg.handshake_pad_min = v6.base.handshake_pad_min;
        cfg.handshake_pad_max = v6.base.handshake_pad_max;
        let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let mut payload = ts.to_be_bytes().to_vec();
        payload.extend_from_slice(&sid.to_be_bytes());
        payload.extend_from_slice(KEY.as_bytes());
        cfg.handshake_payload = payload;
        cfg.v6 = Some(ostp_core::protocol::V6Handshake {
            server: ostp_core::crypto::ServerStatic::Public(server_public),
            hs: v6.hs,
        });
        let mut client = ProtocolMachine::new(cfg).unwrap();
        let msg1 = first_datagram(client.on_event(OstpEvent::Start).unwrap());
        (client, msg1)
    }

    #[test]
    fn the_per_key_cap_sends_close_4_to_the_evicted_session_only() {
        let (private, public) = ostp_core::crypto::noise::generate_server_key();
        let mut dispatcher = new_dispatcher();
        dispatcher.set_wire_versions(Some(private), true);
        let mut clients = Vec::new();
        for i in 0..=MAX_SESSIONS_PER_KEY as u32 {
            let (mut client, msg1) = v6_client_with_sid(public, SID + i);
            let from = addr(&format!("203.0.113.{}:4000", i + 1));
            let reply = accepted_reply(dispatcher.on_datagram(from, msg1).unwrap()).expect("accepted");
            client.on_event(OstpEvent::Inbound(reply)).unwrap();
            clients.push((client, from));
            // The oldest is told apart by when it was last seen.
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        assert_eq!(dispatcher.active_sessions(), MAX_SESSIONS_PER_KEY, "the 33rd took the place of the oldest");
        let (frames, dropped) = dispatcher.on_tick();
        assert_eq!(dropped, vec![SID]);
        let (first, first_addr) = {
            let (c, a) = &mut clients[0];
            (c, *a)
        };
        let (closed, _) = client_reads(first, &frames_to(&frames, first_addr));
        assert_eq!(closed.map(|c| c.0), Some(CloseReason::TooManySessions));
        for (i, (client, from)) in clients.iter_mut().enumerate().skip(1) {
            let (closed, _) = client_reads(client, &frames_to(&frames, *from));
            assert!(closed.is_none(), "session {i} is not told anything");
        }
    }

    #[test]
    fn a_stopping_server_sends_close_5_and_takes_no_new_session() {
        let (mut dispatcher, mut client, home) = connected_v6();
        dispatcher.close_all(CloseReason::ServerShutdown);
        let (frames, _) = dispatcher.on_tick();
        let (closed, _) = client_reads(&mut client, &frames_to(&frames, home));
        assert_eq!(closed.map(|c| c.0), Some(CloseReason::ServerShutdown));

        let (_, public) = ostp_core::crypto::noise::generate_server_key();
        let (_, msg1) = v6_client_with_sid(public, SID + 1);
        assert!(matches!(dispatcher.on_datagram(addr("203.0.113.77:4000"), msg1).unwrap(), DispatchOutcome::Unauthorized));
        assert_eq!(dispatcher.active_sessions(), 0);
    }

    /// Stealth: an unauthenticated packet gets nothing, even from the address
    /// of a session that is being closed.
    #[test]
    fn a_packet_that_does_not_authenticate_gets_no_close() {
        let (mut dispatcher, mut client, home) = connected_v6();
        let datagram = datagram_frame(&mut client, 9, b"x");
        remove_key(&dispatcher);
        let _ = dispatcher.on_tick();
        let mut forged = datagram.to_vec();
        let last = forged.len() - 1;
        forged[last] ^= 0xff;
        // Right header, broken tag: swallowed, and no new Close is built for it.
        let _ = dispatcher.on_datagram(home, Bytes::from(forged));
        let stranger = addr("192.0.2.200:9999");
        assert!(matches!(dispatcher.on_datagram(stranger, Bytes::from(vec![7u8; 90])).unwrap(), DispatchOutcome::Unauthorized));
        let (frames, _) = dispatcher.on_tick();
        assert!(frames_to(&frames, stranger).is_empty());
    }

    fn reply_addr(outcome: DispatchOutcome) -> SocketAddr {
        match outcome {
            DispatchOutcome::Accepted { peer_addr, .. } => peer_addr,
            _ => panic!("packet not accepted"),
        }
    }

    #[test]
    fn replayed_packet_from_another_address_does_not_move_the_session() {
        let home = addr("198.51.100.1:40000");
        let attacker = addr("203.0.113.9:5555");
        let (mut dispatcher, mut client) = established(home);

        let d1 = send(&mut client, b"one");
        assert_eq!(reply_addr(dispatcher.on_datagram(home, d1.clone()).unwrap()), home);

        // The same bytes again, from somewhere else: authentic, but not new.
        let outcome = dispatcher.on_datagram(attacker, d1).unwrap();
        assert_eq!(reply_addr(outcome), home, "replies must stay on the session's address");
        assert_eq!(dispatcher.peer_machines[&SID].last_addr, home);
        assert_eq!(dispatcher.addr_to_session.get(&attacker), None);
    }

    #[test]
    fn replay_of_a_buffered_out_of_order_packet_does_not_move_the_session() {
        let home = addr("198.51.100.1:40000");
        let attacker = addr("203.0.113.9:5555");
        let (mut dispatcher, mut client) = established(home);

        let _lost = send(&mut client, b"one");
        let d2 = send(&mut client, b"two");
        let d3 = send(&mut client, b"three");
        // d2 and d3 wait in the reorder buffer behind the lost d1.
        dispatcher.on_datagram(home, d2.clone()).unwrap();
        dispatcher.on_datagram(home, d3).unwrap();

        dispatcher.on_datagram(attacker, d2).unwrap();
        assert_eq!(dispatcher.peer_machines[&SID].last_addr, home);
    }

    #[test]
    fn garbage_with_a_valid_header_does_not_move_the_session() {
        let home = addr("198.51.100.1:40000");
        let attacker = addr("203.0.113.9:5555");
        let (mut dispatcher, mut client) = established(home);

        let mut forged = send(&mut client, b"one").to_vec();
        let last = forged.len() - 1;
        forged[last] ^= 0xff; // breaks the Poly1305 tag
        assert!(matches!(
            dispatcher.on_datagram(attacker, Bytes::from(forged)).unwrap(),
            DispatchOutcome::Unauthorized
        ));
        assert_eq!(dispatcher.peer_machines[&SID].last_addr, home);
    }

    #[test]
    fn a_new_packet_from_a_new_address_roams() {
        let home = addr("198.51.100.1:40000");
        let roamed = addr("192.0.2.77:61000");
        let (mut dispatcher, mut client) = established(home);

        let d1 = send(&mut client, b"one");
        dispatcher.on_datagram(home, d1).unwrap();

        let d2 = send(&mut client, b"two");
        assert_eq!(reply_addr(dispatcher.on_datagram(roamed, d2).unwrap()), roamed);
        assert_eq!(dispatcher.peer_machines[&SID].last_addr, roamed);
        assert_eq!(dispatcher.addr_to_session.get(&roamed), Some(&SID));
        assert_eq!(dispatcher.addr_to_session.get(&home), None);
    }

    /// A key removed after the first tick is noticed on the next slow pass,
    /// not on every 10 ms tick.
    #[test]
    fn expiry_checks_run_on_the_slow_pass() {
        let (mut dispatcher, _client) = established(addr("198.51.100.1:40000"));
        assert!(dispatcher.on_tick().1.is_empty());
        remove_key(&dispatcher);
        assert!(dispatcher.on_tick().1.is_empty(), "not checked again within the interval");
        dispatcher.last_housekeeping = Some(std::time::Instant::now() - HOUSEKEEPING_INTERVAL);
        assert_eq!(dispatcher.on_tick().1, vec![SID]);
    }

    /// A new handshake that takes the id of a session dropped since the last
    /// tick reports the id at once, so the old session's streams are closed
    /// before the new one opens its own; the tick no longer reports it.
    #[test]
    fn a_reused_session_id_is_reported_as_replaced() {
        let (private, public) = ostp_core::crypto::noise::generate_server_key();
        let mut dispatcher = new_dispatcher();
        dispatcher.set_wire_versions(Some(private), true);
        let (_c1, msg1) = v6_client_with_sid(public, SID);
        assert!(accepted_reply(dispatcher.on_datagram(addr("203.0.113.1:4000"), msg1).unwrap()).is_some());
        assert!(dispatcher.take_replaced().is_empty());
        // The handshake payload carries the time in seconds: in the same
        // second the second one would be the same payload, a replay.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let (_c2, msg2) = v6_client_with_sid(public, SID);
        assert!(accepted_reply(dispatcher.on_datagram(addr("203.0.113.2:4000"), msg2).unwrap()).is_some());
        assert_eq!(dispatcher.take_replaced(), vec![SID]);
        assert_eq!(dispatcher.active_sessions(), 1);
    }

    /// A connect that completes after its stream ended, or after its session
    /// was replaced, is not wanted.
    #[test]
    fn a_connect_that_outlives_its_stream_is_dropped() {
        let (mut dispatcher, _client) = established(addr("198.51.100.1:40000"));
        let t1 = dispatcher.begin_connect(SID, 1);
        assert!(dispatcher.finish_connect(SID, 1, t1));
        let t3 = dispatcher.begin_connect(SID, 3);
        dispatcher.release_stream(SID, 3);
        assert!(!dispatcher.finish_connect(SID, 3, t3), "the stream was closed meanwhile");
        let t5 = dispatcher.begin_connect(SID, 5);
        dispatcher.drop_session(SID);
        assert!(!dispatcher.finish_connect(SID, 5, t5), "the session ended meanwhile");
    }

    /// The address a session roamed away from is reported after the grace
    /// period, once, and not while a session uses it again.
    #[test]
    fn a_vacated_address_is_reported_after_the_grace() {
        let home = addr("198.51.100.1:40000");
        let roamed = addr("198.51.100.2:40001");
        let (mut dispatcher, mut client) = established(home);
        let d1 = send(&mut client, b"one");
        dispatcher.on_datagram(home, d1).unwrap();
        let d2 = send(&mut client, b"two");
        dispatcher.on_datagram(roamed, d2).unwrap();
        assert!(dispatcher.take_vacated(std::time::Duration::from_secs(60)).is_empty());
        assert_eq!(dispatcher.take_vacated(std::time::Duration::ZERO), vec![home]);
        assert!(dispatcher.take_vacated(std::time::Duration::ZERO).is_empty());
    }

    #[test]
    fn a_session_dropped_between_ticks_is_reported_once_by_the_next_tick() {
        let (mut dispatcher, _client) = established(addr("198.51.100.1:40000"));
        dispatcher.drop_session(SID);
        let (_, dropped) = dispatcher.on_tick();
        assert_eq!(dropped, vec![SID], "its streams must be closed");
        assert!(dispatcher.on_tick().1.is_empty());
    }

    #[test]
    fn dropping_an_old_session_keeps_the_address_of_a_newer_one() {
        let home = addr("198.51.100.1:40000");
        let (mut dispatcher, _client) = established(home);
        dispatcher.addr_to_session.insert(home, SID + 1);
        dispatcher.drop_session(SID);
        assert_eq!(dispatcher.addr_to_session.get(&home), Some(&(SID + 1)));
    }

    fn live_sessions(dispatcher: &Dispatcher) -> u64 {
        dispatcher.user_stats.read().unwrap()[KEY].connections.load(Ordering::Relaxed)
    }

    #[test]
    fn sessions_count_live_ones_and_a_client_close_frees_its_session() {
        let home = addr("198.51.100.1:40000");
        let (mut dispatcher, mut client) = established(home);
        assert_eq!(live_sessions(&dispatcher), 1);

        let close = first_datagram(client.on_event(OstpEvent::Close).unwrap());
        dispatcher.on_datagram(home, close).unwrap();
        let (_, dropped) = dispatcher.on_tick();
        assert_eq!(dropped, vec![SID], "a closed session is freed on the next tick");
        assert_eq!(live_sessions(&dispatcher), 0);
        assert_eq!(dispatcher.active_sessions(), 0);

        // Dropping again (or a session that is already gone) never goes below zero.
        dispatcher.drop_session(SID);
        assert_eq!(live_sessions(&dispatcher), 0);
    }
}
