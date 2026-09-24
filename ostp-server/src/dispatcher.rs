use anyhow::Result;
use bytes::Bytes;
use ostp_core::{OstpEvent, ProtocolAction, ProtocolConfig, ProtocolMachine};
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
        app_payloads: Vec<(u32, u16, Bytes)>, // session_id, stream_id, payload
        peer_addr: SocketAddr,
    },
}

/// Per-user traffic statistics.
pub struct UserStats {
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
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
#[derive(Debug, Clone, serde::Serialize)]
pub struct UserStatsSnapshot {
    pub access_key: String,
    pub name: Option<String>,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub connections: u64,
    pub limit_bytes: Option<u64>,
    pub online: bool,
    pub last_seen: Option<u64>,
}

pub struct PeerState {
    pub machine: ProtocolMachine,
    pub last_addr: SocketAddr,
    pub obfuscation_key: [u8; 8],
    pub last_seen: std::time::Instant,
    pub access_key: String,
}

pub struct Dispatcher {
    peer_machines: HashMap<u32, PeerState>,
    addr_to_session: HashMap<SocketAddr, u32>,
    machine_config: ProtocolConfig,
    access_keys: Arc<RwLock<HashMap<String, crate::api::UserMeta>>>,
    user_stats: Arc<RwLock<HashMap<String, Arc<UserStats>>>>,
    replay_cache: std::collections::HashMap<Vec<u8>, u64>,
    roaming_tokens: f64,
    last_token_regen: std::time::Instant,
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
    /// Token bucket bounding how many expensive new-handshake key-trials we run
    /// per second. The existing-session fast path and roaming path are NOT gated
    /// by this; only the O(N_keys) trial over unknown datagrams is, so a garbage
    /// flood from spoofed sources can't force unbounded per-packet crypto work.
    trial_tokens: f64,
    last_trial_regen: std::time::Instant,
}

/// Sustained rate (and burst ceiling) of new-handshake trials per second. Legit
/// first-connect packets are rare, so this is generous for real use while still
/// capping flood-driven trial work at TRIAL_RATE × num_keys crypto ops/sec.
const TRIAL_RATE: f64 = 100.0;

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
            roaming_tokens: 50.0,
            last_token_regen: std::time::Instant::now(),
            secrets_cache: HashMap::new(),
            junk_cache: HashMap::new(),
            trial_tokens: TRIAL_RATE,
            last_trial_regen: std::time::Instant::now(),
        }
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

    /// Active session count.
    pub fn active_sessions(&self) -> usize {
        self.peer_machines.len()
    }

    /// Per-session download-direction congestion headroom, in packets:
    /// `(session_id, available)` where `available = clamped cwnd - in_flight`.
    ///
    /// Consumed by the relay's per-target-connection reader tasks (see
    /// `relay::handle_relay_message`'s Connect handler) to throttle how fast
    /// they pull bytes from the upstream target and forward them to the
    /// client's OSTP session. Without this, a fast target (e.g. a CDN) gets
    /// read and forwarded as fast as the target can serve, completely
    /// ignoring the client-facing session's real congestion window - on a
    /// lossy/jittery client path that self-inflicts a loss burst, which
    /// wrecks the RTT/RTO estimate and can stall the session hard enough to
    /// trip the client's keepalive reconnect. Same clamp(16, 16384) the
    /// client uses for its own analogous uplink gate, for symmetry.
    pub fn snapshot_backpressure(&self) -> Vec<(u32, i64)> {
        self.peer_machines
            .iter()
            .map(|(&sid, ps)| {
                // Ceiling matches MAX_CWND_PACKETS in ostp-core. The old 16384
                // allowed ~20 MB outstanding toward one client — on a mobile
                // downlink that is standing queue, not throughput, and it is the
                // download direction that carries video.
                let cwnd = (ps.machine.cwnd_packets() as i64).clamp(16, 1024);
                let in_flight = ps.machine.in_flight_count() as i64;
                // Pacing gates the RATE, cwnd only the outstanding amount. With
                // the pacing bucket empty, report no headroom so the relay
                // reader pauses instead of handing over another chunk that would
                // leave back-to-back.
                if !ps.machine.can_pace_packet() {
                    return (sid, 0);
                }
                (sid, cwnd - in_flight)
            })
            .collect()
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
            // Token Bucket rate limiter: mitigate seamless roaming CPU DoS vector
            let now = std::time::Instant::now();
            let elapsed = now.duration_since(self.last_token_regen).as_secs_f64();
            self.last_token_regen = now;
            self.roaming_tokens = (self.roaming_tokens + elapsed * 50.0).min(50.0);

            if self.roaming_tokens >= 1.0 {
                self.roaming_tokens -= 1.0;

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
                // Check if key is still valid and not over limit
                let key_valid = self.access_keys.read().unwrap_or_else(|e| e.into_inner()).contains_key(&access_key);
                let user_stats = self.get_or_create_user_stats(&access_key);
                if !key_valid || user_stats.is_over_limit() {
                    tracing::info!("Dropping session {} for key {} (valid={}, over_limit={})",
                        session_id, key_fp(&access_key), key_valid, user_stats.is_over_limit());
                    self.drop_session(session_id);
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
                        tracing::warn!("Protocol error for session {}: {}", session_id, e);
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
                    tracing::info!("Client roamed: session {} from {} to {}", session_id, peer_state.last_addr, peer);
                    self.addr_to_session.remove(&peer_state.last_addr);
                    peer_state.last_addr = peer;
                    self.addr_to_session.insert(peer, session_id);
                }
                if peer_state.last_addr == peer {
                    peer_state.last_seen = std::time::Instant::now();
                }
                let reply_addr = peer_state.last_addr;

                let mut responses = Vec::new();
                let mut app_payloads = Vec::new();

                fn collect_action(
                    act: ProtocolAction,
                    sid: u32,
                    resps: &mut Vec<Bytes>,
                    loads: &mut Vec<(u32, u16, Bytes)>,
                ) {
                    match act {
                        ProtocolAction::SendDatagram(frame) => {
                            resps.push(frame);
                        }
                        ProtocolAction::DeliverApp(stream_id, data) => {
                            loads.push((sid, stream_id, data));
                        }
                        ProtocolAction::Multiple(list) => {
                            for item in list {
                                collect_action(item, sid, resps, loads);
                            }
                        }
                        _ => {}
                    }
                }

                collect_action(action, session_id, &mut responses, &mut app_payloads);

                return Ok(DispatchOutcome::Accepted {
                    responses,
                    app_payloads,
                    peer_addr: reply_addr,
                });
            }
        }

        // Not an existing session — this is the expensive O(N_keys) trial path.
        // Gate it behind a token bucket so a garbage/spoofed-source flood cannot
        // force unbounded per-packet crypto work. Existing sessions (fast path
        // above) and roaming are unaffected. Regenerate at TRIAL_RATE/sec.
        {
            let now = std::time::Instant::now();
            let elapsed = now.duration_since(self.last_trial_regen).as_secs_f64();
            self.last_trial_regen = now;
            self.trial_tokens = (self.trial_tokens + elapsed * TRIAL_RATE).min(TRIAL_RATE);
            if self.trial_tokens < 1.0 {
                // Out of budget: drop silently (no response, no state, no log spam).
                return Ok(DispatchOutcome::Unauthorized);
            }
            self.trial_tokens -= 1.0;
        }

        let keys_snapshot: Vec<String> = self.access_keys.read().unwrap_or_else(|e| e.into_inner()).keys().cloned().collect();

        // Junk marker rotates per time window; check the current and previous
        // window so a client whose clock is up to ~1 window behind/ahead is still
        // recognised. Computed once per datagram, not per candidate key.
        let junk_window = ostp_core::crypto::current_junk_window();

        for candidate_key in keys_snapshot {
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
            let candidate_session_id = u32::from_be_bytes([trial[0], trial[1], trial[2], trial[3]]);

            let mut cfg = self.machine_config.clone();
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

                        let drift = (now as i64 - ts as i64).abs();
                        if drift > 300 {
                            tracing::warn!("Handshake rejected: timestamp drift {}s exceeds 300s limit (peer={})", drift, peer);
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
                                    (now as i64 - cached_ts as i64).abs() <= 300
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
                                tracing::warn!("Max sessions reached ({}), rejecting handshake from {}", MAX_SESSIONS, peer);
                                return Ok(DispatchOutcome::Unauthorized);
                            }

                            self.replay_cache.insert(payload.to_vec(), ts);

                            machine.set_session_keys(candidate_session_id, secrets.obfuscation_key);

                            // Track per-user connection count
                            let user_stats = self.get_or_create_user_stats(&candidate_key);
                            user_stats.connections.fetch_add(1, Ordering::Relaxed);

                            // Check traffic limit before accepting
                            if user_stats.is_over_limit() {
                                tracing::warn!("User {} exceeded traffic limit, rejecting handshake from {}", key_fp(&candidate_key), peer);
                                return Ok(DispatchOutcome::Unauthorized);
                            }

                            self.peer_machines.insert(candidate_session_id, PeerState {
                                machine,
                                last_addr: peer,
                                obfuscation_key: secrets.obfuscation_key,
                                last_seen: std::time::Instant::now(),
                                access_key: candidate_key.clone(),
                            });
                            self.addr_to_session.insert(peer, candidate_session_id);

                            tracing::info!("New session authenticated: sid={} peer={} (active_sessions={}, replay_cache={})",
                                candidate_session_id, peer, self.peer_machines.len(), self.replay_cache.len()
                            );

                            return Ok(DispatchOutcome::Accepted {
                                responses: response_opt.into_iter().collect(),
                                app_payloads: Vec::new(),
                                peer_addr: peer,
                            });
                        }
                    }
                }
            }
        }

        Ok(DispatchOutcome::Unauthorized)
    }

    pub fn outbound_to_session(&mut self, session_id: u32, stream_id: u16, payload: Bytes) -> Result<Option<(Bytes, SocketAddr)>> {
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

    pub fn on_tick(&mut self) -> (Vec<(Bytes, SocketAddr)>, Vec<u32>) {
        // Purge expired handshakes from replay cache (older than 5 min drift allowance)
        let current_sys_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.replay_cache.retain(|_, &mut ts| (current_sys_time as i64 - ts as i64).abs() <= 300);

        // Drop cached secrets/junk-markers for keys that have been deleted, so the
        // caches can't grow without bound as keys churn.
        {
            let keys = self.access_keys.read().unwrap_or_else(|e| e.into_inner());
            self.secrets_cache.retain(|k, _| keys.contains_key(k));
            self.junk_cache.retain(|k, _| keys.contains_key(k));
        }

        let mut frames = Vec::new();
        let mut expired = Vec::new();
        let now = std::time::Instant::now();
        let timeout_dur = std::time::Duration::from_secs(600); // 10 minute session timeout (mobile NAT can be up to 5-10min)

        // Gather expired or invalid sessions
        for (&sid, peer_state) in &self.peer_machines {
            let key_valid = self.access_keys.read().unwrap_or_else(|e| e.into_inner()).contains_key(&peer_state.access_key);
            let user_stats = self.get_or_create_user_stats(&peer_state.access_key);
            if now.duration_since(peer_state.last_seen) > timeout_dur || !key_valid || user_stats.is_over_limit() {
                expired.push(sid);
            }
        }

        // Clear expired/invalid sessions from internal state
        for sid in &expired {
            let peer_state_opt = self.peer_machines.get(sid);
            let reason = if let Some(ps) = peer_state_opt {
                let key_valid = self.access_keys.read().unwrap_or_else(|e| e.into_inner()).contains_key(&ps.access_key);
                let user_stats = self.get_or_create_user_stats(&ps.access_key);
                if now.duration_since(ps.last_seen) > timeout_dur {
                    "inactive >5min"
                } else if !key_valid {
                    "key deleted"
                } else if user_stats.is_over_limit() {
                    "traffic limit exceeded"
                } else {
                    "unknown"
                }
            } else {
                "unknown"
            };
            tracing::info!("Session {} closed ({}), releasing", sid, reason);
            self.drop_session(*sid);
        }

        // Drive ticks for remaining active sessions
        for peer_state in self.peer_machines.values_mut() {
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
                    _ => {}
                }
            }
        }

        (frames, expired)
    }

    pub fn drop_session(&mut self, session_id: u32) {
        if let Some(state) = self.peer_machines.remove(&session_id) {
            self.addr_to_session.remove(&state.last_addr);
        }
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
    use ostp_core::{NoiseRole, PaddingStrategy};

    const KEY: &str = "roaming-test-key";
    const SID: u32 = 0x1234_5678;

    fn base_config(role: NoiseRole) -> ProtocolConfig {
        ProtocolConfig {
            role,
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
            handshake_pad_min: 32,
            handshake_pad_max: 128,
            mtu: 1350,
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
        let keys = Arc::new(RwLock::new(HashMap::from([(KEY.to_string(), crate::api::UserMeta { name: None, limit_bytes: None })])));
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
}
