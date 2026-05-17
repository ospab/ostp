use anyhow::Result;
use bytes::Bytes;
use ostp_core::{OstpEvent, ProtocolAction, ProtocolConfig, ProtocolMachine};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

/// Maximum number of concurrent authenticated sessions.
/// Excess handshake attempts are silently dropped — no response, no state allocated.
const MAX_SESSIONS: usize = 1024;

pub enum DispatchOutcome {
    Unauthorized,
    Accepted {
        responses: Vec<Bytes>,
        app_payloads: Vec<(u32, u16, Bytes)>, // session_id, stream_id, payload
        peer_addr: SocketAddr,
    },
}

pub struct PeerState {
    pub machine: ProtocolMachine,
    pub last_addr: SocketAddr,
    pub obfuscation_key: [u8; 8],
    pub last_seen: std::time::Instant,
}

pub struct Dispatcher {
    peer_machines: HashMap<u32, PeerState>,
    addr_to_session: HashMap<SocketAddr, u32>,
    machine_config: ProtocolConfig,
    access_keys: Arc<RwLock<HashMap<String, ()>>>,
    replay_cache: std::collections::HashMap<Vec<u8>, u64>,
    roaming_tokens: f64,
    last_token_regen: std::time::Instant,
}

impl Dispatcher {
    pub fn new(machine_config: ProtocolConfig, access_keys: Arc<RwLock<HashMap<String, ()>>>) -> Self {
        Self {
            peer_machines: HashMap::new(),
            addr_to_session: HashMap::new(),
            machine_config,
            access_keys,
            replay_cache: std::collections::HashMap::new(),
            roaming_tokens: 50.0,
            last_token_regen: std::time::Instant::now(),
        }
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
            if let Some(peer_state) = self.peer_machines.get_mut(&session_id) {
                if peer_state.last_addr != peer {
                    eprintln!("[ostp] Client roamed: session {} from {} to {}", session_id, peer_state.last_addr, peer);
                    self.addr_to_session.remove(&peer_state.last_addr);
                }
                peer_state.last_addr = peer;
                peer_state.last_seen = std::time::Instant::now();
                self.addr_to_session.insert(peer, session_id);
                
                let action = match peer_state.machine.on_event(OstpEvent::Inbound(packet)) {
                    Ok(a) => a,
                    Err(e) => {
                        eprintln!("[ostp] Protocol error for session {}: {}", session_id, e);
                        return Ok(DispatchOutcome::Unauthorized);
                    }
                };

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
                    peer_addr: peer,
                });
            }
        }

        // Not an existing session — try each registered access key's derived obfuscation key
        let keys_snapshot: Vec<String> = self.access_keys.read().unwrap().keys().cloned().collect();

        for candidate_key in keys_snapshot {
            let obf_key = ostp_core::crypto::derive_obfuscation_key(candidate_key.as_bytes());
            let psk = ostp_core::crypto::derive_psk(candidate_key.as_bytes());

            // Decode the session_id using this key's obfuscation
            // The handshake mask is derived from the Noise payload at bytes [6..],
            // so we must deobfuscate the full packet, not just the header.
            if packet.len() < 7 { continue; }
            let mut trial = packet.to_vec();
            ostp_core::crypto::deobfuscate_packet_inplace(&mut trial, &obf_key, true);
            let candidate_session_id = u32::from_be_bytes([trial[0], trial[1], trial[2], trial[3]]);

            let mut cfg = self.machine_config.clone();
            cfg.session_id = candidate_session_id;
            cfg.psk = psk;
            cfg.handshake_payload = vec![];
            cfg.obfuscation_key = obf_key;

            let mut machine = match ProtocolMachine::new(cfg) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("[ostp] Failed to create protocol machine for key trial: {}", e);
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
                            eprintln!("[ostp] Handshake rejected: timestamp drift {}s exceeds 300s limit (peer={})", drift, peer);
                            continue;
                        }

                        if !self.replay_cache.contains_key(&payload.to_vec()) {
                            if self.replay_cache.len() >= 100_000 {
                                eprintln!("[ostp] Replay cache full (100000 entries), rejecting handshake from {}", peer);
                                return Ok(DispatchOutcome::Unauthorized);
                            }
                            if self.peer_machines.len() >= MAX_SESSIONS {
                                eprintln!("[ostp] Max sessions reached ({}), rejecting handshake from {}", MAX_SESSIONS, peer);
                                return Ok(DispatchOutcome::Unauthorized);
                            }

                            self.replay_cache.insert(payload.to_vec(), ts);

                            machine.set_session_keys(candidate_session_id, obf_key);

                            self.peer_machines.insert(candidate_session_id, PeerState {
                                machine,
                                last_addr: peer,
                                obfuscation_key: obf_key,
                                last_seen: std::time::Instant::now(),
                            });
                            self.addr_to_session.insert(peer, candidate_session_id);

                            eprintln!(
                                "[ostp] New session authenticated: sid={} peer={} (active_sessions={}, replay_cache={})",
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
        match peer_state.machine.on_event(OstpEvent::Outbound(stream_id, payload))? {
            ProtocolAction::SendDatagram(frame) => Ok(Some((frame, addr))),
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

        let mut frames = Vec::new();
        let mut expired = Vec::new();
        let now = std::time::Instant::now();
        let timeout_dur = std::time::Duration::from_secs(300); // 5 minutes session timeout

        // Gather expired sessions
        for (&sid, peer_state) in &self.peer_machines {
            if now.duration_since(peer_state.last_seen) > timeout_dur {
                expired.push(sid);
            }
        }

        // Clear expired sessions from internal state
        for sid in &expired {
            eprintln!("[ostp] Session {} expired (inactive >5min), releasing", sid);
            self.drop_session(*sid);
        }

        // Drive ticks for remaining active sessions
        for peer_state in self.peer_machines.values_mut() {
            let action = match peer_state.machine.on_event(OstpEvent::Tick) {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("[ostp] Tick error for session: {}", e);
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
