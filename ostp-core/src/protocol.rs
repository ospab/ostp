use bytes::Bytes;
use rand::Rng;
use thiserror::Error;
use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

/// Upper bound on a single frame's retransmit timer, after exponential backoff
/// is applied to the adaptive RTO. Past this the session is dead from the
/// user's point of view, and waiting longer only delays recovery.
const MAX_EFFECTIVE_RTO: Duration = Duration::from_secs(8);

use crate::congestion::CongestionController;
use crate::crypto::{NoiseRole, NoiseSession, SessionCipher};
use crate::framing::{AdaptivePadder, FrameHeader, FrameKind, FramedPacket, PaddingStrategy};

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("state error: {0}")]
    State(String),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("framing error: {0}")]
    Framing(String),
}

#[derive(Debug, Clone)]
pub struct ProtocolConfig {
    pub role: NoiseRole,
    pub psk: [u8; 32],
    pub session_id: u32,
    pub handshake_payload: Vec<u8>,
    pub max_padding: usize,
    pub padding_strategy: PaddingStrategy,
    pub obfuscation_key: [u8; 8],
    pub max_reorder: u64,
    pub max_reorder_buffer: usize,
    pub ack_delay_ms: u64,
    pub rto_ms: u64,
    pub max_retries: u8,
    pub max_sent_history: usize,
    /// Key-derived handshake padding range (Kerckhoffs's principle).
    /// Different access keys produce different handshake packet sizes.
    pub handshake_pad_min: usize,
    pub handshake_pad_max: usize,
    pub mtu: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OstpState {
    Init,
    Handshaking,
    Established,
    Closing,
    Closed,
}

pub enum OstpEvent {
    Start,
    Inbound(Bytes),
    Outbound(u16, Bytes), // stream_id, payload
    Close,
    Tick,
}

pub enum ProtocolAction {
    SendDatagram(Bytes), // Fully formed datagram to send globally
    DeliverApp(u16, Bytes), // stream_id, payload
    HandshakePayload(Bytes, Option<Bytes>), // Passed from client's handshake, Optional response to send
    Multiple(Vec<ProtocolAction>),
    Noop,
}

pub struct ProtocolMachine {
    role: NoiseRole,
    state: OstpState,
    noise: NoiseSession,
    send_cipher: Option<SessionCipher>,
    recv_cipher: Option<SessionCipher>,
    send_nonce: u64,
    expected_recv_nonce: u64,
    reorder_buffer: BTreeMap<u64, ProtocolAction>,
    sent_history: VecDeque<SentFrame>,
    session_id: u32,
    handshake_payload: Vec<u8>,
    padder: AdaptivePadder,
    obfuscation_key: [u8; 8],
    max_reorder: u64,
    max_reorder_buffer: usize,
    ack_delay: Duration,
    rto: Duration,
    max_retries: u8,
    max_sent_history: usize,
    ack_pending: bool,
    last_ack_sent: Instant,
    /// Rate-limit: prevents sending a NACK more than once per 30ms to avoid storms
    last_nack_sent: Instant,
    /// Tracks when expected_recv_nonce last advanced. Used for gap recovery:
    /// if the receiver is stuck waiting for a lost frame that the sender already
    /// evicted from sent_history, this timer detects the deadlock and skips
    /// the gap to restore liveness.
    last_recv_advance: Instant,
    /// Highest data nonce that passed AEAD. A packet that raises it is the only
    /// kind allowed to move the session to a new peer address (RFC 9000 §9.3):
    /// a replay, even of a frame still sitting in the reorder buffer, cannot.
    highest_authenticated_recv_nonce: Option<u64>,
    /// Congestion controller (BBR-inspired adaptive window)
    cc: CongestionController,
        /// Key-derived handshake padding range
    handshake_pad_min: usize,
    handshake_pad_max: usize,
    _mtu: usize,
}

// ── Gap recovery (see `ProtocolMachine::recover_stalled_gap`) ────────────────
// How long the receive sequence may sit stuck behind a missing frame, with
// later frames already buffered, before that frame is declared unrecoverable
// and skipped. Derived from the live RTO so it scales with the path instead of
// guessing, then clamped: the floor keeps a fast link from discarding a frame
// that is merely late, the ceiling bounds how long a stall can be visible to
// the user before the tunnel unblocks itself.
const GAP_RECOVERY_RTO_MULTIPLIER: u32 = 8;
const GAP_RECOVERY_MIN: Duration = Duration::from_secs(2);
const GAP_RECOVERY_MAX: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
struct SentFrame {
    nonce: u64,
    bytes: Bytes,
    last_sent: Instant,
    retries: u8,
    is_retransmittable: bool,
}

impl ProtocolMachine {
    pub fn new(config: ProtocolConfig) -> Result<Self, ProtocolError> {
        let noise = NoiseSession::new(
            config.role,
            &config.psk,
        )?;

        Ok(Self {
            role: config.role,
            state: OstpState::Init,
            noise,
            send_cipher: None,
            recv_cipher: None,
            send_nonce: 0,
            expected_recv_nonce: 0,
            reorder_buffer: BTreeMap::new(),
            sent_history: VecDeque::with_capacity(config.max_sent_history.max(1)),
            session_id: config.session_id,
            handshake_payload: config.handshake_payload,
            padder: AdaptivePadder::new(config.mtu, config.max_padding, config.padding_strategy),
            obfuscation_key: config.obfuscation_key,
            max_reorder: config.max_reorder.max(1),
            max_reorder_buffer: config.max_reorder_buffer.max(1),
            ack_delay: Duration::from_millis(config.ack_delay_ms.max(1)),
            rto: Duration::from_millis(config.rto_ms.max(1)),
            max_retries: config.max_retries.max(1),
            max_sent_history: config.max_sent_history.max(1),
            ack_pending: false,
            last_ack_sent: Instant::now(),
            last_nack_sent: Instant::now() - Duration::from_secs(1),
            last_recv_advance: Instant::now(),
            highest_authenticated_recv_nonce: None,
            cc: CongestionController::new(config.mtu as u64),
            handshake_pad_min: config.handshake_pad_min.max(8),
            handshake_pad_max: config.handshake_pad_max.max(config.handshake_pad_min + 16),
            _mtu: config.mtu,
        })
    }

    /// Highest data nonce received that passed authentication, if any.
    pub fn highest_authenticated_recv_nonce(&self) -> Option<u64> {
        self.highest_authenticated_recv_nonce
    }

    pub fn in_flight_count(&self) -> usize {
        // COUNT ONLY retransmittable Data frames — control frames (Ack/Nack) must not
        // contribute to this counter or they will trigger false backpressure.
        self.sent_history.iter().filter(|f| f.is_retransmittable).count()
    }

    /// Sum of retry counters across in-flight frames. Test-only: lets a test
    /// assert the core retransmit invariant (a retry is only ever charged to a
    /// frame that was actually put on the wire) without needing to advance the
    /// clock through several seconds of exponential backoff.
    #[cfg(test)]
    fn total_retries(&self) -> usize {
        self.sent_history
            .iter()
            .filter(|f| f.is_retransmittable)
            .map(|f| f.retries as usize)
            .sum()
    }

    pub fn cwnd_packets(&self) -> usize {
        self.cc.cwnd_packets() as usize
    }

    /// Whether the pacing bucket currently allows releasing another packet.
    ///
    /// The congestion window bounds how much may be UNACKNOWLEDGED; it says
    /// nothing about how fast that window is emptied onto the wire. Sending a
    /// whole window back-to-back is what drives a deep buffer into standing
    /// queue, so admission is gated on both.
    pub fn can_pace_packet(&self) -> bool {
        self.cc.can_pace_packet()
    }

    pub fn on_send(&mut self, bytes: u64) {
        self.cc.on_send(bytes);
    }

    pub fn state(&self) -> OstpState {
        self.state
    }

    pub fn on_event(&mut self, event: OstpEvent) -> Result<ProtocolAction, ProtocolError> {
        match (self.state, event) {
            (OstpState::Init, OstpEvent::Start) => {
                match self.role {
                    NoiseRole::Initiator => {
                        self.state = OstpState::Handshaking;
                        let mut out = vec![0_u8; 1024];
                        let n = self.noise.write_handshake(&self.handshake_payload, &mut out)?;
                        out.truncate(n);
                        self.wrap_datagram_handshake(&out)
                            .map(ProtocolAction::SendDatagram)
                    }
                    NoiseRole::Responder => {
                        self.state = OstpState::Handshaking;
                        Ok(ProtocolAction::Noop)
                    }
                }
            }
            (OstpState::Init, OstpEvent::Inbound(raw)) => {
                self.state = OstpState::Handshaking;
                self.handle_inbound(raw)
            }
            (OstpState::Handshaking, OstpEvent::Inbound(raw)) => {
                self.handle_inbound(raw)
            }
            (OstpState::Handshaking, OstpEvent::Start) => Ok(ProtocolAction::Noop),
            (OstpState::Established, OstpEvent::Outbound(stream_id, app_data)) => {
                self.build_tracked_datagram(stream_id, FrameKind::Data, app_data)
                    .map(ProtocolAction::SendDatagram)
            }
            (OstpState::Established, OstpEvent::Inbound(raw)) => {
                self.handle_inbound(raw)
            }
            (OstpState::Established, OstpEvent::Close) => {
                self.state = OstpState::Closing;
                self.build_tracked_datagram(0, FrameKind::Close, Bytes::new())
                    .map(ProtocolAction::SendDatagram)
            }
            (OstpState::Closing, OstpEvent::Inbound(raw)) => {
                // The remote may still have data or ACKs in transit when we initiated
                // Close. Stay in Closing and process them; handle_inbound transitions to
                // Closed only when it actually receives the peer's Close frame — the old
                // code force-closed after a single inbound packet, losing in-flight data.
                // (Ported from 0.3.x 47d44fa.)
                self.handle_inbound(raw)
            }
            (OstpState::Established, OstpEvent::Tick) => self.handle_tick(),
            // Retransmit our Close frame (and drain pending) while waiting for teardown.
            (OstpState::Closing, OstpEvent::Tick) => self.handle_tick(),
            (OstpState::Closed, _) => Ok(ProtocolAction::Noop),
            (_, OstpEvent::Close) => {
                self.state = OstpState::Closed;
                Ok(ProtocolAction::Noop)
            }
            _ => Ok(ProtocolAction::Noop),
        }
    }

    fn handle_inbound(&mut self, raw: Bytes) -> Result<ProtocolAction, ProtocolError> {
        let mut raw_vec = raw.to_vec();
        let is_handshake = self.state == OstpState::Handshaking || self.state == OstpState::Init;
        crate::crypto::deobfuscate_packet_inplace(&mut raw_vec, &self.obfuscation_key, is_handshake);

        if raw_vec.len() < 4 {
            return Err(ProtocolError::Framing("datagram too short".to_string()));
        }

        let session_id = u32::from_be_bytes([raw_vec[0], raw_vec[1], raw_vec[2], raw_vec[3]]);
        if session_id != self.session_id {
            // Per-packet, attacker-triggerable event: keep at debug and don't
            // dump internal session ids (log-flood + info-leak surface).
            tracing::debug!("session id mismatch (is_handshake={})", is_handshake);
            return Err(ProtocolError::State("session id mismatch".to_string()));
        }

        if self.state == OstpState::Handshaking {
            self.handle_handshake_inbound(&raw_vec)
        } else if self.state == OstpState::Established {
            self.handle_data_inbound(&raw_vec)
        } else {
            Ok(ProtocolAction::Noop)
        }
    }

    fn handle_handshake_inbound(&mut self, raw_vec: &[u8]) -> Result<ProtocolAction, ProtocolError> {
        // Wire format: [session_id:4][noise_len:2][noise_payload:N][random_padding:*]
        // Extract noise_len to pass exactly the right bytes to snow
        if raw_vec.len() < 6 {
            return Err(ProtocolError::Framing("handshake too short for length prefix".to_string()));
        }
        let noise_len = u16::from_be_bytes([raw_vec[4], raw_vec[5]]) as usize;
        if raw_vec.len() < 6 + noise_len {
            return Err(ProtocolError::Framing(format!(
                "handshake truncated: expected {} noise bytes, got {}",
                noise_len, raw_vec.len() - 6
            )));
        }

        let mut read_out = vec![0_u8; 1024];
        let n = self.noise.read_handshake(&raw_vec[6..6 + noise_len], &mut read_out).map_err(|e| {
            ProtocolError::Crypto(format!("noise-read: {:?} (raw_len={}, noise_len={})", e, raw_vec.len(), noise_len))
        })?;
        read_out.truncate(n);

        let response = match self.role {
            NoiseRole::Responder => {
                let mut write_out = vec![0_u8; 1024];
                let out_n = self.noise.write_handshake(&self.handshake_payload, &mut write_out)?;
                write_out.truncate(out_n);
                Some(self.wrap_datagram_handshake(&write_out)?)
            }
            NoiseRole::Initiator => None,
        };

        // Transport keys come from Noise's Split() over the final chaining key,
        // so they depend on the ephemeral `ee` DH secret and give the session
        // forward secrecy. (Previously these were derived from the handshake
        // hash, which never absorbs the DH result — see raw_split's SECURITY
        // note. That is the wire-breaking change gated by PROTOCOL_VERSION.)
        let (send_key, recv_key) = self.noise.raw_split(self.role)?;
        self.send_cipher = Some(SessionCipher::new(&send_key));
        self.recv_cipher = Some(SessionCipher::new(&recv_key));
        self.state = OstpState::Established;

        let extracted_payload = read_out[..n].to_vec();

        Ok(ProtocolAction::HandshakePayload(Bytes::from(extracted_payload), response))
    }

    /// Restores liveness when the receive sequence is stuck behind a frame that
    /// can never arrive.
    ///
    /// Delivery is gated on `expected_recv_nonce`, so a single missing frame
    /// holds back every later frame. That is correct *while the sender can still
    /// retransmit* — but the sender drops a frame from `sent_history` once it
    /// exceeds `max_retries + 2` attempts (see the zombie eviction in
    /// `handle_tick`). After that the frame is gone for good and the two sides
    /// deadlock: the receiver buffers forever and NACKs a nonce nobody can
    /// resend.
    ///
    /// That deadlock is invisible to the keepalive watchdog, which is why it
    /// presented as a hard freeze rather than a reconnect: retransmits, ACKs and
    /// NACKs keep flowing, so the client's `last_valid_recv` keeps refreshing and
    /// its stall detector never fires. The RTT readout freezes at its last value
    /// for the same reason — Pong rides in a Data frame stuck behind the gap.
    ///
    /// So: once we have been stuck long enough that retransmission has provably
    /// given up, skip to the lowest buffered nonce and drain. This drops the
    /// missing frame's payload (one RelayMessage — a chunk of one stream), which
    /// is a real cost, but the alternative is a permanently dead tunnel.
    fn recover_stalled_gap(&mut self) -> Vec<ProtocolAction> {
        let mut recovered = Vec::new();
        if self.reorder_buffer.is_empty() {
            return recovered;
        }

        // Wait out the sender's full retransmit budget before giving up, so a
        // frame that is merely late is never discarded. The sender backs off
        // exponentially, so key this off the live RTO estimate rather than a
        // flat constant, with a floor that keeps low-RTT links from skipping
        // too eagerly and a ceiling that bounds the visible freeze.
        let timeout = self
            .cc
            .rto()
            .saturating_mul(GAP_RECOVERY_RTO_MULTIPLIER)
            .clamp(GAP_RECOVERY_MIN, GAP_RECOVERY_MAX);
        if self.last_recv_advance.elapsed() < timeout {
            return recovered;
        }

        let Some(&resume_at) = self.reorder_buffer.keys().next() else {
            return recovered;
        };
        let skipped = resume_at.saturating_sub(self.expected_recv_nonce);
        tracing::warn!(
            "Gap recovery: no progress for {:?}; skipping {} unrecoverable frame(s) \
             (nonce {} -> {}) to unblock the session",
            self.last_recv_advance.elapsed(),
            skipped,
            self.expected_recv_nonce,
            resume_at
        );

        self.expected_recv_nonce = resume_at;
        while let Some(buffered) = self.reorder_buffer.remove(&self.expected_recv_nonce) {
            recovered.push(buffered);
            match self.expected_recv_nonce.checked_add(1) {
                Some(next) => self.expected_recv_nonce = next,
                // u64 nonce space exhausted: stop draining rather than wrap.
                // The session is finished either way; the caller's next decrypt
                // will fail and tear it down.
                None => break,
            }
        }
        self.last_recv_advance = Instant::now();
        // The peer must learn the sequence moved on, or it will keep
        // retransmitting into the void.
        self.ack_pending = true;

        recovered
    }

    fn handle_data_inbound(&mut self, raw_vec: &[u8]) -> Result<ProtocolAction, ProtocolError> {
        // Check for a stalled gap before classifying this frame, so the rest of
        // the function sees an already-advanced `expected_recv_nonce`. Runs here
        // rather than on Tick because both tick handlers discard DeliverApp
        // actions, and because inbound frames keep arriving throughout the stall
        // (retransmits/ACKs/NACKs/keepalives) — so this path is reliably reached.
        let recovered = self.recover_stalled_gap();
        let result = self.handle_data_inbound_frame(raw_vec)?;
        if recovered.is_empty() {
            return Ok(result);
        }

        // Recovered payloads are older than anything this frame produces, so
        // they go first to preserve delivery order.
        let mut all = recovered;
        match result {
            ProtocolAction::Noop => {}
            ProtocolAction::Multiple(list) => all.extend(list),
            single => all.push(single),
        }
        Ok(if all.len() == 1 {
            all.pop().unwrap()
        } else {
            ProtocolAction::Multiple(all)
        })
    }

    fn handle_data_inbound_frame(&mut self, raw_vec: &[u8]) -> Result<ProtocolAction, ProtocolError> {
        if raw_vec.len() < 12 {
            return Err(ProtocolError::Framing("data datagram too short".to_string()));
        }
        let nonce = u64::from_be_bytes(raw_vec[4..12].try_into().map_err(|_| ProtocolError::Framing("data datagram too short for nonce".into()))?);
        
        if nonce < self.expected_recv_nonce {
            // Duplicate — the ACK we sent was likely lost or delayed.
            tracing::debug!("Duplicate frame nonce={} (expected {}), forcing ACK", nonce, self.expected_recv_nonce);
            if let Some(ack_frame) = self.force_build_ack()? {
                return Ok(ProtocolAction::SendDatagram(ack_frame));
            }
            return Ok(ProtocolAction::Noop);
        }

        if nonce > self.expected_recv_nonce + self.max_reorder {
            tracing::debug!("Frame nonce={} exceeds max reorder window (expected={}, max_gap={}), sending NACK",
                nonce, self.expected_recv_nonce, self.max_reorder
            );
            if let Ok(nack_frame) = self.build_control_datagram(
                0,
                FrameKind::Nack,
                Bytes::copy_from_slice(&self.expected_recv_nonce.to_be_bytes()),
            ) {
                return Ok(ProtocolAction::SendDatagram(nack_frame));
            }
            return Ok(ProtocolAction::Noop);
        }

        let ciphertext = &raw_vec[12..];
        let cipher = self.recv_cipher.as_ref().ok_or_else(|| {
            ProtocolError::State("missing recv cipher".to_string())
        })?;

        let session_id_bytes = self.session_id.to_be_bytes();
        let plaintext = cipher.decrypt(nonce, ciphertext, &session_id_bytes)?;
        if self.highest_authenticated_recv_nonce < Some(nonce) {
            self.highest_authenticated_recv_nonce = Some(nonce);
        }

        let packet = FramedPacket::decode_zero_copy(Bytes::from(plaintext))?;
        
        let mut outbound_actions = Vec::new();

        // Fast path processing for Nacks: act immediately, bypass sequence queue
        if packet.header.kind == FrameKind::Nack
            && packet.payload.len() >= 8 {
                let req_nonce = u64::from_be_bytes(packet.payload[..8].try_into().map_err(|_| ProtocolError::Framing("nack payload too short".into()))?);
                if let Some(cached_frame) = self.lookup_sent_frame(req_nonce) {
                    tracing::debug!("NACK received: retransmitting nonce={}", req_nonce);
                    self.cc.on_loss(cached_frame.len() as u64);
                    outbound_actions.push(ProtocolAction::SendDatagram(cached_frame));
                } else {
                    tracing::debug!("NACK received: nonce={} not found in sent_history (evicted)", req_nonce);
                    // Estimate ~1200 bytes lost for evicted frames
                    self.cc.on_loss(1200);
                }
            }

        if packet.header.kind == FrameKind::Ack {
            let ranges = parse_ack_ranges(&packet.payload)?;
            self.drop_acked_frames(&ranges);
        }

        let action = match packet.header.kind {
            FrameKind::Data => {
                ProtocolAction::DeliverApp(packet.header.stream_id, packet.payload)
            }
            FrameKind::Close => {
                tracing::debug!("Received Close frame, terminating session");
                self.state = OstpState::Closed;
                ProtocolAction::Noop
            }
            FrameKind::KeepAlive => ProtocolAction::Noop,
            _ => ProtocolAction::Noop,
        };

        let mut app_actions = Vec::new();

        if matches!(packet.header.kind, FrameKind::Data | FrameKind::Close | FrameKind::KeepAlive) {
            self.ack_pending = true;
        }

        if nonce == self.expected_recv_nonce {
            app_actions.push(action);
            self.expected_recv_nonce = self.expected_recv_nonce.checked_add(1).ok_or_else(|| {
                ProtocolError::Crypto("recv nonce sequence exhausted".to_string())
            })?;
            self.last_recv_advance = Instant::now();

            // Drain continuous queue
            while let Some(buffered_action) = self.reorder_buffer.remove(&self.expected_recv_nonce) {
                app_actions.push(buffered_action);
                self.expected_recv_nonce = self.expected_recv_nonce.checked_add(1).ok_or_else(|| {
                    ProtocolError::Crypto("recv nonce sequence exhausted".to_string())
                })?;
            }
            self.last_recv_advance = Instant::now();
        } else {
            // Gap detected
            if nonce >= self.expected_recv_nonce {
                if self.reorder_buffer.len() < self.max_reorder_buffer {
                    self.reorder_buffer.insert(nonce, action);
                } else {
                    tracing::warn!("Reorder buffer still full after gap recovery, dropping frame nonce={}", nonce);
                }
            } else {
                tracing::debug!("Frame nonce={} arrived too late after gap recovery, dropping", nonce);
            }

            // Rate-limited NACK: send at most once per (rto/2) to prevent retransmit storms.
            // Using rto/2 means we send a NACK before the sender's timer fires, prompting
            // fast retransmit without flooding. Floor at 10ms to handle very low-RTT links.
            let nack_cooldown = (self.cc.rto() / 2).max(Duration::from_millis(10));
            if self.last_nack_sent.elapsed() >= nack_cooldown {
                self.last_nack_sent = Instant::now();
                let nack_payload = self.expected_recv_nonce.to_be_bytes();
                if let Ok(nack_frame) = self.build_control_datagram(0, FrameKind::Nack, Bytes::copy_from_slice(&nack_payload)) {
                    outbound_actions.push(ProtocolAction::SendDatagram(nack_frame));
                }
            }
        }

        if let Some(ack_frame) = self.build_ack_if_due()? {
            outbound_actions.push(ProtocolAction::SendDatagram(ack_frame));
        }

        // Collate both types of output (application payloads and wire actions like Nacks/Retransmissions)
        let mut all_actions = Vec::new();
        all_actions.extend(outbound_actions);
        all_actions.extend(app_actions);

        if all_actions.is_empty() {
            Ok(ProtocolAction::Noop)
        } else if all_actions.len() == 1 {
            Ok(all_actions.pop().unwrap())
        } else {
            Ok(ProtocolAction::Multiple(all_actions))
        }
    }

    fn wrap_datagram_handshake(&self, noise_payload: &[u8]) -> Result<Bytes, ProtocolError> {
        // Anti-DPI: add random padding after the Noise payload to prevent
        // size fingerprinting. The padding range is derived from the access key
        // (Kerckhoffs's principle), so different keys produce different size
        // distributions — no universal filter can be built from the binary alone.
        //
        // Wire format: [session_id:4][noise_len:2][noise_payload:N][random_padding]
        let pad_len: usize = rand::thread_rng().gen_range(self.handshake_pad_min..=self.handshake_pad_max);
        let mut pad = vec![0u8; pad_len];
        rand::thread_rng().fill(&mut pad[..]);

        let noise_len = noise_payload.len() as u16;
        let mut out = Vec::with_capacity(4 + 2 + noise_payload.len() + pad_len);
        out.extend_from_slice(&self.session_id.to_be_bytes());
        out.extend_from_slice(&noise_len.to_be_bytes());
        out.extend_from_slice(noise_payload);
        out.extend_from_slice(&pad);
        crate::crypto::obfuscate_packet_inplace(&mut out, &self.obfuscation_key, true);
        Ok(Bytes::from(out))
    }

    fn build_tracked_datagram(&mut self, stream_id: u16, kind: FrameKind, payload: Bytes) -> Result<Bytes, ProtocolError> {
        self.build_datagram(stream_id, kind, payload, true)
    }

    fn build_control_datagram(&mut self, stream_id: u16, kind: FrameKind, payload: Bytes) -> Result<Bytes, ProtocolError> {
        self.build_datagram(stream_id, kind, payload, false)
    }

    fn build_datagram(&mut self, stream_id: u16, kind: FrameKind, payload: Bytes, is_retransmittable: bool) -> Result<Bytes, ProtocolError> {
        let padding = self.padder.build_padding(payload.len());
        let header = FrameHeader {
            version: 1,
            kind,
            stream_id,
            payload_len: payload.len() as u32,
            pad_len: padding.len() as u16,
        };

        let packet = FramedPacket {
            header,
            payload,
            padding: Bytes::from(padding),
        };

        let plaintext = packet.encode();
        
        let cipher = self.send_cipher.as_ref().ok_or_else(|| {
            ProtocolError::State("missing send cipher".to_string())
        })?;

        let nonce = self.send_nonce;
        self.send_nonce = self.send_nonce.checked_add(1).ok_or_else(|| {
            ProtocolError::Crypto("send nonce sequence exhausted".to_string())
        })?;

        let session_id_bytes = self.session_id.to_be_bytes();
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref(), &session_id_bytes)?;

        let mut out = Vec::with_capacity(4 + 8 + ciphertext.len());
        out.extend_from_slice(&session_id_bytes);
        out.extend_from_slice(&nonce.to_be_bytes());
        out.extend_from_slice(&ciphertext);
        crate::crypto::obfuscate_packet_inplace(&mut out, &self.obfuscation_key, false);

        let final_bytes = Bytes::from(out);
        
        self.push_sent_frame(nonce, final_bytes.clone(), is_retransmittable);

        Ok(final_bytes)
    }

    pub fn set_session_keys(&mut self, session_id: u32, obfuscation_key: [u8; 8]) {
        self.session_id = session_id;
        self.obfuscation_key = obfuscation_key;
    }

    fn handle_tick(&mut self) -> Result<ProtocolAction, ProtocolError> {
        let mut actions = Vec::new();

        // ── Pending ACK flush ─────────────────────────────────────────
        if let Some(ack_frame) = self.build_ack_if_due()? {
            actions.push(ProtocolAction::SendDatagram(ack_frame));
        }

        let now = Instant::now();
        // Use the adaptive RTO from the congestion controller (RFC 6298 SRTT + 4*RTTVAR).
        // Falls back to rto_initial before the first ACK is received.
        let base_rto_ms = self.cc.rto().max(self.rto).as_millis().max(1) as u64;

        // ── Zombie frame eviction ────────────────────────────────────
        // Evict frames that exceeded max_retries + 2 grace retries.
        let grace = self.max_retries.saturating_add(2);
        let before = self.sent_history.len();
        self.sent_history.retain(|f| !f.is_retransmittable || f.retries <= grace);
        let evicted = before - self.sent_history.len();
        if evicted > 0 {
            tracing::debug!("Evicted {} zombie frames from sent_history (remaining={})", evicted, self.sent_history.len());
        }

        // ── Retransmit expired frames ────────────────────────────────
        // Limit retransmits per tick to prevent bandwidth saturation
        // Backoff starts from retry #0 (immediately effective):
        //   effective_rto = base_rto * 2^retries, capped at 2^6 = 64×
        let mut retransmit_budget: usize = self.cc.retransmit_budget();
        for frame in self.sent_history.iter_mut() {
            if !frame.is_retransmittable {
                continue;
            }
            // Out of budget for this tick — stop scanning rather than walking the
            // rest of the queue. sent_history is in send order, so everything we
            // skip is strictly newer than what we already handled; deferring it to
            // the next tick preserves oldest-first retransmit priority.
            if retransmit_budget == 0 {
                break;
            }

            // Exponential backoff, but bounded in absolute terms. base_rto is
            // itself adaptive and can reach RTO_MAX (16s) on a congested path;
            // multiplying that by the 64x backoff cap yields a frame that sits
            // unretransmitted for ~17 MINUTES, long past the point where the
            // session is simply dead to the user. Cap the product so backoff
            // stays a backoff rather than an outage.
            let backoff_factor = 1u64 << (frame.retries as u64).min(6);
            let effective_rto = Duration::from_millis(base_rto_ms.saturating_mul(backoff_factor))
                .min(MAX_EFFECTIVE_RTO);

            if now.duration_since(frame.last_sent) >= effective_rto {
                // Only burn the retry counter and reset the RTO timer when the
                // frame is ACTUALLY put on the wire. Doing it unconditionally
                // meant that whenever the per-tick budget ran out — which is
                // exactly when loss is heavy and retransmits matter most —
                // frames accumulated "phantom retries" they never actually got,
                // and the zombie eviction above then silently dropped them after
                // `grace` such rounds. The peer never received that data and
                // never would: that stream stalls forever while the session
                // itself stays healthy, which is precisely the reported "tunnel
                // frozen at 0 b/s but the session still up" symptom.
                frame.last_sent = now;
                frame.retries = frame.retries.saturating_add(1);
                actions.push(ProtocolAction::SendDatagram(frame.bytes.clone()));
                retransmit_budget -= 1;
            }
        }

        if actions.is_empty() {
            Ok(ProtocolAction::Noop)
        } else if actions.len() == 1 {
            Ok(actions.pop().unwrap())
        } else {
            Ok(ProtocolAction::Multiple(actions))
        }
    }

    fn build_ack_if_due(&mut self) -> Result<Option<Bytes>, ProtocolError> {
        if !self.ack_pending {
            return Ok(None);
        }
        let now = Instant::now();
        if now.duration_since(self.last_ack_sent) < self.ack_delay {
            return Ok(None);
        }

        let payload = self.build_ack_payload();
        if payload.is_empty() {
            self.ack_pending = false;
            return Ok(None);
        }

        let frame = self.build_control_datagram(0, FrameKind::Ack, payload)?;
        self.ack_pending = false;
        self.last_ack_sent = now;
        Ok(Some(frame))
    }

    fn force_build_ack(&mut self) -> Result<Option<Bytes>, ProtocolError> {
        let payload = self.build_ack_payload();
        if payload.is_empty() {
            self.ack_pending = false;
            return Ok(None);
        }

        let frame = self.build_control_datagram(0, FrameKind::Ack, payload)?;
        self.ack_pending = false;
        self.last_ack_sent = Instant::now();
        Ok(Some(frame))
    }

    fn build_ack_payload(&self) -> Bytes {
        const MAX_RANGES: usize = 8;
        let mut ranges = Vec::new();

        if self.expected_recv_nonce > 0 {
            ranges.push((0_u64, self.expected_recv_nonce - 1));
        }

        let mut current_start: Option<u64> = None;
        let mut last = 0_u64;
        for &nonce in self.reorder_buffer.keys() {
            if current_start.is_none() {
                current_start = Some(nonce);
                last = nonce;
            } else if nonce == last + 1 {
                last = nonce;
            } else {
                ranges.push((current_start.unwrap(), last));
                current_start = Some(nonce);
                last = nonce;
            }
        }
        if let Some(start) = current_start {
            ranges.push((start, last));
        }

        if ranges.is_empty() {
            return Bytes::new();
        }

        if ranges.len() > MAX_RANGES {
            // Always preserve the cumulative range (index 0) so the sender knows
            // all frames up to expected_recv_nonce are received. Truncate SACK ranges.
            let mut trimmed = vec![ranges[0]];
            let tail_start = ranges.len().saturating_sub(MAX_RANGES - 1);
            trimmed.extend_from_slice(&ranges[tail_start..]);
            ranges = trimmed;
        }

        let mut out = Vec::with_capacity(1 + ranges.len() * 16);
        out.push(ranges.len() as u8);
        for (start, end) in ranges {
            out.extend_from_slice(&start.to_be_bytes());
            out.extend_from_slice(&end.to_be_bytes());
        }
        Bytes::from(out)
    }

    fn lookup_sent_frame(&mut self, nonce: u64) -> Option<Bytes> {
        if let Some(frame) = self.sent_history.iter_mut().rev().find(|f| f.nonce == nonce) {
            frame.last_sent = Instant::now();
            frame.retries = frame.retries.saturating_add(1);
            return Some(frame.bytes.clone());
        }
        None
    }

    fn push_sent_frame(&mut self, nonce: u64, bytes: Bytes, is_retransmittable: bool) {
        if is_retransmittable {
            self.cc.on_send(bytes.len() as u64);
        }
        self.sent_history.push_back(SentFrame {
            nonce,
            bytes,
            last_sent: Instant::now(),
            retries: 0,
            is_retransmittable,
        });
        if self.sent_history.len() > self.max_sent_history {
            let overflow = self.sent_history.len() - self.max_sent_history;
            tracing::debug!("sent_history overflow: evicting {} oldest frames (cap={})",
                overflow, self.max_sent_history
            );
            while self.sent_history.len() > self.max_sent_history {
                self.sent_history.pop_front();
            }
        }
    }

    fn drop_acked_frames(&mut self, ranges: &[(u64, u64)]) {
        let now = Instant::now();
        let mut acked_bytes = 0u64;
        let mut min_rtt: Option<Duration> = None;

        for frame in self.sent_history.iter() {
            if nonce_in_ranges(frame.nonce, ranges) {
                acked_bytes += frame.bytes.len() as u64;
                // Karn's algorithm: never take an RTT sample from a frame that
                // was retransmitted. `last_sent` is bumped on every retransmit,
                // so an ACK for the ORIGINAL transmission would be measured
                // against the retransmit time, yielding a spuriously small RTT
                // that drags SRTT/RTO down and triggers more spurious
                // retransmits. Only unambiguous (never-retried) frames qualify.
                if frame.retries == 0 {
                    let rtt = now.duration_since(frame.last_sent);
                    min_rtt = Some(min_rtt.map_or(rtt, |m| m.min(rtt)));
                }
            }
        }

        self.sent_history.retain(|frame| !nonce_in_ranges(frame.nonce, ranges));

        // Notify congestion controller. Feed an RTT sample only when we had at
        // least one unambiguous ACK; otherwise update the window without
        // polluting the RTT estimator.
        if acked_bytes > 0 {
            match min_rtt {
                Some(rtt) => self.cc.on_ack(acked_bytes, rtt),
                None => self.cc.on_ack_no_rtt(acked_bytes),
            }
        }
    }
}

fn parse_ack_ranges(payload: &[u8]) -> Result<Vec<(u64, u64)>, ProtocolError> {
    if payload.is_empty() {
        return Ok(Vec::new());
    }
    let count = payload[0] as usize;
    let expected = 1 + count * 16;
    if payload.len() < expected {
        return Err(ProtocolError::Framing("ack payload truncated".to_string()));
    }

    let mut ranges = Vec::with_capacity(count);
    let mut idx = 1;
    for _ in 0..count {
        let start = u64::from_be_bytes(payload[idx..idx + 8].try_into().map_err(|_| ProtocolError::Framing("ack range start invalid".into()))?);
        let end = u64::from_be_bytes(payload[idx + 8..idx + 16].try_into().map_err(|_| ProtocolError::Framing("ack range end invalid".into()))?);
        ranges.push((start, end));
        idx += 16;
    }
    Ok(ranges)
}

fn nonce_in_ranges(nonce: u64, ranges: &[(u64, u64)]) -> bool {
    ranges.iter().any(|(start, end)| nonce >= *start && nonce <= *end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framing::PaddingStrategy;

    fn test_psk() -> [u8; 32] {
        let mut psk = [0u8; 32];
        psk[0] = 0xAB;
        psk[15] = 0xCD;
        psk[31] = 0xEF;
        psk
    }

    fn make_config(role: NoiseRole) -> ProtocolConfig {
        ProtocolConfig {
            role,
            psk: test_psk(),
            session_id: 1,
            handshake_payload: vec![],
            max_padding: 64,
            padding_strategy: PaddingStrategy::Adaptive,
            obfuscation_key: [0u8; 8],
            max_reorder: 128,
            max_reorder_buffer: 256,
            ack_delay_ms: 5,
            rto_ms: 100,
            max_retries: 4,
            max_sent_history: 1024,
            handshake_pad_min: 8,
            handshake_pad_max: 32,
            mtu: 1400,
        }
    }

    /// Full handshake: Initiator -> Responder -> Initiator -> Established
    fn do_handshake() -> (ProtocolMachine, ProtocolMachine) {
        let mut client = ProtocolMachine::new(make_config(NoiseRole::Initiator)).unwrap();
        let mut server = ProtocolMachine::new(make_config(NoiseRole::Responder)).unwrap();

        // Client sends handshake message 1
        let action = client.on_event(OstpEvent::Start).unwrap();
        let msg1 = match action {
            ProtocolAction::SendDatagram(d) => d,
            _ => panic!("expected SendDatagram from client Start"),
        };
        assert_eq!(client.state(), OstpState::Handshaking);

        // Server receives msg1 and responds
        let action = server.on_event(OstpEvent::Start).unwrap();
        assert!(matches!(action, ProtocolAction::Noop));

        let action = server.on_event(OstpEvent::Inbound(msg1)).unwrap();
        let msg2 = match action {
            ProtocolAction::Multiple(actions) => {
                actions.into_iter().find_map(|a| match a {
                    ProtocolAction::SendDatagram(d) => Some(d),
                    _ => None,
                }).expect("server should send datagram in handshake response")
            }
            ProtocolAction::SendDatagram(d) => d,
            ProtocolAction::HandshakePayload(_, Some(d)) => d,
            other => panic!("unexpected server response: {:?}", std::mem::discriminant(&other)),
        };

        // Client receives msg2 -> Established
        let action = client.on_event(OstpEvent::Inbound(msg2)).unwrap();
        match action {
            ProtocolAction::HandshakePayload(_, _) => {}
            ProtocolAction::Multiple(_) => {}
            _ => {}
        }

        // Both should be Established
        assert_eq!(client.state(), OstpState::Established);
        assert_eq!(server.state(), OstpState::Established);

        (client, server)
    }

    #[test]
    fn test_full_handshake() {
        let (client, server) = do_handshake();
        assert_eq!(client.state(), OstpState::Established);
        assert_eq!(server.state(), OstpState::Established);
    }

    #[test]
    fn test_data_exchange_client_to_server() {
        let (mut client, mut server) = do_handshake();

        // Client sends data
        let payload = Bytes::from_static(b"hello from client");
        let action = client.on_event(OstpEvent::Outbound(1, payload.clone())).unwrap();
        let datagram = match action {
            ProtocolAction::SendDatagram(d) => d,
            _ => panic!("expected SendDatagram"),
        };

        // Server receives and decrypts
        let action = server.on_event(OstpEvent::Inbound(datagram)).unwrap();
        match action {
            ProtocolAction::DeliverApp(stream_id, data) => {
                assert_eq!(stream_id, 1);
                assert_eq!(data.as_ref(), b"hello from client");
            }
            ProtocolAction::Multiple(actions) => {
                let found = actions.iter().any(|a| matches!(a,
                    ProtocolAction::DeliverApp(1, d) if d.as_ref() == b"hello from client"
                ));
                assert!(found, "expected DeliverApp in Multiple");
            }
            _ => panic!("expected DeliverApp or Multiple"),
        }
    }

    #[test]
    fn test_data_exchange_server_to_client() {
        let (mut client, mut server) = do_handshake();

        // Server sends data
        let payload = Bytes::from_static(b"hello from server");
        let action = server.on_event(OstpEvent::Outbound(2, payload.clone())).unwrap();
        let datagram = match action {
            ProtocolAction::SendDatagram(d) => d,
            _ => panic!("expected SendDatagram"),
        };

        // Client receives
        let action = client.on_event(OstpEvent::Inbound(datagram)).unwrap();
        match action {
            ProtocolAction::DeliverApp(stream_id, data) => {
                assert_eq!(stream_id, 2);
                assert_eq!(data.as_ref(), b"hello from server");
            }
            ProtocolAction::Multiple(actions) => {
                let found = actions.iter().any(|a| matches!(a,
                    ProtocolAction::DeliverApp(2, d) if d.as_ref() == b"hello from server"
                ));
                assert!(found, "expected DeliverApp in Multiple");
            }
            _ => panic!("expected DeliverApp or Multiple"),
        }
    }

    #[test]
    fn test_close_sequence() {
        let (mut client, mut server) = do_handshake();

        // Client sends Close
        let action = client.on_event(OstpEvent::Close).unwrap();
        let close_datagram = match action {
            ProtocolAction::SendDatagram(d) => d,
            _ => panic!("expected SendDatagram for Close"),
        };
        assert_eq!(client.state(), OstpState::Closing);

        // Server receives Close
        let _action = server.on_event(OstpEvent::Inbound(close_datagram)).unwrap();
        assert_eq!(server.state(), OstpState::Closed);
    }

    #[test]
    fn test_wrong_psk_handshake_fails() {
        let mut client = ProtocolMachine::new(make_config(NoiseRole::Initiator)).unwrap();

        let mut bad_psk_config = make_config(NoiseRole::Responder);
        bad_psk_config.psk = [0xFF; 32]; // Different PSK
        let mut server = ProtocolMachine::new(bad_psk_config).unwrap();

        let action = client.on_event(OstpEvent::Start).unwrap();
        let msg1 = match action {
            ProtocolAction::SendDatagram(d) => d,
            _ => panic!("expected SendDatagram"),
        };

        let _ = server.on_event(OstpEvent::Start).unwrap();
        // Server should fail to process handshake with wrong PSK
        let result = server.on_event(OstpEvent::Inbound(msg1));
        // Either an error or the server stays in Handshaking (never reaches Established)
        assert!(result.is_err() || server.state() != OstpState::Established);
    }

    #[test]
    fn test_congestion_controller_after_handshake() {
        let (client, _server) = do_handshake();
        // CC should be in SlowStart after handshake
        let budget = client.cc.retransmit_budget();
        assert!(budget >= 2, "initial retransmit budget should be >= 2, got {}", budget);
    }

    #[test]
    fn test_multiple_data_frames() {
        let (mut client, mut server) = do_handshake();

        // Send 10 frames
        for i in 0..10u8 {
            let payload = Bytes::from(vec![i; 100]);
            let action = client.on_event(OstpEvent::Outbound(1, payload)).unwrap();
            let datagram = match action {
                ProtocolAction::SendDatagram(d) => d,
                _ => panic!("expected SendDatagram for frame {}", i),
            };

            let action = server.on_event(OstpEvent::Inbound(datagram)).unwrap();
            match action {
                ProtocolAction::DeliverApp(_, data) => {
                    assert_eq!(data.len(), 100);
                    assert_eq!(data[0], i);
                }
                ProtocolAction::Multiple(actions) => {
                    let found = actions.iter().any(|a| matches!(a,
                        ProtocolAction::DeliverApp(_, d) if d.len() == 100 && d[0] == i
                    ));
                    assert!(found, "frame {} not found in Multiple", i);
                }
                _ => panic!("unexpected action for frame {}", i),
            }
        }

        // Verify in-flight state
        assert!(client.in_flight_count() > 0, "should have in-flight frames");
    }

    #[test]
    fn test_tick_no_crash() {
        let (mut client, mut server) = do_handshake();

        // Tick should not crash on either side
        let _ = client.on_event(OstpEvent::Tick).unwrap();
        let _ = server.on_event(OstpEvent::Tick).unwrap();
    }

    /// A retry may only be charged to a frame that was actually retransmitted.
    ///
    /// The retransmit loop is budget-limited per tick. It used to bump
    /// `retries` and reset `last_sent` for every due frame regardless of
    /// whether the budget allowed it to actually send — so under heavy loss
    /// (exactly when the budget runs out) frames racked up retries they never
    /// received, and the zombie eviction dropped them after `max_retries + 2`
    /// such rounds. That data was never delivered and never would be: the
    /// stream stalls permanently while the session itself stays up.
    #[test]
    fn test_retransmit_budget_charges_retries_only_for_frames_actually_sent() {
        let (mut client, _server) = do_handshake();

        // Queue far more in-flight frames than a single tick's budget allows.
        const FRAMES: usize = 40;
        for i in 0..FRAMES {
            let payload = Bytes::from(vec![i as u8; 200]);
            client.on_event(OstpEvent::Outbound(1, payload)).unwrap();
        }
        assert_eq!(client.in_flight_count(), FRAMES);
        assert_eq!(client.total_retries(), 0, "nothing retransmitted yet");

        // Let every frame's RTO lapse so that on the next tick all FRAMES frames
        // are due at once and the per-tick budget is guaranteed to run out. The
        // effective RTO here is max(cc.rto(), config rto_ms) = 100ms at retries=0.
        std::thread::sleep(Duration::from_millis(150));

        let sent = count_datagrams(&client.on_event(OstpEvent::Tick).unwrap());

        assert!(sent > 0, "expected some retransmits after the RTO lapsed");
        assert!(
            sent < FRAMES,
            "budget should have capped this tick below the {FRAMES} due frames, got {sent}"
        );
        assert_eq!(
            client.total_retries(),
            sent,
            "charged {} retries but only put {} frames on the wire — the \
             difference is phantom retries that will silently evict live data",
            client.total_retries(),
            sent
        );
        assert_eq!(
            client.in_flight_count(),
            FRAMES,
            "nothing was acked, so no frame may be evicted yet"
        );
    }

    /// Count how many datagrams an action tree actually puts on the wire.
    fn count_datagrams(action: &ProtocolAction) -> usize {
        match action {
            ProtocolAction::SendDatagram(_) => 1,
            ProtocolAction::Multiple(list) => list.iter().map(count_datagrams).sum(),
            _ => 0,
        }
    }

    /// Count how many application payloads an action tree actually delivers.
    fn delivered_payloads(action: &ProtocolAction) -> Vec<Bytes> {
        match action {
            ProtocolAction::DeliverApp(_, data) => vec![data.clone()],
            ProtocolAction::Multiple(list) => list.iter().flat_map(delivered_payloads).collect(),
            _ => Vec::new(),
        }
    }

    /// Build `count` data frames on `client`, returning them without delivering
    /// any — lets a test choose which ones to "lose" in transit.
    fn make_data_frames(client: &mut ProtocolMachine, count: u8) -> Vec<Bytes> {
        (0..count)
            .map(|i| {
                let payload = Bytes::from(vec![i; 32]);
                match client.on_event(OstpEvent::Outbound(1, payload)).unwrap() {
                    ProtocolAction::SendDatagram(d) => d,
                    _ => panic!("expected SendDatagram for frame {i}"),
                }
            })
            .collect()
    }

    /// The freeze this fixes: a frame is lost, the sender eventually stops
    /// retransmitting it, and the receiver — which gates delivery on
    /// `expected_recv_nonce` — waits for it forever. Every later frame piles up
    /// undelivered while the transport itself stays healthy, so nothing upstream
    /// notices. Recovery must eventually skip the hole and release the backlog.
    #[test]
    fn test_gap_recovery_releases_permanently_stalled_frames() {
        let (mut client, mut server) = do_handshake();
        let frames = make_data_frames(&mut client, 4);

        // Frame 0 arrives in order and is delivered straight through.
        let action = server.on_event(OstpEvent::Inbound(frames[0].clone())).unwrap();
        assert_eq!(delivered_payloads(&action).len(), 1, "in-order frame should deliver");

        // Frame 1 is lost. 2 and 3 arrive but must be held back — delivering them
        // now would reorder the stream.
        for idx in [2usize, 3] {
            let action = server.on_event(OstpEvent::Inbound(frames[idx].clone())).unwrap();
            assert!(
                delivered_payloads(&action).is_empty(),
                "frame {idx} must stay buffered behind the missing frame"
            );
        }

        // Stand in for "the sender exhausted its retries and dropped frame 1":
        // the sequence has not advanced for longer than the recovery timeout.
        server.last_recv_advance = Instant::now() - GAP_RECOVERY_MAX - Duration::from_secs(1);

        // The next inbound frame (a retransmitted duplicate, which is exactly what
        // a real stalled session keeps receiving) must unblock the backlog.
        let action = server.on_event(OstpEvent::Inbound(frames[0].clone())).unwrap();
        let delivered = delivered_payloads(&action);
        assert_eq!(
            delivered.len(),
            2,
            "both buffered frames must be released once the gap is declared unrecoverable"
        );
        // ...and in order: frame 2 before frame 3.
        assert_eq!(delivered[0][0], 2);
        assert_eq!(delivered[1][0], 3);
    }

    /// Recovery must not be trigger-happy: a frame that is merely late still has
    /// to be waited for, or we would discard data the sender is about to resend.
    #[test]
    fn test_gap_recovery_does_not_fire_before_timeout() {
        let (mut client, mut server) = do_handshake();
        let frames = make_data_frames(&mut client, 3);

        server.on_event(OstpEvent::Inbound(frames[0].clone())).unwrap();
        let action = server.on_event(OstpEvent::Inbound(frames[2].clone())).unwrap();
        assert!(delivered_payloads(&action).is_empty());

        // Well inside the timeout — the gap must still be respected.
        let action = server.on_event(OstpEvent::Inbound(frames[0].clone())).unwrap();
        assert!(
            delivered_payloads(&action).is_empty(),
            "must keep waiting while retransmission is still plausible"
        );

        // And once the genuinely-late frame shows up, normal in-order delivery
        // resumes with nothing dropped.
        let action = server.on_event(OstpEvent::Inbound(frames[1].clone())).unwrap();
        let delivered = delivered_payloads(&action);
        assert_eq!(delivered.len(), 2, "late frame plus the buffered one");
        assert_eq!(delivered[0][0], 1);
        assert_eq!(delivered[1][0], 2);
    }
}
