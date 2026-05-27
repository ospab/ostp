use bytes::Bytes;
use rand::Rng;
use sha2::{Digest, Sha256};
use thiserror::Error;
use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

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
    /// Congestion controller (BBR-inspired adaptive window)
    cc: CongestionController,
        /// Key-derived handshake padding range
    handshake_pad_min: usize,
    handshake_pad_max: usize,
    mtu: usize,
}

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
            cc: CongestionController::new(config.mtu as u64),
            handshake_pad_min: config.handshake_pad_min.max(8),
            handshake_pad_max: config.handshake_pad_max.max(config.handshake_pad_min + 16),
            mtu: config.mtu,
        })
    }

    pub fn in_flight_count(&self) -> usize {
        // COUNT ONLY retransmittable Data frames — control frames (Ack/Nack) must not
        // contribute to this counter or they will trigger false backpressure.
        self.sent_history.iter().filter(|f| f.is_retransmittable).count()
    }

    pub fn cwnd_packets(&self) -> usize {
        self.cc.cwnd_packets() as usize
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
                // Process final in-flight packets to prevent data loss during teardown.
                // The remote may still have data or ACKs in transit when we initiated Close.
                let result = self.handle_inbound(raw);
                self.state = OstpState::Closed;
                result
            }
            (OstpState::Established, OstpEvent::Tick) => self.handle_tick(),
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
            return Err(ProtocolError::State("session id mismatch".to_string()));
        }

        if self.state == OstpState::Handshaking {
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
            tracing::info!("handle_inbound: raw_vec.len()={}, noise_len={}, raw_vec[0..6]={:?}", raw_vec.len(), noise_len, &raw_vec[0..6]);
            
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

            let mut key = [0_u8; 32];
            self.noise.handshake_hash(&mut key)?;
            let (send_key, recv_key) = derive_split_keys(&key, self.role);
            self.send_cipher = Some(SessionCipher::new(&send_key));
            self.recv_cipher = Some(SessionCipher::new(&recv_key));
            self.state = OstpState::Established;

            let extracted_payload = read_out[..n].to_vec();

            Ok(ProtocolAction::HandshakePayload(Bytes::from(extracted_payload), response))
        } else if self.state == OstpState::Established {
            if raw_vec.len() < 12 {
                return Err(ProtocolError::Framing("data datagram too short".to_string()));
            }
            let nonce = u64::from_be_bytes(raw_vec[4..12].try_into().unwrap());
            
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
            
            let packet = FramedPacket::decode_zero_copy(Bytes::from(plaintext))?;
            
            let mut outbound_actions = Vec::new();

            // Fast path processing for Nacks: act immediately, bypass sequence queue
            if packet.header.kind == FrameKind::Nack
                && packet.payload.len() >= 8 {
                    let req_nonce = u64::from_be_bytes(packet.payload[..8].try_into().unwrap());
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
                FrameKind::Resume => {
                    // 0-RTT: treat early data as application data
                    tracing::info!("0-RTT Resume frame received, processing early data");
                    ProtocolAction::DeliverApp(packet.header.stream_id, packet.payload)
                }
                FrameKind::Close => {
                    tracing::info!("Received Close frame, terminating session");
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
                if self.reorder_buffer.len() < self.max_reorder_buffer {
                    self.reorder_buffer.insert(nonce, action);
                } else {
                    tracing::warn!("Reorder buffer full ({}/{}), dropping frame nonce={}",
                        self.reorder_buffer.len(), self.max_reorder_buffer, nonce
                    );
                }

                // Rate-limited NACK: send at most once per 30ms to prevent retransmit storms.
                // Under high load with natural UDP reordering, sending a NACK per packet
                // causes exponential retransmit explosion that saturates the channel.
                let nack_cooldown = Duration::from_millis(30);
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
        } else {
            Ok(ProtocolAction::Noop)
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

        // ── Gap Recovery ──────────────────────────────────────────────
        // If expected_recv_nonce hasn't advanced for 5+ seconds and there
        // are buffered frames waiting, the sender likely evicted the lost
        // frame from sent_history. Skip the gap to restore data flow.
        // This trades a small amount of data loss for connection liveness.
        if !self.reorder_buffer.is_empty()
            && self.last_recv_advance.elapsed() > Duration::from_secs(5)
        {
            if let Some(&first_buffered) = self.reorder_buffer.keys().next() {
                let skipped = first_buffered.saturating_sub(self.expected_recv_nonce);
                self.expected_recv_nonce = first_buffered;
                self.last_recv_advance = Instant::now();

                let mut delivered = 0u64;
                while let Some(buffered_action) = self.reorder_buffer.remove(&self.expected_recv_nonce) {
                    actions.push(buffered_action);
                    self.expected_recv_nonce = self.expected_recv_nonce.saturating_add(1);
                    delivered += 1;
                }
                self.ack_pending = true;
                tracing::debug!("Gap recovery: skipped {} lost frames, delivered {} buffered frames (reorder_buf={})",
                    skipped, delivered, self.reorder_buffer.len()
                );
            }
        }

        // ── Pending ACK flush ─────────────────────────────────────────
        if let Some(ack_frame) = self.build_ack_if_due()? {
            actions.push(ProtocolAction::SendDatagram(ack_frame));
        }

        let now = Instant::now();
        let base_rto_ms = self.rto.as_millis().max(1) as u64;

        // ── Zombie frame eviction ────────────────────────────────────
        // Evict frames that exceeded max_retries + 2 grace retries.
        // Shorter grace period than before (was +4) to free memory faster
        // after high-throughput bursts.
        let grace = self.max_retries.saturating_add(2);
        let before = self.sent_history.len();
        self.sent_history.retain(|f| !f.is_retransmittable || f.retries <= grace);
        let evicted = before - self.sent_history.len();
        if evicted > 0 {
            tracing::debug!("Evicted {} zombie frames from sent_history (remaining={})", evicted, self.sent_history.len());
        }

        // ── Retransmit expired frames ────────────────────────────────
        // Limit retransmits per tick to prevent bandwidth saturation
        let mut retransmit_budget: usize = self.cc.retransmit_budget();
        for frame in self.sent_history.iter_mut() {
            if retransmit_budget == 0 {
                break;
            }
            if !frame.is_retransmittable {
                continue;
            }

            let retry_over = frame.retries.saturating_sub(self.max_retries);
            let backoff_factor = 1u64 << retry_over.min(6);
            let effective_rto = Duration::from_millis(base_rto_ms.saturating_mul(backoff_factor));

            if now.duration_since(frame.last_sent) >= effective_rto {
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
        let mut min_rtt = Duration::from_secs(60);

        // Compute RTT from the oldest acked frame's send timestamp
        for frame in self.sent_history.iter() {
            if nonce_in_ranges(frame.nonce, ranges) {
                acked_bytes += frame.bytes.len() as u64;
                let rtt = now.duration_since(frame.last_sent);
                if rtt < min_rtt {
                    min_rtt = rtt;
                }
            }
        }

        self.sent_history.retain(|frame| !nonce_in_ranges(frame.nonce, ranges));

        // Notify congestion controller
        if acked_bytes > 0 {
            self.cc.on_ack(acked_bytes, min_rtt);
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
        let start = u64::from_be_bytes(payload[idx..idx + 8].try_into().unwrap());
        let end = u64::from_be_bytes(payload[idx + 8..idx + 16].try_into().unwrap());
        ranges.push((start, end));
        idx += 16;
    }
    Ok(ranges)
}

fn nonce_in_ranges(nonce: u64, ranges: &[(u64, u64)]) -> bool {
    ranges.iter().any(|(start, end)| nonce >= *start && nonce <= *end)
}

fn derive_split_keys(base_key: &[u8; 32], role: NoiseRole) -> ([u8; 32], [u8; 32]) {
    let mut initiator_key = [0u8; 32];
    let mut responder_key = [0u8; 32];

    let mut h1 = Sha256::new();
    h1.update(base_key);
    h1.update(b"ostp-initiator");
    initiator_key.copy_from_slice(&h1.finalize());

    let mut h2 = Sha256::new();
    h2.update(base_key);
    h2.update(b"ostp-responder");
    responder_key.copy_from_slice(&h2.finalize());

    match role {
        NoiseRole::Initiator => (initiator_key, responder_key),
        NoiseRole::Responder => (responder_key, initiator_key),
    }
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
}
