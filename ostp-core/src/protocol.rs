use bytes::Bytes;
use sha2::{Digest, Sha256};
use thiserror::Error;
use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

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
            padder: AdaptivePadder::new(1200, config.max_padding, config.padding_strategy),
            obfuscation_key: config.obfuscation_key,
            max_reorder: config.max_reorder.max(1),
            max_reorder_buffer: config.max_reorder_buffer.max(1),
            ack_delay: Duration::from_millis(config.ack_delay_ms.max(1)),
            rto: Duration::from_millis(config.rto_ms.max(1)),
            max_retries: config.max_retries.max(1),
            max_sent_history: config.max_sent_history.max(1),
            ack_pending: false,
            last_ack_sent: Instant::now(),
        })
    }

    pub fn in_flight_count(&self) -> usize {
        self.sent_history.len()
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
            (OstpState::Closing, OstpEvent::Inbound(_)) => {
                self.state = OstpState::Closed;
                Ok(ProtocolAction::Noop)
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
            let mut read_out = vec![0_u8; 1024];
            let n = self.noise.read_handshake(&raw_vec[4..], &mut read_out)?;

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

            return Ok(ProtocolAction::HandshakePayload(Bytes::from(extracted_payload), response));
        } else if self.state == OstpState::Established {
            if raw_vec.len() < 12 {
                return Err(ProtocolError::Framing("data datagram too short".to_string()));
            }
            let nonce = u64::from_be_bytes(raw_vec[4..12].try_into().unwrap());
            
            if nonce < self.expected_recv_nonce {
                // Duplicate packet! The ACK we sent was likely lost or delayed.
                // We MUST trigger an immediate ACK to unblock the sender's congestion window.
                if let Some(ack_frame) = self.force_build_ack()? {
                    return Ok(ProtocolAction::SendDatagram(ack_frame));
                }
                return Ok(ProtocolAction::Noop);
            }

            // Buffer limit to prevent memory bloat, widened to handle high latency/speed gaps
            if nonce > self.expected_recv_nonce + self.max_reorder {
                // Treat as heavy loss: request retransmit of the earliest missing packet.
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
            if packet.header.kind == FrameKind::Nack {
                if packet.payload.len() >= 8 {
                    let req_nonce = u64::from_be_bytes(packet.payload[..8].try_into().unwrap());
                    // Search history from back to front (newest most likely requested)
                    if let Some(cached_frame) = self.lookup_sent_frame(req_nonce) {
                        outbound_actions.push(ProtocolAction::SendDatagram(cached_frame));
                    }
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
                    tracing::error!("FATAL: Recv nonce sequence exhausted (2^64 frames). Session must be terminated to prevent AEAD keystream reuse!");
                    ProtocolError::Crypto("recv nonce sequence exhausted".to_string())
                })?;

                // Drain continuous queue
                while let Some(buffered_action) = self.reorder_buffer.remove(&self.expected_recv_nonce) {
                    app_actions.push(buffered_action);
                    self.expected_recv_nonce = self.expected_recv_nonce.checked_add(1).ok_or_else(|| {
                        tracing::error!("FATAL: Recv nonce sequence exhausted (2^64 frames). Session must be terminated to prevent AEAD keystream reuse!");
                        ProtocolError::Crypto("recv nonce sequence exhausted".to_string())
                    })?;
                }
            } else {
                // Gap detected! Buffer current packet and request immediate retransmit of the gap packet.
                if self.reorder_buffer.len() < self.max_reorder_buffer {
                    self.reorder_buffer.insert(nonce, action);
                }
                
                // Emit a Nack frame for the lowest missing sequence
                let nack_payload = self.expected_recv_nonce.to_be_bytes();
                if let Ok(nack_frame) = self.build_control_datagram(0, FrameKind::Nack, Bytes::copy_from_slice(&nack_payload)) {
                    outbound_actions.push(ProtocolAction::SendDatagram(nack_frame));
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
        let mut out = Vec::with_capacity(4 + noise_payload.len());
        out.extend_from_slice(&self.session_id.to_be_bytes());
        out.extend_from_slice(noise_payload);
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
            tracing::error!("FATAL: Send nonce sequence exhausted (2^64 frames). Session must be terminated to prevent AEAD keystream reuse!");
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

        if let Some(ack_frame) = self.build_ack_if_due()? {
            actions.push(ProtocolAction::SendDatagram(ack_frame));
        }

        let now = Instant::now();
        let base_rto_ms = self.rto.as_millis().max(1) as u64;
        for frame in self.sent_history.iter_mut() {
            if !frame.is_retransmittable {
                continue;
            }

            if frame.retries == self.max_retries {
                tracing::warn!(
                    "Frame {} exceeded max retries ({}); continuing with backoff",
                    frame.nonce,
                    self.max_retries
                );
            }

            let retry_over = frame.retries.saturating_sub(self.max_retries);
            let backoff_factor = 1u64 << retry_over.min(6);
            let effective_rto = Duration::from_millis(base_rto_ms.saturating_mul(backoff_factor));

            if now.duration_since(frame.last_sent) >= effective_rto {
                frame.last_sent = now;
                frame.retries = frame.retries.saturating_add(1);
                actions.push(ProtocolAction::SendDatagram(frame.bytes.clone()));
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
            ranges = ranges[ranges.len() - MAX_RANGES..].to_vec();
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
        while self.sent_history.len() > self.max_sent_history {
            self.sent_history.pop_front();
        }
    }

    fn drop_acked_frames(&mut self, ranges: &[(u64, u64)]) {
        self.sent_history.retain(|frame| !nonce_in_ranges(frame.nonce, ranges));
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
