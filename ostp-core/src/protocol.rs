use bytes::Bytes;
use rand::Rng;
use thiserror::Error;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Upper bound on a single frame's retransmit timer, after exponential backoff
/// is applied to the adaptive RTO. Past this the session is dead from the
/// user's point of view, and waiting longer only delays recovery.
const MAX_EFFECTIVE_RTO: Duration = Duration::from_secs(8);
/// No authenticated datagram for this long while data is in flight means an
/// outage rather than congestion. Keepalives go out every few seconds, and an
/// idle session (nothing in flight) is not affected.
const OUTAGE_SILENCE: Duration = Duration::from_secs(3);
/// A frame is given up only after this long unacknowledged, and a receiver
/// waits as long for a missing one. It matches how long the client keeps a
/// session through an outage (and is well under the server's 10 minutes), so
/// a session that survives an outage has lost nothing on the way.
const FRAME_GIVE_UP: Duration = Duration::from_secs(300);
/// On a reliable carrier (TCP, TLS) a frame is resent on a timer only when it
/// has gone unacknowledged this long: far above any queueing delay, so the
/// timer no longer duplicates frames that are merely queued.
const RELIABLE_CARRIER_RTO: Duration = Duration::from_secs(5);

use crate::congestion::CongestionController;
use crate::crypto::{NoiseRole, NoiseSession, SessionCipher};
use crate::framing::{
    AdaptivePadder, FrameHeader, FrameKind, FramedPacket, FramedPacketV2, PaddingStrategy, DATAGRAM_OVERHEAD,
    DATAGRAM_OVERHEAD_V6,
};

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
    /// `Some`: the handshake is v6 (the server's static key, a masked
    /// handshake datagram). `None`: v5. The caller derives `psk`,
    /// `obfuscation_key` and the padding range for the same version.
    pub v6: Option<V6Handshake>,
}

/// What a v6 handshake needs besides the PSK.
#[derive(Clone)]
pub struct V6Handshake {
    /// The server's static key: the public half on a client, the private on
    /// the server.
    pub server: crate::crypto::ServerStatic,
    /// The keys of the handshake's outer layer (`crypto::handshake_v6`).
    pub hs: crate::crypto::HsKeys,
}

impl std::fmt::Debug for V6Handshake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "V6Handshake({:?})", self.server)
    }
}

impl ProtocolConfig {
    /// The ARQ and padding parameters every OSTP endpoint uses. Keys, session id,
    /// payload and padding strategy are placeholders for the caller to override
    /// (`..ProtocolConfig::with_defaults(role, mtu)`). One copy, because both
    /// ends must agree on RTO and retry counts.
    pub fn with_defaults(role: NoiseRole, mtu: usize) -> Self {
        Self {
            role,
            psk: [0u8; 32],
            session_id: 0,
            handshake_payload: Vec::new(),
            max_padding: mtu.saturating_sub(48).max(256),
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
            mtu,
            v6: None,
        }
    }
}

/// The session id a v6 handshake datagram carries, if it has this key's tag.
/// A server uses it to pick the key (one HMAC per key) before any Noise work.
pub fn v6_handshake_session_id(keys: &crate::crypto::HsKeys, datagram: &[u8]) -> Option<u32> {
    let body = crate::crypto::handshake_v6::open(keys, crate::crypto::HsDirection::ClientToServer, datagram)?;
    let sid = body.get(..4)?;
    Some(u32::from_be_bytes([sid[0], sid[1], sid[2], sid[3]]))
}

/// What identifies a v6 handshake whatever its nonce and padding: the session
/// id and a SHA-256 of the Noise message. `None` without this key's tag or when
/// the body is too short for its own length field. One HMAC and one ChaCha20
/// pass, no curve operation: a server uses it to find a handshake it already
/// answered (the reply cache) before any Noise work.
pub fn v6_handshake_identity(keys: &crate::crypto::HsKeys, datagram: &[u8]) -> Option<(u32, [u8; 32])> {
    use sha2::{Digest, Sha256};
    let body = crate::crypto::handshake_v6::open(keys, crate::crypto::HsDirection::ClientToServer, datagram)?;
    let sid = u32::from_be_bytes(body.get(..4)?.try_into().ok()?);
    let noise_len = u16::from_be_bytes(body.get(4..6)?.try_into().ok()?) as usize;
    let noise = body.get(6..6 + noise_len)?;
    Some((sid, Sha256::digest(noise).into()))
}

/// The client's handshake payload: `timestamp(8) | session_id(4) | access_key`,
/// big-endian, timestamp in unix seconds.
pub fn build_handshake_payload(access_key: &[u8], session_id: u32) -> Vec<u8> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut payload = Vec::with_capacity(8 + 4 + access_key.len());
    payload.extend_from_slice(&timestamp.to_be_bytes());
    payload.extend_from_slice(&session_id.to_be_bytes());
    payload.extend_from_slice(access_key);
    payload
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
    /// A stream's payload, delivered reliably and in order within the stream.
    /// A v5 session has 16-bit stream ids: a larger one is refused.
    Outbound(u32, Bytes), // stream_id, payload
    /// v6 only: a payload that is neither retransmitted nor ordered (UDP). It
    /// counts against the congestion window; a lost one is simply lost.
    OutboundDatagram(u32, Bytes), // stream_id, payload
    /// v6 only: the stream is over on both sides; forget its state. Its id is
    /// not used again, so later frames of it are dropped.
    ReleaseStream(u32),
    Close,
    Tick,
}

pub enum ProtocolAction {
    SendDatagram(Bytes), // Fully formed datagram to send globally
    DeliverApp(u32, Bytes), // stream_id, payload
    /// v6 only: an unsequenced payload arrived (see `OstpEvent::OutboundDatagram`).
    DeliverDatagram(u32, Bytes), // stream_id, payload
    /// v6 only: the stream was reset. On the sender's side it gave up on a
    /// frame of it; on the receiving side the peer said so. The stream is dead
    /// in both directions: nothing more is delivered and `Outbound` for it is
    /// refused.
    StreamReset(u32, ResetReason), // stream_id, reason
    HandshakePayload(Bytes, Option<Bytes>), // Passed from client's handshake, Optional response to send
    Multiple(Vec<ProtocolAction>),
    Noop,
}

/// Why a stream was reset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ResetReason {
    /// The sender gave up retransmitting a frame of the stream: data was lost
    /// for good. The app must not go on as if the stream were intact (a TCP
    /// connection is reset, not left with a hole).
    Lost = 1,
}

impl ResetReason {
    fn from_wire(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Lost),
            _ => None,
        }
    }
}

/// Streams a receiver tracks at once (those with frames waiting or an order
/// to keep): more are refused. The protocol limit on open streams is 1024
/// (`streams::MAX_OPEN_STREAMS`); the slack is for streams that are closing.
const MAX_TRACKED_STREAMS: usize = 2 * crate::streams::MAX_OPEN_STREAMS;
/// Ids of dead (reset or released) streams remembered to drop their late
/// frames; the lowest are forgotten first.
const MAX_DEAD_STREAMS: usize = 8192;
/// How long a datagram may stay unacknowledged before the sender counts it
/// lost (in RTOs): it is never retransmitted, so the timer only frees its
/// share of the congestion window.
const DATAGRAM_LOSS_RTOS: u32 = 4;
/// Nonces one `Abandon` frame is allowed to mark received at the receiver, so
/// a frame cannot make it walk a huge range.
const ABANDON_MAX_SPAN: u64 = 16384;
/// Ranges one `Abandon` frame carries at most.
const ABANDON_MAX_RANGES: usize = 32;

/// A v6 receiver's state for one stream: the next `stream_seq` to deliver and
/// the frames that arrived ahead of it.
#[derive(Debug, Default)]
struct StreamRx {
    expected_seq: u32,
    buffer: BTreeMap<u32, Bytes>,
    buffered_bytes: usize,
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
    /// When the frame at `expected_recv_nonce` was first missed while later
    /// ones arrived, i.e. how old the current gap is. `None`: no gap.
    gap_since: Option<Instant>,
    /// A NACK went out for the current gap. The tick sends one for a gap no
    /// new frame has prompted a NACK for, never a stream of them.
    gap_nacked: bool,
    /// NACKs sent for the current gap; spaces out the tick's repeats.
    gap_nack_count: u32,
    /// The nonce the last NACK asked for. If that frame then arrives twice,
    /// the original was only late: the NACK was spurious.
    nacked_nonce: Option<u64>,
    /// Multiplier of the reorder window, doubled on each spurious NACK (the
    /// path reorders more than the window allows) and halved after
    /// REORDER_MULT_DECAY without one; RFC 8985 §7.2 does the same.
    reorder_mult: u32,
    reorder_mult_at: Instant,
    /// Tracks when expected_recv_nonce last advanced. Used for gap recovery:
    /// if the receiver is stuck waiting for a lost frame that the sender already
    /// evicted from sent_history, this timer detects the deadlock and skips
    /// the gap to restore liveness.
    last_recv_advance: Instant,
    /// Highest data nonce that passed AEAD. A packet that raises it is the only
    /// kind allowed to move the session to a new peer address (RFC 9000 §9.3):
    /// a replay, even of a frame still sitting in the reorder buffer, cannot.
    highest_authenticated_recv_nonce: Option<u64>,
    /// Data datagrams that passed AEAD. Unlike "on_event returned Ok", this
    /// cannot be advanced by a peer that does not hold the session keys, so it
    /// is what callers use as proof the path is alive.
    authenticated_recv_count: u64,
    /// When the last authenticated datagram arrived (see OUTAGE_SILENCE).
    last_authenticated_recv: Option<Instant>,
    /// FRAME_GIVE_UP; a field so tests can shorten it.
    frame_give_up: Duration,
    /// Congestion controller (BBR-inspired adaptive window)
    cc: CongestionController,
    /// The datagrams ride a reliable byte stream (UDP-over-TCP, TLS): nothing
    /// is lost on the way, so timer-driven retransmission only duplicates.
    /// Worse, it feeds on itself: the RTO times the queue in front of the TCP
    /// socket, fires while the frame is merely queued, and every duplicate
    /// lengthens that queue (TCP over TCP). With this set, frames are resent
    /// only when the peer NACKs a gap or after the session moved to another
    /// connection, where what was in flight on the old one is gone.
    reliable_carrier: bool,
    /// When the session last moved (`on_path_change`): on a reliable carrier,
    /// frames sent before this are resent once.
    path_changed_at: Option<Instant>,
    /// The nonce the peer last NACKed. A receiver NACKs the same gap again
    /// (every RTO/2) until it is filled; only the first NACK of a gap is a
    /// new loss for the congestion controller. Counting each one cut the
    /// window by 0.7 per NACK, down to the minimum for one lost frame.
    last_nacked_nonce: Option<u64>,
        /// Key-derived handshake padding range
    handshake_pad_min: usize,
    handshake_pad_max: usize,
    _mtu: usize,
    /// `Some`: the handshake datagrams are v6 (masked, tagged).
    v6_hs: Option<crate::crypto::HsKeys>,
    /// The Noise message of the first handshake datagram a client built, kept
    /// so a resend can be sealed again (`handshake_resend`).
    first_noise: Option<Vec<u8>>,
    /// The session is v6 (`ProtocolConfig.v6` is set): 16-byte frame headers,
    /// delivery order per stream, unsequenced datagrams, no skipping of gaps.
    /// A v5 session never reads the fields below.
    v6: bool,
    /// Next `stream_seq` of each stream we send on.
    send_seq: HashMap<u32, u32>,
    /// Receiving side of each stream.
    streams_rx: HashMap<u32, StreamRx>,
    /// Frames waiting in `streams_rx` buffers, all streams together: bounded
    /// by `max_reorder_buffer`.
    stream_buffered: usize,
    /// Reset or released streams: frames for them are acknowledged and dropped
    /// and `Outbound` for them is refused.
    dead_streams: BTreeSet<u32>,
    /// The last `Abandon` sent in answer to a NACK, to rate-limit those.
    last_abandon_answer: Instant,
}

// ── Gap recovery (see `ProtocolMachine::recover_stalled_gap`) ────────────────
/// The shortest the receive sequence sits stuck behind a missing frame before
/// that frame is declared unrecoverable and skipped; the actual wait is how
/// long the sender keeps retransmitting (`sender_gives_up_after`).
const GAP_RECOVERY_MIN: Duration = Duration::from_secs(2);

// ── Reordering (see `ProtocolMachine::nack_if_due`) ──────────────────────────
/// How long a gap may be a reordering before it is NACKed as a loss: a
/// quarter of the smoothed RTT, as RACK does (RFC 8985), within these bounds.
/// A NACK makes the sender retransmit and shrink its window, so NACKing the
/// first frame that arrives out of order turned every reordering (Wi-Fi,
/// LTE, ECMP) into a loss. A packet-count threshold (TCP's three duplicate
/// ACKs) would not help: at a few thousand packets a second, more than
/// three arrive while a frame is a few milliseconds late.
const REORDER_WINDOW_MIN: Duration = Duration::from_millis(5);
const REORDER_WINDOW_MAX: Duration = Duration::from_millis(100);
/// A receiver that only sends ACKs (a plain download) has no RTT samples of
/// its own, so its estimate stays at the initial 30 ms and the window at
/// 7.5 ms. Spurious NACKs widen it from there.
const REORDER_MULT_MAX: u32 = 16;
const REORDER_MULT_DECAY: Duration = Duration::from_secs(10);
/// The longest pause between the tick's repeated NACKs for one gap.
const RENACK_MAX: Duration = Duration::from_secs(2);
/// The fastest an ACK or NACK goes out in answer to a frame that is not
/// delivered (a duplicate, or one beyond the reorder window).
const ANSWER_MIN_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Debug, Clone)]
struct SentFrame {
    nonce: u64,
    bytes: Bytes,
    /// When it was first sent; a frame is given up only after FRAME_GIVE_UP.
    first_sent: Instant,
    last_sent: Instant,
    retries: u8,
    is_retransmittable: bool,
    /// What the frame is, for a v6 sender that gives up on it or abandons it.
    kind: FrameKind,
    stream_id: u32,
    /// An unsequenced datagram: counted in flight but never resent.
    no_resend: bool,
}

/// What a frame being built is.
#[derive(Clone, Copy)]
struct FrameMeta {
    kind: FrameKind,
    stream_id: u32,
    /// `stream_seq` (v6; 0 for every unsequenced kind).
    seq: u32,
    /// Charged to the congestion window and kept until acknowledged.
    retransmittable: bool,
    /// Never resent (a v6 datagram).
    no_resend: bool,
}

impl ProtocolMachine {
    pub fn new(config: ProtocolConfig) -> Result<Self, ProtocolError> {
        let noise = match &config.v6 {
            Some(v6) => {
                // The half of the server key must fit the role: a client with a
                // private key or a server with a public one is a caller's bug.
                let fits = matches!(
                    (config.role, &v6.server),
                    (NoiseRole::Initiator, crate::crypto::ServerStatic::Public(_))
                        | (NoiseRole::Responder, crate::crypto::ServerStatic::Private(_))
                );
                if !fits {
                    return Err(ProtocolError::State("the server key does not fit the role".to_string()));
                }
                NoiseSession::new_v6(&config.psk, &v6.server)?
            }
            None => NoiseSession::new(config.role, &config.psk)?,
        };
        let v6_hs = config.v6.as_ref().map(|v| v.hs);
        // The MTU comes from user config. Zero divides by zero in the
        // congestion controller and anything under the padder's 64-byte
        // bucket panics in `clamp`, so a nonsense value is raised to the
        // smallest one the framing can use.
        let v6 = config.v6.is_some();
        let overhead = if v6 { DATAGRAM_OVERHEAD_V6 } else { DATAGRAM_OVERHEAD };
        let mtu = config.mtu.max(overhead + 64);
        let now = Instant::now();

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
            padder: AdaptivePadder::new(mtu, config.max_padding, config.padding_strategy).with_overhead(overhead),
            obfuscation_key: config.obfuscation_key,
            max_reorder: config.max_reorder.max(1),
            // A sender never has more than MAX_CWND_PACKETS frames in flight,
            // so a buffer of one window holds every frame a real reordering
            // or loss can leave waiting; anything beyond it only let a key
            // holder make the server keep frames sent far ahead on purpose.
            max_reorder_buffer: config
                .max_reorder_buffer
                .clamp(1, crate::congestion::MAX_CWND_PACKETS as usize),
            ack_delay: Duration::from_millis(config.ack_delay_ms.max(1)),
            rto: Duration::from_millis(config.rto_ms.max(1)),
            max_retries: config.max_retries.max(1),
            max_sent_history: config.max_sent_history.max(1),
            ack_pending: false,
            last_ack_sent: Instant::now(),
            last_nack_sent: now.checked_sub(Duration::from_secs(1)).unwrap_or(now),
            gap_since: None,
            gap_nacked: false,
            gap_nack_count: 0,
            nacked_nonce: None,
            reorder_mult: 1,
            reorder_mult_at: Instant::now(),
            last_recv_advance: Instant::now(),
            highest_authenticated_recv_nonce: None,
            authenticated_recv_count: 0,
            last_authenticated_recv: None,
            frame_give_up: FRAME_GIVE_UP,
            cc: CongestionController::new(mtu as u64),
            reliable_carrier: false,
            path_changed_at: None,
            last_nacked_nonce: None,
            handshake_pad_min: config.handshake_pad_min.max(8),
            handshake_pad_max: config.handshake_pad_max.max(config.handshake_pad_min + 16),
            _mtu: mtu,
            v6_hs,
            first_noise: None,
            v6,
            send_seq: HashMap::new(),
            streams_rx: HashMap::new(),
            stream_buffered: 0,
            dead_streams: BTreeSet::new(),
            last_abandon_answer: now.checked_sub(Duration::from_secs(1)).unwrap_or(now),
        })
    }

    /// A fresh sealing of the first handshake message, for a resend: the same
    /// Noise message, a new nonce and new padding, so two copies on the wire
    /// share no bytes. `None` for a v5 handshake (its resend stays
    /// byte-identical, as 0.4.x servers expect) and before `Start`.
    pub fn handshake_resend(&self) -> Result<Option<Bytes>, ProtocolError> {
        match (&self.v6_hs, &self.first_noise) {
            (Some(_), Some(noise)) => self.wrap_datagram_handshake(noise).map(Some),
            _ => Ok(None),
        }
    }

    /// Highest data nonce received that passed authentication, if any.
    pub fn highest_authenticated_recv_nonce(&self) -> Option<u64> {
        self.highest_authenticated_recv_nonce
    }

    /// Number of data datagrams received that passed authentication.
    pub fn authenticated_recv_count(&self) -> u64 {
        self.authenticated_recv_count
    }

    /// The session now runs over a different socket, address or transport.
    ///
    /// Keys, nonces, streams and the reorder buffer stay as they are, so the
    /// peer sees one continuous session. What was learned about the old path
    /// is dropped, and every unacknowledged frame becomes due on the next
    /// tick: whatever was in flight on the old path is most likely lost with
    /// it, and waiting out a backed-off RTO would stall the move.
    ///
    /// Frames are marked as retransmitted (`retries >= 1`) so an ACK for them
    /// never feeds an RTT sample (Karn), and a pending ACK is forced so the
    /// first packet on the new path carries a fresh nonce, the thing the
    /// server moves the session's address on.
    pub fn on_path_change(&mut self) {
        self.cc.reset_path();
        self.path_changed_at = Some(Instant::now());
        let due = Instant::now()
            .checked_sub(Duration::from_secs(3600))
            .unwrap_or_else(Instant::now);
        for frame in self.sent_history.iter_mut().filter(|f| f.is_retransmittable) {
            frame.last_sent = due;
            frame.retries = 1;
        }
        self.last_nack_sent = due;
        self.last_ack_sent = due;
        self.ack_pending = true;
    }

    /// Whether datagrams ride a reliable byte stream (UDP-over-TCP or TLS)
    /// rather than UDP; see the `reliable_carrier` field. Safe to change at
    /// any time, the peer is not affected.
    pub fn set_reliable_carrier(&mut self, reliable: bool) {
        self.reliable_carrier = reliable;
        self.cc.set_delay_signal(!reliable);
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

    /// Data frames that may go out within `horizon`: what the congestion
    /// window leaves room for, limited by the pacing rate over that time. For
    /// a sender that is woken periodically (a tick, an ACK) and must not
    /// stop between wake-ups merely because the pacing bucket was empty at
    /// the moment it looked.
    pub fn send_budget(&self, horizon: Duration) -> usize {
        let window = self.cc.cwnd_packets().saturating_sub(self.in_flight_count());
        let paced = (self.cc.pacing_budget(horizon) / self._mtu.max(1) as f64).max(0.0) as usize;
        window.min(paced)
    }

    /// How long until the pacing bucket holds one more full packet.
    pub fn time_to_pace(&self) -> Duration {
        self.cc.time_to_pace()
    }

    /// The largest application payload one datagram carries within the
    /// configured MTU; split anything larger (see `relay::data_chunks`).
    pub fn max_payload(&self) -> usize {
        let overhead = if self.v6 { DATAGRAM_OVERHEAD_V6 } else { DATAGRAM_OVERHEAD };
        self._mtu.saturating_sub(overhead).max(64)
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

    /// Whether this session speaks protocol v6 (set by the handshake; a v5
    /// session has 16-bit stream ids and none of the v6 events).
    pub fn is_v6(&self) -> bool {
        self.v6
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
                        let frame = self.wrap_datagram_handshake(&out)?;
                        self.first_noise = Some(out);
                        Ok(ProtocolAction::SendDatagram(frame))
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
                if self.v6 {
                    return self.build_stream_frame(stream_id, app_data).map(ProtocolAction::SendDatagram);
                }
                let stream_id = u16::try_from(stream_id)
                    .map_err(|_| ProtocolError::State("a v5 session has 16-bit stream ids".to_string()))?;
                self.build_tracked_datagram(stream_id, FrameKind::Data, app_data)
                    .map(ProtocolAction::SendDatagram)
            }
            (OstpState::Established, OstpEvent::OutboundDatagram(stream_id, payload)) => {
                if !self.v6 {
                    return Err(ProtocolError::State("unsequenced datagrams need a v6 session".to_string()));
                }
                // Counted in flight (the congestion window sees it), acknowledged
                // like any frame, never resent.
                let meta = FrameMeta { kind: FrameKind::Datagram, stream_id, seq: 0, retransmittable: true, no_resend: true };
                self.build_frame(meta, payload).map(ProtocolAction::SendDatagram)
            }
            (OstpState::Established, OstpEvent::ReleaseStream(stream_id)) => {
                if self.v6 {
                    self.release_stream(stream_id);
                }
                Ok(ProtocolAction::Noop)
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
        let is_handshake = self.state == OstpState::Handshaking || self.state == OstpState::Init;
        let raw_vec = match (&self.v6_hs, is_handshake) {
            (Some(keys), true) => {
                // The peer's direction: a server reads the client's message
                // and the other way round.
                crate::crypto::handshake_v6::open(keys, self.peer_hs_direction(), &raw)
                    .ok_or_else(|| ProtocolError::Framing("not a handshake for this key".to_string()))?
            }
            _ => {
                let mut v = raw.to_vec();
                crate::crypto::deobfuscate_packet_inplace(&mut v, &self.obfuscation_key, is_handshake);
                v
            }
        };

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
        } else if matches!(self.state, OstpState::Established | OstpState::Closing) {
            // Closing too: the ACK for our Close, data still in flight and the
            // peer's own Close arrive after we sent ours. Dropping them left
            // the session waiting for the caller's idle timeout.
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
        // A v6 session never skips: a stream with a hole waits for the peer to
        // reset it (`Abandon`), and the datagram-level holes are filled by the
        // same frame.
        if self.v6 || self.reorder_buffer.is_empty() {
            return recovered;
        }

        // Wait out the sender's full retransmit budget before giving up, so a
        // frame that is merely late is never discarded. This waited 8 RTOs,
        // 2 to 10 s, while the sender keeps retransmitting for ~38 s at a
        // 100 ms RTO: after any outage of a few seconds a frame the sender was
        // about to resend could be skipped, leaving a silent hole in a stream.
        let timeout = self.sender_gives_up_after().max(GAP_RECOVERY_MIN);
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
        self.gap_moved();
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
        
        // Frames this receiver will not deliver (an old nonce, or one beyond
        // the reorder window) still get an answer, so the sender learns what
        // to do; but only once they authenticate, and not more often than
        // ANSWER_MIN_INTERVAL. A replayed capture or a forged header (anyone
        // holding the access key can produce one) used to get an ACK or NACK
        // per packet without either.
        let early = nonce < self.expected_recv_nonce || nonce > self.expected_recv_nonce.saturating_add(self.max_reorder);
        if early {
            let authentic = self
                .recv_cipher
                .as_ref()
                .is_some_and(|c| c.decrypt(nonce, &raw_vec[12..], &self.session_id.to_be_bytes()).is_ok());
            if !authentic {
                return Err(ProtocolError::Crypto("aead-decrypt".to_string()));
            }
        }

        if nonce < self.expected_recv_nonce {
            // A second copy of the frame we NACKed: the original was late,
            // not lost.
            if self.nacked_nonce == Some(nonce) {
                self.nacked_nonce = None;
                self.reorder_mult = (self.reorder_mult * 2).min(REORDER_MULT_MAX);
                self.reorder_mult_at = Instant::now();
                tracing::debug!("Spurious NACK for nonce={nonce}: reorder window x{}", self.reorder_mult);
            }
            // Duplicate — the ACK we sent was likely lost or delayed.
            tracing::debug!("Duplicate frame nonce={} (expected {}), forcing ACK", nonce, self.expected_recv_nonce);
            if self.last_ack_sent.elapsed() >= ANSWER_MIN_INTERVAL {
                if let Some(ack_frame) = self.force_build_ack()? {
                    return Ok(ProtocolAction::SendDatagram(ack_frame));
                }
            }
            return Ok(ProtocolAction::Noop);
        }

        if nonce > self.expected_recv_nonce.saturating_add(self.max_reorder) {
            tracing::debug!("Frame nonce={} exceeds max reorder window (expected={}, max_gap={}), sending NACK",
                nonce, self.expected_recv_nonce, self.max_reorder
            );
            if self.last_nack_sent.elapsed() >= ANSWER_MIN_INTERVAL {
                self.last_nack_sent = Instant::now();
                if let Ok(nack_frame) = self.build_control_datagram(
                    0,
                    FrameKind::Nack,
                    Bytes::copy_from_slice(&self.expected_recv_nonce.to_be_bytes()),
                ) {
                    return Ok(ProtocolAction::SendDatagram(nack_frame));
                }
            }
            return Ok(ProtocolAction::Noop);
        }

        let ciphertext = &raw_vec[12..];
        let cipher = self.recv_cipher.as_ref().ok_or_else(|| {
            ProtocolError::State("missing recv cipher".to_string())
        })?;

        let session_id_bytes = self.session_id.to_be_bytes();
        let plaintext = cipher.decrypt(nonce, ciphertext, &session_id_bytes)?;
        self.authenticated_recv_count = self.authenticated_recv_count.wrapping_add(1);
        // The peer is heard again after silence while data was in flight: the
        // path was down (or came back by itself on the same address), which
        // is not congestion. Without this the window that the outage's lost
        // retransmits shrank to 2 packets climbs back slowly for tens of
        // seconds; start over on this path instead, retransmitting at once.
        let now = Instant::now();
        let was_silent = self.last_authenticated_recv.is_some_and(|t| now.duration_since(t) >= OUTAGE_SILENCE);
        self.last_authenticated_recv = Some(now);
        if was_silent && self.in_flight_count() > 0 {
            self.on_path_change();
        }
        if self.highest_authenticated_recv_nonce < Some(nonce) {
            self.highest_authenticated_recv_nonce = Some(nonce);
        }

        if self.v6 {
            return self.handle_v6_frame(nonce, plaintext);
        }

        let packet = FramedPacket::decode_zero_copy(Bytes::from(plaintext))?;
        // Kinds that exist only in v6 are unknown to a v5 session, as they
        // are to a 0.4.x peer.
        if matches!(packet.header.kind, FrameKind::Datagram | FrameKind::Abandon) {
            return Err(ProtocolError::Framing("unknown frame kind".to_string()));
        }

        let mut outbound_actions = Vec::new();

        // Fast path processing for Nacks: act immediately, bypass sequence queue
        if packet.header.kind == FrameKind::Nack
            && packet.payload.len() >= 8 {
                let req_nonce = u64::from_be_bytes(packet.payload[..8].try_into().map_err(|_| ProtocolError::Framing("nack payload too short".into()))?);
                let new_gap = self.last_nacked_nonce != Some(req_nonce);
                self.last_nacked_nonce = Some(req_nonce);
                if let Some(cached_frame) = self.lookup_sent_frame(req_nonce) {
                    tracing::debug!("NACK received: retransmitting nonce={}", req_nonce);
                    if new_gap {
                        self.cc.on_loss(cached_frame.len() as u64);
                    }
                    self.cc.on_retransmit(cached_frame.len() as u64);
                    outbound_actions.push(ProtocolAction::SendDatagram(cached_frame));
                } else {
                    tracing::debug!("NACK received: nonce={} not found in sent_history (evicted)", req_nonce);
                    if new_gap {
                        // Estimate ~1200 bytes lost for evicted frames
                        self.cc.on_loss(1200);
                    }
                }
            }

        if packet.header.kind == FrameKind::Ack {
            let ranges = parse_ack_ranges(&packet.payload)?;
            self.drop_acked_frames(&ranges);
        }

        let action = match packet.header.kind {
            FrameKind::Data => {
                ProtocolAction::DeliverApp(u32::from(packet.header.stream_id), packet.payload)
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
            self.gap_moved();
        } else {
            // Gap detected
            if nonce >= self.expected_recv_nonce {
                if self.reorder_buffer.len() < self.max_reorder_buffer {
                    self.reorder_buffer.insert(nonce, action);
                } else {
                    tracing::debug!("Reorder buffer full, dropping frame nonce={}", nonce);
                }
            } else {
                tracing::debug!("Frame nonce={} arrived too late after gap recovery, dropping", nonce);
            }

            if self.gap_since.is_none() && !self.reorder_buffer.is_empty() {
                self.gap_since = Some(Instant::now());
                self.gap_nacked = false;
            }
            if let Some(nack_frame) = self.nack_if_due() {
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
    }

    // ── v6: loss recovery per datagram, delivery order per stream ────────────
    //
    // The nonce space, ACK/NACK with SACK, the retransmit timer and the
    // congestion controller are the same as in v5: `expected_recv_nonce` and
    // `reorder_buffer` still say which datagrams arrived (the buffer only keeps
    // the nonces here, the frames wait in the streams' own buffers). What moves
    // is the delivery: a `Data` frame is delivered when its stream's
    // `expected_seq` reaches it, whatever the other streams are missing.
    //
    // A hole is never skipped on the receiver's own say-so. When the sender
    // gives up on a frame it says so (`Abandon`): the nonces will never come
    // and, for a `Data` frame, its stream is reset.

    fn handle_v6_frame(&mut self, nonce: u64, plaintext: Vec<u8>) -> Result<ProtocolAction, ProtocolError> {
        let packet = FramedPacketV2::decode_zero_copy(Bytes::from(plaintext))?;
        let kind = packet.header.kind;
        let stream_id = packet.header.stream_id;

        // Received before (a retransmit whose first copy arrived, a replay):
        // nothing to deliver, and the peer is told what we have.
        if self.reorder_buffer.contains_key(&nonce) {
            return self.answer_duplicate();
        }

        let mut wire: Vec<ProtocolAction> = Vec::new();
        let mut app: Vec<ProtocolAction> = Vec::new();

        // What concerns our own sending acts at once, outside any order.
        match kind {
            FrameKind::Nack if packet.payload.len() >= 8 => self.on_nack_v6(&packet.payload, &mut wire),
            FrameKind::Ack => {
                let ranges = parse_ack_ranges(&packet.payload)?;
                self.drop_acked_frames(&ranges);
            }
            _ => {}
        }

        let before = self.expected_recv_nonce;
        // Out of order with no room for its nonce: dropped without being
        // recorded, so it is not acknowledged and the sender resends it.
        let full = nonce != self.expected_recv_nonce && self.reorder_buffer.len() >= self.max_reorder_buffer;
        let mut record = !full;
        if full {
            tracing::debug!("Reorder buffer full, dropping frame nonce={}", nonce);
        } else {
            match kind {
                FrameKind::Data => {
                    record = self.admit_stream_data(stream_id, packet.header.stream_seq, packet.payload.clone(), &mut app);
                }
                FrameKind::Datagram => app.push(ProtocolAction::DeliverDatagram(stream_id, packet.payload.clone())),
                FrameKind::Close => {
                    tracing::debug!("Received Close frame, terminating session");
                    self.state = OstpState::Closed;
                }
                FrameKind::Abandon => self.on_abandon_v6(&packet.payload, &mut app)?,
                _ => {}
            }
        }

        let held = record && self.record_nonce(nonce)?;
        if matches!(kind, FrameKind::Data | FrameKind::Close | FrameKind::KeepAlive | FrameKind::Datagram | FrameKind::Abandon) {
            self.ack_pending = true;
        }

        if self.expected_recv_nonce != before {
            self.last_recv_advance = Instant::now();
            self.gap_moved();
        }
        if held {
            if self.gap_since.is_none() {
                self.gap_since = Some(Instant::now());
                self.gap_nacked = false;
            }
            if let Some(nack_frame) = self.nack_if_due() {
                wire.push(ProtocolAction::SendDatagram(nack_frame));
            }
        }
        if let Some(ack_frame) = self.build_ack_if_due()? {
            wire.push(ProtocolAction::SendDatagram(ack_frame));
        }

        wire.extend(app);
        Ok(match wire.len() {
            0 => ProtocolAction::Noop,
            1 => wire.pop().expect("one action"),
            _ => ProtocolAction::Multiple(wire),
        })
    }

    /// Marks `nonce` as received at the datagram level: the cumulative point
    /// moves over it when it is the next one (and over the run behind it),
    /// otherwise it waits in `reorder_buffer`. Returns whether it is now
    /// waiting, i.e. a hole is open below it.
    fn record_nonce(&mut self, nonce: u64) -> Result<bool, ProtocolError> {
        if nonce < self.expected_recv_nonce {
            return Ok(false);
        }
        if nonce == self.expected_recv_nonce {
            let exhausted = || ProtocolError::Crypto("recv nonce sequence exhausted".to_string());
            self.expected_recv_nonce = self.expected_recv_nonce.checked_add(1).ok_or_else(exhausted)?;
            while self.reorder_buffer.remove(&self.expected_recv_nonce).is_some() {
                self.expected_recv_nonce = self.expected_recv_nonce.checked_add(1).ok_or_else(exhausted)?;
            }
            return Ok(false);
        }
        if self.reorder_buffer.len() >= self.max_reorder_buffer {
            return Ok(false);
        }
        self.reorder_buffer.insert(nonce, ProtocolAction::Noop);
        Ok(true)
    }

    /// A duplicate datagram: the ACK we sent was probably lost or late.
    fn answer_duplicate(&mut self) -> Result<ProtocolAction, ProtocolError> {
        if self.last_ack_sent.elapsed() >= ANSWER_MIN_INTERVAL {
            if let Some(ack_frame) = self.force_build_ack()? {
                return Ok(ProtocolAction::SendDatagram(ack_frame));
            }
        }
        Ok(ProtocolAction::Noop)
    }

    /// Delivers or holds a stream's `Data` frame by its `stream_seq`. Returns
    /// whether the frame was taken (its nonce is then recorded and
    /// acknowledged); `false` means there was no room and the sender must
    /// resend it.
    fn admit_stream_data(&mut self, stream_id: u32, seq: u32, payload: Bytes, app: &mut Vec<ProtocolAction>) -> bool {
        // Frames of a stream that is over: acknowledged, not delivered. The
        // last sequence number is never used, so the counter cannot wrap.
        if self.dead_streams.contains(&stream_id) || seq == u32::MAX {
            return true;
        }
        if !self.streams_rx.contains_key(&stream_id) && self.streams_rx.len() >= MAX_TRACKED_STREAMS {
            tracing::debug!("Too many streams tracked, dropping frame of stream {}", stream_id);
            return false;
        }
        let st = self.streams_rx.entry(stream_id).or_default();
        if seq < st.expected_seq {
            return true; // delivered already
        }
        if seq == st.expected_seq {
            app.push(ProtocolAction::DeliverApp(stream_id, payload));
            st.expected_seq += 1;
            while let Some(next) = st.buffer.remove(&st.expected_seq) {
                st.buffered_bytes -= next.len();
                self.stream_buffered -= 1;
                app.push(ProtocolAction::DeliverApp(stream_id, next));
                st.expected_seq += 1;
            }
            return true;
        }
        if st.buffer.contains_key(&seq) {
            return true; // held already
        }
        // Ahead of the stream's order: held, within the stream's window and
        // the session's reorder buffer. A frame the stream's flow control
        // allows always fits the first; the second only bounds a peer that
        // sends many streams ahead of themselves.
        if st.buffered_bytes + payload.len() > crate::relay::INITIAL_STREAM_WINDOW as usize
            || self.stream_buffered >= self.max_reorder_buffer
        {
            tracing::debug!("Stream {} buffer full, dropping frame seq={}", stream_id, seq);
            return false;
        }
        st.buffered_bytes += payload.len();
        st.buffer.insert(seq, payload);
        self.stream_buffered += 1;
        true
    }

    /// The stream is over in both directions: its buffers go, and frames that
    /// still arrive for it are acknowledged and dropped. Returns whether it was
    /// alive until now.
    fn kill_stream(&mut self, stream_id: u32) -> bool {
        if let Some(st) = self.streams_rx.remove(&stream_id) {
            self.stream_buffered -= st.buffer.len();
        }
        self.send_seq.remove(&stream_id);
        let newly = self.dead_streams.insert(stream_id);
        while self.dead_streams.len() > MAX_DEAD_STREAMS {
            if let Some(&lowest) = self.dead_streams.iter().next() {
                self.dead_streams.remove(&lowest);
            }
        }
        newly
    }

    fn release_stream(&mut self, stream_id: u32) {
        self.kill_stream(stream_id);
    }

    /// The peer NACKed `nonce` of ours: resend it, unless it is a datagram
    /// (lost, never resent) or no longer in the history (then it is gone for
    /// good and the peer is told, so its hole closes).
    fn on_nack_v6(&mut self, payload: &[u8], wire: &mut Vec<ProtocolAction>) {
        let Ok(raw) = <[u8; 8]>::try_from(&payload[..8]) else {
            return;
        };
        let req_nonce = u64::from_be_bytes(raw);
        let new_gap = self.last_nacked_nonce != Some(req_nonce);
        self.last_nacked_nonce = Some(req_nonce);

        let i = self.sent_history.partition_point(|f| f.nonce < req_nonce);
        let is_datagram = self.sent_history.get(i).filter(|f| f.nonce == req_nonce).map(|f| f.no_resend);
        match is_datagram {
            Some(false) => {
                if let Some(cached) = self.lookup_sent_frame(req_nonce) {
                    tracing::debug!("NACK received: retransmitting nonce={}", req_nonce);
                    if new_gap {
                        self.cc.on_loss(cached.len() as u64);
                    }
                    self.cc.on_retransmit(cached.len() as u64);
                    wire.push(ProtocolAction::SendDatagram(cached));
                }
            }
            Some(true) => {
                if let Some(lost) = self.sent_history.remove(i) {
                    let len = lost.bytes.len() as u64;
                    self.cc.on_discard(len);
                    if new_gap {
                        self.cc.on_loss(len);
                    }
                }
                self.answer_abandon(req_nonce, wire);
            }
            None if req_nonce < self.send_nonce => {
                tracing::debug!("NACK received: nonce={} is gone from sent_history", req_nonce);
                self.answer_abandon(req_nonce, wire);
            }
            // A nonce we never sent: nothing to resend and nothing to abandon.
            None => {}
        }
    }

    /// Tells the peer that `nonce` will never come. At most one per
    /// ANSWER_MIN_INTERVAL: a NACK that gets no answer is repeated by the
    /// receiver's own timer.
    fn answer_abandon(&mut self, nonce: u64, wire: &mut Vec<ProtocolAction>) {
        if self.last_abandon_answer.elapsed() < ANSWER_MIN_INTERVAL {
            return;
        }
        self.last_abandon_answer = Instant::now();
        if let Ok(frames) = self.build_abandon(0, None, &[nonce]) {
            wire.extend(frames.into_iter().map(ProtocolAction::SendDatagram));
        }
    }

    /// `Abandon` frames for `nonces`: `stream_id(4) reason(1) count(1)` and
    /// `count` ranges of `start(8) end(8)`. With a reason the frame is also a
    /// reset of the stream and is retransmitted until acknowledged; without
    /// one it only closes holes, and a lost copy is asked for again by the
    /// receiver's NACK.
    fn build_abandon(&mut self, stream_id: u32, reason: Option<ResetReason>, nonces: &[u64]) -> Result<Vec<Bytes>, ProtocolError> {
        let mut sorted = nonces.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        let mut ranges: Vec<(u64, u64)> = Vec::new();
        for n in sorted {
            match ranges.last_mut() {
                Some(last) if last.1.checked_add(1) == Some(n) => last.1 = n,
                _ => ranges.push((n, n)),
            }
        }
        let per_frame = (self.max_payload().saturating_sub(6) / 16).clamp(1, ABANDON_MAX_RANGES);
        let mut frames = Vec::new();
        for chunk in ranges.chunks(per_frame) {
            let mut payload = Vec::with_capacity(6 + chunk.len() * 16);
            payload.extend_from_slice(&stream_id.to_be_bytes());
            payload.push(reason.map_or(0, |r| r as u8));
            payload.push(chunk.len() as u8);
            for &(start, end) in chunk {
                payload.extend_from_slice(&start.to_be_bytes());
                payload.extend_from_slice(&end.to_be_bytes());
            }
            let meta = FrameMeta {
                kind: FrameKind::Abandon,
                stream_id: 0,
                seq: 0,
                retransmittable: reason.is_some(),
                no_resend: false,
            };
            frames.push(self.build_frame(meta, Bytes::from(payload))?);
        }
        Ok(frames)
    }

    /// The peer will never send these nonces: they count as received, and a
    /// stream it names is reset.
    fn on_abandon_v6(&mut self, payload: &[u8], app: &mut Vec<ProtocolAction>) -> Result<(), ProtocolError> {
        if payload.len() < 6 {
            return Err(ProtocolError::Framing("abandon payload too short".to_string()));
        }
        let stream_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let reason = match payload[4] {
            0 => None,
            byte => Some(ResetReason::from_wire(byte).ok_or_else(|| ProtocolError::Framing("unknown reset reason".to_string()))?),
        };
        let count = payload[5] as usize;
        if payload.len() < 6 + count * 16 {
            return Err(ProtocolError::Framing("abandon payload truncated".to_string()));
        }
        let mut budget = ABANDON_MAX_SPAN;
        for i in 0..count {
            let at = 6 + i * 16;
            let start = u64::from_be_bytes(payload[at..at + 8].try_into().expect("8 bytes"));
            let end = u64::from_be_bytes(payload[at + 8..at + 16].try_into().expect("8 bytes"));
            // Only what the receive window covers: nothing below it is
            // pending, and nothing beyond it can be told apart from a lie.
            let mut n = start.max(self.expected_recv_nonce);
            let last = end.min(self.expected_recv_nonce.saturating_add(self.max_reorder));
            while n <= last && budget > 0 {
                self.record_nonce(n)?;
                budget -= 1;
                if n == u64::MAX {
                    break;
                }
                n += 1;
            }
        }
        if let Some(reason) = reason {
            if self.kill_stream(stream_id) {
                app.push(ProtocolAction::StreamReset(stream_id, reason));
            }
        }
        Ok(())
    }

    /// v6, on the tick: frames the sender gives up on, and datagrams that
    /// were not acknowledged in time.
    ///
    /// A `Data` frame given up on resets its stream (and only that one): every
    /// frame of it still in flight is dropped too, and one `Abandon` carrying
    /// all their nonces and the reason `Lost` goes to the peer, retransmitted
    /// until acknowledged. The caller gets `StreamReset` as well. Frames of
    /// other kinds are evicted as in v5; the receiver's NACK for the hole they
    /// leave is answered with an `Abandon` (`on_nack_v6`).
    fn v6_tick_losses(&mut self, now: Instant, base_rto: Duration, actions: &mut Vec<ProtocolAction>) -> Result<(), ProtocolError> {
        let grace = self.retry_limit();
        let give_up = self.frame_give_up;
        let mut by_stream: BTreeMap<u32, Vec<u64>> = BTreeMap::new();
        for f in self.sent_history.iter() {
            let given_up = f.is_retransmittable
                && !f.no_resend
                && f.retries > grace
                && now.duration_since(f.first_sent) >= give_up;
            if given_up && f.kind == FrameKind::Data {
                by_stream.entry(f.stream_id).or_default();
            }
        }
        if !by_stream.is_empty() {
            let mut freed = 0u64;
            for f in self.sent_history.iter() {
                if f.is_retransmittable && f.kind == FrameKind::Data {
                    if let Some(nonces) = by_stream.get_mut(&f.stream_id) {
                        nonces.push(f.nonce);
                        freed += f.bytes.len() as u64;
                    }
                }
            }
            self.cc.on_discard(freed);
            self.sent_history
                .retain(|f| !(f.is_retransmittable && f.kind == FrameKind::Data && by_stream.contains_key(&f.stream_id)));
            for (stream_id, nonces) in by_stream {
                tracing::debug!("Gave up on a frame of stream {}: resetting it", stream_id);
                self.kill_stream(stream_id);
                for frame in self.build_abandon(stream_id, Some(ResetReason::Lost), &nonces)? {
                    actions.push(ProtocolAction::SendDatagram(frame));
                }
                actions.push(ProtocolAction::StreamReset(stream_id, ResetReason::Lost));
            }
        }

        // A datagram that nothing acknowledged by now is lost.
        let lost_after = base_rto.saturating_mul(DATAGRAM_LOSS_RTOS).min(MAX_EFFECTIVE_RTO);
        let mut lost = Vec::new();
        let mut lost_bytes = 0u64;
        for f in self.sent_history.iter().filter(|f| f.no_resend && now.duration_since(f.first_sent) >= lost_after) {
            lost.push(f.nonce);
            lost_bytes += f.bytes.len() as u64;
        }
        if !lost.is_empty() {
            // The same age test as above, against the same `now`.
            self.sent_history.retain(|f| !(f.no_resend && now.duration_since(f.first_sent) >= lost_after));
            self.cc.on_discard(lost_bytes);
            self.cc.on_loss(lost_bytes);
            for frame in self.build_abandon(0, None, &lost)? {
                actions.push(ProtocolAction::SendDatagram(frame));
            }
        }
        Ok(())
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
        if let Some(keys) = &self.v6_hs {
            // v6: the same body, masked whole (see `crypto::handshake_v6`).
            return Ok(Bytes::from(crate::crypto::handshake_v6::seal(keys, self.own_hs_direction(), &out)));
        }
        crate::crypto::obfuscate_packet_inplace(&mut out, &self.obfuscation_key, true);
        Ok(Bytes::from(out))
    }

    fn own_hs_direction(&self) -> crate::crypto::HsDirection {
        match self.role {
            NoiseRole::Initiator => crate::crypto::HsDirection::ClientToServer,
            NoiseRole::Responder => crate::crypto::HsDirection::ServerToClient,
        }
    }

    fn peer_hs_direction(&self) -> crate::crypto::HsDirection {
        match self.role {
            NoiseRole::Initiator => crate::crypto::HsDirection::ServerToClient,
            NoiseRole::Responder => crate::crypto::HsDirection::ClientToServer,
        }
    }

    fn build_tracked_datagram(&mut self, stream_id: u16, kind: FrameKind, payload: Bytes) -> Result<Bytes, ProtocolError> {
        let meta = FrameMeta { kind, stream_id: u32::from(stream_id), seq: 0, retransmittable: true, no_resend: false };
        self.build_frame(meta, payload)
    }

    fn build_control_datagram(&mut self, stream_id: u16, kind: FrameKind, payload: Bytes) -> Result<Bytes, ProtocolError> {
        let meta = FrameMeta { kind, stream_id: u32::from(stream_id), seq: 0, retransmittable: false, no_resend: false };
        self.build_frame(meta, payload)
    }

    /// A v6 stream's `Data` frame: the next `stream_seq` of the stream, which
    /// is spent only when the frame was built.
    fn build_stream_frame(&mut self, stream_id: u32, payload: Bytes) -> Result<Bytes, ProtocolError> {
        if self.dead_streams.contains(&stream_id) {
            return Err(ProtocolError::State(format!("stream {stream_id} is reset or released")));
        }
        let seq = self.send_seq.get(&stream_id).copied().unwrap_or(0);
        let next = seq
            .checked_add(1)
            .ok_or_else(|| ProtocolError::State("stream sequence exhausted".to_string()))?;
        let meta = FrameMeta { kind: FrameKind::Data, stream_id, seq, retransmittable: true, no_resend: false };
        let frame = self.build_frame(meta, payload)?;
        self.send_seq.insert(stream_id, next);
        Ok(frame)
    }

    fn build_frame(&mut self, meta: FrameMeta, payload: Bytes) -> Result<Bytes, ProtocolError> {
        let FrameMeta { kind, stream_id, seq, retransmittable: is_retransmittable, no_resend } = meta;
        let padding = self.padder.build_padding(payload.len());
        let plaintext = if self.v6 {
            // A frame never exceeds the path MTU.
            if payload.len() > self.max_payload() {
                return Err(ProtocolError::Framing(format!(
                    "payload of {} bytes exceeds the {} a datagram carries",
                    payload.len(),
                    self.max_payload()
                )));
            }
            FramedPacketV2::new(kind, stream_id, seq, payload, Bytes::from(padding))?.encode()
        } else {
            let header = FrameHeader {
                version: 1,
                kind,
                stream_id: stream_id as u16,
                payload_len: payload.len() as u32,
                pad_len: padding.len() as u16,
            };
            FramedPacket {
                header,
                payload,
                padding: Bytes::from(padding),
            }
            .encode()
        };

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
        
        self.push_sent_frame(nonce, final_bytes.clone(), FrameMeta { kind, stream_id, seq, retransmittable: is_retransmittable, no_resend });

        Ok(final_bytes)
    }

    pub fn set_session_keys(&mut self, session_id: u32, obfuscation_key: [u8; 8]) {
        self.session_id = session_id;
        self.obfuscation_key = obfuscation_key;
    }

    /// The adaptive RTO (RFC 6298 SRTT + 4*RTTVAR), never below the configured
    /// one, which is all there is before the first ACK.
    fn base_rto(&self) -> Duration {
        self.cc.rto().max(self.rto).max(Duration::from_millis(1))
    }

    /// A frame is retransmitted until it has been sent this many times more,
    /// then given up on.
    fn retry_limit(&self) -> u8 {
        self.max_retries.saturating_add(2)
    }

    /// How long the sender keeps retransmitting a frame before it gives up,
    /// by the same schedule `handle_tick` follows. Both ends run the same
    /// configuration, so the receiver uses its own estimate of it.
    fn sender_gives_up_after(&self) -> Duration {
        let base = self.base_rto();
        let schedule: Duration =
            (0..=self.retry_limit()).map(|retries| retransmit_wait(base, retries, self.reliable_carrier)).sum();
        schedule.max(self.frame_give_up)
    }

    /// How long a gap waits before it counts as a loss; see REORDER_WINDOW_MIN.
    fn reorder_window(&mut self) -> Duration {
        if self.reorder_mult > 1 && self.reorder_mult_at.elapsed() >= REORDER_MULT_DECAY {
            self.reorder_mult /= 2;
            self.reorder_mult_at = Instant::now();
        }
        (self.cc.smoothed_rtt() / 4)
            .saturating_mul(self.reorder_mult)
            .clamp(REORDER_WINDOW_MIN, REORDER_WINDOW_MAX)
    }

    /// `expected_recv_nonce` moved: the gap closed, or the next one starts now.
    fn gap_moved(&mut self) {
        self.gap_since = (!self.reorder_buffer.is_empty()).then(Instant::now);
        self.gap_nacked = false;
        self.gap_nack_count = 0;
    }

    /// A gap that was NACKed and is still open, with no frame arriving to
    /// prompt another NACK: the NACK, or the frame sent for it, was lost.
    /// The tick asks again, with a growing pause (RTO x2, x4, ... up to
    /// RENACK_MAX), until the gap closes or `recover_stalled_gap` skips it.
    ///
    /// This is not only for lost data: a hole can be a control frame (an ACK
    /// or NACK holds a nonce too) that no retransmit timer ever resends, and
    /// the SACK of what lies behind it lets the sender forget everything, so
    /// a lost NACK left both ends silent for good.
    fn renack_due(&self) -> bool {
        let wait = self
            .base_rto()
            .saturating_mul(1u32 << self.gap_nack_count.clamp(1, 6))
            .min(RENACK_MAX);
        self.gap_nacked && self.gap_since.is_some() && self.last_nack_sent.elapsed() >= wait
    }

    /// A NACK for the frame at `expected_recv_nonce`, once the gap is older
    /// than the reorder window, at most once per rto/2 so a lost frame is
    /// asked for again without a retransmit storm (floor 10 ms for low-RTT
    /// links).
    fn nack_if_due(&mut self) -> Option<Bytes> {
        let since = self.gap_since?;
        if since.elapsed() < self.reorder_window() {
            return None;
        }
        let nack_cooldown = (self.cc.rto() / 2).max(Duration::from_millis(10));
        if self.last_nack_sent.elapsed() < nack_cooldown {
            return None;
        }
        self.last_nack_sent = Instant::now();
        self.gap_nacked = true;
        self.gap_nack_count = self.gap_nack_count.saturating_add(1);
        self.nacked_nonce = Some(self.expected_recv_nonce);
        let nack_payload = self.expected_recv_nonce.to_be_bytes();
        self.build_control_datagram(0, FrameKind::Nack, Bytes::copy_from_slice(&nack_payload)).ok()
    }

    fn handle_tick(&mut self) -> Result<ProtocolAction, ProtocolError> {
        let mut actions = Vec::new();

        // ── Pending ACK flush ─────────────────────────────────────────
        if let Some(ack_frame) = self.build_ack_if_due()? {
            actions.push(ProtocolAction::SendDatagram(ack_frame));
        }

        // ── A gap older than the reorder window, nothing new since ────
        // Inbound frames NACK a gap once it is old enough; when none arrive
        // after that point (the tail of a burst) the tick has to.
        if !self.gap_nacked || self.renack_due() {
            if let Some(nack_frame) = self.nack_if_due() {
                actions.push(ProtocolAction::SendDatagram(nack_frame));
            }
        }

        let now = Instant::now();
        let base_rto = self.base_rto();

        // ── v6: given-up streams and lost datagrams ──────────────────
        if self.v6 {
            self.v6_tick_losses(now, base_rto, &mut actions)?;
        }

        // ── Zombie frame eviction ────────────────────────────────────
        // Past max_retries + 2 attempts AND FRAME_GIVE_UP since it was first
        // sent. A count alone gave up within ~30 s on a short path (small RTO),
        // inside an outage the session was about to survive.
        let grace = self.retry_limit();
        let give_up = self.frame_give_up;
        let given_up_frame =
            |f: &SentFrame| f.is_retransmittable && f.retries > grace && now.duration_since(f.first_sent) >= give_up;
        let before = self.sent_history.len();
        let given_up: u64 = self
            .sent_history
            .iter()
            .filter(|f| given_up_frame(f))
            .map(|f| f.bytes.len() as u64)
            .sum();
        self.cc.on_discard(given_up);
        self.sent_history.retain(|f| !given_up_frame(f));
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
            // A v6 datagram is never resent (`no_resend` is false for every
            // v5 frame).
            if !frame.is_retransmittable || frame.no_resend {
                continue;
            }
            // Out of budget for this tick — stop scanning rather than walking the
            // rest of the queue. sent_history is in send order, so everything we
            // skip is strictly newer than what we already handled; deferring it to
            // the next tick preserves oldest-first retransmit priority.
            if retransmit_budget == 0 {
                break;
            }

            let wait = retransmit_wait(base_rto, frame.retries, self.reliable_carrier);
            let due = if self.reliable_carrier {
                // What was in flight on a connection the session left, and a
                // slow safety net for a frame the sending side dropped from a
                // full queue with nothing after it (no gap, so no NACK).
                self.path_changed_at.is_some_and(|t| frame.last_sent < t)
                    || now.duration_since(frame.last_sent) >= wait
            } else {
                now.duration_since(frame.last_sent) >= wait
            };
            if due {
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
                self.cc.on_retransmit(frame.bytes.len() as u64);
                actions.push(ProtocolAction::SendDatagram(frame.bytes.clone()));
                retransmit_budget -= 1;
            }
        }

        // Our Close was acknowledged, or retransmitted until given up: the
        // session is over even if the peer never sends its own Close (it
        // crashed, or the path died). It used to sit in Closing until the
        // caller's idle timeout.
        if self.state == OstpState::Closing && !self.sent_history.iter().any(|f| f.is_retransmittable && !f.no_resend) {
            self.state = OstpState::Closed;
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
        // The history is in nonce order, and a NACK for a nonce that is not in
        // it must not cost a scan of the whole history.
        let i = self.sent_history.partition_point(|f| f.nonce < nonce);
        let frame = self.sent_history.get_mut(i).filter(|f| f.nonce == nonce)?;
        frame.last_sent = Instant::now();
        frame.retries = frame.retries.saturating_add(1);
        Some(frame.bytes.clone())
    }

    fn push_sent_frame(&mut self, nonce: u64, bytes: Bytes, meta: FrameMeta) {
        if meta.retransmittable {
            self.cc.on_send(bytes.len() as u64);
        }
        self.sent_history.push_back(SentFrame {
            nonce,
            bytes,
            first_sent: Instant::now(),
            last_sent: Instant::now(),
            retries: 0,
            is_retransmittable: meta.retransmittable,
            kind: meta.kind,
            stream_id: meta.stream_id,
            no_resend: meta.no_resend,
        });
        if self.sent_history.len() > self.max_sent_history {
            let overflow = self.sent_history.len() - self.max_sent_history;
            tracing::debug!("sent_history overflow: evicting {} oldest frames (cap={})",
                overflow, self.max_sent_history
            );
            while self.sent_history.len() > self.max_sent_history {
                if let Some(old) = self.sent_history.pop_front() {
                    if old.is_retransmittable {
                        self.cc.on_discard(old.bytes.len() as u64);
                    }
                }
            }
        }
    }

    fn drop_acked_frames(&mut self, ranges: &[(u64, u64)]) {
        // An ACK carries up to 255 ranges and the history up to 32768 frames; a
        // peer repeating one that matches nothing would make every packet cost
        // their product on the server's single packet loop. Merged and sorted,
        // a range check is a binary search, and an ACK outside the history
        // costs nothing.
        let ranges = merge_ranges(ranges);
        let ranges = ranges.as_slice();
        let (Some(oldest), Some(newest)) = (self.sent_history.front(), self.sent_history.back()) else {
            return;
        };
        if !ranges.iter().any(|&(start, end)| end >= oldest.nonce && start <= newest.nonce) {
            return;
        }
        let now = Instant::now();
        let mut acked_bytes = 0u64;
        let mut min_rtt: Option<Duration> = None;

        // Only frames that carry data count: our own ACKs and NACKs sit in the
        // history too, but they were never charged as in flight, and their
        // acknowledgement waits for whatever the peer next sends, which made
        // seconds-long "RTT" samples on a download-only side.
        for frame in self.sent_history.iter().filter(|f| f.is_retransmittable) {
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

/// How long a frame sent `retries` times waits before the next retransmit.
///
/// Exponential backoff, but bounded in absolute terms. The base RTO is itself
/// adaptive and can reach RTO_MAX (16 s) on a congested path; multiplied by
/// the 64x backoff cap that is a frame unretransmitted for ~17 minutes, long
/// past the point where the session is dead to the user. On a reliable
/// carrier the timer is only a slow safety net (see `reliable_carrier`).
fn retransmit_wait(base_rto: Duration, retries: u8, reliable_carrier: bool) -> Duration {
    let backoff = 1u32 << u32::from(retries).min(6);
    let wait = base_rto.saturating_mul(backoff).min(MAX_EFFECTIVE_RTO);
    if reliable_carrier {
        wait.max(RELIABLE_CARRIER_RTO)
    } else {
        wait
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

/// Sorted, non-overlapping ranges covering the same nonces (empty ones dropped).
fn merge_ranges(ranges: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut sorted: Vec<(u64, u64)> = ranges.iter().copied().filter(|(start, end)| start <= end).collect();
    sorted.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(sorted.len());
    for (start, end) in sorted {
        match merged.last_mut() {
            Some(last) if start <= last.1.saturating_add(1) => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
}

/// Whether `nonce` is in one of `ranges`, which `merge_ranges` returned.
fn nonce_in_ranges(nonce: u64, ranges: &[(u64, u64)]) -> bool {
    let after = ranges.partition_point(|&(start, _)| start <= nonce);
    after > 0 && ranges[after - 1].1 >= nonce
}

#[cfg(test)]
mod tests {
    #[test]
    fn defaults_and_handshake_payload_layout() {
        let c = ProtocolConfig::with_defaults(NoiseRole::Initiator, 1350);
        assert_eq!((c.rto_ms, c.max_retries, c.ack_delay_ms), (100, 8, 5));
        assert_eq!((c.max_reorder, c.max_reorder_buffer, c.max_sent_history), (16384, 8192, 32768));
        assert_eq!(c.max_padding, 1302);
        assert_eq!(ProtocolConfig::with_defaults(NoiseRole::Initiator, 100).max_padding, 256);
        let p = build_handshake_payload(b"key", 0x0102_0304);
        assert_eq!(p.len(), 8 + 4 + 3);
        assert_eq!(&p[8..12], &[1, 2, 3, 4]);
        assert_eq!(&p[12..], b"key");
    }

    use super::*;

    #[test]
    fn merged_ack_ranges_cover_the_same_nonces() {
        let raw = [(10, 12), (0, 3), (4, 4), (11, 20), (30, 29), (u64::MAX - 1, u64::MAX)];
        let merged = merge_ranges(&raw);
        assert_eq!(merged, vec![(0, 4), (10, 20), (u64::MAX - 1, u64::MAX)]);
        for n in [0, 4, 5, 9, 10, 20, 21, 29, 30, u64::MAX - 2, u64::MAX] {
            let expected = raw.iter().any(|&(s, e)| n >= s && n <= e);
            assert_eq!(nonce_in_ranges(n, &merged), expected, "nonce {n}");
        }
        assert!(!nonce_in_ranges(5, &[]));
    }
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
            v6: None,
        }
    }

    fn v6_keys() -> crate::crypto::HsKeys {
        crate::crypto::HsKeys { mask_key: [0x11; 32], tag_key: [0x22; 32] }
    }

    /// A v6 pair of configs: the client holds the public half of `private`.
    fn v6_configs(private: [u8; 32], client_knows: [u8; 32]) -> (ProtocolConfig, ProtocolConfig) {
        use crate::crypto::ServerStatic;
        let mut c = make_config(NoiseRole::Initiator);
        c.handshake_payload = b"hello".to_vec();
        c.v6 = Some(V6Handshake { server: ServerStatic::Public(client_knows), hs: v6_keys() });
        let mut s = make_config(NoiseRole::Responder);
        s.v6 = Some(V6Handshake { server: ServerStatic::Private(private), hs: v6_keys() });
        (c, s)
    }

    fn server_reply(action: ProtocolAction) -> (Bytes, Bytes) {
        match action {
            ProtocolAction::HandshakePayload(p, Some(d)) => (p, d),
            _ => panic!("expected the handshake payload and a reply"),
        }
    }

    #[test]
    fn a_v6_handshake_establishes_and_carries_data() {
        let (private, public) = crate::crypto::noise::generate_server_key();
        let (ccfg, scfg) = v6_configs(private, public);
        let mut client = ProtocolMachine::new(ccfg).unwrap();
        let mut server = ProtocolMachine::new(scfg).unwrap();
        let ProtocolAction::SendDatagram(msg1) = client.on_event(OstpEvent::Start).unwrap() else {
            panic!("expected the handshake datagram")
        };
        assert_eq!(v6_handshake_session_id(&v6_keys(), &msg1), Some(1));
        let (payload, reply) = server_reply(server.on_event(OstpEvent::Inbound(msg1)).unwrap());
        assert_eq!(&payload[..], b"hello", "the client's payload reaches the server");
        client.on_event(OstpEvent::Inbound(reply)).unwrap();
        assert_eq!(client.state(), OstpState::Established);
        assert_eq!(server.state(), OstpState::Established);

        let ProtocolAction::SendDatagram(data) = client.on_event(OstpEvent::Outbound(7, Bytes::from_static(b"ping"))).unwrap() else {
            panic!("expected a data datagram")
        };
        let delivered = match server.on_event(OstpEvent::Inbound(data)).unwrap() {
            ProtocolAction::DeliverApp(7, d) => d,
            ProtocolAction::Multiple(list) => list
                .into_iter()
                .find_map(|a| match a {
                    ProtocolAction::DeliverApp(7, d) => Some(d),
                    _ => None,
                })
                .expect("the data"),
            _ => panic!("expected the data"),
        };
        assert_eq!(&delivered[..], b"ping");
    }

    /// The point of NK: a server that holds an access key but not the private
    /// key the client's profile names cannot complete the handshake.
    #[test]
    fn a_v6_client_refuses_a_server_with_another_key() {
        let (_, pinned_public) = crate::crypto::noise::generate_server_key();
        let (impostor_private, _) = crate::crypto::noise::generate_server_key();
        let (ccfg, scfg) = v6_configs(impostor_private, pinned_public);
        let mut client = ProtocolMachine::new(ccfg).unwrap();
        let mut server = ProtocolMachine::new(scfg).unwrap();
        let ProtocolAction::SendDatagram(msg1) = client.on_event(OstpEvent::Start).unwrap() else {
            panic!("expected the handshake datagram")
        };
        // The first message is encrypted to the pinned key: the impostor
        // cannot even read it, so it has nothing to answer with.
        assert!(server.on_event(OstpEvent::Inbound(msg1)).is_err());
        assert_ne!(client.state(), OstpState::Established);
    }

    #[test]
    fn v5_and_v6_do_not_read_each_other() {
        let (private, public) = crate::crypto::noise::generate_server_key();
        let (c6, s6) = v6_configs(private, public);
        // a v5 client against a v6 server
        let mut client5 = ProtocolMachine::new(make_config(NoiseRole::Initiator)).unwrap();
        let mut server6 = ProtocolMachine::new(s6).unwrap();
        let ProtocolAction::SendDatagram(m) = client5.on_event(OstpEvent::Start).unwrap() else { panic!() };
        assert!(server6.on_event(OstpEvent::Inbound(m)).is_err());
        // a v6 client against a v5 server
        let mut client6 = ProtocolMachine::new(c6).unwrap();
        let mut server5 = ProtocolMachine::new(make_config(NoiseRole::Responder)).unwrap();
        let ProtocolAction::SendDatagram(m) = client6.on_event(OstpEvent::Start).unwrap() else { panic!() };
        assert!(server5.on_event(OstpEvent::Inbound(m)).is_err());
    }

    /// A damaged copy of a handshake datagram (any single bit) is refused and
    /// leaves the machine able to take the clean copy that follows: on both
    /// sides, for a bit anywhere in the datagram.
    #[test]
    fn a_damaged_v6_handshake_copy_does_not_spoil_the_clean_one() {
        let (private, public) = crate::crypto::noise::generate_server_key();
        let flip = |d: &Bytes, bit: usize| {
            let mut v = d.to_vec();
            v[bit / 8] ^= 1 << (bit % 8);
            Bytes::from(v)
        };
        // Bits in the nonce, the tag, the session id, the length, the Noise
        // message and the padding (the last byte).
        let picks = |len: usize| vec![3, 12 * 8 + 1, 16 * 8, 20 * 8 + 3, 30 * 8, 60 * 8 + 5, len * 8 - 1];

        let (ccfg, scfg) = v6_configs(private, public);
        let mut client = ProtocolMachine::new(ccfg).unwrap();
        let ProtocolAction::SendDatagram(msg1) = client.on_event(OstpEvent::Start).unwrap() else { panic!() };
        let mut server = ProtocolMachine::new(scfg).unwrap();
        for bit in picks(msg1.len()) {
            let r = server.on_event(OstpEvent::Inbound(flip(&msg1, bit)));
            // A flipped padding bit changes nothing the server reads.
            if bit == msg1.len() * 8 - 1 {
                continue;
            }
            assert!(r.is_err(), "bit {bit} of the first message was accepted");
            assert_ne!(server.state(), OstpState::Established);
        }
        // The padding-bit copy may have completed the handshake already; a
        // fresh server takes the clean one after the damaged ones.
        let (_, scfg) = v6_configs(private, public);
        let mut server = ProtocolMachine::new(scfg).unwrap();
        for bit in [3, 12 * 8 + 1, 16 * 8, 20 * 8 + 3, 30 * 8, 60 * 8 + 5] {
            assert!(server.on_event(OstpEvent::Inbound(flip(&msg1, bit))).is_err());
        }
        let (_, reply) = server_reply(server.on_event(OstpEvent::Inbound(msg1)).unwrap());

        for bit in [3, 12 * 8 + 1, 16 * 8, 20 * 8 + 3, 30 * 8, 60 * 8 + 5] {
            assert!(client.on_event(OstpEvent::Inbound(flip(&reply, bit))).is_err(), "bit {bit} of the reply was accepted");
            assert_ne!(client.state(), OstpState::Established);
        }
        client.on_event(OstpEvent::Inbound(reply.clone())).unwrap();
        assert_eq!(client.state(), OstpState::Established);
        // The reply once more (the server resent it): refused, session intact.
        assert!(client.on_event(OstpEvent::Inbound(reply)).is_err());
        assert_eq!(client.state(), OstpState::Established);
    }

    /// A resend of a v6 handshake is the same Noise message in a new outer
    /// layer: no byte position keeps its value from one copy to the next, and
    /// every copy opens to the same hello on a server machine.
    #[test]
    fn resealed_v6_handshakes_share_no_bytes_and_carry_the_same_hello() {
        let (private, public) = crate::crypto::noise::generate_server_key();
        let (ccfg, scfg) = v6_configs(private, public);
        let mut client = ProtocolMachine::new(ccfg).unwrap();
        assert!(client.handshake_resend().unwrap().is_none(), "nothing to resend before Start");
        let ProtocolAction::SendDatagram(first) = client.on_event(OstpEvent::Start).unwrap() else { panic!() };

        let rounds = 300;
        let mut same = vec![0u32; first.len().min(48)];
        let mut equal_total = 0usize;
        let mut compared = 0usize;
        let mut lengths = std::collections::HashSet::new();
        for _ in 0..rounds {
            let again = client.handshake_resend().unwrap().expect("a v6 resend");
            lengths.insert(again.len());
            for (i, (a, b)) in first.iter().zip(again.iter()).enumerate() {
                compared += 1;
                if a == b {
                    equal_total += 1;
                    if let Some(c) = same.get_mut(i) {
                        *c += 1;
                    }
                }
            }
            // The same Noise message and hello: a server machine takes it.
            let mut server = ProtocolMachine::new(scfg.clone()).unwrap();
            let (payload, _) = server_reply(server.on_event(OstpEvent::Inbound(again)).unwrap());
            assert_eq!(&payload[..], b"hello");
        }
        // Chance agreement is 1/256 a byte. A fixed byte (nonce, tag, session
        // id, length, Noise message) would agree in every round.
        assert!(equal_total * 100 < compared, "{equal_total} of {compared} bytes agree");
        assert!(same.iter().all(|&n| n < 20), "a byte position stays the same: {same:?}");
        assert!(lengths.len() > 10, "the padding length does not vary: {lengths:?}");
    }

    /// v5 resends stay byte-identical: a 0.4.x server keys on the payload, and
    /// the wire is not to change.
    #[test]
    fn a_v5_handshake_has_no_resealed_resend() {
        let mut client = ProtocolMachine::new(make_config(NoiseRole::Initiator)).unwrap();
        client.on_event(OstpEvent::Start).unwrap();
        assert!(client.handshake_resend().unwrap().is_none());
    }

    #[test]
    fn the_server_key_must_fit_the_role() {
        use crate::crypto::ServerStatic;
        let mut c = make_config(NoiseRole::Initiator);
        c.v6 = Some(V6Handshake { server: ServerStatic::Private([1; 32]), hs: v6_keys() });
        assert!(ProtocolMachine::new(c).is_err());
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

    /// The MTU is user config: zero used to divide by zero in the congestion
    /// controller and one under 64 panicked the padder's `clamp`.
    #[test]
    fn a_nonsense_mtu_is_raised_not_a_panic() {
        for mtu in [0usize, 1, 63] {
            let mut ccfg = make_config(NoiseRole::Initiator);
            ccfg.mtu = mtu;
            let mut scfg = make_config(NoiseRole::Responder);
            scfg.mtu = mtu;
            let mut client = ProtocolMachine::new(ccfg).unwrap();
            let mut server = ProtocolMachine::new(scfg).unwrap();
            let ProtocolAction::SendDatagram(msg1) = client.on_event(OstpEvent::Start).unwrap() else {
                panic!("expected the handshake datagram")
            };
            server.on_event(OstpEvent::Start).unwrap();
            let reply = match server.on_event(OstpEvent::Inbound(msg1)).unwrap() {
                ProtocolAction::HandshakePayload(_, Some(d)) => d,
                ProtocolAction::Multiple(list) => list
                    .into_iter()
                    .find_map(|a| match a {
                        ProtocolAction::HandshakePayload(_, Some(d)) => Some(d),
                        ProtocolAction::SendDatagram(d) => Some(d),
                        _ => None,
                    })
                    .expect("a handshake reply"),
                _ => panic!("unexpected server action"),
            };
            client.on_event(OstpEvent::Inbound(reply)).unwrap();
            assert!(client.max_payload() >= 64);
            assert!(client.cwnd_packets() > 0);
            client.on_event(OstpEvent::Outbound(1, Bytes::from_static(b"x"))).unwrap();
            client.on_event(OstpEvent::Tick).unwrap();
        }
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
        // A short give-up time keeps the subtraction valid on a fresh machine.
        server.frame_give_up = Duration::from_secs(5);
        server.last_recv_advance = Instant::now() - server.sender_gives_up_after() - Duration::from_secs(1);

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

    /// After an outage of 10 s (the old upper bound of the wait) the sender
    /// is still retransmitting, so the receiver must still wait: skipping then
    /// left a hole in a stream that the next retransmit would have filled.
    #[test]
    fn gap_recovery_waits_as_long_as_the_sender_retransmits() {
        let (mut client, mut server) = do_handshake();
        let frames = make_data_frames(&mut client, 3);
        server.on_event(OstpEvent::Inbound(frames[0].clone())).unwrap();
        server.on_event(OstpEvent::Inbound(frames[2].clone())).unwrap();

        // At a 100 ms RTO and the max_retries the client and server run with
        // (8), the sender retransmits for ~38 s.
        server.max_retries = 8;
        let gives_up = server.sender_gives_up_after();
        assert!(gives_up > Duration::from_secs(30), "{gives_up:?}");

        server.last_recv_advance = Instant::now() - Duration::from_secs(11);
        let action = server.on_event(OstpEvent::Inbound(frames[0].clone())).unwrap();
        assert!(delivered_payloads(&action).is_empty(), "skipped while the sender was still retransmitting");

        // The retransmit arrives: nothing was lost.
        let delivered = delivered_payloads(&server.on_event(OstpEvent::Inbound(frames[1].clone())).unwrap());
        assert_eq!(delivered.len(), 2);
    }

    /// The receiver's wait and the sender's schedule come from one function.
    #[test]
    fn the_wait_matches_the_retransmit_schedule() {
        let base = Duration::from_millis(100);
        let total: Duration = (0..=10).map(|r| retransmit_wait(base, r, false)).sum();
        // 0.1 + 0.2 + 0.4 + 0.8 + 1.6 + 3.2 + 6.4 x 5 = 38.3 s
        assert_eq!(total, Duration::from_millis(38_300));
        assert_eq!(retransmit_wait(Duration::from_secs(1), 9, false), MAX_EFFECTIVE_RTO);
        assert_eq!(retransmit_wait(base, 0, true), RELIABLE_CARRIER_RTO);
    }

    /// Every datagram `action` would put on the wire, in order.
    fn datagrams_in(action: &ProtocolAction) -> Vec<Bytes> {
        match action {
            ProtocolAction::SendDatagram(d) => vec![d.clone()],
            ProtocolAction::Multiple(list) => list.iter().flat_map(datagrams_in).collect(),
            _ => vec![],
        }
    }

    #[test]
    fn path_change_makes_unacked_frames_due_at_once() {
        let (mut client, _server) = do_handshake();
        let sent = make_data_frames(&mut client, 3);
        assert_eq!(sent.len(), 3);

        // Nothing is due right after sending.
        let before = client.on_event(OstpEvent::Tick).unwrap();
        assert!(datagrams_in(&before).iter().all(|f| !sent.contains(f)));

        client.on_path_change();
        let after = client.on_event(OstpEvent::Tick).unwrap();
        let resent = datagrams_in(&after);
        for frame in &sent {
            assert!(resent.contains(frame), "unacked frame was not retransmitted on the new path");
        }
    }

    #[test]
    fn path_change_keeps_the_session_working() {
        let (mut client, mut server) = do_handshake();
        client.on_path_change();
        server.on_path_change();

        let action = client.on_event(OstpEvent::Outbound(1, Bytes::from_static(b"after the move"))).unwrap();
        let datagram = datagrams_in(&action).remove(0);
        let delivered = delivered_payloads(&server.on_event(OstpEvent::Inbound(datagram)).unwrap());
        assert_eq!(delivered, vec![Bytes::from_static(b"after the move")]);
    }

    #[test]
    fn only_authenticated_datagrams_count_as_received() {
        let (mut client, mut server) = do_handshake();
        let frames = make_data_frames(&mut client, 2);
        assert_eq!(server.authenticated_recv_count(), 0);

        server.on_event(OstpEvent::Inbound(frames[0].clone())).unwrap();
        assert_eq!(server.authenticated_recv_count(), 1);

        // A duplicate is answered with an ACK but is not decrypted again.
        server.on_event(OstpEvent::Inbound(frames[0].clone())).unwrap();
        assert_eq!(server.authenticated_recv_count(), 1);

        // A forged datagram does not count, whatever on_event returns.
        let mut forged = frames[1].to_vec();
        let last = forged.len() - 1;
        forged[last] ^= 0xff;
        let _ = server.on_event(OstpEvent::Inbound(Bytes::from(forged)));
        assert_eq!(server.authenticated_recv_count(), 1);

        server.on_event(OstpEvent::Inbound(frames[1].clone())).unwrap();
        assert_eq!(server.authenticated_recv_count(), 2);
    }

    fn datagrams(action: ProtocolAction) -> Vec<Bytes> {
        match action {
            ProtocolAction::SendDatagram(d) => vec![d],
            ProtocolAction::Multiple(list) => list.into_iter().flat_map(datagrams).collect(),
            _ => Vec::new(),
        }
    }

    #[test]
    fn a_reliable_carrier_resends_only_after_a_path_change() {
        let (mut client, _server) = do_handshake();
        client.set_reliable_carrier(true);
        let sent = datagrams(client.on_event(OstpEvent::Outbound(1, Bytes::from_static(b"payload"))).unwrap());
        assert_eq!(sent.len(), 1);

        // Long past any RTO: over TCP the frame is queued, not lost.
        std::thread::sleep(Duration::from_millis(250));
        let resent = datagrams(client.on_event(OstpEvent::Tick).unwrap());
        assert!(!resent.contains(&sent[0]), "no timer-driven resend on a reliable carrier");

        // The session moved to a new connection: what was in flight is gone,
        // so it is resent, once.
        client.on_path_change();
        let resent = datagrams(client.on_event(OstpEvent::Tick).unwrap());
        assert!(resent.contains(&sent[0]), "in-flight frames are resent after a path change");
        std::thread::sleep(Duration::from_millis(250));
        let again = datagrams(client.on_event(OstpEvent::Tick).unwrap());
        assert!(!again.contains(&sent[0]), "and only once");

        // UDP keeps timer-driven retransmission.
        client.set_reliable_carrier(false);
        std::thread::sleep(Duration::from_millis(250));
        let udp = datagrams(client.on_event(OstpEvent::Tick).unwrap());
        assert!(udp.contains(&sent[0]), "UDP still retransmits on RTO");
    }

    #[test]
    fn repeated_nacks_for_one_gap_shrink_the_window_once() {
        let (mut client, mut server) = do_handshake();
        // The server sends four frames; the client misses the first.
        let frames: Vec<Bytes> = (0..4)
            .map(|i| datagrams(server.on_event(OstpEvent::Outbound(1, Bytes::from(vec![i as u8; 100]))).unwrap()).remove(0))
            .collect();
        let _ = client.on_event(OstpEvent::Inbound(frames[1].clone())).unwrap(); // the gap opens

        // Each later frame finds the gap older than the reorder window and the
        // NACK cooldown over, so each answer carries a NACK (and maybe an ACK:
        // which datagrams go out depends on timing, so they are all fed in).
        let mut answers = Vec::new();
        for f in &frames[2..] {
            client.gap_since = Some(Instant::now() - REORDER_WINDOW_MAX);
            client.last_nack_sent = Instant::now() - Duration::from_secs(1);
            answers.push(datagrams(client.on_event(OstpEvent::Inbound(f.clone())).unwrap()));
        }

        let feed = |server: &mut ProtocolMachine, datagrams_in: &[Bytes]| {
            datagrams_in
                .iter()
                .flat_map(|d| datagrams(server.on_event(OstpEvent::Inbound(d.clone())).unwrap()))
                .any(|out| out == frames[0])
        };
        let before = server.cc.cwnd();
        assert!(feed(&mut server, &answers[0]), "the client NACKs the gap");
        let after_first_gap = server.cc.cwnd();
        assert!(after_first_gap < before, "the first NACK of a gap is a loss");

        // The same gap NACKed again: retransmitted, but no further cut.
        // An ACK riding along may grow the window a little; a second cut would
        // take it to 0.7 of where it was.
        assert!(feed(&mut server, &answers[1]), "the client NACKs the same gap again");
        assert!(server.cc.cwnd() >= after_first_gap, "repeated NACKs of one gap do not shrink the window again");
    }

    /// A frame a few milliseconds late is a reordering, not a loss: no NACK,
    /// so no retransmission and no smaller window at the sender.
    #[test]
    fn a_reordered_frame_inside_the_window_is_not_a_loss() {
        let (mut client, mut server) = do_handshake();
        let frames: Vec<Bytes> = (0..3)
            .map(|i| datagrams(server.on_event(OstpEvent::Outbound(1, Bytes::from(vec![i as u8; 100]))).unwrap()).remove(0))
            .collect();
        // The widest window (100 ms), so a slow test machine stays inside it.
        client.reorder_mult = REORDER_MULT_MAX;
        let before = server.cc.cwnd();
        let mut to_server = Vec::new();
        for f in [&frames[1], &frames[2], &frames[0]] {
            to_server.extend(datagrams(client.on_event(OstpEvent::Inbound(f.clone())).unwrap()));
        }
        to_server.extend(datagrams(client.on_event(OstpEvent::Tick).unwrap()));
        assert!(client.gap_since.is_none(), "the gap closed");
        for d in &to_server {
            let back = datagrams(server.on_event(OstpEvent::Inbound(d.clone())).unwrap());
            assert!(!back.contains(&frames[0]), "a reordered frame was retransmitted");
        }
        assert!(server.cc.cwnd() >= before, "a reordering shrank the window");
    }

    /// A gap older than the reorder window with nothing arriving after it
    /// (the tail of a burst) is NACKed by the tick.
    #[test]
    fn the_tick_nacks_an_old_gap_once() {
        let (mut client, mut server) = do_handshake();
        let frames: Vec<Bytes> = (0..3)
            .map(|i| datagrams(server.on_event(OstpEvent::Outbound(1, Bytes::from(vec![i as u8; 100]))).unwrap()).remove(0))
            .collect();
        for f in &frames[1..] {
            let _ = client.on_event(OstpEvent::Inbound(f.clone())).unwrap();
        }
        client.gap_since = Some(Instant::now() - REORDER_WINDOW_MAX);
        let before = server.cc.cwnd();
        let mut resent = false;
        for d in datagrams(client.on_event(OstpEvent::Tick).unwrap()) {
            resent |= datagrams(server.on_event(OstpEvent::Inbound(d)).unwrap()).contains(&frames[0]);
        }
        assert!(resent, "the old gap was not NACKed");
        assert!(server.cc.cwnd() < before, "a real loss shrinks the window");

        // Straight after, the tick does not NACK again (it repeats a NACK only
        // after a growing pause: see a_lost_nack_for_a_lost_control_frame_is_asked_again).
        let mut again = false;
        for d in datagrams(client.on_event(OstpEvent::Tick).unwrap()) {
            again |= datagrams(server.on_event(OstpEvent::Inbound(d)).unwrap()).contains(&frames[0]);
        }
        assert!(!again, "the tick does not NACK one gap in a stream");
    }

    /// The stall seen with loss in both directions. A lost ACK (a control
    /// frame: it holds a nonce but no retransmit timer ever resends it) leaves
    /// a hole the receiver can only fill by NACKing. The receiver also SACKs
    /// the data behind the hole, so the sender drops it and has nothing in
    /// flight. If then the NACK, or the frame sent for it, is lost, both ends
    /// are silent for good: the tick used to NACK a gap once.
    #[test]
    fn a_lost_nack_for_a_lost_control_frame_is_asked_again() {
        let (mut client, mut server) = do_handshake();

        // The client sends something; the server's ACK for it (nonce 0 of the
        // server's sequence, a control frame) is lost.
        let hello = datagrams(client.on_event(OstpEvent::Outbound(1, Bytes::from_static(b"hi"))).unwrap()).remove(0);
        server.last_ack_sent = Instant::now() - Duration::from_secs(1);
        let lost_ack = datagrams(server.on_event(OstpEvent::Inbound(hello)).unwrap());
        assert_eq!(lost_ack.len(), 1, "the server ACKs the client's frame");

        // The server then sends three data frames; they arrive and wait
        // behind the hole.
        let frames: Vec<Bytes> = (0..3u8)
            .map(|i| datagrams(server.on_event(OstpEvent::Outbound(1, Bytes::from(vec![i; 100]))).unwrap()).remove(0))
            .collect();
        let mut to_server = Vec::new();
        for f in &frames {
            client.last_ack_sent = Instant::now() - Duration::from_secs(1);
            let out = client.on_event(OstpEvent::Inbound(f.clone())).unwrap();
            assert!(delivered_payloads(&out).is_empty(), "held back behind the missing frame");
            to_server.extend(datagrams(out));
        }
        // The client's SACK reaches the server, which now has nothing in flight.
        for d in to_server {
            let _ = server.on_event(OstpEvent::Inbound(d)).unwrap();
        }
        assert_eq!(server.in_flight_count(), 0, "everything behind the hole was acknowledged");

        // The gap is old enough: the tick NACKs it, and that NACK is lost.
        client.gap_since = Some(Instant::now() - REORDER_WINDOW_MAX);
        client.last_nack_sent = Instant::now() - Duration::from_secs(1);
        let first = datagrams(client.on_event(OstpEvent::Tick).unwrap());
        assert!(!first.is_empty(), "the tick NACKs the old gap");
        assert!(client.gap_nacked);

        // A retry is not a stream: right after, the tick stays quiet.
        let quiet = datagrams(client.on_event(OstpEvent::Tick).unwrap());
        assert!(quiet.is_empty(), "no NACK again straight away");

        // Nothing at all happens on the server side either.
        assert!(datagrams(server.on_event(OstpEvent::Tick).unwrap()).is_empty());

        // Later the tick asks again; this one arrives, the server resends the
        // control frame, and the client delivers everything behind it.
        client.last_nack_sent = Instant::now() - Duration::from_secs(10);
        let second = datagrams(client.on_event(OstpEvent::Tick).unwrap());
        assert!(!second.is_empty(), "the tick asks for the missing frame again");
        let mut delivered = 0;
        for nack in second {
            for resent in datagrams(server.on_event(OstpEvent::Inbound(nack)).unwrap()) {
                delivered += delivered_payloads(&client.on_event(OstpEvent::Inbound(resent)).unwrap()).len();
            }
        }
        assert_eq!(delivered, 3, "the three held frames are delivered once the hole is filled");
    }

    /// Once our Close is acknowledged the session is Closed, even if the peer
    /// never sends a Close of its own.
    #[test]
    fn an_acknowledged_close_ends_the_session() {
        let (mut client, mut server) = do_handshake();
        let close = datagrams(client.on_event(OstpEvent::Close).unwrap()).remove(0);
        assert_eq!(client.state(), OstpState::Closing);
        let _ = client.on_event(OstpEvent::Tick).unwrap();
        assert_eq!(client.state(), OstpState::Closing, "the Close is still unacknowledged");

        // The peer receives it and ACKs, but (gone after that) sends no Close back.
        server.last_ack_sent = Instant::now() - Duration::from_secs(1);
        let acks = datagrams(server.on_event(OstpEvent::Inbound(close)).unwrap());
        assert!(!acks.is_empty(), "the peer ACKs the Close");
        for ack in acks {
            let _ = client.on_event(OstpEvent::Inbound(ack)).unwrap();
        }
        let _ = client.on_event(OstpEvent::Tick).unwrap();
        assert_eq!(client.state(), OstpState::Closed);
    }

    #[test]
    fn the_reorder_buffer_is_bounded_by_the_window() {
        let mut cfg = make_config(NoiseRole::Initiator);
        cfg.max_reorder_buffer = 1 << 20;
        let m = ProtocolMachine::new(cfg).unwrap();
        assert_eq!(m.max_reorder_buffer, crate::congestion::MAX_CWND_PACKETS as usize);
    }

    /// The NACKed frame arriving twice (late original, then the retransmit)
    /// shows the path reorders beyond the window: the window widens. A forged
    /// copy does not count.
    #[test]
    fn a_spurious_nack_widens_the_reorder_window() {
        let (mut client, mut server) = do_handshake();
        let frames: Vec<Bytes> = (0..3)
            .map(|i| datagrams(server.on_event(OstpEvent::Outbound(1, Bytes::from(vec![i as u8; 100]))).unwrap()).remove(0))
            .collect();
        for f in &frames[1..] {
            let _ = client.on_event(OstpEvent::Inbound(f.clone())).unwrap();
        }
        client.gap_since = Some(Instant::now() - REORDER_WINDOW_MAX);
        let _ = client.on_event(OstpEvent::Tick).unwrap();
        assert_eq!(client.nacked_nonce, Some(0));
        let narrow = client.reorder_window();

        let _ = client.on_event(OstpEvent::Inbound(frames[0].clone())).unwrap(); // the late original
        let mut forged = frames[0].to_vec();
        let last = forged.len() - 1;
        forged[last] ^= 1;
        let _ = client.on_event(OstpEvent::Inbound(Bytes::from(forged)));
        assert_eq!(client.reorder_mult, 1, "a forged copy must not widen the window");

        let _ = client.on_event(OstpEvent::Inbound(frames[0].clone())).unwrap(); // the retransmit
        assert_eq!(client.reorder_mult, 2);
        assert!(client.reorder_window() > narrow);
    }

    /// A payload of max_payload() bytes makes a datagram no larger than the MTU.
    #[test]
    fn max_payload_fits_the_mtu() {
        let (_client, mut server) = do_handshake();
        let max = server.max_payload();
        for _ in 0..50 {
            let d = datagrams(server.on_event(OstpEvent::Outbound(1, Bytes::from(vec![1u8; max]))).unwrap()).remove(0);
            assert!(d.len() <= 1400, "{} bytes over an MTU of 1400", d.len());
        }
    }

    /// A replayed or forged copy of an old frame gets no answer unless it
    /// authenticates, and an authentic one at most every ANSWER_MIN_INTERVAL.
    #[test]
    fn undeliverable_frames_are_answered_only_when_authentic() {
        let (mut client, mut server) = do_handshake();
        let f = datagrams(server.on_event(OstpEvent::Outbound(1, Bytes::from_static(b"x"))).unwrap()).remove(0);
        let _ = client.on_event(OstpEvent::Inbound(f.clone())).unwrap();

        let mut forged = f.to_vec();
        let last = forged.len() - 1;
        forged[last] ^= 1;
        client.last_ack_sent = Instant::now() - Duration::from_secs(1);
        assert!(client.on_event(OstpEvent::Inbound(Bytes::from(forged))).is_err(), "a forged duplicate is rejected");

        let first = datagrams(client.on_event(OstpEvent::Inbound(f.clone())).unwrap());
        assert_eq!(first.len(), 1, "an authentic duplicate is ACKed");
        client.last_ack_sent = Instant::now(); // as if it had just gone out
        let second = datagrams(client.on_event(OstpEvent::Inbound(f)).unwrap());
        assert!(second.is_empty(), "but not again right away");
    }

    /// Our own ACKs being acknowledged must not feed the RTT estimate.
    #[test]
    fn acked_control_frames_give_no_rtt_sample() {
        let (mut client, mut server) = do_handshake();
        // The client ACKs a frame from the server; that ACK sits in its history.
        let f = datagrams(server.on_event(OstpEvent::Outbound(1, Bytes::from_static(b"x"))).unwrap()).remove(0);
        // The ACK goes out with the answer to the frame or on the next tick,
        // depending on how long ago the last one went.
        let mut acks = datagrams(client.on_event(OstpEvent::Inbound(f)).unwrap());
        client.last_ack_sent = Instant::now() - Duration::from_secs(1);
        acks.extend(datagrams(client.on_event(OstpEvent::Tick).unwrap()));
        assert!(!acks.is_empty());
        for frame in client.sent_history.iter_mut() {
            frame.last_sent = Instant::now() - Duration::from_secs(3);
        }
        let srtt = client.cc.smoothed_rtt();
        // The server acknowledges everything the client sent so far.
        for a in acks {
            let _ = server.on_event(OstpEvent::Inbound(a));
        }
        let keepalive = datagrams(client.on_event(OstpEvent::Outbound(1, Bytes::from_static(b"y"))).unwrap()).remove(0);
        let _ = server.on_event(OstpEvent::Inbound(keepalive)).unwrap();
        server.last_ack_sent = Instant::now() - Duration::from_secs(1);
        for a in datagrams(server.on_event(OstpEvent::Tick).unwrap()) {
            let _ = client.on_event(OstpEvent::Inbound(a));
        }
        assert!(client.cc.smoothed_rtt() < Duration::from_secs(1), "a 3 s old ACK frame became an RTT sample (srtt {:?} -> {:?})", srtt, client.cc.smoothed_rtt());
    }

    // ── v6 session layer ─────────────────────────────────────────────────────

    fn do_handshake_v6() -> (ProtocolMachine, ProtocolMachine) {
        let (private, public) = crate::crypto::noise::generate_server_key();
        let (ccfg, scfg) = v6_configs(private, public);
        let mut client = ProtocolMachine::new(ccfg).unwrap();
        let mut server = ProtocolMachine::new(scfg).unwrap();
        let ProtocolAction::SendDatagram(msg1) = client.on_event(OstpEvent::Start).unwrap() else { panic!() };
        let (_, reply) = server_reply(server.on_event(OstpEvent::Inbound(msg1)).unwrap());
        client.on_event(OstpEvent::Inbound(reply)).unwrap();
        assert!(client.v6 && server.v6);
        (client, server)
    }

    /// What an action tree asks the caller to do, sorted.
    #[derive(Default)]
    struct Out {
        app: Vec<(u32, Bytes)>,
        dgrams: Vec<(u32, Bytes)>,
        resets: Vec<(u32, ResetReason)>,
        wire: Vec<Bytes>,
    }

    fn sort_out(a: ProtocolAction, o: &mut Out) {
        match a {
            ProtocolAction::DeliverApp(s, b) => o.app.push((s, b)),
            ProtocolAction::DeliverDatagram(s, b) => o.dgrams.push((s, b)),
            ProtocolAction::StreamReset(s, r) => o.resets.push((s, r)),
            ProtocolAction::SendDatagram(d) => o.wire.push(d),
            ProtocolAction::Multiple(l) => l.into_iter().for_each(|x| sort_out(x, o)),
            _ => {}
        }
    }

    fn feed(m: &mut ProtocolMachine, d: &Bytes) -> Out {
        let mut o = Out::default();
        sort_out(m.on_event(OstpEvent::Inbound(d.clone())).unwrap(), &mut o);
        o
    }

    fn tick(m: &mut ProtocolMachine) -> Out {
        let mut o = Out::default();
        sort_out(m.on_event(OstpEvent::Tick).unwrap(), &mut o);
        o
    }

    fn send(m: &mut ProtocolMachine, stream: u32, payload: &[u8]) -> Bytes {
        datagrams(m.on_event(OstpEvent::Outbound(stream, Bytes::copy_from_slice(payload))).unwrap()).remove(0)
    }

    fn send_datagram(m: &mut ProtocolMachine, stream: u32, payload: &[u8]) -> Bytes {
        datagrams(m.on_event(OstpEvent::OutboundDatagram(stream, Bytes::copy_from_slice(payload))).unwrap()).remove(0)
    }

    fn texts(o: &Out) -> Vec<(u32, String)> {
        o.app.iter().map(|(s, b)| (*s, String::from_utf8_lossy(b).to_string())).collect()
    }

    #[test]
    fn a_v6_datagram_carries_4_bytes_less_and_never_exceeds_the_mtu() {
        let (c5, _) = do_handshake();
        let (mut c6, mut s6) = do_handshake_v6();
        assert_eq!(c5.max_payload() - c6.max_payload(), 4);
        let max = c6.max_payload();
        for _ in 0..50 {
            let d = send(&mut s6, 2, &vec![1u8; max]);
            assert!(d.len() <= 1400, "{} bytes over an MTU of 1400", d.len());
        }
        // One byte more does not fit a datagram: refused, not truncated or fragmented.
        assert!(c6.on_event(OstpEvent::Outbound(1, Bytes::from(vec![0u8; max + 1]))).is_err());
        assert!(c6.on_event(OstpEvent::OutboundDatagram(1, Bytes::from(vec![0u8; max + 1]))).is_err());
        // A refused frame spends neither a sequence number nor a nonce that matters:
        // the next frame of the stream is seq 0 and delivers.
        let ok = send(&mut c6, 1, b"after");
        assert_eq!(texts(&feed(&mut s6, &ok)), vec![(1, "after".to_string())]);
    }

    #[test]
    fn stream_frames_are_delivered_in_order_per_stream() {
        let (mut client, mut server) = do_handshake_v6();
        let a: Vec<Bytes> = (0..4).map(|i| send(&mut client, 1, format!("a{i}").as_bytes())).collect();

        assert_eq!(texts(&feed(&mut server, &a[0])), vec![(1, "a0".to_string())], "in order: at once");
        assert!(feed(&mut server, &a[2]).app.is_empty(), "ahead of the order: held");
        assert!(feed(&mut server, &a[3]).app.is_empty());
        assert!(feed(&mut server, &a[3]).app.is_empty(), "the same frame again is not held twice");
        assert_eq!(server.stream_buffered, 2);
        assert_eq!(
            texts(&feed(&mut server, &a[1])),
            vec![(1, "a1".to_string()), (1, "a2".to_string()), (1, "a3".to_string())],
            "the missing frame releases the ones behind it, in order"
        );
        assert_eq!(server.stream_buffered, 0);
        for f in &a {
            assert!(feed(&mut server, f).app.is_empty(), "a frame of the past is a duplicate");
        }
    }

    #[test]
    fn a_gap_in_one_stream_does_not_hold_another() {
        let (mut client, mut server) = do_handshake_v6();
        let a0 = send(&mut client, 1, b"a0");
        let a1 = send(&mut client, 1, b"a1");
        let a2 = send(&mut client, 1, b"a2");
        let b0 = send(&mut client, 3, b"b0");
        let b1 = send(&mut client, 3, b"b1");

        // a0 is lost; everything else arrives.
        assert!(feed(&mut server, &a1).app.is_empty());
        assert_eq!(texts(&feed(&mut server, &b0)), vec![(3, "b0".to_string())], "stream 3 does not wait for stream 1");
        assert_eq!(texts(&feed(&mut server, &b1)), vec![(3, "b1".to_string())]);
        assert!(feed(&mut server, &a2).app.is_empty());
        // The datagram-level hole (a0's nonce) is still open and still asked for.
        assert_eq!(server.expected_recv_nonce, 0);
        assert_eq!(
            texts(&feed(&mut server, &a0)),
            vec![(1, "a0".to_string()), (1, "a1".to_string()), (1, "a2".to_string())]
        );
        assert_eq!(server.expected_recv_nonce, 5, "the hole closed");
    }

    /// `Close` is a message inside a sequenced frame, so it is the last thing
    /// delivered on its stream even when it arrives first.
    #[test]
    fn a_close_message_is_delivered_after_the_data_before_it() {
        use crate::relay::RelayMessage;
        let (mut client, mut server) = do_handshake_v6();
        let d0 = send(&mut client, 5, b"x");
        let d1 = send(&mut client, 5, b"y");
        let close = datagrams(
            client
                .on_event(OstpEvent::Outbound(5, Bytes::from(RelayMessage::Close.encode())))
                .unwrap(),
        )
        .remove(0);
        assert!(feed(&mut server, &close).app.is_empty(), "the Close arrived first and waits");
        assert!(feed(&mut server, &d1).app.is_empty());
        let o = feed(&mut server, &d0);
        assert_eq!(o.app.len(), 3);
        assert_eq!(&o.app[0].1[..], b"x");
        assert_eq!(&o.app[1].1[..], b"y");
        assert!(matches!(RelayMessage::decode(&o.app[2].1).unwrap(), RelayMessage::Close), "Close is last");
    }

    /// What stage 2 of the session layer relies on: a stream that is over on
    /// both sides is released, so a long session can open far more streams than
    /// the receiver tracks at once.
    #[test]
    fn more_streams_than_the_receiver_tracks_can_be_opened_one_after_another() {
        use crate::relay::RelayMessage;
        use crate::streams::{HalfClose, Side, StreamIds};
        let (mut client, mut server) = do_handshake_v6();
        let mut cids = StreamIds::new(Side::Client);
        let mut sids = StreamIds::new(Side::Server);
        let total = 3 * MAX_TRACKED_STREAMS / 2 + 100;
        assert!(total > MAX_TRACKED_STREAMS);
        let fin = || Bytes::from(RelayMessage::Fin.encode());
        // The frame goes to `to`; what `to` sends back (ACKs) goes to `from`,
        // and so on until it is quiet: a nonce nobody sees is a hole forever.
        fn deliver(to: &mut ProtocolMachine, from: &mut ProtocolMachine, frame: &Bytes) -> Out {
            let out = feed(to, frame);
            let mut a = out.wire.clone();
            let mut b: Vec<Bytes> = Vec::new();
            while !a.is_empty() || !b.is_empty() {
                for f in a.drain(..) {
                    b.extend(feed(from, &f).wire);
                }
                for f in std::mem::take(&mut b) {
                    a.extend(feed(to, &f).wire);
                }
            }
            out
        }
        let mut first_request = None;
        for i in 0..total {
            let id = cids.open_local().unwrap();
            sids.accept_remote(id).unwrap();
            let mut chalf = HalfClose::default();
            let mut shalf = HalfClose::default();

            // Connect and a request, then the client's Fin.
            let req = send(&mut client, id, format!("request {i}").as_bytes());
            if i == 0 {
                first_request = Some(req.clone());
            }
            let o = deliver(&mut server, &mut client, &req);
            assert_eq!(
                texts(&o),
                vec![(id, format!("request {i}"))],
                "stream {i} (id {id}) delivered; tracked {}, dead {}, expected nonce {}",
                server.streams_rx.len(),
                server.dead_streams.len(),
                server.expected_recv_nonce
            );
            let f = datagrams(client.on_event(OstpEvent::Outbound(id, fin())).unwrap()).remove(0);
            chalf.local_fin();
            let o = deliver(&mut server, &mut client, &f);
            assert!(!o.app.is_empty(), "the client's Fin of stream {i} (id {id}) was not delivered");
            assert!(matches!(RelayMessage::decode(&o.app[0].1).unwrap(), RelayMessage::Fin));
            shalf.remote_fin();

            // The reply and the server's Fin.
            let rep = send(&mut server, id, b"reply");
            assert_eq!(texts(&deliver(&mut client, &mut server, &rep)), vec![(id, "reply".to_string())]);
            let f = datagrams(server.on_event(OstpEvent::Outbound(id, fin())).unwrap()).remove(0);
            assert!(shalf.local_fin(), "the server's side is finished");
            let o = deliver(&mut client, &mut server, &f);
            assert!(matches!(RelayMessage::decode(&o.app[0].1).unwrap(), RelayMessage::Fin));
            assert!(chalf.remote_fin(), "the client's side is finished");

            // Both sides release it.
            sids.close(id).unwrap();
            server.on_event(OstpEvent::ReleaseStream(id)).unwrap();
            cids.close(id).unwrap();
            client.on_event(OstpEvent::ReleaseStream(id)).unwrap();
            assert!(cids.open_count() == 0 && sids.open_count() == 0);
        }
        assert!(server.streams_rx.len() <= 1 && client.streams_rx.len() <= 1, "released streams keep no state");
        // A late copy of a released stream's first frame is dropped, not delivered again.
        let first = first_request.expect("the first request was kept");
        assert!(feed(&mut server, &first).app.is_empty());
    }

    #[test]
    fn a_streams_buffer_is_bounded_by_its_window() {
        let (mut client, mut server) = do_handshake_v6();
        server.max_reorder = 1 << 20;
        server.max_reorder_buffer = 10_000;
        let size = 1300usize;
        let make = |i: u32| {
            let mut p = vec![0u8; size];
            p[..4].copy_from_slice(&i.to_be_bytes());
            p
        };
        let held_max = crate::relay::INITIAL_STREAM_WINDOW as usize / size;
        let total = held_max as u32 + 150;
        let frames: Vec<Bytes> = (0..=total).map(|i| send(&mut client, 1, &make(i))).collect();

        // seq 0 is lost; the rest arrive, more than the window holds.
        let mut rejected = Vec::new();
        for (i, f) in frames.iter().enumerate().skip(1) {
            assert!(feed(&mut server, f).app.is_empty());
            if server.stream_buffered < i {
                rejected.push(i);
                break;
            }
        }
        for f in frames.iter().skip(rejected[0] + 1) {
            feed(&mut server, f);
        }
        let st = &server.streams_rx[&1];
        assert!(st.buffered_bytes <= crate::relay::INITIAL_STREAM_WINDOW as usize);
        assert_eq!(server.stream_buffered, held_max, "the window holds this many frames");
        assert_eq!(server.reorder_buffer.len(), held_max, "a frame that was not taken is not acknowledged either");

        // seq 0 arrives and the held ones go; what was refused is resent and goes too.
        let mut got = feed(&mut server, &frames[0]).app;
        assert_eq!(got.len(), held_max + 1);
        for f in frames.iter().skip(held_max + 1) {
            got.extend(feed(&mut server, f).app);
        }
        assert_eq!(got.len(), total as usize + 1, "nothing lost");
        for (i, (_, p)) in got.iter().enumerate() {
            assert_eq!(u32::from_be_bytes(p[..4].try_into().unwrap()), i as u32, "in order");
        }
    }

    #[test]
    fn the_total_of_the_streams_buffers_is_bounded_by_the_session_limit() {
        let (mut client, mut server) = do_handshake_v6();
        server.max_reorder_buffer = 10;
        // 20 streams; the first frame of each is lost and the second arrives.
        let mut second = Vec::new();
        for s in 1..=20u32 {
            send(&mut client, s, b"first");
            second.push(send(&mut client, s, b"second"));
        }
        for f in &second {
            assert!(feed(&mut server, f).app.is_empty());
        }
        assert_eq!(server.stream_buffered, 10);
        assert_eq!(server.reorder_buffer.len(), 10);
    }

    #[test]
    fn a_v6_receiver_never_skips_a_hole() {
        let (mut client, mut server) = do_handshake_v6();
        let a0 = send(&mut client, 1, b"a0");
        let a1 = send(&mut client, 1, b"a1");
        let a2 = send(&mut client, 1, b"a2");
        assert_eq!(feed(&mut server, &a0).app.len(), 1);
        assert!(feed(&mut server, &a2).app.is_empty());
        // The v5 receiver skips after the sender's retransmit budget; v6 does not.
        server.last_recv_advance = Instant::now() - Duration::from_secs(3600);
        assert!(feed(&mut server, &a0).app.is_empty());
        assert!(tick(&mut server).app.is_empty());
        assert_eq!(texts(&feed(&mut server, &a1)), vec![(1, "a1".to_string()), (1, "a2".to_string())]);
    }

    #[test]
    fn a_datagram_is_delivered_once_and_outside_every_order() {
        let (mut client, mut server) = do_handshake_v6();
        let s0 = send(&mut client, 1, b"s0");
        let d = send_datagram(&mut client, 9, b"udp");
        // The datagram arrives although the stream's first frame did not.
        let o = feed(&mut server, &d);
        assert_eq!(o.dgrams, vec![(9, Bytes::from_static(b"udp"))]);
        assert!(o.app.is_empty());
        assert!(feed(&mut server, &d).dgrams.is_empty(), "a duplicate datagram is not delivered twice");
        assert_eq!(texts(&feed(&mut server, &s0)).len(), 1);
    }

    #[test]
    fn a_lost_datagram_is_not_resent_and_does_not_hold_back_stream_data() {
        let (mut client, mut server) = do_handshake_v6();
        let d = send_datagram(&mut client, 9, b"udp"); // lost
        let s0 = send(&mut client, 1, b"s0");
        let s1 = send(&mut client, 1, b"s1");
        assert_eq!(client.in_flight_count(), 3, "a datagram counts against the window");

        // The stream's data is delivered at once, behind the datagram's hole.
        let mut to_client = Vec::new();
        for (f, name) in [(&s0, "s0"), (&s1, "s1")] {
            let o = feed(&mut server, f);
            assert_eq!(texts(&o), vec![(1, name.to_string())]);
            to_client.extend(o.wire);
        }
        assert_eq!(server.expected_recv_nonce, 0, "the datagram's nonce is a hole");

        // The receiver NACKs the hole; the sender does not resend a datagram.
        server.gap_since = Some(Instant::now() - REORDER_WINDOW_MAX);
        server.last_nack_sent = Instant::now() - Duration::from_secs(1);
        server.last_ack_sent = Instant::now() - Duration::from_secs(1);
        to_client.extend(tick(&mut server).wire);
        let mut answers = Vec::new();
        for w in &to_client {
            answers.extend(feed(&mut client, w).wire);
        }
        assert!(!answers.contains(&d), "a lost datagram is not resent");
        assert!(!answers.is_empty(), "but the receiver is told it will never come");
        assert_eq!(client.in_flight_count(), 0, "the datagram left the window with the acknowledged frames");

        for a in &answers {
            feed(&mut server, a);
        }
        assert!(server.expected_recv_nonce >= 3, "the hole is closed: {}", server.expected_recv_nonce);
        assert!(server.reorder_buffer.is_empty());
        // The stream goes on.
        let s2 = send(&mut client, 1, b"s2");
        assert_eq!(texts(&feed(&mut server, &s2)), vec![(1, "s2".to_string())]);
    }

    #[test]
    fn a_datagram_is_not_resent_on_the_timer_but_data_is() {
        let (mut client, mut server) = do_handshake_v6();
        let d = send_datagram(&mut client, 9, b"udp");
        let s = send(&mut client, 1, b"data");
        for f in client.sent_history.iter_mut() {
            f.last_sent = Instant::now() - Duration::from_secs(2);
        }
        let t = tick(&mut client);
        assert!(t.wire.contains(&s), "stream data is resent on the timer");
        assert!(!t.wire.contains(&d), "a datagram is not");

        // Unacknowledged for long enough, the datagram is counted lost and
        // leaves the window; the peer is told.
        for f in client.sent_history.iter_mut().filter(|f| f.no_resend) {
            f.first_sent = Instant::now() - Duration::from_secs(30);
        }
        let t = tick(&mut client);
        assert!(!t.wire.contains(&d));
        assert!(client.sent_history.iter().all(|f| !f.no_resend));
        assert_eq!(client.in_flight_count(), 1, "only the stream's frame is left in flight");
        for w in &t.wire {
            feed(&mut server, w);
        }
        assert_eq!(server.expected_recv_nonce, 1, "the datagram's hole is closed, the stream's frame is still due");
        assert_eq!(texts(&feed(&mut server, &s)), vec![(1, "data".to_string())]);
    }

    #[test]
    fn giving_up_on_a_frame_resets_that_stream_on_both_ends_and_no_other() {
        let (mut client, mut server) = do_handshake_v6();
        let f0 = send(&mut client, 1, b"f0"); // lost for good
        let f1 = send(&mut client, 1, b"f1");
        let g0 = send(&mut client, 3, b"g0");
        let g1 = send(&mut client, 3, b"g1");

        assert!(feed(&mut server, &f1).app.is_empty(), "held behind f0");
        let mut acks = Vec::new();
        for g in [&g0, &g1] {
            let o = feed(&mut server, g);
            assert_eq!(o.app.len(), 1, "stream 3 is not held by stream 1");
            acks.extend(o.wire);
        }
        server.last_ack_sent = Instant::now() - Duration::from_secs(1);
        acks.extend(tick(&mut server).wire);
        for a in &acks {
            feed(&mut client, a);
        }
        assert_eq!(client.in_flight_count(), 1, "only f0 is unacknowledged");

        // The sender runs out of patience with f0.
        for f in client.sent_history.iter_mut() {
            f.retries = 50;
            f.first_sent = Instant::now() - Duration::from_secs(400);
        }
        let t = tick(&mut client);
        assert_eq!(t.resets, vec![(1, ResetReason::Lost)], "the sender knows it gave up, and only on stream 1");
        assert!(!t.wire.is_empty(), "and tells the receiver");
        assert!(client.on_event(OstpEvent::Outbound(1, Bytes::from_static(b"more"))).is_err(), "stream 1 is dead");
        let g2 = send(&mut client, 3, b"g2"); // stream 3 goes on
        assert_eq!(client.in_flight_count(), 2, "the reset frame, until acknowledged, and g2");

        // The receiver learns it from the frame it can receive.
        let mut resets = Vec::new();
        for w in &t.wire {
            resets.extend(feed(&mut server, w).resets);
        }
        assert_eq!(resets, vec![(1, ResetReason::Lost)]);
        assert!(server.streams_rx.get(&1).is_none(), "its buffer is gone");
        assert_eq!(server.stream_buffered, 0);
        assert!(server.reorder_buffer.is_empty(), "f0's hole is closed");
        assert!(server.on_event(OstpEvent::Outbound(1, Bytes::from_static(b"x"))).is_err(), "dead in both directions");
        // A straggler of the dead stream, and the other stream's next frame.
        assert!(feed(&mut server, &f0).app.is_empty());
        assert_eq!(texts(&feed(&mut server, &g2)), vec![(3, "g2".to_string())]);

        // The reset is retransmitted until acknowledged.
        server.last_ack_sent = Instant::now() - Duration::from_secs(1);
        for a in tick(&mut server).wire {
            feed(&mut client, &a);
        }
        assert_eq!(client.in_flight_count(), 0);
    }

    #[test]
    fn a_lost_reset_is_retransmitted() {
        let (mut client, mut server) = do_handshake_v6();
        send(&mut client, 1, b"f0");
        for f in client.sent_history.iter_mut() {
            f.retries = 50;
            f.first_sent = Instant::now() - Duration::from_secs(400);
        }
        let lost = tick(&mut client);
        assert_eq!(lost.resets.len(), 1);
        // That datagram never arrives. A later tick past the RTO sends it again.
        for f in client.sent_history.iter_mut() {
            f.last_sent = Instant::now() - Duration::from_secs(60);
        }
        let again = tick(&mut client);
        assert!(!again.wire.is_empty(), "the reset is resent");
        let mut resets = Vec::new();
        for w in &again.wire {
            resets.extend(feed(&mut server, w).resets);
        }
        assert_eq!(resets, vec![(1, ResetReason::Lost)]);
    }

    #[test]
    fn a_nack_for_a_nonce_that_is_gone_is_answered_with_an_abandon() {
        let (mut client, mut server) = do_handshake_v6();
        let a = send(&mut client, 1, b"a");
        let b = send(&mut client, 1, b"b");
        // a is lost, then forgotten by the sender's history.
        client.sent_history.pop_front();
        feed(&mut server, &b);
        server.gap_since = Some(Instant::now() - REORDER_WINDOW_MAX);
        server.last_nack_sent = Instant::now() - Duration::from_secs(1);
        let nack = tick(&mut server).wire;
        let mut back = Vec::new();
        for n in &nack {
            back.extend(feed(&mut client, n).wire);
        }
        assert!(!back.contains(&a));
        assert!(!back.is_empty());
        for x in &back {
            feed(&mut server, x);
        }
        assert!(server.reorder_buffer.is_empty() && server.expected_recv_nonce >= 2, "the hole is closed");
        // A nonce the sender never used is not abandoned.
        let before = client.send_nonce;
        let mut wire = Vec::new();
        client.on_nack_v6(&(before + 100).to_be_bytes(), &mut wire);
        assert!(wire.is_empty());
    }

    #[test]
    fn a_v5_session_knows_nothing_of_v6_things() {
        let (mut client, mut server) = do_handshake();
        assert!(!client.v6);
        assert!(client.on_event(OstpEvent::OutboundDatagram(1, Bytes::from_static(b"x"))).is_err());
        assert!(client.on_event(OstpEvent::Outbound(70_000, Bytes::from_static(b"x"))).is_err());
        // 16-bit ids still work, and the frame is the 12-byte-header one:
        // v5's max payload is unchanged.
        let f = send(&mut client, 65_535, b"x");
        let o = feed(&mut server, &f);
        assert_eq!(texts(&o), vec![(65_535, "x".to_string())]);
        assert_eq!(client.max_payload(), 1400 - DATAGRAM_OVERHEAD);
    }
}
