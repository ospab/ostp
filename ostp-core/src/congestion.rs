//! Congestion control for the OSTP protocol.
//!
//! Slow start, then CUBIC (RFC 9438) for window growth and loss response,
//! with a delay signal on top: a smoothed RTT far above the path's minimum is
//! a standing queue and is treated as congestion. Sending is paced at
//! cwnd / min_rtt.
//!
//! CUBIC replaced Reno-style growth (+1 packet per RTT, x0.7 on every gap):
//! with any random loss that held the window near 1.2 / sqrt(p) packets,
//! about 120 packets at 0.01% loss, tens of Mbit/s on a 300 Mbit/s path.
//!
//! RTO calculation follows RFC 6298:
//!   SRTT = (1 - α) * SRTT + α * RTT       (α = 1/8)
//!   RTTVAR = (1 - β) * RTTVAR + β * |SRTT - RTT|  (β = 1/4)
//!   RTO = SRTT + 4 * RTTVAR
//!   clamped to [RTO_MIN, RTO_MAX]

use core::time::Duration;

use crate::sys::Instant;

#[cfg(feature = "std")]
fn cbrt(x: f64) -> f64 {
    x.cbrt()
}
#[cfg(not(feature = "std"))]
fn cbrt(x: f64) -> f64 {
    libm::cbrt(x)
}

/// Congestion control state for a single OSTP session.
pub struct CongestionController {
    /// Current congestion window in bytes (how much can be in-flight)
    cwnd: u64,
    /// Slow-start threshold in bytes
    ssthresh: u64,
    /// Current phase
    phase: Phase,
    /// Minimum RTT observed (for BBR-style bandwidth estimation)
    min_rtt: Duration,
    /// Smoothed RTT (RFC 6298 SRTT)
    srtt: Duration,
    /// RTT variance (RFC 6298 RTTVAR)
    rttvar: Duration,
    /// Whether we have received a first RTT sample
    rtt_initialized: bool,
    /// Bytes currently in flight (unacknowledged)
    bytes_in_flight: u64,
    /// Total bytes acknowledged (for bandwidth estimation)
    total_acked: u64,
    /// Last time we received an ACK
    last_ack_time: Instant,
    /// Number of loss events in the current window
    loss_count: u32,
    /// Pacing rate: bytes per second
    pacing_rate: u64,
    /// Token-bucket allowance for pacing, in bytes.
    pacing_tokens: f64,
    pacing_last_refill: Instant,
    /// MTU estimate (used for cwnd → packet count conversion)
    mtu: u64,
    /// Min RTT expiry: re-probe after 10 seconds
    min_rtt_stamp: Instant,
    /// Loss events counted toward SLOW_START_LOSS_TOLERANCE within the
    /// current SLOW_START_LOSS_WINDOW (see on_loss's SlowStart arm).
    slow_start_losses: u32,
    /// Start of the current loss-tolerance window.
    slow_start_loss_window_start: Instant,
    /// CUBIC (RFC 9438): the window, in packets, before the last reduction.
    w_max: f64,
    /// CUBIC: start of the current growth epoch (`None` until the first ACK
    /// after a reduction or the end of slow start).
    epoch_start: Option<Instant>,
    /// CUBIC: time from the epoch start to reach `w_max` again, seconds.
    k: f64,
    /// CUBIC: the window standard TCP would have now, packets (RFC 9438 §4.3).
    w_est: f64,
    /// When the window was last reduced. Losses within one smoothed RTT of a
    /// reduction belong to the same congestion event and do not reduce it
    /// again: several frames lost from one burst used to cut the window by
    /// 0.7 for each of them.
    last_reduction: Option<Instant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Exponential growth until loss or ssthresh
    SlowStart,
    /// Probe bandwidth: additive increase
    ProbeBandwidth,
}

/// Initial congestion window: 32 packets × MTU (IW10 is too conservative for modern links)
const INITIAL_CWND_PACKETS: u64 = 32;
/// Minimum cwnd: 2 packets
const MIN_CWND_PACKETS: u64 = 2;
/// Min RTT expiry window (after which we re-probe)
const MIN_RTT_EXPIRY: Duration = Duration::from_secs(10);
/// Absolute ceiling on the congestion window, in packets: about 11 MB at a
/// 1350-byte MTU, the bandwidth-delay product of 1 Gbit/s at 90 ms. The old
/// 1024 (1.4 MB) capped one session at ~275 Mbit/s at 40 ms and ~180 Mbit/s
/// at 60 ms however fast the path. A deep buffer does not get to fill this:
/// the delay signal (RTT_INFLATION_*) ends growth when the queue builds.
pub const MAX_CWND_PACKETS: u64 = 8192;
/// CUBIC constants (RFC 9438 §5): multiplicative decrease and the scaling
/// constant, in packets and seconds.
const CUBIC_BETA: f64 = 0.7;
const CUBIC_C: f64 = 0.4;
/// SRTT/min_rtt ratio at which slow start stops. Doubling is what fills a deep
/// buffer fastest, so growth must end when the queue starts building rather
/// than waiting for a loss that a deep buffer may never produce.
const RTT_INFLATION_EXIT_SLOW_START: f64 = 2.0;
/// SRTT/min_rtt ratio treated as a standing queue that must be actively drained.
const RTT_INFLATION_BACKOFF: f64 = 4.0;
/// How much pacing allowance may accumulate, expressed as time-at-rate.
const PACING_BURST: Duration = Duration::from_millis(10);
const RTO_MIN: Duration = Duration::from_millis(50);
/// Maximum RTO
const RTO_MAX: Duration = Duration::from_secs(16);
/// Initial RTT estimate — 30 ms is reasonable for a well-connected VPN server.
/// Will be replaced by first real measurement within milliseconds.
const INITIAL_RTT: Duration = Duration::from_millis(30);

/// Isolated packet loss during slow start (a single dropped frame from
/// wireless noise, a brief LTE handover blip, etc.) is normal on real
/// mobile/Wi-Fi links and does NOT mean the link is congested. The previous
/// behavior exited slow start and halved cwnd on the very FIRST loss, which
/// on any link with a non-zero background loss rate permanently downgrades
/// the session from exponential growth to linear (+1 MTU/RTT) ProbeBandwidth
/// growth within the first few RTTs - turning what should be a sub-second
/// ramp-up into tens of seconds to minutes before throughput opens up
/// (observed as: a trickle of KB/s, then a sudden jump once cwnd finally
/// claws back up). Only treat loss as a real congestion signal - and pay
/// the full slow-start-exit + halving cost - once this many losses land
/// within SLOW_START_LOSS_WINDOW.
const SLOW_START_LOSS_TOLERANCE: u32 = 3;
/// Window within which SLOW_START_LOSS_TOLERANCE losses must land to count
/// as sustained (rather than isolated) loss. Roughly a few RTTs on a
/// well-connected link, generous on a slow one.
const SLOW_START_LOSS_WINDOW: Duration = Duration::from_millis(500);

impl CongestionController {
    pub fn new(mtu: u64) -> Self {
        let now = Instant::now();
        let initial_cwnd = INITIAL_CWND_PACKETS * mtu;
        // Initial pacing: deliver cwnd in ~2 RTTs to fill the pipe quickly
        let initial_pacing = initial_cwnd * 1_000_000 / INITIAL_RTT.as_micros().max(1) as u64;
        Self {
            cwnd: initial_cwnd,
            ssthresh: u64::MAX,
            phase: Phase::SlowStart,
            min_rtt: INITIAL_RTT,
            srtt: INITIAL_RTT,
            rttvar: INITIAL_RTT / 2,
            rtt_initialized: false,
            bytes_in_flight: 0,
            total_acked: 0,
            last_ack_time: now,
            loss_count: 0,
            pacing_rate: initial_pacing,
            mtu,
            min_rtt_stamp: now,
            slow_start_losses: 0,
            slow_start_loss_window_start: now,
            pacing_tokens: (INITIAL_CWND_PACKETS * mtu) as f64,
            pacing_last_refill: now,
            w_max: 0.0,
            epoch_start: None,
            k: 0.0,
            w_est: 0.0,
            last_reduction: None,
        }
    }

    /// Forget what was learned about the network path, keeping only the
    /// accounting of bytes still in flight. After the session moves to another
    /// socket, address or transport, the old RTT and window describe a path
    /// that no longer carries it: a window grown on Wi-Fi would flood a fresh
    /// cellular path, and an RTO inflated while the old path was dying would
    /// hold back the first retransmits on the new one.
    pub fn reset_path(&mut self) {
        let bytes_in_flight = self.bytes_in_flight;
        let total_acked = self.total_acked;
        *self = Self::new(self.mtu);
        self.bytes_in_flight = bytes_in_flight;
        self.total_acked = total_acked;
    }

    /// Bytes of pacing allowance available right now, without consuming any.
    ///
    /// Read-only so the send path can use it as an admission check before it
    /// commits to building a datagram.
    pub fn pacing_available(&self) -> f64 {
        let elapsed = self.pacing_last_refill.elapsed().as_secs_f64();
        (self.pacing_tokens + elapsed * self.pacing_rate as f64).min(self.pacing_burst())
    }

    /// Whether at least one full-size packet may be released right now.
    pub fn can_pace_packet(&self) -> bool {
        self.pacing_available() >= self.mtu as f64
    }

    /// Ceiling on accumulated allowance.
    ///
    /// Pacing intervals here are fractions of a millisecond, so releasing
    /// strictly one packet at a time would need a sub-millisecond timer per
    /// packet. Instead we allow a short burst — the same trade every real
    /// pacing implementation makes — sized so the loop's existing ~10ms wakeups
    /// can still saturate the configured rate, with a small floor so a
    /// cold/low estimate can never wedge sending entirely.
    fn pacing_burst(&self) -> f64 {
        let by_rate = self.pacing_rate as f64 * PACING_BURST.as_secs_f64();
        by_rate.max((self.mtu * 4) as f64)
    }

    /// Refill from elapsed time and deduct `bytes`. Called on the real send
    /// path; allowance is permitted to go negative so an oversized packet still
    /// pays for itself rather than being released for free.
    fn consume_pacing(&mut self, bytes: u64) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.pacing_last_refill).as_secs_f64();
        self.pacing_last_refill = now;
        self.pacing_tokens =
            (self.pacing_tokens + elapsed * self.pacing_rate as f64).min(self.pacing_burst())
                - bytes as f64;
    }

    /// Returns the current congestion window in bytes.
    pub fn cwnd(&self) -> u64 {
        self.cwnd
    }

    /// Returns the current congestion window in packets.
    pub fn cwnd_packets(&self) -> usize {
        (self.cwnd / self.mtu).max(MIN_CWND_PACKETS) as usize
    }

    /// Returns the current pacing rate in bytes/sec.
    pub fn pacing_rate(&self) -> u64 {
        self.pacing_rate
    }

    /// Returns the smoothed RTT estimate (SRTT).
    pub fn smoothed_rtt(&self) -> Duration {
        self.srtt
    }

    /// Returns the adaptive RTO computed per RFC 6298:
    ///   RTO = SRTT + 4 * RTTVAR, clamped to [RTO_MIN, RTO_MAX].
    ///
    /// This replaces the static `rto_ms` field in ProtocolMachine so that
    /// retransmit timers automatically track changing network conditions.
    pub fn rto(&self) -> Duration {
        let rttvar4 = self.rttvar.saturating_mul(4);
        let rto = self.srtt.saturating_add(rttvar4);
        rto.clamp(RTO_MIN, RTO_MAX)
    }

    /// Returns how many bytes can still be sent.
    pub fn available_cwnd(&self) -> u64 {
        self.cwnd.saturating_sub(self.bytes_in_flight)
    }

    /// Returns the recommended retransmit budget per tick.
    pub fn retransmit_budget(&self) -> usize {
        // Allow retransmitting up to 1/4 of the cwnd in packets per tick.
        // Capped at 512 a 10 ms tick: 64 left an 8192-frame window more than
        // a second to resend after a path change. Retransmits are paced too
        // (on_retransmit), so a large budget does not mean a burst of new data.
        let budget = (self.cwnd_packets() / 4).max(2);
        budget.min(512)
    }

    /// Check whether we can send more data.
    pub fn can_send(&self) -> bool {
        self.bytes_in_flight < self.cwnd
    }

    /// Record that we sent `bytes` of data.
    pub fn on_send(&mut self, bytes: u64) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_add(bytes);
        // Charge the pacing bucket here rather than at the admission check, so
        // every byte that actually reaches the wire is paid for exactly once —
        // including retransmits, which are precisely what must not be allowed
        // to bypass the rate limit and pile into an already-full queue.
        self.consume_pacing(bytes);
    }

    /// Record that `bytes` were acknowledged but WITHOUT a usable RTT sample
    /// (e.g. every acked frame was retransmitted, so Karn's algorithm forbids
    /// measuring RTT from it). The window still advances; only the RTT estimator
    /// is left untouched.
    pub fn on_ack_no_rtt(&mut self, bytes: u64) {
        let now = Instant::now();
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes);
        self.total_acked = self.total_acked.saturating_add(bytes);
        self.grow_window(bytes);
        self.update_pacing_rate();
        self.last_ack_time = now;
    }

    /// Record that `bytes` were acknowledged with the given RTT sample.
    pub fn on_ack(&mut self, bytes: u64, rtt: Duration) {
        let now = Instant::now();
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes);
        self.total_acked = self.total_acked.saturating_add(bytes);

        // Update RTT measurements
        self.update_rtt(rtt, now);

        self.grow_window(bytes);
        self.update_pacing_rate();
        self.last_ack_time = now;
    }

    /// Congestion-window growth shared by both ACK paths (slow start / probe).
    fn grow_window(&mut self, bytes: u64) {
        // ── Delay-based congestion signal ────────────────────────────────────
        // A loss-only controller is blind on a deeply-buffered path, and mobile
        // carrier buffers are very deep: they absorb a burst instead of dropping
        // it, so no loss is ever signalled and cwnd keeps growing. The queue —
        // not the link — is what grows, and the standing delay it adds shows up
        // as RTT inflating far above the path's floor. Left unchecked this is a
        // positive feedback loop: bigger queue -> larger RTT samples -> larger
        // SRTT -> larger RTO -> retransmits pile on -> bigger queue, which is
        // how a session ends up reporting multi-second (even multi-minute) RTT
        // and stalls video until the buffer finally drains or the user
        // reconnects. Treat sustained RTT inflation as congestion in its own
        // right, exactly as it is.
        let inflation = if self.rtt_initialized && !self.min_rtt.is_zero() {
            self.srtt.as_secs_f64() / self.min_rtt.as_secs_f64()
        } else {
            1.0
        };

        if inflation >= RTT_INFLATION_BACKOFF {
            // Standing queue is severe — actively drain it. Once per congestion
            // event, like a loss: SRTT falls slowly, and halving on every ACK
            // while it did took the window to the minimum within a few ACKs.
            if self.reduce(0.5) {
                tracing::debug!(cwnd = self.cwnd, inflation, "congestion: draining standing queue");
            }
            return;
        }

        match self.phase {
            Phase::SlowStart => {
                // Exponential doubling is what fills a deep buffer fastest, so
                // leave slow start as soon as the queue starts to build rather
                // than waiting for the loss that may never come.
                if inflation >= RTT_INFLATION_EXIT_SLOW_START {
                    self.ssthresh = self.cwnd;
                    self.enter_congestion_avoidance();
                    tracing::debug!(cwnd = self.cwnd, inflation, "congestion: RTT inflation ended slow start");
                    self.clamp_cwnd();
                    return;
                }
                // Exponential growth: increase cwnd by acked bytes (doubles per RTT)
                self.cwnd = self.cwnd.saturating_add(bytes);
                if self.cwnd >= self.ssthresh {
                    self.enter_congestion_avoidance();
                    tracing::debug!(cwnd = self.cwnd, "congestion: exiting slow start");
                }
            }
            Phase::ProbeBandwidth => self.cubic_grow(bytes),
        }

        self.clamp_cwnd();
    }

    fn cwnd_packets_f(&self) -> f64 {
        self.cwnd as f64 / self.mtu as f64
    }

    /// Slow start is over: CUBIC continues from the current window.
    fn enter_congestion_avoidance(&mut self) {
        self.phase = Phase::ProbeBandwidth;
        self.w_max = self.cwnd_packets_f();
        self.epoch_start = None;
    }

    /// CUBIC window growth for `bytes` newly acknowledged (RFC 9438 §4).
    fn cubic_grow(&mut self, bytes: u64) {
        let now = Instant::now();
        let cwnd = self.cwnd_packets_f();
        let acked = bytes as f64 / self.mtu as f64;
        let epoch = match self.epoch_start {
            Some(e) => e,
            None => {
                // A new epoch: K is the time to climb back to w_max.
                self.k = if cwnd < self.w_max { cbrt((self.w_max - cwnd) / CUBIC_C) } else { 0.0 };
                if cwnd > self.w_max {
                    self.w_max = cwnd;
                }
                self.w_est = cwnd;
                self.epoch_start = Some(now);
                now
            }
        };
        let t = now.duration_since(epoch).as_secs_f64();
        let rtt = self.srtt.as_secs_f64();
        // Where the cubic curve is one RTT from now, bounded to 1.5x per RTT.
        let target = (CUBIC_C * { let d = t + rtt - self.k; d * d * d } + self.w_max).clamp(cwnd, 1.5 * cwnd);
        // Standard TCP's window for the same path (the "Reno-friendly" region):
        // CUBIC is never slower than Reno would be.
        let alpha = 3.0 * (1.0 - CUBIC_BETA) / (1.0 + CUBIC_BETA);
        self.w_est += alpha * acked / cwnd.max(1.0);
        let goal = target.max(self.w_est);
        let increase = if goal > cwnd { (goal - cwnd) * acked / cwnd.max(1.0) } else { acked / (100.0 * cwnd.max(1.0)) };
        self.cwnd = self.cwnd.saturating_add((increase * self.mtu as f64) as u64);
    }

    /// One congestion event: the window becomes `factor` of what it was,
    /// unless it was already reduced within the last smoothed RTT (the same
    /// event, e.g. several frames lost from one burst). Returns whether it
    /// reduced.
    fn reduce(&mut self, factor: f64) -> bool {
        let now = Instant::now();
        if self.last_reduction.is_some_and(|t| now.duration_since(t) < self.srtt) {
            return false;
        }
        self.last_reduction = Some(now);
        let cwnd = self.cwnd_packets_f();
        // Fast convergence (RFC 9438 §4.7): a window that peaked below the
        // last one releases bandwidth to newer flows.
        self.w_max = if cwnd < self.w_max { cwnd * (1.0 + CUBIC_BETA) / 2.0 } else { cwnd };
        self.cwnd = ((self.cwnd as f64 * factor) as u64).max(MIN_CWND_PACKETS * self.mtu);
        self.ssthresh = self.cwnd;
        self.phase = Phase::ProbeBandwidth;
        self.epoch_start = None;
        self.clamp_cwnd();
        self.update_pacing_rate();
        true
    }

    /// Hard ceiling on the congestion window.
    ///
    /// Independent of any estimate: no real path this protocol runs over has a
    /// bandwidth-delay product anywhere near this, so a window above it is
    /// buffered queue rather than data in transit. Without it, slow start on a
    /// buffer that never drops could grow the window into the tens of megabytes.
    fn clamp_cwnd(&mut self) {
        let ceiling = MAX_CWND_PACKETS.saturating_mul(self.mtu);
        if self.cwnd > ceiling {
            self.cwnd = ceiling;
        }
    }

    /// A retransmission goes on the wire: it is paced like any other packet,
    /// so retransmits under loss cannot burst into a queue that is already
    /// full. It is not new data in flight: the frame was counted when first
    /// sent and leaves when it is acknowledged or discarded.
    pub fn on_retransmit(&mut self, bytes: u64) {
        self.consume_pacing(bytes);
    }

    /// A frame left the sender without an acknowledgement (given up on, or
    /// pushed out of the history): it is no longer in flight.
    pub fn on_discard(&mut self, bytes: u64) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes);
    }

    /// Record a loss event. The lost frame stays in flight until it is
    /// acknowledged (its retransmission) or discarded.
    pub fn on_loss(&mut self, _bytes_lost: u64) {
        self.loss_count += 1;

        match self.phase {
            Phase::SlowStart => {
                let now = Instant::now();
                if now.duration_since(self.slow_start_loss_window_start) > SLOW_START_LOSS_WINDOW {
                    // Previous window's losses have aged out - this loss starts a fresh count.
                    self.slow_start_losses = 0;
                    self.slow_start_loss_window_start = now;
                }
                self.slow_start_losses += 1;

                if self.slow_start_losses >= SLOW_START_LOSS_TOLERANCE {
                    // Sustained loss within the window: treat as real congestion
                    // and continue with CUBIC from beta of the window.
                    if self.reduce(CUBIC_BETA) {
                        tracing::debug!(cwnd = self.cwnd, "congestion: sustained loss during slow start, exiting");
                    }
                } else {
                    // Isolated loss: likely non-congestive noise. Take a mild,
                    // temporary haircut but keep exponential growth going -
                    // don't throw away slow start over a single dropped frame.
                    self.cwnd = (self.cwnd * 8 / 10).max(MIN_CWND_PACKETS * self.mtu);
                    tracing::debug!(cwnd = self.cwnd, count = self.slow_start_losses, "congestion: isolated loss during slow start, staying in slow start");
                }
            }
            Phase::ProbeBandwidth => {
                if self.reduce(CUBIC_BETA) {
                    tracing::debug!(cwnd = self.cwnd, "congestion: loss, cwnd reduced");
                }
            }
        }

        self.update_pacing_rate();
    }

    /// Bytes that may leave within `horizon` at the pacing rate, counting the
    /// allowance already in the bucket. For a sender that is woken
    /// periodically rather than per packet.
    pub fn pacing_budget(&self, horizon: Duration) -> f64 {
        let elapsed = self.pacing_last_refill.elapsed().as_secs_f64();
        let now = (self.pacing_tokens + elapsed * self.pacing_rate as f64).min(self.pacing_burst());
        now + horizon.as_secs_f64() * self.pacing_rate as f64
    }

    /// How long until one full packet of pacing allowance is there.
    pub fn time_to_pace(&self) -> Duration {
        let missing = self.mtu as f64 - self.pacing_available();
        if missing <= 0.0 || self.pacing_rate == 0 {
            return Duration::ZERO;
        }
        Duration::from_secs_f64(missing / self.pacing_rate as f64)
    }

    // ── Private ──────────────────────────────────────────────────────────────

    fn update_rtt(&mut self, rtt: Duration, now: Instant) {
        // Update windowed minimum RTT (for pacing)
        if rtt < self.min_rtt || now.duration_since(self.min_rtt_stamp) >= MIN_RTT_EXPIRY {
            self.min_rtt = rtt;
            self.min_rtt_stamp = now;
        }

        // Update SRTT and RTTVAR per RFC 6298
        if !self.rtt_initialized {
            // First measurement: initialize directly. min_rtt too: left at
            // INITIAL_RTT (30 ms) it stayed below any real RTT over 30 ms for
            // MIN_RTT_EXPIRY, so srtt/min_rtt read as a standing queue from the
            // first ACK: slow start ended at once above 60 ms, and above
            // 120 ms every ACK halved the window for the first 10 seconds.
            self.srtt = rtt;
            self.rttvar = rtt / 2;
            self.min_rtt = rtt;
            self.min_rtt_stamp = now;
            self.rtt_initialized = true;
        } else {
            // RTTVAR = (3/4) * RTTVAR + (1/4) * |SRTT - R|
            let diff = if rtt > self.srtt {
                rtt - self.srtt
            } else {
                self.srtt - rtt
            };
            // Integer-safe: RTTVAR = RTTVAR - RTTVAR/4 + diff/4
            self.rttvar = self.rttvar
                .saturating_sub(self.rttvar / 4)
                .saturating_add(diff / 4);

            // SRTT = (7/8) * SRTT + (1/8) * R
            self.srtt = self.srtt
                .saturating_sub(self.srtt / 8)
                .saturating_add(rtt / 8);
        }

        tracing::trace!(
            srtt_ms = self.srtt.as_millis(),
            rttvar_ms = self.rttvar.as_millis(),
            rto_ms = self.rto().as_millis(),
            "congestion: RTT updated"
        );
    }

    fn update_pacing_rate(&mut self) {
        // Pacing rate = cwnd / min_rtt (delivery rate target)
        let rtt_us = self.min_rtt.as_micros().max(1) as u64;
        self.pacing_rate = self.cwnd * 1_000_000 / rtt_us;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_state() {
        let cc = CongestionController::new(1200);
        assert_eq!(cc.cwnd(), 32 * 1200); // 32 * 1200
        assert!(cc.can_send());
        assert_eq!(cc.cwnd_packets(), 32);
    }

    #[test]
    fn test_slow_start_growth() {
        let mut cc = CongestionController::new(1200);
        let initial = cc.cwnd();
        cc.on_send(1200);
        cc.on_ack(1200, Duration::from_millis(50));
        assert!(cc.cwnd() > initial);
    }

    #[test]
    fn test_loss_reduces_cwnd() {
        let mut cc = CongestionController::new(1200);
        let initial = cc.cwnd();
        cc.on_loss(1200);
        assert!(cc.cwnd() < initial);
    }

    /// A controller past slow start with a real RTT sample, at `packets`.
    fn in_avoidance(packets: u64, rtt: Duration) -> CongestionController {
        let mut cc = CongestionController::new(1200);
        cc.on_ack(1200, rtt);
        cc.cwnd = packets * 1200;
        cc.enter_congestion_avoidance();
        cc
    }

    #[test]
    fn several_losses_in_one_rtt_are_one_reduction() {
        let mut cc = in_avoidance(1000, Duration::from_millis(40));
        cc.on_loss(1200);
        let once = cc.cwnd();
        assert_eq!(once, 700 * 1200);
        for _ in 0..5 {
            cc.on_loss(1200);
        }
        assert_eq!(cc.cwnd(), once, "a burst of losses within one RTT cut the window again");
    }

    /// CUBIC climbs back towards the window it had before a loss far faster
    /// than one packet per RTT.
    #[test]
    fn cubic_recovers_much_faster_than_reno() {
        let mut cc = in_avoidance(1000, Duration::from_millis(40));
        cc.on_loss(1200);
        cc.epoch_start = None;
        // Two seconds of ACKs (50 RTTs at 40 ms), a window's worth per RTT.
        let start = Instant::now() - Duration::from_secs(2);
        cc.cubic_grow(1200);
        cc.epoch_start = Some(start);
        for _ in 0..50 {
            let w = cc.cwnd();
            cc.on_ack(w, Duration::from_millis(40));
        }
        let packets = cc.cwnd() / 1200;
        assert!(packets > 750, "{packets} packets: Reno would be near 750");
        assert!(packets <= MAX_CWND_PACKETS);
    }

    #[test]
    fn a_standing_queue_halves_the_window_once_per_rtt() {
        let mut cc = in_avoidance(1000, Duration::from_millis(20));
        cc.srtt = Duration::from_millis(100); // 5x the minimum
        cc.on_ack(1200, Duration::from_millis(100));
        let once = cc.cwnd();
        assert!(once <= 501 * 1200);
        for _ in 0..20 {
            cc.on_ack(1200, Duration::from_millis(100));
        }
        assert!(cc.cwnd() >= once, "every ACK halved the window again");
    }

    /// The bufferbloat case: a deep buffer absorbs everything, so NOTHING is
    /// ever lost, but the standing queue inflates RTT. A loss-only controller
    /// grows cwnd forever here — which is how a session ends up reporting
    /// multi-second RTT and stalling video.
    #[test]
    fn test_rtt_inflation_halts_growth_without_any_loss() {
        let mut cc = CongestionController::new(1200);

        // Establish a low path floor; this becomes min_rtt.
        for _ in 0..4 {
            cc.on_send(1200);
            cc.on_ack(1200, Duration::from_millis(20));
        }
        let cwnd_before = cc.cwnd();

        // Queue builds: RTT climbs far above the floor, still zero loss.
        for _ in 0..20 {
            cc.on_send(1200);
            cc.on_ack(1200, Duration::from_millis(400));
        }

        assert!(
            cc.cwnd() <= cwnd_before,
            "cwnd kept growing while the queue was inflating RTT ({} -> {})",
            cwnd_before,
            cc.cwnd()
        );
    }

    /// Pacing must actually bound the release rate: draining the bucket has to
    /// deny the next packet. Without this the congestion window alone decides,
    /// and a whole window leaves back-to-back.
    #[test]
    fn test_pacing_bucket_denies_once_drained() {
        let mut cc = CongestionController::new(1200);
        assert!(cc.can_pace_packet(), "a fresh controller must allow sending");

        // Spend well beyond one burst allowance.
        let burst_bytes = cc.pacing_available();
        let mut spent = 0.0;
        while spent <= burst_bytes + 1200.0 {
            cc.on_send(1200);
            spent += 1200.0;
        }

        assert!(
            !cc.can_pace_packet(),
            "pacing allowed unbounded sending: {} bytes still available after spending {}",
            cc.pacing_available(),
            spent
        );
    }

    /// The allowance must refill over time, or sending would stall permanently
    /// once the first burst is spent.
    #[test]
    fn test_pacing_bucket_refills_over_time() {
        let mut cc = CongestionController::new(1200);
        while cc.can_pace_packet() {
            cc.on_send(1200);
        }
        assert!(!cc.can_pace_packet());

        std::thread::sleep(Duration::from_millis(25));
        assert!(
            cc.can_pace_packet(),
            "pacing bucket never refilled; sending would be stuck forever"
        );
    }

    /// cwnd must never exceed the absolute ceiling, however long slow start
    /// runs unopposed — above it the window is buffered queue, not throughput.
    #[test]
    fn test_cwnd_never_exceeds_absolute_ceiling() {
        let mut cc = CongestionController::new(1200);
        // Constant RTT: no inflation signal, so only the hard cap can stop this.
        for _ in 0..5000 {
            cc.on_send(1200);
            cc.on_ack(1200, Duration::from_millis(30));
        }
        assert!(
            cc.cwnd() <= MAX_CWND_PACKETS * 1200,
            "cwnd {} exceeded the {}-packet ceiling",
            cc.cwnd(),
            MAX_CWND_PACKETS
        );
    }

    #[test]
    fn test_isolated_slow_start_loss_does_not_exit_slow_start() {
        // A single dropped packet (wireless noise, a brief handover blip) is
        // normal on real links and must not permanently downgrade the
        // session from exponential to linear growth.
        let mut cc = CongestionController::new(1200);
        cc.on_loss(1200);
        assert_eq!(cc.phase, Phase::SlowStart, "one isolated loss must not exit slow start");

        // It should still shrink the window somewhat (not ignored entirely),
        // just far less punishing than the sustained-congestion case.
        let after_one = cc.cwnd();
        assert!(after_one < INITIAL_CWND_PACKETS * 1200);
    }

    #[test]
    fn test_sustained_slow_start_loss_exits_slow_start() {
        // Losses landing close together (within SLOW_START_LOSS_WINDOW) are
        // a real congestion signal and must still trigger the harsher
        // exit-slow-start + halve response.
        let mut cc = CongestionController::new(1200);
        for _ in 0..SLOW_START_LOSS_TOLERANCE {
            cc.on_loss(1200);
        }
        assert_eq!(cc.phase, Phase::ProbeBandwidth, "sustained loss must exit slow start");
    }

    #[test]
    fn test_slow_start_loss_window_resets_after_expiry() {
        // Two losses far enough apart (window expired between them) must
        // each be treated as isolated, not accumulated toward the sustained-
        // loss threshold.
        let mut cc = CongestionController::new(1200);
        cc.on_loss(1200);
        assert_eq!(cc.phase, Phase::SlowStart);

        // Simulate the window having expired by resetting its start
        // directly (std::thread::sleep in a unit test would be flaky/slow).
        cc.slow_start_loss_window_start = Instant::now() - SLOW_START_LOSS_WINDOW - Duration::from_millis(1);
        cc.on_loss(1200);
        assert_eq!(cc.phase, Phase::SlowStart, "a loss after the window expired must restart the count, not accumulate");
        assert_eq!(cc.slow_start_losses, 1);
    }

    #[test]
    fn test_can_send_limits() {
        let mut cc = CongestionController::new(1200);
        // Send until cwnd is exhausted
        for _ in 0..32 {
            cc.on_send(1200);
        }
        assert!(!cc.can_send()); // cwnd exhausted
    }

    #[test]
    fn test_retransmit_budget() {
        let cc = CongestionController::new(1200);
        let budget = cc.retransmit_budget();
        assert!(budget >= 2);
        assert!(budget <= 64);
    }

    #[test]
    fn test_rtt_tracking_first_sample() {
        let mut cc = CongestionController::new(1200);
        cc.on_send(1200);
        cc.on_ack(1200, Duration::from_millis(25));
        // After first sample: SRTT = 25ms, RTTVAR = 12ms
        assert_eq!(cc.smoothed_rtt(), Duration::from_millis(25));
    }

    #[test]
    fn test_rto_rfc6298() {
        let mut cc = CongestionController::new(1200);
        // After first sample with RTT=50ms: SRTT=50ms, RTTVAR=25ms, RTO=150ms
        cc.on_send(1200);
        cc.on_ack(1200, Duration::from_millis(50));
        let rto = cc.rto();
        // RTO = 50 + 4*25 = 150ms; clamped to [50ms, 16s]
        assert!(rto >= RTO_MIN);
        assert!(rto <= RTO_MAX);
        assert_eq!(rto, Duration::from_millis(150));
    }

    #[test]
    fn test_on_ack_no_rtt_grows_window_without_touching_srtt() {
        let mut cc = CongestionController::new(1200);
        // Establish a known SRTT with a real sample.
        cc.on_send(1200);
        cc.on_ack(1200, Duration::from_millis(40));
        let srtt_before = cc.smoothed_rtt();
        let cwnd_before = cc.cwnd();

        // A Karn's-algorithm ACK (all acked frames were retransmitted): window
        // must advance, RTT estimate must be untouched.
        cc.on_send(1200);
        cc.on_ack_no_rtt(1200);
        assert!(cc.cwnd() > cwnd_before, "cwnd should still grow on a no-RTT ack");
        assert_eq!(cc.smoothed_rtt(), srtt_before, "SRTT must not move on a no-RTT ack");
    }

    #[test]
    fn test_rto_clamp_min() {
        let cc = CongestionController::new(1200);
        // Even with no RTT samples, RTO should not go below RTO_MIN
        assert!(cc.rto() >= RTO_MIN);
    }

    #[test]
    fn test_rto_adapts_after_multiple_samples() {
        let mut cc = CongestionController::new(1200);
        // Feed several consistent RTT samples
        for _ in 0..8 {
            cc.on_send(1200);
            cc.on_ack(1200, Duration::from_millis(20));
        }
        // After convergence, RTTVAR should be small → RTO close to SRTT + small margin
        let rto = cc.rto();
        // Should be well below 100ms (the old hardcoded default)
        assert!(rto < Duration::from_millis(200));
        assert!(rto >= RTO_MIN);
    }

    /// On a 150 ms path the first ACKs must not read as a standing queue:
    /// min_rtt comes from the first sample, not the 30 ms guess.
    #[test]
    fn slow_start_survives_a_long_path() {
        let mut cc = CongestionController::new(1200);
        let start = cc.cwnd();
        for _ in 0..20 {
            cc.on_send(1200);
            cc.on_ack(1200, Duration::from_millis(150));
        }
        assert_eq!(cc.phase, Phase::SlowStart, "slow start ended on the first ACKs of a 150 ms path");
        assert_eq!(cc.cwnd(), start + 20 * 1200, "the window grows by what was acknowledged");
    }

    /// The same after a path change, which resets the estimate.
    #[test]
    fn a_new_path_learns_its_own_min_rtt() {
        let mut cc = CongestionController::new(1200);
        cc.on_ack(1200, Duration::from_millis(20));
        cc.reset_path();
        for _ in 0..10 {
            cc.on_ack(1200, Duration::from_millis(200));
        }
        assert_eq!(cc.phase, Phase::SlowStart);
        assert!(cc.cwnd() >= INITIAL_CWND_PACKETS * 1200);
    }

    #[test]
    fn a_loss_does_not_take_the_frame_out_of_flight() {
        let mut cc = CongestionController::new(1200);
        cc.on_send(1200);
        cc.on_loss(1200);
        assert_eq!(cc.bytes_in_flight, 1200, "it leaves when acknowledged or discarded");
        cc.on_discard(1200);
        assert_eq!(cc.bytes_in_flight, 0);
    }

    #[test]
    fn retransmits_are_paced() {
        let mut cc = CongestionController::new(1200);
        let before = cc.pacing_available();
        cc.on_retransmit(1200 * 8);
        assert!(cc.pacing_available() < before);
        assert_eq!(cc.bytes_in_flight, 0, "a retransmit is not new data in flight");
    }
}
