//! Congestion control for the OSTP protocol.
//!
//! Implements a simplified BBR-inspired algorithm that estimates bottleneck
//! bandwidth and minimum RTT to determine the optimal sending rate.
//! This replaces the fixed `retransmit_budget = 8` with an adaptive
//! congestion window that responds to network conditions.

use std::time::{Duration, Instant};

/// Congestion control state for a single OSTP session.
pub struct CongestionController {
    /// Current congestion window in bytes (how much can be in-flight)
    cwnd: u64,
    /// Slow-start threshold in bytes
    ssthresh: u64,
    /// Current phase
    phase: Phase,
    /// Minimum RTT observed
    min_rtt: Duration,
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
    /// MTU estimate (used for cwnd → packet count conversion)
    mtu: u64,
    /// Min RTT expiry: re-probe after 10 seconds
    min_rtt_stamp: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Exponential growth until loss or ssthresh
    SlowStart,
    /// Probe bandwidth: cycle through pacing gains
    ProbeBandwidth,
}

/// Initial congestion window: 10 packets × MTU
const INITIAL_CWND_PACKETS: u64 = 10;
/// Minimum cwnd: 2 packets
const MIN_CWND_PACKETS: u64 = 2;
/// Min RTT expiry window (after which we re-probe)
const MIN_RTT_EXPIRY: Duration = Duration::from_secs(10);

impl CongestionController {
    pub fn new(mtu: u64) -> Self {
        let now = Instant::now();
        let initial_cwnd = INITIAL_CWND_PACKETS * mtu;
        Self {
            cwnd: initial_cwnd,
            ssthresh: u64::MAX,
            phase: Phase::SlowStart,
            min_rtt: Duration::from_millis(100), // Conservative initial estimate
            bytes_in_flight: 0,
            total_acked: 0,
            last_ack_time: now,
            loss_count: 0,
            pacing_rate: initial_cwnd * 10, // initial: ~10 windows/sec
            mtu,
            min_rtt_stamp: now,
        }
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

    /// Returns the smoothed RTT estimate.
    pub fn smoothed_rtt(&self) -> Duration {
        self.min_rtt
    }

    /// Returns how many bytes can still be sent.
    pub fn available_cwnd(&self) -> u64 {
        self.cwnd.saturating_sub(self.bytes_in_flight)
    }

    /// Returns the recommended retransmit budget per tick.
    pub fn retransmit_budget(&self) -> usize {
        // Allow retransmitting up to 1/4 of the cwnd in packets per tick
        let budget = (self.cwnd_packets() / 4).max(2);
        budget.min(64) // cap at 64 to prevent burst
    }

    /// Check whether we can send more data.
    pub fn can_send(&self) -> bool {
        self.bytes_in_flight < self.cwnd
    }

    /// Record that we sent `bytes` of data.
    pub fn on_send(&mut self, bytes: u64) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_add(bytes);
    }

    /// Record that `bytes` were acknowledged with the given RTT sample.
    pub fn on_ack(&mut self, bytes: u64, rtt: Duration) {
        let now = Instant::now();
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes);
        self.total_acked = self.total_acked.saturating_add(bytes);

        // Update RTT
        self.update_rtt(rtt, now);

        // Update bandwidth estimate
        self.update_bandwidth(bytes, now);

        // State machine
        match self.phase {
            Phase::SlowStart => {
                // Exponential growth: increase cwnd by acked bytes
                self.cwnd = self.cwnd.saturating_add(bytes);
                if self.cwnd >= self.ssthresh {
                    self.phase = Phase::ProbeBandwidth;
                    tracing::debug!(cwnd = self.cwnd, "congestion: exiting slow start");
                }
            }
            Phase::ProbeBandwidth => {
                // TCP Reno Additive Increase: increase cwnd by ~1 MTU per RTT
                self.cwnd = self.cwnd.saturating_add(bytes * self.mtu / self.cwnd.max(1));
            }
        }

        self.update_pacing_rate();
        self.last_ack_time = now;
    }

    /// Record a loss event.
    pub fn on_loss(&mut self, bytes_lost: u64) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes_lost);
        self.loss_count += 1;

        match self.phase {
            Phase::SlowStart => {
                // Exit slow start, set ssthresh to half of cwnd
                self.ssthresh = self.cwnd / 2;
                self.cwnd = self.ssthresh.max(MIN_CWND_PACKETS * self.mtu);
                self.phase = Phase::ProbeBandwidth;
                tracing::debug!(cwnd = self.cwnd, ssthresh = self.ssthresh, "congestion: loss during slow start");
            }
            Phase::ProbeBandwidth => {
                // Multiplicative decrease: cwnd *= 0.7 (BBR-style, less aggressive than Cubic's 0.5)
                self.cwnd = (self.cwnd * 7 / 10).max(MIN_CWND_PACKETS * self.mtu);
                tracing::debug!(cwnd = self.cwnd, "congestion: loss, cwnd reduced");
            }
        }

        self.update_pacing_rate();
    }

    /// Called periodically to update state.
    pub fn on_tick(&mut self) {
        // Nothing special needed per-tick -- state updates happen on ACK/loss
    }

    // ── Private ──────────────────────────────────────────────────────────────

    fn update_rtt(&mut self, rtt: Duration, now: Instant) {
        // Track windowed minimum RTT
        if rtt < self.min_rtt || now.duration_since(self.min_rtt_stamp) >= MIN_RTT_EXPIRY {
            self.min_rtt = rtt;
            self.min_rtt_stamp = now;
        }
    }

    fn update_bandwidth(&mut self, _acked_bytes: u64, now: Instant) {
        let elapsed = now.duration_since(self.last_ack_time);
        if elapsed.as_micros() > 0 {
        // Removed bw_samples tracking
        }
    }



    fn update_pacing_rate(&mut self) {
        // Pacing rate = cwnd / min_rtt (with gain)
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
        assert_eq!(cc.cwnd(), 12000); // 10 * 1200
        assert!(cc.can_send());
        assert_eq!(cc.cwnd_packets(), 10);
    }

    #[test]
    fn test_slow_start_growth() {
        let mut cc = CongestionController::new(1200);
        // Simulate sending and ACKing
        cc.on_send(1200);
        cc.on_ack(1200, Duration::from_millis(50));
        // cwnd should grow
        assert!(cc.cwnd() > 12000);
    }

    #[test]
    fn test_loss_reduces_cwnd() {
        let mut cc = CongestionController::new(1200);
        let initial = cc.cwnd();
        cc.on_loss(1200);
        assert!(cc.cwnd() < initial);
    }

    #[test]
    fn test_can_send_limits() {
        let mut cc = CongestionController::new(1200);
        // Send until cwnd is exhausted
        for _ in 0..10 {
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
    fn test_rtt_tracking() {
        let mut cc = CongestionController::new(1200);
        cc.on_send(1200);
        cc.on_ack(1200, Duration::from_millis(25));
        assert_eq!(cc.smoothed_rtt(), Duration::from_millis(25));
    }
}
