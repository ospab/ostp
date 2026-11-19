//! The two delays the apps show.
//!
//! The in-tunnel ping (`RelayMessage::Ping`/`Pong` on the control stream)
//! waits behind every data frame queued ahead of it, so it measures the queue
//! as much as the network: 50 s on a TLS carrier whose server queue had grown
//! that long. What the apps show as "RTT" is the path's own round trip, which
//! the congestion controller measures from ACKs (`ProtocolMachine::path_rtt`).
//! The in-tunnel ping stays as a second number, the queue delay: how much
//! longer a message takes than a bare frame would.

use ostp_core::congestion::PathRtt;
use std::time::Duration;

/// The apps show the queue delay when it is above this.
pub const QUEUE_SHOWN_ABOVE_MS: f64 = 200.0;

/// The path RTT to show for a set of sessions: the best (lowest) smoothed RTT
/// among those that have a sample. A session without one (just started, or
/// just moved to a new path) says nothing about the path yet.
pub fn best_path_rtt(sessions: impl IntoIterator<Item = Option<PathRtt>>) -> Option<Duration> {
    sessions.into_iter().flatten().map(|p| p.smoothed).min()
}

/// Queue delay, in ms: the in-tunnel round trip beyond the path's. Never
/// negative: a ping can be answered a little sooner than the smoothed RTT.
pub fn queue_delay_ms(tunnel_ms: f64, path_ms: f64) -> f64 {
    (tunnel_ms - path_ms).max(0.0)
}

/// The CLI's status line: the path RTT, and the queue delay when it is worth
/// showing.
pub fn status_text(rtt_ms: f64, queue_ms: f64) -> String {
    if queue_ms > QUEUE_SHOWN_ABOVE_MS {
        format!("rtt={rtt_ms:.1}ms, queue={queue_ms:.0}ms")
    } else {
        format!("rtt={rtt_ms:.1}ms")
    }
}

/// Milliseconds, as the apps' integer field wants them.
pub fn to_ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(ms: u64) -> Option<PathRtt> {
        Some(PathRtt { smoothed: Duration::from_millis(ms), min: Duration::from_millis(ms / 2) })
    }

    #[test]
    fn the_best_live_session_gives_the_path_rtt() {
        assert_eq!(best_path_rtt([p(120), p(45), p(300)]), Some(Duration::from_millis(45)));
        // A session with no sample yet does not pull the answer to zero.
        assert_eq!(best_path_rtt([None, p(90)]), Some(Duration::from_millis(90)));
        assert_eq!(best_path_rtt([None, None]), None);
        assert_eq!(best_path_rtt(std::iter::empty()), None);
    }

    #[test]
    fn the_queue_delay_is_the_tunnel_ping_beyond_the_path_and_never_negative() {
        assert_eq!(queue_delay_ms(50_000.0, 40.0), 49_960.0);
        assert_eq!(queue_delay_ms(35.0, 40.0), 0.0);
        assert_eq!(queue_delay_ms(0.0, 0.0), 0.0);
    }

    #[test]
    fn the_status_line_names_the_queue_only_above_the_threshold() {
        assert_eq!(status_text(42.0, 0.0), "rtt=42.0ms");
        assert_eq!(status_text(42.0, 200.0), "rtt=42.0ms");
        assert_eq!(status_text(42.0, 1800.4), "rtt=42.0ms, queue=1800ms");
    }

    #[test]
    fn a_duration_becomes_fractional_milliseconds() {
        assert_eq!(to_ms(Duration::from_micros(1500)), 1.5);
    }
}
