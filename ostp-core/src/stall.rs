//! Stall detection for a session's sending side.
//!
//! A frame lost on a datagram path waits for its retransmit timer, which backs
//! off exponentially: the cumulative wait for one frame could reach tens of
//! seconds, and a v5 session delivers nothing behind a missing frame. The
//! timer cannot tell a quiet path from a lost tail, so this watches the one
//! thing that matters: data is in flight and no ACK made progress.
//!
//! A stall is data in flight and no ACK progress for longer than
//! `max(4 x SRTT, 1 s)`. Then the oldest unacknowledged frame is resent at
//! once (a tail-loss probe), and again every such period until an ACK moves.
//! The detector only says when; the machine resends. Nothing here reconnects
//! or changes the carrier: the detector acts inside the session.
//!
//! On a reliable carrier (UoT, TLS) a frame is never lost on the way and
//! nothing is resent, so there the stall is counted and logged only: nothing
//! heard from the peer for `RELIABLE_STALL` while data is queued.
//!
//! Pure: time is passed in.

use std::time::{Duration, Instant};

/// The shortest period of no ACK progress that is a stall.
pub const MIN_STALL: Duration = Duration::from_secs(1);
/// On a reliable carrier: nothing heard from the peer for this long.
pub const RELIABLE_STALL: Duration = Duration::from_secs(5);

/// How long without ACK progress, with data in flight, is a stall (and the
/// longest a data frame waits between two sends).
pub fn threshold(srtt: Duration) -> Duration {
    srtt.saturating_mul(4).max(MIN_STALL)
}

/// Whether the `n`th stall (counted from 1) is logged: the first, then every
/// power of two, so a flapping path cannot fill the log.
pub fn loggable(n: u32) -> bool {
    n.is_power_of_two()
}

/// A stall that was found, or goes on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stall {
    /// How long there has been no progress.
    pub stalled_for: Duration,
    /// The number of this stall since the session started (from 1).
    pub episode: u32,
    /// The first probe of this stall: its start.
    pub first: bool,
    /// Probes sent in this stall, this one included.
    pub probes: u32,
}

/// A stall that ended: progress came back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StallEnd {
    pub lasted: Duration,
    pub episode: u32,
    pub probes: u32,
}

#[derive(Debug)]
pub struct StallDetector {
    /// The last progress, or the moment data was first put in flight on an
    /// idle session.
    last_progress: Instant,
    /// The start of the stall in progress, and when it last probed.
    stall: Option<(Instant, Instant)>,
    probes: u32,
    episodes: u32,
}

impl StallDetector {
    pub fn new(now: Instant) -> Self {
        StallDetector { last_progress: now, stall: None, probes: 0, episodes: 0 }
    }

    /// Stalls so far.
    pub fn episodes(&self) -> u32 {
        self.episodes
    }

    /// Whether a stall is going on.
    pub fn stalled(&self) -> bool {
        self.stall.is_some()
    }

    /// Data went into flight. On a session with nothing in flight before,
    /// this starts the clock: a long idle time is not a stall.
    pub fn on_data_sent(&mut self, now: Instant, was_idle: bool) {
        if was_idle {
            self.last_progress = now;
        }
    }

    /// An ACK acknowledged something (or, on a reliable carrier, the peer was
    /// heard). Ends a stall.
    pub fn on_progress(&mut self, now: Instant) -> Option<StallEnd> {
        self.last_progress = now;
        let (start, _) = self.stall.take()?;
        let probes = std::mem::take(&mut self.probes);
        Some(StallEnd { lasted: now.duration_since(start), episode: self.episodes, probes })
    }

    /// Nothing is in flight any more (everything was acknowledged or given
    /// up): there is nothing to stall on.
    pub fn on_idle(&mut self, now: Instant) {
        self.last_progress = now;
        self.stall = None;
        self.probes = 0;
    }

    /// The caller found nothing to act on for `stall` just returned by
    /// `poll` (only frames that are never resent were in flight): it was no
    /// stall, and it is not counted.
    pub fn retract(&mut self, stall: &Stall, now: Instant) {
        if stall.first {
            self.episodes = self.episodes.saturating_sub(1);
        }
        self.on_idle(now);
    }

    /// A stall found, or going on, with data in flight: `after` is how long
    /// without progress makes one (`threshold` of the SRTT, or `RELIABLE_STALL`).
    /// Returns `Some` once per `after`: at the start of a stall, and again for
    /// each further period of it.
    pub fn poll(&mut self, now: Instant, in_flight: bool, after: Duration) -> Option<Stall> {
        if !in_flight {
            self.on_idle(now);
            return None;
        }
        let since = match self.stall {
            Some((_, last_probe)) => last_probe,
            None => self.last_progress,
        };
        if now.duration_since(since) < after {
            return None;
        }
        let first = self.stall.is_none();
        let start = match self.stall {
            Some((start, _)) => start,
            None => {
                self.episodes += 1;
                self.last_progress
            }
        };
        self.stall = Some((start, now));
        self.probes += 1;
        Some(Stall { stalled_for: now.duration_since(start), episode: self.episodes, first, probes: self.probes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn the_threshold_is_four_srtts_and_never_below_a_second() {
        assert_eq!(threshold(ms(20)), MIN_STALL);
        assert_eq!(threshold(ms(250)), MIN_STALL);
        assert_eq!(threshold(ms(400)), ms(1600));
        assert_eq!(threshold(ms(3000)), ms(12_000));
    }

    #[test]
    fn nothing_in_flight_is_never_a_stall() {
        let t0 = Instant::now();
        let mut d = StallDetector::new(t0);
        assert_eq!(d.poll(t0 + Duration::from_secs(60), false, MIN_STALL), None);
        assert_eq!(d.episodes(), 0);
        // And the idle time does not count once data goes in flight.
        let later = t0 + Duration::from_secs(60);
        d.on_data_sent(later, true);
        assert_eq!(d.poll(later + ms(900), true, MIN_STALL), None);
        let s = d.poll(later + ms(1000), true, MIN_STALL).expect("a second without progress");
        assert!(s.first);
        assert_eq!(s.stalled_for, ms(1000));
    }

    #[test]
    fn a_stall_starts_after_the_threshold_and_probes_once_per_period() {
        let t0 = Instant::now();
        let mut d = StallDetector::new(t0);
        d.on_data_sent(t0, true);
        let after = ms(1600);

        assert_eq!(d.poll(t0 + ms(1599), true, after), None);
        let first = d.poll(t0 + ms(1600), true, after).unwrap();
        assert_eq!(first, Stall { stalled_for: ms(1600), episode: 1, first: true, probes: 1 });
        // The same period does not probe twice.
        assert_eq!(d.poll(t0 + ms(1601), true, after), None);
        assert_eq!(d.poll(t0 + ms(3199), true, after), None);
        let second = d.poll(t0 + ms(3200), true, after).unwrap();
        assert_eq!(second, Stall { stalled_for: ms(3200), episode: 1, first: false, probes: 2 });
        assert!(d.stalled());
    }

    #[test]
    fn progress_ends_the_stall_and_reports_it() {
        let t0 = Instant::now();
        let mut d = StallDetector::new(t0);
        d.on_data_sent(t0, true);
        d.poll(t0 + ms(1000), true, MIN_STALL).unwrap();
        d.poll(t0 + ms(2000), true, MIN_STALL).unwrap();
        let end = d.on_progress(t0 + ms(2400)).unwrap();
        assert_eq!(end, StallEnd { lasted: ms(2400), episode: 1, probes: 2 });
        assert!(!d.stalled());
        // Progress with no stall going says nothing.
        assert_eq!(d.on_progress(t0 + ms(2500)), None);
    }

    #[test]
    fn steady_progress_is_never_a_stall() {
        let t0 = Instant::now();
        let mut d = StallDetector::new(t0);
        d.on_data_sent(t0, true);
        let mut now = t0;
        for _ in 0..100 {
            now += ms(500);
            d.on_progress(now);
            assert_eq!(d.poll(now + ms(1), true, MIN_STALL), None);
        }
        assert_eq!(d.episodes(), 0);
    }

    #[test]
    fn each_stall_is_numbered_and_a_new_one_starts_from_the_last_progress() {
        let t0 = Instant::now();
        let mut d = StallDetector::new(t0);
        d.on_data_sent(t0, true);
        assert_eq!(d.poll(t0 + ms(1000), true, MIN_STALL).unwrap().episode, 1);
        d.on_progress(t0 + ms(1100));
        // The second stall is timed from the progress, not from the first one.
        assert_eq!(d.poll(t0 + ms(2000), true, MIN_STALL), None);
        let s = d.poll(t0 + ms(2100), true, MIN_STALL).unwrap();
        assert_eq!((s.episode, s.first, s.probes, s.stalled_for), (2, true, 1, ms(1000)));
    }

    /// The `n`th stall is logged for the first and for each power of two.
    #[test]
    fn the_log_gets_the_first_stall_and_then_every_power_of_two() {
        let logged: Vec<u32> = (1..=40).filter(|&n| loggable(n)).collect();
        assert_eq!(logged, [1, 2, 4, 8, 16, 32]);
        assert!(!loggable(0));
    }

    /// Data that is acknowledged leaves nothing to stall on: the next data
    /// after a long idle time starts its own clock.
    #[test]
    fn going_idle_ends_a_stall_without_a_report() {
        let t0 = Instant::now();
        let mut d = StallDetector::new(t0);
        d.on_data_sent(t0, true);
        d.poll(t0 + ms(1000), true, MIN_STALL).unwrap();
        assert!(d.stalled());
        assert_eq!(d.poll(t0 + ms(1500), false, MIN_STALL), None);
        assert!(!d.stalled());
        // The count of stalls stays.
        assert_eq!(d.episodes(), 1);
    }

    /// A stall the caller finds nothing to resend for was none.
    #[test]
    fn a_retracted_stall_is_not_counted() {
        let t0 = Instant::now();
        let mut d = StallDetector::new(t0);
        d.on_data_sent(t0, true);
        let s = d.poll(t0 + ms(1000), true, MIN_STALL).unwrap();
        d.retract(&s, t0 + ms(1000));
        assert_eq!(d.episodes(), 0);
        assert!(!d.stalled());
        // The clock starts from there.
        assert_eq!(d.poll(t0 + ms(1500), true, MIN_STALL), None);
        assert_eq!(d.poll(t0 + ms(2000), true, MIN_STALL).unwrap().episode, 1);
    }

    /// On a reliable carrier the same detector counts silence from the peer.
    #[test]
    fn a_reliable_carrier_counts_five_seconds_of_silence_with_data_queued() {
        let t0 = Instant::now();
        let mut d = StallDetector::new(t0);
        d.on_data_sent(t0, true);
        assert_eq!(d.poll(t0 + ms(4999), true, RELIABLE_STALL), None);
        let s = d.poll(t0 + ms(5000), true, RELIABLE_STALL).unwrap();
        assert!(s.first);
        // The peer is heard: over.
        assert_eq!(d.on_progress(t0 + ms(5200)).unwrap().lasted, ms(5200));
    }
}
