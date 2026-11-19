//! Path MTU discovery for one direction of one session, in the spirit of
//! RFC 8899 (DPLPMTUD): the sender finds out by itself how large a datagram the
//! path carries, so nobody has to type an MTU.
//!
//! Each side probes what IT sends. It starts at a size every path carries
//! (`BASE`), and tries the next rung of a short ladder with a padded probe that
//! the peer must acknowledge:
//!
//! - an ACKed probe confirms its size, and the next rung is tried at once;
//! - a rung whose probe is lost `MAX_PROBE_LOSSES` times in a row is the
//!   ceiling: the size stays at the rung below, and the rung above is tried
//!   again only after `REPROBE_AFTER` (the path may have changed);
//! - black hole detection: when frames of one size keep getting lost (the same
//!   frame, again and again) while smaller ones get through, the path no longer
//!   carries that size. The size drops below it and the lost size becomes the
//!   ceiling.
//!
//! This is the pure logic: time is passed in, nothing is sent here. The
//! protocol machine builds the probes and tells this what happened to them
//! (`ProtocolMachine`, v6 sessions on a datagram carrier only).

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// The size (UDP payload, the whole datagram) every path is taken to carry: a
/// 1280-byte IPv6 minimum MTU less IP and UDP headers leaves 1232.
pub const BASE: usize = 1200;
/// The rungs above `BASE`, tried in this order.
pub const LADDER: [usize; 4] = [1280, 1350, 1400, 1452];
/// The most a datagram is ever made: the top rung (1500 less IPv4 and UDP
/// headers is 1472; the rest is left for tunnels under the path).
pub const MAX: usize = 1452;
/// A rung is the ceiling after this many probes of it were lost in a row.
pub const MAX_PROBE_LOSSES: u8 = 3;
/// A ceiling is forgotten, and the rung above tried again, after this long.
pub const REPROBE_AFTER: Duration = Duration::from_secs(600);
/// The pause before a lost probe is tried again.
pub const RETRY_PAUSE: Duration = Duration::from_millis(500);
/// A frame resent this many times and still lost is a candidate black hole.
pub const BLACK_HOLE_RETRIES: u8 = 3;
/// A frame this much smaller than the lost one is "small".
const SMALL_MARGIN: usize = 32;
/// ACK summaries kept as evidence.
const EVIDENCE_KEPT: usize = 32;

/// What changed, for the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    /// A probe was acknowledged: the size grew.
    Raised { to: usize },
    /// `size` is lost for good (for now): the rung below it is the most there is.
    Ceiling { size: usize },
    /// Frames of `lost` bytes kept getting lost while smaller ones got through:
    /// the size fell from `from` to `to`.
    BlackHole { lost: usize, from: usize, to: usize },
    /// The ceiling is forgotten: the next rung is tried again.
    Reprobing { size: usize },
}

/// The sizes of the frames one ACK acknowledged.
#[derive(Debug, Clone, Copy)]
struct AckSummary {
    at: Instant,
    smallest: usize,
    largest: usize,
}

pub struct PathMtu {
    /// Rungs above the base, ascending, none above the configured maximum.
    rungs: Vec<usize>,
    base: usize,
    current: usize,
    /// The smallest size known not to pass; the rung is not probed (and the
    /// size not used) until `REPROBE_AFTER`.
    ceiling: Option<(usize, Instant)>,
    in_flight: Option<usize>,
    losses: u8,
    next_probe_at: Instant,
    acks: VecDeque<AckSummary>,
}

impl PathMtu {
    /// Starts at `base` and may climb to `max` (rungs above `max` are not
    /// tried). A `base` at or above `max` is a fixed size: nothing is probed.
    pub fn new(base: usize, max: usize, now: Instant) -> Self {
        let rungs = LADDER.iter().copied().filter(|&r| r > base && r <= max).collect();
        PathMtu {
            rungs,
            base,
            current: base,
            ceiling: None,
            in_flight: None,
            losses: 0,
            next_probe_at: now,
            acks: VecDeque::new(),
        }
    }

    /// The size to send at.
    pub fn current(&self) -> usize {
        self.current
    }

    /// The ceiling now in force, if any.
    pub fn ceiling(&self) -> Option<usize> {
        self.ceiling.map(|(size, _)| size)
    }

    /// Whether a probe is out.
    pub fn probing(&self) -> bool {
        self.in_flight.is_some()
    }

    /// The size of a probe to send now, or `None`. Asking marks the probe as
    /// sent: report its fate with `probe_acked` or `probe_lost`.
    pub fn next_probe(&mut self, now: Instant) -> (Option<usize>, Option<Change>) {
        let mut change = None;
        if self.in_flight.is_some() {
            return (None, None);
        }
        if let Some((size, since)) = self.ceiling {
            if now.duration_since(since) >= REPROBE_AFTER {
                self.ceiling = None;
                self.losses = 0;
                change = Some(Change::Reprobing { size });
            }
        }
        if now < self.next_probe_at {
            return (None, change);
        }
        let limit = self.ceiling.map_or(usize::MAX, |(size, _)| size);
        let target = self.rungs.iter().copied().find(|&r| r > self.current && r < limit);
        if let Some(size) = target {
            self.in_flight = Some(size);
        }
        (target, change)
    }

    /// The probe of `size` was acknowledged.
    pub fn probe_acked(&mut self, size: usize, now: Instant) -> Option<Change> {
        if self.in_flight != Some(size) {
            return None;
        }
        self.in_flight = None;
        self.losses = 0;
        self.next_probe_at = now;
        if size > self.current {
            self.current = size;
            return Some(Change::Raised { to: size });
        }
        None
    }

    /// The probe of `size` was lost. After `MAX_PROBE_LOSSES` in a row the
    /// size is the ceiling.
    pub fn probe_lost(&mut self, size: usize, now: Instant) -> Option<Change> {
        if self.in_flight != Some(size) {
            return None;
        }
        self.in_flight = None;
        self.losses += 1;
        if self.losses >= MAX_PROBE_LOSSES {
            self.losses = 0;
            self.ceiling = Some((size, now));
            return Some(Change::Ceiling { size });
        }
        self.next_probe_at = now + RETRY_PAUSE;
        None
    }

    /// Frames of `smallest..=largest` bytes of ours were acknowledged: the
    /// evidence black hole detection weighs.
    pub fn note_acked(&mut self, smallest: usize, largest: usize, now: Instant) {
        if self.acks.len() == EVIDENCE_KEPT {
            self.acks.pop_front();
        }
        self.acks.push_back(AckSummary { at: now, smallest, largest });
    }

    /// A frame of `len` bytes, first sent at `first_sent`, was resent
    /// `retries` times and is still not acknowledged. Returns the change when
    /// this is a black hole: since it was first sent nothing that large has
    /// been acknowledged, but something clearly smaller has (so the path is
    /// up, and it is the size it will not carry).
    ///
    /// Frames bigger than the current size were built before an earlier drop
    /// and say nothing new; frames at the base size cannot go lower.
    pub fn black_hole(&mut self, len: usize, retries: u8, first_sent: Instant, now: Instant) -> Option<Change> {
        if retries < BLACK_HOLE_RETRIES || len <= self.base || len > self.current {
            return None;
        }
        let since = |s: &&AckSummary| s.at >= first_sent;
        // A frame that large got through while this one was being lost: the
        // path carries the size, and this loss is something else.
        if self.acks.iter().filter(since).any(|s| s.largest >= len) {
            return None;
        }
        // Nothing small got through either: the path is down, not the size.
        if !self.acks.iter().filter(since).any(|s| s.smallest + SMALL_MARGIN <= len) {
            return None;
        }
        let from = self.current;
        // The largest size below the lost one.
        let to = std::iter::once(self.base)
            .chain(self.rungs.iter().copied())
            .filter(|&r| r < len)
            .max()
            .unwrap_or(self.base);
        self.current = to;
        self.ceiling = Some((len, now));
        self.in_flight = None;
        self.losses = 0;
        self.next_probe_at = now;
        // What was acknowledged at the old sizes proves nothing about the new.
        self.acks.clear();
        Some(Change::BlackHole { lost: len, from, to })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(base: Instant, secs: f64) -> Instant {
        base + Duration::from_secs_f64(secs)
    }

    /// A path that carries `path` bytes: probes at most that big are acked.
    /// Runs the probing to rest and returns the size it settled on.
    fn settle(path: usize) -> (PathMtu, Instant) {
        let t0 = Instant::now();
        let mut m = PathMtu::new(BASE, MAX, t0);
        let mut now = t0;
        // A step is longer than the retry pause, and all of them together
        // shorter than the time a ceiling is kept.
        for _ in 0..60 {
            if let (Some(size), _) = m.next_probe(now) {
                if size <= path {
                    m.probe_acked(size, now);
                } else {
                    m.probe_lost(size, now);
                }
            }
            now += Duration::from_millis(600);
        }
        (m, now)
    }

    #[test]
    fn it_starts_at_the_base_and_probes_the_first_rung() {
        let t0 = Instant::now();
        let mut m = PathMtu::new(BASE, MAX, t0);
        assert_eq!(m.current(), 1200);
        assert_eq!(m.next_probe(t0).0, Some(1280));
        // One probe at a time.
        assert!(m.probing());
        assert_eq!(m.next_probe(t0).0, None);
    }

    #[test]
    fn a_path_that_carries_everything_climbs_the_whole_ladder() {
        let (m, _) = settle(1500);
        assert_eq!(m.current(), 1452);
        assert_eq!(m.ceiling(), None);
        assert!(!m.probing());
    }

    /// The size is the largest rung the path carries, whatever lies between.
    #[test]
    fn the_size_settles_on_the_largest_rung_that_passes() {
        for (path, want) in [(1200, 1200), (1279, 1200), (1280, 1280), (1349, 1280), (1360, 1350), (1420, 1400), (1452, 1452)] {
            let (m, _) = settle(path);
            assert_eq!(m.current(), want, "path of {path}");
        }
    }

    #[test]
    fn a_rung_is_the_ceiling_only_after_three_lost_probes_in_a_row() {
        let t0 = Instant::now();
        let mut m = PathMtu::new(BASE, MAX, t0);
        let mut now = t0;
        assert_eq!(m.next_probe(now).0, Some(1280));
        assert_eq!(m.probe_acked(1280, now), Some(Change::Raised { to: 1280 }));
        assert_eq!(m.next_probe(now).0, Some(1350));
        // Two losses are random loss, not a ceiling: the same rung is tried again.
        assert_eq!(m.probe_lost(1350, now), None);
        assert_eq!(m.next_probe(now).0, None, "waits out the retry pause");
        now += RETRY_PAUSE;
        assert_eq!(m.next_probe(now).0, Some(1350));
        assert_eq!(m.probe_lost(1350, now), None);
        now += RETRY_PAUSE;
        assert_eq!(m.next_probe(now).0, Some(1350));
        // The third in a row is.
        assert_eq!(m.probe_lost(1350, now), Some(Change::Ceiling { size: 1350 }));
        assert_eq!(m.ceiling(), Some(1350));
        assert_eq!(m.current(), 1280);
        now += RETRY_PAUSE;
        assert_eq!(m.next_probe(now).0, None, "nothing above a ceiling is tried");
    }

    #[test]
    fn an_acknowledged_probe_forgives_earlier_losses() {
        let t0 = Instant::now();
        let mut m = PathMtu::new(BASE, MAX, t0);
        let mut now = t0;
        m.next_probe(now);
        m.probe_lost(1280, now);
        now += RETRY_PAUSE;
        m.next_probe(now);
        m.probe_lost(1280, now);
        now += RETRY_PAUSE;
        m.next_probe(now);
        m.probe_acked(1280, now);
        // The next rung starts its own count.
        m.next_probe(now);
        assert_eq!(m.probe_lost(1350, now), None);
        assert_eq!(m.ceiling(), None);
    }

    #[test]
    fn a_report_for_a_probe_that_is_not_out_changes_nothing() {
        let t0 = Instant::now();
        let mut m = PathMtu::new(BASE, MAX, t0);
        assert_eq!(m.probe_acked(1280, t0), None);
        assert_eq!(m.probe_lost(1280, t0), None);
        m.next_probe(t0);
        // A late answer for another size.
        assert_eq!(m.probe_acked(1350, t0), None);
        assert_eq!(m.current(), 1200);
        assert!(m.probing());
    }

    /// A path that grew a larger MTU is found again, but only after 10 minutes.
    #[test]
    fn a_ceiling_is_probed_again_after_ten_minutes() {
        let (mut m, _) = settle(1300);
        assert_eq!(m.current(), 1280);
        assert_eq!(m.ceiling(), Some(1350));
        let since = m.ceiling.unwrap().1;
        assert_eq!(m.next_probe(since + REPROBE_AFTER - Duration::from_secs(1)).0, None);

        // The path now carries 1452.
        let later = since + REPROBE_AFTER;
        let (probe, change) = m.next_probe(later);
        assert_eq!(change, Some(Change::Reprobing { size: 1350 }));
        assert_eq!(probe, Some(1350));
        assert_eq!(m.probe_acked(1350, later), Some(Change::Raised { to: 1350 }));
        assert_eq!(m.next_probe(later).0, Some(1400));
        m.probe_acked(1400, later);
        assert_eq!(m.next_probe(later).0, Some(1452));
        m.probe_acked(1452, later);
        assert_eq!(m.current(), 1452);
    }

    #[test]
    fn a_failed_reprobe_costs_no_size() {
        let (mut m, _) = settle(1300);
        let mut t = m.ceiling.unwrap().1 + REPROBE_AFTER;
        for i in 0..MAX_PROBE_LOSSES {
            let (probe, _) = m.next_probe(t);
            assert_eq!(probe, Some(1350), "try {i}");
            m.probe_lost(1350, t);
            t += RETRY_PAUSE;
        }
        assert_eq!(m.current(), 1280);
        assert_eq!(m.ceiling(), Some(1350));
    }

    /// A fixed size (the base at or above the maximum) is never probed.
    #[test]
    fn a_maximum_at_the_base_probes_nothing() {
        let t0 = Instant::now();
        let mut m = PathMtu::new(1200, 1200, t0);
        assert_eq!(m.next_probe(t0).0, None);
        // And rungs above the maximum are not tried.
        let mut m = PathMtu::new(1200, 1350, t0);
        m.next_probe(t0);
        m.probe_acked(1280, t0);
        assert_eq!(m.next_probe(t0).0, Some(1350));
        m.probe_acked(1350, t0);
        assert_eq!(m.next_probe(t0).0, None);
    }

    // ── Black hole detection ──

    fn at_1452() -> (PathMtu, Instant) {
        let (m, now) = settle(1500);
        assert_eq!(m.current(), 1452);
        (m, now)
    }

    const MS: Duration = Duration::from_millis(1);

    /// A frame of `len` bytes first sent at `now`, resent `retries` times, a
    /// second on.
    fn lost(m: &mut PathMtu, len: usize, retries: u8, sent: Instant) -> Option<Change> {
        m.black_hole(len, retries, sent, sent + Duration::from_secs(1))
    }

    #[test]
    fn frames_lost_again_and_again_while_small_ones_get_through_drop_the_size() {
        let (mut m, sent) = at_1452();
        // After the full-size frame went out, small frames (keepalives, pings)
        // were acknowledged; it was not.
        m.note_acked(60, 200, sent + 10 * MS);
        assert_eq!(lost(&mut m, 1452, 1, sent), None, "one loss is not a black hole");
        assert_eq!(lost(&mut m, 1452, 2, sent), None);
        let change = lost(&mut m, 1452, 3, sent);
        assert_eq!(change, Some(Change::BlackHole { lost: 1452, from: 1452, to: 1400 }));
        assert_eq!(m.current(), 1400);
        assert_eq!(m.ceiling(), Some(1452));
        // Frames built at the old size are still in flight and still lost: they
        // are not a new verdict.
        assert_eq!(lost(&mut m, 1452, 4, sent), None);
        assert_eq!(m.current(), 1400);
    }

    #[test]
    fn a_frame_below_a_rung_drops_to_the_largest_rung_below_it() {
        let (mut m, sent) = at_1452();
        m.note_acked(60, 200, sent + 10 * MS);
        // The padding made this frame 1290 bytes: the path carries less than that.
        assert_eq!(lost(&mut m, 1290, 3, sent), Some(Change::BlackHole { lost: 1290, from: 1452, to: 1280 }));
        assert_eq!(m.current(), 1280);
    }

    #[test]
    fn without_a_small_frame_getting_through_the_path_is_down_not_the_size() {
        let (mut m, sent) = at_1452();
        assert_eq!(lost(&mut m, 1452, 5, sent), None, "no evidence at all");
        // Only frames about as large were acknowledged since.
        m.note_acked(1440, 1452, sent + 10 * MS);
        assert_eq!(lost(&mut m, 1452, 5, sent), None);
        // Small frames got through, but before this frame was sent: that was
        // another time.
        m.note_acked(60, 200, sent - 10 * MS);
        assert_eq!(lost(&mut m, 1452, 5, sent), None);
        assert_eq!(m.current(), 1452);
    }

    #[test]
    fn a_large_frame_acknowledged_after_the_loss_began_means_the_size_passes() {
        let (mut m, sent) = at_1452();
        m.note_acked(60, 200, sent + 10 * MS);
        m.note_acked(1000, 1452, sent + 20 * MS);
        assert_eq!(lost(&mut m, 1452, 5, sent), None, "the path carried that size meanwhile");
        // A large frame acknowledged before it was sent says nothing.
        let (mut m, sent) = at_1452();
        m.note_acked(1000, 1452, sent - 20 * MS);
        m.note_acked(60, 200, sent + 10 * MS);
        assert!(lost(&mut m, 1452, 5, sent).is_some());
    }

    #[test]
    fn the_base_size_cannot_be_a_black_hole() {
        let (mut m, sent) = at_1452();
        m.note_acked(60, 100, sent + 10 * MS);
        assert_eq!(lost(&mut m, BASE, 9, sent), None);
        assert_eq!(lost(&mut m, BASE - 50, 9, sent), None);
    }

    /// After a drop the size recovers by itself: the ceiling is lifted after
    /// ten minutes and the rung above is probed again.
    #[test]
    fn after_a_black_hole_the_lost_size_is_tried_again_in_ten_minutes() {
        let (mut m, sent) = at_1452();
        m.note_acked(60, 200, sent + 10 * MS);
        let now = sent + Duration::from_secs(1);
        m.black_hole(1452, 3, sent, now).unwrap();
        assert_eq!(m.next_probe(now + Duration::from_secs(60)).0, None);
        let (probe, change) = m.next_probe(now + REPROBE_AFTER);
        assert_eq!(change, Some(Change::Reprobing { size: 1452 }));
        assert_eq!(probe, Some(1452));
    }

    #[test]
    fn the_evidence_is_bounded() {
        let t0 = Instant::now();
        let mut m = PathMtu::new(BASE, MAX, t0);
        for i in 0..10_000u64 {
            m.note_acked(60, 1300, at(t0, i as f64 * 0.001));
        }
        assert_eq!(m.acks.len(), EVIDENCE_KEPT);
    }
}
