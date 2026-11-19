//! The queue toward a client on TCP or TLS, kept short in time.
//!
//! On a byte stream OSTP sees no loss, and the delay signal is off there (see
//! `CongestionController::set_delay_signal`), so nothing in the congestion
//! controller stops the server from queueing more than the connection drains.
//! The send queue of such a client used to take up to ~15,000 frames (20 MB):
//! at a few Mbit/s that is tens of seconds, and everything behind it (the
//! in-tunnel ping the apps show as RTT, the next second of a video) waited
//! that long. A 50 s "RTT" on TLS was this queue, not the path.
//!
//! Now each connection's writer measures how fast it really drains while it
//! has a backlog, and the readers may fill the queue only to about
//! `TARGET_DELAY` of that rate. On Linux the socket also keeps little unsent
//! data in the kernel (`TCP_NOTSENT_LOWAT`), so the measured rate is the
//! path's, not the speed of filling a kernel buffer.

use portable_atomic::AtomicU64;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, LazyLock, RwLock};
use std::time::{Duration, Instant};

/// How much queue a TCP/TLS client may have, in time at its drain rate.
pub const TARGET_DELAY: Duration = Duration::from_millis(100);
/// Frames allowed whatever the rate: a slow link still moves, and a short
/// queue never starves the writer between two refills.
pub const MIN_FRAMES: usize = 64;
/// Until the first measurement (about 1 MB): enough for a fast start.
pub const START_FRAMES: usize = 768;
/// Bytes of a typical full frame, to turn a rate into frames.
const FRAME_BYTES: u64 = 1350;
/// A rate sample covers at least this much backlogged time.
const SAMPLE_WINDOW: Duration = Duration::from_millis(100);
/// Unsent bytes the kernel keeps for a TCP client (Linux).
pub const NOTSENT_LOWAT: u32 = 128 * 1024;

/// One connection's measured drain rate, in bytes per second (0: not yet known).
#[derive(Default)]
pub struct Drain {
    rate: AtomicU64,
}

impl Drain {
    pub fn rate(&self) -> u64 {
        self.rate.load(Ordering::Relaxed)
    }

    /// A new sample, smoothed (1/8 weight, as SRTT): one burst does not move it far.
    pub fn sample(&self, bytes: u64, over: Duration) {
        let secs = over.as_secs_f64();
        if secs <= 0.0 {
            return;
        }
        let s = (bytes as f64 / secs) as u64;
        let old = self.rate();
        let new = if old == 0 { s } else { old - old / 8 + s / 8 };
        self.rate.store(new.max(1), Ordering::Relaxed);
    }

    /// Frames the queue may hold.
    pub fn target_frames(&self) -> usize {
        match self.rate() {
            0 => START_FRAMES,
            r => ((r as f64 * TARGET_DELAY.as_secs_f64()) as u64 / FRAME_BYTES).max(MIN_FRAMES as u64) as usize,
        }
    }
}

/// Measures a writer's drain rate: only time when frames were waiting counts,
/// since an idle connection says nothing about how fast it could go.
pub struct Meter {
    drain: Arc<Drain>,
    since: Option<Instant>,
    bytes: u64,
}

impl Meter {
    pub fn new(drain: Arc<Drain>) -> Self {
        Self { drain, since: None, bytes: 0 }
    }

    /// `bytes` were just written; `backlog` frames still wait.
    pub fn written(&mut self, bytes: usize, backlog: usize, now: Instant) {
        if backlog == 0 {
            self.since = None;
            self.bytes = 0;
            return;
        }
        let since = *self.since.get_or_insert(now);
        self.bytes += bytes as u64;
        let over = now.saturating_duration_since(since);
        if over >= SAMPLE_WINDOW {
            self.drain.sample(self.bytes, over);
            self.since = Some(now);
            self.bytes = 0;
        }
    }
}

static DRAINS: LazyLock<RwLock<HashMap<SocketAddr, Arc<Drain>>>> = LazyLock::new(Default::default);

/// A new TCP/TLS client: its drain starts unknown.
pub fn register(addr: SocketAddr) -> Arc<Drain> {
    let d = Arc::new(Drain::default());
    DRAINS.write().unwrap_or_else(|e| e.into_inner()).insert(addr, d.clone());
    d
}

/// The connection ended; a newer connection from the same address keeps its own entry.
pub fn unregister(addr: SocketAddr, mine: &Arc<Drain>) {
    let mut map = DRAINS.write().unwrap_or_else(|e| e.into_inner());
    if map.get(&addr).is_some_and(|d| Arc::ptr_eq(d, mine)) {
        map.remove(&addr);
    }
}

/// Frames the queue toward `addr` may hold now.
pub fn target_frames(addr: SocketAddr) -> usize {
    DRAINS
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get(&addr)
        .map_or(START_FRAMES, |d| d.target_frames())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_queue_holds_about_a_tenth_of_a_second() {
        let d = Drain::default();
        assert_eq!(d.target_frames(), START_FRAMES, "unknown rate: the start allowance");
        // 2 Mbit/s = 250,000 B/s: 100 ms is 25,000 B, under the floor of 64 frames.
        d.sample(250_000, Duration::from_secs(1));
        assert_eq!(d.target_frames(), MIN_FRAMES);
        // 100 Mbit/s: 100 ms is 1.25 MB, about 925 frames.
        let fast = Drain::default();
        fast.sample(12_500_000, Duration::from_secs(1));
        assert_eq!(fast.target_frames(), 925);
    }

    #[test]
    fn only_backlogged_time_is_measured() {
        let d = Arc::new(Drain::default());
        let mut m = Meter::new(d.clone());
        let t0 = Instant::now();
        // Idle writes (nothing waiting) never make a sample.
        m.written(1350, 0, t0);
        m.written(1350, 0, t0 + Duration::from_secs(1));
        assert_eq!(d.rate(), 0);
        // Backlogged for 200 ms, 100 frames written: 135,000 B in 0.2 s.
        for i in 0..=100u64 {
            m.written(1350, 5, t0 + Duration::from_millis(1000 + 2 * i));
        }
        let r = d.rate();
        assert!((600_000..=700_000).contains(&r), "{r}");
    }

    #[test]
    fn a_newer_connection_keeps_its_entry() {
        let a: SocketAddr = "198.51.100.1:5000".parse().unwrap();
        let old = register(a);
        let new = register(a);
        new.sample(12_500_000, Duration::from_secs(1));
        unregister(a, &old);
        assert_eq!(target_frames(a), 925);
        unregister(a, &new);
        assert_eq!(target_frames(a), START_FRAMES);
    }
}
