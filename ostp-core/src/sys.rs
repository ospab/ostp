//! Platform services the protocol needs: a monotonic clock, a wall clock and
//! entropy.
//!
//! With the `std` feature these come from the operating system (`std::time`,
//! `rand`). Without it (`no_std + alloc`, e.g. inside a kernel) the embedder
//! calls [`install`] once, before creating any `ProtocolMachine`, and hands over
//! three plain functions. Nothing here ever falls back to a weak source: an
//! uninstalled entropy hook panics instead of returning predictable bytes.

#[cfg(feature = "std")]
pub use std::time::Instant;

#[cfg(feature = "std")]
mod imp {
    use rand::Rng;

    pub fn fill_random(buf: &mut [u8]) {
        rand::thread_rng().fill(buf);
    }

    pub fn unix_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

#[cfg(not(feature = "std"))]
mod imp {
    use core::sync::atomic::{AtomicUsize, Ordering};

    static MONOTONIC_NS: AtomicUsize = AtomicUsize::new(0);
    static UNIX_SECS: AtomicUsize = AtomicUsize::new(0);
    static FILL_RANDOM: AtomicUsize = AtomicUsize::new(0);

    /// The three functions a `no_std` embedder provides.
    #[derive(Clone, Copy)]
    pub struct Hooks {
        /// Monotonic nanoseconds since an arbitrary epoch (e.g. boot).
        pub monotonic_ns: fn() -> u64,
        /// Seconds since the Unix epoch; 0 if the wall clock is not set. Only
        /// used to rotate the junk marker, so a wrong clock costs junk filtering,
        /// not security.
        pub unix_secs: fn() -> u64,
        /// Cryptographically secure random bytes (e.g. RDRAND/RDSEED).
        pub fill_random: fn(&mut [u8]),
    }

    /// Install the platform hooks. Call once, before any other use of the crate.
    pub fn install(h: Hooks) {
        MONOTONIC_NS.store(h.monotonic_ns as usize, Ordering::Release);
        UNIX_SECS.store(h.unix_secs as usize, Ordering::Release);
        FILL_RANDOM.store(h.fill_random as usize, Ordering::Release);
    }

    pub(super) fn monotonic_ns() -> u64 {
        let p = MONOTONIC_NS.load(Ordering::Acquire);
        if p == 0 {
            return 0;
        }
        // SAFETY: only `install` writes this, and always with a valid `fn() -> u64`.
        let f: fn() -> u64 = unsafe { core::mem::transmute(p) };
        f()
    }

    pub fn unix_secs() -> u64 {
        let p = UNIX_SECS.load(Ordering::Acquire);
        if p == 0 {
            return 0;
        }
        // SAFETY: as above.
        let f: fn() -> u64 = unsafe { core::mem::transmute(p) };
        f()
    }

    pub fn fill_random(buf: &mut [u8]) {
        let p = FILL_RANDOM.load(Ordering::Acquire);
        assert!(p != 0, "ostp-core: sys::install was not called (no entropy source)");
        // SAFETY: as above.
        let f: fn(&mut [u8]) = unsafe { core::mem::transmute(p) };
        f(buf)
    }
}

#[cfg(not(feature = "std"))]
pub use imp::{install, Hooks};
pub use imp::{fill_random, unix_secs};

/// Monotonic instant for `no_std` builds, mirroring the parts of
/// `std::time::Instant` the protocol uses. Subtraction saturates at the clock's
/// zero instead of panicking.
#[cfg(not(feature = "std"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant(u64);

#[cfg(not(feature = "std"))]
mod instant_impl {
    use super::{imp, Instant};
    use core::ops::{Add, AddAssign, Sub};
    use core::time::Duration;

    fn dur_ns(d: Duration) -> u64 {
        u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
    }

    impl Instant {
        pub fn now() -> Self {
            Instant(imp::monotonic_ns())
        }
        pub fn duration_since(&self, earlier: Instant) -> Duration {
            Duration::from_nanos(self.0.saturating_sub(earlier.0))
        }
        pub fn saturating_duration_since(&self, earlier: Instant) -> Duration {
            self.duration_since(earlier)
        }
        pub fn checked_duration_since(&self, earlier: Instant) -> Option<Duration> {
            self.0.checked_sub(earlier.0).map(Duration::from_nanos)
        }
        pub fn elapsed(&self) -> Duration {
            Instant::now().duration_since(*self)
        }
        pub fn checked_add(&self, d: Duration) -> Option<Instant> {
            self.0.checked_add(dur_ns(d)).map(Instant)
        }
        pub fn checked_sub(&self, d: Duration) -> Option<Instant> {
            self.0.checked_sub(dur_ns(d)).map(Instant)
        }
    }

    impl Add<Duration> for Instant {
        type Output = Instant;
        fn add(self, d: Duration) -> Instant {
            Instant(self.0.saturating_add(dur_ns(d)))
        }
    }
    impl AddAssign<Duration> for Instant {
        fn add_assign(&mut self, d: Duration) {
            *self = *self + d;
        }
    }
    impl Sub<Duration> for Instant {
        type Output = Instant;
        fn sub(self, d: Duration) -> Instant {
            Instant(self.0.saturating_sub(dur_ns(d)))
        }
    }
    impl Sub<Instant> for Instant {
        type Output = Duration;
        fn sub(self, other: Instant) -> Duration {
            self.duration_since(other)
        }
    }
}

/// A uniformly random `u16`.
pub fn random_u16() -> u16 {
    let mut b = [0u8; 2];
    fill_random(&mut b);
    u16::from_le_bytes(b)
}

/// A random integer in `lo..=hi` (`lo <= hi`). Used for padding sizes only, so
/// the negligible modulo bias is irrelevant.
pub fn random_range_inclusive(lo: usize, hi: usize) -> usize {
    debug_assert!(lo <= hi);
    let span = (hi - lo) as u64 + 1;
    let mut b = [0u8; 8];
    fill_random(&mut b);
    lo + (u64::from_le_bytes(b) % span) as usize
}
