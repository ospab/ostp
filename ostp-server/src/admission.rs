//! Rate limits for the expensive work unknown datagrams trigger: trying
//! every access key on a would-be handshake, and scanning sessions for a
//! roamed one.
//!
//! One server-wide bucket alone let ~100 garbage datagrams a second from
//! anywhere use up the whole budget, so nobody new could connect. Now each
//! source (an IPv4 address, an IPv6 /64) has its own small bucket, and
//! sources that completed a handshake recently skip the server-wide one: a
//! flood, spoofed or not, no longer keeps returning users out. The
//! server-wide bucket stays for everyone else, because it is what bounds the
//! CPU a flood can cost (each key trial is an X25519 operation).

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Beyond this many tracked sources, new ones get only the server-wide
/// bucket, so a flood from millions of spoofed addresses cannot grow the map.
const MAX_SOURCES: usize = 100_000;
const MAX_KNOWN: usize = 65_536;
/// How long a source that authenticated stays trusted.
const KNOWN_FOR: Duration = Duration::from_secs(24 * 3600);
const PRUNE_EVERY: Duration = Duration::from_secs(60);

#[derive(Clone, Copy)]
struct Bucket {
    tokens: f64,
    at: Instant,
}

impl Bucket {
    fn full(burst: f64, now: Instant) -> Self {
        Self { tokens: burst, at: now }
    }

    fn refill(&mut self, rate: f64, burst: f64, now: Instant) {
        self.tokens = (self.tokens + now.duration_since(self.at).as_secs_f64() * rate).min(burst);
        self.at = now;
    }
}

pub struct Admission {
    rate: f64,
    burst: f64,
    global_rate: f64,
    global: Bucket,
    sources: HashMap<IpAddr, Bucket>,
    known: HashMap<IpAddr, Instant>,
    last_prune: Instant,
}

/// The unit a source is counted in: an IPv4 address, or an IPv6 /64 (one
/// subscriber usually holds a whole /64 and can pick any address in it).
fn source(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let s = v6.segments();
                IpAddr::V6(std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
            }
        },
        v4 => v4,
    }
}

impl Admission {
    /// `rate`/`burst` per source, `global_rate` (also its burst) for all
    /// sources not known to have authenticated.
    pub fn new(rate: f64, burst: f64, global_rate: f64) -> Self {
        let now = Instant::now();
        Self {
            rate,
            burst,
            global_rate,
            global: Bucket::full(global_rate, now),
            sources: HashMap::new(),
            known: HashMap::new(),
            last_prune: now,
        }
    }

    fn prune(&mut self, now: Instant) {
        if now.duration_since(self.last_prune) < PRUNE_EVERY {
            return;
        }
        self.last_prune = now;
        let (rate, burst) = (self.rate, self.burst);
        // A bucket that has refilled to full carries no state worth keeping.
        self.sources.retain(|_, b| {
            b.refill(rate, burst, now);
            b.tokens < burst
        });
        self.known.retain(|_, at| now.duration_since(*at) < KNOWN_FOR);
    }

    /// Whether to do the work for a datagram from `ip`; spends a token if so.
    pub fn admit(&mut self, ip: IpAddr) -> bool {
        self.admit_at(ip, Instant::now())
    }

    fn admit_at(&mut self, ip: IpAddr, now: Instant) -> bool {
        self.prune(now);
        let src = source(ip);
        let (rate, burst) = (self.rate, self.burst);
        let tracked = self.sources.len() < MAX_SOURCES || self.sources.contains_key(&src);
        if tracked {
            let b = self.sources.entry(src).or_insert_with(|| Bucket::full(burst, now));
            b.refill(rate, burst, now);
            if b.tokens < 1.0 {
                return false;
            }
        }
        if !self.known.contains_key(&src) {
            self.global.refill(self.global_rate, self.global_rate, now);
            if self.global.tokens < 1.0 {
                return false;
            }
            self.global.tokens -= 1.0;
        }
        if tracked {
            if let Some(b) = self.sources.get_mut(&src) {
                b.tokens -= 1.0;
            }
        }
        true
    }

    /// `ip` completed a handshake: it skips the server-wide bucket for a day.
    pub fn mark_known(&mut self, ip: IpAddr) {
        let src = source(ip);
        if self.known.len() < MAX_KNOWN || self.known.contains_key(&src) {
            self.known.insert(src, Instant::now());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn a_flood_from_elsewhere_does_not_lock_out_a_known_source() {
        let mut a = Admission::new(10.0, 20.0, 100.0);
        let now = Instant::now();
        a.mark_known(ip("198.51.100.7"));
        // Spoofed flood from many sources drains the server-wide bucket.
        let admitted = (0..10_000u32)
            .filter(|i| a.admit_at(IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + i)), now))
            .count();
        assert_eq!(admitted, 100, "the server-wide bucket bounds the work");
        assert!(!a.admit_at(ip("203.0.113.9"), now), "an unknown source waits for the bucket");
        assert!(a.admit_at(ip("198.51.100.7"), now), "a returning user gets in");
    }

    #[test]
    fn one_source_cannot_take_the_whole_budget() {
        let mut a = Admission::new(10.0, 20.0, 100.0);
        let now = Instant::now();
        let from_one = (0..1000).filter(|_| a.admit_at(ip("203.0.113.9"), now)).count();
        assert_eq!(from_one, 20);
        assert!(a.admit_at(ip("198.51.100.1"), now), "others still get in");
    }

    #[test]
    fn an_ipv6_slash64_is_one_source() {
        let mut a = Admission::new(10.0, 2.0, 100.0);
        let now = Instant::now();
        assert!(a.admit_at(ip("2001:db8::1"), now));
        assert!(a.admit_at(ip("2001:db8::2"), now));
        assert!(!a.admit_at(ip("2001:db8::3"), now));
        assert!(a.admit_at(ip("2001:db8:0:1::1"), now));
    }
}
