//! Per-IP admission limit for new TCP (UoT/TLS/upgrade) connections.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const WINDOW: Duration = Duration::from_secs(10);
const MAX_CONNS: u32 = 10;
/// How often stale windows are swept, so a scan from many addresses cannot
/// grow the map without bound.
const PRUNE_EVERY: Duration = Duration::from_secs(60);

pub struct ConnLimiter {
    inner: Mutex<Inner>,
}

struct Inner {
    windows: HashMap<IpAddr, (u32, Instant)>,
    last_prune: Instant,
}

impl Default for ConnLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnLimiter {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner { windows: HashMap::new(), last_prune: Instant::now() }),
        }
    }

    /// Counts one connection attempt from `ip`; false once it exceeds the window budget.
    pub fn check(&self, ip: IpAddr) -> bool {
        self.check_at(ip.to_canonical(), Instant::now())
    }

    fn check_at(&self, ip: IpAddr, now: Instant) -> bool {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if now.duration_since(inner.last_prune) >= PRUNE_EVERY {
            inner.windows.retain(|_, (_, start)| now.duration_since(*start) < WINDOW);
            inner.last_prune = now;
        }
        let entry = inner.windows.entry(ip).or_insert((0, now));
        if now.duration_since(entry.1) >= WINDOW {
            *entry = (1, now);
            true
        } else {
            entry.0 += 1;
            entry.0 <= MAX_CONNS
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.lock().unwrap().windows.len()
    }
}

/// Connections from loopback come from a local web server (nginx/apache/caddy)
/// fronting OSTP; their per-client limit is applied to the forwarded address instead.
pub fn is_trusted_proxy(peer: SocketAddr) -> bool {
    peer.ip().to_canonical().is_loopback()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn blocks_after_budget_and_resets_after_window() {
        let l = ConnLimiter::new();
        let t0 = Instant::now();
        for _ in 0..MAX_CONNS {
            assert!(l.check_at(ip("203.0.113.1"), t0));
        }
        assert!(!l.check_at(ip("203.0.113.1"), t0));
        assert!(l.check_at(ip("203.0.113.2"), t0), "other clients are unaffected");
        assert!(l.check_at(ip("203.0.113.1"), t0 + WINDOW));
    }

    #[test]
    fn stale_windows_are_pruned() {
        let l = ConnLimiter::new();
        let t0 = Instant::now();
        for i in 0..100u8 {
            l.check_at(IpAddr::from([198, 51, 100, i]), t0);
        }
        assert_eq!(l.len(), 100);
        l.check_at(ip("192.0.2.1"), t0 + PRUNE_EVERY);
        assert_eq!(l.len(), 1);
    }

    #[test]
    fn mapped_v4_and_v4_share_a_window() {
        let l = ConnLimiter::new();
        for _ in 0..MAX_CONNS {
            assert!(l.check(ip("203.0.113.9")));
        }
        assert!(!l.check(ip("::ffff:203.0.113.9")));
    }

    #[test]
    fn loopback_is_trusted_proxy() {
        assert!(is_trusted_proxy("127.0.0.1:1".parse().unwrap()));
        assert!(is_trusted_proxy("[::1]:1".parse().unwrap()));
        assert!(is_trusted_proxy("[::ffff:127.0.0.1]:1".parse().unwrap()));
        assert!(!is_trusted_proxy("203.0.113.1:1".parse().unwrap()));
    }
}
