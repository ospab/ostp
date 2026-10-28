//! Per-IP admission limit for new TCP (UoT/TLS/upgrade) connections.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const WINDOW: Duration = Duration::from_secs(10);
/// Generous on purpose: one client opens several sessions at once (mux, plus
/// a NAT64 retry each), and mobile carriers put many subscribers behind one
/// CGNAT address. This only stops floods.
const MAX_CONNS: u32 = 60;
/// How often stale windows are swept, so a scan from many addresses cannot
/// grow the map without bound.
const PRUNE_EVERY: Duration = Duration::from_secs(60);
/// Sources tracked at once. A client holds a whole IPv6 /64 and can pick any
/// address in it, so between sweeps the map could otherwise grow with the
/// connection rate. Past the cap an unknown source is admitted untracked: the
/// pending-connection limit still bounds what that costs.
const MAX_TRACKED: usize = 100_000;

/// The unit a source is counted in: an IPv4 address, or an IPv6 /64 (one
/// subscriber holds a whole /64 and can pick any address in it).
fn source(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let s = v6.segments();
            IpAddr::V6(std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
        v4 => v4,
    }
}

pub struct ConnLimiter {
    inner: Mutex<Inner>,
    unauth: Arc<UnauthSlots>,
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
            unauth: Arc::new(UnauthSlots::default()),
        }
    }

    /// A slot for a UoT connection from `ip` that has not authenticated yet;
    /// `None` when that source already holds the maximum.
    pub fn acquire_unauth(&self, ip: IpAddr) -> Option<UnauthGuard> {
        self.unauth.try_acquire(ip)
    }

    /// Counts one connection attempt from `ip`; false once it exceeds the window budget.
    pub fn check(&self, ip: IpAddr) -> bool {
        self.check_at(ip.to_canonical(), Instant::now())
    }

    fn check_at(&self, ip: IpAddr, now: Instant) -> bool {
        let ip = source(ip);
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if now.duration_since(inner.last_prune) >= PRUNE_EVERY {
            inner.windows.retain(|_, (_, start)| now.duration_since(*start) < WINDOW);
            inner.last_prune = now;
        }
        if inner.windows.len() >= MAX_TRACKED && !inner.windows.contains_key(&ip) {
            return true;
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

/// Connections per source that have been classified as UoT but have not shown
/// a valid handshake yet. A real client's handshake is answered within a round
/// trip, so a source holding this many is probing or hoarding descriptors. It
/// matches `MAX_CONNS` in spirit: above one client's own parallel sessions,
/// below what makes a single address a threat.
pub const MAX_UNAUTHENTICATED_PER_SOURCE: u32 = 64;

/// Counts not-yet-authenticated connections per source; a slot is held by the
/// guard until the connection authenticates or ends.
#[derive(Default)]
pub struct UnauthSlots {
    held: Mutex<HashMap<IpAddr, u32>>,
}

pub struct UnauthGuard {
    slots: Arc<UnauthSlots>,
    ip: IpAddr,
}

impl UnauthSlots {
    pub fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<UnauthGuard> {
        self.try_acquire_max(ip, MAX_UNAUTHENTICATED_PER_SOURCE)
    }

    fn try_acquire_max(self: &Arc<Self>, ip: IpAddr, max: u32) -> Option<UnauthGuard> {
        let ip = source(ip);
        let mut held = self.held.lock().unwrap_or_else(|e| e.into_inner());
        let n = held.entry(ip).or_insert(0);
        if *n >= max {
            return None;
        }
        *n += 1;
        Some(UnauthGuard { slots: self.clone(), ip })
    }
}

impl Drop for UnauthGuard {
    fn drop(&mut self) {
        let mut held = self.slots.held.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = held.get_mut(&self.ip) {
            *n -= 1;
            if *n == 0 {
                held.remove(&self.ip);
            }
        }
    }
}

/// Lookups of secrets (subscription tokens, access keys) that found nothing,
/// per source. Once a source has used its budget in a window its further
/// lookups are refused without being tried; correct ones never count.
pub struct FailureLimiter {
    window: Duration,
    max: u32,
    inner: Mutex<Inner>,
}

impl FailureLimiter {
    pub fn new(window: Duration, max: u32) -> Self {
        Self { window, max, inner: Mutex::new(Inner { windows: HashMap::new(), last_prune: Instant::now() }) }
    }

    /// False while `ip` has used up its failures for the current window.
    pub fn allowed(&self, ip: IpAddr) -> bool {
        self.allowed_at(ip, Instant::now())
    }

    pub fn record_failure(&self, ip: IpAddr) {
        self.record_failure_at(ip, Instant::now());
    }

    fn allowed_at(&self, ip: IpAddr, now: Instant) -> bool {
        let ip = source(ip);
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        match inner.windows.get(&ip) {
            Some((n, start)) if now.duration_since(*start) < self.window => *n < self.max,
            _ => true,
        }
    }

    fn record_failure_at(&self, ip: IpAddr, now: Instant) {
        let ip = source(ip);
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if now.duration_since(inner.last_prune) >= PRUNE_EVERY {
            let window = self.window;
            inner.windows.retain(|_, (_, start)| now.duration_since(*start) < window);
            inner.last_prune = now;
        }
        if inner.windows.len() >= MAX_TRACKED && !inner.windows.contains_key(&ip) {
            return;
        }
        let entry = inner.windows.entry(ip).or_insert((0, now));
        if now.duration_since(entry.1) >= self.window {
            *entry = (1, now);
        } else {
            entry.0 = entry.0.saturating_add(1);
        }
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
    fn an_ipv6_slash64_shares_one_window() {
        let l = ConnLimiter::new();
        let t0 = Instant::now();
        for i in 0..MAX_CONNS {
            assert!(l.check_at(ip(&format!("2001:db8:1:2::{:x}", i + 1)), t0));
        }
        assert!(!l.check_at(ip("2001:db8:1:2::ffff"), t0), "another address of the same /64 is the same source");
        assert!(l.check_at(ip("2001:db8:1:3::1"), t0), "a different /64 is not");
    }

    #[test]
    fn unauthenticated_slots_are_per_source_and_released_on_drop() {
        let slots = Arc::new(UnauthSlots::default());
        let a = ip("203.0.113.1");
        let held: Vec<_> = (0..3).map(|_| slots.try_acquire_max(a, 3).unwrap()).collect();
        assert!(slots.try_acquire_max(a, 3).is_none(), "the fourth is refused");
        assert!(slots.try_acquire_max(ip("203.0.113.2"), 3).is_some(), "another source is not");
        drop(held);
        let again = slots.try_acquire_max(a, 3);
        assert!(again.is_some(), "slots come back");
        // The other source's guard was dropped at once, so only `a` is left.
        assert_eq!(slots.held.lock().unwrap().len(), 1, "empty entries are removed");
    }

    #[test]
    fn unauthenticated_slots_count_an_ipv6_slash64_as_one_source() {
        let slots = Arc::new(UnauthSlots::default());
        let _a = slots.try_acquire_max(ip("2001:db8:1:2::1"), 1).unwrap();
        assert!(slots.try_acquire_max(ip("2001:db8:1:2::2"), 1).is_none());
        assert!(slots.try_acquire_max(ip("2001:db8:1:3::1"), 1).is_some());
    }

    #[test]
    fn failures_block_a_source_until_the_window_ends() {
        let l = FailureLimiter::new(Duration::from_secs(60), 3);
        let t0 = Instant::now();
        let a = ip("203.0.113.1");
        for _ in 0..3 {
            assert!(l.allowed_at(a, t0));
            l.record_failure_at(a, t0);
        }
        assert!(!l.allowed_at(a, t0));
        assert!(l.allowed_at(ip("203.0.113.2"), t0), "others are unaffected");
        assert!(l.allowed_at(a, t0 + Duration::from_secs(60)));
    }

    #[test]
    fn loopback_is_trusted_proxy() {
        assert!(is_trusted_proxy("127.0.0.1:1".parse().unwrap()));
        assert!(is_trusted_proxy("[::1]:1".parse().unwrap()));
        assert!(is_trusted_proxy("[::ffff:127.0.0.1]:1".parse().unwrap()));
        assert!(!is_trusted_proxy("203.0.113.1:1".parse().unwrap()));
    }
}
