//! Log privacy: one place that decides what a log line may say about
//! destinations and client addresses.
//!
//! Three modes, one per process (`log.privacy` in the config):
//!
//! - `normal` (default): no destinations (hosts and ports of sites, SNI and DNS
//!   names, relay targets) in any log; client addresses cut to /24 (IPv4) or
//!   /48 (IPv6).
//! - `strict`: like `normal`, and a client address becomes a tag, an HMAC keyed
//!   by a random salt that changes every UTC day and lives only in memory: the
//!   same client has the same tag for the day, and nothing links two days.
//! - `debug`: everything, as the old `debug` setting did. Only on request.
//!
//! Code that logs a destination or a client address goes through
//! [`fmt_target`], [`fmt_peer`] and [`fmt_ip`]; code that logs an error text
//! that may embed a destination goes through [`fmt_error`].

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::borrow::Cow;
use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Mutex;

/// How much a log may say. See the module documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Privacy {
    Strict,
    #[default]
    Normal,
    Debug,
}

impl Privacy {
    pub fn as_str(self) -> &'static str {
        match self {
            Privacy::Strict => "strict",
            Privacy::Normal => "normal",
            Privacy::Debug => "debug",
        }
    }

    pub fn parse(s: &str) -> Option<Privacy> {
        match s.trim().to_ascii_lowercase().as_str() {
            "strict" => Some(Privacy::Strict),
            "normal" => Some(Privacy::Normal),
            "debug" => Some(Privacy::Debug),
            _ => None,
        }
    }

    /// The mode a config asks for: an explicit `log.privacy` wins; without it
    /// the old `debug: true` still means `debug`.
    pub fn resolve(explicit: Option<Privacy>, legacy_debug: bool) -> Privacy {
        explicit.unwrap_or(if legacy_debug { Privacy::Debug } else { Privacy::Normal })
    }
}

static MODE: AtomicU8 = AtomicU8::new(1);

/// Sets the mode of this process. Called at start and when a config reload
/// changes it.
pub fn set_privacy(p: Privacy) {
    MODE.store(p as u8, Ordering::Relaxed);
}

/// The mode of this process; `normal` until [`set_privacy`] is called.
pub fn privacy() -> Privacy {
    match MODE.load(Ordering::Relaxed) {
        0 => Privacy::Strict,
        2 => Privacy::Debug,
        _ => Privacy::Normal,
    }
}

/// True in `debug`: the lines that carry destinations and full addresses.
pub fn is_debug() -> bool {
    privacy() == Privacy::Debug
}

/// A destination (`host:port`, a name, an SNI) for a log line: in full in
/// `debug`, `<hidden>` otherwise.
pub fn fmt_target(target: impl Display) -> Cow<'static, str> {
    fmt_target_in(privacy(), target)
}

fn fmt_target_in(mode: Privacy, target: impl Display) -> Cow<'static, str> {
    if mode == Privacy::Debug {
        Cow::Owned(target.to_string())
    } else {
        Cow::Borrowed("<hidden>")
    }
}

/// A client's address and port for a log line. `debug`: as is. `normal`: the
/// /24 (IPv6: /48) network, no port. `strict`: the day's tag, no port.
pub fn fmt_peer(addr: SocketAddr) -> String {
    match privacy() {
        Privacy::Debug => addr.to_string(),
        _ => fmt_ip(addr.ip()),
    }
}

/// [`fmt_peer`] for an address without a port.
pub fn fmt_ip(ip: IpAddr) -> String {
    fmt_ip_in(privacy(), ip, &today_salt())
}

fn fmt_ip_in(mode: Privacy, ip: IpAddr, salt: &[u8; 32]) -> String {
    match mode {
        Privacy::Debug => ip.to_string(),
        Privacy::Normal => truncate_ip(ip),
        Privacy::Strict => tag_ip(salt, ip),
    }
}

/// `203.0.113.77` -> `203.0.113.0/24`; an IPv6 address keeps its first 48 bits
/// (`2001:db8:1::/48`). An IPv4-mapped IPv6 address counts as IPv4.
pub fn truncate_ip(ip: IpAddr) -> String {
    match unmap(ip) {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}/24", Ipv4Addr::new(o[0], o[1], o[2], 0))
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("{}/48", Ipv6Addr::new(s[0], s[1], s[2], 0, 0, 0, 0, 0))
        }
    }
}

fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

/// `peer-` and eight hex digits of HMAC-SHA256(salt, address).
pub fn tag_ip(salt: &[u8; 32], ip: IpAddr) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(salt).expect("HMAC takes any key length");
    match unmap(ip) {
        IpAddr::V4(v4) => mac.update(&v4.octets()),
        IpAddr::V6(v6) => mac.update(&v6.octets()),
    }
    let out = mac.finalize().into_bytes();
    format!("peer-{:02x}{:02x}{:02x}{:02x}", out[0], out[1], out[2], out[3])
}

/// The salt of the current UTC day: made at random the first time it is asked
/// for on a day, never written anywhere, gone with the process.
struct DailySalt {
    day: u64,
    salt: [u8; 32],
}

static SALT: Mutex<Option<DailySalt>> = Mutex::new(None);

fn today_salt() -> [u8; 32] {
    let day = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / 86_400)
        .unwrap_or(0);
    salt_for_day(day)
}

fn salt_for_day(day: u64) -> [u8; 32] {
    let mut guard = SALT.lock().unwrap_or_else(|e| e.into_inner());
    match guard.as_ref() {
        Some(s) if s.day == day => s.salt,
        _ => {
            let mut salt = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);
            *guard = Some(DailySalt { day, salt });
            salt
        }
    }
}

/// An error text for a log line. The texts of connect and resolve errors can
/// embed the name or the address that was reached for (and the resolver's
/// answer), so outside `debug` only the kind of the error is written.
pub fn fmt_error(text: &str) -> Cow<'_, str> {
    if is_debug() {
        Cow::Borrowed(text)
    } else {
        Cow::Borrowed(error_kind(text))
    }
}

/// What went wrong, without the details of where.
pub fn error_kind(text: &str) -> &'static str {
    let t = text.to_ascii_lowercase();
    let has = |words: &[&str]| words.iter().any(|w| t.contains(w));
    if has(&["closed to clients", "blocked", "refuses", "not allowed"]) {
        "blocked by policy"
    } else if has(&["too many open"]) {
        "too many connections"
    } else if has(&["timed out", "timeout"]) {
        "timed out"
    } else if has(&["refused"]) {
        "connection refused"
    } else if has(&["unreachable"]) {
        "network unreachable"
    } else if has(&["reset", "broken pipe", "aborted"]) {
        "connection reset"
    } else if has(&["no addresses", "lookup", "resolv", "dns", "name or service", "no record", "nxdomain"]) {
        "name not resolved"
    } else {
        "failed"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_is_cut_to_a_24() {
        assert_eq!(truncate_ip("203.0.113.77".parse().unwrap()), "203.0.113.0/24");
        assert_eq!(truncate_ip("::ffff:198.51.100.9".parse().unwrap()), "198.51.100.0/24");
    }

    #[test]
    fn ipv6_is_cut_to_a_48() {
        assert_eq!(truncate_ip("2001:db8:1:2:3:4:5:6".parse().unwrap()), "2001:db8:1::/48");
    }

    #[test]
    fn same_day_same_tag_other_salt_other_tag() {
        let ip: IpAddr = "203.0.113.77".parse().unwrap();
        let (a, b) = ([1u8; 32], [2u8; 32]);
        assert_eq!(tag_ip(&a, ip), tag_ip(&a, ip));
        assert_ne!(tag_ip(&a, ip), tag_ip(&b, ip));
        assert_ne!(tag_ip(&a, ip), tag_ip(&a, "203.0.113.78".parse().unwrap()));
        assert!(!tag_ip(&a, ip).contains("203"));
    }

    #[test]
    fn the_salt_holds_for_a_day_and_changes_with_the_next() {
        let d1 = salt_for_day(20_000);
        assert_eq!(d1, salt_for_day(20_000));
        let d2 = salt_for_day(20_001);
        assert_ne!(d1, d2);
        // Yesterday's salt is not kept: going back does not bring it back.
        assert_ne!(d1, salt_for_day(20_000));
    }

    #[test]
    fn modes_format_addresses_and_targets() {
        let ip: IpAddr = "203.0.113.77".parse().unwrap();
        let salt = [7u8; 32];
        assert_eq!(fmt_ip_in(Privacy::Debug, ip, &salt), "203.0.113.77");
        assert_eq!(fmt_ip_in(Privacy::Normal, ip, &salt), "203.0.113.0/24");
        assert!(fmt_ip_in(Privacy::Strict, ip, &salt).starts_with("peer-"));
        assert_eq!(fmt_target_in(Privacy::Debug, "example.com:443"), "example.com:443");
        assert_eq!(fmt_target_in(Privacy::Normal, "example.com:443"), "<hidden>");
        assert_eq!(fmt_target_in(Privacy::Strict, "example.com:443"), "<hidden>");
    }

    #[test]
    fn an_error_keeps_its_kind_and_loses_the_destination() {
        assert_eq!(error_kind("example.com:443: no addresses for example.com:443"), "name not resolved");
        assert_eq!(error_kind("connect to 198.51.100.7:443 timed out"), "timed out");
        assert_eq!(error_kind("Connection refused (os error 111)"), "connection refused");
        assert_eq!(error_kind("10.0.0.1:80: closed to clients"), "blocked by policy");
        for text in ["example.com: lookup failed", "connect to 198.51.100.7:443 timed out"] {
            let kind = error_kind(text);
            assert!(!kind.contains("example") && !kind.contains("198"), "{kind}");
        }
    }

    #[test]
    fn resolve_prefers_the_explicit_setting() {
        assert_eq!(Privacy::resolve(None, false), Privacy::Normal);
        assert_eq!(Privacy::resolve(None, true), Privacy::Debug);
        assert_eq!(Privacy::resolve(Some(Privacy::Strict), true), Privacy::Strict);
        assert_eq!(Privacy::resolve(Some(Privacy::Normal), true), Privacy::Normal);
        let cfg: Result<Privacy, _> = serde_json::from_str("\"loud\"");
        assert!(cfg.is_err());
        assert_eq!(serde_json::from_str::<Privacy>("\"strict\"").unwrap(), Privacy::Strict);
    }
}
