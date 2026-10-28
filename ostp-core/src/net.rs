//! Network helpers shared by the client, the server and the CLI: CIDR
//! matching, domain-suffix matching, address classification and
//! `host:port` splitting. One copy, so a fix lands everywhere.

use std::net::IpAddr;

// ── CIDR ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cidr {
    V4(u32, u8),
    V6(u128, u8),
}

impl Cidr {
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self, ip) {
            (Cidr::V4(net, bits), IpAddr::V4(addr)) => {
                let mask = if *bits == 0 { 0 } else { u32::MAX << (32 - (*bits).min(32)) };
                (u32::from_be_bytes(addr.octets()) & mask) == (*net & mask)
            }
            (Cidr::V6(net, bits), IpAddr::V6(addr)) => {
                let mask = if *bits == 0 { 0 } else { u128::MAX << (128 - (*bits).min(128)) };
                (u128::from_be_bytes(addr.octets()) & mask) == (*net & mask)
            }
            _ => false,
        }
    }
}

/// `addr`, or `addr/prefix`. Surrounding spaces are ignored; a prefix longer
/// than the address is clamped to a host route (/33 -> /32), not an overflow.
pub fn parse_cidr(value: &str) -> Option<Cidr> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let (addr, bits) = match value.split_once('/') {
        Some((a, b)) => (a.trim().parse::<IpAddr>().ok()?, Some(b.trim().parse::<u8>().ok()?)),
        None => (value.parse::<IpAddr>().ok()?, None),
    };
    Some(match addr {
        IpAddr::V4(v4) => Cidr::V4(u32::from_be_bytes(v4.octets()), bits.map_or(32, |b| b.min(32))),
        IpAddr::V6(v6) => Cidr::V6(u128::from_be_bytes(v6.octets()), bits.map_or(128, |b| b.min(128))),
    })
}

// ── Domains ──────────────────────────────────────────────────────────────────

/// The form a domain has on the wire: lower case, no trailing dot, and an
/// internationalized name (`пример.рф`) in punycode (`xn--e1afmkfd.xn--p1ai`),
/// which is what DNS, SNI and SOCKS requests carry. A string that is not a
/// valid domain is only lower-cased, so it still matches itself.
pub fn normalize_domain(domain: &str) -> String {
    let domain = domain.trim().trim_end_matches('.');
    if domain.is_ascii() {
        return domain.to_ascii_lowercase();
    }
    idna::domain_to_ascii(domain).unwrap_or_else(|_| domain.to_lowercase())
}

/// Does `host` equal `suffix` or sit under it, at a label boundary? A leading
/// `.` or `*` on the suffix is ignored; an empty suffix matches nothing.
pub fn domain_matches_suffix(host: &str, suffix: &str) -> bool {
    let suffix = normalize_domain(suffix.trim().trim_start_matches(['.', '*']));
    if suffix.is_empty() {
        return false;
    }
    let host = normalize_domain(host);
    host == suffix
        || host
            .strip_suffix(suffix.as_str())
            .is_some_and(|rest| rest.ends_with('.'))
}

// ── Address classification ───────────────────────────────────────────────────

/// An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) as the IPv4 it stands for,
/// so the v4 rules cannot be bypassed by writing the address as v6.
pub fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// Never a destination: unspecified, broadcast, multicast, link-local
/// (cloud metadata), "this network" and reserved (240/4) ranges.
pub fn is_special(ip: IpAddr) -> bool {
    match canonical(ip) {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_unspecified() || v4.is_broadcast() || v4.is_multicast() || v4.is_link_local() || o[0] == 0 || o[0] >= 240
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            v6.is_unspecified() || v6.is_multicast() || (s[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Private and carrier-grade NAT networks, IPv6 unique-local. Alibaba's
/// metadata (100.100.100.200) and AWS's IPv6 one (fd00:ec2::254) are here.
pub fn is_private(ip: IpAddr) -> bool {
    match canonical(ip) {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private() || (o[0] == 100 && (64..128).contains(&o[1]))
        }
        IpAddr::V6(v6) => (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

pub fn is_loopback(ip: IpAddr) -> bool {
    canonical(ip).is_loopback()
}

/// An address on the public internet: none of the classes above.
pub fn is_public(ip: IpAddr) -> bool {
    !(is_special(ip) || is_private(ip) || is_loopback(ip))
}

// ── host:port ────────────────────────────────────────────────────────────────

/// `host:port` or `[v6]:port`. An unbracketed IPv6 address is ambiguous and
/// refused, as is a missing or non-numeric port.
pub fn split_host_port(target: &str) -> Option<(String, u16)> {
    let (host, port) = target.rsplit_once(':')?;
    if host.starts_with('[') && host.ends_with(']') {
        let host = host.trim_start_matches('[').trim_end_matches(']').to_string();
        return Some((host, port.parse().ok()?));
    }
    if host.contains(':') {
        return None;
    }
    Some((host.to_string(), port.parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn cidr_prefixes() {
        assert!(parse_cidr("10.0.0.0/8").unwrap().contains(&ip("10.200.1.1")));
        assert!(!parse_cidr("10.0.0.0/8").unwrap().contains(&ip("11.0.0.1")));
        // /0 matches everything of its family, only that family.
        assert!(parse_cidr("0.0.0.0/0").unwrap().contains(&ip("8.8.8.8")));
        assert!(!parse_cidr("0.0.0.0/0").unwrap().contains(&ip("::1")));
        assert!(parse_cidr("::/0").unwrap().contains(&ip("2606:4700::1")));
        // /32 and /128 are host routes.
        let c = parse_cidr("1.2.3.4/32").unwrap();
        assert!(c.contains(&ip("1.2.3.4")) && !c.contains(&ip("1.2.3.5")));
        let c = parse_cidr("::1/128").unwrap();
        assert!(c.contains(&ip("::1")) && !c.contains(&ip("::2")));
        // Over-long prefixes are clamped, never an overflowing shift.
        assert_eq!(parse_cidr("1.2.3.4/33"), Some(Cidr::V4(0x01020304, 32)));
        assert_eq!(parse_cidr("1.2.3.4/200"), Some(Cidr::V4(0x01020304, 32)));
        assert_eq!(parse_cidr("::1/129"), Some(Cidr::V6(1, 128)));
        assert!(!parse_cidr("1.2.3.4/33").unwrap().contains(&ip("1.2.3.5")));
        // A hand-built out-of-range prefix cannot panic `contains` either.
        assert!(Cidr::V4(0x01020304, 40).contains(&ip("1.2.3.4")));
        assert!(Cidr::V6(1, 255).contains(&ip("::1")));
    }

    #[test]
    fn cidr_parsing_edges() {
        assert_eq!(parse_cidr("  192.168.1.1  "), Some(Cidr::V4(0xc0a80101, 32)));
        assert_eq!(parse_cidr(" 10.0.0.0 / 8 "), Some(Cidr::V4(0x0a000000, 8)));
        assert_eq!(parse_cidr("fd00::1"), Some(Cidr::V6((0xfd00u128 << 112) | 1, 128)));
        for bad in ["", "   ", "not-an-ip/24", "1.2.3.4/", "1.2.3.4/x", "1.2.3.4/-1", "1.2.3.4/256", "1.2.3.4/8/8", "/8"] {
            assert!(parse_cidr(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn domains_normalize() {
        assert_eq!(normalize_domain("  Example.COM. "), "example.com");
        assert_eq!(normalize_domain("пример.рф"), "xn--e1afmkfd.xn--p1ai");
        assert_eq!(normalize_domain("ПРИМЕР.РФ."), "xn--e1afmkfd.xn--p1ai");
        assert_eq!(normalize_domain("xn--e1afmkfd.xn--p1ai"), "xn--e1afmkfd.xn--p1ai");
        assert_eq!(normalize_domain(""), "");
    }

    #[test]
    fn domain_suffixes() {
        assert!(domain_matches_suffix("example.com", "example.com"));
        assert!(domain_matches_suffix("a.b.Example.com.", ".example.com"));
        assert!(domain_matches_suffix("x.test.org", "*.test.org"));
        assert!(!domain_matches_suffix("badexample.com", "example.com"));
        assert!(!domain_matches_suffix("example.com", "a.example.com"));
        assert!(!domain_matches_suffix("example.com", ""));
        assert!(!domain_matches_suffix("example.com", " . "));
        assert!(domain_matches_suffix("test.onion", ".onion"));
        assert!(!domain_matches_suffix("onion.com", ".onion"));
        // Internationalized rule against the punycode name on the wire.
        assert!(domain_matches_suffix("xn--e1afmkfd.xn--p1ai", "пример.рф"));
        assert!(domain_matches_suffix("www.xn--e1afmkfd.xn--p1ai.", "пример.рф"));
        assert!(domain_matches_suffix("пример.рф", "xn--e1afmkfd.xn--p1ai"));
        assert!(!domain_matches_suffix("xn--p1ai", "пример.рф"));
    }

    #[test]
    fn special_ranges() {
        for s in ["0.0.0.0", "0.1.2.3", "255.255.255.255", "224.0.0.1", "239.255.255.250", "169.254.169.254",
                  "240.0.0.1", "250.1.1.1", "::", "ff02::1", "fe80::1", "febf::1", "::ffff:169.254.169.254",
                  "::ffff:240.0.0.1"] {
            assert!(is_special(ip(s)), "{s}");
        }
        for s in ["1.1.1.1", "10.0.0.1", "127.0.0.1", "100.64.0.1", "223.255.255.255", "2606:4700::1111",
                  "fd00::1", "::1"] {
            assert!(!is_special(ip(s)), "{s}");
        }
    }

    #[test]
    fn private_ranges() {
        for s in ["10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1", "100.64.0.1", "100.127.255.255",
                  "100.100.100.200", "fc00::1", "fd00:ec2::254", "::ffff:10.0.0.1", "::ffff:100.64.0.1"] {
            assert!(is_private(ip(s)), "{s}");
        }
        for s in ["172.15.0.1", "172.32.0.1", "100.63.255.255", "100.128.0.1", "192.169.0.1", "11.0.0.1",
                  "1.1.1.1", "2606:4700::1111", "fe00::1", "::ffff:8.8.8.8"] {
            assert!(!is_private(ip(s)), "{s}");
        }
    }

    #[test]
    fn loopback_ranges() {
        for s in ["127.0.0.1", "127.255.255.254", "::1", "::ffff:127.0.0.1"] {
            assert!(is_loopback(ip(s)), "{s}");
        }
        for s in ["128.0.0.1", "::2", "::ffff:8.8.8.8", "10.0.0.1"] {
            assert!(!is_loopback(ip(s)), "{s}");
        }
    }

    #[test]
    fn public_addresses() {
        for s in ["1.1.1.1", "78.46.170.2", "93.184.216.34", "2606:4700::1111", "::ffff:8.8.8.8"] {
            assert!(is_public(ip(s)), "{s}");
        }
        for s in ["192.168.1.1", "100.64.0.1", "169.254.1.1", "127.0.0.1", "0.0.0.0", "255.255.255.255",
                  "240.0.0.1", "224.0.0.1", "::1", "::", "fd00::1", "fe80::1", "::ffff:192.168.1.1"] {
            assert!(!is_public(ip(s)), "{s}");
        }
    }

    #[test]
    fn host_port() {
        let sp = split_host_port;
        assert_eq!(sp("example.com:443"), Some(("example.com".into(), 443)));
        assert_eq!(sp("127.0.0.1:80"), Some(("127.0.0.1".into(), 80)));
        assert_eq!(sp("[::1]:80"), Some(("::1".into(), 80)));
        assert_eq!(sp("[2606:4700::1111]:8080"), Some(("2606:4700::1111".into(), 8080)));
        assert_eq!(sp("noport"), None);
        assert_eq!(sp("::1:8080"), None);
        assert_eq!(sp("[::1]"), None);
        assert_eq!(sp("example.com:"), None);
        assert_eq!(sp("example.com:http"), None);
        assert_eq!(sp("example.com:65536"), None);
        assert_eq!(sp(""), None);
    }
}
