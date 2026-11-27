// Windows Firewall rules that keep DNS (and, when it is not captured, IPv6) from leaving
// outside the tunnel. Pure functions: they only build the `netsh` arguments.
//
// Windows asks every adapter's resolver at once (smart multi-homed name resolution), so
// the router's or the ISP's resolver, often on-link and never routed into the TUN, still
// saw every name. A block rule wins over any allow rule, so the rules block everything
// except the addresses that may be reached: the tunnel's resolver, the tunnel's own
// subnet and loopback.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Every rule name this module can create. Deleted at the start and in the guard's Drop.
pub const GUARD_RULE_NAMES: [&str; 5] = [
    "OSTP DNS guard UDP v4",
    "OSTP DNS guard TCP v4",
    "OSTP DNS guard UDP v6",
    "OSTP DNS guard TCP v6",
    "OSTP DNS guard IPv6 block",
];

/// DNS (53) and DNS over TLS / QUIC (853).
const DNS_PORTS: &str = "53,853";

/// The address used on the adapter when no resolver is configured.
pub const DEFAULT_TUN_DNS: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FwRule {
    pub name: &'static str,
    /// The arguments after `netsh`.
    pub args: Vec<String>,
}

/// The inclusive ranges of the address space (0..=max) not covered by `allowed`.
/// `allowed` may overlap and be unsorted; ranges past `max` are clamped.
pub fn complement(allowed: &[(u128, u128)], max: u128) -> Vec<(u128, u128)> {
    let mut v: Vec<(u128, u128)> = allowed.iter().map(|&(s, e)| (s, e.min(max))).filter(|&(s, e)| s <= e).collect();
    v.sort();
    let mut out = Vec::new();
    let mut next: Option<u128> = Some(0);
    for (s, e) in v {
        let Some(n) = next else { break };
        if s > n {
            out.push((n, s - 1));
        }
        if e >= n {
            next = e.checked_add(1).filter(|x| *x <= max);
        }
    }
    if let Some(n) = next {
        out.push((n, max));
    }
    out
}

fn v4_net(ip: Ipv4Addr, prefix: u8) -> (u128, u128) {
    let p = u32::from(prefix.min(32));
    let mask = if p == 0 { 0 } else { u32::MAX << (32 - p) };
    let start = u32::from(ip) & mask;
    (u128::from(start), u128::from(start | !mask))
}

fn v6_net(ip: Ipv6Addr, prefix: u8) -> (u128, u128) {
    let p = u32::from(prefix.min(128));
    let mask = if p == 0 { 0 } else { u128::MAX << (128 - p) };
    let start = u128::from(ip) & mask;
    (start, start | !mask)
}

fn fmt_v4_ranges(ranges: &[(u128, u128)]) -> String {
    let one = |s: u128, e: u128| {
        let (a, b) = (Ipv4Addr::from(s as u32), Ipv4Addr::from(e as u32));
        if s == e { a.to_string() } else { format!("{a}-{b}") }
    };
    ranges.iter().map(|&(s, e)| one(s, e)).collect::<Vec<_>>().join(",")
}

fn fmt_v6_ranges(ranges: &[(u128, u128)]) -> String {
    let one = |s: u128, e: u128| {
        let (a, b) = (Ipv6Addr::from(s), Ipv6Addr::from(e));
        if s == e { a.to_string() } else { format!("{a}-{b}") }
    };
    ranges.iter().map(|&(s, e)| one(s, e)).collect::<Vec<_>>().join(",")
}

/// `remoteip` value: every IPv4 address except the tunnel's resolver, the tunnel
/// subnet, loopback and the server.
pub fn v4_remote_ips(dns: Option<Ipv4Addr>, server: IpAddr) -> String {
    let mut allowed = vec![v4_net(Ipv4Addr::new(10, 1, 0, 0), 24), v4_net(Ipv4Addr::LOCALHOST, 8)];
    if let Some(d) = dns {
        allowed.push(v4_net(d, 32));
    }
    if let IpAddr::V4(s) = server {
        allowed.push(v4_net(s, 32));
    }
    fmt_v4_ranges(&complement(&allowed, u128::from(u32::MAX)))
}

/// `remoteip` value: every IPv6 address except the tunnel's resolver (if any),
/// loopback and the server.
pub fn v6_remote_ips(dns: Option<Ipv6Addr>, server: IpAddr) -> String {
    let mut allowed = vec![v6_net(Ipv6Addr::LOCALHOST, 128)];
    if let Some(d) = dns {
        allowed.push(v6_net(d, 128));
    }
    if let IpAddr::V6(s) = server {
        allowed.push(v6_net(s, 128));
    }
    fmt_v6_ranges(&complement(&allowed, u128::MAX))
}

fn add_rule(name: &'static str, protocol: &str, remote_port: Option<&str>, remote_ip: String) -> FwRule {
    let mut args: Vec<String> = ["advfirewall", "firewall", "add", "rule"].iter().map(|s| s.to_string()).collect();
    args.push(format!("name={name}"));
    args.push("dir=out".into());
    args.push("action=block".into());
    args.push(format!("protocol={protocol}"));
    if let Some(p) = remote_port {
        args.push(format!("remoteport={p}"));
    }
    args.push(format!("remoteip={remote_ip}"));
    FwRule { name, args }
}

/// Rules that block DNS outside the tunnel: UDP and TCP to ports 53 and 853 of every
/// address except the tunnel's resolver. The IPv6 pair is added only when IPv6 goes
/// through the tunnel (`dns_v6` is the tunnel's IPv6 resolver, if one is set); when it
/// does not, `ipv6_block_rule` blocks all of IPv6 instead.
pub fn dns_guard_rules(dns_v4: Option<Ipv4Addr>, dns_v6: Option<Ipv6Addr>, server: IpAddr, ipv6_captured: bool) -> Vec<FwRule> {
    let v4 = v4_remote_ips(dns_v4, server);
    let mut rules = vec![
        add_rule(GUARD_RULE_NAMES[0], "udp", Some(DNS_PORTS), v4.clone()),
        add_rule(GUARD_RULE_NAMES[1], "tcp", Some(DNS_PORTS), v4),
    ];
    if ipv6_captured {
        let v6 = v6_remote_ips(dns_v6, server);
        rules.push(add_rule(GUARD_RULE_NAMES[2], "udp", Some(DNS_PORTS), v6.clone()));
        rules.push(add_rule(GUARD_RULE_NAMES[3], "tcp", Some(DNS_PORTS), v6));
    }
    rules
}

/// Blocks all outbound IPv6 for a tunnel that does not carry it, so IPv6 cannot leak.
/// Link-local (fe80::/10) and multicast (ff00::/8) stay open: they never leave the
/// link and neighbour discovery needs them. The server's own address stays reachable.
pub fn ipv6_block_rule(server: IpAddr) -> FwRule {
    let mut allowed = vec![
        v6_net(Ipv6Addr::LOCALHOST, 128),
        v6_net(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10),
        v6_net(Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8),
    ];
    if let IpAddr::V6(s) = server {
        allowed.push(v6_net(s, 128));
    }
    add_rule(GUARD_RULE_NAMES[4], "any", None, fmt_v6_ranges(&complement(&allowed, u128::MAX)))
}

/// The arguments that delete a guard rule by name.
pub fn delete_rule_args(name: &str) -> Vec<String> {
    ["advfirewall", "firewall", "delete", "rule"].iter().map(|s| s.to_string()).chain([format!("name={name}")]).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complement_of_nothing_is_everything() {
        assert_eq!(complement(&[], 255), vec![(0, 255)]);
    }

    #[test]
    fn complement_skips_allowed_and_merges_overlaps() {
        assert_eq!(complement(&[(10, 20), (15, 30), (50, 50)], 255), vec![(0, 9), (31, 49), (51, 255)]);
        // unsorted input, ranges at both ends
        assert_eq!(complement(&[(200, 255), (0, 4)], 255), vec![(5, 199)]);
        assert_eq!(complement(&[(0, 255)], 255), vec![]);
    }

    #[test]
    fn complement_does_not_overflow_at_the_top() {
        assert_eq!(complement(&[(u128::MAX, u128::MAX)], u128::MAX), vec![(0, u128::MAX - 1)]);
        assert_eq!(complement(&[(0, u128::MAX)], u128::MAX), vec![]);
    }

    #[test]
    fn v4_ranges_leave_out_the_resolver() {
        let s = v4_remote_ips(Some("1.1.1.1".parse().unwrap()), "203.0.113.7".parse().unwrap());
        assert_eq!(
            s,
            "0.0.0.0-1.1.1.0,1.1.1.2-10.0.255.255,10.1.1.0-126.255.255.255,128.0.0.0-203.0.113.6,203.0.113.8-255.255.255.255"
        );
        // the allowed addresses are not inside any listed range
        assert!(!s.contains("1.1.1.1"));
    }

    #[test]
    fn v4_ranges_with_the_default_resolver_and_a_v6_server() {
        let s = v4_remote_ips(Some(DEFAULT_TUN_DNS), "2001:db8::1".parse().unwrap());
        assert_eq!(s, "0.0.0.0-1.1.1.0,1.1.1.2-10.0.255.255,10.1.1.0-126.255.255.255,128.0.0.0-255.255.255.255");
    }

    #[test]
    fn v6_ranges_leave_out_loopback_resolver_and_server() {
        let s = v6_remote_ips(Some("2606:4700:4700::1111".parse().unwrap()), "2001:db8::5".parse().unwrap());
        let parts: Vec<&str> = s.split(',').collect();
        assert_eq!(parts[0], "::");
        assert_eq!(parts[1], "::2-2001:db8::4");
        assert_eq!(parts.len(), 4);
        assert!(parts.last().unwrap().ends_with("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"));
    }

    #[test]
    fn dns_rules_cover_udp_and_tcp_on_53_and_853() {
        let rules = dns_guard_rules(Some(DEFAULT_TUN_DNS), None, "203.0.113.7".parse().unwrap(), true);
        assert_eq!(rules.len(), 4);
        let udp4 = &rules[0];
        assert_eq!(udp4.name, "OSTP DNS guard UDP v4");
        assert_eq!(&udp4.args[..4], ["advfirewall", "firewall", "add", "rule"]);
        for a in ["name=OSTP DNS guard UDP v4", "dir=out", "action=block", "protocol=udp", "remoteport=53,853"] {
            assert!(udp4.args.iter().any(|x| x == a), "missing {a}");
        }
        assert!(udp4.args.last().unwrap().starts_with("remoteip=0.0.0.0-1.1.1.0,"));
        assert!(rules[1].args.iter().any(|x| x == "protocol=tcp"));
        assert!(rules[2].args.iter().any(|x| x == "protocol=udp"));
        assert_eq!(rules[3].name, "OSTP DNS guard TCP v6");
    }

    #[test]
    fn without_ipv6_capture_only_the_v4_pair_is_added() {
        let rules = dns_guard_rules(Some(DEFAULT_TUN_DNS), None, "2001:db8::1".parse().unwrap(), false);
        assert_eq!(rules.iter().map(|r| r.name).collect::<Vec<_>>(), ["OSTP DNS guard UDP v4", "OSTP DNS guard TCP v4"]);
    }

    #[test]
    fn ipv6_block_keeps_link_local_loopback_and_the_server() {
        let r = ipv6_block_rule("2001:db8::5".parse().unwrap());
        assert_eq!(r.name, "OSTP DNS guard IPv6 block");
        assert!(r.args.iter().any(|x| x == "protocol=any"));
        assert!(!r.args.iter().any(|x| x.starts_with("remoteport")));
        let ips = r.args.last().unwrap();
        assert!(ips.starts_with("remoteip=::2-2001:db8::4,"));
        // fe80::/10 and ff00::/8 are gaps, the server is a gap
        assert!(ips.contains("2001:db8::4,"));
        assert!(ips.contains("2001:db8::6-"));
        assert!(ips.contains("fec0::-feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff,"));
    }

    #[test]
    fn delete_args_name_the_rule() {
        assert_eq!(
            delete_rule_args("OSTP DNS guard UDP v4"),
            ["advfirewall", "firewall", "delete", "rule", "name=OSTP DNS guard UDP v4"]
        );
    }

    #[test]
    fn every_rule_name_is_in_the_delete_list() {
        let all: Vec<&str> = dns_guard_rules(None, None, "1.2.3.4".parse().unwrap(), true)
            .iter()
            .map(|r| r.name)
            .chain([ipv6_block_rule("1.2.3.4".parse().unwrap()).name])
            .collect();
        for n in all {
            assert!(GUARD_RULE_NAMES.contains(&n));
        }
    }
}
