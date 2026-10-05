//! Where a client's connection may go from this server.
//!
//! The internet: always. This machine's loopback: only the services meant
//! for clients (the panel, DNS), unless the owner sets `local_access`.
//! Private networks (the provider's internal network, a home LAN): only with
//! `local_access`. Link-local addresses, which include the cloud metadata
//! service at 169.254.169.254 with the instance's credentials, and other
//! special ranges: never.
//!
//! Checked on the address actually dialled, after name resolution, so a name
//! pointing at 127.0.0.1 or 169.254.169.254 is refused like the address is.

use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone, Default)]
pub struct TargetPolicy {
    /// Clients may reach this machine's own services and private networks.
    pub local_access: bool,
    /// Loopback ports open to clients without `local_access`.
    pub loopback_ports: Vec<u16>,
}

fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// Never a destination: unspecified, broadcast, multicast, link-local
/// (cloud metadata), "this network" and reserved ranges.
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

impl TargetPolicy {
    /// The strictest policy: the public internet only (the overnet exit).
    pub fn public_only() -> Self {
        Self::default()
    }

    pub fn allows(&self, addr: SocketAddr) -> bool {
        let ip = addr.ip();
        if is_special(ip) {
            return false;
        }
        if is_loopback(ip) {
            return self.local_access || self.loopback_ports.contains(&addr.port());
        }
        if is_private(ip) {
            return self.local_access;
        }
        true
    }

    pub fn check(&self, addr: SocketAddr) -> anyhow::Result<()> {
        if self.allows(addr) {
            return Ok(());
        }
        let ip = addr.ip();
        let why = if is_special(ip) {
            "a link-local or reserved address (cloud metadata lives there)"
        } else if is_loopback(ip) {
            "a service on the server itself"
        } else {
            "a private network address"
        };
        anyhow::bail!("{addr}: {why}, closed to clients (\"local_access\": true in the server config opens it)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn default_policy() {
        let p = TargetPolicy { local_access: false, loopback_ports: vec![9090, 53] };
        assert!(p.allows(a("93.184.216.34:443")));
        assert!(p.allows(a("[2606:4700::1111]:443")));
        assert!(p.allows(a("127.0.0.1:9090")), "the panel");
        assert!(p.allows(a("127.0.0.1:53")));
        assert!(!p.allows(a("127.0.0.1:6379")), "other local services");
        assert!(!p.allows(a("[::1]:22")));
        assert!(!p.allows(a("[::ffff:127.0.0.1]:6379")), "v4-mapped loopback");
        assert!(!p.allows(a("169.254.169.254:80")), "cloud metadata");
        assert!(!p.allows(a("10.0.0.5:5432")));
        assert!(!p.allows(a("192.168.1.1:80")));
        assert!(!p.allows(a("100.100.100.200:80")));
        assert!(!p.allows(a("[fd00:ec2::254]:80")));
        assert!(!p.allows(a("[fe80::1]:80")));
        assert!(!p.allows(a("0.0.0.0:80")));
        assert!(!p.allows(a("224.0.0.1:80")));
    }

    #[test]
    fn local_access_opens_this_machine_and_lans_but_never_metadata() {
        let p = TargetPolicy { local_access: true, loopback_ports: vec![] };
        assert!(p.allows(a("127.0.0.1:6379")));
        assert!(p.allows(a("192.168.1.1:80")));
        assert!(!p.allows(a("169.254.169.254:80")));
    }
}
