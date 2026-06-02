use crate::config::ExclusionConfig;
use std::time::Duration;
use tokio::time::timeout;

#[derive(Clone)]
pub struct ExclusionMatcher {
    pub domain_suffix: Vec<String>,
    pub cidrs: Vec<Cidr>,
    pub processes: Vec<String>,
    pub physical_if_index: Option<u32>,
    pub physical_if_name: Option<String>,
}

impl ExclusionMatcher {
    pub fn new(
        exclusions: &ExclusionConfig,
        physical_if_index: Option<u32>,
        physical_if_name: Option<String>,
    ) -> Self {
        let mut cidrs = Vec::new();
        for ip in &exclusions.ips {
            if let Some(cidr) = parse_cidr(ip) {
                cidrs.push(cidr);
            }
        }

        let processes = exclusions.processes.iter()
            .map(|p| p.trim().to_lowercase())
            .filter(|p| !p.is_empty())
            .collect();

        Self {
            domain_suffix: exclusions
                .domains
                .iter()
                .map(|d| d.trim().trim_start_matches('.').to_lowercase())
                .filter(|d| !d.is_empty())
                .collect(),
            cidrs,
            processes,
            physical_if_index,
            physical_if_name,
        }
    }

    pub async fn should_bypass_target(&self, host: &str, port: u16, timeout_value: Duration) -> bool {
        if self.match_domain(host) {
            return true;
        }

        if self.cidrs.is_empty() {
            return false;
        }

        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            return self.match_ip(&ip);
        }

        let lookup_target = (host.to_string(), port);
        match timeout(timeout_value, tokio::net::lookup_host(lookup_target)).await {
            Ok(Ok(addrs)) => addrs.into_iter().any(|addr| self.match_ip(&addr.ip())),
            _ => false,
        }
    }

    pub fn match_domain(&self, host: &str) -> bool {
        if self.domain_suffix.is_empty() {
            return false;
        }
        let host = host.trim_end_matches('.').to_lowercase();
        self.domain_suffix.iter().any(|suffix| {
            host == *suffix || host.ends_with(&format!(".{suffix}"))
        })
    }

    pub fn match_ip(&self, ip: &std::net::IpAddr) -> bool {
        self.cidrs.iter().any(|cidr| cidr.contains(ip))
    }

    pub fn match_process(&self, process_name: &str) -> bool {
        if self.processes.is_empty() {
            return false;
        }
        let p = process_name.to_lowercase();
        self.processes.iter().any(|ex| p.contains(ex))
    }
}

#[derive(Clone)]
pub enum Cidr {
    V4(u32, u8),
    V6(u128, u8),
}

impl Cidr {
    pub fn contains(&self, ip: &std::net::IpAddr) -> bool {
        match (self, ip) {
            (Cidr::V4(net, bits), std::net::IpAddr::V4(addr)) => {
                let mask = if *bits == 0 { 0 } else { u32::MAX << (32 - bits) };
                let ip = u32::from_be_bytes(addr.octets());
                (ip & mask) == (*net & mask)
            }
            (Cidr::V6(net, bits), std::net::IpAddr::V6(addr)) => {
                let mask = if *bits == 0 { 0 } else { u128::MAX << (128 - bits) };
                let ip = u128::from_be_bytes(addr.octets());
                (ip & mask) == (*net & mask)
            }
            _ => false,
        }
    }
}

pub fn parse_cidr(s: &str) -> Option<Cidr> {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.is_empty() || parts.len() > 2 {
        return None;
    }
    if let Ok(ip) = parts[0].parse::<std::net::IpAddr>() {
        let bits = if parts.len() == 2 {
            parts[1].parse::<u8>().ok()?
        } else {
            match ip {
                std::net::IpAddr::V4(_) => 32,
                std::net::IpAddr::V6(_) => 128,
            }
        };
        match ip {
            std::net::IpAddr::V4(v4) => Some(Cidr::V4(u32::from_be_bytes(v4.octets()), bits)),
            std::net::IpAddr::V6(v6) => Some(Cidr::V6(u128::from_be_bytes(v6.octets()), bits)),
        }
    } else {
        None
    }
}
