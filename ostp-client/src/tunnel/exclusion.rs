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
    /// Everything this matcher is asked about goes direct: set for one
    /// connection whose program is excluded.
    pub bypass_all: bool,
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
                .map(|d| normalize_domain(d.trim_start_matches(['.', '*'])))
                .filter(|d| !d.is_empty())
                .collect(),
            cidrs,
            processes,
            physical_if_index,
            physical_if_name,
            bypass_all: false,
        }
    }

    pub async fn should_bypass_target(&self, host: &str, port: u16, timeout_value: Duration) -> bool {
        if self.bypass_all {
            return true;
        }
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
        self.domain_suffix.iter().any(|suffix| ostp_core::net::domain_matches_suffix(host, suffix))
    }

    pub fn match_ip(&self, ip: &std::net::IpAddr) -> bool {
        self.cidrs.iter().any(|cidr| cidr.contains(ip))
    }

    /// The name of the program owning the local socket `local`, when that
    /// program is excluded. Looks the owner up only when process exclusions
    /// are configured, since the lookup reads the system's socket tables.
    pub async fn excluded_process(
        &self,
        proto: crate::tunnel::process_lookup::Proto,
        local: std::net::SocketAddr,
    ) -> Option<String> {
        if self.processes.is_empty() {
            return None;
        }
        let name = tokio::task::spawn_blocking(move || {
            crate::tunnel::process_lookup::process_owning(proto, local)
        })
        .await
        .ok()
        .flatten();
        match name {
            Some(name) if self.match_process(&name) => Some(name),
            Some(name) => {
                tracing::debug!("{local} belongs to {name}, not excluded");
                None
            }
            None => {
                tracing::debug!("no process found for {local}");
                None
            }
        }
    }

    pub fn match_process(&self, process_name: &str) -> bool {
        if self.processes.is_empty() {
            return false;
        }
        let p = process_name.to_lowercase();
        self.processes.iter().any(|ex| p.contains(ex))
    }
}

// Shared with the server so a rule means the same on both sides.
pub use ostp_core::net::{normalize_domain, parse_cidr, Cidr};

#[cfg(test)]
mod tests {
    use super::*;

    fn matcher(domains: &[&str]) -> ExclusionMatcher {
        let cfg = ExclusionConfig {
            domains: domains.iter().map(|d| d.to_string()).collect(),
            ..Default::default()
        };
        ExclusionMatcher::new(&cfg, None, None)
    }

    #[test]
    fn internationalized_domains_match_their_punycode() {
        let m = matcher(&["пример.рф", ".Госуслуги.РФ"]);
        assert!(m.match_domain("xn--e1afmkfd.xn--p1ai"));
        assert!(m.match_domain("www.xn--e1afmkfd.xn--p1ai."));
        assert!(m.match_domain("пример.рф"));
        assert!(m.match_domain("lk.xn--c1aapkosapc.xn--p1ai"));
        assert!(!m.match_domain("xn--p1ai"));
    }

    #[test]
    fn ascii_domains_match_suffixes_only_at_a_label() {
        let m = matcher(&["Example.com", "*.test.org"]);
        assert!(m.match_domain("example.com"));
        assert!(m.match_domain("a.b.EXAMPLE.com."));
        assert!(!m.match_domain("badexample.com"));
        assert!(m.match_domain("x.test.org"));
    }

    #[tokio::test]
    async fn an_excluded_program_bypasses_everything() {
        let mut m = matcher(&[]);
        let t = Duration::from_millis(10);
        assert!(!m.should_bypass_target("example.com", 443, t).await);
        m.bypass_all = true;
        assert!(m.should_bypass_target("example.com", 443, t).await);
    }
}
