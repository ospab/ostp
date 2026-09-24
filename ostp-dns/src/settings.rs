//! The `dns` section of the server config.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BlockingMode {
    /// NXDOMAIN: the name does not exist.
    #[default]
    Nxdomain,
    /// 0.0.0.0 / :: answers.
    NullIp,
    /// REFUSED.
    Refused,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamMode {
    /// Upstreams in order, the next one when a query fails.
    #[default]
    Fallback,
    /// All upstreams at once, the first answer wins.
    Parallel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterList {
    pub name: String,
    pub url: String,
    #[serde(default = "yes")]
    pub enabled: bool,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rewrite {
    /// "panel.ostp", or "*.example.org" for every subdomain.
    pub domain: String,
    /// IPv4, IPv6 or a domain name (answered as CNAME).
    pub answer: String,
}

/// Block lists anyone can turn on by id (`ostp dns list add <id>`).
pub const PRESET_LISTS: &[(&str, &str, &str)] = &[
    ("adguard", "AdGuard DNS filter", "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"),
    ("adaway", "AdAway default blocklist", "https://adaway.org/hosts.txt"),
    ("stevenblack", "Steven Black's unified hosts", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"),
    ("oisd-small", "OISD small", "https://small.oisd.nl/"),
    ("hagezi-light", "HaGeZi Light", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/light.txt"),
];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsSettings {
    /// Filtering resolver for everything clients resolve through the tunnel.
    pub enabled: bool,
    /// While `enabled` is off, still answer clients' port-53 queries
    /// (forwarded, unfiltered) so they never leave from the server's address.
    pub intercept_all_port53: bool,
    /// "https://host/dns-query" (DoH), "tls://host" (DoT), "tcp://ip:53",
    /// "udp://ip:53" or a bare IP.
    pub upstreams: Vec<String>,
    pub upstream_mode: UpstreamMode,
    /// Cached answers (entries); 0 turns the cache off.
    pub cache_size: usize,
    pub cache_min_ttl: u32,
    pub cache_max_ttl: u32,
    pub blocking_mode: BlockingMode,
    pub blocked_ttl: u32,
    /// Block lists (adblock or hosts syntax).
    pub lists: Vec<FilterList>,
    /// Allow lists: every domain in them is never blocked.
    pub allowlists: Vec<FilterList>,
    /// How often lists are downloaded again.
    pub update_interval_hours: u32,
    /// Own rules: "||ads.example^", "@@||good.example^", "0.0.0.0 bad.example",
    /// "1.2.3.4 host.lan" (answered with that address).
    pub user_rules: Vec<String>,
    pub rewrites: Vec<Rewrite>,
    /// Forces safe search on Google, YouTube, Bing, DuckDuckGo and Yandex.
    pub safe_search: bool,
    /// Stops browsers from skipping this resolver with their own DNS over
    /// HTTPS (Firefox canary domain, well-known DoH hostnames).
    pub block_doh_bypass: bool,
    /// Ids from `services::SERVICES`.
    pub blocked_services: Vec<String>,
    /// Recent queries kept for the panel.
    pub query_log_size: usize,

    // Before 0.4.6: kept readable, folded into the fields above.
    #[serde(skip_serializing)]
    pub doh_upstream: Option<String>,
    #[serde(skip_serializing)]
    pub adblock_urls: Option<Vec<String>>,
    #[serde(skip_serializing)]
    pub custom_domains: Option<HashMap<String, String>>,
    #[serde(skip_serializing)]
    pub local_port: Option<u16>,
}

impl Default for DnsSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            intercept_all_port53: false,
            upstreams: vec!["https://cloudflare-dns.com/dns-query".into(), "https://dns.google/dns-query".into()],
            upstream_mode: UpstreamMode::Fallback,
            cache_size: 10_000,
            cache_min_ttl: 60,
            cache_max_ttl: 86_400,
            blocking_mode: BlockingMode::Nxdomain,
            blocked_ttl: 300,
            lists: vec![FilterList { name: PRESET_LISTS[0].1.into(), url: PRESET_LISTS[0].2.into(), enabled: true }],
            allowlists: Vec::new(),
            update_interval_hours: 24,
            user_rules: Vec::new(),
            rewrites: Vec::new(),
            safe_search: false,
            block_doh_bypass: true,
            blocked_services: Vec::new(),
            query_log_size: 1000,
            doh_upstream: None,
            adblock_urls: None,
            custom_domains: None,
            local_port: None,
        }
    }
}

impl DnsSettings {
    /// Folds the pre-0.4.6 fields into the current ones.
    pub fn normalized(mut self) -> Self {
        if let Some(u) = self.doh_upstream.take().filter(|u| !u.is_empty()) {
            if !self.upstreams.contains(&u) {
                self.upstreams.insert(0, u);
            }
        }
        if let Some(urls) = self.adblock_urls.take() {
            for url in urls {
                if !self.lists.iter().any(|l| l.url == url) {
                    self.lists.push(FilterList { name: url.clone(), url, enabled: true });
                }
            }
        }
        if let Some(map) = self.custom_domains.take() {
            for (domain, answer) in map {
                if !self.rewrites.iter().any(|r| r.domain == domain) {
                    self.rewrites.push(Rewrite { domain, answer });
                }
            }
        }
        self.local_port = None;
        self
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.enabled && self.upstreams.is_empty() {
            anyhow::bail!("dns.upstreams must name at least one upstream resolver");
        }
        for u in &self.upstreams {
            crate::upstream::Upstream::parse(u)?;
        }
        for r in &self.rewrites {
            if r.domain.trim().is_empty() || r.answer.trim().is_empty() {
                anyhow::bail!("dns.rewrites entries need both a domain and an answer");
            }
        }
        for s in &self.blocked_services {
            if !crate::services::SERVICES.iter().any(|(id, _, _)| id == s) {
                anyhow::bail!("dns.blocked_services: unknown service \"{s}\" (ostp dns service list)");
            }
        }
        if self.cache_min_ttl > self.cache_max_ttl {
            anyhow::bail!("dns.cache_min_ttl is larger than dns.cache_max_ttl");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_fields_fold_in() {
        let s: DnsSettings = serde_json::from_str(
            r#"{"enabled": true, "doh_upstream": "https://doh.example/dns-query", "adblock_urls": ["https://l.example/a.txt"],
                "custom_domains": {"nas.lan": "192.168.1.5"}, "local_port": 50053}"#,
        )
        .unwrap();
        let s = s.normalized();
        assert_eq!(s.upstreams[0], "https://doh.example/dns-query");
        assert!(s.lists.iter().any(|l| l.url == "https://l.example/a.txt"));
        assert_eq!(s.rewrites, vec![Rewrite { domain: "nas.lan".into(), answer: "192.168.1.5".into() }]);
        let out = serde_json::to_string(&s).unwrap();
        assert!(!out.contains("doh_upstream") && !out.contains("local_port"));
        s.validate().unwrap();
    }
}
