//! The `warp` section of the server config and how enabling it edits the
//! `outbound` section.

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const DEFAULT_LISTEN: &str = "127.0.0.1:40000";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WarpMode {
    /// Everything the server opens outwards goes through WARP.
    All,
    /// Only what the `outbound` rules send to the proxy.
    Rules,
}

impl WarpMode {
    pub fn as_str(self) -> &'static str {
        match self {
            WarpMode::All => "all",
            WarpMode::Rules => "rules",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct WarpConfig {
    pub enabled: bool,
    pub mode: WarpMode,
    /// Loopback address of the local SOCKS5 proxy.
    pub listen: String,
    /// `host:port` (or `ip:port`) of Cloudflare's endpoint, replacing the one
    /// the registration gave. Empty = the registered one.
    pub endpoint: String,
}

impl Default for WarpConfig {
    fn default() -> Self {
        Self { enabled: false, mode: WarpMode::Rules, listen: DEFAULT_LISTEN.to_string(), endpoint: String::new() }
    }
}

impl WarpConfig {
    /// The loopback socket address of the proxy. A SOCKS5 server without
    /// authentication on a public address is an open proxy, so anything but
    /// a loopback address is refused.
    pub fn listen_addr(&self) -> Result<std::net::SocketAddr> {
        let a: std::net::SocketAddr = self
            .listen
            .parse()
            .map_err(|_| anyhow!("warp.listen \"{}\" is not an address:port such as {DEFAULT_LISTEN}", self.listen))?;
        if !a.ip().is_loopback() {
            bail!("warp.listen must be a loopback address (it is a SOCKS5 proxy without a password); got {a}");
        }
        if a.port() == 0 {
            bail!("warp.listen needs a fixed port: the outbound section points at it");
        }
        Ok(a)
    }

    pub fn validate(&self) -> Result<()> {
        self.listen_addr()?;
        if !self.endpoint.is_empty() {
            let (host, port) = self
                .endpoint
                .rsplit_once(':')
                .ok_or_else(|| anyhow!("warp.endpoint \"{}\" is not host:port", self.endpoint))?;
            if host.trim_matches(['[', ']']).is_empty() || port.parse::<u16>().ok().filter(|p| *p != 0).is_none() {
                bail!("warp.endpoint \"{}\" is not host:port", self.endpoint);
            }
        }
        Ok(())
    }
}

/// The `outbound` section for `--all`: SOCKS5 to WARP's proxy, everything
/// through it, no rule that could send something out directly.
pub fn outbound_for_all(listen: std::net::SocketAddr) -> Value {
    json!({
        "enabled": true,
        "protocol": "socks5",
        "address": listen.ip().to_string(),
        "port": listen.port(),
        "username": "",
        "password": "",
        "rules": [],
        "default_action": "proxy"
    })
}

/// Whether the outbound section already sends this server's traffic to WARP's
/// proxy.
pub fn outbound_points_at(outbound: &Value, listen: std::net::SocketAddr) -> bool {
    outbound.get("enabled").and_then(Value::as_bool).unwrap_or(false)
        && outbound.get("protocol").and_then(Value::as_str).is_some_and(|p| p.eq_ignore_ascii_case("socks5"))
        && outbound.get("address").and_then(Value::as_str).and_then(|a| a.parse::<std::net::IpAddr>().ok()) == Some(listen.ip())
        && outbound.get("port").and_then(Value::as_u64) == Some(u64::from(listen.port()))
}

/// Whether an action string, read the way the server reads it, means the
/// proxy: only "direct" and "block" mean something else; an absent or
/// unknown value is the proxy (see `parse_outbound_action` in `ostp`).
fn action_is_proxy(a: Option<&str>) -> bool {
    !matches!(a, Some("direct") | Some("block"))
}

/// Whether any rule (or the default) sends something to the proxy.
pub fn outbound_has_proxy_rule(outbound: &Value) -> bool {
    let default_proxy = action_is_proxy(outbound.get("default_action").and_then(Value::as_str));
    let rule_proxy = outbound
        .get("rules")
        .and_then(Value::as_array)
        .is_some_and(|r| r.iter().any(|x| action_is_proxy(x.get("action").and_then(Value::as_str))));
    default_proxy || rule_proxy
}

/// The operator's own `outbound` section with its proxy replaced by WARP's;
/// rules, default action and `send_from` stay as written. `Err` when there is
/// nothing for `--rules` to act on.
pub fn outbound_for_rules(existing: Option<&Value>, listen: std::net::SocketAddr) -> Result<Value> {
    let existing = existing
        .filter(|o| !o.is_null())
        .ok_or_else(|| anyhow!("there is no `outbound` section: write the rules that should go through WARP first (action \"proxy\"), or use --all"))?;
    if !outbound_has_proxy_rule(existing) {
        bail!("the `outbound` section has no rule with action \"proxy\" and its default action is not \"proxy\": nothing would go through WARP; add the rules first, or use --all");
    }
    let mut o = existing.clone();
    o["enabled"] = json!(true);
    o["protocol"] = json!("socks5");
    o["address"] = json!(listen.ip().to_string());
    o["port"] = json!(listen.port());
    o["username"] = json!("");
    o["password"] = json!("");
    Ok(o)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr() -> std::net::SocketAddr {
        "127.0.0.1:40000".parse().unwrap()
    }

    #[test]
    fn default_is_off_and_valid() {
        let c = WarpConfig::default();
        assert!(!c.enabled);
        c.validate().unwrap();
        assert_eq!(c.listen_addr().unwrap(), addr());
    }

    #[test]
    fn the_proxy_stays_on_loopback() {
        for bad in ["0.0.0.0:40000", "10.0.0.1:40000", "[::]:40000", "127.0.0.1:0", "127.0.0.1", "nonsense"] {
            let c = WarpConfig { listen: bad.into(), ..Default::default() };
            assert!(c.validate().is_err(), "{bad} must be refused");
        }
        for ok in ["127.0.0.1:1080", "[::1]:40000", "127.5.5.5:40001"] {
            let c = WarpConfig { listen: ok.into(), ..Default::default() };
            c.validate().unwrap();
        }
    }

    #[test]
    fn endpoint_is_host_port() {
        let mut c = WarpConfig::default();
        for ok in ["engage.cloudflareclient.com:2408", "162.159.192.1:500", "[2606:4700:d0::a29f:c001]:2408"] {
            c.endpoint = ok.into();
            c.validate().unwrap();
        }
        for bad in ["engage.cloudflareclient.com", "host:0", "host:99999", ":2408"] {
            c.endpoint = bad.into();
            assert!(c.validate().is_err(), "{bad}");
        }
    }

    #[test]
    fn section_parses_with_missing_fields_and_rejects_unknown_modes() {
        let c: WarpConfig = serde_json::from_value(json!({"enabled": true, "mode": "all"})).unwrap();
        assert!(c.enabled && c.mode == WarpMode::All);
        assert_eq!(c.listen, DEFAULT_LISTEN);
        assert!(serde_json::from_value::<WarpConfig>(json!({"mode": "some"})).is_err());
    }

    #[test]
    fn all_mode_has_no_way_out_but_the_proxy() {
        let o = outbound_for_all(addr());
        assert_eq!(o["default_action"], "proxy");
        assert_eq!(o["rules"], json!([]));
        assert!(outbound_points_at(&o, addr()));
        // The section parses as the server's own type would (checked in ostp-server's tests).
        assert_eq!(o["protocol"], "socks5");
    }

    #[test]
    fn rules_mode_keeps_the_operators_rules_and_swaps_only_the_proxy() {
        let mine = json!({
            "enabled": false, "protocol": "http", "address": "203.0.113.5", "port": 3128,
            "username": "u", "password": "p",
            "rules": [
                {"domain_suffix": ["example.com"], "action": "proxy"},
                {"ip_cidr": ["10.0.0.0/8"], "action": "direct", "send_from": "192.0.2.1"}
            ],
            "default_action": "direct"
        });
        let o = outbound_for_rules(Some(&mine), addr()).unwrap();
        assert_eq!(o["rules"], mine["rules"]);
        assert_eq!(o["default_action"], "direct");
        assert_eq!(o["protocol"], "socks5");
        assert_eq!(o["address"], "127.0.0.1");
        assert_eq!(o["port"], 40000);
        assert_eq!(o["username"], "");
        assert_eq!(o["password"], "");
        assert_eq!(o["enabled"], true);
        assert!(outbound_points_at(&o, addr()));
        assert!(!outbound_points_at(&mine, addr()));
    }

    #[test]
    fn rules_mode_refuses_when_nothing_would_go_through_warp() {
        assert!(outbound_for_rules(None, addr()).is_err());
        assert!(outbound_for_rules(Some(&Value::Null), addr()).is_err());
        let none = json!({"enabled": true, "rules": [{"domain_suffix": ["a.com"], "action": "direct"}], "default_action": "direct"});
        assert!(outbound_for_rules(Some(&none), addr()).is_err());
        let default_proxy = json!({"enabled": true, "rules": [], "default_action": "proxy"});
        assert!(outbound_for_rules(Some(&default_proxy), addr()).is_ok());
        // The server reads a missing default action as "proxy".
        let missing = json!({"enabled": true, "rules": []});
        assert!(outbound_for_rules(Some(&missing), addr()).is_ok());
        let only_block = json!({"rules": [{"ip_cidr": ["10.0.0.0/8"], "action": "block"}], "default_action": "direct"});
        assert!(outbound_for_rules(Some(&only_block), addr()).is_err());
    }
}
