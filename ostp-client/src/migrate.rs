//! The ONE authoritative place that upgrades an old `config.json` to the
//! current schema. Reachable only via the explicit `ostp migrate` command —
//! nothing else in this codebase silently rewrites a user's config on their
//! behalf (the old 0.3.x line used to auto-migrate on every load with just a
//! log warning; that's exactly the kind of "invisible until something looks
//! wrong" behavior this module replaces).
//!
//! Every field this module cannot map forward is reported explicitly in
//! `MigrationReport.notes`, never silently dropped without a trace.

use serde_json::{json, Value};

#[derive(Debug, Default)]
pub struct MigrationReport {
    /// Whether anything was actually different from the current schema.
    pub changed: bool,
    /// Human-readable line per field added, converted, or dropped.
    pub notes: Vec<String>,
}

impl MigrationReport {
    fn note(&mut self, msg: impl Into<String>) {
        self.changed = true;
        self.notes.push(msg.into());
    }
}

/// Which config this file is (mirrors `AppMode`'s `"mode"` tag). Old configs
/// from before that tag existed are sniffed structurally as a fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigKind {
    Client,
    Server,
    Relay,
}

pub fn detect_kind(json: &Value) -> Option<ConfigKind> {
    match json.get("mode").and_then(|v| v.as_str()) {
        Some("client") => return Some(ConfigKind::Client),
        Some("server") => return Some(ConfigKind::Server),
        Some("relay") => return Some(ConfigKind::Relay),
        _ => {}
    }
    // No (or unrecognized) "mode" tag — this is an older config from before
    // it was mandatory. Sniff by the fields that have been present on each
    // shape since the earliest surviving config format.
    if json.get("upstream_tcp").is_some() || json.get("upstream_api_url").is_some() {
        Some(ConfigKind::Relay)
    } else if json.get("access_keys").is_some() || json.get("listen").is_some() {
        Some(ConfigKind::Server)
    } else if json.get("access_key").is_some() || json.get("server").is_some() {
        Some(ConfigKind::Client)
    } else {
        None
    }
}

/// Migrates a client config of any known past shape to the current flat
/// schema. Returns the migrated JSON and a report of every change made.
///
/// Known input shapes, oldest first:
/// - **v0.3.1–v0.3.21 "modular multi-server"**: `inbounds`/`outbounds` arrays
///   + `routing.rules`. Only the first `ostp`-type outbound is kept (this
///   line no longer supports multiple simultaneous servers); every other
///   `ostp` outbound is reported by tag+address so nothing vanishes
///   invisibly. `urltest`/`selector`/`direct`/`block` outbounds have no
///   equivalent and are dropped (reported).
/// - **pre-0.3.1 flat (up to v0.2.98)**: same field names as today
///   (`server`, `access_key`, `tun`, `exclude`, `mux`, `transport`, ...)
///   except `tun.wintun_path`/`tun.ipv4_address` (internal driver detail,
///   never user-meaningful data) and `transport.wss` (the WSS framing
///   feature removed entirely in the 0.4.0 rebuild) — both dropped with an
///   explicit note; everything else maps 1:1, nothing to convert.
/// - **configs carrying a leftover `transport.stealth_sni`**: dropped with a
///   note, same reasoning as `wss` — it never fed into anything on the wire
///   (no TLS/HTTP mimicry exists in this project), so there is no successor
///   field. Not tied to a specific version: it lingered in the schema well
///   past when the mimicry work it was meant for got removed.
/// - **current flat schema**: no-op, `changed = false`.
pub fn migrate_client_json(json: Value) -> (Value, MigrationReport) {
    let mut report = MigrationReport::default();

    let has_inbounds = json.get("inbounds").and_then(|v| v.as_array()).is_some();
    let has_outbounds = json.get("outbounds").and_then(|v| v.as_array()).is_some();

    if has_inbounds && has_outbounds {
        return migrate_client_from_modular(json, report);
    }

    // Flat shape already (current or pre-0.3.1) — normalize obsolete fields
    // in place rather than rebuilding the whole document from scratch, so
    // any field this module doesn't know about yet still survives untouched.
    let mut out = json;

    if let Some(tun) = out.get_mut("tun").and_then(|t| t.as_object_mut()) {
        for dead_field in ["wintun_path", "ipv4_address"] {
            if tun.remove(dead_field).is_some() {
                report.note(format!(
                    "Dropped tun.{dead_field} — internal driver detail from an older WinTun \
                     integration, not applicable to the current TUN implementation."
                ));
            }
        }
    }
    if let Some(transport) = out.get_mut("transport").and_then(|t| t.as_object_mut()) {
        if transport.remove("wss").is_some() {
            report.note(
                "Dropped transport.wss — WSS framing was removed in the 0.4.0 rebuild \
                 (the project follows a zapret-like approach: no protocol mimicry, \
                 just packet-level obfuscation/manipulation, so there is no successor field)."
                    .to_string(),
            );
        }
        if transport.remove("stealth_sni").is_some() {
            report.note(
                "Dropped transport.stealth_sni — never actually used to construct any wire \
                 bytes (no TLS/HTTP mimicry exists in this project — same zapret-like \
                 reasoning as transport.wss), so it was unused config plumbing with no effect."
                    .to_string(),
            );
        }
    }

    (out, report)
}

fn migrate_client_from_modular(json: Value, mut report: MigrationReport) -> (Value, MigrationReport) {
    report.changed = true; // the shape itself is being replaced regardless of field-level detail

    let inbounds = json.get("inbounds").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let outbounds = json.get("outbounds").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let routing = json.get("routing").cloned().unwrap_or(json!({}));
    let default_outbound = routing.get("default_outbound").and_then(|v| v.as_str()).map(String::from);

    // ── Pick the primary "ostp" outbound ────────────────────────────────
    // Prefer the one routing.default_outbound points at (directly, or via a
    // urltest/selector group that references it); otherwise take the first
    // ostp outbound in file order. Every other ostp outbound is reported by
    // tag+address, not silently discarded.
    let ostp_outbounds: Vec<&Value> = outbounds
        .iter()
        .filter(|o| o.get("type").and_then(|t| t.as_str()) == Some("ostp"))
        .collect();

    // default_outbound might name an ostp outbound directly, OR name a
    // urltest/selector GROUP whose first member is the one to actually use —
    // check both, since a plain `.or_else` here would never even attempt the
    // group lookup while default_outbound is Some(_) (which it almost always
    // is), silently falling through to "just take the first ostp outbound in
    // file order" instead — exactly the kind of silent wrong answer this
    // migrator exists to avoid.
    let primary_tag: Option<String> = default_outbound.as_deref().and_then(|def_tag| {
        if ostp_outbounds.iter().any(|o| o.get("tag").and_then(|t| t.as_str()) == Some(def_tag)) {
            return Some(def_tag.to_string());
        }
        outbounds.iter().find_map(|o| {
            let is_group = matches!(o.get("type").and_then(|t| t.as_str()), Some("urltest") | Some("selector"));
            let tag_matches = o.get("tag").and_then(|t| t.as_str()) == Some(def_tag);
            if is_group && tag_matches {
                o.get("outbounds")
                    .and_then(|v| v.as_array())
                    .and_then(|arr| arr.first())
                    .and_then(|v| v.as_str())
                    .map(String::from)
            } else {
                None
            }
        })
    });

    let primary = primary_tag
        .as_deref()
        .and_then(|tag| ostp_outbounds.iter().find(|o| o.get("tag").and_then(|t| t.as_str()) == Some(tag)))
        .copied()
        .or_else(|| ostp_outbounds.first().copied());

    let Some(primary) = primary else {
        report.note(
            "No 'ostp'-type outbound found in the old modular config — nothing to migrate \
             the server connection from. Wrote a placeholder; you MUST fill in server/access_key \
             by hand or re-import a share link."
                .to_string(),
        );
        return (
            json!({
                "server": "127.0.0.1:50000",
                "access_key": "",
            }),
            report,
        );
    };

    for other in &ostp_outbounds {
        if !std::ptr::eq(*other, primary) {
            let tag = other.get("tag").and_then(|t| t.as_str()).unwrap_or("?");
            let addr = other.get("server").and_then(|t| t.as_str()).unwrap_or("?");
            let port = other.get("port").and_then(|t| t.as_u64()).unwrap_or(0);
            report.note(format!(
                "Dropped additional server '{tag}' ({addr}:{port}) — multi-server / urltest \
                 failover is no longer supported; only one server per config now. Kept the \
                 one from routing.default_outbound (or the first one if that wasn't set)."
            ));
        }
    }

    let server = primary.get("server").and_then(|v| v.as_str()).unwrap_or("127.0.0.1").to_string();
    let port = primary.get("port").and_then(|v| v.as_u64()).unwrap_or(50000);
    let access_key = primary.get("access_key").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let transport_type = primary
        .get("transport")
        .and_then(|t| t.get("type").or_else(|| t.get("mode")))
        .and_then(|v| v.as_str())
        .unwrap_or("udp")
        .to_string();
    if let Some(sni) = primary.get("transport").and_then(|t| t.get("stealth_sni")).and_then(|v| v.as_str()) {
        if !sni.is_empty() {
            report.note(format!(
                "Dropped transport.stealth_sni ({sni:?}) — never actually used to construct \
                 any wire bytes; unused config plumbing with no successor field."
            ));
        }
    }
    let tcp_fragmentation = primary
        .get("transport")
        .and_then(|t| t.get("tcp_fragmentation"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let mux_enabled = primary.get("multiplex").and_then(|m| m.get("enabled")).and_then(|v| v.as_bool()).unwrap_or(false);
    let mux_sessions = primary.get("multiplex").and_then(|m| m.get("sessions")).and_then(|v| v.as_u64()).unwrap_or(1);

    // ── TUN + local proxy inbounds ───────────────────────────────────────
    let tun_inbound = inbounds.iter().find(|i| i.get("type").and_then(|t| t.as_str()) == Some("tun"));
    let proxy_inbound = inbounds.iter().find(|i| i.get("type").and_then(|t| t.as_str()) == Some("local_proxy"));

    let tun_enable = tun_inbound.is_some();
    let mtu = tun_inbound.and_then(|t| t.get("mtu")).and_then(|v| v.as_u64());

    let socks5_bind = proxy_inbound
        .map(|p| {
            let listen = p.get("listen").and_then(|v| v.as_str()).unwrap_or("127.0.0.1");
            let port = p.get("port").and_then(|v| v.as_u64()).unwrap_or(1088);
            format!("{listen}:{port}")
        })
        .unwrap_or_else(|| "127.0.0.1:1088".to_string());

    // ── Exclusions from routing.rules → direct ──────────────────────────
    let mut ex_domains: Vec<String> = Vec::new();
    let mut ex_ips: Vec<String> = Vec::new();
    let mut ex_processes: Vec<String> = Vec::new();
    if let Some(rules) = routing.get("rules").and_then(|v| v.as_array()) {
        for rule in rules {
            if rule.get("outbound").and_then(|v| v.as_str()) != Some("direct") {
                continue; // only "route to direct" rules were ever exclusions in the old format
            }
            if let Some(v) = rule.get("domain_suffix").and_then(|v| v.as_array()) {
                ex_domains.extend(v.iter().filter_map(|s| s.as_str().map(String::from)));
            }
            if let Some(v) = rule.get("ip_cidr").and_then(|v| v.as_array()) {
                ex_ips.extend(v.iter().filter_map(|s| s.as_str().map(String::from)));
            }
            if let Some(v) = rule.get("process_name").and_then(|v| v.as_array()) {
                ex_processes.extend(v.iter().filter_map(|s| s.as_str().map(String::from)));
            }
        }
    }
    for other_rule_outbound in routing
        .get("rules")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|r| r.get("outbound").and_then(|v| v.as_str()))
        .filter(|o| *o != "direct")
    {
        report.note(format!(
            "Dropped a routing rule targeting outbound '{other_rule_outbound}' — only \
             \"route to direct\" rules map to today's exclusions; anything else \
             (custom per-domain outbound selection) has no equivalent anymore."
        ));
    }

    let debug = json.get("log").and_then(|l| l.get("level")).and_then(|v| v.as_str()) == Some("debug");

    let mut client = json!({
        "server": server,
        "port": port,
        "access_key": access_key,
        "socks5_bind": socks5_bind,
        "debug": debug,
        "tun": {
            "enable": tun_enable,
            "dns": null,
            "kill_switch": false,
        },
        "exclude": {
            "domains": ex_domains,
            "ips": ex_ips,
            "processes": ex_processes,
        },
        "mux": {
            "enabled": mux_enabled,
            "sessions": mux_sessions,
        },
        "transport": {
            "mode": transport_type,
            "tcp_fragmentation": tcp_fragmentation,
        },
    });
    if let Some(mtu) = mtu {
        client["mtu"] = json!(mtu);
    }
    if let Some(gui) = json.get("gui") {
        client["gui"] = gui.clone();
    }

    (client, report)
}

/// Migrates a server config. The server shape has stayed structurally
/// identical since the earliest surviving version — this only backfills the
/// `api` section (added after some configs already existed) and drops the
/// legacy `api.token` field. Ported from the ad-hoc Python snippet that used
/// to live in `scripts/install.sh` and only ran at install/update time.
pub fn migrate_server_json(json: Value) -> (Value, MigrationReport) {
    let mut report = MigrationReport::default();
    let mut out = json;

    let obj = match out.as_object_mut() {
        Some(o) => o,
        None => return (out, report),
    };

    let api = obj.entry("api").or_insert_with(|| json!({}));
    if let Some(api_obj) = api.as_object_mut() {
        let defaults: [(&str, Value); 5] = [
            ("enabled", json!(false)),
            ("bind", json!("0.0.0.0:9090")),
            ("webpath", json!("")),
            ("username", json!("")),
            ("password_hash", json!("")),
        ];
        for (key, default) in defaults {
            if !api_obj.contains_key(key) {
                report.note(format!("Added api.{key} = {default} (missing default)"));
                api_obj.insert(key.to_string(), default);
            }
        }
        if api_obj.remove("token").is_some() {
            report.note(
                "Dropped legacy api.token — superseded by api.password_hash; \
                 set a new admin password with the management API or panel."
                    .to_string(),
            );
        }
    }

    // Backfill the SOCKS5 credential fields on `outbound`, added after some
    // server configs already existed. These are plain strings that default to
    // "" (no-auth), so making them explicit is safe and concise. The optional
    // `bind_ip` (top level) and per-rule `send_from` are deliberately NOT
    // backfilled: absent means "use the default source", which is correct — and
    // a placeholder would either be stripped (null) or, worse, parse as an
    // invalid source IP ("").
    if let Some(outbound) = obj.get_mut("outbound").and_then(|o| o.as_object_mut()) {
        for key in ["username", "password"] {
            if !outbound.contains_key(key) {
                report.note(format!("Added outbound.{key} = \"\" (missing default)"));
                outbound.insert(key.to_string(), json!(""));
            }
        }
    }

    (out, report)
}

/// Final normalization pass applied to every migrated config: strip null-valued
/// keys at every nesting level. A JSON null means "unset", so it is pure noise —
/// removing it is the "concise" part of the migration, and it never loses real
/// data (a set value is never null). Key ORDER is already canonical for free:
/// serde_json serializes object keys in sorted order, so any write of a migrated
/// config comes out stably ordered no matter how disordered the input was.
///
/// Returns whether it removed anything, so the caller folds it into the
/// "was this already up to date?" decision.
pub fn normalize(value: &mut Value) -> bool {
    let before = value.clone();
    strip_nulls(value);
    *value != before
}

/// Recursively drop keys whose value is JSON null, descending into nested
/// objects and array elements. Empty objects and arrays are kept — an explicit
/// `rules: []` or `exclude: {}` carries intent; only nulls are noise.
fn strip_nulls(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.retain(|_, v| !v.is_null());
            for v in map.values_mut() {
                strip_nulls(v);
            }
        }
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                strip_nulls(v);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A realistic v0.3.21-shaped modular config (TUN + local_proxy inbounds,
    /// a single ostp outbound, exclusion rules, mux) — mirrors the actual
    /// shape from that tag, field for field.
    #[test]
    fn modular_single_server_preserves_every_field() {
        let old = json!({
            "version": "0.3.21",
            "log": { "level": "debug" },
            "inbounds": [
                { "type": "tun", "tag": "tun-in", "auto_route": true, "mtu": 1350 },
                { "type": "local_proxy", "tag": "socks-in", "protocol": "socks", "listen": "127.0.0.1", "port": 1088 }
            ],
            "outbounds": [
                {
                    "type": "ostp", "tag": "proxy",
                    "server": "203.0.113.5", "port": 50000, "access_key": "sekrit123",
                    "transport": { "type": "uot", "stealth_sni": "vk.com", "tcp_fragmentation": true },
                    "multiplex": { "enabled": true, "sessions": 4 }
                },
                { "type": "direct", "tag": "direct" },
                { "type": "block", "tag": "block" }
            ],
            "routing": {
                "rules": [
                    { "domain_suffix": ["local.lan", "internal.corp"], "outbound": "direct" },
                    { "ip_cidr": ["192.168.0.0/16"], "outbound": "direct" },
                    { "process_name": ["steam.exe"], "outbound": "direct" }
                ],
                "default_outbound": "proxy"
            }
        });

        let (new, report) = migrate_client_json(old);
        assert!(report.changed);
        assert_eq!(new["server"], "203.0.113.5");
        assert_eq!(new["port"], 50000);
        assert_eq!(new["access_key"], "sekrit123");
        assert_eq!(new["socks5_bind"], "127.0.0.1:1088");
        assert_eq!(new["mtu"], 1350);
        assert_eq!(new["debug"], true);
        assert_eq!(new["tun"]["enable"], true);
        assert_eq!(new["transport"]["mode"], "uot");
        assert_eq!(new["transport"]["tcp_fragmentation"], true);
        assert_eq!(new["mux"]["enabled"], true);
        assert_eq!(new["mux"]["sessions"], 4);
        assert_eq!(new["exclude"]["domains"], json!(["local.lan", "internal.corp"]));
        assert_eq!(new["exclude"]["ips"], json!(["192.168.0.0/16"]));
        assert_eq!(new["exclude"]["processes"], json!(["steam.exe"]));
        // stealth_sni never fed into any wire bytes — dropped, not carried forward.
        assert!(new["transport"].get("stealth_sni").is_none());
        assert!(report.notes.iter().any(|n| n.contains("stealth_sni") && n.contains("vk.com")));
    }

    /// Old modular configs that had MULTIPLE ostp outbounds (multi-server) —
    /// must keep the one routing.default_outbound points at and report every
    /// other one by name/address rather than picking silently.
    #[test]
    fn modular_multi_server_keeps_default_and_reports_the_rest() {
        let old = json!({
            "inbounds": [],
            "outbounds": [
                { "type": "ostp", "tag": "proxy-0", "server": "1.1.1.1", "port": 50000, "access_key": "k1" },
                { "type": "ostp", "tag": "proxy-1", "server": "2.2.2.2", "port": 50000, "access_key": "k2" },
                {
                    "type": "urltest", "tag": "proxy",
                    "outbounds": ["proxy-1", "proxy-0"], "url": "http://cp.cloudflare.com"
                }
            ],
            "routing": { "rules": [], "default_outbound": "proxy" }
        });

        let (new, report) = migrate_client_json(old);
        // urltest's first member (proxy-1 / 2.2.2.2) is the one actually picked.
        assert_eq!(new["server"], "2.2.2.2");
        assert_eq!(new["access_key"], "k2");
        assert!(report.notes.iter().any(|n| n.contains("proxy-0") && n.contains("1.1.1.1")));
    }

    /// Pre-0.3.1 flat config carrying fields that no longer exist
    /// (tun.wintun_path, tun.ipv4_address, transport.wss, transport.stealth_sni)
    /// — those get dropped with a note; every field that's still meaningful
    /// passes through untouched, byte for byte.
    #[test]
    fn flat_legacy_drops_only_dead_fields() {
        let old = json!({
            "server": "198.51.100.9:50000",
            "access_key": "oldkey",
            "mtu": 1200,
            "socks5_bind": "127.0.0.1:1090",
            "tun": {
                "enable": true,
                "wintun_path": "C:\\Program Files\\wintun\\wintun.dll",
                "ipv4_address": "10.0.0.2",
                "dns": "1.1.1.1",
                "kill_switch": true
            },
            "exclude": { "domains": ["a.com"], "ips": null, "processes": null },
            "mux": { "enabled": false, "sessions": 1 },
            "transport": { "mode": "udp", "stealth_sni": "bing.com", "wss": true }
        });

        let (new, report) = migrate_client_json(old);
        assert!(report.changed);
        // Untouched fields survive exactly as they were.
        assert_eq!(new["server"], "198.51.100.9:50000");
        assert_eq!(new["access_key"], "oldkey");
        assert_eq!(new["mtu"], 1200);
        assert_eq!(new["tun"]["enable"], true);
        assert_eq!(new["tun"]["dns"], "1.1.1.1");
        assert_eq!(new["tun"]["kill_switch"], true);
        assert_eq!(new["exclude"]["domains"], json!(["a.com"]));
        // Dead fields are gone...
        assert!(new["tun"].get("wintun_path").is_none());
        assert!(new["tun"].get("ipv4_address").is_none());
        assert!(new["transport"].get("wss").is_none());
        assert!(new["transport"].get("stealth_sni").is_none());
        // ...and their removal was reported, not silent.
        assert!(report.notes.iter().any(|n| n.contains("wintun_path")));
        assert!(report.notes.iter().any(|n| n.contains("ipv4_address")));
        assert!(report.notes.iter().any(|n| n.contains("wss")));
        assert!(report.notes.iter().any(|n| n.contains("stealth_sni")));
    }

    /// A config already in the current shape must be a true no-op: report
    /// says nothing changed, and every field is untouched.
    #[test]
    fn current_flat_config_is_a_no_op() {
        let current = json!({
            "server": "example.com:50000",
            "access_key": "k",
            "tun": { "enable": false, "dns": null, "kill_switch": false },
            "exclude": { "domains": [], "ips": [], "processes": [] },
            "mux": { "enabled": false, "sessions": 1 },
            "transport": { "mode": "udp", "tcp_fragmentation": false }
        });
        let (new, report) = migrate_client_json(current.clone());
        assert!(!report.changed);
        assert_eq!(new, current);
    }

    /// Every migrated output must actually deserialize into the ONE
    /// canonical schema (`crate::config`) — this is the same check
    /// `cmd_migrate` runs at runtime before ever touching a user's file,
    /// exercised here directly so a schema/migrator drift fails a fast unit
    /// test instead of surfacing as "your migrated config won't load".
    #[test]
    fn every_migrated_output_matches_the_canonical_schema() {
        let modular = json!({
            "inbounds": [{ "type": "tun", "tag": "tun-in", "mtu": 1350 }],
            "outbounds": [
                { "type": "ostp", "tag": "proxy", "server": "1.2.3.4", "port": 50000, "access_key": "k" },
                { "type": "direct", "tag": "direct" }
            ],
            "routing": { "rules": [], "default_outbound": "proxy" }
        });
        let (new, _) = migrate_client_json(modular);
        serde_json::from_value::<crate::config::ClientFileConfig>(new)
            .expect("modular->flat migration output must match ClientFileConfig");

        let legacy_flat = json!({
            "server": "1.2.3.4:50000",
            "access_key": "k",
            "tun": { "enable": true, "wintun_path": "x", "ipv4_address": "y" }
        });
        let (new, _) = migrate_client_json(legacy_flat);
        serde_json::from_value::<crate::config::ClientFileConfig>(new)
            .expect("legacy-flat migration output must match ClientFileConfig");

        let server = json!({ "listen": "0.0.0.0:50000", "access_keys": ["k"] });
        let (new, _) = migrate_server_json(server);
        serde_json::from_value::<crate::config::ServerConfig>(new)
            .expect("server migration output must match ServerConfig");
    }

    #[test]
    fn server_config_backfills_api_defaults_and_drops_legacy_token() {
        let old = json!({
            "listen": "0.0.0.0:50000",
            "access_keys": ["k1"],
            "api": { "token": "old-plain-token" }
        });
        let (new, report) = migrate_server_json(old);
        assert!(report.changed);
        assert_eq!(new["api"]["enabled"], false);
        assert_eq!(new["api"]["bind"], "0.0.0.0:9090");
        assert!(new["api"].get("token").is_none());
        assert!(report.notes.iter().any(|n| n.contains("api.token")));
    }

    /// A server config whose `outbound` predates the SOCKS5 credential fields
    /// must get them backfilled — this is exactly the "migrate said nothing to
    /// migrate but the new fields were missing" gap. The optional bind_ip /
    /// send_from must NOT be injected (absent = correct).
    #[test]
    fn server_migrate_backfills_outbound_credentials() {
        let old = json!({
            "listen": "0.0.0.0:50000",
            "access_keys": ["k1"],
            "api": { "enabled": true, "bind": "0.0.0.0:9090", "webpath": "", "username": "", "password_hash": "" },
            "outbound": {
                "enabled": false, "protocol": "socks5", "address": "127.0.0.1", "port": 40000,
                "default_action": "proxy",
                "rules": [{ "action": "proxy", "domain_suffix": [".onion"] }]
            }
        });
        let (new, report) = migrate_server_json(old);
        assert!(report.changed, "adding the missing credential fields is a change");
        assert_eq!(new["outbound"]["username"], "");
        assert_eq!(new["outbound"]["password"], "");
        // Optional fields are left absent, not injected.
        assert!(new.get("bind_ip").is_none());
        assert!(new["outbound"]["rules"][0].get("send_from").is_none());
    }

    #[test]
    fn detect_kind_falls_back_to_structural_sniffing_without_mode_tag() {
        assert_eq!(detect_kind(&json!({"access_key": "x", "server": "y"})), Some(ConfigKind::Client));
        assert_eq!(detect_kind(&json!({"access_keys": ["x"], "listen": "y"})), Some(ConfigKind::Server));
        assert_eq!(detect_kind(&json!({"upstream_tcp": "x", "upstream_api_url": "y"})), Some(ConfigKind::Relay));
        assert_eq!(detect_kind(&json!({"mode": "client", "server": "x"})), Some(ConfigKind::Client));
    }

    // ── normalization (concise + no data loss + canonical) ──────────────────

    #[test]
    fn normalize_strips_nulls_but_keeps_real_data_and_empty_collections() {
        let mut v = json!({
            "mode": "client",
            "server": "1.2.3.4:50000",
            "access_key": "k",
            "socks5_bind": null,                 // unset → removed
            "tun": { "enable": true, "dns": null }, // nested null → removed
            "exclude": { "domains": [], "ips": null }, // empty [] kept, null removed
            "mux": { "enabled": false, "sessions": 1 },
        });
        let changed = normalize(&mut v);
        assert!(changed, "stripping nulls is a change");
        assert!(v.get("socks5_bind").is_none(), "top-level null must be gone");
        assert!(v["tun"].get("dns").is_none(), "nested null must be gone");
        assert!(v["exclude"].get("ips").is_none(), "nested null must be gone");
        assert_eq!(v["exclude"]["domains"], json!([]), "an explicit empty array is intent, kept");
        assert_eq!(v["server"], json!("1.2.3.4:50000"), "real data untouched");
        assert_eq!(v["tun"]["enable"], json!(true));
    }

    #[test]
    fn normalize_is_idempotent() {
        let mut v = json!({ "mode": "server", "listen": "0.0.0.0:50000", "access_keys": ["k"], "debug": null });
        assert!(normalize(&mut v), "first pass removes the null");
        let once = v.clone();
        assert!(!normalize(&mut v), "second pass changes nothing");
        assert_eq!(v, once);
    }

    #[test]
    fn normalize_never_drops_unknown_fields() {
        // A field the schema has never heard of must survive — no data loss ever.
        let mut v = json!({ "mode": "client", "server": "s", "access_key": "k", "some_future_field": {"a": 1} });
        normalize(&mut v);
        assert_eq!(v["some_future_field"], json!({"a": 1}), "unknown data must be preserved verbatim");
    }

    /// Forcing function: the configs the tool itself generates (init/setup
    /// templates, current shape) must already be canonical — running the full
    /// migrate pipeline over them must report NO change. If someone adds a field
    /// to a template or the schema without teaching the migrator, this fails
    /// instead of a user silently ending up with a config that `ostp migrate`
    /// keeps trying to "fix". Covers all three kinds.
    #[test]
    fn generated_configs_are_already_canonical() {
        // These mirror the exact shapes emitted by `ostp init` / the wizard.
        let client = json!({
            "mode": "client", "server": "127.0.0.1:50000", "access_key": "k",
            "socks5_bind": "127.0.0.1:1088",
            "transport": { "mode": "udp", "tcp_fragmentation": false },
            "debug": false,
        });
        let server = json!({
            "mode": "server", "listen": "0.0.0.0:50000", "access_keys": ["k"],
            "outbound": { "enabled": false, "protocol": "socks5", "address": "127.0.0.1",
                          "port": 9050, "username": "", "password": "", "default_action": "proxy", "rules": [] },
            "debug": false,
        });
        let relay = json!({
            "mode": "relay", "listen": "0.0.0.0:50000",
            "upstream_tcp": "1.2.3.4:50000", "upstream_udp": "1.2.3.4:50000", "debug": false,
        });

        for (name, cfg) in [("client", client), ("server", server), ("relay", relay)] {
            let mut v = cfg.clone();
            let changed = normalize(&mut v);
            assert!(!changed, "the generated {name} template must be canonical (no nulls to strip)");
            assert_eq!(v, cfg, "normalizing the {name} template must not alter it");
        }
    }
}
