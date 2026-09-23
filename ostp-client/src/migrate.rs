//! Upgrades a `config.json` of any past shape to the current schema.
//!
//! Configs carry a schema version (`config_version`). Migration runs the
//! ordered steps from the file's version up to [`CURRENT_VERSION`], each step
//! exactly once, then stamps the new version, so running it again is a no-op.
//! Files from before the stamp existed are dated by their shape.
//!
//! What changed is not hand-reported: [`Migration::changes`] is a structural
//! diff of input against output, and each step adds the reason for what it
//! did. Keys the schema does not know (typos, leftovers) are found by
//! round-tripping through the typed config — no key list to maintain — and
//! reported with a suggestion, never deleted.
//!
//! Reachable only through `ostp migrate`: nothing rewrites a user's config
//! behind their back.

use anyhow::{anyhow, bail, Result};
use serde_json::{json, Map, Value};

/// Schema versions:
/// - `0`: 0.3.1–0.3.21 client, modular `inbounds`/`outbounds`/`routing`.
/// - `1`: flat configs up to 0.4.5, no version stamp; may carry settings of
///   features that no longer exist.
/// - `2`: 0.4.6+, stamped `config_version`.
pub const CURRENT_VERSION: u32 = 2;

/// Which config this file is (mirrors `AppMode`'s `"mode"` tag). Old configs
/// from before that tag existed are sniffed structurally as a fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigKind {
    Client,
    Server,
    Relay,
}

impl ConfigKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ConfigKind::Client => "client",
            ConfigKind::Server => "server",
            ConfigKind::Relay => "relay",
        }
    }
}

pub fn detect_kind(json: &Value) -> Option<ConfigKind> {
    match json.get("mode").and_then(|v| v.as_str()) {
        Some("client") => return Some(ConfigKind::Client),
        Some("server") => return Some(ConfigKind::Server),
        Some("relay") => return Some(ConfigKind::Relay),
        _ => {}
    }
    // No (or unrecognized) "mode" tag — an older config from before it was
    // mandatory. Sniff by the fields each shape has always had.
    if json.get("upstream_tcp").is_some() || json.get("upstream_api_url").is_some() {
        Some(ConfigKind::Relay)
    } else if json.get("access_keys").is_some() || json.get("listen").is_some() {
        Some(ConfigKind::Server)
    } else if json.get("access_key").is_some() || json.get("server").is_some() || json.get("outbounds").is_some() {
        Some(ConfigKind::Client)
    } else {
        None
    }
}

/// The schema version a file is at: its stamp, or dated by shape.
pub fn detect_version(json: &Value) -> u32 {
    if let Some(v) = json.get("config_version").and_then(|v| v.as_u64()) {
        return v as u32;
    }
    let modular = json.get("inbounds").is_some_and(|v| v.is_array()) && json.get("outbounds").is_some_and(|v| v.is_array());
    if modular { 0 } else { 1 }
}

// ── Steps ────────────────────────────────────────────────────────────────────

/// One schema change: applies to files of `kind` at version `from`.
struct Step {
    kind: ConfigKind,
    from: u32,
    title: &'static str,
    run: fn(&mut Value, &mut Vec<String>),
}

const STEPS: &[Step] = &[
    Step { kind: ConfigKind::Client, from: 0, title: "0.3.x modular client config to the flat format", run: client_modular_to_flat },
    Step { kind: ConfigKind::Client, from: 1, title: "remove settings of removed features", run: client_drop_removed },
    Step { kind: ConfigKind::Relay, from: 1, title: "remove relay-side authentication settings", run: relay_drop_auth },
];

fn remove_with_reason(obj: &mut Map<String, Value>, path: &str, key: &str, reason: &str, notes: &mut Vec<String>) {
    if obj.remove(key).is_some() {
        notes.push(format!("{path}{key}: {reason}"));
    }
}

fn client_drop_removed(v: &mut Value, notes: &mut Vec<String>) {
    if let Some(tun) = v.get_mut("tun").and_then(|t| t.as_object_mut()) {
        for key in ["wintun_path", "ipv4_address"] {
            remove_with_reason(tun, "tun.", key, "internal detail of an older WinTun integration; the current TUN sets it itself", notes);
        }
    }
    if let Some(t) = v.get_mut("transport").and_then(|t| t.as_object_mut()) {
        remove_with_reason(t, "transport.", "wss", "WSS framing was removed in 0.4.0; the TLS carrier is `transport.tls`", notes);
        remove_with_reason(t, "transport.", "stealth_sni", "never reached the wire; the real TLS server name is `transport.tls_sni`", notes);
    }
}

fn relay_drop_auth(v: &mut Value, notes: &mut Vec<String>) {
    if let Some(obj) = v.as_object_mut() {
        for key in ["upstream_api_url", "upstream_api_token", "sync_interval_secs"] {
            remove_with_reason(obj, "", key, "the relay no longer authenticates clients (the target server does, end to end)", notes);
        }
    }
}

/// 0.3.x kept one or more servers as `ostp` outbounds, the proxy and TUN as
/// inbounds, and exclusions as `routing.rules` pointing at `direct`.
fn client_modular_to_flat(v: &mut Value, notes: &mut Vec<String>) {
    let old = std::mem::take(v);
    let outbounds = old.get("outbounds").and_then(|x| x.as_array()).cloned().unwrap_or_default();
    let inbounds = old.get("inbounds").and_then(|x| x.as_array()).cloned().unwrap_or_default();
    let routing = old.get("routing").cloned().unwrap_or(json!({}));
    let tag_of = |o: &Value| o.get("tag").and_then(|t| t.as_str()).map(str::to_string);
    let is_ostp = |o: &&Value| o.get("type").and_then(|t| t.as_str()) == Some("ostp");
    let ostp: Vec<&Value> = outbounds.iter().filter(is_ostp).collect();

    // The server to keep: the one routing.default_outbound names, directly
    // or as the first member of a urltest/selector group; else the first.
    let wanted = routing.get("default_outbound").and_then(|d| d.as_str()).and_then(|d| {
        if ostp.iter().any(|o| tag_of(o).as_deref() == Some(d)) {
            return Some(d.to_string());
        }
        outbounds.iter().find_map(|o| {
            let group = matches!(o.get("type").and_then(|t| t.as_str()), Some("urltest" | "selector"));
            (group && tag_of(o).as_deref() == Some(d))
                .then(|| o.get("outbounds")?.as_array()?.first()?.as_str().map(str::to_string))
                .flatten()
        })
    });
    let primary = wanted
        .as_deref()
        .and_then(|t| ostp.iter().copied().find(|o| tag_of(o).as_deref() == Some(t)))
        .or_else(|| ostp.first().copied());

    let Some(primary) = primary else {
        notes.push("no `ostp` outbound found: server and access_key are empty and must be filled in (or re-import a share link)".into());
        *v = json!({ "mode": "client", "server": "", "access_key": "" });
        return;
    };
    for other in &ostp {
        if !std::ptr::eq(*other, primary) {
            notes.push(format!(
                "dropped server {:?} ({}:{}): only one server per config is supported now",
                tag_of(other).unwrap_or_default(),
                other.get("server").and_then(|s| s.as_str()).unwrap_or("?"),
                other.get("port").and_then(|p| p.as_u64()).unwrap_or(0)
            ));
        }
    }

    let host = primary.get("server").and_then(|s| s.as_str()).unwrap_or("");
    let port = primary.get("port").and_then(|p| p.as_u64()).unwrap_or(50000);
    let server = if host.contains(':') && !host.starts_with('[') { format!("[{host}]:{port}") } else { format!("{host}:{port}") };
    let t = primary.get("transport");
    let mode = t.and_then(|t| t.get("type").or_else(|| t.get("mode"))).and_then(|m| m.as_str()).unwrap_or("udp");
    if let Some(sni) = t.and_then(|t| t.get("stealth_sni")).and_then(|s| s.as_str()).filter(|s| !s.is_empty()) {
        notes.push(format!("transport.stealth_sni ({sni:?}) dropped: it never reached the wire"));
    }

    let tun = inbounds.iter().find(|i| i.get("type").and_then(|t| t.as_str()) == Some("tun"));
    let proxy = inbounds.iter().find(|i| i.get("type").and_then(|t| t.as_str()) == Some("local_proxy"));

    let (mut domains, mut ips, mut procs) = (Vec::<Value>::new(), Vec::<Value>::new(), Vec::<Value>::new());
    for rule in routing.get("rules").and_then(|r| r.as_array()).into_iter().flatten() {
        let target = rule.get("outbound").and_then(|o| o.as_str()).unwrap_or("");
        if target != "direct" {
            notes.push(format!("dropped a routing rule to outbound {target:?}: only rules to `direct` map to today's exclusions"));
            continue;
        }
        for (field, into) in [("domain_suffix", &mut domains), ("ip_cidr", &mut ips), ("process_name", &mut procs)] {
            into.extend(rule.get(field).and_then(|x| x.as_array()).into_iter().flatten().cloned());
        }
    }

    let mut out = json!({
        "mode": "client",
        "server": server,
        "access_key": primary.get("access_key").and_then(|k| k.as_str()).unwrap_or(""),
        "socks5_bind": proxy.map(|p| format!(
            "{}:{}",
            p.get("listen").and_then(|l| l.as_str()).unwrap_or("127.0.0.1"),
            p.get("port").and_then(|x| x.as_u64()).unwrap_or(1088)
        )).unwrap_or_else(|| "127.0.0.1:1088".into()),
        "debug": old.pointer("/log/level").and_then(|l| l.as_str()) == Some("debug"),
        "tun": { "enable": tun.is_some(), "kill_switch": false },
        "exclude": { "domains": domains, "ips": ips, "processes": procs },
        "mux": {
            "enabled": primary.pointer("/multiplex/enabled").and_then(|x| x.as_bool()).unwrap_or(false),
            "sessions": primary.pointer("/multiplex/sessions").and_then(|x| x.as_u64()).unwrap_or(1),
        },
        "transport": {
            "mode": mode,
            "tcp_fragmentation": t.and_then(|t| t.get("tcp_fragmentation")).and_then(|x| x.as_bool()).unwrap_or(false),
        },
    });
    if let Some(mtu) = tun.and_then(|t| t.get("mtu")).and_then(|m| m.as_u64()) {
        out["mtu"] = json!(mtu);
    }
    if let Some(gui) = old.get("gui") {
        out["gui"] = gui.clone();
    }
    notes.push(format!("kept server {server}"));
    *v = out;
}

// ── Driver ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum Change {
    Added { path: String, value: Value },
    Removed { path: String, value: Value },
    Changed { path: String, from: Value, to: Value },
}

impl std::fmt::Display for Change {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Change::Added { path, value } => write!(f, "+ {path} = {value}"),
            Change::Removed { path, value } => write!(f, "- {path} (was {value})"),
            Change::Changed { path, from, to } => write!(f, "~ {path}: {from} -> {to}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct UnknownKey {
    pub path: String,
    pub suggestion: Option<String>,
}

#[derive(Debug)]
pub struct StepReport {
    pub title: &'static str,
    pub from: u32,
    pub notes: Vec<String>,
}

#[derive(Debug)]
pub struct Migration {
    pub kind: ConfigKind,
    pub from_version: u32,
    pub output: Value,
    pub steps: Vec<StepReport>,
    pub changes: Vec<Change>,
    /// Keys the schema does not know. Kept in the output; ostp ignores them.
    pub unknown_keys: Vec<UnknownKey>,
}

impl Migration {
    pub fn is_up_to_date(&self) -> bool {
        self.changes.is_empty()
    }
}

/// Migrates any past config to the current schema. The output is checked
/// against the typed schema before it is returned.
pub fn migrate(input: Value) -> Result<Migration> {
    if !input.is_object() {
        bail!("the config is not a JSON object");
    }
    let kind = detect_kind(&input).ok_or_else(|| anyhow!("cannot tell whether this is a client, server or relay config"))?;
    let from_version = detect_version(&input);
    if from_version > CURRENT_VERSION {
        bail!(
            "this config is schema version {from_version}, written by a newer ostp (this one knows up to {CURRENT_VERSION}); update ostp instead of migrating"
        );
    }

    let mut out = input.clone();
    let mut steps = Vec::new();
    for version in from_version..CURRENT_VERSION {
        for step in STEPS.iter().filter(|s| s.from == version && s.kind == kind) {
            let mut notes = Vec::new();
            (step.run)(&mut out, &mut notes);
            steps.push(StepReport { title: step.title, from: version, notes });
        }
    }
    out["mode"] = json!(kind.as_str());
    out["config_version"] = json!(CURRENT_VERSION);
    strip_nulls(&mut out);

    let typed: crate::config::UnifiedConfig = serde_json::from_value(out.clone())
        .map_err(|e| anyhow!("the migrated config does not match the schema ({e}); nothing was written. This is a bug in the migrator, please report it"))?;
    let known = serde_json::to_value(&typed)?;
    let mut unknown_keys = Vec::new();
    find_unknown(&out, &known, "", &mut unknown_keys);

    let mut changes = Vec::new();
    diff(&input, &out, "", &mut changes);
    Ok(Migration { kind, from_version, output: out, steps, changes, unknown_keys })
}

/// A JSON null means "unset"; dropping it loses nothing. Empty objects and
/// arrays are kept: an explicit `rules: []` carries intent.
fn strip_nulls(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.retain(|_, v| !v.is_null());
            map.values_mut().for_each(strip_nulls);
        }
        Value::Array(arr) => arr.iter_mut().for_each(strip_nulls),
        _ => {}
    }
}

fn join(path: &str, key: &str) -> String {
    if path.is_empty() { key.to_string() } else { format!("{path}.{key}") }
}

fn diff(a: &Value, b: &Value, path: &str, out: &mut Vec<Change>) {
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            let mut keys: Vec<&String> = x.keys().chain(y.keys()).collect();
            keys.sort();
            keys.dedup();
            for k in keys {
                let p = join(path, k);
                match (x.get(k), y.get(k)) {
                    (Some(av), Some(bv)) => diff(av, bv, &p, out),
                    (Some(av), None) => out.push(Change::Removed { path: p, value: av.clone() }),
                    (None, Some(bv)) => out.push(Change::Added { path: p, value: bv.clone() }),
                    (None, None) => {}
                }
            }
        }
        (Value::Array(x), Value::Array(y)) if x.len() == y.len() => {
            for (i, (av, bv)) in x.iter().zip(y).enumerate() {
                diff(av, bv, &format!("{path}[{i}]"), out);
            }
        }
        _ if a != b => out.push(Change::Changed { path: path.to_string(), from: a.clone(), to: b.clone() }),
        _ => {}
    }
}

/// Every key of `value` must appear in `known`, the typed round-trip of the
/// same config (which serializes every field the schema has).
fn find_unknown(value: &Value, known: &Value, path: &str, out: &mut Vec<UnknownKey>) {
    match (value, known) {
        (Value::Object(v), Value::Object(k)) => {
            for (key, child) in v {
                match k.get(key) {
                    Some(kc) => find_unknown(child, kc, &join(path, key), out),
                    None => out.push(UnknownKey {
                        path: join(path, key),
                        suggestion: closest(key, k.keys().map(String::as_str)),
                    }),
                }
            }
        }
        (Value::Array(v), Value::Array(k)) if v.len() == k.len() => {
            for (i, (vc, kc)) in v.iter().zip(k).enumerate() {
                find_unknown(vc, kc, &format!("{path}[{i}]"), out);
            }
        }
        _ => {}
    }
}

fn closest<'a>(key: &str, candidates: impl Iterator<Item = &'a str>) -> Option<String> {
    candidates
        .map(|c| (levenshtein(&key.to_lowercase(), &c.to_lowercase()), c))
        .filter(|(d, c)| *d <= 2.max(c.len() / 4))
        .min_by_key(|(d, _)| *d)
        .map(|(_, c)| c.to_string())
}

fn levenshtein(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut cur = vec![i + 1];
        for (j, cb) in b.iter().enumerate() {
            cur.push((prev[j] + usize::from(ca != *cb)).min(prev[j + 1] + 1).min(cur[j] + 1));
        }
        prev = cur;
    }
    prev[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(v: Value) -> Migration {
        migrate(v).expect("migration must succeed")
    }

    /// Every fixture: migrating the output again changes nothing.
    fn assert_idempotent(m: &Migration) {
        let again = run(m.output.clone());
        assert!(again.is_up_to_date(), "second run changed: {:?}", again.changes);
        assert!(again.steps.is_empty());
    }

    #[test]
    fn modular_client_becomes_flat_with_a_usable_server_address() {
        let old = json!({
            "version": "0.3.21",
            "log": { "level": "debug" },
            "inbounds": [
                { "type": "tun", "tag": "tun-in", "auto_route": true, "mtu": 1350 },
                { "type": "local_proxy", "tag": "socks-in", "protocol": "socks", "listen": "127.0.0.1", "port": 1088 }
            ],
            "outbounds": [
                { "type": "ostp", "tag": "proxy", "server": "203.0.113.5", "port": 50000, "access_key": "sekrit123",
                  "transport": { "type": "uot", "stealth_sni": "vk.com", "tcp_fragmentation": true },
                  "multiplex": { "enabled": true, "sessions": 4 } },
                { "type": "direct", "tag": "direct" }
            ],
            "routing": {
                "rules": [
                    { "domain_suffix": ["local.lan"], "outbound": "direct" },
                    { "ip_cidr": ["192.168.0.0/16"], "outbound": "direct" },
                    { "process_name": ["steam.exe"], "outbound": "direct" },
                    { "domain_suffix": ["ads.example"], "outbound": "block" }
                ],
                "default_outbound": "proxy"
            }
        });
        let m = run(old);
        assert_eq!(m.from_version, 0);
        let o = &m.output;
        // Host and port together: the client resolves "host:port".
        assert_eq!(o["server"], "203.0.113.5:50000");
        assert!(o.get("port").is_none());
        assert_eq!(o["access_key"], "sekrit123");
        assert_eq!(o["socks5_bind"], "127.0.0.1:1088");
        assert_eq!(o["mtu"], 1350);
        assert_eq!(o["debug"], true);
        assert_eq!(o["transport"]["mode"], "uot");
        assert_eq!(o["mux"]["sessions"], 4);
        assert_eq!(o["exclude"]["processes"], json!(["steam.exe"]));
        assert_eq!(o["config_version"], CURRENT_VERSION);
        let notes: Vec<&String> = m.steps.iter().flat_map(|s| &s.notes).collect();
        assert!(notes.iter().any(|n| n.contains("block")));
        assert!(notes.iter().any(|n| n.contains("stealth_sni")));
        assert!(m.unknown_keys.is_empty(), "{:?}", m.unknown_keys);
        assert_idempotent(&m);
    }

    #[test]
    fn modular_multi_server_keeps_the_group_default_and_names_the_rest() {
        let m = run(json!({
            "inbounds": [],
            "outbounds": [
                { "type": "ostp", "tag": "proxy-0", "server": "1.1.1.1", "port": 50000, "access_key": "k1" },
                { "type": "ostp", "tag": "proxy-1", "server": "2001:db8::1", "port": 443, "access_key": "k2" },
                { "type": "urltest", "tag": "proxy", "outbounds": ["proxy-1", "proxy-0"] }
            ],
            "routing": { "rules": [], "default_outbound": "proxy" }
        }));
        assert_eq!(m.output["server"], "[2001:db8::1]:443");
        assert_eq!(m.output["access_key"], "k2");
        assert!(m.steps[0].notes.iter().any(|n| n.contains("proxy-0") && n.contains("1.1.1.1")));
    }

    #[test]
    fn flat_legacy_client_loses_only_removed_features() {
        let m = run(json!({
            "server": "198.51.100.9:50000",
            "access_key": "oldkey",
            "mtu": 1200,
            "tun": { "enable": true, "wintun_path": "C:\\wintun.dll", "ipv4_address": "10.0.0.2", "dns": "1.1.1.1" },
            "exclude": { "domains": ["a.com"], "ips": null },
            "transport": { "mode": "udp", "stealth_sni": "bing.com", "wss": true }
        }));
        assert_eq!(m.from_version, 1);
        let o = &m.output;
        assert_eq!(o["server"], "198.51.100.9:50000");
        assert_eq!(o["tun"]["dns"], "1.1.1.1");
        assert_eq!(o["exclude"]["domains"], json!(["a.com"]));
        for gone in ["/tun/wintun_path", "/tun/ipv4_address", "/transport/wss", "/transport/stealth_sni", "/exclude/ips"] {
            assert!(o.pointer(gone).is_none(), "{gone} should be gone");
        }
        let removed: Vec<String> = m
            .changes
            .iter()
            .filter_map(|c| match c { Change::Removed { path, .. } => Some(path.clone()), _ => None })
            .collect();
        assert!(removed.contains(&"transport.wss".to_string()), "{removed:?}");
        assert!(m.changes.contains(&Change::Added { path: "mode".into(), value: json!("client") }));
        assert!(m.changes.contains(&Change::Added { path: "config_version".into(), value: json!(CURRENT_VERSION) }));
        assert_idempotent(&m);
    }

    /// Server shape never changed: only the stamp is added. In particular the
    /// API token is still used by the server and must survive, and no section
    /// the user did not write is invented.
    #[test]
    fn server_gets_only_the_version_stamp() {
        let m = run(json!({
            "mode": "server",
            "listen": "0.0.0.0:50000",
            "access_keys": ["k1", { "access_key": "k2", "name": "bob" }],
            "api": { "enabled": true, "token": "relay-token" },
            "domain": "vpn.example.com",
            "tls": { "enabled": true, "ws_path": "/Xk3pQ9aZr2" }
        }));
        assert_eq!(m.output["api"], json!({ "enabled": true, "token": "relay-token" }));
        assert!(m.output.get("outbound").is_none());
        assert_eq!(m.output["tls"], json!({ "enabled": true, "ws_path": "/Xk3pQ9aZr2" }));
        assert_eq!(m.changes, vec![Change::Added { path: "config_version".into(), value: json!(CURRENT_VERSION) }]);
        assert!(m.unknown_keys.is_empty(), "{:?}", m.unknown_keys);
        assert_idempotent(&m);
    }

    #[test]
    fn relay_drops_the_old_authentication_settings() {
        let m = run(json!({
            "mode": "relay",
            "listen": "0.0.0.0:50000",
            "upstream_tcp": "203.0.113.10:50000",
            "upstream_udp": "203.0.113.10:50000",
            "upstream_api_url": "http://203.0.113.10:9090",
            "upstream_api_token": "t",
            "sync_interval_secs": 60
        }));
        for gone in ["upstream_api_url", "upstream_api_token", "sync_interval_secs"] {
            assert!(m.output.get(gone).is_none());
        }
        assert_eq!(m.steps.len(), 1);
        assert_eq!(m.steps[0].notes.len(), 3);
        assert_idempotent(&m);
    }

    #[test]
    fn current_config_is_a_true_no_op() {
        let current = json!({
            "mode": "client", "config_version": CURRENT_VERSION,
            "server": "vpn.example.com:443", "access_key": "k",
            "transport": { "mode": "uot", "tcp_fragmentation": false, "tls": true, "ws_path": "/Xk3pQ9aZr2" }
        });
        let m = run(current.clone());
        assert!(m.is_up_to_date(), "{:?}", m.changes);
        assert_eq!(m.output, current);
    }

    #[test]
    fn unknown_keys_are_reported_with_a_suggestion_and_kept() {
        let m = run(json!({
            "mode": "client", "config_version": CURRENT_VERSION,
            "server": "h:1", "access_key": "k",
            "tranport": { "mode": "uot" },
            "tun": { "enable": true, "kil_switch": true },
            "my_note": "hello"
        }));
        let find = |p: &str| m.unknown_keys.iter().find(|u| u.path == p).cloned();
        assert_eq!(find("tranport").unwrap().suggestion.as_deref(), Some("transport"));
        assert_eq!(find("tun.kil_switch").unwrap().suggestion.as_deref(), Some("kill_switch"));
        assert_eq!(find("my_note").unwrap().suggestion, None);
        assert_eq!(m.output["tranport"], json!({ "mode": "uot" }), "unknown data is never deleted");
    }

    #[test]
    fn a_newer_schema_is_refused() {
        let e = migrate(json!({ "mode": "client", "config_version": CURRENT_VERSION + 1, "server": "h:1", "access_key": "k" }))
            .unwrap_err();
        assert!(e.to_string().contains("newer ostp"), "{e}");
    }

    #[test]
    fn detect_kind_falls_back_to_structural_sniffing_without_mode_tag() {
        assert_eq!(detect_kind(&json!({"access_key": "x", "server": "y"})), Some(ConfigKind::Client));
        assert_eq!(detect_kind(&json!({"access_keys": ["x"], "listen": "y"})), Some(ConfigKind::Server));
        assert_eq!(detect_kind(&json!({"upstream_tcp": "x", "upstream_api_url": "y"})), Some(ConfigKind::Relay));
        assert_eq!(detect_kind(&json!({"inbounds": [], "outbounds": []})), Some(ConfigKind::Client));
        assert_eq!(detect_kind(&json!({"mode": "client", "server": "x"})), Some(ConfigKind::Client));
    }

    /// The configs ostp itself writes (`ostp init`, the wizard) must already
    /// be current: a fresh install never needs `ostp migrate`.
    #[test]
    fn generated_configs_are_already_current() {
        let client = json!({
            "mode": "client", "config_version": CURRENT_VERSION, "server": "127.0.0.1:50000", "access_key": "k",
            "socks5_bind": "127.0.0.1:1088",
            "transport": { "mode": "udp", "tcp_fragmentation": false },
            "debug": false,
        });
        let server = json!({
            "mode": "server", "config_version": CURRENT_VERSION, "listen": "0.0.0.0:50000", "access_keys": ["k"],
            "outbound": { "enabled": false, "protocol": "socks5", "address": "127.0.0.1",
                          "port": 9050, "username": "", "password": "", "default_action": "proxy", "rules": [] },
            "domain": "",
            "tls": { "enabled": false, "frontend": "builtin", "ws_path": "/Xk3pQ9aZr2", "cert": "acme", "public_port": 443,
                     "acme": { "email": "", "staging": false } },
            "debug": false,
        });
        let relay = json!({
            "mode": "relay", "config_version": CURRENT_VERSION, "listen": "0.0.0.0:50000",
            "upstream_tcp": "1.2.3.4:50000", "upstream_udp": "1.2.3.4:50000", "debug": false,
        });
        for (name, cfg) in [("client", client), ("server", server), ("relay", relay)] {
            let m = run(cfg);
            assert!(m.is_up_to_date(), "the generated {name} config needs migrating: {:?}", m.changes);
            assert!(m.unknown_keys.is_empty(), "the generated {name} config has unknown keys: {:?}", m.unknown_keys);
        }
    }
}
