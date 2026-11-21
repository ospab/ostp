//! `ostp manage` for a person at a terminal: the same answers as the JSON the
//! apps read, as text in the style of the other commands.

use colored::Colorize;
use serde_json::Value;

/// Which command produced the answer: it decides how the text reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shown {
    Install,
    Status,
    Users,
    UserAdd,
    UserSet,
    UserRemove,
    UserRename,
    UserLimit,
    UserDevices,
    Logs,
    Dns,
    ServerInfo,
    Restart,
    SubIds,
}

/// Binary size with a unit, as people read it: 1.5 GiB.
pub fn bytes(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

fn ok(msg: &str) -> String {
    format!("  {} {msg}", "✓".green())
}

fn name_of(u: &Value) -> String {
    match u["name"].as_str().filter(|n| !n.is_empty()) {
        Some(n) => n.to_string(),
        None => format!("#{}", u["number"].as_u64().unwrap_or(0)),
    }
}

fn limits_line(u: &Value) -> String {
    let traffic = match u["limit_bytes"].as_u64() {
        Some(b) => bytes(b),
        None => "unlimited".into(),
    };
    let devices = match u["max_devices"].as_u64() {
        Some(d) => d.to_string(),
        None => "unlimited".into(),
    };
    let mut line = format!("traffic {traffic}, devices {devices}");
    if let Some(t) = u["expires_at"].as_u64() {
        let date = ostp_core::access_keys::format_date(t);
        if u["expired"].as_bool() == Some(true) {
            line.push_str(&format!(", {}", format!("expired {date}").red()));
        } else {
            line.push_str(&format!(", until {date}"));
        }
    }
    line
}

/// One user in full: key, limits, links and subscription.
fn user_block(u: &Value) -> Vec<String> {
    let mut out = vec![
        format!("    Access key:   {}", u["key"].as_str().unwrap_or_default()),
        format!("    Limits:       {}", limits_line(u)),
    ];
    if let Some(links) = u["links"].as_array() {
        for l in links {
            let label = l["label"].as_str().unwrap_or("link");
            out.push(format!("    {:<13} {}", format!("{label}:"), l["uri"].as_str().unwrap_or_default().cyan()));
        }
    }
    if let Some(s) = u["subscription"].as_str() {
        out.push(format!("    Subscription: {}", s.cyan()));
    }
    out
}

fn users_table(v: &Value) -> Vec<String> {
    let list = v["users"].as_array().cloned().unwrap_or_default();
    if list.is_empty() {
        return vec!["  No users.".into()];
    }
    let width = list.iter().map(|u| name_of(u).chars().count()).max().unwrap_or(4).max(4);
    let mut out = vec![format!("  {:>3}  {:<width$}  {:<7}  {:>21}  {}", "#", "Name", "Online", "Traffic (up / down)", "Limits")];
    for u in &list {
        let online = match u["online"].as_bool() {
            Some(true) => "yes".green().to_string(),
            Some(false) => "no ".to_string(),
            None => " - ".to_string(),
        };
        let traffic = match (u["bytes_up"].as_u64(), u["bytes_down"].as_u64()) {
            (Some(up), Some(down)) => format!("{} / {}", bytes(up), bytes(down)),
            _ => "-".into(),
        };
        out.push(format!(
            "  {:>3}  {:<width$}  {:<7}  {:>21}  {}",
            u["number"].as_u64().unwrap_or(0),
            name_of(u),
            online,
            traffic,
            limits_line(u)
        ));
    }
    out.push(String::new());
    out.push("  Links of a user: ostp links. Change one: ostp manage user-set NAME --limit-bytes N --devices N --expires YYYY-MM-DD".dimmed().to_string());
    out
}

/// Scalars as `key: value`, objects indented below their key; empty values left out.
fn tree(v: &Value, indent: usize, out: &mut Vec<String>) {
    let Some(obj) = v.as_object() else { return };
    let pad = " ".repeat(indent);
    for (k, val) in obj {
        let label = k.replace('_', " ");
        match val {
            Value::Null => {}
            Value::Object(_) => {
                out.push(format!("{pad}{label}:"));
                tree(val, indent + 2, out);
            }
            Value::Array(items) if items.iter().all(|i| !i.is_object()) => {
                if !items.is_empty() {
                    let joined = items.iter().map(scalar).collect::<Vec<_>>().join(", ");
                    out.push(format!("{pad}{label}: {joined}"));
                }
            }
            Value::Array(items) => {
                out.push(format!("{pad}{label}:"));
                for i in items {
                    let mut sub = Vec::new();
                    tree(i, 0, &mut sub);
                    out.push(format!("{pad}  - {}", sub.join(", ")));
                }
            }
            _ => out.push(format!("{pad}{label}: {}", scalar(val))),
        }
    }
}

fn scalar(v: &Value) -> String {
    match v {
        Value::Bool(true) => "yes".into(),
        Value::Bool(false) => "no".into(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn on_off(b: bool) -> String {
    if b { "on".green().to_string() } else { "off".into() }
}

fn status(v: &Value) -> Vec<String> {
    let svc = &v["service"];
    let state = if svc["active"].as_bool() == Some(true) {
        "running".green().to_string()
    } else if svc["registered"].as_bool() == Some(true) {
        "stopped".red().to_string()
    } else {
        "not installed".yellow().to_string()
    };
    let mut out = vec![
        format!("  OSTP {}: {state}{}", v["version"].as_str().unwrap_or("?"),
            if svc["enabled"].as_bool() == Some(true) { ", starts at boot" } else { "" }),
        format!("  Listen:       {}", v["listen"].as_str().unwrap_or("-")),
        format!("  Users:        {}{}", v["users"], match v["sessions"].as_u64() {
            Some(s) => format!(", sessions now {s}"),
            None => String::new(),
        }),
    ];
    let tls = &v["tls"];
    out.push(if tls["enabled"].as_bool() == Some(true) {
        let days = tls["cert_days_left"].as_i64().map(|d| format!(", certificate {d} days left")).unwrap_or_default();
        format!("  HTTPS:        {} ({}{days})", on_off(true), tls["domain"].as_str().unwrap_or("-"))
    } else {
        format!("  HTTPS:        {} (ostp cert issue)", on_off(false))
    });
    out.push(format!("  Subscription: {}", on_off(v["subscription"].as_bool() == Some(true))));
    let panel = &v["panel"];
    out.push(if panel["enabled"].as_bool() == Some(true) {
        format!("  Panel:        {} at {}/{}/", on_off(true), panel["bind"].as_str().unwrap_or("-"), panel["webpath"].as_str().unwrap_or("panel"))
    } else {
        format!("  Panel:        {} (ostp panel enable)", on_off(false))
    });
    let ov = &v["overnet"];
    out.push(format!("  Overnet:      {}", on_off(ov["enabled"].as_bool() == Some(true))));
    out.push("  System:".into());
    tree(&v["system"], 4, &mut out);
    out
}

/// The text for one answer.
pub fn render(shown: Shown, v: &Value) -> Vec<String> {
    match shown {
        Shown::Users => users_table(v),
        Shown::Install => {
            let mut out = vec![ok(if v["created"].as_bool() == Some(true) {
                "Server installed and started"
            } else {
                "The server was already set up; the service is running"
            })];
            if let Some(fw) = v["firewall"].as_array().filter(|f| !f.is_empty()) {
                out.push(format!("  Firewall opened: {}", fw.iter().map(scalar).collect::<Vec<_>>().join(", ")));
            }
            out.push(String::new());
            out.extend(users_table(v));
            out
        }
        Shown::UserAdd | Shown::UserSet => {
            let u = &v["user"];
            let verb = if shown == Shown::UserAdd { "Added user" } else { "Saved user" };
            let mut out = vec![ok(&format!("{verb} {}", name_of(u).bold()))];
            out.extend(user_block(u));
            out.push("  The running server picks the change up within a few seconds.".dimmed().to_string());
            out
        }
        Shown::UserRemove => {
            let r = &v["removed"];
            let name = r["name"].as_str().filter(|n| !n.is_empty()).unwrap_or("(no name)");
            vec![ok(&format!("Removed user {} (key {})", name.bold(), r["key"].as_str().unwrap_or_default()))]
        }
        Shown::UserRename => vec![ok(&format!("Renamed: the user is now {}", v["renamed"]["name"].as_str().unwrap_or_default().bold()))],
        Shown::UserLimit => {
            let l = &v["limit"];
            let name = l["name"].as_str().filter(|n| !n.is_empty()).unwrap_or("the user");
            vec![match l["max_devices"].as_u64() {
                Some(n) => ok(&format!("{}: at most {n} device(s) on the subscription", name.bold())),
                None => ok(&format!("{}: no device limit", name.bold())),
            }]
        }
        Shown::UserDevices => {
            let name = v["user"]["name"].as_str().filter(|n| !n.is_empty()).unwrap_or("the user").to_string();
            let limit = v["max_devices"].as_u64().map_or("no limit".to_string(), |n| format!("limit {n}"));
            let list = v["devices"].as_array().cloned().unwrap_or_default();
            let mut out = vec![format!("  Devices of {} ({limit}): {}", name.bold(), list.len())];
            for d in &list {
                let mut parts = Vec::new();
                tree(d, 0, &mut parts);
                out.push(format!("    - {}", parts.join(", ")));
            }
            if list.is_empty() {
                out.push("    None yet. A device is counted when its app fetches the subscription with its device ID on.".into());
            }
            out
        }
        Shown::Logs => v["lines"].as_array().map(|l| l.iter().map(scalar).collect()).unwrap_or_default(),
        Shown::Restart => vec![if v["active"].as_bool() == Some(true) {
            ok("Service restarted and running")
        } else {
            format!("  {} The service did not stay up: journalctl -u ostp -n 50", "✗".red())
        }],
        Shown::Status => status(v),
        Shown::Dns => {
            let mut out = Vec::new();
            tree(v, 2, &mut out);
            out
        }
        Shown::ServerInfo => server_info(&v["server_info"]),
        Shown::SubIds => sub_ids(v),
    }
}

/// `sub-ids`: who still has an old-style link, or who just got a new one.
fn sub_ids(v: &Value) -> Vec<String> {
    let list = v["users"].as_array().cloned().unwrap_or_default();
    let assigned = v["assigned"].as_bool() == Some(true);
    if list.is_empty() {
        return vec![ok("Every user has a subscription id")];
    }
    let mut out = vec![if assigned {
        ok(&format!("New subscription links for {} user(s); their old links no longer work:", list.len()))
    } else {
        format!("  {} user(s) still have the old kind of link (a hash of the access key):", list.len())
    }];
    for u in &list {
        let mut line = format!("    [{}] {}", u["number"].as_u64().unwrap_or(0), name_of(u));
        if let Some(s) = u["subscription"].as_str() {
            line.push_str(&format!("  {}", s.cyan()));
        }
        out.push(line);
    }
    if !assigned {
        out.push("  ostp manage sub-ids --assign-missing gives each a random one (their current links stop working).".dimmed().to_string());
    }
    out
}

/// The server's info as its clients get it.
fn server_info(v: &Value) -> Vec<String> {
    let op = &v["operator"];
    let field = |k: &str| op[k].as_str().unwrap_or("-").to_string();
    let mut out = vec![
        ok("Saved; clients get it inside the tunnel (the running server picks it up within a few seconds)"),
        format!("  Name:     {}", field("name")),
        format!("  Location: {}", field("location")),
        format!("  Contact:  {}", field("contact")),
    ];
    match op["about"].as_str() {
        Some(about) => {
            out.push("  About:".into());
            out.extend(about.lines().map(|l| format!("    {l}")));
        }
        None => out.push("  About:    -".into()),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sizes_read_like_sizes() {
        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(1536), "1.5 KiB");
        assert_eq!(bytes(5 << 30), "5.0 GiB");
    }

    #[test]
    fn a_device_limit_reads_as_a_sentence() {
        colored::control::set_override(false);
        let v = json!({ "limit": { "key": "k", "name": "pops", "max_devices": 1 } });
        assert_eq!(render(Shown::UserLimit, &v), vec!["  ✓ pops: at most 1 device(s) on the subscription"]);
        let v = json!({ "limit": { "key": "k", "name": "pops", "max_devices": null } });
        assert_eq!(render(Shown::UserLimit, &v), vec!["  ✓ pops: no device limit"]);
        colored::control::set_override(false);
        let v = json!({ "assigned": false, "users": [{ "number": 2, "name": "pops", "key": "k", "subscription": null }] });
        let lines = render(Shown::SubIds, &v);
        assert_eq!(lines[1], "    [2] pops");
        assert!(lines[2].contains("--assign-missing"));
        let v = json!({ "assigned": true, "users": [] });
        assert_eq!(render(Shown::SubIds, &v), vec!["  ✓ Every user has a subscription id"]);
    }

    #[test]
    fn an_expiry_shows_in_the_limits() {
        colored::control::set_override(false);
        let u = json!({ "limit_bytes": null, "max_devices": null, "expires_at": 1767225599u64, "expired": true });
        assert_eq!(limits_line(&u), "traffic unlimited, devices unlimited, expired 2025-12-31");
        let u = json!({ "limit_bytes": null, "max_devices": null, "expires_at": 1767225599u64, "expired": false });
        assert_eq!(limits_line(&u), "traffic unlimited, devices unlimited, until 2025-12-31");
        let lines = render(Shown::ServerInfo, &json!({ "server_info": { "operator": { "name": "n", "about": "a\nb" } } }));
        assert!(lines.iter().any(|l| l == "  Name:     n"));
        assert!(lines.iter().any(|l| l == "    b"));
    }

    #[test]
    fn the_user_table_has_a_row_per_user() {
        colored::control::set_override(false);
        let v = json!({ "users": [
            { "number": 1, "name": "pops", "key": "k1", "online": true, "bytes_up": 1024, "bytes_down": 2048, "limit_bytes": null, "max_devices": 1 },
            { "number": 2, "name": "", "key": "k2", "online": null, "bytes_up": null, "bytes_down": null, "limit_bytes": 1073741824u64, "max_devices": null },
        ]});
        let lines = render(Shown::Users, &v);
        assert!(lines[1].contains("pops") && lines[1].contains("1.0 KiB / 2.0 KiB") && lines[1].contains("devices 1"), "{}", lines[1]);
        assert!(lines[2].contains("#2") && lines[2].contains("traffic 1.0 GiB"), "{}", lines[2]);
        assert!(!lines.iter().any(|l| l.contains('{')), "no JSON in the text");
    }
}
