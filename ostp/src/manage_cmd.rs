//! `ostp manage`: the server's state and everyday changes as JSON, for the
//! desktop app, which runs these over SSH.
//!
//! Every subcommand prints exactly one JSON object on stdout. A failure is
//! `{"error": "..."}` with exit code 1. Nothing here asks questions, so the
//! commands work without a terminal.

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::path::Path;
use std::process::Command;

use ostp_client::config::{AppMode, ServerConfig, UnifiedConfig};

#[derive(clap::Subcommand, Debug)]
pub enum ManageAction {
    /// First install: write a server config, register and start the service.
    /// On a server that is already set up, only makes sure the service runs.
    Install {
        /// UDP and TCP port OSTP listens on
        #[arg(long, default_value_t = 50000)]
        port: u16,
        /// Address clients use to reach the server, when the server cannot
        /// find its own public address (a VPS behind NAT)
        #[arg(long)]
        host: Option<String>,
        /// Name of the first user
        #[arg(long, default_value = "me")]
        user: String,
    },
    /// Service, system, TLS, subscription and panel state
    Status,
    /// Users with their links and traffic
    Users,
    /// Add a user with a new access key
    UserAdd { name: String },
    /// Remove a user: number (as in `ostp links`), name or access key
    UserRemove { user: String },
    /// Rename a user: number, name or access key, then the new name
    UserRename { user: String, name: String },
    /// Last lines of the service log
    Logs {
        #[arg(short = 'n', long, default_value_t = 200)]
        lines: usize,
    },
    /// Restart the service
    Restart,
}

pub fn run(action: ManageAction, config_path: &Path) -> ! {
    let result = match action {
        ManageAction::Install { port, host, user } => install(config_path, port, host.as_deref(), &user),
        ManageAction::Status => status(config_path),
        ManageAction::Users => users(config_path),
        ManageAction::UserAdd { name } => user_add(config_path, &name),
        ManageAction::UserRemove { user } => user_remove(config_path, &user),
        ManageAction::UserRename { user, name } => user_rename(config_path, &user, &name),
        ManageAction::Logs { lines } => logs(lines),
        ManageAction::Restart => restart().map(|active| json!({ "active": active })),
    };
    match result {
        Ok(v) => {
            println!("{v}");
            std::process::exit(0)
        }
        Err(e) => {
            println!("{}", json!({ "error": format!("{e:#}") }));
            std::process::exit(1)
        }
    }
}

// ── Config access ────────────────────────────────────────────────────────────

fn load(config_path: &Path) -> Result<(Value, ServerConfig)> {
    let v = crate::cert_cmd::read_json(config_path)?;
    let cfg: UnifiedConfig = serde_json::from_value(v.clone())?;
    match cfg.mode {
        AppMode::Server(s) => Ok((v, s)),
        _ => bail!("{} is not a server config", config_path.display()),
    }
}

/// Validates the whole config, keeps a backup and writes it readable by root
/// only. The running server picks up access-key changes from the file by
/// itself.
fn save(config_path: &Path, v: &Value) -> Result<()> {
    let parsed: UnifiedConfig = serde_json::from_value(v.clone()).context("the resulting config does not parse")?;
    parsed.validate()?;
    if config_path.exists() {
        std::fs::copy(config_path, config_path.with_extension("json.bak"))
            .with_context(|| format!("cannot back up {}", config_path.display()))?;
    }
    write_private(config_path, serde_json::to_string_pretty(v)?.as_bytes())
}

fn write_private(path: &Path, body: &[u8]) -> Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let mut f = opts.open(path).with_context(|| format!("cannot write {}", path.display()))?;
    std::io::Write::write_all(&mut f, body).with_context(|| format!("cannot write {}", path.display()))
}

/// Index into `access_keys` for a number (1-based), a name or a key.
fn find_user(v: &Value, who: &str) -> Result<usize> {
    let keys = v["access_keys"].as_array().ok_or_else(|| anyhow!("the config has no access_keys"))?;
    let who = who.trim();
    keys.iter()
        .enumerate()
        .find(|(i, u)| {
            let (key, name) = key_and_name(u);
            who == (i + 1).to_string() || who == key || (!name.is_empty() && who.eq_ignore_ascii_case(&name))
        })
        .map(|(i, _)| i)
        .ok_or_else(|| anyhow!("no user matches {who}"))
}

fn key_and_name(u: &Value) -> (String, String) {
    match u {
        Value::String(k) => (k.clone(), String::new()),
        _ => (
            u["access_key"].as_str().unwrap_or_default().to_string(),
            u["name"].as_str().unwrap_or_default().to_string(),
        ),
    }
}

// ── Service ──────────────────────────────────────────────────────────────────

const UNIT: &str = "/etc/systemd/system/ostp.service";

fn systemctl(args: &[&str]) -> bool {
    Command::new("systemctl").args(args).output().is_ok_and(|o| o.status.success())
}

fn service_active() -> bool {
    systemctl(&["is-active", "--quiet", "ostp"])
}

fn register_service(config_path: &Path) -> Result<()> {
    let binary = std::env::current_exe().unwrap_or_else(|_| "/opt/ostp/ostp".into());
    let dir = binary.parent().map(|p| p.display().to_string()).unwrap_or_else(|| "/opt/ostp".into());
    let unit = format!(
        "[Unit]\nDescription=OSTP Stealth Transport Protocol\nAfter=network.target\nWants=network-online.target\n\n\
         [Service]\nType=simple\nUser=root\nWorkingDirectory={dir}\nExecStart={} --config {}\n\
         Restart=always\nRestartSec=5\nLimitNOFILE=65535\nEnvironment=RUST_LOG=info\n\n\
         [Install]\nWantedBy=multi-user.target\n",
        binary.display(),
        config_path.display()
    );
    std::fs::write(UNIT, unit).with_context(|| format!("cannot write {UNIT} (not root?)"))?;
    systemctl(&["daemon-reload"]);
    if !systemctl(&["enable", "ostp"]) {
        bail!("systemctl enable ostp failed");
    }
    Ok(())
}

/// Restarts (or starts) the service and reports whether it stayed up.
fn restart() -> Result<bool> {
    if !Path::new(UNIT).exists() && !Path::new("/lib/systemd/system/ostp.service").exists() {
        bail!("the ostp service is not registered");
    }
    systemctl(&["restart", "ostp"]);
    std::thread::sleep(std::time::Duration::from_secs(2));
    Ok(service_active())
}

fn journal_tail(lines: usize) -> Vec<String> {
    Command::new("journalctl")
        .args(["-u", "ostp", "-n", &lines.to_string(), "--no-pager", "-o", "short-iso"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).lines().map(str::to_string).collect())
        .unwrap_or_default()
}

/// Opens the port in ufw or firewalld when one of them is active. A firewall
/// that is not running, or one of the cloud provider's, is left alone.
fn open_firewall(port: u16) -> Vec<String> {
    let mut done = Vec::new();
    let ufw_active = Command::new("ufw")
        .arg("status")
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("Status: active"));
    if ufw_active {
        for proto in ["udp", "tcp"] {
            if Command::new("ufw").args(["allow", &format!("{port}/{proto}")]).output().is_ok_and(|o| o.status.success()) {
                done.push(format!("ufw: {port}/{proto}"));
            }
        }
    }
    if Command::new("firewall-cmd").arg("--state").output().is_ok_and(|o| o.status.success()) {
        for proto in ["udp", "tcp"] {
            if Command::new("firewall-cmd")
                .args(["--permanent", &format!("--add-port={port}/{proto}")])
                .output()
                .is_ok_and(|o| o.status.success())
            {
                done.push(format!("firewalld: {port}/{proto}"));
            }
        }
        let _ = Command::new("firewall-cmd").arg("--reload").output();
    }
    done
}

// ── Commands ─────────────────────────────────────────────────────────────────

fn install(config_path: &Path, port: u16, host: Option<&str>, user: &str) -> Result<Value> {
    let config_dir = crate::config_dir_of(config_path);
    let mut firewall = Vec::new();
    let created = !config_path.exists();
    if created {
        std::fs::create_dir_all(&config_dir).with_context(|| format!("cannot create {}", config_dir.display()))?;
        // Links advertise this address: the server's own public one, or the
        // one the app reached it on when the server sits behind NAT.
        let detected = crate::detect_all_public_ipv4();
        let public = detected
            .first()
            .cloned()
            .or_else(|| host.map(str::to_string))
            .ok_or_else(|| anyhow!("cannot find the server's public address; pass --host"))?;
        let mut addresses = vec![public];
        addresses.extend(detected.into_iter().skip(1));
        std::fs::write(config_dir.join(".ostp_public_ip"), addresses.join("\n") + "\n")?;

        let v = json!({
            "mode": "server",
            "config_version": ostp_client::migrate::CURRENT_VERSION,
            "log_level": "info",
            "listen": format!("0.0.0.0:{port}"),
            "access_keys": [{ "access_key": crate::generate_secure_key("hex"), "name": user }],
            "api": { "enabled": false, "bind": "127.0.0.1:9090", "webpath": "", "username": "", "password_hash": "" },
            "debug": false
        });
        save(config_path, &v)?;
        firewall = open_firewall(port);
    } else {
        load(config_path).context("a config already exists and is not a usable server config")?;
    }
    if !Path::new(UNIT).exists() {
        register_service(config_path)?;
    }
    if !restart()? {
        bail!("the ostp service did not start:\n{}", journal_tail(20).join("\n"));
    }
    let mut out = users(config_path)?;
    out["created"] = created.into();
    out["firewall"] = firewall.into();
    Ok(out)
}

/// The overnet section plus what is actually running: the program, the
/// gateway answering, so the app can say why .ov does not work.
fn overnet_status(v: &Value) -> Value {
    let cfg: ostp_server::OvernetConfig = v
        .get("overnet")
        .filter(|o| !o.is_null())
        .and_then(|o| serde_json::from_value(o.clone()).ok())
        .unwrap_or_default();
    let installed = std::process::Command::new("overnet").arg("--version").output().is_ok_and(|o| o.status.success());
    let gateway_up = cfg.gateway.parse::<std::net::SocketAddr>().is_ok_and(|a| {
        std::net::TcpStream::connect_timeout(&a, std::time::Duration::from_secs(2)).is_ok()
    });
    json!({
        "enabled": cfg.enabled,
        "entry": cfg.enabled && cfg.entry,
        "exit": cfg.enabled && cfg.exit,
        "gateway": cfg.gateway,
        "exit_listen": cfg.exit_listen,
        "installed": installed,
        "gateway_up": gateway_up,
    })
}

fn status(config_path: &Path) -> Result<Value> {
    let (v, server) = load(config_path)?;
    let stats = read_stats(config_path);
    let tls = match crate::cert_cmd::tls_settings(config_path) {
        Ok(t) => {
            let cert = ostp_server::tls::acme::cert_info(&t.cert_path).ok();
            let now = ostp_server::tls::acme::unix_now();
            json!({
                "enabled": true,
                "domain": t.domain,
                "frontend": t.frontend.as_str(),
                "cert_days_left": cert.as_ref().map(|c| c.days_left(now)),
                "cert_self_signed": cert.as_ref().map(|c| c.self_signed),
            })
        }
        Err(_) => json!({ "enabled": false, "domain": server.domain }),
    };
    let api = &v["api"];
    let str_of = |k: &str| api[k].as_str().unwrap_or_default().to_string();
    Ok(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "service": {
            "registered": Path::new(UNIT).exists(),
            "active": service_active(),
            "enabled": systemctl(&["is-enabled", "--quiet", "ostp"]),
            "started_at": stats.as_ref().map(|s| s.started_at),
        },
        "sessions": stats.as_ref().map(|s| s.sessions),
        "stats_at": stats.as_ref().map(|s| s.written_at),
        "users": server.access_keys.len(),
        "listen": server.listen.primary(),
        "udp_port": crate::cert_cmd::listen_port(&v),
        "tls": tls,
        "subscription": server.subscription.as_ref().is_some_and(|s| s.is_enabled()),
        "panel": {
            "enabled": api["enabled"].as_bool().unwrap_or(false),
            "bind": str_of("bind"),
            // The path the panel is actually served at: an empty webpath
            // means /panel/ (ostp-server's api.rs), not the site root.
            "webpath": match str_of("webpath").trim_matches('/') {
                "" => "panel".to_string(),
                w => w.to_string(),
            },
            "login": !str_of("username").is_empty() && !str_of("password_hash").is_empty(),
        },
        "overnet": overnet_status(&v),
        "system": system_info(),
    }))
}

fn read_stats(config_path: &Path) -> Option<ostp_server::StatsFile> {
    let path = crate::config_dir_of(config_path).join(ostp_server::STATS_FILE);
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

fn users(config_path: &Path) -> Result<Value> {
    let (_, server) = load(config_path)?;
    let stats = read_stats(config_path);
    let list: Vec<Value> = server
        .access_keys
        .iter()
        .enumerate()
        .map(|(i, u)| {
            let key = u.key();
            let s = stats.as_ref().and_then(|s| s.users.iter().find(|x| x.access_key == key));
            let links: Vec<Value> = crate::share_links_for(&server, &key, config_path)
                .into_iter()
                .map(|(label, l)| json!({ "label": label, "uri": l.to_uri() }))
                .collect();
            json!({
                "number": i + 1,
                "name": u.name().unwrap_or_default(),
                "key": key,
                "links": links,
                "subscription": crate::subscription_url_for(&server, &key),
                "bytes_up": s.map(|s| s.bytes_up),
                "bytes_down": s.map(|s| s.bytes_down),
                "online": s.map(|s| s.online),
                "last_seen": s.and_then(|s| s.last_seen),
                "limit_bytes": u.limit(),
            })
        })
        .collect();
    Ok(json!({ "users": list, "stats_at": stats.map(|s| s.written_at) }))
}

fn user_add(config_path: &Path, name: &str) -> Result<Value> {
    let name = name.trim();
    if name.is_empty() {
        bail!("the name must not be empty");
    }
    let (mut v, _) = load(config_path)?;
    if find_user(&v, name).is_ok() {
        bail!("a user named {name} already exists");
    }
    let key = crate::generate_secure_key("hex");
    v["access_keys"]
        .as_array_mut()
        .ok_or_else(|| anyhow!("the config has no access_keys"))?
        .push(json!({ "access_key": key, "name": name }));
    save(config_path, &v)?;
    let all = users(config_path)?;
    let user = all["users"].as_array().and_then(|u| u.iter().find(|u| u["key"] == key.as_str()).cloned());
    Ok(json!({ "user": user }))
}

fn user_remove(config_path: &Path, who: &str) -> Result<Value> {
    let (mut v, _) = load(config_path)?;
    let i = find_user(&v, who)?;
    let keys = v["access_keys"].as_array_mut().unwrap();
    if keys.len() == 1 {
        bail!("this is the last user; add another one first");
    }
    let removed = keys.remove(i);
    save(config_path, &v)?;
    let (key, name) = key_and_name(&removed);
    Ok(json!({ "removed": { "name": name, "key": key } }))
}

fn user_rename(config_path: &Path, who: &str, name: &str) -> Result<Value> {
    let name = name.trim();
    if name.is_empty() {
        bail!("the name must not be empty");
    }
    let (mut v, _) = load(config_path)?;
    let i = find_user(&v, who)?;
    if find_user(&v, name).is_ok_and(|other| other != i) {
        bail!("a user named {name} already exists");
    }
    let entry = &mut v["access_keys"][i];
    let (key, _) = key_and_name(entry);
    let mut renamed = if entry.is_object() { entry.clone() } else { json!({ "access_key": key }) };
    renamed["name"] = name.into();
    *entry = renamed;
    save(config_path, &v)?;
    Ok(json!({ "renamed": { "key": key, "name": name } }))
}

fn logs(lines: usize) -> Result<Value> {
    Ok(json!({ "lines": journal_tail(lines.clamp(1, 5000)) }))
}

// ── System ───────────────────────────────────────────────────────────────────

fn system_info() -> Value {
    let read = |p: &str| std::fs::read_to_string(p).unwrap_or_default();
    let os = read("/etc/os-release")
        .lines()
        .find_map(|l| l.strip_prefix("PRETTY_NAME="))
        .map(|s| s.trim_matches('"').to_string());
    let load: Vec<f64> = read("/proc/loadavg").split_whitespace().take(3).filter_map(|x| x.parse().ok()).collect();
    let meminfo = read("/proc/meminfo");
    let mem = |field: &str| -> Option<u64> {
        meminfo
            .lines()
            .find_map(|l| l.strip_prefix(field))
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|kb| kb.parse::<u64>().ok())
            .map(|kb| kb * 1024)
    };
    let uptime = read("/proc/uptime").split_whitespace().next().and_then(|x| x.parse::<f64>().ok()).map(|x| x as u64);
    let (disk_total, disk_free) = disk("/");
    json!({
        "os": os,
        "arch": std::env::consts::ARCH,
        "kernel": read("/proc/sys/kernel/osrelease").trim(),
        "cpus": std::thread::available_parallelism().map(|n| n.get()).ok(),
        "uptime_secs": uptime,
        "load": load,
        "mem_total": mem("MemTotal:"),
        "mem_available": mem("MemAvailable:"),
        "disk_total": disk_total,
        "disk_free": disk_free,
    })
}

/// `df -P -B1 <path>`: total and available bytes.
fn disk(path: &str) -> (Option<u64>, Option<u64>) {
    let out = Command::new("df").args(["-P", "-B1", path]).output().ok();
    let text = out.map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default();
    let fields: Vec<&str> = text.lines().nth(1).map(|l| l.split_whitespace().collect()).unwrap_or_default();
    (fields.get(1).and_then(|x| x.parse().ok()), fields.get(3).and_then(|x| x.parse().ok()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_config(v: &Value) -> tempfile_like::Dir {
        let dir = tempfile_like::Dir::new();
        std::fs::write(dir.path().join("config.json"), serde_json::to_string(v).unwrap()).unwrap();
        std::fs::write(dir.path().join(".ostp_public_ip"), "203.0.113.7\n").unwrap();
        dir
    }

    /// A tiny self-cleaning temporary directory (no extra dependency).
    mod tempfile_like {
        pub struct Dir(std::path::PathBuf);
        impl Dir {
            pub fn new() -> Self {
                let p = std::env::temp_dir().join(format!("ostp-manage-{}-{}", std::process::id(), rand::random::<u64>()));
                std::fs::create_dir_all(&p).unwrap();
                Dir(p)
            }
            pub fn path(&self) -> &std::path::Path {
                &self.0
            }
        }
        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    fn server() -> Value {
        json!({
            "mode": "server",
            "config_version": ostp_client::migrate::CURRENT_VERSION,
            "listen": "0.0.0.0:50000",
            "access_keys": ["00112233445566778899aabbccddeeff", { "access_key": "ffeeddccbbaa99887766554433221100", "name": "phone" }]
        })
    }

    #[test]
    fn users_come_with_links_and_stats() {
        let dir = temp_config(&server());
        let cfg = dir.path().join("config.json");
        let stats = ostp_server::StatsFile {
            written_at: 10,
            started_at: 1,
            sessions: 1,
            users: vec![ostp_server::UserStatsSnapshot {
                access_key: "ffeeddccbbaa99887766554433221100".into(),
                name: None,
                bytes_up: 5,
                bytes_down: 7,
                connections: 1,
                limit_bytes: None,
                online: true,
                last_seen: Some(9),
            }],
        };
        std::fs::write(dir.path().join(ostp_server::STATS_FILE), serde_json::to_vec(&stats).unwrap()).unwrap();

        let out = users(&cfg).unwrap();
        let list = out["users"].as_array().unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0]["name"], "");
        assert_eq!(list[0]["bytes_down"], Value::Null);
        assert_eq!(list[1]["name"], "phone");
        assert_eq!(list[1]["bytes_down"], 7);
        assert_eq!(list[1]["online"], true);
        let uri = list[1]["links"][0]["uri"].as_str().unwrap();
        assert!(uri.starts_with("ostp://") && uri.contains("203.0.113.7:50000"), "{uri}");
        assert_eq!(out["stats_at"], 10);
    }

    #[test]
    fn add_rename_and_remove_users() {
        let dir = temp_config(&server());
        let cfg = dir.path().join("config.json");

        let added = user_add(&cfg, "laptop").unwrap();
        assert_eq!(added["user"]["name"], "laptop");
        assert_eq!(added["user"]["number"], 3);
        assert!(user_add(&cfg, "Laptop").is_err(), "names are unique, case-insensitively");

        // A bare key becomes a named entry.
        user_rename(&cfg, "1", "desktop").unwrap();
        let (v, _) = load(&cfg).unwrap();
        assert_eq!(v["access_keys"][0]["name"], "desktop");
        assert_eq!(v["access_keys"][0]["access_key"], "00112233445566778899aabbccddeeff");
        assert!(user_rename(&cfg, "desktop", "phone").is_err());

        let removed = user_remove(&cfg, "phone").unwrap();
        assert_eq!(removed["removed"]["key"], "ffeeddccbbaa99887766554433221100");
        user_remove(&cfg, "laptop").unwrap();
        assert!(user_remove(&cfg, "desktop").is_err(), "the last user stays");
        assert!(user_remove(&cfg, "nobody").is_err());

        // A backup of the previous version is kept.
        assert!(cfg.with_extension("json.bak").exists());
    }

    #[test]
    fn system_info_reads_this_machine() {
        let s = system_info();
        assert!(s["arch"].is_string());
        #[cfg(target_os = "linux")]
        assert!(s["mem_total"].as_u64().unwrap_or(0) > 0);
    }
}
