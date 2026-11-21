//! The operating system's proxy settings: switched to the local OSTP proxy while the
//! client runs and put back as they were afterwards.
//!
//! Before the first change the user's own values are saved (in memory and in
//! `ostp-sysproxy-backup.json` next to the binary, so they survive a crash). Disabling
//! restores them instead of just switching the proxy off, and `recover_stale_proxy`
//! (also run by `SystemProxyGuard::enable`) puts them back after a crash.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;

#[cfg(target_os = "windows")]
use std::process::Command;

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

#[cfg(target_os = "windows")]
#[link(name = "wininet")]
extern "system" {
    fn InternetSetOptionW(
        hInternet: *mut std::ffi::c_void,
        dwOption: u32,
        lpBuffer: *mut std::ffi::c_void,
        dwBufferLength: u32,
    ) -> i32;
}
#[cfg(target_os = "windows")]
const INTERNET_OPTION_SETTINGS_CHANGED: u32 = 39;
#[cfg(target_os = "windows")]
const INTERNET_OPTION_REFRESH: u32 = 37;

// ──────────────────────────────────────────────────────────────────────────────
// Saved settings
// ──────────────────────────────────────────────────────────────────────────────

/// What the user had before OSTP changed it.
#[derive(Clone, Serialize, Deserialize)]
struct Backup {
    /// "windows", "gnome", "kde5" or "kde6": which mechanism the values belong to.
    backend: String,
    /// The proxy address OSTP set (`host:port`), to tell its own leftovers from
    /// settings the user changed since.
    ours: String,
    /// Setting name → previous value; `None` when the setting did not exist.
    values: BTreeMap<String, Option<String>>,
}

static BACKUP: Mutex<Option<Backup>> = Mutex::new(None);
const BACKUP_FILE: &str = "ostp-sysproxy-backup.json";

fn backup_path() -> Option<PathBuf> {
    std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.join(BACKUP_FILE)))
}

fn load_backup() -> Option<Backup> {
    if let Some(b) = BACKUP.lock().ok().and_then(|b| b.clone()) {
        return Some(b);
    }
    let raw = std::fs::read_to_string(backup_path()?).ok()?;
    serde_json::from_str(&raw).ok()
}

fn store_backup(b: &Backup) {
    if let Ok(mut m) = BACKUP.lock() {
        *m = Some(b.clone());
    }
    if let (Some(path), Ok(json)) = (backup_path(), serde_json::to_string_pretty(b)) {
        if let Err(e) = std::fs::write(&path, json) {
            tracing::warn!("could not save the previous proxy settings to {}: {e}", path.display());
        }
    }
}

fn clear_backup() {
    if let Ok(mut m) = BACKUP.lock() {
        *m = None;
    }
    if let Some(path) = backup_path() {
        let _ = std::fs::remove_file(path);
    }
}

/// Saves the user's current settings before OSTP touches them. A backup left by an
/// earlier run is kept when the settings still point at OSTP (it holds the user's
/// originals); when the user changed them since, the old backup is stale and replaced.
fn ensure_backup(backend: &str, ours: &str, read: impl FnOnce() -> BTreeMap<String, Option<String>>) {
    if let Some(mut old) = load_backup() {
        if old.backend == backend && platform_points_to_ours(&old) {
            old.ours = ours.to_string();
            store_backup(&old);
            return;
        }
        clear_backup();
    }
    store_backup(&Backup { backend: backend.to_string(), ours: ours.to_string(), values: read() });
}

/// Puts the saved settings back and forgets them. False when there was no backup.
fn restore_backup() -> bool {
    match load_backup() {
        Some(b) => {
            platform_restore(&b);
            clear_backup();
            true
        }
        None => false,
    }
}

/// Splits `host:port` (also `[v6]:port`) into the host and the port as text.
#[cfg_attr(target_os = "windows", allow(dead_code))]
fn split_proxy_addr(addr: &str) -> (String, String) {
    if let Ok(sa) = addr.parse::<std::net::SocketAddr>() {
        return (sa.ip().to_string(), sa.port().to_string());
    }
    match addr.rsplit_once(':') {
        Some((h, p)) => (h.trim_matches(['[', ']']).to_string(), p.to_string()),
        None => (addr.to_string(), "1088".to_string()),
    }
}

/// Value `name` from the output of `reg query <key> /v <name>`; a DWORD comes back in
/// decimal. `None` when the output has no such value.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn parse_reg_value(output: &str, name: &str) -> Option<String> {
    for line in output.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix(name) else { continue };
        // Whole word: "ProxyEnable" must not match "ProxyEnableX".
        if !rest.starts_with(char::is_whitespace) {
            continue;
        }
        let rest = rest.trim_start();
        let (kind, data) = match rest.find(char::is_whitespace) {
            Some(i) => (&rest[..i], rest[i..].trim()),
            None => (rest, ""),
        };
        if kind == "REG_DWORD" {
            let hex = data.trim_start_matches("0x");
            return u32::from_str_radix(hex, 16).ok().map(|v| v.to_string());
        }
        return Some(data.to_string());
    }
    None
}

/// Restores the user's proxy settings if a previous run died before it could (a crash,
/// a kill, a power cut). Does nothing when the settings no longer point at OSTP: the
/// user has changed them since, and those are theirs.
pub fn recover_stale_proxy() {
    let Some(b) = load_backup() else { return };
    if platform_points_to_ours(&b) {
        tracing::info!("Restoring the proxy settings left behind by an earlier run");
        platform_restore(&b);
    }
    clear_backup();
    platform_refresh();
}

// ──────────────────────────────────────────────────────────────────────────────
// Windows
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
const INTERNET_SETTINGS: &str = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
#[cfg(target_os = "windows")]
const PROXY_VALUES: [&str; 3] = ["ProxyEnable", "ProxyServer", "ProxyOverride"];

#[cfg(target_os = "windows")]
fn reg_query(name: &str) -> Option<String> {
    let out = Command::new("reg")
        .creation_flags(CREATE_NO_WINDOW)
        .args(["query", INTERNET_SETTINGS, "/v", name])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    parse_reg_value(&String::from_utf8_lossy(&out.stdout), name)
}

#[cfg(target_os = "windows")]
fn reg_set(name: &str, value: &str) -> bool {
    let kind = if name == "ProxyEnable" { "REG_DWORD" } else { "REG_SZ" };
    match Command::new("reg")
        .creation_flags(CREATE_NO_WINDOW)
        .args(["add", INTERNET_SETTINGS, "/v", name, "/t", kind, "/d", value, "/f"])
        .output()
    {
        Ok(out) if out.status.success() => true,
        Ok(out) => {
            tracing::error!("Failed to set {name}: {}", String::from_utf8_lossy(&out.stderr));
            false
        }
        Err(e) => {
            tracing::error!("Failed to execute reg.exe ({name}): {e}");
            false
        }
    }
}

#[cfg(target_os = "windows")]
fn reg_delete(name: &str) {
    let _ = Command::new("reg")
        .creation_flags(CREATE_NO_WINDOW)
        .args(["delete", INTERNET_SETTINGS, "/v", name, "/f"])
        .output();
}

#[cfg(target_os = "windows")]
fn platform_points_to_ours(b: &Backup) -> bool {
    b.backend == "windows"
        && reg_query("ProxyServer").as_deref() == Some(b.ours.as_str())
        && reg_query("ProxyEnable").as_deref() == Some("1")
}

#[cfg(target_os = "windows")]
fn platform_restore(b: &Backup) {
    for (name, value) in &b.values {
        match value {
            Some(v) => {
                reg_set(name, v);
            }
            None => reg_delete(name),
        }
    }
}

#[cfg(target_os = "windows")]
fn platform_refresh() {
    refresh_wininet();
}

#[cfg(target_os = "windows")]
pub fn enable_windows_proxy(proxy_addr: &str) {
    tracing::info!("Enabling Windows system proxy: {}", proxy_addr);

    ensure_backup("windows", proxy_addr, || {
        PROXY_VALUES.iter().map(|n| (n.to_string(), reg_query(n))).collect()
    });

    reg_set("ProxyEnable", "1");
    reg_set("ProxyServer", proxy_addr);

    // Set initial bypass list (will be expanded by update_proxy_bypass_list)
    update_proxy_bypass_list_windows(&[], &[]);

    refresh_wininet();
    tracing::info!("System proxy enabled successfully");
}

/// Update the Windows ProxyOverride registry value to include user-configured
/// excluded domains and IPs. This makes excluded hosts bypass the OSTP proxy
/// entirely at the OS level — the most reliable split-tunneling mechanism.
///
/// For each domain `d`, adds both `d` and `*.d` so both the root and all
/// subdomains bypass the proxy.
/// For IPs, adds them verbatim (Windows supports exact IPs and wildcards like
/// `192.168.*`).
#[cfg(target_os = "windows")]
pub fn update_proxy_bypass_list(domains: &[String], ips: &[String]) {
    update_proxy_bypass_list_windows(domains, ips);
    refresh_wininet();
}

#[cfg(not(target_os = "windows"))]
pub fn update_proxy_bypass_list(_domains: &[String], _ips: &[String]) {
    // The Linux/macOS system proxy has no bypass list.
}

#[cfg(target_os = "windows")]
fn update_proxy_bypass_list_windows(domains: &[String], ips: &[String]) {
    // Base list: always bypass local addresses
    let mut parts: Vec<String> = vec![
        "localhost".into(),
        "127.*".into(),
        "10.*".into(),
        "172.16.*".into(),
        "172.17.*".into(),
        "172.18.*".into(),
        "172.19.*".into(),
        "172.20.*".into(),
        "172.21.*".into(),
        "172.22.*".into(),
        "172.23.*".into(),
        "172.24.*".into(),
        "172.25.*".into(),
        "172.26.*".into(),
        "172.27.*".into(),
        "172.28.*".into(),
        "172.29.*".into(),
        "172.30.*".into(),
        "172.31.*".into(),
        "192.168.*".into(),
        "<local>".into(),
    ];

    // Add excluded domains: both exact and wildcard subdomain form
    for d in domains {
        let original = d.trim().trim_start_matches(['.', '*']).to_lowercase();
        let d = crate::tunnel::exclusion::normalize_domain(&original);
        if d.is_empty() { continue; }
        // Browsers compare the list with the punycode name; keep the
        // readable form too for programs that pass it as typed.
        if original.trim_end_matches('.') != d {
            parts.push(format!("*.{}", original.trim_end_matches('.')));
            parts.push(original.trim_end_matches('.').to_string());
        }
        parts.push(d.clone());
        parts.push(format!("*.{}", d));
    }

    // Add excluded IPs verbatim
    for ip in ips {
        let ip = ip.trim();
        if ip.is_empty() { continue; }
        // Strip CIDR suffix if present — Windows ProxyOverride doesn't support CIDR
        let host = ip.split('/').next().unwrap_or(ip);
        parts.push(host.to_string());
    }

    let override_value = parts.join(";");
    tracing::info!("Updating ProxyOverride: {}", override_value);

    reg_set("ProxyOverride", &override_value);
}

#[cfg(target_os = "windows")]
pub fn disable_system_proxy() {
    tracing::info!("Disabling Windows system proxy");
    if !restore_backup() {
        // No saved settings (e.g. the file was deleted): at least switch the proxy off.
        reg_set("ProxyEnable", "0");
    }
    refresh_wininet();
}

#[cfg(target_os = "windows")]
fn refresh_wininet() {
    unsafe {
        InternetSetOptionW(
            std::ptr::null_mut(),
            INTERNET_OPTION_SETTINGS_CHANGED,
            std::ptr::null_mut(),
            0,
        );
        InternetSetOptionW(
            std::ptr::null_mut(),
            INTERNET_OPTION_REFRESH,
            std::ptr::null_mut(),
            0,
        );
    }
}

#[cfg(target_os = "windows")]
pub fn enable_system_proxy(proxy_addr: &str) {
    enable_windows_proxy(proxy_addr);
}

// ──────────────────────────────────────────────────────────────────────────────
// Linux (GNOME / KDE)
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(not(target_os = "windows"))]
const GNOME_KEYS: [(&str, &str); 4] = [
    ("org.gnome.system.proxy", "mode"),
    ("org.gnome.system.proxy.socks", "host"),
    ("org.gnome.system.proxy.socks", "port"),
    ("org.gnome.system.proxy", "ignore-hosts"),
];
#[cfg(not(target_os = "windows"))]
const KDE_KEYS: [&str; 2] = ["ProxyType", "socksProxy"];

#[cfg(not(target_os = "windows"))]
fn is_gui_session() -> bool {
    std::env::var("DISPLAY").is_ok() || std::env::var("WAYLAND_DISPLAY").is_ok()
}

#[cfg(not(target_os = "windows"))]
fn gs_get(schema: &str, key: &str) -> Option<String> {
    let out = std::process::Command::new("gsettings").args(["get", schema, key]).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// `value` is GVariant text, quotes included, as `gsettings get` prints it.
#[cfg(not(target_os = "windows"))]
fn gs_set(schema: &str, key: &str, value: &str) -> bool {
    std::process::Command::new("gsettings")
        .args(["set", schema, key, value])
        .output()
        .is_ok_and(|o| o.status.success())
}

#[cfg(not(target_os = "windows"))]
fn kde_read(cmd: &str, key: &str) -> Option<String> {
    let out = std::process::Command::new(cmd)
        .args(["--file", "kioslaverc", "--group", "Proxy Settings", "--key", key])
        .output()
        .ok()?;
    let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (out.status.success() && !v.is_empty()).then_some(v)
}

#[cfg(not(target_os = "windows"))]
fn kde_write(cmd: &str, key: &str, value: Option<&str>) -> bool {
    let mut c = std::process::Command::new(cmd);
    c.args(["--file", "kioslaverc", "--group", "Proxy Settings", "--key", key]);
    match value {
        Some(v) => c.arg(v),
        None => c.arg("--delete"),
    };
    c.output().is_ok_and(|o| o.status.success())
}

#[cfg(not(target_os = "windows"))]
fn kde_notify() {
    let _ = std::process::Command::new("dbus-send")
        .args(["--type=signal", "/KIO/Scheduler", "org.kde.KIO.Scheduler.reparseSlaveConfiguration", "string:''"])
        .output();
}

#[cfg(not(target_os = "windows"))]
fn platform_points_to_ours(b: &Backup) -> bool {
    let (host, port) = split_proxy_addr(&b.ours);
    match b.backend.as_str() {
        "gnome" => {
            gs_get("org.gnome.system.proxy", "mode").as_deref() == Some("'manual'")
                && gs_get("org.gnome.system.proxy.socks", "host") == Some(format!("'{host}'"))
                && gs_get("org.gnome.system.proxy.socks", "port") == Some(port)
        }
        "kde5" | "kde6" => {
            let cmd = if b.backend == "kde5" { "kreadconfig5" } else { "kreadconfig6" };
            kde_read(cmd, "ProxyType").as_deref() == Some("1")
                && kde_read(cmd, "socksProxy") == Some(format!("socks://{host}:{port}"))
        }
        _ => false,
    }
}

#[cfg(not(target_os = "windows"))]
fn platform_restore(b: &Backup) {
    match b.backend.as_str() {
        "gnome" => {
            for (name, value) in &b.values {
                if let (Some((schema, key)), Some(v)) = (name.split_once('/'), value) {
                    gs_set(schema, key, v);
                }
            }
        }
        "kde5" | "kde6" => {
            let cmd = if b.backend == "kde5" { "kwriteconfig5" } else { "kwriteconfig6" };
            for (key, value) in &b.values {
                kde_write(cmd, key, value.as_deref());
            }
            kde_notify();
        }
        _ => {}
    }
}

#[cfg(not(target_os = "windows"))]
fn platform_refresh() {}

#[cfg(not(target_os = "windows"))]
pub fn enable_system_proxy(proxy_addr: &str) {
    let (host, port) = split_proxy_addr(proxy_addr);

    if is_gui_session() {
        tracing::info!("Enabling Linux system proxy (GNOME/KDE): {}", proxy_addr);

        // GNOME: the previous values are read first; a failing read means no gsettings.
        let gnome_prev: BTreeMap<String, Option<String>> = GNOME_KEYS
            .iter()
            .map(|(s, k)| (format!("{s}/{k}"), gs_get(s, k)))
            .collect();
        if gnome_prev.values().any(|v| v.is_some()) {
            ensure_backup("gnome", proxy_addr, || gnome_prev);
            if gs_set("org.gnome.system.proxy", "mode", "'manual'") {
                gs_set("org.gnome.system.proxy.socks", "host", &format!("'{host}'"));
                gs_set("org.gnome.system.proxy.socks", "port", &port);
                gs_set("org.gnome.system.proxy", "ignore-hosts", "['localhost', '127.0.0.0/8', '10.0.0.0/8', '192.168.0.0/16']");
                tracing::info!("GNOME system proxy enabled.");
                return;
            }
            // Not usable after all (no such schema): drop the backup we just took.
            clear_backup();
        }

        for (read, write, backend) in [("kreadconfig5", "kwriteconfig5", "kde5"), ("kreadconfig6", "kwriteconfig6", "kde6")] {
            if !std::process::Command::new(read).arg("--version").output().is_ok_and(|o| o.status.success()) {
                continue;
            }
            ensure_backup(backend, proxy_addr, || {
                KDE_KEYS.iter().map(|k| (k.to_string(), kde_read(read, k))).collect()
            });
            if kde_write(write, "ProxyType", Some("1")) {
                let socks_val = format!("socks://{host}:{port}");
                kde_write(write, "socksProxy", Some(&socks_val));
                kde_notify();
                tracing::info!("KDE system proxy enabled.");
                return;
            }
            clear_backup();
        }
    }

    println!("[ostp] SOCKS5 proxy on socks5://{proxy_addr}; no desktop session to set it on.");
    println!("[ostp] In this shell: eval $(ostp proxy-env)    or: curl -x socks5://{proxy_addr} ...");
}

#[cfg(not(target_os = "windows"))]
pub fn disable_system_proxy() {
    if !is_gui_session() {
        return;
    }
    tracing::info!("Disabling Linux system proxy...");
    if restore_backup() {
        return;
    }
    // No saved settings (nothing was changed by this run, or the file is gone).
    // Only act when the settings still point at OSTP's default port.
    if gs_get("org.gnome.system.proxy.socks", "port").as_deref() == Some("1088") {
        let _ = gs_set("org.gnome.system.proxy", "mode", "'none'");
    }
}

pub struct SystemProxyGuard {
    active: bool,
}

impl SystemProxyGuard {
    pub fn enable(proxy_addr: &str) -> Self {
        // A crashed earlier run may have left OSTP's proxy in place: put the user's
        // own settings back first, so the backup taken now holds those.
        recover_stale_proxy();
        enable_system_proxy(proxy_addr);
        Self { active: true }
    }
}

impl Drop for SystemProxyGuard {
    fn drop(&mut self) {
        if self.active {
            disable_system_proxy();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_addr_splits_for_ipv4_and_ipv6() {
        assert_eq!(split_proxy_addr("127.0.0.1:1088"), ("127.0.0.1".into(), "1088".into()));
        assert_eq!(split_proxy_addr("[::1]:1088"), ("::1".into(), "1088".into()));
        assert_eq!(split_proxy_addr("localhost:8080"), ("localhost".into(), "8080".into()));
    }

    #[test]
    fn reg_query_output_is_parsed() {
        let out = "\r\nHKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\r\n    ProxyEnable    REG_DWORD    0x1\r\n\r\n";
        assert_eq!(parse_reg_value(out, "ProxyEnable"), Some("1".to_string()));
        let out = "HKEY\\...\r\n    ProxyServer    REG_SZ    127.0.0.1:1088\r\n";
        assert_eq!(parse_reg_value(out, "ProxyServer"), Some("127.0.0.1:1088".to_string()));
        // A value with spaces keeps them.
        let out = "    ProxyOverride    REG_SZ    localhost;<local>; a b\r\n";
        assert_eq!(parse_reg_value(out, "ProxyOverride"), Some("localhost;<local>; a b".to_string()));
        // Only the exact name matches; an empty string value is empty, not absent.
        assert_eq!(parse_reg_value("    ProxyEnableX    REG_DWORD    0x1\r\n", "ProxyEnable"), None);
        assert_eq!(parse_reg_value("    ProxyServer    REG_SZ\r\n", "ProxyServer"), Some(String::new()));
        assert_eq!(parse_reg_value("", "ProxyServer"), None);
    }

    #[test]
    fn backup_roundtrips_through_json() {
        let mut values = BTreeMap::new();
        values.insert("ProxyEnable".to_string(), Some("0".to_string()));
        values.insert("ProxyOverride".to_string(), None);
        let b = Backup { backend: "windows".into(), ours: "127.0.0.1:1088".into(), values };
        let back: Backup = serde_json::from_str(&serde_json::to_string(&b).unwrap()).unwrap();
        assert_eq!(back.values, b.values);
        assert_eq!(back.ours, b.ours);
    }
}
