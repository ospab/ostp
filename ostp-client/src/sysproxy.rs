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

#[cfg(target_os = "windows")]
pub fn enable_windows_proxy(proxy_addr: &str) {
    tracing::info!("Enabling Windows system proxy: {}", proxy_addr);

    let result = Command::new("reg")
        .creation_flags(CREATE_NO_WINDOW)
        .args([
            "add",
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
            "/v", "ProxyEnable",
            "/t", "REG_DWORD",
            "/d", "1",
            "/f",
        ])
        .output();
    match result {
        Ok(out) if !out.status.success() => {
            tracing::error!("Failed to set ProxyEnable: {}", String::from_utf8_lossy(&out.stderr));
        }
        Err(e) => tracing::error!("Failed to execute reg.exe (ProxyEnable): {}", e),
        _ => {}
    }

    let result = Command::new("reg")
        .creation_flags(CREATE_NO_WINDOW)
        .args([
            "add",
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
            "/v", "ProxyServer",
            "/t", "REG_SZ",
            "/d", proxy_addr,
            "/f",
        ])
        .output();
    match result {
        Ok(out) if !out.status.success() => {
            tracing::error!("Failed to set ProxyServer: {}", String::from_utf8_lossy(&out.stderr));
        }
        Err(e) => tracing::error!("Failed to execute reg.exe (ProxyServer): {}", e),
        _ => {}
    }

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

    let _ = Command::new("reg")
        .creation_flags(CREATE_NO_WINDOW)
        .args([
            "add",
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
            "/v", "ProxyOverride",
            "/t", "REG_SZ",
            "/d", &override_value,
            "/f",
        ])
        .output();
}

#[cfg(target_os = "windows")]
pub fn disable_system_proxy() {
    tracing::info!("Disabling Windows system proxy");
    let _ = Command::new("reg")
        .creation_flags(CREATE_NO_WINDOW)
        .args([
            "add",
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
            "/v", "ProxyEnable",
            "/t", "REG_DWORD",
            "/d", "0",
            "/f",
        ])
        .output();

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

#[cfg(not(target_os = "windows"))]
pub fn enable_system_proxy(proxy_addr: &str) {
    let parts: Vec<&str> = proxy_addr.split(':').collect();
    let host = parts.first().unwrap_or(&"127.0.0.1");
    let port = parts.get(1).unwrap_or(&"1088");

    let is_gui = std::env::var("DISPLAY").is_ok() || std::env::var("WAYLAND_DISPLAY").is_ok();

    if is_gui {
        tracing::info!("Enabling Linux system proxy (GNOME/KDE): {}", proxy_addr);
        
        let gnome_res = std::process::Command::new("gsettings")
            .args(["set", "org.gnome.system.proxy", "mode", "manual"])
            .output();
            
        if let Ok(out) = gnome_res {
            if out.status.success() {
                let _ = std::process::Command::new("gsettings").args(["set", "org.gnome.system.proxy.socks", "host", host]).output();
                let _ = std::process::Command::new("gsettings").args(["set", "org.gnome.system.proxy.socks", "port", port]).output();
                let _ = std::process::Command::new("gsettings").args(["set", "org.gnome.system.proxy", "ignore-hosts", "['localhost', '127.0.0.0/8', '10.0.0.0/8', '192.168.0.0/16']"]).output();
                tracing::info!("GNOME system proxy enabled.");
                return;
            }
        }

        for cmd in ["kwriteconfig5", "kwriteconfig6"] {
            let kde_res = std::process::Command::new(cmd)
                .args(["--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType", "1"])
                .output();
                
            if let Ok(out) = kde_res {
                if out.status.success() {
                    let socks_val = format!("socks://{}:{}", host, port);
                    let _ = std::process::Command::new(cmd).args(["--file", "kioslaverc", "--group", "Proxy Settings", "--key", "socksProxy", &socks_val]).output();
                    let _ = std::process::Command::new("dbus-send").args(["--type=signal", "/KIO/Scheduler", "org.kde.KIO.Scheduler.reparseSlaveConfiguration", "string:''"]).output();
                    tracing::info!("KDE system proxy enabled.");
                    return;
                }
            }
        }
    }

    println!("[ostp] SOCKS5 proxy on socks5://{proxy_addr}; no desktop session to set it on.");
    println!("[ostp] In this shell: eval $(ostp proxy-env)    or: curl -x socks5://{proxy_addr} ...");
}

#[cfg(not(target_os = "windows"))]
pub fn disable_system_proxy() {
    let is_gui = std::env::var("DISPLAY").is_ok() || std::env::var("WAYLAND_DISPLAY").is_ok();
    if is_gui {
        tracing::info!("Disabling Linux system proxy...");
        let _ = std::process::Command::new("gsettings").args(["set", "org.gnome.system.proxy", "mode", "none"]).output();
        let _ = std::process::Command::new("kwriteconfig5").args(["--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType", "0"]).output();
        let _ = std::process::Command::new("kwriteconfig6").args(["--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType", "0"]).output();
        let _ = std::process::Command::new("dbus-send").args(["--type=signal", "/KIO/Scheduler", "org.kde.KIO.Scheduler.reparseSlaveConfiguration", "string:''"]).output();
    }
}

#[cfg(target_os = "windows")]
pub fn enable_system_proxy(proxy_addr: &str) {
    enable_windows_proxy(proxy_addr);
}


pub struct SystemProxyGuard {
    active: bool,
}

impl SystemProxyGuard {
    pub fn enable(proxy_addr: &str) -> Self {
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
