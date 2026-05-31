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

    // Set bypass list to prevent proxy loop for localhost traffic
    let _ = Command::new("reg")
        .creation_flags(CREATE_NO_WINDOW)
        .args([
            "add",
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
            "/v", "ProxyOverride",
            "/t", "REG_SZ",
            "/d", "localhost;127.*;10.*;192.168.*;<local>",
            "/f",
        ])
        .output();

    refresh_wininet();
    tracing::info!("System proxy enabled successfully");
}

#[cfg(target_os = "windows")]
pub fn disable_windows_proxy() {
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
    let host = parts.get(0).unwrap_or(&"127.0.0.1");
    let port = parts.get(1).unwrap_or(&"1088");

    let is_gui = std::env::var("DISPLAY").is_ok() || std::env::var("WAYLAND_DISPLAY").is_ok();

    if is_gui {
        tracing::info!("Enabling Linux system proxy (GNOME/KDE): {}", proxy_addr);
        
        // Try GNOME gsettings
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

        // Try KDE kwriteconfig5/6
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

    // Headless fallback
    println!("\n===================================================================");
    println!("OSTP Local Proxy is running at socks5://{}", proxy_addr);
    println!("Since you are in a headless/terminal environment, OSTP cannot automatically");
    println!("configure your system proxy. To route traffic from this terminal, run:");
    println!("\n    eval $(ostp --proxy-env)\n");
    println!("Or configure your application (e.g. curl -x socks5://{})", proxy_addr);
    println!("===================================================================\n");
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

#[cfg(target_os = "windows")]
pub fn disable_system_proxy() {
    disable_windows_proxy();
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
