use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{watch, Mutex};
use serde::{Deserialize, Serialize};
use anyhow::Result;
use ostp_client::bridge::BridgeMetrics;
use portable_atomic::Ordering;
use tauri::Emitter;

// ── Config types ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(tag = "mode", rename_all = "lowercase")]
enum AppMode {
    Server(serde_json::Value),
    Client(ClientConfigRaw),
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct UnifiedConfig {
    #[serde(flatten)]
    mode: AppMode,
    log_level: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct ClientConfigRaw {
    server: String,
    access_key: String,
    socks5_bind: Option<String>,
    tun: Option<TunConfig>,
    transport: Option<TransportConfigRaw>,
    debug: Option<bool>,
    exclude: Option<ExcludeConfig>,
    mux: Option<MuxConfig>,
    gui: Option<GuiConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct GuiConfig {
    autoconnect: Option<bool>,
    launch_startup: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct TunConfig {
    enable: bool,
    wintun_path: Option<String>,
    ipv4_address: Option<String>,
    dns: Option<String>,
    stack: Option<String>,
    kill_switch: Option<bool>,
}


#[derive(Debug, Deserialize, Serialize, Clone)]
struct TransportConfigRaw {
    mode: Option<String>,
    tcp_fragmentation: Option<bool>,
    frag_chunk: Option<usize>,
    frag_sleep: Option<u64>,
    junk_pc: Option<[usize; 2]>,
    junk_ps: Option<[usize; 2]>,
    ttl_desync: Option<bool>,
    ttl_desync_ttl: Option<u8>,
    ttl_desync_count: Option<u8>,
    ttl_desync_auto: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct ExcludeConfig {
    domains: Option<Vec<String>>,
    ips: Option<Vec<String>>,
    processes: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct MuxConfig {
    enabled: Option<bool>,
    sessions: Option<usize>,
}

#[derive(Serialize)]
struct UIMetrics {
    bytes_sent: u64,
    bytes_recv: u64,
    rtt_ms: u32,
}

// ── Messages exchanged with the privileged helper ────────────────────────────

#[derive(Deserialize, Clone)]
#[serde(tag = "type", rename_all = "lowercase")]
enum HelperMsg {
    Status { value: u8 },
    Log { message: String },
    Metrics { bytes_sent: u64, bytes_recv: u64, rtt_ms: u32 },
    Error { message: String },
}

// ── Application state ─────────────────────────────────────────────────────────

struct InProcessState {
    shutdown_tx: Option<tokio::sync::watch::Sender<bool>>,
    config_tx:   Option<tokio::sync::watch::Sender<ostp_client::config::ClientConfig>>,
    metrics: Arc<ostp_client::bridge::BridgeMetrics>,
    handle: tokio::task::JoinHandle<Result<(), String>>,
    error_msg: Arc<tokio::sync::Mutex<Option<String>>>,
}

struct HelperState {
    pipe_state: Arc<Mutex<HelperPipeState>>,
    cmd_tx: tokio::sync::mpsc::Sender<String>,
    token: String,
    port: u16,
}

enum TunnelHandle {
    InProcess(InProcessState),
    Helper(HelperState),
}

struct AppStateInner {
    tunnel: Option<TunnelHandle>,
}

impl Drop for AppStateInner {
    fn drop(&mut self) {
        if let Some(TunnelHandle::InProcess(ref mut s)) = self.tunnel {
            if let Some(tx) = s.shutdown_tx.take() {
                let _ = tx.send(true);
            }
        }
    }
}

struct AppState(Mutex<AppStateInner>);

// ── Config helpers ────────────────────────────────────────────────────────────

/// Per-user config location, used whenever the config cannot live next to the
/// executable.
fn user_config_path() -> PathBuf {
    let base = std::env::var_os(if cfg!(windows) { "APPDATA" } else { "HOME" })
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let dir = if cfg!(windows) { base.join("OSTP") } else { base.join(".config").join("ostp") };
    dir.join("config.json")
}

/// Where the GUI reads and writes its configuration.
///
/// Portable installs keep the config beside the executable, which is what the
/// zip has always done, and that is preserved wherever the directory is
/// actually writable.
///
/// What it must never do again is fall back to a bare relative `config.json`.
/// That resolves against the process working directory, which for a Start Menu
/// shortcut is whatever Windows chose — often `C:\Windows\System32`. Reading
/// and saving settings then failed with "Access is denied" (os error 5), and on
/// a writable working directory it would have been worse still: settings would
/// silently persist somewhere unrelated and appear to vanish.
///
/// Writability is measured rather than inferred from the install location. An
/// installer can put the app anywhere — a per-machine install onto a data drive
/// may well be writable, while Program Files is not — so the location alone
/// says nothing.
fn get_config_path() -> PathBuf {
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(parent) = exe_path.parent() {
            let portable = parent.join("config.json");
            if portable.exists() {
                if is_file_writable(&portable) {
                    return portable;
                }
                // Read-only beside the exe: unusable as the live file, but its
                // contents are still worth carrying over once.
                let user = user_config_path();
                if !user.exists() {
                    if let Some(dir) = user.parent() {
                        let _ = std::fs::create_dir_all(dir);
                    }
                    let _ = std::fs::copy(&portable, &user);
                }
            } else if is_dir_writable(parent) {
                // No config yet and the directory takes writes: a portable
                // unzip, so keep the config travelling with the folder.
                return portable;
            }
        }
    }

    let path = user_config_path();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    path
}

/// Whether an existing file can actually be written to.
///
/// Answered by opening it, not by reading permission bits: on Windows the
/// effective answer depends on the ACL and on virtualization, and `readonly()`
/// reflects neither.
fn is_file_writable(path: &std::path::Path) -> bool {
    std::fs::OpenOptions::new().append(true).open(path).is_ok()
}

/// Whether new files can be created in a directory, tested by doing it.
fn is_dir_writable(dir: &std::path::Path) -> bool {
    let probe = dir.join(format!(".ostp-write-test-{}", std::process::id()));
    match std::fs::File::create(&probe) {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

fn map_to_client_config(raw: &ClientConfigRaw, mode: &str) -> ostp_client::config::ClientConfig {
    ostp_client::config::ClientConfig {
        mode: mode.to_string(),
        debug: raw.debug.unwrap_or(false),
        ostp: ostp_client::config::OstpConfig {
            server_addr: raw.server.clone(),
            local_bind_addr: "0.0.0.0:0".to_string(),
            access_key: raw.access_key.clone(),
            handshake_timeout_ms: 5000,
            io_timeout_ms: 5000,
            mtu: 1350,
            keepalive_interval_sec: 5,
        },
        local_proxy: ostp_client::config::LocalProxyConfig {
            bind_addr: raw.socks5_bind.clone().unwrap_or_else(|| "127.0.0.1:1088".to_string()),
            connect_timeout_ms: 5000,
        },

        transport: ostp_client::config::TransportConfig {
            mode: raw.transport.as_ref().and_then(|t| t.mode.clone()).unwrap_or_else(|| "udp".to_string()),
            tcp_fragmentation: raw.transport.as_ref().and_then(|t| t.tcp_fragmentation).unwrap_or(false),
            frag_chunk: raw.transport.as_ref().and_then(|t| t.frag_chunk).unwrap_or(2),
            frag_sleep: raw.transport.as_ref().and_then(|t| t.frag_sleep).unwrap_or(2),
            junk_pc: raw.transport.as_ref().and_then(|t| t.junk_pc).unwrap_or([2, 5]),
            junk_ps: raw.transport.as_ref().and_then(|t| t.junk_ps).unwrap_or([100, 1000]),
            ttl_desync: raw.transport.as_ref().and_then(|t| t.ttl_desync).unwrap_or(false),
            ttl_desync_ttl: raw.transport.as_ref().and_then(|t| t.ttl_desync_ttl).unwrap_or(8),
            ttl_desync_count: raw.transport.as_ref().and_then(|t| t.ttl_desync_count).unwrap_or(2),
            ttl_desync_auto: raw.transport.as_ref().and_then(|t| t.ttl_desync_auto).unwrap_or(true),
        },
        exclusions: ostp_client::config::ExclusionConfig {
            domains: raw.exclude.as_ref().and_then(|e| e.domains.clone()).unwrap_or_default(),
            ips: raw.exclude.as_ref().and_then(|e| e.ips.clone()).unwrap_or_default(),
            processes: raw.exclude.as_ref().and_then(|e| e.processes.clone()).unwrap_or_default(),
        },
        multiplex: ostp_client::config::MultiplexConfig {
            enabled: raw.mux.as_ref().and_then(|m| m.enabled).unwrap_or(false),
            sessions: raw.mux.as_ref().and_then(|m| m.sessions).unwrap_or(1),
        },
        dns_server: raw.tun.as_ref().and_then(|t| t.dns.clone()),
        tun_stack: raw.tun.as_ref().and_then(|t| t.stack.clone()).unwrap_or_else(|| "system".to_string()),
        kill_switch: raw.tun.as_ref().and_then(|t| t.kill_switch).unwrap_or(false),
        gui: raw.gui.as_ref().map(|g| serde_json::to_value(g).unwrap()),
    }
}

// ── Tauri commands ────────────────────────────────────────────────────────────

/// Returns the directory path where wintun.dll should be placed.
#[tauri::command]
fn get_wintun_install_path() -> String {
    if let Some(helper) = find_helper_exe() {
        if let Some(dir) = helper.parent() {
            return dir.to_string_lossy().into_owned();
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        return cwd.to_string_lossy().into_owned();
    }
    String::new()
}

/// A `Command` for a console program, with the console window suppressed.
///
/// The GUI is a windowed-subsystem binary, so every console child it spawns
/// pops up a console window for as long as that child runs. With `reg`,
/// `tasklist` and `schtasks` all being invoked from here, that surfaced as
/// windows flashing on screen — worst while polling for the scheduled task,
/// which could spawn twenty of them in a row.
#[cfg(target_os = "windows")]
fn quiet_command(program: &str) -> std::process::Command {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let mut cmd = std::process::Command::new(program);
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd
}

/// Sets or removes the app from Windows startup (HKCU\...\Run).
#[tauri::command]
fn set_autostart(enable: bool) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        let key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
        let app_name = "OSTP";
        if enable {
            let exe = std::env::current_exe()
                .map_err(|e| format!("Cannot get exe path: {}", e))?;
            let exe_str = format!("\"{}\"", exe.to_string_lossy());
            let out = quiet_command("reg")
                .args(["add", key, "/v", app_name, "/t", "REG_SZ", "/d", &exe_str, "/f"])
                .output()
                .map_err(|e| format!("reg add failed: {}", e))?;
            if !out.status.success() {
                return Err(String::from_utf8_lossy(&out.stderr).to_string());
            }
        } else {
            let _ = quiet_command("reg")
                .args(["delete", key, "/v", app_name, "/f"])
                .output();
        }
    }
    #[cfg(target_os = "linux")]
    {
        // XDG autostart: desktop environments launch every .desktop file in
        // ~/.config/autostart on login. This is the portable equivalent of the
        // HKCU Run key above and needs no elevation.
        let path = linux_autostart_path().ok_or("Cannot determine the autostart directory")?;
        if enable {
            let exe = std::env::current_exe().map_err(|e| format!("Cannot get exe path: {}", e))?;
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)
                    .map_err(|e| format!("Cannot create {}: {}", dir.display(), e))?;
            }
            let entry = format!(
                "[Desktop Entry]\n\
                 Type=Application\n\
                 Name=OSTP\n\
                 Exec=\"{}\"\n\
                 Terminal=false\n\
                 X-GNOME-Autostart-enabled=true\n",
                exe.display()
            );
            std::fs::write(&path, entry)
                .map_err(|e| format!("Cannot write {}: {}", path.display(), e))?;
        } else if path.exists() {
            std::fs::remove_file(&path)
                .map_err(|e| format!("Cannot remove {}: {}", path.display(), e))?;
        }
    }
    Ok(())
}

/// Path of the XDG autostart entry, honouring XDG_CONFIG_HOME.
#[cfg(target_os = "linux")]
fn linux_autostart_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(base.join("autostart").join("ostp.desktop"))
}

/// Checks if the app is currently in Windows startup.
#[tauri::command]
fn get_autostart() -> bool {
    #[cfg(target_os = "windows")]
    {
        let key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
        let out = quiet_command("reg")
            .args(["query", key, "/v", "OSTP"])
            .output();
        if let Ok(o) = out {
            return o.status.success();
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Some(path) = linux_autostart_path() {
            return path.exists();
        }
    }
    false
}

/// Returns a sorted, deduplicated list of currently running process names.
#[tauri::command]
fn list_running_processes() -> Vec<String> {
    #[cfg(target_os = "windows")]
    {
        if let Ok(out) = quiet_command("tasklist")
            .args(["/FO", "CSV", "/NH"])
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            let mut names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
            for line in text.lines() {
                // CSV format: "chrome.exe","1234","Console","1","123,456 K"
                let name = line.trim_matches('"').split('"').next().unwrap_or("");
                if !name.is_empty() && name.ends_with(".exe") {
                    names.insert(name.to_string());
                }
            }
            return names.into_iter().collect();
        }
    }
    #[cfg(target_os = "linux")]
    {
        use std::process::Command;
        if let Ok(out) = Command::new("ps")
            .args(["-e", "-o", "comm="])
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            let mut names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
            for line in text.lines() {
                let name = line.trim();
                if !name.is_empty() {
                    names.insert(name.to_string());
                }
            }
            return names.into_iter().collect();
        }
    }
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        if let Ok(out) = Command::new("ps")
            .args(["-e", "-o", "comm="])
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            let mut names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
            for line in text.lines() {
                let name = line.trim().split('/').last().unwrap_or("");
                if !name.is_empty() {
                    names.insert(name.to_string());
                }
            }
            return names.into_iter().collect();
        }
    }
    vec![]
}

#[tauri::command]
async fn get_config() -> Result<String, String> {
    let path = get_config_path();
    if !path.exists() {
        return Ok(r#"{
  "_comment": "OSTP Client Configuration",
  "mode": "client",
  "log_level": "info",
  
  "_comment_server": "Address of the remote OSTP server",
  "server": "127.0.0.1:50000",
  
  "_comment_access_key": "Must match one of the access_keys on the server",
  "access_key": "your-secret-access-key-hex-or-base64",
  
  "_comment_socks5_bind": "The local port where the system/browser should connect (HTTP/SOCKS5)",
  "socks5_bind": "127.0.0.1:1088",
  
  "_comment_tun": "Virtual network adapter settings (native OSTP TUN via wintun.dll)",
  "tun": {
    "enable": false,
    "wintun_path": "./wintun.dll",
    "ipv4_address": "10.1.0.2/24",
    "dns": "1.1.1.1",
    "kill_switch": false
  },
  
  "_comment_exclude": "Bypass tunnel for these domains/IPs (only works in proxy mode)",
  "exclude": {
    "domains": ["localhost", "127.0.0.1"],
    "ips": [],
    "processes": []
  },
  
  "mux": {
    "enabled": false,
    "sessions": 1
  },
  "debug": false
}"#.into());
    }
    std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read config: {}", e))
}

#[tauri::command]
async fn save_config(json_content: String) -> Result<bool, String> {
    // Strip JSONC comments before validation
    let mut stripped = json_comments::StripComments::new(json_content.as_bytes());
    let _parsed: UnifiedConfig = serde_json::from_reader(&mut stripped)
        .map_err(|e| format!("Invalid configuration: {}", e))?;
    let path = get_config_path();
    std::fs::write(path, json_content).map_err(|e| format!("Failed to write config: {}", e))?;
    Ok(true)
}

#[tauri::command]
async fn get_tunnel_status(state: tauri::State<'_, AppState>) -> Result<u8, String> {
    let guard = state.0.lock().await;
    match &guard.tunnel {
        None => Ok(0),
        Some(TunnelHandle::InProcess(s)) => {
            let finished = s.handle.is_finished();
            let conn_state = s.metrics.connection_state.load(Ordering::Relaxed);
            eprintln!("[OSTP] get_tunnel_status InProcess: finished={} conn_state={}", finished, conn_state);
            if finished {
                let mut err_guard = s.error_msg.lock().await;
                if let Some(e) = err_guard.take() {
                    eprintln!("[OSTP] get_tunnel_status returning Err: {}", e);
                    return Err(e);
                }
                return Ok(0);
            }
            Ok(conn_state)
        }
        Some(TunnelHandle::Helper(h)) => {
            let mut ps = h.pipe_state.lock().await;
            eprintln!("[OSTP] get_tunnel_status Helper: conn_state={}", ps.connection_state);
            if ps.connection_state == 0 {
                if let Some(e) = ps.error_msg.take() {
                    eprintln!("[OSTP] get_tunnel_status returning Err: {}", e);
                    return Err(e);
                }
            }
            Ok(ps.connection_state)
        }
    }
}

#[tauri::command]
async fn get_metrics(state: tauri::State<'_, AppState>) -> Result<Option<UIMetrics>, String> {
    let guard = state.0.lock().await;
    match &guard.tunnel {
        None => Ok(None),
        Some(TunnelHandle::InProcess(s)) => Ok(Some(UIMetrics {
            bytes_sent: s.metrics.bytes_sent.load(Ordering::Relaxed),
            bytes_recv: s.metrics.bytes_recv.load(Ordering::Relaxed),
            rtt_ms: s.metrics.rtt_ms.load(Ordering::Relaxed),
        })),
        Some(TunnelHandle::Helper(h)) => {
            let ps = h.pipe_state.lock().await;
            Ok(Some(UIMetrics {
                bytes_sent: ps.bytes_sent,
                bytes_recv: ps.bytes_recv,
                rtt_ms: ps.rtt_ms,
            }))
        }
    }
}

#[tauri::command]
async fn reload_tunnel(state: tauri::State<'_, AppState>) -> Result<bool, String> {
    let guard = state.0.lock().await;
    if guard.tunnel.is_none() {
        return Ok(false);
    }
    
    let path = get_config_path();
    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("Read config error: {}", e))?;
    let mut stripped = json_comments::StripComments::new(content.as_bytes());
    let unified: UnifiedConfig = serde_json::from_reader(&mut stripped)
        .map_err(|e| format!("Parse config error: {}", e))?;
    let client_cfg = match unified.mode {
        AppMode::Client(c) => c,
        AppMode::Server(_) => return Err("GUI only supports Client mode.".into()),
    };
    let mode_str = if client_cfg.tun.as_ref().map(|t| t.enable).unwrap_or(false) { "tun" } else { "proxy" };
    let core_cfg = map_to_client_config(&client_cfg, mode_str);
    let config_str = serde_json::to_string(&core_cfg).unwrap();

    match &guard.tunnel {
        Some(TunnelHandle::Helper(h)) => {
            let cmd = format!(
                "{{\"cmd\":\"reload\",\"config\":{},\"token\":\"{}\"}}\n",
                serde_json::to_string(&config_str).unwrap(),
                h.token
            );
            let _ = h.cmd_tx.send(cmd).await;
        }
        Some(TunnelHandle::InProcess(s)) => {
            // Hot-reload exclusions by pushing new config into the watch channel.
            // If config_tx is None (old tunnel without this feature), return false.
            if let Some(ref tx) = s.config_tx {
                let _ = tx.send(core_cfg);
                return Ok(true);
            }
            return Ok(false);
        }
        None => {}
    }
    Ok(true)
}

#[tauri::command]
async fn stop_tunnel(state: tauri::State<'_, AppState>) -> Result<bool, String> {
    let mut guard = state.0.lock().await;
    match guard.tunnel.take() {
        None => {}
        Some(TunnelHandle::InProcess(mut s)) => {
            if let Some(tx) = s.shutdown_tx.take() { let _ = tx.send(true); }
            s.handle.abort();
            // Brief wait for cleanup
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                s.handle,
            ).await;
        }
        Some(TunnelHandle::Helper(h)) => {
            let stop_cmd = serde_json::json!({
                "cmd": "stop",
                "token": h.token
            }).to_string();
            let _ = h.cmd_tx.send(format!("{}\n", stop_cmd)).await;
        }
    }
    Ok(true)
}

/// Render a share link to an SVG QR code locally. The access key never leaves
/// the device — unlike an online QR service. (Ported from the current ostp-gui.)
#[tauri::command]
fn generate_qr(text: String) -> Result<String, String> {
    let code = qrcode::QrCode::new(text.as_bytes()).map_err(|e| e.to_string())?;
    let svg = code
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(220, 220)
        .dark_color(qrcode::render::svg::Color("#000000"))
        .light_color(qrcode::render::svg::Color("#ffffff"))
        .build();
    Ok(svg)
}

#[tauri::command]
async fn start_tunnel(state: tauri::State<'_, AppState>, app: tauri::AppHandle) -> Result<bool, String> {
    let mut guard = state.0.lock().await;

    // Tear down any existing tunnel before starting a fresh one — otherwise a
    // server change would silently keep the old connection/server. start_tunnel
    // is only ever invoked on an explicit connect, so restarting here is safe.
    // This implements the plan's "server change = full stop+start, not hot-reload".
    match guard.tunnel.take() {
        None => {}
        Some(TunnelHandle::InProcess(mut s)) => {
            if let Some(tx) = s.shutdown_tx.take() { let _ = tx.send(true); }
            s.handle.abort();
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), s.handle).await;
        }
        Some(TunnelHandle::Helper(h)) => {
            let stop_cmd = serde_json::json!({ "cmd": "stop", "token": h.token }).to_string();
            let _ = h.cmd_tx.send(format!("{}\n", stop_cmd)).await;
            // Let the elevated helper stop the tunnel and release the ostp_tun
            // adapter before a new helper tries to create it (avoids name clashes).
            tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
        }
    }

    let path = get_config_path();
    let content = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let mut stripped = json_comments::StripComments::new(content.as_bytes());
    let unified: UnifiedConfig = serde_json::from_reader(&mut stripped)
        .map_err(|e| format!("Config parse error: {}", e))?;

    let client_cfg = match unified.mode {
        AppMode::Client(c) => c,
        AppMode::Server(_) => return Err("GUI only supports Client mode.".into()),
    };

    let is_tun_enabled = client_cfg.tun.as_ref().map(|t| t.enable).unwrap_or(false);
    eprintln!("[OSTP] start_tunnel: is_tun_enabled={}", is_tun_enabled);

    #[cfg(target_os = "windows")]
    if is_tun_enabled {
        let mut found = false;
        if let Ok(cwd) = std::env::current_dir() {
            let p = cwd.join("wintun.dll");
            eprintln!("[OSTP] checking wintun at: {:?} exists={}", p, p.exists());
            if p.exists() { found = true; }
        }
        if !found {
            if let Some(helper) = find_helper_exe() {
                eprintln!("[OSTP] helper exe found at: {:?}", helper);
                if let Some(dir) = helper.parent() {
                    let p = dir.join("wintun.dll");
                    eprintln!("[OSTP] checking wintun at: {:?} exists={}", p, p.exists());
                    if p.exists() { found = true; }
                }
            } else {
                eprintln!("[OSTP] helper exe NOT FOUND");
            }
        }
        if !found {
            eprintln!("[OSTP] WINTUN_MISSING — returning error");
            return Err("WINTUN_MISSING".to_string());
        }
    }

    if is_tun_enabled {
        eprintln!("[OSTP] starting TUN via helper");
        start_tun_via_helper(&mut guard, &client_cfg, app).await
    } else {
        eprintln!("[OSTP] starting proxy in-process");
        start_proxy_in_process(&mut guard, &client_cfg, app).await
    }
}

async fn start_proxy_in_process(
    guard: &mut AppStateInner,
    raw: &ClientConfigRaw,
    app: tauri::AppHandle,
) -> Result<bool, String> {
    let mapped = map_to_client_config(raw, "proxy");
    let metrics = Arc::new(BridgeMetrics {
        bytes_sent: portable_atomic::AtomicU64::new(0),
        bytes_recv: portable_atomic::AtomicU64::new(0),
        // Start at 1 (connecting) so UI polling doesn't see 0 and flip back to disconnected
        // before the handshake task has had a chance to begin.
        connection_state: portable_atomic::AtomicU8::new(1),
        rtt_ms: portable_atomic::AtomicU32::new(0),
    });

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    // Config hot-reload channel: allows updating exclusions while tunnel is running.
    let (config_tx, config_rx) = watch::channel(mapped.clone());
    let metrics_clone = metrics.clone();
    let error_msg = Arc::new(tokio::sync::Mutex::new(None));
    let error_msg_clone = error_msg.clone();

    let handle = tokio::spawn(async move {
        match ostp_client::runner::run_client_core(mapped, metrics_clone, shutdown_rx, Some(config_rx)).await {
            Ok(_) => Ok(()),
            Err(e) => {
                let mut err_guard = error_msg_clone.lock().await;
                *err_guard = Some(e.to_string());
                let _ = app.emit("tunnel-error", e.to_string());
                Err(e.to_string())
            }
        }
    });

    guard.tunnel = Some(TunnelHandle::InProcess(InProcessState {
        shutdown_tx: Some(shutdown_tx),
        config_tx: Some(config_tx),
        metrics,
        handle,
        error_msg,
    }));
    Ok(true)
}

async fn start_tun_via_helper(
    guard: &mut AppStateInner,
    raw: &ClientConfigRaw,
    app: tauri::AppHandle,
) -> Result<bool, String> {
    // TUN goes through a privileged helper. Elevation is implemented for
    // Windows (UAC) and Linux (polkit/pkexec); anywhere else launch_as_admin
    // reports that plainly rather than letting this fail later as a confusing
    // missing-file error.
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| format!("Bind error: {}", e))?;
        listener.local_addr().unwrap().port()
    };

    let auth_token = rand::random::<u64>().to_string();
    let helper_exe = find_helper_exe()
        .ok_or_else(|| format!("{HELPER_EXE_NAME} not found next to the app or in target/."))?;
    launch_as_admin(&helper_exe, &auth_token, port).map_err(|e| format!("Failed to launch helper: {}", e))?;
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

    let socket = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            match tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port)).await {
                Ok(s) => return Ok::<_, std::io::Error>(s),
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(200)).await,
            }
        }
    }).await.map_err(|_| "Timeout connecting to helper.".to_string())?
     .map_err(|e| e.to_string())?;

    // Send the correctly MAPPED config
    let mapped = map_to_client_config(raw, "tun");
    let start_cmd = serde_json::json!({
        "cmd": "start",
        "config": serde_json::to_string(&mapped).unwrap_or_default(),
        "token": auth_token
    }).to_string();

    let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::channel::<String>(16);
    let pipe_state = Arc::new(Mutex::new(HelperPipeState { connection_state: 1, bytes_sent: 0, bytes_recv: 0, rtt_ms: 0, error_msg: None }));
    let state_for_task = pipe_state.clone();

    tokio::spawn(async move {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, split};
        let (reader_half, mut writer_half) = split(socket);
        let mut reader = BufReader::new(reader_half);
        let _ = writer_half.write_all(format!("{}\n", start_cmd).as_bytes()).await;

        let mut line = String::new();
        loop {
            tokio::select! {
                result = reader.read_line(&mut line) => {
                    if result.unwrap_or(0) == 0 { break; }
                    let trimmed = line.trim().to_string();
                    line.clear();
                    if let Ok(msg) = serde_json::from_str::<HelperMsg>(&trimmed) {
                        let mut s = state_for_task.lock().await;
                        match msg {
                            HelperMsg::Status { value } => s.connection_state = value,
                            HelperMsg::Metrics { bytes_sent, bytes_recv, rtt_ms } => { s.bytes_sent = bytes_sent; s.bytes_recv = bytes_recv; s.rtt_ms = rtt_ms; }
                            HelperMsg::Error { message } => { 
                                s.connection_state = 0; 
                                s.error_msg = Some(message.clone());
                                eprintln!("Helper error: {}", message);
                                let _ = app.emit("tunnel-error", message);
                            }
                            _ => {}
                        }
                    }
                }
                cmd = cmd_rx.recv() => {
                    if let Some(c) = cmd { let _ = writer_half.write_all(c.as_bytes()).await; } else { break; }
                }
            }
        }
        state_for_task.lock().await.connection_state = 0;
    });

    guard.tunnel = Some(TunnelHandle::Helper(HelperState { pipe_state, cmd_tx, token: auth_token, port }));
    Ok(true)
}

struct HelperPipeState {
    connection_state: u8,
    bytes_sent: u64,
    bytes_recv: u64,
    rtt_ms: u32,
    error_msg: Option<String>,
}

/// Executable name of the TUN helper for the current platform.
///
/// The ".exe" suffix was hardcoded, so on Linux every lookup below searched for
/// a file that cannot exist and the GUI reported the helper as missing on a
/// platform where it ships without an extension.
const HELPER_EXE_NAME: &str = if cfg!(windows) {
    "ostp-tun-helper.exe"
} else {
    "ostp-tun-helper"
};

fn find_helper_exe() -> Option<PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            // 1. Release/Production adjacent
            let candidate = dir.join(HELPER_EXE_NAME);
            if candidate.exists() { return Some(candidate); }

            // 2. Tauri target directory fallback
            // e.g. from ostp-gui/src-tauri/target/debug/deps/
            let mut parent = dir;
            while let Some(p) = parent.parent() {
                if p.file_name().map(|n| n == "target").unwrap_or(false) {
                    let deb = p.join("debug").join(HELPER_EXE_NAME);
                    if deb.exists() { return Some(deb); }
                    let rel = p.join("release").join(HELPER_EXE_NAME);
                    if rel.exists() { return Some(rel); }
                }
                parent = p;
            }
        }
    }
    // 3. Current working directory target fallback
    let cwd = std::env::current_dir().unwrap_or_default();
    let candidates = [
        cwd.join(HELPER_EXE_NAME),
        cwd.join("target").join("debug").join(HELPER_EXE_NAME),
        cwd.join("target").join("release").join(HELPER_EXE_NAME),
        cwd.join("..").join("target").join("debug").join(HELPER_EXE_NAME),
        cwd.join("..").join("target").join("release").join(HELPER_EXE_NAME),
        cwd.join("..").join("..").join("target").join("debug").join(HELPER_EXE_NAME),
        cwd.join("..").join("..").join("target").join("release").join(HELPER_EXE_NAME),
    ];
    for path in &candidates {
        if path.exists() { return Some(path.clone()); }
    }
    None
}

/// Name of the Scheduled Task that runs the helper elevated without a prompt.
#[cfg(target_os = "windows")]
const HELPER_TASK_NAME: &str = "OSTP TUN Helper";

/// Fixed path the GUI writes launch parameters to, and the task's command line
/// reads them from.
///
/// A Scheduled Task stores a FIXED command line, so the per-launch port and
/// token cannot travel as arguments. The file lives under the user's own
/// LOCALAPPDATA: the helper runs elevated but as the SAME user, so this keeps
/// the token inside the trust boundary it already had — no other user can read
/// it, which would not be true of a shared location.
#[cfg(target_os = "windows")]
fn helper_args_file() -> PathBuf {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    base.join("OSTP").join("helper-args.json")
}

/// Undoes XML entity escaping. `&amp;` must be handled last, or `&amp;lt;`
/// would come back as `<`.
#[cfg(target_os = "windows")]
fn xml_unescape(s: &str) -> String {
    s.replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// The exe path currently baked into the registered task, if any.
///
/// Queried as XML rather than `/FO LIST /V`: the list format's field labels are
/// localized (on a Russian Windows "Task To Run" is "Задача для запуска"),
/// whereas XML tag names are fixed.
///
/// Encoding depends on where the output goes, which is measured rather than
/// assumed: to a console schtasks writes UTF-16LE with a BOM, but into a
/// redirected pipe — our case — it writes UTF-8 with no BOM. Both are handled,
/// keyed off the BOM, so this keeps working if that ever flips.
#[cfg(target_os = "windows")]
fn helper_task_command() -> Option<String> {
    let out = quiet_command("schtasks")
        .args(["/Query", "/TN", HELPER_TASK_NAME, "/XML"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }

    let text = if out.stdout.starts_with(&[0xFF, 0xFE]) {
        let units: Vec<u16> = out.stdout[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(&out.stdout).into_owned()
    };

    let start = text.find("<Command>")? + "<Command>".len();
    let end = text[start..].find("</Command>")? + start;
    Some(xml_unescape(text[start..end].trim()))
}

/// Whether a task is registered AND still points at the exe we are about to run.
///
/// The path matters as much as the name. A task registered by a dev build (or
/// by an install that has since moved) keeps its original `<Command>`, and
/// `schtasks /Run` reports success merely for *accepting* the request — a task
/// whose exe no longer exists fails asynchronously and silently. Trusting the
/// name alone therefore bought a 60-second "Timeout connecting to helper" on
/// every single connect, permanently, until the task was deleted by hand.
/// Re-registering costs one consent prompt and fixes it for good.
#[cfg(target_os = "windows")]
fn helper_task_matches(exe: &std::path::Path) -> bool {
    let Some(registered) = helper_task_command() else {
        diag_log("task: schtasks /Query returned nothing usable — no task, or its XML had no <Command>");
        return false;
    };
    let registered = registered.trim().trim_matches('"');
    let path = std::path::Path::new(registered);

    // Requiring the registered path to equal the helper we would have launched
    // was too strict, and bought nothing. What the check exists to catch is a
    // task left pointing at a binary that is gone — `schtasks /Run` reports
    // success merely for accepting such a request, so the app would then wait
    // on a helper that never starts. Testing that the file exists catches
    // exactly that, while a task registered by the installer against an
    // equivalent copy of the helper no longer costs the user a prompt.
    let same_program = path
        .file_name()
        .map(|n| n.eq_ignore_ascii_case(HELPER_EXE_NAME))
        .unwrap_or(false);
    let exists = path.is_file();

    diag_log(&format!(
        "task: registered={registered:?} exists={exists} same_program={same_program} wanted={:?}",
        exe.display().to_string()
    ));
    exists && same_program
}

/// Appends a line to a small log beside the helper's argument file.
///
/// The GUI is a windowed binary with no console, so every `eprintln!` on this
/// path went nowhere — which left the one decision that matters, whether the
/// scheduled task gets used or the user gets a consent prompt, completely
/// unobservable from a user's machine.
#[cfg(target_os = "windows")]
fn diag_log(msg: &str) {
    let path = helper_args_file().with_file_name("helper-launch.log");
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        use std::io::Write;
        let _ = writeln!(f, "{msg}");
    }
}

#[cfg(target_os = "windows")]
fn launch_as_admin(exe: &std::path::PathBuf, token: &str, port: u16) -> anyhow::Result<()> {
    // Preferred path: hand the parameters over in a file and trigger the
    // pre-registered task, which runs elevated with no prompt. Falls back to a
    // direct elevated launch when the task is absent (first ever run, or the
    // user removed it) — and that first run is also where the task gets created,
    // so the prompt appears once rather than on every connect.
    let args_file = helper_args_file();
    if let Some(dir) = args_file.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let payload = serde_json::json!({ "port": port, "token": token });
    let wrote_args = std::fs::write(&args_file, payload.to_string()).is_ok();

    if wrote_args {
        // Deliberately does NOT create the task when it is missing. Registering
        // one is privileged, so the app could only do it by raising the very
        // prompt this exists to avoid — and it would then charge the user two
        // prompts for the privilege. Creating it belongs to the installer,
        // which is already elevated. Without it we simply fall through to the
        // direct elevated launch, which prompts once per connect as before.
        if helper_task_matches(exe) {
            let run = quiet_command("schtasks")
                .args(["/Run", "/TN", HELPER_TASK_NAME])
                .output();
            match run {
                Ok(o) if o.status.success() => {
                    diag_log("run: schtasks /Run accepted — no consent prompt");
                    return Ok(());
                }
                Ok(o) => diag_log(&format!(
                    "run: schtasks /Run failed ({:?}): {} {}",
                    o.status.code(),
                    String::from_utf8_lossy(&o.stdout).trim(),
                    String::from_utf8_lossy(&o.stderr).trim()
                )),
                Err(e) => diag_log(&format!("run: schtasks /Run could not start: {e}")),
            }
        }
        // Falling through: remove the file so a stale token is not left behind.
        let _ = std::fs::remove_file(&args_file);
    }

    diag_log("falling back to a direct elevated launch — this is the consent prompt");
    launch_as_admin_direct(exe, token, port)
}

/// The original one-prompt-per-launch path, kept as the fallback.
#[cfg(target_os = "windows")]
fn launch_as_admin_direct(exe: &std::path::PathBuf, token: &str, port: u16) -> anyhow::Result<()> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null_mut;

    let exe_wstr: Vec<u16> = exe.as_os_str().encode_wide().chain(Some(0)).collect();
    let verb_wstr: Vec<u16> = OsStr::new("runas").encode_wide().chain(Some(0)).collect();
    
    // Write token to temp file for security instead of passing via cmdline
    let temp_dir = std::env::temp_dir();
    let token_file = temp_dir.join(format!("ostp_auth_{}.tmp", rand::random::<u32>()));
    std::fs::write(&token_file, token)?;
    
    let params_str = format!("--port {} --token-file \"{}\"", port, token_file.display());
    let params_wstr: Vec<u16> = OsStr::new(&params_str).encode_wide().chain(Some(0)).collect();
    #[link(name = "shell32")] extern "system" { fn ShellExecuteW(h: *mut std::ffi::c_void, op: *const u16, f: *const u16, p: *const u16, d: *const u16, s: i32) -> isize; }
    #[link(name = "kernel32")] extern "system" { fn GetLastError() -> u32; }

    // Use the GUI executable's directory as the working directory so dependencies are found
    let cwd_path = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let dir_wstr: Vec<u16> = cwd_path.parent().unwrap_or(std::path::Path::new(".")).as_os_str().encode_wide().chain(Some(0)).collect();

    // Remove Mark of the Web (Zone.Identifier) so SmartScreen doesn't block UAC
    let zone_id = format!("{}:Zone.Identifier", exe.display());
    let _ = std::fs::remove_file(zone_id);

    // Use SW_SHOWNORMAL (1) instead of SW_HIDE (0) because runas with SW_HIDE is automatically blocked by UAC
    let ret = unsafe { ShellExecuteW(null_mut(), verb_wstr.as_ptr(), exe_wstr.as_ptr(), params_wstr.as_ptr(), dir_wstr.as_ptr(), 1) };

    // ShellExecuteW's return is a pseudo-HINSTANCE: > 32 means the call itself
    // "succeeded" — but that range INCLUDES ERROR_CANCELLED (1223), which is
    // exactly what Windows returns when the user clicks "No" on the UAC prompt.
    // The old `ret <= 32` check alone treated a user-denied prompt as success,
    // silently starting nothing and reporting a single opaque "denied or
    // missing" message that could not distinguish "no prompt ever shown"
    // (missing exe, ret<=32) from "prompt shown and declined" (ret==1223) from
    // any other Win32 failure — exactly the ambiguity blocking diagnosis here.
    if ret == 1223 {
        anyhow::bail!("UAC elevation was denied. TUN mode requires administrator privileges.");
    }
    if ret <= 32 {
        let win_err = unsafe { GetLastError() };
        anyhow::bail!(
            "Failed to request UAC elevation for the TUN helper (ShellExecuteW ret={}, \
             GetLastError={}, path={}). If this keeps happening with no prompt ever appearing, \
             an unsigned binary can be silently blocked by SmartScreen/antivirus during \
             elevation — try running ostp-gui.exe as Administrator manually.",
            ret, win_err, exe.display()
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn launch_as_admin(exe: &PathBuf, token: &str, port: u16) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    // Same shape as the Windows path: the token goes through a file rather than
    // argv, so it never shows up in the process list.
    let token_file = std::env::temp_dir().join(format!("ostp_auth_{}.tmp", rand::random::<u32>()));
    std::fs::write(&token_file, token)?;
    // Unlike Windows, /tmp is world-readable here, and this token authenticates
    // control of the privileged tunnel helper — restrict it to the owner.
    let _ = std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o600));

    // pkexec is polkit's front-end: in a desktop session it raises a graphical
    // authentication dialog. sudo is not an option from a GUI process, which has
    // no terminal to prompt on.
    match Command::new("pkexec")
        .arg(exe)
        .arg("--port")
        .arg(port.to_string())
        .arg("--token-file")
        .arg(&token_file)
        .spawn()
    {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let _ = std::fs::remove_file(&token_file);
            anyhow::bail!(
                "pkexec was not found, so the TUN helper cannot be granted the privileges it \
                 needs. Install polkit (package \"policykit-1\" on Debian/Ubuntu, \"polkit\" on \
                 Fedora/Arch), or use proxy mode, which needs no elevation."
            )
        }
        Err(e) => {
            let _ = std::fs::remove_file(&token_file);
            Err(e.into())
        }
    }
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn launch_as_admin(_exe: &PathBuf, _token: &str, _port: u16) -> Result<()> {
    anyhow::bail!("TUN mode needs a privileged helper, which is implemented on Windows and Linux only. Use proxy mode on this platform.");
}

#[cfg(target_os = "windows")]
fn show_error_dialog(msg: &str) {
    use std::os::windows::ffi::OsStrExt;
    let msg_w: Vec<u16> = std::ffi::OsStr::new(msg).encode_wide().chain(Some(0)).collect();
    let title_w: Vec<u16> = std::ffi::OsStr::new("OSTP GUI Error").encode_wide().chain(Some(0)).collect();
    #[link(name = "user32")] extern "system" { fn MessageBoxW(hWnd: *mut std::ffi::c_void, lpText: *const u16, lpCaption: *const u16, uType: u32) -> i32; }
    unsafe { MessageBoxW(std::ptr::null_mut(), msg_w.as_ptr(), title_w.as_ptr(), 0x10); } // 0x10 is MB_ICONERROR
}

#[cfg(not(target_os = "windows"))]
fn show_error_dialog(msg: &str) {
    println!("ERROR: {}", msg);
}

static SINGLE_INSTANCE_LOCK: std::sync::OnceLock<std::net::TcpListener> = std::sync::OnceLock::new();

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    if let Ok(listener) = std::net::TcpListener::bind("127.0.0.1:49153") {
        let _ = SINGLE_INSTANCE_LOCK.set(listener);
    } else {
        #[cfg(not(debug_assertions))]
        {
            show_error_dialog("Приложение OSTP GUI уже запущено!");
            return;
        }
        #[cfg(debug_assertions)]
        println!("WARNING: OSTP GUI is already running, ignoring in debug mode.");
    }

    let state = AppState(Mutex::new(AppStateInner { tunnel: None }));
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(state)
        .setup(|app| {
            use tauri::menu::{Menu, MenuItem};
            use tauri::tray::{TrayIconBuilder, TrayIconEvent, MouseButton, MouseButtonState};
            use tauri::{Manager, Emitter};

            let config_path = get_config_path();
            let mut masked_ip = String::from("0.0.0.0");
            if config_path.exists() {
                if let Ok(content) = std::fs::read_to_string(&config_path) {
                    let mut stripped = json_comments::StripComments::new(content.as_bytes());
                    if let Ok(val) = serde_json::from_reader::<_, serde_json::Value>(&mut stripped) {
                        if let Some(server) = val.get("server").and_then(|s| s.as_str()) {
                            let parts: Vec<&str> = server.split(':').collect();
                            let ip = parts[0];
                            let port = if parts.len() > 1 { parts[1] } else { "" };
                            let octets: Vec<&str> = ip.split('.').collect();
                            if octets.len() == 4 {
                                masked_ip = format!("{}.{}.**.**:{}", octets[0], octets[1], port);
                            } else if octets.len() > 2 {
                                masked_ip = format!("{}...:{}", octets[0], port);
                            } else {
                                masked_ip = server.to_string();
                            }
                        }
                    }
                }
            }

            let connect_i = MenuItem::with_id(app, "connect", "Подключиться", true, None::<&str>)?;
            let disconnect_i = MenuItem::with_id(app, "disconnect", "Отключиться", true, None::<&str>)?;
            let server_i = MenuItem::with_id(app, "server", format!("Сервер: {}", masked_ip), false, None::<&str>)?;
            let version_i = MenuItem::with_id(app, "version", format!("OSTP v{}", env!("CARGO_PKG_VERSION")), false, None::<&str>)?;
            let show_i = MenuItem::with_id(app, "show", "Показать окно", true, None::<&str>)?;
            let exit_i = MenuItem::with_id(app, "exit", "Выход", true, None::<&str>)?;
            
            let menu = Menu::with_items(app, &[
                &server_i,
                &version_i,
                &connect_i,
                &disconnect_i,
                &show_i,
                &exit_i,
            ])?;

            let _tray = TrayIconBuilder::new()
                .icon(app.default_window_icon().unwrap().clone())
                .menu(&menu)
                .on_menu_event(|app, event| {
                    match event.id.as_ref() {
                        "connect" => {
                            let _ = app.emit("tray_connect", ());
                        }
                        "disconnect" => {
                            let _ = app.emit("tray_disconnect", ());
                        }
                        "show" => {
                            if let Some(window) = app.get_webview_window("main") {
                                let _ = window.show();
                                let _ = window.set_focus();
                            }
                        }
                        "exit" => {
                            app.exit(0);
                        }
                        _ => {}
                    }
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = event {
                        let app = tray.app_handle();
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                })
                .build(app)?;

            Ok(())
        })
        .on_window_event(|window, event| match event {
            tauri::WindowEvent::CloseRequested { api, .. } => {
                let _ = window.hide();
                api.prevent_close();
            }
            _ => {}
        })
        .invoke_handler(tauri::generate_handler![start_tunnel, stop_tunnel, reload_tunnel, get_tunnel_status, get_metrics, get_config, save_config, get_wintun_install_path, set_autostart, get_autostart, list_running_processes, generate_qr])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
