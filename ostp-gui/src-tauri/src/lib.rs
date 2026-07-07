use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{watch, Mutex};
use serde::{Deserialize, Serialize};
use anyhow::Result;
use ostp_client::bridge::BridgeMetrics;
use portable_atomic::Ordering;
use tauri::Emitter;

mod ipc_crypto;
mod dns_prober;

// ── Config types ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(tag = "mode", rename_all = "lowercase")]
enum AppMode {
    Server(serde_json::Value),
    #[serde(rename = "client")]
    Client(serde_json::Value),
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct UnifiedConfig {
    #[serde(flatten)]
    mode: AppMode,
    log_level: Option<String>,
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
    Log { #[allow(dead_code)] message: String },
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
    #[allow(dead_code)]
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

fn get_config_path() -> PathBuf {
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(parent) = exe_path.parent() {
            let path = parent.join("config.json");
            if path.exists() {
                return path;
            }
        }
    }
    PathBuf::from("config.json")
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

/// Sets or removes the app from Windows startup (HKCU\...\Run).
#[tauri::command]
fn set_autostart(enable: bool) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        let key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
        let app_name = "OSTP";
        if enable {
            let exe = std::env::current_exe()
                .map_err(|e| format!("Cannot get exe path: {}", e))?;
            let exe_str = format!("\"{}\"", exe.to_string_lossy());
            let out = Command::new("reg")
                .args(["add", key, "/v", app_name, "/t", "REG_SZ", "/d", &exe_str, "/f"])
                .output()
                .map_err(|e| format!("reg add failed: {}", e))?;
            if !out.status.success() {
                return Err(String::from_utf8_lossy(&out.stderr).to_string());
            }
        } else {
            let _ = Command::new("reg")
                .args(["delete", key, "/v", app_name, "/f"])
                .output();
        }
    }
    Ok(())
}

/// Checks if the app is currently in Windows startup.
#[tauri::command]
fn get_autostart() -> bool {
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        let key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
        let out = Command::new("reg")
            .args(["query", key, "/v", "OSTP"])
            .output();
        if let Ok(o) = out {
            return o.status.success();
        }
    }
    false
}

/// Returns a sorted, deduplicated list of currently running process names.
#[tauri::command]
fn list_running_processes() -> Vec<String> {
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        if let Ok(out) = Command::new("tasklist")
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
  
  "_comment_api": "Management API Server (used by control panel)",
  "api": {
    "enabled": true,
    "bind": "127.0.0.1:50001",
    "token": "admin-secret-token"
  },
  
  "_comment_server": "Address of the remote OSTP server",
  "server": "127.0.0.1:50000",
  
  "_comment_access_key": "Must match one of the access_keys on the server",
  "access_key": "your-secret-access-key-hex-or-base64",
  
  "_comment_socks5_bind": "The local port where the system/browser should connect (HTTP/SOCKS5)",
  "socks5_bind": "127.0.0.1:1088",
  
  "_comment_tun": "Virtual network adapter settings (requires tun2socks.exe to be present)",
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
    
    let mut final_content = json_content;
    if !final_content.trim_start().starts_with("// OSTP") {
        let header = "// OSTP Configuration v0.3.1\n// DO NOT EDIT THIS COMMENT - Migrator relies on it\n";
        final_content = format!("{}{}", header, final_content);
    }
    
    std::fs::write(path, final_content).map_err(|e| format!("Failed to write config: {}", e))?;
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
    let (migrated, _) = ostp_client::config::ClientConfig::migrate_json(client_cfg);
    let core_cfg: ostp_client::config::ClientConfig = serde_json::from_value(migrated)
        .map_err(|e| format!("Failed to parse migrated config: {}", e))?;
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

#[tauri::command]
fn generate_qr(text: String) -> Result<String, String> {
    // Render the share link to an SVG QR locally — the access key never leaves
    // the device (unlike an online QR service).
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

    // If a tunnel is already running (a UI/backend desync left a stale handle, or
    // the user is switching servers), tear it down before starting a fresh one —
    // otherwise we'd silently keep the old connection/server. start_tunnel is only
    // ever invoked on an explicit connect (the UI calls it only while it believes
    // it is disconnected), so restarting here is safe.
    match guard.tunnel.take() {
        Some(TunnelHandle::Helper(h)) => {
            let stop_cmd = serde_json::json!({ "cmd": "stop", "token": h.token }).to_string();
            let _ = h.cmd_tx.send(format!("{}\n", stop_cmd)).await;
            // Let the elevated helper stop the tunnel and release the TUN adapter
            // before a new helper tries to create it (avoids ostp_tun name clashes).
            tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
        }
        Some(TunnelHandle::InProcess(mut s)) => {
            if let Some(tx) = s.shutdown_tx.take() { let _ = tx.send(true); }
            s.handle.abort();
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), s.handle).await;
        }
        None => {}
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

    let (migrated, _) = ostp_client::config::ClientConfig::migrate_json(client_cfg);
    
    let is_tun_enabled = migrated.get("inbounds")
        .and_then(|i| i.as_array())
        .map(|i| i.iter().any(|v| v.get("type").and_then(|t| t.as_str()) == Some("tun")))
        .unwrap_or(false);

    let parsed_config: ostp_client::config::ClientConfig = serde_json::from_value(migrated)
        .map_err(|e| format!("Failed to parse migrated config: {}", e))?;
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
        start_tun_via_helper(&mut guard, &parsed_config, app).await
    } else {
        eprintln!("[OSTP] starting proxy in-process");
        start_proxy_in_process(&mut guard, &parsed_config, app).await
    }
}

async fn start_proxy_in_process(
    guard: &mut AppStateInner,
    parsed_config: &ostp_client::config::ClientConfig,
    app: tauri::AppHandle,
) -> Result<bool, String> {
    let mapped = parsed_config.clone();
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
    parsed_config: &ostp_client::config::ClientConfig,
    app: tauri::AppHandle,
) -> Result<bool, String> {
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .map_err(|e| format!("Bind error: {}", e))?;
        listener.local_addr()
            .map_err(|e| format!("Get local_addr failed: {}", e))?.port()
    };

    let auth_token = rand::random::<u64>().to_string();
    let helper_exe = find_helper_exe()
        .ok_or_else(|| "ostp-tun-helper.exe not found.".to_string())?;
    launch_as_admin(&helper_exe, &auth_token, port)
        .map_err(|e| format!("Failed to launch helper: {}", e))?;
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

    let socket = tokio::time::timeout(std::time::Duration::from_secs(15), async {
        loop {
            match tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port)).await {
                Ok(s) => return Ok::<_, std::io::Error>(s),
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(200)).await,
            }
        }
    }).await.map_err(|_| "Timeout connecting to helper (15s)".to_string())?
     .map_err(|e| e.to_string())?;

    let key = ipc_crypto::derive_key(&auth_token);
    let crypto = ipc_crypto::IpcCrypto::new(&key);

    let mapped = parsed_config.clone();
    let start_cmd = serde_json::json!({
        "cmd": "start",
        "config": serde_json::to_string(&mapped).unwrap_or_default(),
        "token": auth_token
    }).to_string();

    let encrypted_cmd = crypto.encrypt(start_cmd.as_bytes())
        .map_err(|e| format!("Encryption failed: {}", e))?;
    let encoded_cmd = hex::encode(&encrypted_cmd);

    let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::channel::<String>(16);
    let pipe_state = Arc::new(Mutex::new(HelperPipeState {
        connection_state: 1,
        bytes_sent: 0,
        bytes_recv: 0,
        rtt_ms: 0,
        error_msg: None
    }));
    let state_for_task = pipe_state.clone();
    let crypto_for_task = ipc_crypto::IpcCrypto::new(&key);

    tokio::spawn(async move {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, split};
        let (reader_half, mut writer_half) = split(socket);
        let mut reader = BufReader::new(reader_half);
        let _ = writer_half.write_all(format!("{}\n", encoded_cmd).as_bytes()).await;

        let mut line = String::new();
        loop {
            tokio::select! {
                result = reader.read_line(&mut line) => {
                    if result.unwrap_or(0) == 0 { break; }
                    let trimmed = line.trim().to_string();
                    line.clear();

                    if let Ok(encrypted_bytes) = hex::decode(&trimmed) {
                        if let Ok(decrypted) = crypto_for_task.decrypt(&encrypted_bytes) {
                            if let Ok(msg_str) = String::from_utf8(decrypted) {
                                if let Ok(msg) = serde_json::from_str::<HelperMsg>(&msg_str) {
                                    let mut s = state_for_task.lock().await;
                                    match msg {
                                        HelperMsg::Status { value } => s.connection_state = value,
                                        HelperMsg::Metrics { bytes_sent, bytes_recv, rtt_ms } => {
                                            s.bytes_sent = bytes_sent;
                                            s.bytes_recv = bytes_recv;
                                            s.rtt_ms = rtt_ms;
                                        }
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
                        }
                    }
                }
                cmd = cmd_rx.recv() => {
                    if let Some(c) = cmd {
                        if let Ok(enc) = crypto_for_task.encrypt(c.as_bytes()) {
                            let encoded = hex::encode(&enc);
                            let _ = writer_half.write_all(format!("{}\n", encoded).as_bytes()).await;
                        }
                    } else {
                        break;
                    }
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

#[cfg(target_os = "windows")]
const HELPER_EXE_NAME: &str = "ostp-tun-helper.exe";
#[cfg(not(target_os = "windows"))]
const HELPER_EXE_NAME: &str = "ostp-tun-helper";

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

#[cfg(target_os = "windows")]
fn launch_as_admin(exe: &std::path::PathBuf, token: &str, port: u16) -> anyhow::Result<()> {
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
    
    // Use the GUI executable's directory as the working directory so dependencies are found
    let cwd_path = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let dir_wstr: Vec<u16> = cwd_path.parent().unwrap_or(std::path::Path::new(".")).as_os_str().encode_wide().chain(Some(0)).collect();
    
    let ret = unsafe { ShellExecuteW(null_mut(), verb_wstr.as_ptr(), exe_wstr.as_ptr(), params_wstr.as_ptr(), dir_wstr.as_ptr(), 1) };
    
    if ret <= 32 { anyhow::bail!("UAC denied or helper missing (ret={}).", ret); }
    Ok(())
}

#[cfg(target_os = "macos")]
fn launch_as_admin(exe: &std::path::PathBuf, token: &str, port: u16) -> anyhow::Result<()> {
    let temp_dir = std::env::temp_dir();
    let token_file = temp_dir.join(format!("ostp_auth_{}.tmp", rand::random::<u32>()));
    std::fs::write(&token_file, token)?;
    
    let cmd = format!("'{}' --port {} --token-file '{}'", exe.display(), port, token_file.display());
    let script = format!("do shell script \"{}\" with administrator privileges", cmd);
    
    let status = std::process::Command::new("osascript")
        .arg("-e")
        .arg(&script)
        .status()?;
        
    if !status.success() {
        anyhow::bail!("osascript failed");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn launch_as_admin(exe: &std::path::PathBuf, token: &str, port: u16) -> anyhow::Result<()> {
    let temp_dir = std::env::temp_dir();
    let token_file = temp_dir.join(format!("ostp_auth_{}.tmp", rand::random::<u32>()));
    std::fs::write(&token_file, token)?;
    
    let status = std::process::Command::new("pkexec")
        .arg(exe)
        .arg("--port")
        .arg(port.to_string())
        .arg("--token-file")
        .arg(&token_file)
        .status()?;
        
    if !status.success() {
        anyhow::bail!("pkexec failed");
    }
    Ok(())
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
    } else if !cfg!(debug_assertions) {
        show_error_dialog("Приложение OSTP GUI уже запущено!");
        return;
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
        .invoke_handler(tauri::generate_handler![start_tunnel, stop_tunnel, reload_tunnel, get_tunnel_status, get_metrics, get_config, save_config, get_wintun_install_path, set_autostart, get_autostart, list_running_processes, dns_prober::run_dns_prober, generate_qr])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
