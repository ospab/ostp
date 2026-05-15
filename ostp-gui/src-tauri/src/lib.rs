use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;
use serde::{Deserialize, Serialize};
use anyhow::Result;
use ostp_client::bridge::BridgeMetrics;
use portable_atomic::Ordering;

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
    turn: Option<TurnConfigRaw>,
    debug: Option<bool>,
    exclude: Option<ExcludeConfig>,
    mux: Option<MuxConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct TunConfig {
    enable: bool,
    wintun_path: Option<String>,
    ipv4_address: Option<String>,
    dns: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct TurnConfigRaw {
    enabled: bool,
    server_addr: String,
    username: Option<String>,
    access_key: Option<String>,
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
}

// ── Messages exchanged with the privileged helper ────────────────────────────

#[derive(Deserialize, Clone)]
#[serde(tag = "type", rename_all = "lowercase")]
enum HelperMsg {
    Status { value: u8 },
    Log { message: String },
    Metrics { bytes_sent: u64, bytes_recv: u64 },
    Error { message: String },
}

// ── Application state ─────────────────────────────────────────────────────────

// For proxy (non-TUN) mode: runs in-process.
struct InProcessState {
    shutdown_tx: Option<watch::Sender<bool>>,
    metrics: Arc<BridgeMetrics>,
    handle: JoinHandle<Result<(), String>>,
}

// For TUN mode: communicates with the privileged helper via named pipe.
struct HelperState {
    /// Shared state updated by pipe reader task
    pipe_state: Arc<Mutex<HelperPipeState>>,
    /// Send commands to helper over named pipe
    cmd_tx: tokio::sync::mpsc::Sender<String>,
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

#[tauri::command]
async fn get_config() -> Result<String, String> {
    let path = get_config_path();
    if !path.exists() {
        return Ok(r#"{
  "mode": "client",
  "log_level": "info",
  "server": "127.0.0.1:50000",
  "access_key": "your-secret-access-key-hex-or-base64",
  "socks5_bind": "127.0.0.1:1088",
  "tun": {
    "enable": true,
    "wintun_path": "./wintun.dll",
    "ipv4_address": "10.1.0.2/24"
  },
  "debug": false
}"#.into());
    }
    std::fs::read_to_string(&path).map_err(|e| format!("Read error: {}", e))
}

#[tauri::command]
async fn save_config(json_content: String) -> Result<bool, String> {
    let _parsed: UnifiedConfig = serde_json::from_str(&json_content)
        .map_err(|e| format!("Invalid OSTP config JSON: {}", e))?;
    let path = get_config_path();
    std::fs::write(path, json_content).map_err(|e| format!("Write error: {}", e))?;
    Ok(true)
}

#[tauri::command]
async fn get_tunnel_status(state: tauri::State<'_, AppState>) -> Result<u8, String> {
    let guard = state.0.lock().await;
    match &guard.tunnel {
        None => Ok(0),
        Some(TunnelHandle::InProcess(s)) => {
            if s.handle.is_finished() {
                return Ok(0);
            }
            Ok(s.metrics.connection_state.load(Ordering::Relaxed))
        }
        Some(TunnelHandle::Helper(h)) => {
            let ps = h.pipe_state.lock().await;
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
        })),
        Some(TunnelHandle::Helper(h)) => {
            let ps = h.pipe_state.lock().await;
            Ok(Some(UIMetrics {
                bytes_sent: ps.bytes_sent,
                bytes_recv: ps.bytes_recv,
            }))
        }
    }
}

#[tauri::command]
async fn stop_tunnel(state: tauri::State<'_, AppState>) -> Result<bool, String> {
    let mut guard = state.0.lock().await;
    match guard.tunnel.take() {
        None => {}
        Some(TunnelHandle::InProcess(mut s)) => {
            if let Some(tx) = s.shutdown_tx.take() {
                let _ = tx.send(true);
            }
            drop(s.handle);
        }
        Some(TunnelHandle::Helper(h)) => {
            let _ = h.cmd_tx.send("{\"cmd\":\"stop\"}\n".to_string()).await;
        }
    }
    Ok(true)
}

#[tauri::command]
async fn start_tunnel(state: tauri::State<'_, AppState>) -> Result<bool, String> {
    let mut guard = state.0.lock().await;

    // Already running?
    match &guard.tunnel {
        Some(TunnelHandle::InProcess(s)) if !s.handle.is_finished() => return Ok(true),
        Some(TunnelHandle::Helper(_)) => return Ok(true),
        _ => {}
    }
    // Clean up finished handle
    guard.tunnel = None;

    let path = get_config_path();
    if !path.exists() {
        return Err("config.json not found. Go to Settings and configure your connection first.".into());
    }

    let content = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let unified: UnifiedConfig = serde_json::from_str(&content)
        .map_err(|e| format!("Config parse error: {}", e))?;

    let client_cfg = match unified.mode {
        AppMode::Client(c) => c,
        AppMode::Server(_) => return Err("Configuration is in Server mode. GUI only supports Client mode.".into()),
    };

    let is_tun_enabled = client_cfg.tun.as_ref().map(|t| t.enable).unwrap_or(false);

    if is_tun_enabled {
        // ── TUN mode: launch privileged helper ────────────────────────────────
        start_tun_via_helper(&mut guard, client_cfg, content).await
    } else {
        // ── Proxy mode: run in-process ────────────────────────────────────────
        start_proxy_in_process(&mut guard, client_cfg).await
    }
}

// ── In-process proxy tunnel ──────────────────────────────────────────────────

async fn start_proxy_in_process(
    guard: &mut AppStateInner,
    client_cfg: ClientConfigRaw,
) -> Result<bool, String> {
    let turn_cfg = client_cfg.turn.as_ref();
    let mapped = ostp_client::config::ClientConfig {
        mode: "proxy".to_string(),
        debug: client_cfg.debug.unwrap_or(false),
        ostp: ostp_client::config::OstpConfig {
            server_addr: client_cfg.server.clone(),
            local_bind_addr: "0.0.0.0:0".to_string(),
            access_key: client_cfg.access_key.clone(),
            handshake_timeout_ms: 5000,
            io_timeout_ms: 5000,
        },
        local_proxy: ostp_client::config::LocalProxyConfig {
            bind_addr: client_cfg.socks5_bind.clone().unwrap_or_else(|| "127.0.0.1:1088".to_string()),
            connect_timeout_ms: 5000,
        },
        turn: ostp_client::config::TurnConfig {
            enabled: turn_cfg.map(|t| t.enabled).unwrap_or(false),
            server_addr: turn_cfg.and_then(|t| Some(t.server_addr.clone())).unwrap_or_default(),
            username: turn_cfg.and_then(|t| t.username.clone()).unwrap_or_default(),
            access_key: turn_cfg.and_then(|t| t.access_key.clone()).unwrap_or_default(),
        },
        exclusions: ostp_client::config::ExclusionConfig {
            domains: client_cfg.exclude.as_ref().and_then(|e| e.domains.clone()).unwrap_or_default(),
            ips: client_cfg.exclude.as_ref().and_then(|e| e.ips.clone()).unwrap_or_default(),
            processes: client_cfg.exclude.as_ref().and_then(|e| e.processes.clone()).unwrap_or_default(),
        },
        multiplex: ostp_client::config::MultiplexConfig {
            enabled: client_cfg.mux.as_ref().and_then(|m| m.enabled).unwrap_or(false),
            sessions: client_cfg.mux.as_ref().and_then(|m| m.sessions).unwrap_or(1),
        },
        dns_server: None,
    };

    let metrics = Arc::new(BridgeMetrics {
        bytes_sent: portable_atomic::AtomicU64::new(0),
        bytes_recv: portable_atomic::AtomicU64::new(0),
        connection_state: portable_atomic::AtomicU8::new(0),
    });

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let metrics_clone = metrics.clone();
    let handle = tokio::spawn(async move {
        match ostp_client::runner::run_client_core(mapped, metrics_clone, shutdown_rx).await {
            Ok(_) => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    });

    guard.tunnel = Some(TunnelHandle::InProcess(InProcessState {
        shutdown_tx: Some(shutdown_tx),
        metrics,
        handle,
    }));
    Ok(true)
}

// ── Privileged TUN helper via named pipe ─────────────────────────────────────

const PIPE_NAME: &str = r"\\.\pipe\ostp-tun-helper";

async fn start_tun_via_helper(
    guard: &mut AppStateInner,
    _client_cfg: ClientConfigRaw,
    raw_config_json: String,
) -> Result<bool, String> {
    // Find the helper binary next to our exe
    let helper_exe = find_helper_exe().ok_or_else(|| {
        "ostp-tun-helper.exe not found next to the application. Please reinstall.".to_string()
    })?;

    // Launch with UAC elevation via ShellExecuteW("runas")
    launch_as_admin(&helper_exe).map_err(|e| format!("Failed to launch helper: {}", e))?;

    // Give the helper time to start and create the pipe
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

    // Connect to the helper's named pipe
    let pipe = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        async {
            loop {
                match tokio::net::windows::named_pipe::ClientOptions::new().open(PIPE_NAME) {
                    Ok(p) => return Ok::<_, std::io::Error>(p),
                    Err(_) => tokio::time::sleep(std::time::Duration::from_millis(200)).await,
                }
            }
        }
    ).await.map_err(|_| "Timed out connecting to TUN helper. It may have been denied by UAC.".to_string())?
     .map_err(|e| format!("Pipe connection error: {}", e))?;

    // Build the config JSON and send start command
    let mut mapped_config = serde_json::from_str::<serde_json::Value>(&raw_config_json)
        .map_err(|e| e.to_string())?;
    // Ensure mode is set
    if let Some(obj) = mapped_config.as_object_mut() {
        obj.insert("mode".to_string(), serde_json::Value::String("tun".to_string()));
    }
    let start_cmd = serde_json::json!({
        "cmd": "start",
        "config": serde_json::to_string(&mapped_config).unwrap_or_default()
    }).to_string();

    // Set up channel for sending commands to helper task
    let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::channel::<String>(16);

    // Spawn a task that manages the pipe I/O
    let pipe_state: Arc<Mutex<HelperPipeState>> = Arc::new(Mutex::new(HelperPipeState {
        connection_state: 1,
        bytes_sent: 0,
        bytes_recv: 0,
    }));
    let state_for_task = pipe_state.clone();

    tokio::spawn(async move {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::io::split;

        let (reader_half, mut writer_half) = split(pipe);
        let mut reader = BufReader::new(reader_half);

        // Send the start command
        let _ = writer_half.write_all(format!("{}\n", start_cmd).as_bytes()).await;

        // Concurrently: read from pipe, write commands from channel
        let mut line = String::new();
        loop {
            tokio::select! {
                result = reader.read_line(&mut line) => {
                    let n = result.unwrap_or(0);
                    if n == 0 { break; } // Helper disconnected
                    let trimmed = line.trim().to_string();
                    line.clear();
                    if trimmed.is_empty() { continue; }
                    if let Ok(msg) = serde_json::from_str::<HelperMsg>(&trimmed) {
                        let mut s = state_for_task.lock().await;
                        match msg {
                            HelperMsg::Status { value } => s.connection_state = value,
                            HelperMsg::Metrics { bytes_sent, bytes_recv } => {
                                s.bytes_sent = bytes_sent;
                                s.bytes_recv = bytes_recv;
                            }
                            HelperMsg::Error { .. } => s.connection_state = 0,
                            HelperMsg::Log { .. } => {}
                        }
                    }
                }
                cmd = cmd_rx.recv() => {
                    match cmd {
                        Some(c) => { let _ = writer_half.write_all(c.as_bytes()).await; }
                        None => break,
                    }
                }
            }
        }
        // Mark stopped
        let mut s = state_for_task.lock().await;
        s.connection_state = 0;
    });

    guard.tunnel = Some(TunnelHandle::Helper(HelperState {
        pipe_state,
        cmd_tx,
    }));

    Ok(true)
}

struct HelperPipeState {
    connection_state: u8,
    bytes_sent: u64,
    bytes_recv: u64,
}

fn find_helper_exe() -> Option<PathBuf> {
    // The helper is always built to the same target dir as the GUI exe.
    // In dev mode: target/debug/ostp-tun-helper.exe (same dir as ostp-gui.exe)
    // In release:  target/release/ostp-tun-helper.exe (same dir as ostp-gui.exe)
    // In installed build: next to ostp-gui.exe
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join("ostp-tun-helper.exe");
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn launch_as_admin(exe: &PathBuf) -> Result<()> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null_mut;

    let exe_wstr: Vec<u16> = exe.as_os_str().encode_wide().chain(Some(0)).collect();
    let verb_wstr: Vec<u16> = OsStr::new("runas").encode_wide().chain(Some(0)).collect();

    #[link(name = "shell32")]
    extern "system" {
        fn ShellExecuteW(
            hwnd: *mut std::ffi::c_void,
            lpOperation: *const u16,
            lpFile: *const u16,
            lpParameters: *const u16,
            lpDirectory: *const u16,
            nShowCmd: i32,
        ) -> isize;
    }

    let ret = unsafe {
        ShellExecuteW(
            null_mut(),
            verb_wstr.as_ptr(),
            exe_wstr.as_ptr(),
            null_mut(),
            null_mut(),
            0, // SW_HIDE
        )
    };

    if ret <= 32 {
        anyhow::bail!("ShellExecuteW failed (code {}). UAC was denied or helper not found.", ret);
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn launch_as_admin(_exe: &PathBuf) -> Result<()> {
    anyhow::bail!("TUN mode via helper is only supported on Windows");
}

// ── Tauri setup ───────────────────────────────────────────────────────────────

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let state = AppState(Mutex::new(AppStateInner { tunnel: None }));

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            start_tunnel,
            stop_tunnel,
            get_tunnel_status,
            get_metrics,
            get_config,
            save_config
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
