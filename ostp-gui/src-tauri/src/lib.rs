use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;
use serde::{Deserialize, Serialize};
use anyhow::Result;
use ostp_client::bridge::BridgeMetrics;
use portable_atomic::Ordering;

// Config deserialization matching ostp core
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(tag = "mode", rename_all = "lowercase")]
enum AppMode {
    Server(serde_json::Value), // We ignore server config in GUI
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

struct AppStateInner {
    shutdown_tx: Option<watch::Sender<bool>>,
    metrics: Option<Arc<BridgeMetrics>>,
    handle: Option<JoinHandle<Result<(), String>>>,
}

impl Drop for AppStateInner {
    fn drop(&mut self) {
        // Send final signal to ensure the core background threads exit immediately
        // and activate Wintun routing cleanup Drop routines.
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }
    }
}

struct AppState(Mutex<AppStateInner>);

fn get_config_path() -> PathBuf {
    // Standard behavior: same dir as current exe, or fall back to current working dir
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

#[tauri::command]
async fn get_config() -> Result<String, String> {
    let path = get_config_path();
    if !path.exists() {
        // Return default template if file missing
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
    // Validate formatting
    let _parsed: UnifiedConfig = serde_json::from_str(&json_content)
        .map_err(|e| format!("Invalid OSTP config JSON: {}", e))?;
    
    let path = get_config_path();
    std::fs::write(path, json_content).map_err(|e| format!("Write error: {}", e))?;
    Ok(true)
}

#[tauri::command]
async fn get_tunnel_status(state: tauri::State<'_, AppState>) -> Result<bool, String> {
    let guard = state.0.lock().await;
    if let Some(ref handle) = guard.handle {
        Ok(!handle.is_finished())
    } else {
        Ok(false)
    }
}

#[tauri::command]
async fn get_metrics(state: tauri::State<'_, AppState>) -> Result<Option<UIMetrics>, String> {
    let guard = state.0.lock().await;
    if let Some(ref metrics) = guard.metrics {
        Ok(Some(UIMetrics {
            bytes_sent: metrics.bytes_sent.load(Ordering::Relaxed),
            bytes_recv: metrics.bytes_recv.load(Ordering::Relaxed),
        }))
    } else {
        Ok(None)
    }
}

#[tauri::command]
async fn stop_tunnel(state: tauri::State<'_, AppState>) -> Result<bool, String> {
    let mut guard = state.0.lock().await;
    if let Some(tx) = guard.shutdown_tx.take() {
        let _ = tx.send(true);
    }
    if let Some(handle) = guard.handle.take() {
        let _ = handle.await;
    }
    guard.metrics = None;
    Ok(true)
}

#[tauri::command]
async fn start_tunnel(state: tauri::State<'_, AppState>) -> Result<bool, String> {
    // Ensure it's stopped first
    let mut guard = state.0.lock().await;
    if let Some(ref h) = guard.handle {
        if !h.is_finished() {
            return Ok(true); // Already running
        }
    }

    let path = get_config_path();
    if !path.exists() {
        return Err("config.json not found. Go to Settings and configure your key first.".into());
    }

    let content = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let unified: UnifiedConfig = serde_json::from_str(&content).map_err(|e| format!("Config parse error: {}", e))?;
    
    let client_cfg = match unified.mode {
        AppMode::Client(c) => c,
        AppMode::Server(_) => return Err("Configuration is in Server mode. GUI only supports Client configurations.".into()),
    };

    // Translate to ostp_client domain struct
    let is_tun_enabled = client_cfg.tun.as_ref().map(|t| t.enable).unwrap_or(false);
    let turn_cfg = client_cfg.turn.as_ref();
    
    let mapped_config = ostp_client::config::ClientConfig {
        mode: if is_tun_enabled { "tun".to_string() } else { "proxy".to_string() },
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
    };

    let metrics = Arc::new(BridgeMetrics {
        bytes_sent: portable_atomic::AtomicU64::new(0),
        bytes_recv: portable_atomic::AtomicU64::new(0),
    });
    
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    
    let metrics_clone = metrics.clone();
    let engine_handle = tokio::spawn(async move {
        match ostp_client::runner::run_client_core(mapped_config, metrics_clone, shutdown_rx).await {
            Ok(_) => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    });

    guard.shutdown_tx = Some(shutdown_tx);
    guard.metrics = Some(metrics);
    guard.handle = Some(engine_handle);

    Ok(true)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let state = AppState(Mutex::new(AppStateInner {
        shutdown_tx: None,
        metrics: None,
        handle: None,
    }));

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
