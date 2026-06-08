// ostp-tun-helper/src/main.rs
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use std::io::Write as _;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{watch, Mutex};
use tokio::net::TcpListener;
use portable_atomic::Ordering;

fn log_to_file(msg: &str) {
    let msg = msg.to_string();
    tokio::task::spawn_blocking(move || {
        let path = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("ostp-helper.log")))
            .unwrap_or_else(|| std::path::PathBuf::from("ostp-helper.log"));
        if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(file, "[{}] {}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"), msg);
        }
    });
}



#[derive(Deserialize)]
#[serde(tag = "cmd", rename_all = "lowercase")]
enum GuiCmd {
    Start { config: String, token: String },
    Reload { config: String, token: String },
    Stop { token: String },
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
#[allow(dead_code)]
enum HelperMsg {
    Status { value: u8 },
    Log { message: String },
    Metrics { bytes_sent: u64, bytes_recv: u64, rtt_ms: u32 },
    Error { message: String },
}

struct TunnelState {
    shutdown_tx: Option<watch::Sender<bool>>,
    config_tx: Option<watch::Sender<ostp_client::config::ClientConfig>>,
    metrics: Option<Arc<ostp_client::bridge::BridgeMetrics>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    ostp_client::logging::setup_panic_hook();
    let _log_guard = ostp_client::logging::init_tracing("info", "ostp-helper", env!("CARGO_PKG_VERSION"));

    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let _ = std::env::set_current_dir(dir);
        }
    }

    let mut expected_token = String::new();
    let mut port = 53211u16;
    let args: Vec<String> = std::env::args().collect();
    for i in 1..args.len() {
        if args[i] == "--port" && i + 1 < args.len() {
            port = args[i + 1].parse().unwrap_or(53211);
        }
        if args[i] == "--token" && i + 1 < args.len() {
            expected_token = args[i + 1].clone();
        }
    }

    log_to_file("Helper started (TCP mode)");

    if expected_token.is_empty() {
        log_to_file("FATAL: OSTP_TUN_TOKEN environment variable is required for security. Unauthorized access denied.");
        return Err(anyhow::anyhow!("OSTP_TUN_TOKEN environment variable is required"));
    }

    if let Err(e) = run_server(expected_token, port).await {
        log_to_file(&format!("Fatal error: {}", e));
    }
    log_to_file("Helper exiting");
    Ok(())
}

async fn run_server(expected_token: String, port: u16) -> Result<()> {
    let state = Arc::new(Mutex::new(TunnelState {
        shutdown_tx: None,
        config_tx: None,
        metrics: None,
    }));

    let bind_addr = format!("127.0.0.1:{}", port);
    log_to_file(&format!("Attempting to bind to {}", bind_addr));
    let listener = TcpListener::bind(&bind_addr).await.map_err(|e| {
        log_to_file(&format!("Bind failed: {}", e));
        e
    })?;
    log_to_file("Listening successfully");

    // Wait for GUI to connect (60 second timeout)
    let (socket, _) = match tokio::time::timeout(Duration::from_secs(60), listener.accept()).await {
        Ok(Ok(s)) => s,
        _ => {
            log_to_file("No connection from GUI within 60s, exiting");
            return Ok(());
        }
    };

    log_to_file("GUI connected via TCP");

    let (reader_half, writer_half) = tokio::io::split(socket);
    let writer = Arc::new(Mutex::new(writer_half));
    let mut reader = BufReader::new(reader_half);

    let send_msg = {
        let writer = writer.clone();
        move |msg: HelperMsg| {
            let writer = writer.clone();
            let json = serde_json::to_string(&msg).unwrap_or_default();
            tokio::spawn(async move {
                let mut w = writer.lock().await;
                let _ = w.write_all(format!("{}\n", json).as_bytes()).await;
            });
        }
    };

    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await.unwrap_or(0);
        if n == 0 {
            log_to_file("GUI disconnected, stopping tunnel");
            let mut st = state.lock().await;
            if let Some(tx) = st.shutdown_tx.take() {
                let _ = tx.send(true);
            }
            break;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() { continue; }

        let cmd: GuiCmd = match serde_json::from_str(trimmed) {
            Ok(c) => c,
            Err(e) => {
                send_msg(HelperMsg::Error { message: format!("Bad command: {}", e) });
                continue;
            }
        };

        match cmd {
            GuiCmd::Start { config, token } => {
                if token != expected_token {
                    log_to_file("Received START command with invalid token");
                    send_msg(HelperMsg::Error { message: "Invalid authorization token".to_string() });
                    continue;
                }
                log_to_file("Received START command");
                {
                    let mut st = state.lock().await;
                    if let Some(tx) = st.shutdown_tx.take() {
                        let _ = tx.send(true);
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }

                let cfg: ostp_client::config::ClientConfig = match serde_json::from_str(&config) {
                    Ok(c) => c,
                    Err(e) => {
                        log_to_file(&format!("Config parse error: {}", e));
                        send_msg(HelperMsg::Error { message: format!("Config parse error: {}", e) });
                        continue;
                    }
                };

                let metrics = Arc::new(ostp_client::bridge::BridgeMetrics {
                    bytes_sent: portable_atomic::AtomicU64::new(0),
                    bytes_recv: portable_atomic::AtomicU64::new(0),
                    connection_state: portable_atomic::AtomicU8::new(0),
                    rtt_ms: portable_atomic::AtomicU32::new(0),
                });

                let (shutdown_tx, shutdown_rx) = watch::channel(false);
                let (config_tx, config_rx) = watch::channel(cfg.clone());

                {
                    let mut st = state.lock().await;
                    st.shutdown_tx = Some(shutdown_tx);
                    st.config_tx = Some(config_tx);
                    st.metrics = Some(metrics.clone());
                }

                let metrics_for_runner = metrics.clone();
                let writer_for_err = writer.clone();
                let shutdown_rx_for_core = shutdown_rx.clone();
                tokio::spawn(async move {
                    log_to_file("Starting tunnel core...");
                    match ostp_client::runner::run_client_core(cfg, metrics_for_runner, shutdown_rx_for_core, Some(config_rx)).await {
                        Ok(_) => { log_to_file("Tunnel core stopped normally"); }
                        Err(e) => {
                            log_to_file(&format!("Tunnel core error: {}", e));
                            let json = serde_json::to_string(&HelperMsg::Error { message: e.to_string() }).unwrap_or_default();
                            let mut w = writer_for_err.lock().await;
                            let _ = w.write_all(format!("{}\n", json).as_bytes()).await;
                        }
                    }
                });

                let writer_tick = writer.clone();
                let metrics_tick = metrics.clone();
                let mut shutdown_rx_tick = shutdown_rx.clone();
                tokio::spawn(async move {
                    let mut last_state = 99u8;
                    loop {
                        tokio::select! {
                            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                            _ = shutdown_rx_tick.changed() => {
                                if *shutdown_rx_tick.borrow() { break; }
                            }
                        }
                        
                        let cs = metrics_tick.connection_state.load(Ordering::Relaxed);
                        let sent = metrics_tick.bytes_sent.load(Ordering::Relaxed);
                        let recv = metrics_tick.bytes_recv.load(Ordering::Relaxed);

                        let rtt = metrics_tick.rtt_ms.load(Ordering::Relaxed);

                        let mut w = writer_tick.lock().await;
                        if cs != last_state {
                            last_state = cs;
                            let json = serde_json::to_string(&HelperMsg::Status { value: cs }).unwrap_or_default();
                            if w.write_all(format!("{}\n", json).as_bytes()).await.is_err() { break; }
                        }
                        let json = serde_json::to_string(&HelperMsg::Metrics { bytes_sent: sent, bytes_recv: recv, rtt_ms: rtt }).unwrap_or_default();
                        if w.write_all(format!("{}\n", json).as_bytes()).await.is_err() { break; }
                        drop(w);
                    }
                });

                send_msg(HelperMsg::Status { value: 1 });
            }
            GuiCmd::Reload { config, token } => {
                if token != expected_token {
                    send_msg(HelperMsg::Error { message: "Invalid authorization token".to_string() });
                    continue;
                }
                log_to_file("Received RELOAD command");
                
                let cfg: ostp_client::config::ClientConfig = match serde_json::from_str(&config) {
                    Ok(c) => c,
                    Err(e) => {
                        send_msg(HelperMsg::Error { message: format!("Config parse error during reload: {}", e) });
                        continue;
                    }
                };

                {
                    let st = state.lock().await;
                    if let Some(tx) = &st.config_tx {
                        let _ = tx.send(cfg);
                        log_to_file("Config sent to running core for seamless hot-reload");
                    }
                }

                send_msg(HelperMsg::Status { value: 1 });
            }
            GuiCmd::Stop { token } => {
                if token != expected_token {
                    log_to_file("Received STOP command with invalid token");
                    send_msg(HelperMsg::Error { message: "Invalid authorization token".to_string() });
                    continue;
                }
                log_to_file("Received STOP command");
                let mut st = state.lock().await;
                if let Some(tx) = st.shutdown_tx.take() {
                    let _ = tx.send(true);
                }
                st.metrics = None;
                send_msg(HelperMsg::Status { value: 0 });
            }
        }
    }
    Ok(())
}
