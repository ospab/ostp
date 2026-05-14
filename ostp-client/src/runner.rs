use anyhow::Result;
use tokio::sync::{mpsc, watch};

use crate::app::BridgeCommand;
use crate::bridge::{Bridge, BridgeMetrics};
use crate::signal::wait_for_shutdown_signal;
use crate::tunnel;
use std::sync::Arc;

#[cfg(target_os = "windows")]
extern "system" {
    fn FreeConsole() -> i32;
    fn GetConsoleWindow() -> *mut std::ffi::c_void;
    fn ShowWindow(hwnd: *mut std::ffi::c_void, cmd_show: i32) -> i32;
}

fn hide_console() {
    #[cfg(target_os = "windows")]
    unsafe {
        let hwnd = GetConsoleWindow();
        if !hwnd.is_null() {
            ShowWindow(hwnd, 0); // SW_HIDE = 0
        }
        FreeConsole();
    }
}

#[cfg(target_os = "windows")]
fn is_admin() -> bool {
    std::process::Command::new("net")
        .arg("session")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(target_os = "windows")]
fn relaunch_as_admin() -> Result<()> {
    let current_exe = std::env::current_exe()?;
    let exe_str = current_exe.to_string_lossy();
    let _ = std::process::Command::new("powershell")
        .args([
            "-Command",
            &format!("Start-Process -FilePath '{}' -Verb RunAs", exe_str),
        ])
        .spawn()?;
    std::process::exit(0);
}

pub async fn run_client(config: crate::config::ClientConfig) -> Result<()> {
    let bg = std::env::args().any(|a| a == "--bg");

    if bg {
        hide_console();
    }

    #[cfg(target_os = "windows")]
    if config.mode == "tun" && !is_admin() {
        println!("[ostp-client] TUN mode requires Administrator privileges. Relaunching as Admin...");
        relaunch_as_admin()?;
    }

    if config.mode == "tun" && !config.exclusions.processes.is_empty() {
        println!("[ostp-client] WARNING: process exclusions are not supported in the current TUN implementation");
    }

    if config.mode == "tun" {
        tunnel::download_wintun_dll(config.debug)?;
        tunnel::download_tun2socks(config.debug)?;
    }

    let (proxy_events_tx, proxy_events_rx) = mpsc::channel(10000);
    let (client_msgs_tx, client_msgs_rx) = mpsc::channel(10000);

    let metrics = Arc::new(BridgeMetrics {
        bytes_sent: portable_atomic::AtomicU64::new(0),
        bytes_recv: portable_atomic::AtomicU64::new(0),
    });

    let bridge = Bridge::new(&config, metrics)?;

    let (ui_tx, mut ui_rx) = mpsc::channel(512);
    let (cmd_tx, cmd_rx) = mpsc::channel(128);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let proxy_shutdown_rx = shutdown_tx.subscribe();

    let is_tun = config.mode == "tun";

    // Auto-connect on startup
    let _ = cmd_tx.send(BridgeCommand::ToggleTunnel).await;

    let debug_enabled = config.debug;

    // Headless event logger
    let cmd_tx_clone = cmd_tx.clone();
    tokio::spawn(async move {
        let mut last_status = None;
        while let Some(msg) = ui_rx.recv().await {
            match msg {
                crate::app::UiEvent::Log(text) => {
                    if debug_enabled || is_essential_log(&text) {
                        println!("[client] {text}");
                    }
                }
                crate::app::UiEvent::Metrics { status, rtt_ms, .. } => {
                    let status_str = status.as_str().to_string();
                    if last_status != Some(status_str.clone()) {
                        last_status = Some(status_str.clone());
                        println!("[client] status={status_str} rtt_ms={:.1}", rtt_ms);
                    }
                }
                crate::app::UiEvent::Traffic { .. } => {}
                crate::app::UiEvent::ProfileChanged(profile) => {
                    if debug_enabled {
                        println!("[client] profile={profile:?}");
                    }
                }
                crate::app::UiEvent::TunnelStopped => {
                    if is_tun {
                        println!("[client] tunnel=tun stopped, reconnecting in 5s");
                    } else {
                        println!("[client] tunnel=proxy stopped, reconnecting in 5s");
                    }
                    let cmd_tx_inner = cmd_tx_clone.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                        let _ = cmd_tx_inner.send(BridgeCommand::ToggleTunnel).await;
                    });
                }
            }
        }
    });

    let bridge_task = tokio::spawn(async move {
        bridge.run(ui_tx, cmd_rx, shutdown_rx, proxy_events_rx, client_msgs_tx).await
    });

    let config_clone = config.clone();
    let proxy_task = tokio::spawn(async move {
        tunnel::run_local_proxy(
            config.local_proxy,
            config.ostp,
            config.exclusions,
            config.debug,
            proxy_shutdown_rx,
            proxy_events_tx,
            client_msgs_rx,
        )
        .await
    });

    let wintun_shutdown_rx = shutdown_tx.subscribe();
    let wintun_task = if config_clone.mode == "tun" {
        Some(tokio::spawn(async move {
            tunnel::run_wintun_tunnel(config_clone, wintun_shutdown_rx).await
        }))
    } else {
        None
    };

    // Wait for Ctrl-C / signal
    wait_for_shutdown_signal().await?;
    let _ = cmd_tx.send(BridgeCommand::Shutdown).await;

    let _ = shutdown_tx.send(true);
    let _ = bridge_task.await?;
    let _ = proxy_task.await?;
    if let Some(task) = wintun_task {
        let _ = task.await?;
    }
    tunnel::cleanup().await?;

    Ok(())
}

#[allow(dead_code)]
fn format_bytes(bps: u64) -> String {
    if bps >= 1_000_000 {
        format!("{:.1}MB", bps as f64 / 1_000_000.0)
    } else if bps >= 1_000 {
        format!("{:.1}KB", bps as f64 / 1_000.0)
    } else {
        format!("{bps}B")
    }
}

fn is_essential_log(text: &str) -> bool {
    matches!(
        text,
        "Handshaking started"
            | "Bridge connection established"
            | "TUN Tunnel established"
            | "Bridge stopped"
            | "TUN Tunnel stopped"
            | "Runtime config reloaded"
    ) || text.starts_with("Connected UDP directly to ")
        || text.starts_with("TURN: Relay allocated")
        || text.starts_with("TURN allocation failed")
        || text.starts_with("Handshake failed")
        || text.starts_with("Connection timeout")
}
