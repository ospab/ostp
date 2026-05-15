use anyhow::Result;
use tokio::sync::{mpsc, watch};

use crate::app::BridgeCommand;
use crate::bridge::{Bridge, BridgeMetrics};
use crate::signal::wait_for_shutdown_signal;
use crate::tunnel;
use std::sync::Arc;

#[cfg(target_os = "windows")]
#[link(name = "kernel32")]
extern "system" {
    fn FreeConsole() -> i32;
    fn GetConsoleWindow() -> *mut std::ffi::c_void;
}

#[cfg(target_os = "windows")]
#[link(name = "user32")]
extern "system" {
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
pub fn is_admin() -> bool {
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
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null_mut;

    let exe = std::env::current_exe()?;
    let exe_wstr: Vec<u16> = exe.as_os_str().encode_wide().chain(Some(0)).collect();

    let mut args_joined = String::new();
    for arg in std::env::args().skip(1) {
        if !args_joined.is_empty() {
            args_joined.push(' ');
        }
        args_joined.push('"');
        args_joined.push_str(&arg.replace('"', "\\\""));
        args_joined.push('"');
    }
    let args_wstr: Vec<u16> = OsStr::new(&args_joined).encode_wide().chain(Some(0)).collect();

    let dir = std::env::current_dir()?;
    let dir_wstr: Vec<u16> = dir.as_os_str().encode_wide().chain(Some(0)).collect();

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

    unsafe {
        let ret = ShellExecuteW(
            null_mut(),
            verb_wstr.as_ptr(),
            exe_wstr.as_ptr(),
            args_wstr.as_ptr(),
            dir_wstr.as_ptr(),
            1, // SW_SHOWNORMAL = 1
        );
        if ret <= 32 {
            return Err(anyhow::anyhow!(
                "Windows UAC Elevation failed or was denied by policy (ShellExecuteW code: {})", 
                ret
            ));
        }
    }

    std::process::exit(0);
}

pub async fn run_client(config: crate::config::ClientConfig) -> Result<()> {
    #[cfg(target_os = "windows")]
    if config.mode == "tun" && !is_admin() {
        println!("[ostp-client] TUN mode requires Administrator privileges. Relaunching executable as Admin...");
        relaunch_as_admin()?;
    }

    let bg = std::env::args().any(|a| a == "--bg");

    if bg {
        hide_console();
    }

    let metrics = Arc::new(BridgeMetrics {
        bytes_sent: portable_atomic::AtomicU64::new(0),
        bytes_recv: portable_atomic::AtomicU64::new(0),
        connection_state: portable_atomic::AtomicU8::new(0),
    });

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    tokio::spawn(async move {
        if let Ok(_) = wait_for_shutdown_signal().await {
            let _ = shutdown_tx.send(true);
        }
    });

    run_client_core(config, metrics, shutdown_rx).await
}

pub async fn run_client_core(
    config: crate::config::ClientConfig,
    metrics: Arc<BridgeMetrics>,
    mut shutdown_rx_ext: watch::Receiver<bool>,
) -> Result<()> {
    #[cfg(target_os = "windows")]
    if config.mode == "tun" && !is_admin() {
        return Err(anyhow::anyhow!("Administrator privileges are required to initialize TUN mode. Please run the application as Administrator."));
    }

    if config.mode == "tun" && !config.exclusions.processes.is_empty() {
        println!("[ostp-client] WARNING: process exclusions are not supported in the current TUN implementation");
    }

    let (proxy_events_tx, proxy_events_rx) = mpsc::channel(10000);
    let (client_msgs_tx, client_msgs_rx) = mpsc::channel(10000);

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
            tunnel::run_tun_tunnel(config_clone, wintun_shutdown_rx).await
        }))
    } else {
        None
    };

    // Wait for external / UI shutdown signal
    let _ = shutdown_rx_ext.changed().await;
    
    let _ = cmd_tx.send(BridgeCommand::Shutdown).await;

    let _ = shutdown_tx.send(true);
    let _ = bridge_task.await?;
    let _ = proxy_task.await?;
    if let Some(task) = wintun_task {
        let _ = task.await?;
    }

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
