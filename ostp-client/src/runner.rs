use anyhow::Result;
use tokio::sync::{mpsc, watch};

use crate::app::BridgeCommand;
use crate::bridge::{Bridge, BridgeMetrics};
use crate::signal::wait_for_shutdown_signal;
use crate::tunnel;
use std::sync::Arc;
use std::fs::OpenOptions;
use std::io::Write as _;

fn log_to_core_file(msg: &str) {
    // Writes into the single shared ostp.log (same file as the tracing appender),
    // not a separate ostp-core.log — see logging::LOG_FILE_NAME.
    let path = crate::logging::log_file_path();
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "[{}] {}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"), msg);
    }
}

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

#[cfg(target_os = "linux")]
pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(target_os = "linux")]
fn relaunch_as_root() -> Result<()> {
    use std::io::IsTerminal;
    let exe = std::env::current_exe()?;
    let args: Vec<String> = std::env::args().skip(1).collect();

    let is_gui = std::env::var("DISPLAY").is_ok() || std::env::var("WAYLAND_DISPLAY").is_ok();
    let is_term = std::io::stdout().is_terminal();

    let mut cmd = if is_gui && !is_term {
        let mut c = std::process::Command::new("pkexec");
        c.arg(exe);
        c
    } else {
        let mut c = std::process::Command::new("sudo");
        c.arg(exe);
        c
    };

    cmd.args(&args);
    
    let status = cmd.status().map_err(|e| anyhow::anyhow!("Failed to execute privilege escalation command: {}", e))?;
    
    if !status.success() {
        return Err(anyhow::anyhow!("Privilege escalation failed or was denied."));
    }

    std::process::exit(0);
}

pub async fn run_client(config: crate::config::ClientConfig) -> Result<()> {
    #[cfg(target_os = "windows")]
    if config.mode == "tun" && !is_admin() {
        println!("[ostp] TUN mode requires administrator privileges. Relaunching...");
        relaunch_as_admin()?;
    }

    #[cfg(target_os = "linux")]
    if config.mode == "tun" && !is_root() {
        println!("[ostp] TUN mode requires root privileges. Requesting sudo/pkexec elevation...");
        relaunch_as_root()?;
    }

    let bg = std::env::args().any(|a| a == "--bg");

    if bg {
        hide_console();
    }

    let metrics = Arc::new(BridgeMetrics {
        bytes_sent: portable_atomic::AtomicU64::new(0),
        bytes_recv: portable_atomic::AtomicU64::new(0),
        connection_state: portable_atomic::AtomicU8::new(0),
        rtt_ms: portable_atomic::AtomicU32::new(0),
    });

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    tokio::spawn(async move {
        if wait_for_shutdown_signal().await.is_ok() {
            let _ = shutdown_tx.send(true);
        }
    });

    run_client_core(config, metrics, shutdown_rx, None).await
}

/// Runs the client until shutdown. Reconnecting to the server is the bridge's
/// job (one policy: move the session, else handshake again). This loop only
/// restarts everything when a task dies outright (proxy listener, TUN device),
/// with backoff, so a crashed component does not end the client.
pub async fn run_client_core(
    config: crate::config::ClientConfig,
    metrics: Arc<BridgeMetrics>,
    mut shutdown_rx_ext: watch::Receiver<bool>,
    config_rx: Option<watch::Receiver<crate::config::ClientConfig>>,
) -> Result<()> {
    use portable_atomic::Ordering;

    const BACKOFF_SCHEDULE_SECS: [u64; 6] = [1, 2, 5, 10, 20, 30];
    // A run that stayed up at least this long counts as "was actually
    // connected", so a later drop restarts the backoff from the top instead
    // of inheriting a long delay from a previous flaky stretch.
    const STABLE_UPTIME: std::time::Duration = std::time::Duration::from_secs(60);
    let mut backoff_idx = 0usize;

    loop {
        if *shutdown_rx_ext.borrow() {
            return Ok(());
        }

        let attempt_start = std::time::Instant::now();
        let result = run_client_once(config.clone(), metrics.clone(), shutdown_rx_ext.clone(), config_rx.clone()).await;

        if *shutdown_rx_ext.borrow() {
            // Shutdown was requested during (or right after) this attempt — honor it, don't retry.
            return match result {
                Err(RunError::Startup(e) | RunError::Crashed(e)) => Err(e),
                Ok(()) => Ok(()),
            };
        }
        match result {
            Ok(()) => {}
            // Never retry a start that failed: the user fixes the cause and starts again.
            Err(RunError::Startup(e)) => return Err(e),
            Err(RunError::Crashed(e)) => {
                tracing::warn!("client run ended unexpectedly, will auto-reconnect: {e}");
            }
        }

        if attempt_start.elapsed() >= STABLE_UPTIME {
            backoff_idx = 0;
        }
        let delay = BACKOFF_SCHEDULE_SECS[backoff_idx.min(BACKOFF_SCHEDULE_SECS.len() - 1)];
        backoff_idx += 1;

        // Reflect the retry wait as "connecting" rather than "disconnected".
        metrics.connection_state.store(1, Ordering::Relaxed);
        tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_secs(delay)) => {}
            _ = shutdown_rx_ext.changed() => {
                if *shutdown_rx_ext.borrow() {
                    return Ok(());
                }
            }
        }
    }
}

/// Why one run ended. The split decides whether `run_client_core` starts again.
enum RunError {
    /// The client never got going: bad address, no privileges, the first
    /// connection refused. Retrying would fail the same way, so the user decides.
    Startup(anyhow::Error),
    /// A task died after the link had been up: worth a restart.
    Crashed(anyhow::Error),
}

async fn run_client_once(
    mut config: crate::config::ClientConfig,
    metrics: Arc<BridgeMetrics>,
    mut shutdown_rx_ext: watch::Receiver<bool>,
    mut config_rx: Option<watch::Receiver<crate::config::ClientConfig>>,
) -> std::result::Result<(), RunError> {
    #[cfg(target_os = "windows")]
    if config.mode == "tun" && !is_admin() {
        return Err(RunError::Startup(anyhow::anyhow!("Administrator privileges are required to initialize TUN mode. Please run the application as Administrator.")));
    }

    #[cfg(target_os = "linux")]
    if config.mode == "tun" && !is_root() {
        return Err(RunError::Startup(anyhow::anyhow!("Root privileges are required to initialize TUN mode on Linux. Please run with sudo.")));
    }

    log_to_core_file(&format!("[core] Starting run_client_core in mode: {}", config.mode));
    // The name as configured, for error messages (server_addr is replaced by an IP below).
    let server_name = config.ostp.server_addr.clone();

    // Resolve the server IP before we override system routing and DNS.
    // This prevents DNS deadlock if the VPN disconnects and tries to reconnect,
    // and also ensures we add the direct route to the exact IP the bridge connects to.
    #[allow(unused_mut)]
    let mut resolved_addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host(&config.ostp.server_addr)
        .await
        .map_err(|e| RunError::Startup(anyhow::anyhow!("Failed to resolve server address {}: {}", config.ostp.server_addr, e)))?
        .collect();
    // IPv4 first (stable sort keeps the resolver's order within a family): a
    // blackholed IPv6 route would otherwise make the only address we hand to the
    // bridge a dead one, and IPv4 would never be tried.
    resolved_addrs.sort_by_key(|a| a.is_ipv6());

    let target_addr = resolved_addrs.first()
        .ok_or_else(|| RunError::Startup(anyhow::anyhow!("No IP addresses resolved for {}", config.ostp.server_addr)))?;

    log_to_core_file(&format!("[core] Resolved server address to {}", target_addr));
    // The bridge derives the TLS SNI and the upgrade's Host header from
    // server_addr when tls_sni is unset. Pin the name before replacing it with
    // the IP, or the certificate check and the web server's vhost both see the
    // bare IP (certificate "not valid for name", or the default site's 200).
    if config.transport.tls_sni.is_none() {
        config.transport.tls_sni = server_name_to_pin(&config.ostp.server_addr);
    }
    config.ostp.server_addr = target_addr.to_string();


    // The system proxy is set by the bridge while it is connected (proxy mode
    // only). Setting it here as well enabled it twice, and the bridge's second
    // enable reset the bypass list this one had just written.

    let (proxy_events_tx, proxy_events_rx) = mpsc::channel(256);
    let (client_msgs_tx, client_msgs_rx) = mpsc::unbounded_channel();
    
    // Setup exclusions hot-reload channel
    let (reload_tx, reload_rx) = watch::channel(config.exclusions.clone());

    let mut bridge = Bridge::new(&config, metrics).map_err(RunError::Startup)?;
    bridge.reload_tx = Some(reload_tx.clone());

    let (ui_tx, mut ui_rx) = mpsc::channel(512);
    let (cmd_tx, cmd_rx) = mpsc::channel(128);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let proxy_shutdown_rx = shutdown_tx.subscribe();


    // Auto-connect on startup
    let _ = cmd_tx.send(BridgeCommand::ToggleTunnel).await;

    let debug_enabled = config.debug;

    // The bridge reports a first connection that failed as "Connection failed:"
    // followed by TunnelStopped, and then idles. Nobody toggles the tunnel here,
    // so an unrequested TunnelStopped before the link was up ends this run.
    let was_up = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let was_up_logger = was_up.clone();
    let (first_fail_tx, mut first_fail_rx) = tokio::sync::oneshot::channel::<String>();

    // Headless event logger
    tokio::spawn(async move {
        let mut last_status = None;
        let mut last_failure = String::new();
        let mut first_fail_tx = Some(first_fail_tx);
        while let Some(msg) = ui_rx.recv().await {
            match msg {
                crate::app::UiEvent::Log(text) => {
                    if let Some(reason) = text.strip_prefix("Connection failed:") {
                        last_failure = reason.trim().to_string();
                    }
                    if debug_enabled || is_essential_log(&text) {
                        log_to_core_file(&format!("[ostp] {text}"));
                        println!("[ostp] {text}");
                    }
                }
                crate::app::UiEvent::Metrics { status, rtt_ms, .. } => {
                    if matches!(status, crate::app::ConnectionStatus::Established) {
                        was_up_logger.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                    let status_str = status.as_str().to_string();
                    if last_status != Some(status_str.clone()) {
                        last_status = Some(status_str.clone());
                        println!("[ostp] Status: {} (rtt={:.1}ms)", status_str, rtt_ms);
                    }
                }
                crate::app::UiEvent::Traffic { .. } => {}
                crate::app::UiEvent::ProfileChanged(profile) => {
                    if debug_enabled {
                        println!("[ostp] Obfuscation profile: {profile:?}");
                    }
                }
                crate::app::UiEvent::TunnelStopped => {
                    println!("[ostp] Tunnel stopped");
                    if !was_up_logger.load(std::sync::atomic::Ordering::Relaxed) {
                        if let Some(tx) = first_fail_tx.take() {
                            let _ = tx.send(std::mem::take(&mut last_failure));
                        }
                    }
                }
            }
        }
    });

    let mut bridge_task = tokio::spawn(async move {
        bridge.run(ui_tx, cmd_rx, shutdown_rx, proxy_events_rx, client_msgs_tx).await
    });

    let config_clone = config.clone();
    let proxy_exclusions_rx = reload_rx.clone();
    let mut proxy_task = tokio::spawn(async move {
        tunnel::run_local_proxy(
            config.local_proxy,
            config.ostp,
            proxy_exclusions_rx,
            config.debug,
            proxy_shutdown_rx,
            proxy_events_tx,
            client_msgs_rx,
        )
        .await
    });

    let wintun_shutdown_rx = shutdown_tx.subscribe();
    let wintun_exclusions_rx = reload_rx.clone();
    let mut wintun_task = if config_clone.mode == "tun" {
        Some(tokio::spawn(async move {
            tunnel::run_tun_tunnel(config_clone, wintun_shutdown_rx, wintun_exclusions_rx).await
        }))
    } else {
        None
    };

    // Wait for local_shutdown
    let mut local_shutdown = shutdown_rx_ext.clone();
    let cmd_tx_loop = cmd_tx.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = local_shutdown.changed() => {
                    if *local_shutdown.borrow() {
                        let _ = cmd_tx_loop.send(BridgeCommand::Shutdown).await;
                        break;
                    }
                }
                Some(Ok(_)) = async {
                    if let Some(ref mut rx) = config_rx {
                        Some(rx.changed().await)
                    } else {
                        std::future::pending().await
                    }
                } => {
                    if let Some(ref rx) = config_rx {
                        let new_cfg = rx.borrow().clone();
                        // Update Windows ProxyOverride so excluded domains/IPs
                        // bypass the system proxy immediately (proxy mode only).
                        crate::sysproxy::update_proxy_bypass_list(
                            &new_cfg.exclusions.domains,
                            &new_cfg.exclusions.ips,
                        );
                        let _ = reload_tx.send(new_cfg.exclusions);
                    }
                }
            }
        }
    });

    // Wait for either external shutdown OR any task to fail
    let mut outcome: std::result::Result<(), anyhow::Error> = Ok(());
    let mut first_connect_failed = false;
    tokio::select! {
        _ = shutdown_rx_ext.changed() => {
            let _ = cmd_tx.send(BridgeCommand::Shutdown).await;
            let _ = shutdown_tx.send(true);
        }
        Ok(reason) = &mut first_fail_rx => {
            let _ = shutdown_tx.send(true);
            first_connect_failed = true;
            outcome = Err(if reason.is_empty() {
                anyhow::anyhow!("the first connection to {} failed", server_name)
            } else {
                anyhow::anyhow!("the first connection to {} failed: {}", server_name, reason)
            });
        }
        res = &mut bridge_task => {
            let _ = shutdown_tx.send(true);
            outcome = res.map_err(|e| anyhow::anyhow!("Bridge task panicked: {}", e)).and_then(|r| r);
        }
        res = &mut proxy_task => {
            let _ = shutdown_tx.send(true);
            outcome = res.map_err(|e| anyhow::anyhow!("Proxy task panicked: {}", e)).and_then(|r| r);
        }
        res = async {
            if let Some(t) = wintun_task.as_mut() { t.await } else { std::future::pending().await }
        } => {
            let _ = shutdown_tx.send(true);
            outcome = res.map_err(|e| anyhow::anyhow!("TUN task panicked: {}", e)).and_then(|r| r);
        }
    }

    // Final cleanup: wait for tasks to finish
    let _ = bridge_task.await;
    let _ = proxy_task.await;
    if let Some(task) = wintun_task {
        let _ = task.await;
    }

    match outcome {
        Ok(()) => Ok(()),
        Err(e) if first_connect_failed || !was_up.load(std::sync::atomic::Ordering::Relaxed) => Err(RunError::Startup(e)),
        Err(e) => Err(RunError::Crashed(e)),
    }
}

fn is_essential_log(text: &str) -> bool {
    matches!(
        text,
        "Connection established"
            | "TUN tunnel established"
            | "TUN tunnel stopped"
            | "Bridge stopped"
            | "Runtime config reloaded"
            | "Connecting to remote server..."
    ) || text.starts_with("Reconnect attempt")
        || text.starts_with("Connection attempt")
        || text.starts_with("Connected to ")
        || text.starts_with("TURN relay allocated")
        || text.starts_with("TURN allocation failed")
        || text.starts_with("Allocating TURN relay")
        || text.starts_with("Connection failed:")
        || text.starts_with("Connection lost")
        || text.starts_with("Protocol tick fatal error")
}

/// The host of `server_addr` when it is a name rather than an IP literal:
/// the name the certificate and the web server's vhost are issued for.
fn server_name_to_pin(server_addr: &str) -> Option<String> {
    let host = crate::bridge::server_host(server_addr);
    (!host.is_empty() && host.parse::<std::net::IpAddr>().is_err()).then_some(host)
}

#[cfg(test)]
mod server_name_tests {
    use super::server_name_to_pin;

    #[test]
    fn pins_names_but_not_ip_literals() {
        assert_eq!(server_name_to_pin("alt.ospab.org:443").as_deref(), Some("alt.ospab.org"));
        assert_eq!(server_name_to_pin("alt.ospab.org").as_deref(), Some("alt.ospab.org"));
        assert_eq!(server_name_to_pin("31.76.224.166:443"), None);
        assert_eq!(server_name_to_pin("[2001:db8::1]:443"), None);
    }
}
