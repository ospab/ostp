use anyhow::{anyhow, Result};
use tokio::sync::{mpsc, watch};
#[cfg(target_os = "linux")]
use tracing::info;

use crate::tunnel::{ProxyEvent, ProxyToClientMsg};
#[cfg(target_os = "linux")]
use crate::tunnel::tun_device::create_tun_device;
#[cfg(target_os = "linux")]
use crate::tunnel::smoltcp_stack::run_smoltcp_stack;

#[cfg(target_os = "linux")]
use std::net::ToSocketAddrs;
#[cfg(target_os = "linux")]
use std::process::Command;

#[cfg(target_os = "linux")]
struct LinuxRouteGuard {
    server_ip_str: String,
    default_gw: String,
    default_if: String,
}

#[cfg(target_os = "linux")]
impl Drop for LinuxRouteGuard {
    fn drop(&mut self) {
        let cleanup_script = format!(
            "ip route del 0.0.0.0/1 dev ostp_tun || true; \
             ip route del 128.0.0.0/1 dev ostp_tun || true; \
             ip route del {} via {} dev {} || true; \
             ip route del 1.1.1.1 via {} dev {} || true; \
             ip link set dev ostp_tun down || true; \
             ip tuntap del name ostp_tun mode tun || true",
            self.server_ip_str, self.default_gw, self.default_if,
            self.default_gw, self.default_if
        );
        let _ = Command::new("sh").args(["-c", &cleanup_script]).output();
    }
}

#[cfg(target_os = "linux")]
pub async fn run_linux_tunnel(
    config: crate::config::ClientConfig,
    proxy_events_tx: mpsc::Sender<ProxyEvent>,
    client_msgs_rx: mpsc::UnboundedReceiver<(u16, ProxyToClientMsg)>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    info!("Initializing built-in Linux TUN tunnel...");

    // 1. Pre-flight system checks
    let is_root = Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
        .unwrap_or(false);

    if !is_root {
        return Err(anyhow!("FATAL: OSTP TUN mode requires root privileges on Linux. Please run via sudo."));
    }

    let has_ip_cmd = Command::new("which")
        .arg("ip")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !has_ip_cmd {
        return Err(anyhow!("FATAL: 'ip' command not found. OSTP TUN mode requires 'iproute2' package to be installed."));
    }

    // 2. Resolve Server IP for routing table exclusion
    let server_ip = config.ostp.server_addr.to_socket_addrs()
        .map_err(|e| anyhow!("Failed to resolve remote server IP: {}", e))?
        .next()
        .map(|addr| addr.ip())
        .ok_or_else(|| anyhow!("Could not resolve host IP for routing exclusion"))?;
    
    let server_ip_str = server_ip.to_string();
    info!("Resolved server IP: {}", server_ip_str);

    // 3. Detect current default gateway and interface
    let route_output = Command::new("sh")
        .arg("-c")
        .arg("ip route show default | head -n1")
        .output()?;
    
    let route_str = String::from_utf8_lossy(&route_output.stdout);
    let parts: Vec<&str> = route_str.split_whitespace().collect();
    
    let mut default_gw = String::new();
    let mut default_if = String::new();
    
    for i in 0..parts.len() {
        if parts[i] == "via" && i + 1 < parts.len() {
            default_gw = parts[i+1].to_string();
        }
        if parts[i] == "dev" && i + 1 < parts.len() {
            default_if = parts[i+1].to_string();
        }
    }

    if default_gw.is_empty() || default_if.is_empty() {
        return Err(anyhow!("Failed to discover active default gateway or network interface on Linux system."));
    }

    info!("Default route: gateway={} interface={}", default_gw, default_if);

    // Create the TunDevice inside the client process (creates the interface and sets up IP/MTU/Status)
    let tun_dev = create_tun_device("ostp_tun", config.ostp.mtu)?;

    let mut _guard = LinuxRouteGuard {
        server_ip_str: server_ip_str.clone(),
        default_gw: default_gw.clone(),
        default_if: default_if.clone(),
    };

    // 4. Setup routing rules
    let setup_script = format!(
        "ip route add {} via {} dev {}; \
         ip route add 1.1.1.1 via {} dev {}; \
         ip route add 0.0.0.0/1 dev ostp_tun; \
         ip route add 128.0.0.0/1 dev ostp_tun",
        server_ip_str, default_gw, default_if,
        default_gw, default_if
    );

    let out = Command::new("sh")
        .args(["-c", &setup_script])
        .output()?;
    
    if !out.status.success() {
        tracing::warn!("Warning: Setup routing returned: {}", String::from_utf8_lossy(&out.stderr));
    }

    info!("TUN tunnel active. Direct in-process packets handling started.");

    // Run the smoltcp stack loop in the background
    let stack_shutdown_rx = shutdown.clone();
    let stack_handle = tokio::spawn(async move {
        if let Err(e) = run_smoltcp_stack(
            tun_dev.packet_rx,
            tun_dev.packet_tx,
            config.ostp.mtu,
            proxy_events_tx,
            client_msgs_rx,
            stack_shutdown_rx,
        ).await {
            tracing::error!("smoltcp stack loop failed: {:?}", e);
        }
    });

    // 5. Wait for shutdown signal
    let _ = shutdown.changed().await;

    info!("Deactivating TUN tunnel...");
    drop(_guard);

    // Terminate smoltcp stack
    let _ = stack_handle.await;

    info!("TUN tunnel stopped.");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub async fn run_linux_tunnel(
    _config: crate::config::ClientConfig,
    _proxy_events_tx: mpsc::Sender<ProxyEvent>,
    _client_msgs_rx: mpsc::UnboundedReceiver<(u16, ProxyToClientMsg)>,
    _shutdown: watch::Receiver<bool>,
) -> Result<()> {
    Err(anyhow!("Linux tunnel driver executed on a non-Linux host!"))
}
