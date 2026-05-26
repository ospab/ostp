use anyhow::{anyhow, Result};
use tokio::sync::{mpsc, watch};
#[cfg(target_os = "windows")]
use tracing::info;

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

use crate::tunnel::{ProxyEvent, ProxyToClientMsg};
#[cfg(target_os = "windows")]
use crate::tunnel::tun_device::create_tun_device;
#[cfg(target_os = "windows")]
use crate::tunnel::smoltcp_stack::run_smoltcp_stack;

#[cfg(target_os = "windows")]
pub async fn run_wintun_tunnel(
    config: crate::config::ClientConfig,
    proxy_events_tx: mpsc::Sender<ProxyEvent>,
    client_msgs_rx: mpsc::UnboundedReceiver<(u16, ProxyToClientMsg)>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    use std::net::ToSocketAddrs;
    use std::process::Command;

    const CREATE_NO_WINDOW: u32 = 0x08000000;
    const TUN_NAME: &str = "ostp_tun";

    struct WintunGuard {
        server_ip_str: String,
    }
    
    impl Drop for WintunGuard {
        fn drop(&mut self) {
            let cleanup_script = format!(
                "$remote_ip = '{}'\n\
                 Remove-NetRoute -DestinationPrefix \"$remote_ip/32\" -Confirm:$false -ErrorAction SilentlyContinue\n\
                 Remove-NetRoute -DestinationPrefix \"1.1.1.1/32\" -Confirm:$false -ErrorAction SilentlyContinue\n\
                 Remove-NetFirewallRule -DisplayName 'OSTP Tunnel*' -ErrorAction SilentlyContinue\n\
                 netsh interface ipv4 set dnsservers name=\"{TUN_NAME}\" source=dhcp 2>$null\n",
                self.server_ip_str
            );
            let _ = Command::new("powershell")
                .creation_flags(CREATE_NO_WINDOW)
                .args(["-NoProfile", "-Command", &cleanup_script])
                .output();
        }
    }

    info!("Initializing built-in Wintun TUN tunnel...");

    // 1. Delete stale TUN adapter if it exists from a previous run.
    let _ = Command::new("powershell")
        .creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile", "-Command", &format!(
            "Get-NetAdapter -Name '{TUN_NAME}*' -ErrorAction SilentlyContinue | \
             Disable-NetAdapter -Confirm:$false -ErrorAction SilentlyContinue; \
             netsh interface set interface \"{TUN_NAME}\" admin=disable 2>$null"
        )])
        .output();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // 2. Resolve Server IP for routing table exclusion
    let server_ip = config.ostp.server_addr.to_socket_addrs()
        .map_err(|e| anyhow!("Failed to resolve remote server IP: {}", e))?
        .next()
        .map(|addr| addr.ip())
        .ok_or_else(|| anyhow!("Could not resolve host IP for routing exclusion"))?;
    
    let server_ip_str = server_ip.to_string();
    info!("Resolved server IP: {}", server_ip_str);

    // 3. Prepare routing and firewall setup script
    let current_exe = std::env::current_exe()?.to_string_lossy().into_owned();

    let setup_script = format!(
        "$remote_ip = '{}'\n\
         $exe_path = '{}'\n\
         $route = Find-NetRoute -RemoteIPAddress $remote_ip -ErrorAction SilentlyContinue | Select-Object -First 1\n\
         if (-not $route) {{\n\
             $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Where-Object {{ $_.InterfaceAlias -notmatch 'tun' -and $_.InterfaceAlias -notmatch 'wintun' }} | Sort-Object RouteMetric | Select-Object -First 1\n\
         }}\n\
         $gw = $route.NextHop\n\
         $ifIndex = $route.InterfaceIndex\n\
         New-NetRoute -DestinationPrefix \"$remote_ip/32\" -NextHop $gw -InterfaceIndex $ifIndex -RouteMetric 1 -ErrorAction SilentlyContinue\n\
         $dns_ips = Get-DnsClientServerAddress -InterfaceIndex $ifIndex | Select-Object -ExpandProperty ServerAddresses\n\
         foreach ($dns in $dns_ips) {{\n\
             if ($dns -match '^\\d+\\.\\d+\\.\\d+\\.\\d+$') {{\n\
                 New-NetRoute -DestinationPrefix \"$dns/32\" -NextHop $gw -InterfaceIndex $ifIndex -RouteMetric 1 -ErrorAction SilentlyContinue\n\
             }}\n\
         }}\n\
         New-NetRoute -DestinationPrefix \"1.1.1.1/32\" -NextHop $gw -InterfaceIndex $ifIndex -RouteMetric 1 -ErrorAction SilentlyContinue\n\
         New-NetFirewallRule -DisplayName 'OSTP Tunnel In' -Direction Inbound -Program $exe_path -Action Allow -Enabled True -ErrorAction SilentlyContinue\n\
         New-NetFirewallRule -DisplayName 'OSTP Tunnel Out' -Direction Outbound -Program $exe_path -Action Allow -Enabled True -ErrorAction SilentlyContinue\n",
        server_ip_str, current_exe
    );

    // Create the TunDevice inside the client process
    let tun_dev = create_tun_device(TUN_NAME, config.ostp.mtu)?;

    let mut _guard = WintunGuard {
        server_ip_str: server_ip_str.clone(),
    };

    // Run route setup in parallel
    let route_handle = {
        let script = setup_script.clone();
        tokio::task::spawn_blocking(move || {
            Command::new("powershell")
                .creation_flags(CREATE_NO_WINDOW)
                .args(["-NoProfile", "-Command", &script])
                .output()
        })
    };

    // 5. Wait for TUN adapter to appear
    let adapter_deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(8);
    let mut adapter_ready = false;
    while tokio::time::Instant::now() < adapter_deadline {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        let check = Command::new("powershell")
            .creation_flags(CREATE_NO_WINDOW)
            .args(["-NoProfile", "-Command",
                &format!("(Get-NetAdapter -Name '{TUN_NAME}' -ErrorAction SilentlyContinue).Status")])
            .output();
        if let Ok(out) = check {
            let status = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if status == "Up" || status == "Disconnected" || !status.is_empty() {
                adapter_ready = true;
                break;
            }
        }
    }

    if !adapter_ready {
        tracing::warn!("WARNING: TUN adapter did not appear within timeout. Proceeding anyway.");
    }

    // Wait for route setup to finish
    let _ = route_handle.await;

    // 6. Configure the adapter
    info!("Applying network configuration...");
    let mut net_setup = format!(
        "netsh interface ipv4 set address name=\"{TUN_NAME}\" static 10.1.0.2 255.255.255.0 10.1.0.1\n\
         netsh interface ipv4 set subinterface \"{TUN_NAME}\" mtu={} store=persistent\n\
         netsh interface ipv4 set interface name=\"{TUN_NAME}\" metric=5\n",
         config.ostp.mtu
    );
    
    if let Some(ref dns) = config.dns_server {
        if !dns.is_empty() {
            info!("DNS server: {}", dns);
            net_setup.push_str(&format!(
                "netsh interface ipv4 set dnsservers name=\"{TUN_NAME}\" static {} primary\n", dns
            ));
        }
    }
    
    let _ = Command::new("powershell")
        .creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile", "-Command", &net_setup])
        .output()?;

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

    // 8. Wait for shutdown signal
    let _ = shutdown.changed().await;

    info!("Deactivating TUN tunnel...");
    drop(_guard);
    
    // Terminate smoltcp stack
    let _ = stack_handle.await;

    info!("TUN tunnel stopped.");
    Ok(())
}

#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
pub async fn run_wintun_tunnel(
    _config: crate::config::ClientConfig,
    _proxy_events_tx: mpsc::Sender<ProxyEvent>,
    _client_msgs_rx: mpsc::UnboundedReceiver<(u16, ProxyToClientMsg)>,
    _shutdown: watch::Receiver<bool>,
) -> Result<()> {
    Err(anyhow!("Wintun driver executed on a non-Windows host!"))
}
