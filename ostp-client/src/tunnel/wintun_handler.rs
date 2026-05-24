use anyhow::{anyhow, Result};
use tokio::sync::watch;

#[cfg(target_os = "windows")]
pub async fn run_wintun_tunnel(
    config: crate::config::ClientConfig,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    use std::net::ToSocketAddrs;
    use std::process::{Command, Stdio, Child};
    use std::os::windows::process::CommandExt;

    const CREATE_NO_WINDOW: u32 = 0x08000000;
    const TUN_NAME: &str = "ostp_tun";

    struct WintunGuard {
        server_ip_str: String,
        child: Option<Child>,
    }
    
    impl Drop for WintunGuard {
        fn drop(&mut self) {
            if let Some(mut child) = self.child.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
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

    let debug = config.debug;

    tracing::info!("Initializing TUN tunnel...");

    let exe = std::env::current_exe()?;
    let dir = exe.parent().ok_or_else(|| anyhow!("failed to get binary directory"))?;
    let tun2socks_exe = dir.join("tun2socks.exe");

    if !tun2socks_exe.exists() {
        return Err(anyhow!(
            "CRITICAL: 'tun2socks.exe' binary is missing!\n\
            OSTP requires tun2socks for TUN mode on Windows. Please download the appropriate binary from: \n\
            https://github.com/xjasonlyu/tun2socks/releases \n\
            and place it in the same directory as the ostp executable ({}).",
            dir.display()
        ));
    }

    // 1. Delete stale TUN adapter if it exists from a previous run.
    //    This prevents wintun from creating "ostp_tun 2", "ostp_tun 3", etc.
    tracing::info!("Cleaning up stale TUN adapter...");
    let _ = Command::new("powershell")
        .creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile", "-Command", &format!(
            "Get-NetAdapter -Name '{TUN_NAME}*' -ErrorAction SilentlyContinue | \
             Disable-NetAdapter -Confirm:$false -ErrorAction SilentlyContinue; \
             netsh interface set interface \"{TUN_NAME}\" admin=disable 2>$null"
        )])
        .output();
    // Brief pause to let the driver release the adapter
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // 2. Resolve Server IP for routing table exclusion
    let server_ip = config.ostp.server_addr.to_socket_addrs()
        .map_err(|e| anyhow!("Failed to resolve remote server IP: {}", e))?
        .next()
        .map(|addr| addr.ip())
        .ok_or_else(|| anyhow!("Could not resolve host IP for routing exclusion"))?;
    
    let server_ip_str = server_ip.to_string();
    tracing::info!("Resolved server IP: {}", server_ip_str);

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

    // 4. Launch tun2socks + route setup IN PARALLEL to save ~3 seconds
    let proxy_url = format!("http://{}", config.local_proxy.bind_addr);
    tracing::info!("Starting tun2socks (proxy={})", proxy_url);

    // Spawn tun2socks immediately — it creates the adapter on its own
    let mut child = Command::new(&tun2socks_exe)
        .creation_flags(CREATE_NO_WINDOW)
        .args([
            "-device", TUN_NAME,
            "-proxy", &proxy_url,
            "-loglevel", if debug { "debug" } else { "error" }
        ])
        .current_dir(dir)
        .stdout(if debug { Stdio::piped() } else { Stdio::null() })
        .stderr(if debug { Stdio::piped() } else { Stdio::null() })
        .spawn()
        .map_err(|e| anyhow!("Failed to launch tun2socks.exe: {}", e))?;

    let mut _guard = WintunGuard {
        server_ip_str: server_ip_str.clone(),
        child: None,
    };

    // Run route setup in parallel while tun2socks creates the adapter.
    // Also poll for the adapter to appear (typically <1s).
    let route_handle = {
        let script = setup_script.clone();
        tokio::task::spawn_blocking(move || {
            Command::new("powershell")
                .creation_flags(CREATE_NO_WINDOW)
                .args(["-NoProfile", "-Command", &script])
                .output()
        })
    };

    // 5. Wait for TUN adapter to appear (poll with timeout instead of fixed 2s sleep)
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
            if debug {
                tracing::info!("Adapter status: '{}'", status);
            }
            if status == "Up" || status == "Disconnected" || !status.is_empty() {
                adapter_ready = true;
                break;
            }
        }
    }

    if !adapter_ready {
        tracing::warn!("WARNING: TUN adapter did not appear within timeout. Proceeding anyway.");
    }

    // Wait for route setup to finish (should already be done by now)
    let _ = route_handle.await;

    // 6. Configure the adapter (IP, metric, MTU, DNS)
    tracing::info!("Applying network configuration...");
    let mut net_setup = format!(
        "netsh interface ipv4 set address name=\"{TUN_NAME}\" static 10.1.0.2 255.255.255.0 10.1.0.1\n\
         netsh interface ipv4 set subinterface \"{TUN_NAME}\" mtu={} store=persistent\n\
         netsh interface ipv4 set interface name=\"{TUN_NAME}\" metric=5\n",
         config.ostp.mtu
    );
    
    if let Some(ref dns) = config.dns_server {
        if !dns.is_empty() {
            tracing::info!("DNS server: {}", dns);
            net_setup.push_str(&format!(
                "netsh interface ipv4 set dnsservers name=\"{TUN_NAME}\" static {} primary\n", dns
            ));
        }
    }
    
    let _ = Command::new("powershell")
        .creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile", "-Command", &net_setup])
        .output()?;

    tracing::info!("TUN tunnel active. All traffic is routed through OSTP.");

    // 7. Spawn debug log readers for tun2socks output
    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    _guard.child = Some(child);

    if debug {
        std::thread::spawn(move || {
            use std::io::{BufRead, BufReader};
            if let Some(out) = stdout.take() {
                let reader = BufReader::new(out);
                for line in reader.lines().map_while(Result::ok) {
                    tracing::debug!("tun2socks: {}", line);
                }
            }
        });
        std::thread::spawn(move || {
            use std::io::{BufRead, BufReader};
            if let Some(err) = stderr.take() {
                let reader = BufReader::new(err);
                for line in reader.lines().map_while(Result::ok) {
                    tracing::warn!("tun2socks: {}", line);
                }
            }
        });
    }

    // 8. Wait for shutdown signal
    let _ = shutdown.changed().await;

    tracing::info!("Deactivating TUN tunnel...");
    drop(_guard);
    tracing::info!("TUN tunnel stopped.");
    
    Ok(())
}

#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
pub async fn run_wintun_tunnel(
    _config: crate::config::ClientConfig,
    _shutdown: watch::Receiver<bool>,
) -> Result<()> {
    Err(anyhow!("Wintun driver executed on a non-Windows host!"))
}
