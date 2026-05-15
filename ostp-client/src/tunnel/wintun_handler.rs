use anyhow::{anyhow, Result};
use tokio::sync::watch;

#[cfg(target_os = "windows")]
pub async fn run_wintun_tunnel(
    config: crate::config::ClientConfig,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    use std::net::ToSocketAddrs;
    use std::process::{Command, Stdio, Child};

    struct WintunGuard {
        server_ip_str: String,
        child: Option<Child>,
    }
    
    impl Drop for WintunGuard {
        fn drop(&mut self) {
            if let Some(mut child) = self.child.take() {
                let _ = child.kill();
            }
            let cleanup_script = format!(
                "$remote_ip = '{}'\n\
                 Remove-NetRoute -DestinationPrefix \"$remote_ip/32\" -Confirm:$false -ErrorAction SilentlyContinue\n\
                 Remove-NetRoute -DestinationPrefix \"1.1.1.1/32\" -Confirm:$false -ErrorAction SilentlyContinue\n\
                 Remove-NetFirewallRule -DisplayName 'OSTP Tunnel*' -ErrorAction SilentlyContinue\n",
                self.server_ip_str
            );
            let _ = Command::new("powershell").args(["-Command", &cleanup_script]).output();
        }
    }

    let debug = config.debug;

    if debug {
        println!("[ostp-client] Initializing high-performance TUN tunnel via tun2socks...");
    }

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

    // 2. Resolve Server IP for routing table exclusion
    let server_ip = config.ostp.server_addr.to_socket_addrs()
        .map_err(|e| anyhow!("Failed to resolve remote server IP: {}", e))?
        .next()
        .map(|addr| addr.ip())
        .ok_or_else(|| anyhow!("Could not resolve host IP for routing exclusion"))?;
    
    let server_ip_str = server_ip.to_string();

    if debug {
        println!("[ostp-client] Resolved remote server IP: {}", server_ip_str);
    }

    // 3. Run PowerShell script to configure system routes
    if debug {
        println!("[ostp-client] Injecting system routing tables and excluding remote proxy...");
    }

    let current_exe = std::env::current_exe()?.to_string_lossy().into_owned();

    let setup_script = format!(
        "$remote_ip = '{}'\n\
         $exe_path = '{}'\n\
         $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Where-Object {{ $_.InterfaceAlias -notmatch 'tun' -and $_.InterfaceAlias -notmatch 'wintun' }} | Sort-Object RouteMetric | Select-Object -First 1\n\
         $gw = $route.NextHop\n\
         $ifIndex = $route.InterfaceIndex\n\
         # 1. Bypass route for the proxy server itself\n\
         New-NetRoute -DestinationPrefix \"$remote_ip/32\" -NextHop $gw -InterfaceIndex $ifIndex -RouteMetric 1 -ErrorAction SilentlyContinue\n\
         # 2. Bypass routes for all current Physical DNS servers to avoid UDP associate deadlocks\n\
         $dns_ips = Get-DnsClientServerAddress -InterfaceIndex $ifIndex | Select-Object -ExpandProperty ServerAddresses\n\
         foreach ($dns in $dns_ips) {{\n\
             if ($dns -match '^\\d+\\.\\d+\\.\\d+\\.\\d+$') {{\n\
                 New-NetRoute -DestinationPrefix \"$dns/32\" -NextHop $gw -InterfaceIndex $ifIndex -RouteMetric 1 -ErrorAction SilentlyContinue\n\
             }}\n\
         }}\n\
         New-NetRoute -DestinationPrefix \"1.1.1.1/32\" -NextHop $gw -InterfaceIndex $ifIndex -RouteMetric 1 -ErrorAction SilentlyContinue\n\
         # 3. Windows Firewall Rules\n\
         New-NetFirewallRule -DisplayName 'OSTP Tunnel In' -Direction Inbound -Program $exe_path -Action Allow -Enabled True -ErrorAction SilentlyContinue\n\
         New-NetFirewallRule -DisplayName 'OSTP Tunnel Out' -Direction Outbound -Program $exe_path -Action Allow -Enabled True -ErrorAction SilentlyContinue\n",
        server_ip_str, current_exe
    );

    let out = Command::new("powershell")
        .args(["-Command", &setup_script])
        .output()?;
    
    if !out.status.success() && debug {
        println!("[ostp-client] Warning: Setup routing returned: {}", String::from_utf8_lossy(&out.stderr));
    }

    // 4. Prepare and launch tun2socks.exe in the background
    // Switch from SOCKS5 to HTTP protocol. This natively forces tun2socks NOT to attempt UDP Associate,
    // preventing SOCKS5 command 3 unsupported errors while still tunneling 100% of global TCP traffic!
    let proxy_url = format!("http://{}", config.local_proxy.bind_addr);
    
    if debug {
        println!("[ostp-client] Spawning tun2socks daemon pointing to {}", proxy_url);
    }

    let mut child = Command::new(&tun2socks_exe)
        .args([
            "-device", "ostp_tun",
            "-proxy", &proxy_url,
            "-loglevel", if debug { "debug" } else { "error" }
        ])
        .current_dir(dir)
        .stdout(if debug { Stdio::piped() } else { Stdio::null() })
        .stderr(if debug { Stdio::piped() } else { Stdio::null() })
        .spawn()
        .map_err(|e| anyhow!("Failed to launch tun2socks.exe background process: {}", e))?;

    let mut _guard = WintunGuard {
        server_ip_str: server_ip_str.clone(),
        child: None, // Will set below
    };

    // 5. Once tun2socks creates the interface, apply network settings (IP, metric)
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    if debug {
        println!("[ostp-client] Applying network configurations onto 'ostp_tun' interface...");
    }

    // We omit setting dnsservers on the TUN interface entirely. This allows Windows to natively fallback
    // to the physical interface DNS servers, which are physically routed and work flawlessly.
    let net_setup = "\
        netsh interface ipv4 set address name=\"ostp_tun\" static 10.1.0.2 255.255.255.0 10.1.0.1\n\
        netsh interface ipv4 set interface name=\"ostp_tun\" metric=5\n";
    
    let _ = Command::new("powershell")
        .args(["-Command", net_setup])
        .output()?;

    println!("[client] TUN Tunnel established, internet traffic is now routing through OSTP.");

    // 6. Spawn thread to keep logging tun2socks output if in debug mode
    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    _guard.child = Some(child);

    if debug {
        std::thread::spawn(move || {
            use std::io::{BufRead, BufReader};
            if let Some(out) = stdout.take() {
                let reader = BufReader::new(out);
                for line in reader.lines().map_while(Result::ok) {
                    println!("[tun2socks] {}", line);
                }
            }
        });
        std::thread::spawn(move || {
            use std::io::{BufRead, BufReader};
            if let Some(err) = stderr.take() {
                let reader = BufReader::new(err);
                for line in reader.lines().map_while(Result::ok) {
                    println!("[tun2socks err] {}", line);
                }
            }
        });
    }

    // 7. Wait for shutdown signal
    let _ = shutdown.changed().await;

    println!("[client] Deactivating TUN tunnel and restoring system network topology...");

    // Drop guard runs cleanup automatically
    drop(_guard);

    println!("[client] TUN Tunnel stopped.");
    
    Ok(())
}

