use anyhow::{anyhow, Result};
use tokio::sync::watch;

#[cfg(target_os = "windows")]
pub async fn run_wintun_tunnel(
    config: crate::config::ClientConfig,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    use std::net::ToSocketAddrs;
    use std::process::{Command, Stdio};
    
    let debug = config.debug;

    if debug {
        println!("[ostp-client] Initializing high-performance TUN tunnel via tun2socks...");
    }

    // 1. Get executable directory to locate tun2socks.exe and wintun.dll
    let exe = std::env::current_exe()?;
    let dir = exe.parent().ok_or_else(|| anyhow!("failed to get binary directory"))?;
    let tun2socks_exe = dir.join("tun2socks.exe");

    if !tun2socks_exe.exists() {
        return Err(anyhow!("tun2socks.exe not found! Please ensure initialization downloaded it successfully."));
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

    let setup_script = format!(
        "$remote_ip = '{}'\n\
         $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1\n\
         $gw = $route.NextHop\n\
         $ifIndex = $route.InterfaceIndex\n\
         New-NetRoute -DestinationPrefix \"$remote_ip/32\" -NextHop $gw -InterfaceIndex $ifIndex -RouteMetric 1 -ErrorAction SilentlyContinue\n\
         New-NetRoute -DestinationPrefix \"1.1.1.1/32\" -NextHop $gw -InterfaceIndex $ifIndex -RouteMetric 1 -ErrorAction SilentlyContinue\n",
        server_ip_str
    );

    let out = Command::new("powershell")
        .args(["-Command", &setup_script])
        .output()?;
    
    if !out.status.success() && debug {
        println!("[ostp-client] Warning: Setup routing returned: {}", String::from_utf8_lossy(&out.stderr));
    }

    // 4. Prepare and launch tun2socks.exe in the background
    let proxy_url = format!("socks5://{}", config.local_proxy.bind_addr);
    
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
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow!("Failed to launch tun2socks.exe background process: {}", e))?;

    // 5. Once tun2socks creates the interface, apply network settings (IP, metric, DNS)
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    if debug {
        println!("[ostp-client] Applying network configurations onto 'ostp_tun' interface...");
    }

    let net_setup = "\
        netsh interface ipv4 set address name=\"ostp_tun\" static 10.1.0.2 255.255.255.0 10.1.0.1\n\
        netsh interface ipv4 set interface name=\"ostp_tun\" metric=5\n\
        netsh interface ipv4 set dnsservers name=\"ostp_tun\" static 1.1.1.1 primary\n";
    
    let _ = Command::new("powershell")
        .args(["-Command", net_setup])
        .output()?;

    println!("[client] TUN Tunnel established, internet traffic is now routing through OSTP.");

    // 6. Spawn thread to keep logging tun2socks output if in debug mode
    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
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

    // 8. Terminate tun2socks
    let _ = child.kill();

    // 9. Run cleanup routing script
    let cleanup_script = format!(
        "$remote_ip = '{}'\n\
         Remove-NetRoute -DestinationPrefix \"$remote_ip/32\" -Confirm:$false -ErrorAction SilentlyContinue\n\
         Remove-NetRoute -DestinationPrefix \"1.1.1.1/32\" -Confirm:$false -ErrorAction SilentlyContinue\n",
        server_ip_str
    );

    let _ = Command::new("powershell")
        .args(["-Command", &cleanup_script])
        .output()?;

    println!("[client] TUN Tunnel stopped.");
    
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub async fn run_wintun_tunnel(
    _config: crate::config::ClientConfig,
    _shutdown: watch::Receiver<bool>,
) -> Result<()> {
    Err(anyhow!("Wintun is only supported on Windows!"))
}
