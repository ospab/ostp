use anyhow::{anyhow, Result};
use tokio::sync::watch;

#[cfg(target_os = "linux")]
use std::net::ToSocketAddrs;
#[cfg(target_os = "linux")]
use std::process::{Command, Stdio};
#[cfg(target_os = "linux")]
use std::io::{BufRead, BufReader};

#[cfg(target_os = "linux")]
pub async fn run_linux_tunnel(
    config: crate::config::ClientConfig,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let debug = config.debug;
    if debug {
        println!("[ostp-client] Starting Linux TUN handler initialization...");
    }

    // 1. Locate tun2socks binary
    let exe = std::env::current_exe()?;
    let dir = exe.parent().ok_or_else(|| anyhow!("failed to get binary directory"))?;
    
    let mut tun2socks_exe = dir.join("tun2socks");
    if !tun2socks_exe.exists() {
        // Try system PATH via standard command check
        let in_path = Command::new("which")
            .arg("tun2socks")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if in_path {
            tun2socks_exe = std::path::PathBuf::from("tun2socks");
        } else {
            return Err(anyhow!("tun2socks executable not found in local dir or PATH. Please ensure dependencies are present."));
        }
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

    // 3. Detect current default gateway and interface
    let route_output = Command::new("sh")
        .arg("-c")
        .arg("ip route show default | head -n1")
        .output()?;
    
    let route_str = String::from_utf8_lossy(&route_output.stdout);
    let parts: Vec<&str> = route_str.split_whitespace().collect();
    
    // Expected: "default via 192.168.1.1 dev eth0 ..."
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

    if debug {
        println!("[ostp-client] Physical route anchor: gateway={} interface={}", default_gw, default_if);
    }

    // 4. Setup commands (Using standard /1 routing trick for fail-proof overriding)
    let setup_script = format!(
        "ip tuntap add name ostp_tun mode tun || true; \
         ip addr add 10.1.0.2/24 dev ostp_tun || true; \
         ip link set dev ostp_tun up; \
         ip route add {} via {} dev {}; \
         ip route add 1.1.1.1 via {} dev {}; \
         ip route add 0.0.0.0/1 dev ostp_tun; \
         ip route add 128.0.0.0/1 dev ostp_tun",
        server_ip_str, default_gw, default_if,
        default_gw, default_if
    );

    if debug {
        println!("[ostp-client] Executing Linux network config: {}", setup_script);
    }

    let out = Command::new("sh")
        .args(["-c", &setup_script])
        .output()?;
    
    if !out.status.success() && debug {
        println!("[ostp-client] Warning: Setup routing returned: {}", String::from_utf8_lossy(&out.stderr));
    }

    // 5. Prepare and launch tun2socks
    let proxy_url = format!("socks5://{}", config.local_proxy.bind_addr);
    
    if debug {
        println!("[ostp-client] Spawning {} -device ostp_tun -proxy {}", tun2socks_exe.display(), proxy_url);
    }

    let mut child = Command::new(&tun2socks_exe)
        .args([
            "-device", "ostp_tun",
            "-proxy", &proxy_url,
        ])
        .stdout(if debug { Stdio::piped() } else { Stdio::null() })
        .stderr(if debug { Stdio::piped() } else { Stdio::null() })
        .spawn()
        .map_err(|e| anyhow!("Failed to spawn tun2socks process: {}", e))?;

    println!("[client] TUN Tunnel established, Linux traffic is now routing through OSTP.");

    if debug {
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        
        tokio::spawn(async move {
            let reader = BufReader::new(stdout);
            for line in reader.lines().map_while(Result::ok) {
                println!("[tun2socks] {}", line);
            }
        });
        
        tokio::spawn(async move {
            let reader = BufReader::new(stderr);
            for line in reader.lines().map_while(Result::ok) {
                eprintln!("[tun2socks-err] {}", line);
            }
        });
    }

    // 6. Wait for shutdown signal
    let _ = shutdown.changed().await;

    println!("[client] Deactivating TUN tunnel and restoring Linux network topology...");

    // 7. Terminate process
    let _ = child.kill();

    // 8. Cleanup routing and virtual interface
    let cleanup_script = format!(
        "ip route del 0.0.0.0/1 dev ostp_tun || true; \
         ip route del 128.0.0.0/1 dev ostp_tun || true; \
         ip route del {} via {} dev {} || true; \
         ip route del 1.1.1.1 via {} dev {} || true; \
         ip link set dev ostp_tun down || true; \
         ip tuntap del name ostp_tun mode tun || true",
        server_ip_str, default_gw, default_if,
        default_gw, default_if
    );

    let _ = Command::new("sh")
        .args(["-c", &cleanup_script])
        .output()?;

    println!("[client] Linux TUN Tunnel stopped.");
    
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub async fn run_linux_tunnel(
    _config: crate::config::ClientConfig,
    _shutdown: watch::Receiver<bool>,
) -> Result<()> {
    Err(anyhow!("Linux tunnel driver executed on a non-Linux host!"))
}
