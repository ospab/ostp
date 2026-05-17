use anyhow::{anyhow, Result};
use tokio::sync::watch;

#[cfg(target_os = "linux")]
use std::net::ToSocketAddrs;
#[cfg(target_os = "linux")]
use std::process::{Command, Stdio, Child};
#[cfg(target_os = "linux")]
use std::io::{BufRead, BufReader};

#[cfg(target_os = "linux")]
struct LinuxRouteGuard {
    server_ip_str: String,
    default_gw: String,
    default_if: String,
    child: Option<Child>,
}

#[cfg(target_os = "linux")]
impl Drop for LinuxRouteGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
        }
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
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let debug = config.debug;
    if debug {
        println!("[ostp] Initializing TUN tunnel...");
    }

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
            return Err(anyhow!(
                "CRITICAL: 'tun2socks' binary is missing!\n\
                OSTP requires tun2socks for TUN mode on Linux. Please download the appropriate binary for your architecture from: \n\
                https://github.com/xjasonlyu/tun2socks/releases \n\
                and place it in the same directory as the ostp executable ({}), or install it globally in your PATH.",
                dir.display()
            ));
        }
    }

    // 1.5. Pre-flight system checks
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

    if debug {
        println!("[ostp] Resolved server IP: {}", server_ip_str);
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
        println!("[ostp] Default route: gateway={} interface={}", default_gw, default_if);
    }

    // 4. Setup commands (Using standard /1 routing trick for fail-proof overriding)
    let setup_script = format!(
        "ip tuntap add name ostp_tun mode tun || true; \
         ip link set dev ostp_tun mtu 1300; \
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
        println!("[ostp] Executing Linux network config: {}", setup_script);
    }

    let out = Command::new("sh")
        .args(["-c", &setup_script])
        .output()?;
    
    if !out.status.success() && debug {
        println!("[ostp] Warning: Setup routing returned: {}", String::from_utf8_lossy(&out.stderr));
    }

    // 5. Prepare and launch tun2socks
    // Using HTTP Proxy natively avoids any UDP Associate requests,
    // providing clean TCP proxying with maximum reliability.
    let proxy_url = format!("http://{}", config.local_proxy.bind_addr);
    
    if debug {
        println!("[ostp] Spawning {} -device ostp_tun -proxy {}", tun2socks_exe.display(), proxy_url);
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

    let mut _guard = LinuxRouteGuard {
        server_ip_str: server_ip_str.clone(),
        default_gw: default_gw.clone(),
        default_if: default_if.clone(),
        child: None,
    };

    println!("[ostp] TUN tunnel active. All traffic is routed through OSTP.");

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

    _guard.child = Some(child);

    // 6. Wait for shutdown signal
    let _ = shutdown.changed().await;

    println!("[ostp] Deactivating TUN tunnel...");

    // Drop guard runs cleanup automatically
    drop(_guard);

    println!("[ostp] TUN tunnel stopped.");
    
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
