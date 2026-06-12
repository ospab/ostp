use anyhow::{anyhow, Result};
use tokio::sync::watch;

// ──────────────────────────────────────────────────────────────────────────────
// Windows / Linux desktop TUN
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(any(target_os = "windows", target_os = "linux"))]
pub async fn run_native_tunnel(
    config: crate::config::ClientConfig,
    mut shutdown: watch::Receiver<bool>,
    mut exclusions_rx: watch::Receiver<crate::config::ExclusionConfig>,
) -> Result<()> {
    use std::net::ToSocketAddrs;
    use netstack_smoltcp::StackBuilder;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use futures::{StreamExt, SinkExt};

    #[cfg(target_os = "linux")]
    {
        use std::io::{self, IsTerminal, Write};
        if io::stdout().is_terminal() {
            println!("\n===================================================================");
            println!("WARNING: TUN mode will modify the system routing table.");
            println!("If you are connected to a headless server via SSH, you may lose");
            println!("your connection when default routes are redirected into the tunnel.");
            println!("===================================================================\n");
            print!("Are you sure you want to initialize the TUN interface? [yes/no]: ");
            io::stdout().flush().unwrap();

            let mut input = String::new();
            io::stdin().read_line(&mut input).unwrap();
            let ans = input.trim().to_lowercase();
            if ans != "y" && ans != "yes" {
                return Err(anyhow!("TUN initialization aborted by user."));
            }
        }
    }

    let debug = config.debug;
    tracing::info!("Initializing NATIVE TUN tunnel (smoltcp)...");

    // ── 1. Resolve server IP ──────────────────────────────────────────────────
    let server_ip = config
        .ostp
        .server_addr
        .to_socket_addrs()
        .map_err(|e| anyhow!("Failed to resolve server IP: {}", e))?
        .next()
        .map(|a| a.ip())
        .ok_or_else(|| anyhow!("Could not resolve server host"))?;
    #[allow(unused_variables)]
    let server_ip_str = server_ip.to_string();

    // ── 2. Resolve excluded domains → IP addresses for bypass routing ─────────
    let mut bypass_ips: Vec<std::net::IpAddr> = Vec::new();

    // Server IP always bypasses TUN
    bypass_ips.push(server_ip);

    for ip_str in &config.exclusions.ips {
        let host = ip_str.split('/').next().unwrap_or(ip_str);
        if let Ok(ip) = host.parse() {
            bypass_ips.push(ip);
        }
    }

    for domain in &config.exclusions.domains {
        match tokio::net::lookup_host((domain.as_str(), 443u16)).await {
            Ok(addrs) => {
                for addr in addrs {
                    bypass_ips.push(addr.ip());
                }
            }
            Err(e) => {
                tracing::warn!("Failed to pre-resolve excluded domain {domain}: {e}");
            }
        }
    }

    if !config.exclusions.processes.is_empty() {
        tracing::warn!(
            "Process-based split tunneling is not fully supported in TUN mode on all platforms \
             without WFP/eBPF. Processes in the exclusion list will still be tunneled. \
             Use IP or domain exclusions instead."
        );
    }

    // ── 3. Create TUN device via ostp-tun crate ───────────────────────────────
    let opts = ostp_tun::OstpTunOptions {
        server_ip,
        bypass_ips,
        dns_server: config.dns_server.clone(),
        kill_switch: config.kill_switch,
        mtu: config.ostp.mtu as u16,
        wintun_path: None,
    };

    let tun_interface = ostp_tun::OstpTunInterface::create(opts)
        .await
        .map_err(|e| anyhow!("Failed to create OstpTunInterface: {}", e))?;
        
    let dev = tun_interface.device;
    let _route_guard = tun_interface.guard;

    // ── 7. Build smoltcp network stack ────────────────────────────────────────
    let (stack, tcp_runner, udp_socket, tcp_listener) = StackBuilder::default()
        .stack_buffer_size(100_000)
        .tcp_buffer_size(100_000)
        .udp_buffer_size(100_000)
        .enable_tcp(true)
        .enable_udp(true)
        .mtu(config.ostp.mtu)
        .build()?;

    let mut runner_task = tokio::spawn(async move {
        if let Some(runner) = tcp_runner {
            let _ = runner.await;
        }
    });

    // ── 8. Wire TUN ↔ smoltcp stack ───────────────────────────────────────────
    let (mut stack_sink, mut stack_stream) = stack.split();
    let (mut tun_read, mut tun_write) = tokio::io::split(dev);

    let mut tun_to_stack = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            match tun_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let frame = buf[..n].to_vec();
                    if let Err(e) = stack_sink.send(frame).await {
                        if e.kind() == std::io::ErrorKind::BrokenPipe {
                            break;
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!("tun_read error: {e}");
                }
            }
        }
    });

    let mut stack_to_tun = tokio::spawn(async move {
        while let Some(Ok(frame)) = stack_stream.next().await {
            if let Err(e) = tun_write.write(&frame).await {
                tracing::debug!("tun_write error: {e}");
            }
        }
    });

    // ── 9. UDP: forward everything through OSTP proxy ─────────────────────────
    //   UDP exclusions are handled at the routing table level (step 5), so
    //   UDP packets for excluded IPs never reach smoltcp at all.
    let udp_proxy_addr = {
        let mut a = config.local_proxy.bind_addr.clone();
        if a.starts_with("0.0.0.0:") {
            a = a.replace("0.0.0.0:", "127.0.0.1:");
        }
        a
    };
    let debug_udp = debug;
    let mut udp_proxy_task = tokio::spawn(async move {
        if let Some(udp_sock) = udp_socket {
            super::udp_nat::run_udp_nat(udp_sock, udp_proxy_addr, debug_udp).await;
        }
    });

    // ── 10. TCP: forward to OSTP proxy (with domain-level bypass via SNI) ─────
    //
    //   For IP-based exclusions:  handled by routing table → packets never arrive here.
    //   For domain-based exclusions: The IP is already in routing table (pre-resolved in
    //     step 3), so most traffic won't arrive. As a belt-and-suspenders fallback,
    //     we also sniff TLS SNI and bypass if it matches — this covers CDN cases where
    //     the IP wasn't known at startup.
    //
    //   For bypassed connections we bind the outgoing socket to the physical interface
    //   (IP_UNICAST_IF) so it goes out via the real NIC, not TUN.

    let proxy_addr_tcp = {
        let mut a = config.local_proxy.bind_addr.clone();
        if a.starts_with("0.0.0.0:") {
            a = a.replace("0.0.0.0:", "127.0.0.1:");
        }
        a
    };

    // Build exclusion matcher for SNI-based domain bypass (fallback / CDN handling)
    let current_exclusions = exclusions_rx.borrow().clone();
    let matcher = crate::tunnel::exclusion::ExclusionMatcher::new(&current_exclusions, None, None);
    let matcher_arc = std::sync::Arc::new(tokio::sync::RwLock::new(matcher));
    
    let matcher_clone = matcher_arc.clone();
    tokio::spawn(async move {
        while let Ok(_) = exclusions_rx.changed().await {
            let current = exclusions_rx.borrow().clone();
            let new_matcher = crate::tunnel::exclusion::ExclusionMatcher::new(&current, None, None);
            *matcher_clone.write().await = new_matcher;
            if true {
                tracing::debug!("Desktop TUN exclusions hot-reloaded");
            }
        }
    });

    // Physical interface index — Some on Windows, None everywhere else
    #[cfg(target_os = "windows")]
    let phys_if_for_bypass: Option<u32> = ostp_tun::windows::windows_route::sys::get_default_ipv4_route().map(|(_, idx)| idx);
    #[cfg(not(target_os = "windows"))]
    let phys_if_for_bypass: Option<u32> = None;

    // Linux: physical interface name for SO_BINDTODEVICE
    #[cfg(target_os = "linux")]
    let linux_phys_name = crate::tunnel::proxy::get_linux_physical_if_name();
    #[cfg(not(target_os = "linux"))]
    let linux_phys_name: Option<String> = None;
    let _ = &linux_phys_name; // suppress unused warning on Windows

    let mut tcp_accept_task = tokio::spawn(async move {
        let Some(mut listener) = tcp_listener else { return; };

        while let Some((mut stream, local, remote)) = listener.next().await {
            let proxy_addr = proxy_addr_tcp.clone();
            let matcher_arc = matcher_arc.clone();
            #[cfg(target_os = "linux")]
            let lin_name = linux_phys_name.clone();

            tokio::spawn(async move {
                let matcher = matcher_arc.read().await.clone();
                if true {
                    tracing::debug!("TUN TCP {local} → {remote}");
                }

                // ── Sniff TLS ClientHello for SNI ─────────────────────────────
                let mut sniff_buf = [0u8; 2048];
                let sniff_len =
                    match tokio::time::timeout(
                        std::time::Duration::from_millis(100),
                        stream.read(&mut sniff_buf),
                    )
                    .await
                    {
                        Ok(Ok(n)) => n,
                        _ => 0,
                    };

                // ── Decide: bypass or tunnel? ─────────────────────────────────
                let mut should_bypass = false;

                // 1. SNI domain check (belt-and-suspenders for CDNs / late-resolved IPs)
                if sniff_len > 0 {
                    if let Some(sni) =
                        crate::tunnel::sni_sniff::extract_sni(&sniff_buf[..sniff_len])
                    {
                        if true {
                            tracing::debug!("TUN SNI: {sni}");
                        }
                        if matcher.match_domain(&sni) {
                            if true {
                                tracing::debug!("TUN BYPASS (SNI domain): {sni} → {remote}");
                            }
                            should_bypass = true;
                        }
                    }
                }

                // 2. Destination IP CIDR check (for IPs not in routing table / IPv6)
                if !should_bypass && matcher.match_ip(&remote.ip()) {
                    if true {
                        tracing::debug!("TUN BYPASS (IP match): {remote}");
                    }
                    should_bypass = true;
                }

                // ── Bypass path: direct TCP bypassing TUN ─────────────────────
                if should_bypass {
                    let socket = match remote {
                        std::net::SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4(),
                        std::net::SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6(),
                    };
                    let Ok(socket) = socket else { return; };

                    // Bind to physical interface so packets don't loop back into TUN

                    #[cfg(target_os = "windows")]
                    if let Some(idx) = phys_if_for_bypass {
                        if let Err(e) = crate::tunnel::proxy::bind_socket_to_interface(
                            &socket,
                            remote.is_ipv6(),
                            idx,
                        ) {
                            tracing::warn!("bind_socket_to_interface failed: {e}");
                        }
                    }
                    #[cfg(target_os = "linux")]
                    if let Some(ref name) = lin_name {
                        let _ = crate::tunnel::proxy::bind_socket_to_interface(&socket, name);
                    }

                    match tokio::time::timeout(
                        std::time::Duration::from_secs(10),
                        socket.connect(remote),
                    )
                    .await
                    {
                        Ok(Ok(mut direct)) => {
                            if sniff_len > 0 {
                                if direct.write_all(&sniff_buf[..sniff_len]).await.is_err() {
                                    return;
                                }
                            }
                            let _ = tokio::io::copy_bidirectional(&mut stream, &mut direct).await;
                        }
                        _ => {
                            tracing::debug!("Direct bypass connect to {remote} failed");
                        }
                    }
                    return;
                }

                // ── Tunnel path: forward via local OSTP SOCKS5 proxy ──────────
                let Ok(mut socks) = tokio::net::TcpStream::connect(&proxy_addr).await else {
                    return;
                };

                // SOCKS5 handshake (no auth)
                if socks.write_all(&[5, 1, 0]).await.is_err() { return; }
                let mut buf2 = [0u8; 2];
                if socks.read_exact(&mut buf2).await.is_err() || buf2[0] != 5 || buf2[1] != 0 {
                    return;
                }

                // CONNECT request
                let mut req = vec![5u8, 1, 0];
                match remote.ip() {
                    std::net::IpAddr::V4(v4) => {
                        req.push(1);
                        req.extend_from_slice(&v4.octets());
                    }
                    std::net::IpAddr::V6(v6) => {
                        req.push(4);
                        req.extend_from_slice(&v6.octets());
                    }
                }
                req.extend_from_slice(&remote.port().to_be_bytes());
                if socks.write_all(&req).await.is_err() { return; }

                let mut rep = [0u8; 10];
                if socks.read_exact(&mut rep).await.is_err() || rep[1] != 0 { return; }

                // Replay sniffed bytes
                if sniff_len > 0 && socks.write_all(&sniff_buf[..sniff_len]).await.is_err() {
                    return;
                }

                let _ = tokio::io::copy_bidirectional(&mut stream, &mut socks).await;
            });
        }
    });

    tracing::info!("NATIVE TUN tunnel active.");

    tokio::select! {
        _ = shutdown.changed() => {}
        _ = &mut runner_task => {}
        _ = &mut tun_to_stack => {}
        _ = &mut stack_to_tun => {}
        _ = &mut udp_proxy_task => {}
        _ = &mut tcp_accept_task => {}
    }

    tracing::info!("Deactivating NATIVE TUN tunnel...");

    // ── Cleanup ───────────────────────────────────────────────────────────────
    // Cleanup is handled automatically by the _route_guard Drop trait in ostp-tun

    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────────
// Stub for unsupported platforms
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
pub async fn run_native_tunnel(
    _config: crate::config::ClientConfig,
    _shutdown: watch::Receiver<bool>,
    _exclusions_rx: watch::Receiver<crate::config::ExclusionConfig>,
) -> Result<()> {
    Err(anyhow!("Native TUN tunnel is only supported on Windows/Linux"))
}

// ──────────────────────────────────────────────────────────────────────────────
// Android: TUN from file-descriptor (opened by VpnService)
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(target_os = "android")]
pub async fn run_native_tunnel_from_fd(
    config: crate::config::ClientConfig,
    mut shutdown: watch::Receiver<bool>,
    mut exclusions_rx: watch::Receiver<crate::config::ExclusionConfig>,
    fd: i32,
) -> Result<()> {
    use netstack_smoltcp::StackBuilder;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use futures::{StreamExt, SinkExt};
    use std::os::unix::io::{FromRawFd, AsRawFd};

    let debug = config.debug;
    tracing::info!("Initializing NATIVE TUN tunnel on Android (FD {})", fd);

    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags >= 0 {
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }

    let read_fd = unsafe { libc::dup(fd) };
    if read_fd < 0 {
        return Err(anyhow!("Failed to dup tun fd for reading"));
    }

    let file = unsafe { std::fs::File::from_raw_fd(read_fd) };
    let tun_stream = tokio::io::unix::AsyncFd::new(file)?;

    let (stack, tcp_runner, udp_socket, tcp_listener) = StackBuilder::default()
        .stack_buffer_size(100_000)
        .tcp_buffer_size(100_000)
        .udp_buffer_size(100_000)
        .enable_tcp(true)
        .enable_udp(true)
        .mtu(config.ostp.mtu)
        .build()?;

    let mut runner_task = tokio::spawn(async move {
        if let Some(runner) = tcp_runner {
            let _ = runner.await;
        }
    });

    let (mut stack_sink, mut stack_stream) = stack.split();

    let _tun_to_stack = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let mut guard = match tun_stream.readable().await {
                Ok(g) => g,
                Err(_) => break,
            };
            let n = match guard.try_io(|inner| {
                let res = unsafe {
                    libc::read(
                        inner.as_raw_fd(),
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                    )
                };
                if res < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::WouldBlock {
                        Err(err)
                    } else {
                        Ok(0_isize)
                    }
                } else {
                    Ok(res)
                }
            }) {
                Ok(Ok(n)) if n > 0 => n as usize,
                Ok(Ok(_)) => continue,
                Ok(Err(_)) => continue,
                Err(_) => continue,
            };

            let frame = buf[..n].to_vec();
            if let Err(e) = stack_sink.send(frame).await {
                if e.kind() == std::io::ErrorKind::BrokenPipe {
                    break;
                }
            }
        }
    });

    let write_fd = unsafe { libc::dup(fd) };
    if write_fd < 0 {
        return Err(anyhow!("Failed to dup tun fd for writing"));
    }
    unsafe {
        let flags = libc::fcntl(write_fd, libc::F_GETFL);
        if flags >= 0 {
            libc::fcntl(write_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }
    let write_file = unsafe { std::fs::File::from_raw_fd(write_fd) };
    let tun_write_stream = tokio::io::unix::AsyncFd::new(write_file)?;

    let _stack_to_tun = tokio::spawn(async move {
        while let Some(Ok(frame)) = stack_stream.next().await {
            let mut written = 0;
            while written < frame.len() {
                let mut guard = match tun_write_stream.writable().await {
                    Ok(g) => g,
                    Err(_) => break,
                };
                let res = guard.try_io(|inner| {
                    let res = unsafe {
                        libc::write(
                            inner.as_raw_fd(),
                            frame[written..].as_ptr() as *const libc::c_void,
                            frame.len() - written,
                        )
                    };
                    if res < 0 {
                        let err = std::io::Error::last_os_error();
                        if err.kind() == std::io::ErrorKind::WouldBlock {
                            Err(err)
                        } else {
                            Ok(res)
                        }
                    } else {
                        Ok(res)
                    }
                });
                match res {
                    Ok(Ok(n)) if n > 0 => written += n as usize,
                    Ok(Ok(_)) => break,
                    Ok(Err(_)) => break,
                    Err(_) => continue,
                }
            }
        }
    });

    let mut proxy_addr = config.local_proxy.bind_addr.clone();
    if proxy_addr.starts_with("0.0.0.0:") {
        proxy_addr = proxy_addr.replace("0.0.0.0:", "127.0.0.1:");
    }

    let udp_proxy_addr = proxy_addr.clone();
    let debug_udp = debug;
    let mut udp_proxy_task = tokio::spawn(async move {
        if let Some(udp_sock) = udp_socket {
            super::udp_nat::run_udp_nat(udp_sock, udp_proxy_addr, debug_udp).await;
        }
    });

    let current_exclusions = exclusions_rx.borrow().clone();
    let matcher = crate::tunnel::exclusion::ExclusionMatcher::new(&current_exclusions, None, None);
    let matcher_arc = std::sync::Arc::new(tokio::sync::RwLock::new(matcher));
    
    let matcher_clone = matcher_arc.clone();
    tokio::spawn(async move {
        while let Ok(_) = exclusions_rx.changed().await {
            let current = exclusions_rx.borrow().clone();
            let new_matcher = crate::tunnel::exclusion::ExclusionMatcher::new(&current, None, None);
            *matcher_clone.write().await = new_matcher;
            if true {
                tracing::debug!("Android TUN exclusions hot-reloaded");
            }
        }
    });

    let mut tcp_accept_task = tokio::spawn(async move {
        let Some(mut listener) = tcp_listener else { return; };

        while let Some((mut stream, local, remote)) = listener.next().await {
            let proxy_addr = proxy_addr.clone();
            let matcher_arc = matcher_arc.clone();

            tokio::spawn(async move {
                let matcher = matcher_arc.read().await.clone();

                if true {
                    tracing::debug!("Android TUN TCP {local} → {remote}");
                }

                // Sniff SNI
                let mut sniff_buf = [0u8; 2048];
                let sniff_len =
                    match tokio::time::timeout(
                        std::time::Duration::from_millis(100),
                        stream.read(&mut sniff_buf),
                    )
                    .await
                    {
                        Ok(Ok(n)) => n,
                        _ => 0,
                    };

                let mut should_bypass = false;

                // 1. SNI domain
                if sniff_len > 0 {
                    if let Some(sni) =
                        crate::tunnel::sni_sniff::extract_sni(&sniff_buf[..sniff_len])
                    {
                        if true { tracing::debug!("Android TUN SNI: {sni}"); }
                        if matcher.match_domain(&sni) {
                            should_bypass = true;
                        }
                    }
                }

                // 2. Process (Android: /proc/net lookup)
                if !should_bypass {
                    if let Some(exe) =
                        crate::tunnel::process_lookup::get_process_name_from_port(local.port())
                    {
                        if true {
                            tracing::debug!("Android TUN port {} → EXE: {}", local.port(), exe);
                        }
                        if matcher.match_process(&exe) {
                            should_bypass = true;
                        }
                    }
                }

                // 3. IP CIDR
                if !should_bypass && matcher.match_ip(&remote.ip()) {
                    should_bypass = true;
                }

                // Bypass: connect directly (Android VPN service already protects the socket
                // from re-entering the TUN through VpnService.protect())
                if should_bypass {
                    if true {
                        tracing::debug!("Android TUN BYPASS: {remote}");
                    }
                    let socket = match remote {
                        std::net::SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4(),
                        std::net::SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6(),
                    };
                    let Ok(socket) = socket else { return; };

                    match tokio::time::timeout(
                        std::time::Duration::from_secs(10),
                        socket.connect(remote),
                    )
                    .await
                    {
                        Ok(Ok(mut direct)) => {
                            if sniff_len > 0 {
                                if direct.write_all(&sniff_buf[..sniff_len]).await.is_err() {
                                    return;
                                }
                            }
                            let _ = tokio::io::copy_bidirectional(&mut stream, &mut direct).await;
                        }
                        _ => {
                            tracing::debug!("Android bypass connect to {remote} failed");
                        }
                    }
                    return;
                }

                // Tunnel via SOCKS5 proxy
                let Ok(mut socks) = tokio::net::TcpStream::connect(&proxy_addr).await else {
                    return;
                };
                if socks.write_all(&[5, 1, 0]).await.is_err() { return; }
                let mut buf2 = [0u8; 2];
                if socks.read_exact(&mut buf2).await.is_err() || buf2[0] != 5 || buf2[1] != 0 {
                    return;
                }
                let mut req = vec![5u8, 1, 0];
                match remote.ip() {
                    std::net::IpAddr::V4(v4) => {
                        req.push(1);
                        req.extend_from_slice(&v4.octets());
                    }
                    std::net::IpAddr::V6(v6) => {
                        req.push(4);
                        req.extend_from_slice(&v6.octets());
                    }
                }
                req.extend_from_slice(&remote.port().to_be_bytes());
                if socks.write_all(&req).await.is_err() { return; }
                let mut rep = [0u8; 10];
                if socks.read_exact(&mut rep).await.is_err() || rep[1] != 0 { return; }
                if sniff_len > 0 && socks.write_all(&sniff_buf[..sniff_len]).await.is_err() {
                    return;
                }
                let _ = tokio::io::copy_bidirectional(&mut stream, &mut socks).await;
            });
        }
    });

    tracing::info!("NATIVE TUN (Android) tunnel active.");

    tokio::select! {
        _ = shutdown.changed() => {}
        _ = &mut runner_task => {}
        _ = _tun_to_stack => {}
        _ = _stack_to_tun => {}
        _ = &mut udp_proxy_task => {}
        _ = &mut tcp_accept_task => {}
    }

    tracing::info!("NATIVE TUN (Android) deactivated.");
    Ok(())
}

#[cfg(not(target_os = "android"))]
pub async fn run_native_tunnel_from_fd(
    _config: crate::config::ClientConfig,
    _shutdown: watch::Receiver<bool>,
    _fd: i32,
) -> Result<()> {
    Err(anyhow!("Native TUN from FD is only supported on Android"))
}
