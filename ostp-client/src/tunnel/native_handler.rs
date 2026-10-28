use anyhow::{anyhow, Result};
use tokio::sync::watch;

// ──────────────────────────────────────────────────────────────────────────────
// Shared part: smoltcp stack over an already opened TUN (desktop and Android)
// ──────────────────────────────────────────────────────────────────────────────

/// What differs between the desktop and the Android callers of `run_stack_over_tun`.
#[cfg(any(target_os = "windows", target_os = "linux", target_os = "android"))]
struct StackParams {
    /// "Desktop" / "Android": used in the exclusions hot-reload log line.
    name: &'static str,
    /// Logged once the stack is up.
    active_msg: &'static str,
    /// Physical interface index for bypass sockets and the UDP NAT (Windows only).
    phys_if_for_bypass: Option<u32>,
    /// Physical interface name for SO_BINDTODEVICE (Linux only).
    linux_phys_name: Option<String>,
}

/// Builds the netstack, wires it to the TUN halves and runs the UDP NAT and the TCP
/// acceptor until shutdown or until any of the tasks ends.
#[cfg(any(target_os = "windows", target_os = "linux", target_os = "android"))]
async fn run_stack_over_tun<R, W>(
    config: crate::config::ClientConfig,
    mut shutdown: watch::Receiver<bool>,
    mut exclusions_rx: watch::Receiver<crate::config::ExclusionConfig>,
    mut tun_read: R,
    mut tun_write: W,
    params: StackParams,
) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use netstack_smoltcp::StackBuilder;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use futures::{StreamExt, SinkExt};

    let debug = config.debug;
    let StackParams { name, active_msg, phys_if_for_bypass, linux_phys_name } = params;
    let _ = (&phys_if_for_bypass, &linux_phys_name); // not every platform uses both

    // ── 7. Build smoltcp network stack ────────────────────────────────────────
    let (stack, tcp_runner, udp_socket, tcp_listener) = StackBuilder::default()
        .stack_buffer_size(1024)
        .tcp_buffer_size(1024)
        .udp_buffer_size(1024)
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

    let mut tun_to_stack = tokio::spawn(async move {
        // Reassemble IPv4 fragments before the netstack sees them: smoltcp drops
        // UDP fragments with a wire::Error, which silently kills any >MTU UDP
        // datagram (game traffic in particular). See ip_reasm for the details.
        let mut reasm = super::ip_reasm::Reassembler::new();
        let mut buf = vec![0u8; 65536];
        loop {
            match tun_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let Some(frame) = reasm.process(&buf[..n]) else {
                        continue; // fragment buffered; nothing to forward yet
                    };
                    if let Err(e) = stack_sink.send(frame).await {
                        if e.kind() == std::io::ErrorKind::BrokenPipe {
                            break;
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!("tun_read error: {e}");
                    // A failing descriptor fails again at once; without a pause
                    // this loop would hold a core until the tunnel is stopped.
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }
        }
    });

    let mut stack_to_tun = tokio::spawn(async move {
        while let Some(Ok(frame)) = stack_stream.next().await {
            if let Err(e) = tun_write.write_all(&frame).await {
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
    // Build exclusion matcher for dynamic bypass
    let current_exclusions = exclusions_rx.borrow().clone();
    let matcher = crate::tunnel::exclusion::ExclusionMatcher::new(&current_exclusions, None, None);
    let matcher_arc = std::sync::Arc::new(tokio::sync::RwLock::new(matcher));

    let matcher_clone = matcher_arc.clone();
    tokio::spawn(async move {
        while let Ok(_) = exclusions_rx.changed().await {
            let current = exclusions_rx.borrow().clone();
            let new_matcher = crate::tunnel::exclusion::ExclusionMatcher::new(&current, None, None);
            *matcher_clone.write().await = new_matcher;
            tracing::debug!("{name} TUN exclusions hot-reloaded");
        }
    });

    let debug_udp = debug;
    let udp_matcher = matcher_arc.clone();
    let udp_lin_name = linux_phys_name.clone();

    let mut udp_proxy_task = tokio::spawn(async move {
        if let Some(udp_sock) = udp_socket {
            super::udp_nat::run_udp_nat(udp_sock, udp_proxy_addr, debug_udp, udp_matcher, phys_if_for_bypass, udp_lin_name).await;
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
    //   (IP_UNICAST_IF) so it goes out via the real NIC, not TUN. On Android the
    //   VpnService already protects the socket from re-entering the TUN.

    let proxy_addr_tcp = {
        let mut a = config.local_proxy.bind_addr.clone();
        if a.starts_with("0.0.0.0:") {
            a = a.replace("0.0.0.0:", "127.0.0.1:");
        }
        a
    };

    let mut tcp_accept_task = tokio::spawn(async move {
        let Some(mut listener) = tcp_listener else { return; };

        while let Some((mut stream, local, remote)) = listener.next().await {
            let proxy_addr = proxy_addr_tcp.clone();
            let matcher_arc = matcher_arc.clone();
            #[cfg(target_os = "linux")]
            let lin_name = linux_phys_name.clone();

            tokio::spawn(async move {
                let matcher = matcher_arc.read().await.clone();
                if debug {
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

                // 1. The program that opened the connection.
                if let Some(name) = matcher
                    .excluded_process(crate::tunnel::process_lookup::Proto::Tcp, local)
                    .await
                {
                    if debug {
                        tracing::info!("TUN TCP BYPASS (process {name}): {local} → {remote}");
                    }
                    should_bypass = true;
                }

                // 2. SNI domain check (belt-and-suspenders for CDNs / late-resolved IPs)
                if !should_bypass && sniff_len > 0 {
                    if let Some(sni) =
                        crate::tunnel::sni_sniff::extract_sni(&sniff_buf[..sniff_len])
                    {
                        if debug {
                            tracing::debug!("TUN SNI: {sni}");
                        }
                        if matcher.match_domain(&sni) {
                            if debug {
                                tracing::info!("TUN TCP BYPASS (SNI domain): {sni} → {remote}");
                            }
                            should_bypass = true;
                        }
                    }
                }

                // 3. Destination IP CIDR check (for IPs not in routing table / IPv6)
                if !should_bypass && matcher.match_ip(&remote.ip()) {
                    if debug {
                        tracing::info!("TUN TCP BYPASS (IP match): {remote}");
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

                    // The current interface: a network change moves it (ostp_tun
                    // keeps it up to date), the one from the start may be gone.
                    #[cfg(target_os = "windows")]
                    if let Some(idx) = ostp_tun::physical_if_index().or(phys_if_for_bypass) {
                        if let Err(e) = crate::tunnel::proxy::bind_socket_to_interface(
                            &socket,
                            remote.is_ipv6(),
                            idx,
                        ) {
                            tracing::error!("TUN TCP BYPASS failed to bind to physical interface {}: {}", idx, e);
                        } else {
                            if debug {
                                tracing::info!("TUN TCP BYPASS bound to physical interface {}", idx);
                            }
                        }
                    } else {
                        tracing::warn!("TUN TCP BYPASS has no physical interface index!");
                    }
                    #[cfg(target_os = "linux")]
                    if let Some(ref name) = ostp_tun::physical_if_name().or_else(|| lin_name.clone()) {
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

    tracing::info!("{active_msg}");

    tokio::select! {
        _ = shutdown.changed() => {}
        _ = &mut runner_task => {}
        _ = &mut tun_to_stack => {}
        _ = &mut stack_to_tun => {}
        _ = &mut udp_proxy_task => {}
        _ = &mut tcp_accept_task => {}
    }

    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────────
// Windows / Linux desktop TUN
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(any(target_os = "windows", target_os = "linux"))]
pub async fn run_native_tunnel(
    config: crate::config::ClientConfig,
    shutdown: watch::Receiver<bool>,
    exclusions_rx: watch::Receiver<crate::config::ExclusionConfig>,
) -> Result<()> {
    use std::net::ToSocketAddrs;

    tracing::info!("Initializing NATIVE TUN tunnel (smoltcp)...");

    // Capture physical interface index for bypass BEFORE we create the TUN device and alter routes.
    #[cfg(target_os = "windows")]
    let phys_if_for_bypass: Option<u32> = ostp_tun::windows::windows_route::sys::get_default_ipv4_route().map(|(_, idx)| idx);
    #[cfg(not(target_os = "windows"))]
    let phys_if_for_bypass: Option<u32> = None;

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
        let domain = crate::tunnel::exclusion::normalize_domain(domain.trim_start_matches(['.', '*']));
        match tokio::net::lookup_host((domain.as_str(), 443u16)).await {
            Ok(addrs) => {
                for addr in addrs {
                    bypass_ips.push(addr.ip());
                }
            }
            Err(e) => {
                tracing::warn!("Failed to pre-resolve excluded domain {domain}: {e}");
            }
        };
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
        .map_err(|e| anyhow!("Failed to create the TUN interface: {}", e))?;
    // Printed only now: the server connection is reported separately, and
    // "established" used to appear before the TUN device existed.
    println!("[ostp] TUN interface is up: all traffic goes through the tunnel");

    let dev = tun_interface.device;
    let _route_guard = tun_interface.guard;

    // Linux: physical interface name for SO_BINDTODEVICE
    #[cfg(target_os = "linux")]
    let linux_phys_name = crate::tunnel::proxy::get_linux_physical_if_name();
    #[cfg(not(target_os = "linux"))]
    let linux_phys_name: Option<String> = None;

    let (tun_read, tun_write) = tokio::io::split(dev);
    let result = run_stack_over_tun(
        config,
        shutdown,
        exclusions_rx,
        tun_read,
        tun_write,
        StackParams {
            name: "Desktop",
            active_msg: "NATIVE TUN tunnel active.",
            phys_if_for_bypass,
            linux_phys_name,
        },
    )
    .await;

    tracing::info!("Deactivating NATIVE TUN tunnel...");

    // ── Cleanup ───────────────────────────────────────────────────────────────
    // Cleanup is handled automatically by the _route_guard Drop trait in ostp-tun

    result
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

/// One dup of the VpnService TUN fd as a tokio reader and writer. Every read and
/// write is a single `libc::read`/`libc::write` on the non-blocking descriptor,
/// driven by `AsyncFd` readiness.
#[cfg(target_os = "android")]
struct FdIo(tokio::io::unix::AsyncFd<std::fs::File>);

#[cfg(target_os = "android")]
impl tokio::io::AsyncRead for FdIo {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::os::unix::io::AsRawFd;
        use std::task::Poll;

        let this = self.get_mut();
        loop {
            let mut guard = match this.0.poll_read_ready(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(g)) => g,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            };
            let unfilled = buf.initialize_unfilled();
            match guard.try_io(|inner| {
                let res = unsafe {
                    libc::read(
                        inner.as_raw_fd(),
                        unfilled.as_mut_ptr() as *mut libc::c_void,
                        unfilled.len(),
                    )
                };
                if res < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(res as usize)
                }
            }) {
                // 0 is end of stream: the descriptor was closed (the VPN was
                // stopped or revoked) and the reader loop ends.
                Ok(Ok(n)) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                // A real error goes to the reader loop, which pauses on it; looping
                // here would spin, because readiness stays set for a broken fd.
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                // Would block: try_io cleared readiness, wait for the next one.
                Err(_would_block) => continue,
            }
        }
    }
}

#[cfg(target_os = "android")]
impl tokio::io::AsyncWrite for FdIo {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::os::unix::io::AsRawFd;
        use std::task::Poll;

        let this = self.get_mut();
        loop {
            let mut guard = match this.0.poll_write_ready(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(g)) => g,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            };
            match guard.try_io(|inner| {
                let res = unsafe {
                    libc::write(
                        inner.as_raw_fd(),
                        buf.as_ptr() as *const libc::c_void,
                        buf.len(),
                    )
                };
                if res < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(res as usize)
                }
            }) {
                Ok(r) => return Poll::Ready(r),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

#[cfg(target_os = "android")]
pub async fn run_native_tunnel_from_fd(
    config: crate::config::ClientConfig,
    shutdown: watch::Receiver<bool>,
    exclusions_rx: watch::Receiver<crate::config::ExclusionConfig>,
    fd: i32,
) -> Result<()> {
    use std::os::unix::io::FromRawFd;

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
    let tun_read = FdIo(tokio::io::unix::AsyncFd::new(file)?);

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
    let tun_write = FdIo(tokio::io::unix::AsyncFd::new(write_file)?);

    let result = run_stack_over_tun(
        config,
        shutdown,
        exclusions_rx,
        tun_read,
        tun_write,
        StackParams {
            name: "Android",
            active_msg: "NATIVE TUN (Android) tunnel active.",
            phys_if_for_bypass: None,
            linux_phys_name: None,
        },
    )
    .await;

    tracing::info!("NATIVE TUN (Android) deactivated.");
    result
}

#[cfg(not(target_os = "android"))]
pub async fn run_native_tunnel_from_fd(
    _config: crate::config::ClientConfig,
    _shutdown: watch::Receiver<bool>,
    _exclusions_rx: watch::Receiver<crate::config::ExclusionConfig>,
    _fd: i32,
) -> Result<()> {
    Err(anyhow!("Native TUN from FD is only supported on Android"))
}
