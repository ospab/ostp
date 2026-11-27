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
        .mtu(config.ostp.mtu.tun_mtu())
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
    let reload_task = tokio::spawn(async move {
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

        // Connection tasks live in a JoinSet: aborting this task drops the set and
        // with it every open connection.
        let mut conns = tokio::task::JoinSet::new();
        loop {
            let (mut stream, local, remote) = tokio::select! {
                next = listener.next() => match next {
                    Some(c) => c,
                    None => break,
                },
                // Reap finished connections so the set does not grow forever.
                Some(_) = conns.join_next(), if !conns.is_empty() => continue,
            };
            let proxy_addr = proxy_addr_tcp.clone();
            let matcher_arc = matcher_arc.clone();
            #[cfg(target_os = "linux")]
            let lin_name = linux_phys_name.clone();

            conns.spawn(async move {
                let matcher = matcher_arc.read().await.clone();
                if debug {
                    crate::logs::tun_tcp(local, remote);
                }

                // ── Sniff TLS ClientHello for SNI ─────────────────────────────
                // The whole ClientHello: a post-quantum one comes in two segments.
                let mut sniff_buf = Vec::new();
                crate::tunnel::sni_sniff::read_first_bytes(
                    &mut stream,
                    &mut sniff_buf,
                    std::time::Duration::from_millis(100),
                )
                .await;
                let sniff_len = sniff_buf.len();
                let sni = if sniff_len > 0 {
                    crate::tunnel::sni_sniff::extract_sni(&sniff_buf)
                } else {
                    None
                };

                // ── Decide: bypass or tunnel? ─────────────────────────────────
                let mut should_bypass = false;

                // 1. The program that opened the connection.
                if let Some(name) = matcher
                    .excluded_process(crate::tunnel::process_lookup::Proto::Tcp, local)
                    .await
                {
                    if debug {
                        crate::logs::tun_bypass_process(&name, local, remote);
                    }
                    should_bypass = true;
                }

                // 2. SNI domain check (belt-and-suspenders for CDNs / late-resolved IPs)
                if !should_bypass {
                    if let Some(sni) = &sni {
                        if debug {
                            crate::logs::tun_sni(sni);
                        }
                        if matcher.match_domain(sni) {
                            if debug {
                                crate::logs::tun_bypass_sni(sni, remote);
                            }
                            should_bypass = true;
                        }
                    }
                }

                // 3. Destination IP CIDR check (for IPs not in routing table / IPv6)
                if !should_bypass && matcher.match_ip(&remote.ip()) {
                    if debug {
                        crate::logs::tun_bypass_ip(remote);
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
                            crate::logs::bypass_connect_failed(remote);
                        }
                    }
                    return;
                }

                // ── Tunnel path: forward via local OSTP SOCKS5 proxy ──────────
                // By the ClientHello's name when it has one, so the server's
                // `domain_suffix` rules match (by address only `ip_cidr` can);
                // the server resolves it. A name it cannot connect to soon is
                // tried again by the address the program used.
                let name = sni.as_deref().and_then(|s| connect_name(s, remote));
                let mut socks = None;
                if let Some(name) = &name {
                    let started = std::time::Instant::now();
                    match socks_connect(&proxy_addr, &socks_connect_request(remote, Some(name))).await {
                        Ok(s) => socks = Some(s),
                        // The server's rules refused the name: not tried by address.
                        Err(crate::tunnel::proxy::SOCKS_NOT_ALLOWED) => return,
                        // A slow failure: the address would fail as slowly.
                        Err(_) if started.elapsed() >= NAME_FALLBACK_WITHIN => return,
                        Err(_) => {}
                    }
                }
                let mut socks = match socks {
                    Some(s) => s,
                    None => match socks_connect(&proxy_addr, &socks_connect_request(remote, None)).await {
                        Ok(s) => s,
                        Err(_) => return,
                    },
                };

                // Replay sniffed bytes
                if sniff_len > 0 && socks.write_all(&sniff_buf[..sniff_len]).await.is_err() {
                    return;
                }

                // A reset of the stream to the server reaches this side as a reset of
                // the SOCKS connection (the proxy closes it with a zero linger time);
                // the program's flow then gets a TCP RST, not the FIN a drop sends.
                relay_flow(&mut stream, &mut socks, |s| s.abort()).await;
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

    // Stop every task and wait for it: a dropped JoinHandle only detaches the task,
    // which would keep the TUN device and the userspace stack alive after the
    // tunnel is stopped, and a restart in the same process would meet the old ones.
    runner_task.abort();
    tun_to_stack.abort();
    stack_to_tun.abort();
    udp_proxy_task.abort();
    tcp_accept_task.abort();
    reload_task.abort();
    let _ = tokio::join!(
        runner_task,
        tun_to_stack,
        stack_to_tun,
        udp_proxy_task,
        tcp_accept_task,
        reload_task
    );

    Ok(())
}

/// Wraps the SOCKS side of a relayed flow and notes whether either direction
/// failed with a connection reset (what the local proxy's zero-linger close of a
/// reset stream looks like to a reader or a writer).
#[cfg(any(target_os = "windows", target_os = "linux", target_os = "android", test))]
struct ResetSpy<T> {
    inner: T,
    saw_reset: bool,
}

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "android", test))]
impl<T> ResetSpy<T> {
    fn note<R>(&mut self, r: std::task::Poll<std::io::Result<R>>) -> std::task::Poll<std::io::Result<R>> {
        if let std::task::Poll::Ready(Err(e)) = &r {
            if matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
            ) {
                self.saw_reset = true;
            }
        }
        r
    }
}

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "android", test))]
impl<T: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for ResetSpy<T> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let r = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
        self.note(r)
    }
}

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "android", test))]
impl<T: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for ResetSpy<T> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let r = std::pin::Pin::new(&mut self.inner).poll_write(cx, buf);
        self.note(r)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let r = std::pin::Pin::new(&mut self.inner).poll_flush(cx);
        self.note(r)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let r = std::pin::Pin::new(&mut self.inner).poll_shutdown(cx);
        self.note(r)
    }
}

/// Copies both ways between a TUN flow (`local`, the program's side) and the
/// connection to the local SOCKS proxy (`socks`) until both ends are done.
///
/// A normal end leaves `local` to be dropped, which closes the flow with a FIN.
/// If the SOCKS connection ended with a connection reset (a stream reset or an
/// abort from the server), `abort` is called on `local` before it is dropped, so
/// the program gets a TCP RST and sees a truncated transfer as a failure. An
/// error on the local side alone does not call it: a flow that is already gone
/// has nothing to reset.
#[cfg(any(target_os = "windows", target_os = "linux", target_os = "android", test))]
async fn relay_flow<A, B>(local: &mut A, socks: &mut B, abort: impl FnOnce(&mut A))
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut spy = ResetSpy { inner: socks, saw_reset: false };
    let _ = tokio::io::copy_bidirectional(local, &mut spy).await;
    if spy.saw_reset {
        abort(local);
    }
}

/// A connection by name that failed sooner than this (the server could not
/// resolve the name, say) is tried again by address; a slower failure is
/// not, it would only make the program wait twice.
#[cfg(any(target_os = "windows", target_os = "linux", target_os = "android", test))]
const NAME_FALLBACK_WITHIN: std::time::Duration = std::time::Duration::from_secs(3);

/// Whether `ip` is an internet address. A connection to anything else (a
/// LAN, this server's 10.1.0.1, a carrier-grade NAT range) keeps its
/// address: the name of a ClientHello sent there may mean something else on
/// the server.
#[cfg(any(target_os = "windows", target_os = "linux", target_os = "android", test))]
fn is_internet_address(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xC0) == 64) // 100.64.0.0/10
                || o[0] >= 240)
        }
        std::net::IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_internet_address(std::net::IpAddr::V4(v4));
            }
            let s = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // unique local
                || (s[0] & 0xffc0) == 0xfe80) // link local
        }
    }
}

/// The name a TUN connection to `remote` is sent to the server by, from the
/// server name `sni` of its ClientHello: a DNS name (not an address), and
/// only for a connection to an internet address.
#[cfg(any(target_os = "windows", target_os = "linux", target_os = "android", test))]
fn connect_name(sni: &str, remote: std::net::SocketAddr) -> Option<String> {
    if !is_internet_address(remote.ip()) {
        return None;
    }
    crate::tunnel::sni_sniff::routable_sni(sni)
}

/// A SOCKS5 CONNECT request for `remote`, by `name` (address type 3) when
/// given, otherwise by the address (types 1 and 4).
#[cfg(any(target_os = "windows", target_os = "linux", target_os = "android", test))]
fn socks_connect_request(remote: std::net::SocketAddr, name: Option<&str>) -> Vec<u8> {
    let mut req = vec![5u8, 1, 0];
    match (name, remote.ip()) {
        (Some(name), _) if !name.is_empty() && name.len() <= 255 => {
            req.push(3);
            req.push(name.len() as u8);
            req.extend_from_slice(name.as_bytes());
        }
        (_, std::net::IpAddr::V4(v4)) => {
            req.push(1);
            req.extend_from_slice(&v4.octets());
        }
        (_, std::net::IpAddr::V6(v6)) => {
            req.push(4);
            req.extend_from_slice(&v6.octets());
        }
    }
    req.extend_from_slice(&remote.port().to_be_bytes());
    req
}

/// Opens a connection through the local SOCKS5 proxy with the CONNECT
/// request `req`. On a refusal, the SOCKS5 reply code (0xFF when the local
/// proxy could not be talked to at all).
#[cfg(any(target_os = "windows", target_os = "linux", target_os = "android", test))]
async fn socks_connect(proxy_addr: &str, req: &[u8]) -> Result<tokio::net::TcpStream, u8> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    const BROKEN: u8 = 0xFF;
    let mut socks = tokio::net::TcpStream::connect(proxy_addr).await.map_err(|_| BROKEN)?;
    // SOCKS5 handshake: no auth, and the mark that the exclusions are checked.
    socks.write_all(&[5, 2, 0, crate::tunnel::proxy::TUN_CHECKED_METHOD]).await.map_err(|_| BROKEN)?;
    let mut buf2 = [0u8; 2];
    socks.read_exact(&mut buf2).await.map_err(|_| BROKEN)?;
    if buf2 != [5, 0] {
        return Err(BROKEN);
    }
    socks.write_all(req).await.map_err(|_| BROKEN)?;
    // The local proxy answers with an IPv4 address: 10 bytes.
    let mut rep = [0u8; 10];
    socks.read_exact(&mut rep).await.map_err(|_| BROKEN)?;
    match rep[1] {
        0 => Ok(socks),
        code => Err(code),
    }
}

#[cfg(test)]
mod connect_tests {
    use super::*;

    fn sa(s: &str) -> std::net::SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn a_connect_by_name_carries_the_sni() {
        let remote = sa("142.250.74.14:443");
        let name = connect_name("WWW.YouTube.com", remote).unwrap();
        assert_eq!(name, "www.youtube.com");
        let req = socks_connect_request(remote, Some(&name));
        let mut want = vec![5, 1, 0, 3, 15];
        want.extend_from_slice(b"www.youtube.com");
        want.extend_from_slice(&443u16.to_be_bytes());
        assert_eq!(req, want);
    }

    #[test]
    fn without_a_name_the_address_is_sent() {
        assert_eq!(socks_connect_request(sa("142.250.74.14:443"), None), vec![5, 1, 0, 1, 142, 250, 74, 14, 1, 187]);
        let v6 = socks_connect_request(sa("[2a00:1450::200e]:443"), None);
        assert_eq!(v6[3], 4);
        assert_eq!(v6.len(), 4 + 16 + 2);
    }

    #[test]
    fn no_name_for_local_addresses_or_address_snis() {
        assert!(connect_name("panel.ostp.example", sa("10.1.0.1:443")).is_none());
        assert!(connect_name("nas.home.example", sa("192.168.1.10:443")).is_none());
        assert!(connect_name("x.example", sa("100.64.1.1:443")).is_none());
        assert!(connect_name("x.example", sa("[fe80::1]:443")).is_none());
        assert!(connect_name("x.example", sa("[fd00::1]:443")).is_none());
        assert!(connect_name("142.250.74.14", sa("142.250.74.14:443")).is_none());
        assert!(connect_name("localhost", sa("142.250.74.14:443")).is_none());
        assert!(connect_name("x.example", sa("[2a00:1450::200e]:443")).is_some());
    }

    /// A fake local proxy that answers CONNECT with `code` and hands back
    /// the request it got.
    async fn fake_proxy(code: u8) -> (String, tokio::task::JoinHandle<Vec<u8>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let task = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut hello = [0u8; 4];
            s.read_exact(&mut hello).await.unwrap();
            assert_eq!(hello, [5, 2, 0, crate::tunnel::proxy::TUN_CHECKED_METHOD]);
            s.write_all(&[5, 0]).await.unwrap();
            let mut req = vec![0u8; 512];
            let n = s.read(&mut req).await.unwrap();
            req.truncate(n);
            s.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
            req
        });
        (addr, task)
    }

    #[tokio::test]
    async fn the_proxy_gets_the_name_and_a_refusal_is_reported() {
        let req = socks_connect_request(sa("142.250.74.14:443"), Some("www.youtube.com"));
        let (addr, task) = fake_proxy(0).await;
        assert!(socks_connect(&addr, &req).await.is_ok());
        assert_eq!(task.await.unwrap(), req);

        let (addr, task) = fake_proxy(4).await;
        assert_eq!(socks_connect(&addr, &req).await.err(), Some(4));
        task.await.unwrap();

        let (addr, task) = fake_proxy(crate::tunnel::proxy::SOCKS_NOT_ALLOWED).await;
        assert_eq!(socks_connect(&addr, &req).await.err(), Some(crate::tunnel::proxy::SOCKS_NOT_ALLOWED));
        task.await.unwrap();
    }

    #[test]
    fn a_refusal_by_the_servers_rules_is_told_apart() {
        use crate::tunnel::proxy::{socks_error_code, SOCKS_NOT_ALLOWED};
        assert_eq!(socks_error_code("connect failed: blocked by outbound rule: a.example:443"), SOCKS_NOT_ALLOWED);
        assert_eq!(socks_error_code("connect failed: a.example: blocked by DNS filtering"), SOCKS_NOT_ALLOWED);
        assert_eq!(socks_error_code("connect failed: dns resolution failed for a.example:443"), 0x04);
    }
}

#[cfg(test)]
mod relay_tests {
    use super::*;
    use std::{
        io,
        pin::Pin,
        task::{Context, Poll},
    };
    use tokio::io::{AsyncWriteExt, ReadBuf};

    /// A SOCKS-side connection that fails its reads with `kind`, or ends cleanly.
    struct FakeSocks {
        read_error: Option<io::ErrorKind>,
    }

    impl tokio::io::AsyncRead for FakeSocks {
        fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, _: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            match self.read_error {
                Some(kind) => Poll::Ready(Err(kind.into())),
                None => Poll::Ready(Ok(())), // EOF
            }
        }
    }

    impl tokio::io::AsyncWrite for FakeSocks {
        fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    async fn run(read_error: Option<io::ErrorKind>, close_local_first: bool) -> bool {
        let (mut local, mut app) = tokio::io::duplex(1024);
        if close_local_first {
            // the program goes away: the local side ends (EOF), the other side stays quiet
            app.shutdown().await.unwrap();
        } else {
            // keep the program's end open so only the SOCKS side decides the end
            std::mem::forget(app);
        }
        let mut socks = FakeSocks { read_error };
        let mut aborted = false;
        relay_flow(&mut local, &mut socks, |_| aborted = true).await;
        aborted
    }

    #[tokio::test]
    async fn a_reset_of_the_socks_connection_aborts_the_flow() {
        assert!(run(Some(io::ErrorKind::ConnectionReset), false).await);
        assert!(run(Some(io::ErrorKind::ConnectionAborted), false).await);
    }

    #[tokio::test]
    async fn a_normal_end_does_not_abort() {
        // the SOCKS side ends with EOF and the program's side too: a FIN, not a RST
        assert!(!run(None, true).await);
    }

    #[tokio::test]
    async fn other_socks_errors_do_not_abort() {
        assert!(!run(Some(io::ErrorKind::TimedOut), false).await);
        assert!(!run(Some(io::ErrorKind::UnexpectedEof), false).await);
    }
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
    let mut bypass_nets: Vec<(std::net::IpAddr, u8)> = Vec::new();

    // Server IP always bypasses TUN
    bypass_nets.push((server_ip, if server_ip.is_ipv4() { 32 } else { 128 }));

    // Excluded IPs and CIDRs keep their real prefix: `10.0.0.0/16` used to become a
    // single /32 host route, so the rest of the range went into the tunnel.
    for ip_str in &config.exclusions.ips {
        match crate::tunnel::exclusion::parse_cidr(ip_str) {
            Some(crate::tunnel::exclusion::Cidr::V4(addr, bits)) => {
                bypass_nets.push((std::net::IpAddr::V4(std::net::Ipv4Addr::from(addr)), bits));
            }
            Some(crate::tunnel::exclusion::Cidr::V6(addr, bits)) => {
                bypass_nets.push((std::net::IpAddr::V6(std::net::Ipv6Addr::from(addr)), bits));
            }
            None => tracing::warn!("ignoring invalid excluded address {ip_str:?}"),
        }
    }

    for domain in &config.exclusions.domains {
        let domain = crate::tunnel::exclusion::normalize_domain(domain.trim_start_matches(['.', '*']));
        match tokio::net::lookup_host((domain.as_str(), 443u16)).await {
            Ok(addrs) => {
                for addr in addrs {
                    let ip = addr.ip();
                    bypass_nets.push((ip, if ip.is_ipv4() { 32 } else { 128 }));
                }
            }
            Err(e) => {
                crate::logs::preresolve_failed(&domain, &e);
            }
        };
    }


    // ── 3. Create TUN device via ostp-tun crate ───────────────────────────────
    let opts = ostp_tun::OstpTunOptions {
        server_ip,
        bypass_nets,
        dns_server: config.dns_server.clone(),
        kill_switch: config.kill_switch,
        mtu: config.ostp.mtu.tun_mtu() as u16,
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
