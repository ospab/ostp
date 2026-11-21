use std::collections::HashMap;
use crate::tunnel::exclusion::ExclusionMatcher;
use anyhow::{anyhow, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use tokio::sync::{mpsc, watch};
use tokio::time::{timeout, Duration};

use crate::config::{ExclusionConfig, LocalProxyConfig, OstpConfig};
use crate::tunnel::{ProxyEvent, ProxyToClientMsg};

#[cfg(target_os = "windows")]
use std::os::windows::io::AsRawSocket;

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;

#[cfg(target_os = "windows")]
#[link(name = "ws2_32")]
extern "system" {
    fn setsockopt(
        s: usize,
        level: i32,
        optname: i32,
        optval: *const u8,
        optlen: i32,
    ) -> i32;
}

#[cfg(target_os = "windows")]
pub fn bind_socket_to_interface(socket: &impl AsRawSocket, is_ipv6: bool, if_index: u32) -> std::io::Result<()> {
    let s = socket.as_raw_socket() as usize;
    if is_ipv6 {
        // IPV6_UNICAST_IF expects interface index in host byte order
        let optval = if_index;
        let ret = unsafe {
            setsockopt(
                s,
                41, // IPPROTO_IPV6
                31, // IPV6_UNICAST_IF
                &optval as *const u32 as *const u8,
                4,
            )
        };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
    } else {
        // IP_UNICAST_IF expects interface index in NETWORK byte order (big-endian)
        let optval = if_index.to_be();
        let ret = unsafe {
            setsockopt(
                s,
                0, // IPPROTO_IP
                31, // IP_UNICAST_IF
                &optval as *const u32 as *const u8,
                4,
            )
        };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn bind_socket_to_interface(socket: &impl AsRawFd, if_name: &str) -> std::io::Result<()> {
    let fd = socket.as_raw_fd();
    let mut if_name_bytes = if_name.as_bytes().to_vec();
    if_name_bytes.push(0);
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            if_name_bytes.as_ptr() as *const std::ffi::c_void,
            if_name_bytes.len() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

pub fn get_windows_physical_if_index() -> Option<u32> {
    #[cfg(target_os = "windows")]
    {
        return ostp_tun::windows::windows_route::sys::get_default_ipv4_route().map(|(_, idx)| idx);
    }
    #[cfg(not(target_os = "windows"))]
    {
        None
    }
}

pub fn get_linux_physical_if_name() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let output = std::process::Command::new("ip")
            .args(["route", "show", "default"])
            .output()
            .ok()?;
        if output.status.success() {
            let s = String::from_utf8_lossy(&output.stdout);
            if let Some(dev_part) = s.split_whitespace().skip_while(|w| *w != "dev").nth(1) {
                return Some(dev_part.to_string());
            }
        }
    }
    None
}

#[allow(unused_variables)]
async fn connect_bypassing_tun(
    target: &str,
    physical_if_index: Option<u32>,
    _physical_if_name: &Option<String>,
) -> Result<TcpStream> {
    let resolved = tokio::net::lookup_host(target).await
        .with_context(|| format!("failed to resolve host for bypass connect: {target}"))?;

    let mut last_err = None;
    for addr in resolved {
        let socket = if addr.is_ipv6() {
            let s = tokio::net::TcpSocket::new_v6()?;
            let _ = s.bind("[::]:0".parse().unwrap());
            s
        } else {
            let s = tokio::net::TcpSocket::new_v4()?;
            let _ = s.bind("0.0.0.0:0".parse().unwrap());
            s
        };

        #[cfg(target_os = "windows")]
        if let Some(if_index) = physical_if_index {
            if let Err(e) = bind_socket_to_interface(&socket, addr.is_ipv6(), if_index) {
                tracing::warn!("Failed to bind TCP socket to interface {}: {}", if_index, e);
            }
        }

        #[cfg(target_os = "linux")]
        if let Some(ref if_name) = _physical_if_name {
            if let Err(e) = bind_socket_to_interface(&socket, if_name) {
                tracing::warn!("Failed to bind TCP socket to interface {}: {}", if_name, e);
            }
        }

        match socket.connect(addr).await {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                last_err = Some(e);
            }
        }
    }

    Err(anyhow!(
        "direct connect failed: {:?}",
        last_err.map(|e| e.to_string()).unwrap_or_else(|| "no addresses resolved".to_string())
    ))
}

#[allow(unused_variables)]
async fn create_udp_socket_bypassing_tun(
    is_ipv6: bool,
    physical_if_index: Option<u32>,
    _physical_if_name: &Option<String>,
) -> Result<UdpSocket> {
    let addr: std::net::SocketAddr = if is_ipv6 {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    
    let socket = UdpSocket::bind(addr).await
        .with_context(|| format!("failed to bind direct UdpSocket to wildcard {}", addr))?;

    #[cfg(target_os = "windows")]
    if let Some(if_index) = physical_if_index {
        if let Err(e) = bind_socket_to_interface(&socket, is_ipv6, if_index) {
            tracing::warn!("Failed to bind UDP socket to interface index {}: {}", if_index, e);
        }
    }

    #[cfg(target_os = "linux")]
    if let Some(ref if_name) = _physical_if_name {
        if let Err(e) = bind_socket_to_interface(&socket, if_name) {
            tracing::warn!("Failed to bind UDP socket to interface {}: {}", if_name, e);
        }
    }

    Ok(socket)
}

/// Local connections open at once. The cap keeps a runaway program from taking
/// every descriptor of the machine (the tunnel's own limit per session is
/// lower: `ostp_core::streams::MAX_OPEN_STREAMS`).
const MAX_LOCAL_STREAMS: usize = 20_000;
/// Download bytes waiting for a local program to read them. Toward a server
/// without flow control (v5 before 0.4.7) the server sends as fast as the
/// path allows whether or not the program reads, so a stalled reader would
/// otherwise grow the client's memory by the whole download; past it the
/// stream is reset. With flow control (every v6 stream) the window keeps the
/// queue under 8 MiB and this is never reached.
const MAX_QUEUED_DOWNLOAD: usize = 32 * 1024 * 1024;
/// How long a local program gets to send its first byte (browsers keep
/// pre-opened sockets idle for a while) and to finish a SOCKS5 or HTTP request.
const LOCAL_FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(120);
const LOCAL_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// A local connection's queue towards its task: the messages, and how many
/// download bytes are in them.
struct StreamSlot {
    tx: mpsc::UnboundedSender<ProxyToClientMsg>,
    queued: Arc<std::sync::atomic::AtomicUsize>,
}

async fn read_exact_within(client: &mut TcpStream, buf: &mut [u8], limit: Duration) -> Result<()> {
    timeout(limit, client.read_exact(buf))
        .await
        .map_err(|_| anyhow!("the local program did not finish its request in time"))??;
    Ok(())
}

/// Binds the local proxy's listening socket. Separate from the accept loop so a
/// caller (the Android library) can report a busy port before it starts anything.
pub async fn bind_local_proxy(bind_addr: &str) -> Result<TcpListener> {
    let listener = TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind local HTTP/SOCKS5 proxy at {bind_addr}"))?;

    tracing::info!("local HTTP/SOCKS5 proxy listening at {}", bind_addr);
    if let Ok(local) = listener.local_addr() {
        if !local.ip().is_loopback() {
            tracing::warn!(
                "the local proxy listens on {local}, not on a loopback address: it has no authentication, \
                 so anyone who can reach this port can use the tunnel as an open proxy"
            );
        }
    }
    Ok(listener)
}

pub async fn run_local_socks5_proxy(
    cfg: LocalProxyConfig,
    ostp: OstpConfig,
    exclusions_rx: watch::Receiver<ExclusionConfig>,
    debug: bool,
    shutdown: watch::Receiver<bool>,
    proxy_events_tx: mpsc::Sender<ProxyEvent>,
    client_msgs_rx: mpsc::UnboundedReceiver<(u32, ProxyToClientMsg)>,
) -> Result<()> {
    let listener = bind_local_proxy(&cfg.bind_addr).await?;
    run_local_socks5_proxy_on(listener, cfg, ostp, exclusions_rx, debug, shutdown, proxy_events_tx, client_msgs_rx).await
}

/// The accept loop of the local proxy on an already bound `listener`.
pub async fn run_local_socks5_proxy_on(
    listener: TcpListener,
    cfg: LocalProxyConfig,
    ostp: OstpConfig,
    mut exclusions_rx: watch::Receiver<ExclusionConfig>,
    debug: bool,
    mut shutdown: watch::Receiver<bool>,
    proxy_events_tx: mpsc::Sender<ProxyEvent>,
    mut client_msgs_rx: mpsc::UnboundedReceiver<(u32, ProxyToClientMsg)>,
) -> Result<()> {
    let connect_timeout = Duration::from_millis(cfg.connect_timeout_ms.max(1));

    let physical_if_index = tokio::task::spawn_blocking(get_windows_physical_if_index).await.unwrap_or(None);
    let physical_if_name = tokio::task::spawn_blocking(get_linux_physical_if_name).await.unwrap_or(None);

    if physical_if_index.is_some() {
        tracing::info!("Local proxy physical interface index: {:?}", physical_if_index);
    }
    if physical_if_name.is_some() {
        tracing::info!("Local proxy physical interface name: {:?}", physical_if_name);
    }

    let mut current_exclusions = exclusions_rx.borrow().clone();
    let mut matcher = ExclusionMatcher::new(&current_exclusions, physical_if_index, physical_if_name.clone());
    let (connect_tx, mut connect_rx) = mpsc::channel(128);
    // A fixed MTU cuts each read to that size, as it always did. With `auto`
    // the bridge cuts to the datagram size the session has found, which grows
    // while the session runs: the reads go to it whole.
    let max_chunk = match ostp.mtu {
        crate::config::MtuSetting::Fixed(mtu) => mtu.saturating_sub(150).max(512),
        crate::config::MtuSetting::Auto => usize::MAX,
    };

    let mut next_stream_id: u32 = 1;
    let mut active_streams: HashMap<u32, StreamSlot> = HashMap::new();

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }
            Ok(_) = exclusions_rx.changed() => {
                current_exclusions = exclusions_rx.borrow().clone();
                matcher = ExclusionMatcher::new(&current_exclusions, physical_if_index, physical_if_name.clone());
                if true {
                    tracing::info!("Local proxy exclusions hot-reloaded");
                }
            }
            accepted = listener.accept() => {
                // An accept error (out of descriptors, a connection reset
                // before it was accepted) is about that connection, not the
                // listener: ending here stops the whole client.
                let (socket, _) = match accepted {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!("local proxy accept failed: {e}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                if active_streams.len() >= MAX_LOCAL_STREAMS {
                    tracing::warn!("local proxy: {MAX_LOCAL_STREAMS} connections open, refusing another");
                    continue;
                }
                let stream_id = next_stream_id;
                // Advance, skipping zero and any stream_id still in active_streams
                loop {
                    next_stream_id = next_stream_id.wrapping_add(1);
                    if next_stream_id == 0 { next_stream_id = 1; }
                    if !active_streams.contains_key(&next_stream_id) { break; }
                }

                let (tx, rx) = mpsc::unbounded_channel();
                let queued = Arc::new(std::sync::atomic::AtomicUsize::new(0));
                active_streams.insert(stream_id, StreamSlot { tx, queued: queued.clone() });

                let event_tx = proxy_events_tx.clone();
                let c_tx = connect_tx.clone();
                let matcher_clone = matcher.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_proxy_client(
                        socket,
                        stream_id,
                        event_tx,
                        rx,
                        queued,
                        c_tx,
                        connect_timeout,
                        debug,
                        matcher_clone,
                        max_chunk,
                    ).await {
                        let msg = err.to_string();
                        // Suppress routine disconnects and unsupported SOCKS5 command attempts (like UDP) from spam logs
                        if !msg.contains("UnexpectedEof")
                            && !msg.contains("Connection reset")
                            && !msg.contains("Broken pipe")
                            && !msg.contains("unsupported SOCKS5 command")
                            && debug {
                                tracing::warn!("proxy client error: {err}");
                            }
                    }
                });
            }
            Some((stream_id, msg)) = client_msgs_rx.recv() => {
                if stream_id == 0 {
                    if let ProxyToClientMsg::Close = msg {
                        if true {
                            tracing::info!("Resetting all active proxy streams on reconnect");
                        }
                        for (_, slot) in active_streams.drain() {
                            let _ = slot.tx.send(ProxyToClientMsg::Close);
                        }
                    }
                } else if let Some(slot) = active_streams.get(&stream_id) {
                    let mut stalled = false;
                    if let ProxyToClientMsg::Data(data) = &msg {
                        let queued = slot.queued.fetch_add(data.len(), std::sync::atomic::Ordering::Relaxed) + data.len();
                        stalled = queued > MAX_QUEUED_DOWNLOAD;
                    }
                    if stalled {
                        tracing::warn!("stream {stream_id}: over {} MB waiting for the local program, resetting it", MAX_QUEUED_DOWNLOAD >> 20);
                        let _ = slot.tx.send(ProxyToClientMsg::Error("the local program does not read fast enough".into()));
                        active_streams.remove(&stream_id);
                        // The server keeps sending until told otherwise.
                        let events = proxy_events_tx.clone();
                        tokio::spawn(async move {
                            let _ = events.send(ProxyEvent::Close { stream_id }).await;
                        });
                    } else if slot.tx.send(msg).is_err() {
                        active_streams.remove(&stream_id);
                    }
                }
            }
            Some(stream_id) = connect_rx.recv() => {
                // The connection is over, however it ended. The bridge is told
                // once: a v6 stream it still holds is aborted and released.
                if active_streams.remove(&stream_id).is_some() {
                    let events = proxy_events_tx.clone();
                    tokio::spawn(async move {
                        let _ = events.send(ProxyEvent::Gone { stream_id }).await;
                    });
                }
            }
        }
    }

    Ok(())
}

/// Index just past the first blank line (`\r\n\r\n`) of an HTTP request head.
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// `authority` (`host`, `host:port`, `[v6]`, `[v6]:port`) with `default_port` added
/// when it has none. A bare IPv6 literal without brackets is bracketed.
fn with_default_port(authority: &str, default_port: u16) -> String {
    if let Some(rest) = authority.strip_prefix('[') {
        // "[v6]" or "[v6]:port"
        return match rest.find(']') {
            Some(close) if rest[close + 1..].starts_with(':') && rest.len() > close + 2 => authority.to_string(),
            Some(close) => format!("[{}]:{}", &rest[..close], default_port),
            None => authority.to_string(),
        };
    }
    match authority.matches(':').count() {
        0 => format!("{authority}:{default_port}"),
        1 => authority.to_string(),
        // Several colons without brackets: an IPv6 literal.
        _ => format!("[{authority}]:{default_port}"),
    }
}

/// Extracts `host:port` from an HTTP absolute-URI like `http://example.com/path` or
/// `http://[::1]:8080/x`. Falls back to the raw target if already in `host:port` form.
fn extract_host_port(uri: &str, default_port: u16) -> String {
    let without_scheme = if let Some(rest) = uri.strip_prefix("https://") {
        rest
    } else if let Some(rest) = uri.strip_prefix("http://") {
        rest
    } else {
        uri
    };
    // The authority ends at the path, query or fragment; drop any user info.
    let authority = without_scheme.split(['/', '?', '#']).next().unwrap_or(without_scheme);
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    with_default_port(authority, default_port)
}

struct StreamGuard {
    stream_id: u32,
    close_tx: mpsc::Sender<u32>,
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        let tx = self.close_tx.clone();
        let id = self.stream_id;
        tokio::spawn(async move {
            let _ = tx.send(id).await;
        });
    }
}

async fn handle_udp_associate(
    mut client_tcp: TcpStream,
    udp_socket: tokio::net::UdpSocket,
    stream_id: u32,
    event_tx: mpsc::Sender<ProxyEvent>,
    mut rx: mpsc::UnboundedReceiver<ProxyToClientMsg>,
    close_tx: mpsc::Sender<u32>,
    debug: bool,
    matcher: ExclusionMatcher,
    connect_timeout: Duration,
) -> Result<()> {
    let client_udp_addr = Arc::new(std::sync::Mutex::new(None));
    // Only datagrams from the host of the control connection are relayed: the first
    // sender used to be taken as the client, whoever it was.
    let control_ip = client_tcp.peer_addr().ok().map(|a| a.ip());
    let mut buf = vec![0u8; 65536];
    
    let udp_socket = Arc::new(udp_socket);
    let sock_rx = udp_socket.clone();
    let sock_tx = udp_socket;

    let mut direct_udp_v4: Option<Arc<UdpSocket>> = None;
    let mut direct_udp_v6: Option<Arc<UdpSocket>> = None;
    // Held only to keep the direct-UDP readers' cancellation senders alive;
    // dropping this (on every return path from this function) is what tells
    // spawn_direct_udp_reader's tasks to stop. See its doc comment.
    let mut direct_udp_cancel_txs: Vec<tokio::sync::oneshot::Sender<()>> = Vec::new();

    let mut tcp_buf = [0u8; 1];
    loop {
        tokio::select! {
            res = client_tcp.read(&mut tcp_buf) => {
                match res {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
            res = sock_rx.recv_from(&mut buf) => {
                let (len, addr) = match res {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::debug!("udp_associate recv_from error: {}", e);
                        continue; // transient error, don't kill the session
                    }
                };
                if control_ip.map_or(true, |ip| ip != addr.ip()) {
                    tracing::debug!("udp_associate: dropped a datagram from {addr}, not the control connection's host");
                    continue;
                }
                {
                    let mut guard = client_udp_addr.lock().unwrap();
                    if guard.is_none() {
                        *guard = Some(addr);
                    }
                }
                if len < 4 { continue; }
                let frag = buf[2];
                if frag != 0 { continue; } // Fragmented UDP not supported
                let atyp = buf[3];
                let (header_len, target) = match atyp {
                    0x01 => {
                        if len < 10 { continue; }
                        let ip = std::net::Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
                        let port = u16::from_be_bytes([buf[8], buf[9]]);
                        (10, format!("{}:{}", ip, port))
                    }
                    0x03 => {
                        if len < 5 { continue; }
                        let domain_len = buf[4] as usize;
                        if len < 5 + domain_len + 2 { continue; }
                        let domain = String::from_utf8_lossy(&buf[5..5+domain_len]);
                        let port = u16::from_be_bytes([buf[5+domain_len], buf[5+domain_len+1]]);
                        (5 + domain_len + 2, format!("{}:{}", domain, port))
                    }
                    0x04 => {
                        if len < 22 { continue; }
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(&buf[4..20]);
                        let ip = std::net::Ipv6Addr::from(octets);
                        let port = u16::from_be_bytes([buf[20], buf[21]]);
                        (22, format!("[{}]:{}", ip, port))
                    }
                    _ => continue,
                };
                let payload = bytes::Bytes::copy_from_slice(&buf[header_len..len]);

                let target_host = if let Some((host, _)) = split_host_port(&target) { host } else { target.clone() };
                let target_port = match split_host_port(&target) { Some((_, p)) => p, None => 0 };
                // Check if target should bypass the tunnel
                if matcher.should_bypass_target(&target_host, target_port, connect_timeout).await {
                    crate::logs::udp_bypass(&target);
                    // Resolve target to find if it is IPv4 or IPv6
                    if let Ok(resolved_addrs) = tokio::net::lookup_host(&target).await {
                        if let Some(target_addr) = resolved_addrs.into_iter().next() {
                            let is_ipv6 = target_addr.is_ipv6();
                            let direct_socket = if is_ipv6 {
                                if direct_udp_v6.is_none() {
                                    match create_udp_socket_bypassing_tun(true, matcher.physical_if_index, &matcher.physical_if_name).await {
                                        Ok(s) => {
                                            let s_arc = Arc::new(s);
                                            let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();
                                            spawn_direct_udp_reader(s_arc.clone(), sock_tx.clone(), client_udp_addr.clone(), debug, cancel_rx);
                                            direct_udp_cancel_txs.push(cancel_tx);
                                            direct_udp_v6 = Some(s_arc);
                                        }
                                        Err(e) => {
                                            tracing::error!("Failed to create bypass UDP v6 socket: {}", e);
                                        }
                                    }
                                }
                                &direct_udp_v6
                            } else {
                                if direct_udp_v4.is_none() {
                                    match create_udp_socket_bypassing_tun(false, matcher.physical_if_index, &matcher.physical_if_name).await {
                                        Ok(s) => {
                                            let s_arc = Arc::new(s);
                                            let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();
                                            spawn_direct_udp_reader(s_arc.clone(), sock_tx.clone(), client_udp_addr.clone(), debug, cancel_rx);
                                            direct_udp_cancel_txs.push(cancel_tx);
                                            direct_udp_v4 = Some(s_arc);
                                        }
                                        Err(e) => {
                                            tracing::error!("Failed to create bypass UDP v4 socket: {}", e);
                                        }
                                    }
                                }
                                &direct_udp_v4
                            };

                            if let Some(s) = direct_socket {
                                if let Err(e) = s.send_to(&payload, target_addr).await {
                                    crate::logs::udp_send_failed(target_addr, &e);
                                }
                            }
                        }
                    }
                } else {
                    crate::logs::udp_forward(&target, payload.len());
                    let _ = event_tx.send(ProxyEvent::UdpData { stream_id, target, payload }).await;
                }
            }
            msg = rx.recv() => {
                match msg {
                    Some(ProxyToClientMsg::UdpData(target, data)) => {
                        if let Some(client_addr) = {
                            let guard = client_udp_addr.lock().unwrap();
                            *guard
                        } {
                            let mut packet = vec![0x00, 0x00, 0x00];
                            let mut parts = target.rsplitn(2, ':');
                            let port_str = parts.next().unwrap_or("0");
                            let host_str = parts.next().unwrap_or(&target);
                            let host_str = host_str.trim_start_matches('[').trim_end_matches(']');
                            let port = port_str.parse::<u16>().unwrap_or(0);
                            
                            if let Ok(ipv4) = host_str.parse::<std::net::Ipv4Addr>() {
                                packet.push(0x01);
                                packet.extend_from_slice(&ipv4.octets());
                            } else if let Ok(ipv6) = host_str.parse::<std::net::Ipv6Addr>() {
                                packet.push(0x04);
                                packet.extend_from_slice(&ipv6.octets());
                            } else {
                                packet.push(0x03);
                                let bytes = host_str.as_bytes();
                                packet.push(bytes.len() as u8);
                                packet.extend_from_slice(bytes);
                            }
                            packet.extend_from_slice(&port.to_be_bytes());
                            packet.extend_from_slice(&data);
                            crate::logs::udp_reply(&target, data.len());
                            let _ = sock_tx.send_to(&packet, client_addr).await;
                        } else {
                            crate::logs::bad_target(&target);
                        }
                    }
                    Some(ProxyToClientMsg::Close) | Some(ProxyToClientMsg::Reset) | Some(ProxyToClientMsg::Error(_)) | None => break,
                    _ => {}
                }
            }
        }
    }
    let _ = close_tx.send(stream_id).await;
    Ok(())
}

fn spawn_direct_udp_reader(
    direct_socket: Arc<UdpSocket>,
    sock_tx: Arc<UdpSocket>,
    client_udp_addr: Arc<std::sync::Mutex<Option<std::net::SocketAddr>>>,
    _debug: bool,
    mut cancel_rx: tokio::sync::oneshot::Receiver<()>,
) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let recv_result = tokio::select! {
                // Fires as soon as the sender half (held by handle_udp_associate
                // for exactly this reason) is dropped - which happens the
                // instant that function returns, on every exit path, with no
                // explicit signaling needed. Without this, a UDP-associate
                // session that ever bypassed traffic direct (excluded IP/
                // domain) leaked this socket + task for the rest of the
                // process's life once the session ended: nothing else ever
                // stopped this loop.
                _ = &mut cancel_rx => break,
                res = direct_socket.recv_from(&mut buf) => res,
            };
            match recv_result {
                Ok((len, target_addr)) => {
                    let client_addr = {
                        let guard = client_udp_addr.lock().unwrap();
                        *guard
                    };
                    if let Some(client_addr) = client_addr {
                        let mut packet = vec![0x00, 0x00, 0x00];
                        if let Ok(ipv4) = target_addr.ip().to_string().parse::<std::net::Ipv4Addr>() {
                            packet.push(0x01);
                            packet.extend_from_slice(&ipv4.octets());
                        } else if let Ok(ipv6) = target_addr.ip().to_string().parse::<std::net::Ipv6Addr>() {
                            packet.push(0x04);
                            packet.extend_from_slice(&ipv6.octets());
                        } else {
                            continue;
                        }
                        packet.extend_from_slice(&target_addr.port().to_be_bytes());
                        packet.extend_from_slice(&buf[..len]);
                        if let Err(e) = sock_tx.send_to(&packet, client_addr).await {
                            if true {
                                tracing::warn!("failed to send direct UDP response to client: {e}");
                            }
                        }
                    }
                }
                Err(e) => {
                    if true {
                        tracing::debug!("direct UDP socket read loop exiting: {e}");
                    }
                    break;
                }
            }
        }
    });
}

/// Reads the destination of a SOCKS5 request (the part after the 4-byte header) as
/// `host:port`. `None` for an address type this proxy does not support.
async fn read_socks5_target(client: &mut TcpStream, atyp: u8) -> Result<Option<String>> {
    // 1 length byte + up to 255 domain bytes + 2 port bytes.
    let mut addr_buf = [0_u8; 258];
    Ok(Some(match atyp {
        0x01 => {
            // IPv4: 4 bytes address + 2 bytes port
            read_exact_within(client, &mut addr_buf[0..6], LOCAL_REQUEST_TIMEOUT).await?;
            let ip = std::net::Ipv4Addr::new(addr_buf[0], addr_buf[1], addr_buf[2], addr_buf[3]);
            let port = u16::from_be_bytes([addr_buf[4], addr_buf[5]]);
            format!("{}:{}", ip, port)
        }
        0x03 => {
            // Domain: 1 byte length, then domain, then 2 bytes port
            read_exact_within(client, &mut addr_buf[0..1], LOCAL_REQUEST_TIMEOUT).await?;
            let domain_len = addr_buf[0] as usize;
            read_exact_within(client, &mut addr_buf[0..domain_len + 2], LOCAL_REQUEST_TIMEOUT).await?;
            let domain = String::from_utf8_lossy(&addr_buf[0..domain_len]);
            let port = u16::from_be_bytes([addr_buf[domain_len], addr_buf[domain_len + 1]]);
            format!("{}:{}", domain, port)
        }
        0x04 => {
            // IPv6: 16 bytes + 2 bytes port
            read_exact_within(client, &mut addr_buf[0..18], LOCAL_REQUEST_TIMEOUT).await?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&addr_buf[0..16]);
            let ip = std::net::Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([addr_buf[16], addr_buf[17]]);
            format!("[{}]:{}", ip, port)
        }
        _ => return Ok(None),
    }))
}

async fn handle_proxy_client(
    mut client: TcpStream,
    stream_id: u32,
    event_tx: mpsc::Sender<ProxyEvent>,
    mut rx: mpsc::UnboundedReceiver<ProxyToClientMsg>,
    queued: Arc<std::sync::atomic::AtomicUsize>,
    close_tx: mpsc::Sender<u32>,
    connect_timeout: Duration,
    debug: bool,
    mut matcher: ExclusionMatcher,
    max_chunk: usize,
) -> Result<()> {
    let _guard = StreamGuard { stream_id, close_tx: close_tx.clone() };

    // A program on this machine is known by its end of the connection. An
    // excluded one goes direct whatever it asks for.
    if let Ok(peer) = client.peer_addr() {
        if peer.ip().is_loopback() {
            if let Some(name) = matcher
                .excluded_process(crate::tunnel::process_lookup::Proto::Tcp, peer)
                .await
            {
                tracing::debug!("proxy BYPASS (process {name}) stream_id={stream_id}");
                matcher.bypass_all = true;
            }
        }
    }

    // Peek the first byte to distinguish SOCKS5 (0x05) from HTTP (any printable ASCII)
    let mut first_byte = [0_u8; 1];
    read_exact_within(&mut client, &mut first_byte, LOCAL_FIRST_BYTE_TIMEOUT).await?;

    let target: String;
    let is_socks5 = first_byte[0] == 0x05;
    // Whether the stream behind this connection is a v6 one (see
    // `ProxyToClientMsg::ConnectOkV6`): half-close, flow control from the start.
    let v6: bool;

    if is_socks5 {
        // ── SOCKS5 Handshake ──────────────────────────────────────────
        let mut second_byte = [0_u8; 1];
        read_exact_within(&mut client, &mut second_byte, LOCAL_REQUEST_TIMEOUT).await?;
        let nmethods = second_byte[0] as usize;
        if nmethods > 0 {
            let mut methods_buf = vec![0_u8; nmethods];
            read_exact_within(&mut client, &mut methods_buf, LOCAL_REQUEST_TIMEOUT).await?;
        }
        // Reply: version=5, NO AUTHENTICATION
        client.write_all(&[0x05, 0x00]).await?;

        // ── SOCKS5 Request ────────────────────────────────────────────
        let mut req = [0_u8; 4];
        read_exact_within(&mut client, &mut req, LOCAL_REQUEST_TIMEOUT).await?;
        if req[0] != 0x05 {
            return Err(anyhow!("SOCKS5 request version mismatch"));
        }
        
        let is_udp = req[1] == 0x03;
        if req[1] != 0x01 && !is_udp {
            // Not CONNECT and Not UDP ASSOCIATE — send COMMAND NOT SUPPORTED
            client.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            return Err(anyhow!("unsupported SOCKS5 command {}", req[1]));
        }

        target = match read_socks5_target(&mut client, req[3]).await? {
            Some(t) => t,
            None => {
                client.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
                return Err(anyhow!("unsupported SOCKS5 address type: {}", req[3]));
            }
        };

        if is_udp {
            if true { tracing::debug!("proxy UDP ASSOCIATE stream_id={stream_id}"); }
            let udp_socket = UdpSocket::bind("127.0.0.1:0").await?;
            let port = udp_socket.local_addr()?.port();
            let mut reply = vec![0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1];
            reply.extend_from_slice(&port.to_be_bytes());
            client.write_all(&reply).await?;
            
            event_tx.send(ProxyEvent::UdpAssociate { stream_id }).await?;
            return handle_udp_associate(
                client,
                udp_socket,
                stream_id,
                event_tx,
                rx,
                close_tx,
                debug,
                matcher,
                connect_timeout,
            ).await;
        }

        crate::logs::proxy_connect_request(stream_id, &target);
        let target_host = if let Some((host, _)) = split_host_port(&target) { host } else { target.clone() };
        let target_port = match split_host_port(&target) { Some((_, p)) => p, None => 0 };
        if matcher.should_bypass_target(&target_host, target_port, connect_timeout).await {
            return direct_connect_socks5(
                client,
                stream_id,
                &target,
                matcher.physical_if_index,
                &matcher.physical_if_name,
                close_tx,
                debug,
            ).await;
        }
        event_tx.send(ProxyEvent::NewStream { stream_id, target: target.clone() }).await?;

        match timeout(connect_timeout, rx.recv()).await {
            Ok(Some(ok @ (ProxyToClientMsg::ConnectOk | ProxyToClientMsg::ConnectOkV6))) => {
                v6 = matches!(ok, ProxyToClientMsg::ConnectOkV6);
                // SUCCESS: version, 0=success, reserved, IPv4 type, 4 bytes addr, 2 bytes port
                client.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            }
            Ok(Some(ProxyToClientMsg::Error(msg))) => {
                client.write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
                let _ = close_tx.send(stream_id).await;
                return Err(anyhow!("SOCKS5 connect error: {msg}"));
            }
            Ok(_) => {
                client.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
                let _ = close_tx.send(stream_id).await;
                return Err(anyhow!("connect dropped"));
            }
            Err(_) => {
                client.write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
                let _ = close_tx.send(stream_id).await;
                return Err(anyhow!("connect timeout"));
            }
        }
    } else {
        // ── HTTP Proxy (CONNECT and plain GET/POST) ───────────────────
        // Read the rest of the HTTP request headers byte-by-byte
        let mut header_bytes = Vec::with_capacity(512);
        let mut leftover: Vec<u8>;
        header_bytes.push(first_byte[0]);
        let mut chunk = [0_u8; 512];
        loop {
            let n = timeout(LOCAL_REQUEST_TIMEOUT, client.read(&mut chunk))
                .await
                .map_err(|_| anyhow!("the local program did not finish its request in time"))??;
            if n == 0 {
                return Err(anyhow!("connection closed during HTTP header read"));
            }
            header_bytes.extend_from_slice(&chunk[..n]);
            // The request may arrive with its body (or, after CONNECT, the first bytes
            // of the tunneled stream) in the same read: cut at the first blank line.
            if let Some(end) = find_header_end(&header_bytes) {
                leftover = header_bytes.split_off(end);
                break;
            }
            if header_bytes.len() > 8192 {
                client.write_all(b"HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n").await?;
                return Err(anyhow!("HTTP header too large"));
            }
        }

        let req_str = String::from_utf8_lossy(&header_bytes);
        let first_line = req_str.lines().next().unwrap_or("");
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() < 2 {
            client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await?;
            return Err(anyhow!("malformed HTTP request line: {:?}", first_line));
        }

        let method = parts[0].to_uppercase();
        let raw_uri = parts[1];

        target = if method == "CONNECT" {
            // CONNECT uses host:port directly — e.g. "CONNECT example.com:443 HTTP/1.1"
            with_default_port(raw_uri, 443)
        } else {
            // Plain HTTP: absolute URI like "GET http://example.com/path HTTP/1.1"
            let default_port = if raw_uri.starts_with("https://") { 443u16 } else { 80u16 };
            extract_host_port(raw_uri, default_port)
        };

        crate::logs::proxy_connect(stream_id, &target);
        // What goes to the remote side before the raw copy starts: for CONNECT only the
        // bytes that followed the request headers, for a plain request the headers
        // (which this proxy consumed) and whatever of the body came with them.
        let forward_prefix: Vec<u8> = if method == "CONNECT" {
            std::mem::take(&mut leftover)
        } else {
            let mut v = std::mem::take(&mut header_bytes);
            v.append(&mut leftover);
            v
        };
        let target_host = if let Some((host, _)) = split_host_port(&target) { host } else { target.clone() };
        let target_port = match split_host_port(&target) { Some((_, p)) => p, None => 443 };
        if matcher.should_bypass_target(&target_host, target_port, connect_timeout).await {
            return direct_connect_http(
                client,
                stream_id,
                &target,
                method.as_str(),
                forward_prefix,
                matcher.physical_if_index,
                &matcher.physical_if_name,
                close_tx,
                debug,
            ).await;
        }
        event_tx.send(ProxyEvent::NewStream { stream_id, target: target.clone() }).await?;

        match timeout(connect_timeout, rx.recv()).await {
            Ok(Some(ok @ (ProxyToClientMsg::ConnectOk | ProxyToClientMsg::ConnectOkV6))) => {
                v6 = matches!(ok, ProxyToClientMsg::ConnectOkV6);
                if method == "CONNECT" {
                    // For CONNECT, tell client the tunnel is ready
                    client.write_all(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: ostp/1.0\r\n\r\n").await?;
                }
                // For plain HTTP the request we consumed must be forwarded to the
                // server over the newly established tunnel; for CONNECT, any bytes
                // the program sent right behind the request.
                for piece in forward_prefix.chunks(max_chunk) {
                    event_tx.send(ProxyEvent::Data {
                        stream_id,
                        payload: bytes::Bytes::copy_from_slice(piece),
                    }).await?;
                }
            }
            Ok(Some(ProxyToClientMsg::Error(msg))) => {
                client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await?;
                let _ = close_tx.send(stream_id).await;
                return Err(anyhow!("HTTP connect error: {msg}"));
            }
            Ok(_) => {
                client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await?;
                let _ = close_tx.send(stream_id).await;
                return Err(anyhow!("connect dropped"));
            }
            Err(_) => {
                client.write_all(b"HTTP/1.1 504 Gateway Timeout\r\n\r\n").await?;
                let _ = close_tx.send(stream_id).await;
                return Err(anyhow!("connect timeout"));
            }
        }
    }

    // ── Bidirectional raw data forwarding ─────────────────────────────
    let mut tcp_buf = vec![0_u8; 65536];
    // Flow control, once the server sent the first `Window` for the stream:
    // `credit` is what may still be read from the program and sent, and
    // `consumed` what reached the program since the last grant to the server.
    let mut flow_control = false;
    let mut credit: i64 = i64::MAX;
    // A v6 stream has a window from the start, without a `Window` message.
    if v6 {
        flow_control = true;
        credit = ostp_core::relay::INITIAL_STREAM_WINDOW as i64;
    }
    let mut consumed: u32 = 0;
    // v6 half-close: the program closed its side (we sent `Fin`), or the peer
    // sent its own `Fin`. The connection ends when both have.
    let mut local_eof = false;
    let mut remote_fin = false;
    loop {
        let read_limit = if local_eof { 0 } else { credit.clamp(0, tcp_buf.len() as i64) as usize };
        tokio::select! {
            read_res = client.read(&mut tcp_buf[..read_limit]), if read_limit > 0 => {
                match read_res {
                    Ok(0) if v6 => {
                        // The program will send no more but still reads: the
                        // other direction goes on.
                        let _ = event_tx.send(ProxyEvent::Fin { stream_id }).await;
                        tracing::debug!("proxy FIN stream_id={stream_id}");
                        local_eof = true;
                        if remote_fin {
                            break;
                        }
                    }
                    Ok(0) => {
                        let _ = event_tx.send(ProxyEvent::Close { stream_id }).await;
                        if true {
                            tracing::info!("proxy CLOSE stream_id={stream_id}");
                        }
                        break;
                    }
                    Ok(n) => {
                        if flow_control {
                            credit -= n as i64;
                        }
                        let mut offset = 0;
                        while offset < n {
                            let end = offset.saturating_add(max_chunk).min(n);
                            let _ = event_tx.send(ProxyEvent::Data {
                                stream_id,
                                payload: bytes::Bytes::copy_from_slice(&tcp_buf[offset..end]),
                            }).await;
                            offset = end;
                        }
                    }
                    Err(_) => {
                        let _ = event_tx.send(ProxyEvent::Close { stream_id }).await;
                        if true {
                            tracing::info!("proxy CLOSE stream_id={stream_id}");
                        }
                        break;
                    }
                }
            }
            msg = rx.recv() => {
                match msg {
                    Some(ProxyToClientMsg::Data(data)) => {
                        queued.fetch_sub(data.len(), std::sync::atomic::Ordering::Relaxed);
                        if client.write_all(&data).await.is_err() {
                            let _ = event_tx.send(ProxyEvent::Close { stream_id }).await;
                            break;
                        }
                        if flow_control {
                            consumed = consumed.saturating_add(data.len() as u32);
                            if consumed >= ostp_core::relay::WINDOW_UPDATE_STEP {
                                let _ = event_tx.send(ProxyEvent::Consumed { stream_id, bytes: consumed }).await;
                                consumed = 0;
                            }
                        }
                    }
                    Some(ProxyToClientMsg::Window(bytes)) => {
                        if flow_control {
                            credit = credit.saturating_add(bytes as i64);
                        } else {
                            // The server's first grant: what it allows from now on.
                            flow_control = true;
                            credit = bytes as i64;
                        }
                    }
                    Some(ProxyToClientMsg::Fin) => {
                        // The peer will send no more: the program gets its end
                        // of stream (after every byte before it, which came
                        // first), and may still write.
                        remote_fin = true;
                        let _ = client.shutdown().await;
                        if local_eof {
                            break;
                        }
                    }
                    Some(ProxyToClientMsg::Reset) => {
                        // Aborted or lost: the program must see a reset, not an
                        // orderly end of a truncated stream.
                        reset_connection(&client);
                        break;
                    }
                    Some(ProxyToClientMsg::Close) | Some(ProxyToClientMsg::Error(_)) | None => {
                        break;
                    }
                    Some(ProxyToClientMsg::ConnectOk) | Some(ProxyToClientMsg::ConnectOkV6) | Some(ProxyToClientMsg::UdpData(_, _)) => {} // ignored after connect phase
                }
            }
        }
    }

    let _ = close_tx.send(stream_id).await;
    Ok(())
}


use ostp_core::net::split_host_port;

/// Closes the program's connection with a reset (RST) instead of a FIN: a
/// zero linger time makes the close abort the connection.
fn reset_connection(client: &TcpStream) {
    if let Err(e) = socket2::SockRef::from(client).set_linger(Some(Duration::ZERO)) {
        tracing::debug!("could not set a zero linger to reset the connection: {e}");
    }
}

async fn direct_connect_socks5(
    mut client: TcpStream,
    stream_id: u32,
    target: &str,
    physical_if_index: Option<u32>,
    physical_if_name: &Option<String>,
    close_tx: mpsc::Sender<u32>,
    _debug: bool,
) -> Result<()> {
    crate::logs::proxy_bypass(stream_id, &target);
    let mut remote = connect_bypassing_tun(target, physical_if_index, physical_if_name).await?;

    client.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
    let _ = tokio::io::copy_bidirectional(&mut client, &mut remote).await;
    let _ = close_tx.send(stream_id).await;
    Ok(())
}

async fn direct_connect_http(
    mut client: TcpStream,
    stream_id: u32,
    target: &str,
    method: &str,
    forward_prefix: Vec<u8>,
    physical_if_index: Option<u32>,
    physical_if_name: &Option<String>,
    close_tx: mpsc::Sender<u32>,
    _debug: bool,
) -> Result<()> {
    crate::logs::proxy_bypass(stream_id, &target);
    let mut remote = connect_bypassing_tun(target, physical_if_index, physical_if_name).await?;

    if method == "CONNECT" {
        client.write_all(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: ostp/1.0\r\n\r\n").await?;
    }
    if !forward_prefix.is_empty() {
        remote.write_all(&forward_prefix).await?;
    }

    let _ = tokio::io::copy_bidirectional(&mut client, &mut remote).await;
    let _ = close_tx.send(stream_id).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn host_port_from_absolute_uri() {
        assert_eq!(extract_host_port("http://example.com/path", 80), "example.com:80");
        assert_eq!(extract_host_port("http://example.com:8080/x?y=1", 80), "example.com:8080");
        assert_eq!(extract_host_port("https://example.com", 443), "example.com:443");
        assert_eq!(extract_host_port("http://example.com?q=1", 80), "example.com:80");
        assert_eq!(extract_host_port("http://user:pw@example.com/x", 80), "example.com:80");
    }

    #[test]
    fn host_port_with_ipv6_literals() {
        assert_eq!(extract_host_port("http://[::1]/x", 80), "[::1]:80");
        assert_eq!(extract_host_port("http://[::1]:8080/x", 80), "[::1]:8080");
        assert_eq!(extract_host_port("http://[2001:db8::7]", 80), "[2001:db8::7]:80");
        assert_eq!(with_default_port("[::1]", 443), "[::1]:443");
        assert_eq!(with_default_port("[::1]:8443", 443), "[::1]:8443");
        assert_eq!(with_default_port("example.com", 443), "example.com:443");
        assert_eq!(with_default_port("example.com:8443", 443), "example.com:8443");
    }

    #[test]
    fn header_end_is_the_first_blank_line() {
        let req = b"POST http://h/ HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\n\r\nbody";
        let end = find_header_end(req).unwrap();
        assert_eq!(&req[end..], b"body");
        assert_eq!(find_header_end(b"GET / HTTP/1.1\r\nHost: h\r\n"), None);
        // Bytes after a CONNECT head are not lost either.
        let connect = b"CONNECT h:443 HTTP/1.1\r\n\r\n\x16\x03\x01";
        assert_eq!(&connect[find_header_end(connect).unwrap()..], b"\x16\x03\x01");
    }

    /// A connected pair: the first stream is what the proxy reads, the second the
    /// "program" writing to it.
    async fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (server, client) = tokio::join!(listener.accept(), TcpStream::connect(addr));
        (server.unwrap().0, client.unwrap())
    }

    #[tokio::test]
    async fn socks5_domain_of_255_bytes_does_not_overflow() {
        let (mut server, mut client) = pair().await;
        let domain = "a".repeat(255);
        let mut msg = vec![255u8];
        msg.extend_from_slice(domain.as_bytes());
        msg.extend_from_slice(&443u16.to_be_bytes());
        client.write_all(&msg).await.unwrap();
        let target = read_socks5_target(&mut server, 0x03).await.unwrap();
        assert_eq!(target, Some(format!("{domain}:443")));
    }

    #[tokio::test]
    async fn socks5_address_types() {
        let (mut server, mut client) = pair().await;
        client.write_all(&[1, 2, 3, 4, 0x01, 0xbb]).await.unwrap();
        assert_eq!(read_socks5_target(&mut server, 0x01).await.unwrap(), Some("1.2.3.4:443".to_string()));
        let mut v6 = vec![0u8; 15];
        v6.push(1);
        v6.extend_from_slice(&80u16.to_be_bytes());
        client.write_all(&v6).await.unwrap();
        assert_eq!(read_socks5_target(&mut server, 0x04).await.unwrap(), Some("[::1]:80".to_string()));
        assert_eq!(read_socks5_target(&mut server, 0x09).await.unwrap(), None);
    }
}
