use std::collections::HashMap;
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
fn bind_socket_to_interface(socket: &impl AsRawSocket, is_ipv6: bool, if_index: u32) -> std::io::Result<()> {
    let s = socket.as_raw_socket() as usize;
    if is_ipv6 {
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
fn bind_socket_to_interface(socket: &impl AsRawFd, if_name: &str) -> std::io::Result<()> {
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

fn get_windows_physical_if_index() -> Option<u32> {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        let output = std::process::Command::new("powershell")
            .creation_flags(CREATE_NO_WINDOW)
            .args([
                "-NoProfile",
                "-Command",
                "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Where-Object { $_.InterfaceAlias -notmatch 'ostp' -and $_.InterfaceAlias -notmatch 'tun' -and $_.InterfaceAlias -notmatch 'wintun' } | Sort-Object RouteMetric | Select-Object -ExpandProperty InterfaceIndex -First 1"
            ])
            .output()
            .ok()?;
        if output.status.success() {
            let s = String::from_utf8_lossy(&output.stdout);
            if let Ok(index) = s.trim().parse::<u32>() {
                return Some(index);
            }
        }
    }
    None
}

fn get_linux_physical_if_name() -> Option<String> {
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

pub async fn run_local_socks5_proxy(
    cfg: LocalProxyConfig,
    ostp: OstpConfig,
    exclusions: ExclusionConfig,
    debug: bool,
    mut shutdown: watch::Receiver<bool>,
    proxy_events_tx: mpsc::Sender<ProxyEvent>,
    mut client_msgs_rx: mpsc::UnboundedReceiver<(u16, ProxyToClientMsg)>,
) -> Result<()> {
    let connect_timeout = Duration::from_millis(cfg.connect_timeout_ms.max(1));
    let listener = TcpListener::bind(&cfg.bind_addr)
        .await
        .with_context(|| format!("failed to bind local HTTP/SOCKS5 proxy at {}", cfg.bind_addr))?;

    if debug {
        tracing::info!("local HTTP/SOCKS5 proxy listening at {}", cfg.bind_addr);
        tracing::info!("Windows system proxy: set HTTP proxy to {}. tun2socks: SOCKS5 on same address.", cfg.bind_addr);
    }

    let physical_if_index = tokio::task::spawn_blocking(get_windows_physical_if_index).await.unwrap_or(None);
    let physical_if_name = tokio::task::spawn_blocking(get_linux_physical_if_name).await.unwrap_or(None);

    if physical_if_index.is_some() {
        tracing::info!("Local proxy physical interface index: {:?}", physical_if_index);
    }
    if physical_if_name.is_some() {
        tracing::info!("Local proxy physical interface name: {:?}", physical_if_name);
    }

    let matcher = ExclusionMatcher::new(&exclusions, physical_if_index, physical_if_name.clone());
    let (connect_tx, mut connect_rx) = mpsc::channel(128);
    let max_chunk = ostp.mtu.saturating_sub(150).max(512);

    let mut next_stream_id: u16 = 1;
    let mut active_streams: HashMap<u16, mpsc::UnboundedSender<ProxyToClientMsg>> = HashMap::new();

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let (socket, _) = accepted?;
                let stream_id = next_stream_id;
                // Advance, skipping zero and any stream_id still in active_streams
                loop {
                    next_stream_id = next_stream_id.wrapping_add(1);
                    if next_stream_id == 0 { next_stream_id = 1; }
                    if !active_streams.contains_key(&next_stream_id) { break; }
                }

                let (tx, rx) = mpsc::unbounded_channel();
                active_streams.insert(stream_id, tx);

                let event_tx = proxy_events_tx.clone();
                let c_tx = connect_tx.clone();
                let matcher_clone = matcher.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_proxy_client(
                        socket,
                        stream_id,
                        event_tx,
                        rx,
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
                        if debug {
                            tracing::info!("Resetting all active proxy streams on reconnect");
                        }
                        for (_, tx) in active_streams.drain() {
                            let _ = tx.send(ProxyToClientMsg::Close);
                        }
                    }
                } else if let Some(tx) = active_streams.get(&stream_id) {
                    if tx.send(msg).is_err() {
                        active_streams.remove(&stream_id);
                    }
                }
            }
            Some(stream_id) = connect_rx.recv() => {
                active_streams.remove(&stream_id);
            }
        }
    }

    Ok(())
}

/// Extracts `host:port` from an HTTP absolute-URI like `http://example.com/path` or `https://example.com`.
/// Falls back to the raw target if already in `host:port` form.
fn extract_host_port(uri: &str, default_port: u16) -> String {
    let without_scheme = if let Some(rest) = uri.strip_prefix("https://") {
        rest
    } else if let Some(rest) = uri.strip_prefix("http://") {
        rest
    } else {
        uri
    };
    // Trim path/query fragment
    let host_part = without_scheme.split('/').next().unwrap_or(without_scheme);
    if host_part.contains(':') {
        host_part.to_string()
    } else {
        format!("{}:{}", host_part, default_port)
    }
}

struct StreamGuard {
    stream_id: u16,
    close_tx: mpsc::Sender<u16>,
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
    stream_id: u16,
    event_tx: mpsc::Sender<ProxyEvent>,
    mut rx: mpsc::UnboundedReceiver<ProxyToClientMsg>,
    close_tx: mpsc::Sender<u16>,
    debug: bool,
    matcher: ExclusionMatcher,
    connect_timeout: Duration,
) -> Result<()> {
    let client_udp_addr = Arc::new(std::sync::Mutex::new(None));
    let mut buf = vec![0u8; 65536];
    
    let udp_socket = Arc::new(udp_socket);
    let sock_rx = udp_socket.clone();
    let sock_tx = udp_socket;

    let mut direct_udp_v4: Option<Arc<UdpSocket>> = None;
    let mut direct_udp_v6: Option<Arc<UdpSocket>> = None;

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

                // Check if target should bypass the tunnel
                if matcher.should_bypass(&target, connect_timeout).await {
                    if debug {
                        tracing::info!("proxy UDP BYPASS target={}", target);
                    }
                    // Resolve target to find if it is IPv4 or IPv6
                    if let Ok(resolved_addrs) = tokio::net::lookup_host(&target).await {
                        if let Some(target_addr) = resolved_addrs.into_iter().next() {
                            let is_ipv6 = target_addr.is_ipv6();
                            let direct_socket = if is_ipv6 {
                                if direct_udp_v6.is_none() {
                                    match create_udp_socket_bypassing_tun(true, matcher.physical_if_index, &matcher.physical_if_name).await {
                                        Ok(s) => {
                                            let s_arc = Arc::new(s);
                                            spawn_direct_udp_reader(s_arc.clone(), sock_tx.clone(), client_udp_addr.clone(), debug);
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
                                            spawn_direct_udp_reader(s_arc.clone(), sock_tx.clone(), client_udp_addr.clone(), debug);
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
                                    if debug {
                                        tracing::warn!("failed to send bypass UDP packet to {}: {}", target_addr, e);
                                    }
                                }
                            }
                        }
                    }
                } else {
                    tracing::debug!("proxy.rs forwarding UDP DATA to server for target={} payload len={}", target, payload.len());
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
                            tracing::debug!("proxy.rs forwarding UDP REPLY to client_addr={} from server for target={} payload len={}", client_addr, target, data.len());
                            let _ = sock_tx.send_to(&packet, client_addr).await;
                        } else {
                            tracing::error!("proxy.rs failed to parse target string as SocketAddr: {}", target);
                        }
                    }
                    Some(ProxyToClientMsg::Close) | Some(ProxyToClientMsg::Error(_)) | None => break,
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
    debug: bool,
) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            match direct_socket.recv_from(&mut buf).await {
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
                            if debug {
                                tracing::warn!("failed to send direct UDP response to client: {e}");
                            }
                        }
                    }
                }
                Err(e) => {
                    if debug {
                        tracing::debug!("direct UDP socket read loop exiting: {e}");
                    }
                    break;
                }
            }
        }
    });
}

async fn handle_proxy_client(
    mut client: TcpStream,
    stream_id: u16,
    event_tx: mpsc::Sender<ProxyEvent>,
    mut rx: mpsc::UnboundedReceiver<ProxyToClientMsg>,
    close_tx: mpsc::Sender<u16>,
    connect_timeout: Duration,
    debug: bool,
    matcher: ExclusionMatcher,
    max_chunk: usize,
) -> Result<()> {
    let _guard = StreamGuard { stream_id, close_tx: close_tx.clone() };

    // Peek the first byte to distinguish SOCKS5 (0x05) from HTTP (any printable ASCII)
    let mut first_byte = [0_u8; 1];
    client.read_exact(&mut first_byte).await?;

    let target: String;
    let is_socks5 = first_byte[0] == 0x05;

    if is_socks5 {
        // ── SOCKS5 Handshake ──────────────────────────────────────────
        let mut second_byte = [0_u8; 1];
        client.read_exact(&mut second_byte).await?;
        let nmethods = second_byte[0] as usize;
        if nmethods > 0 {
            let mut methods_buf = vec![0_u8; nmethods];
            client.read_exact(&mut methods_buf).await?;
        }
        // Reply: version=5, NO AUTHENTICATION
        client.write_all(&[0x05, 0x00]).await?;

        // ── SOCKS5 Request ────────────────────────────────────────────
        let mut req = [0_u8; 4];
        client.read_exact(&mut req).await?;
        if req[0] != 0x05 {
            return Err(anyhow!("SOCKS5 request version mismatch"));
        }
        
        let is_udp = req[1] == 0x03;
        if req[1] != 0x01 && !is_udp {
            // Not CONNECT and Not UDP ASSOCIATE — send COMMAND NOT SUPPORTED
            client.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            return Err(anyhow!("unsupported SOCKS5 command {}", req[1]));
        }

        let mut addr_buf = [0_u8; 256];
        target = match req[3] {
            0x01 => {
                // IPv4: 4 bytes address + 2 bytes port
                client.read_exact(&mut addr_buf[0..6]).await?;
                let ip = std::net::Ipv4Addr::new(addr_buf[0], addr_buf[1], addr_buf[2], addr_buf[3]);
                let port = u16::from_be_bytes([addr_buf[4], addr_buf[5]]);
                format!("{}:{}", ip, port)
            }
            0x03 => {
                // Domain: 1 byte length, then domain, then 2 bytes port
                client.read_exact(&mut addr_buf[0..1]).await?;
                let domain_len = addr_buf[0] as usize;
                client.read_exact(&mut addr_buf[0..domain_len + 2]).await?;
                let domain = String::from_utf8_lossy(&addr_buf[0..domain_len]);
                let port = u16::from_be_bytes([addr_buf[domain_len], addr_buf[domain_len + 1]]);
                format!("{}:{}", domain, port)
            }
            0x04 => {
                // IPv6: 16 bytes + 2 bytes port
                client.read_exact(&mut addr_buf[0..18]).await?;
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&addr_buf[0..16]);
                let ip = std::net::Ipv6Addr::from(octets);
                let port = u16::from_be_bytes([addr_buf[16], addr_buf[17]]);
                format!("[{}]:{}", ip, port)
            }
            atyp => {
                client.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
                return Err(anyhow!("unsupported SOCKS5 address type: {}", atyp));
            }
        };

        if is_udp {
            if debug { tracing::info!("proxy UDP ASSOCIATE stream_id={stream_id}"); }
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

        if debug {
            tracing::info!("proxy CONNECT stream_id={stream_id} target={target}");
        }
        if matcher.should_bypass(&target, connect_timeout).await {
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
            Ok(Some(ProxyToClientMsg::ConnectOk)) => {
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
        header_bytes.push(first_byte[0]);
        let mut chunk = [0_u8; 512];
        loop {
            let n = client.read(&mut chunk).await?;
            if n == 0 {
                return Err(anyhow!("connection closed during HTTP header read"));
            }
            header_bytes.extend_from_slice(&chunk[..n]);
            if header_bytes.len() >= 4 {
                let tail = &header_bytes[header_bytes.len().saturating_sub(4)..];
                if tail.ends_with(b"\r\n\r\n") {
                    break;
                }
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
            if raw_uri.contains(':') {
                raw_uri.to_string()
            } else {
                format!("{}:443", raw_uri)
            }
        } else {
            // Plain HTTP: absolute URI like "GET http://example.com/path HTTP/1.1"
            let default_port = if raw_uri.starts_with("https://") { 443u16 } else { 80u16 };
            extract_host_port(raw_uri, default_port)
        };

        if debug {
            tracing::info!("proxy CONNECT stream_id={stream_id} target={target}");
        }
        if matcher.should_bypass(&target, connect_timeout).await {
            return direct_connect_http(
                client,
                stream_id,
                &target,
                method.as_str(),
                header_bytes,
                matcher.physical_if_index,
                &matcher.physical_if_name,
                close_tx,
                debug,
            ).await;
        }
        event_tx.send(ProxyEvent::NewStream { stream_id, target: target.clone() }).await?;

        match timeout(connect_timeout, rx.recv()).await {
            Ok(Some(ProxyToClientMsg::ConnectOk)) => {
                if method == "CONNECT" {
                    // For CONNECT, tell client the tunnel is ready
                    client.write_all(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: ostp/1.0\r\n\r\n").await?;
                } else {
                    // For plain HTTP (GET/POST), we MUST forward the request headers we consumed
                    // to the server over the newly established tunnel.
                    event_tx.send(ProxyEvent::Data {
                        stream_id,
                        payload: bytes::Bytes::copy_from_slice(&header_bytes),
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
    loop {
        tokio::select! {
            read_res = client.read(&mut tcp_buf) => {
                match read_res {
                    Ok(0) => {
                        let _ = event_tx.send(ProxyEvent::Close { stream_id }).await;
                        if debug {
                            tracing::info!("proxy CLOSE stream_id={stream_id}");
                        }
                        break;
                    }
                    Ok(n) => {
                        let mut offset = 0;
                        while offset < n {
                            let end = (offset + max_chunk).min(n);
                            let _ = event_tx.send(ProxyEvent::Data {
                                stream_id,
                                payload: bytes::Bytes::copy_from_slice(&tcp_buf[offset..end]),
                            }).await;
                            offset = end;
                        }
                    }
                    Err(_) => {
                        let _ = event_tx.send(ProxyEvent::Close { stream_id }).await;
                        if debug {
                            tracing::info!("proxy CLOSE stream_id={stream_id}");
                        }
                        break;
                    }
                }
            }
            msg = rx.recv() => {
                match msg {
                    Some(ProxyToClientMsg::Data(data)) => {
                        if client.write_all(&data).await.is_err() {
                            let _ = event_tx.send(ProxyEvent::Close { stream_id }).await;
                            break;
                        }
                    }
                    Some(ProxyToClientMsg::Close) | Some(ProxyToClientMsg::Error(_)) | None => {
                        break;
                    }
                    Some(ProxyToClientMsg::ConnectOk) | Some(ProxyToClientMsg::UdpData(_, _)) => {} // ignored after connect phase
                }
            }
        }
    }

    let _ = close_tx.send(stream_id).await;
    Ok(())
}

#[derive(Clone)]
struct ExclusionMatcher {
    domain_suffix: Vec<String>,
    cidrs: Vec<Cidr>,
    physical_if_index: Option<u32>,
    physical_if_name: Option<String>,
}

impl ExclusionMatcher {
    fn new(
        exclusions: &ExclusionConfig,
        physical_if_index: Option<u32>,
        physical_if_name: Option<String>,
    ) -> Self {
        let mut cidrs = Vec::new();
        for ip in &exclusions.ips {
            if let Some(cidr) = parse_cidr(ip) {
                cidrs.push(cidr);
            }
        }

        Self {
            domain_suffix: exclusions
                .domains
                .iter()
                .map(|d| d.trim().trim_start_matches('.').to_lowercase())
                .filter(|d| !d.is_empty())
                .collect(),
            cidrs,
            physical_if_index,
            physical_if_name,
        }
    }

    async fn should_bypass(&self, target: &str, timeout_value: Duration) -> bool {
        let (host, port) = match split_host_port(target) {
            Some(v) => v,
            None => return false,
        };

        if self.match_domain(&host) {
            return true;
        }

        if self.cidrs.is_empty() {
            return false;
        }

        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            return self.match_ip(&ip);
        }

        let lookup_target = (host.clone(), port);
        match timeout(timeout_value, tokio::net::lookup_host(lookup_target)).await {
            Ok(Ok(addrs)) => addrs.into_iter().any(|addr| self.match_ip(&addr.ip())),
            _ => false,
        }
    }

    fn match_domain(&self, host: &str) -> bool {
        if self.domain_suffix.is_empty() {
            return false;
        }
        let host = host.trim_end_matches('.').to_lowercase();
        self.domain_suffix.iter().any(|suffix| {
            host == *suffix || host.ends_with(&format!(".{suffix}"))
        })
    }

    fn match_ip(&self, ip: &std::net::IpAddr) -> bool {
        self.cidrs.iter().any(|cidr| cidr.contains(ip))
    }
}

#[derive(Clone)]
enum Cidr {
    V4(u32, u8),
    V6(u128, u8),
}

impl Cidr {
    fn contains(&self, ip: &std::net::IpAddr) -> bool {
        match (self, ip) {
            (Cidr::V4(net, bits), std::net::IpAddr::V4(addr)) => {
                let mask = if *bits == 0 { 0 } else { u32::MAX << (32 - bits) };
                let ip = u32::from_be_bytes(addr.octets());
                (ip & mask) == (*net & mask)
            }
            (Cidr::V6(net, bits), std::net::IpAddr::V6(addr)) => {
                let mask = if *bits == 0 { 0 } else { u128::MAX << (128 - bits) };
                let ip = u128::from_be_bytes(addr.octets());
                (ip & mask) == (*net & mask)
            }
            _ => false,
        }
    }
}

fn parse_cidr(value: &str) -> Option<Cidr> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    if let Some((addr_str, bits_str)) = value.split_once('/') {
        let bits: u8 = bits_str.parse().ok()?;
        if let Ok(addr) = addr_str.parse::<std::net::IpAddr>() {
            return match addr {
                std::net::IpAddr::V4(v4) => Some(Cidr::V4(u32::from_be_bytes(v4.octets()), bits.min(32))),
                std::net::IpAddr::V6(v6) => Some(Cidr::V6(u128::from_be_bytes(v6.octets()), bits.min(128))),
            };
        }
    }

    if let Ok(addr) = value.parse::<std::net::IpAddr>() {
        return match addr {
            std::net::IpAddr::V4(v4) => Some(Cidr::V4(u32::from_be_bytes(v4.octets()), 32)),
            std::net::IpAddr::V6(v6) => Some(Cidr::V6(u128::from_be_bytes(v6.octets()), 128)),
        };
    }

    None
}

fn split_host_port(target: &str) -> Option<(String, u16)> {
    if let Some((host, port)) = target.rsplit_once(':') {
        if host.starts_with('[') && host.ends_with(']') {
            let host = host.trim_start_matches('[').trim_end_matches(']').to_string();
            let port = port.parse().ok()?;
            return Some((host, port));
        }
        if host.contains(':') {
            return None;
        }
        let port = port.parse().ok()?;
        return Some((host.to_string(), port));
    }
    None
}

async fn direct_connect_socks5(
    mut client: TcpStream,
    stream_id: u16,
    target: &str,
    physical_if_index: Option<u32>,
    physical_if_name: &Option<String>,
    close_tx: mpsc::Sender<u16>,
    debug: bool,
) -> Result<()> {
    if debug {
        tracing::info!("proxy BYPASS stream_id={stream_id} target={target}");
    }
    let mut remote = connect_bypassing_tun(target, physical_if_index, physical_if_name).await?;

    client.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
    let _ = tokio::io::copy_bidirectional(&mut client, &mut remote).await;
    let _ = close_tx.send(stream_id).await;
    Ok(())
}

async fn direct_connect_http(
    mut client: TcpStream,
    stream_id: u16,
    target: &str,
    method: &str,
    header_bytes: Vec<u8>,
    physical_if_index: Option<u32>,
    physical_if_name: &Option<String>,
    close_tx: mpsc::Sender<u16>,
    debug: bool,
) -> Result<()> {
    if debug {
        tracing::info!("proxy BYPASS stream_id={stream_id} target={target}");
    }
    let mut remote = connect_bypassing_tun(target, physical_if_index, physical_if_name).await?;

    if method == "CONNECT" {
        client.write_all(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: ostp/1.0\r\n\r\n").await?;
    } else {
        remote.write_all(&header_bytes).await?;
    }

    let _ = tokio::io::copy_bidirectional(&mut client, &mut remote).await;
    let _ = close_tx.send(stream_id).await;
    Ok(())
}
