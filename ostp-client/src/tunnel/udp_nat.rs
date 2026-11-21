use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use futures::StreamExt;

pub async fn run_udp_nat(
    udp_socket: netstack_smoltcp::UdpSocket,
    proxy_addr: String,
    debug: bool,
    matcher: std::sync::Arc<tokio::sync::RwLock<crate::tunnel::exclusion::ExclusionMatcher>>,
    phys_if_index: Option<u32>,
    phys_if_name: Option<String>,
) {
    let (mut rx, tx) = udp_socket.split();
    let tx = Arc::new(Mutex::new(tx));
    
    // map from internal client src to a channel that sends (payload, external_dst)
    let mut sessions: HashMap<SocketAddr, mpsc::Sender<(Vec<u8>, SocketAddr)>> = HashMap::new();

    let mut cleanup_tick = tokio::time::interval(std::time::Duration::from_secs(60));

    loop {
        tokio::select! {
            packet = rx.next() => {
                match packet {
                    Some((payload, src, dst)) => {
                        if payload.is_empty() { continue; }

                        // Deliver the packet; if the session ended meanwhile (idle
                        // timeout), start a new one and deliver to it instead of
                        // dropping the first packet of the next burst.
                        let mut pending = Some((payload, dst));
                        for _ in 0..2 {
                            let Some(item) = pending.take() else { break };
                            if !sessions.contains_key(&src) {
                                let session_tx = spawn_session(
                                    src, dst, &proxy_addr, &tx, &matcher, debug,
                                    phys_if_index, &phys_if_name,
                                ).await;
                                sessions.insert(src, session_tx);
                            }
                            let Some(sender) = sessions.get(&src) else { break };
                            match sender.try_send(item) {
                                Err(mpsc::error::TrySendError::Closed(item)) => {
                                    sessions.remove(&src);
                                    pending = Some(item);
                                }
                                Err(mpsc::error::TrySendError::Full(_)) => {
                                    // Drop packet to avoid blocking the TUN interface loop
                                }
                                Ok(_) => {}
                            }
                        }
                    }
                    None => break,
                }
            }
            _ = cleanup_tick.tick() => {
                sessions.retain(|_, sender| !sender.is_closed());
            }
        }
    }
}

/// Starts a NAT session task for `src` (direct bypass or through the local proxy,
/// decided by the exclusion matcher) and returns the sender feeding it.
#[allow(clippy::too_many_arguments)]
async fn spawn_session(
    src: SocketAddr,
    dst: SocketAddr,
    proxy_addr: &str,
    tx: &Arc<Mutex<netstack_smoltcp::udp::WriteHalf>>,
    matcher: &Arc<tokio::sync::RwLock<crate::tunnel::exclusion::ExclusionMatcher>>,
    debug: bool,
    phys_if_index: Option<u32>,
    phys_if_name: &Option<String>,
) -> mpsc::Sender<(Vec<u8>, SocketAddr)> {
    let (session_tx, mut session_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(1024);
    let proxy_addr_clone = proxy_addr.to_string();
    let tx_clone = tx.clone();

    let current = matcher.read().await.clone();
    let mut should_bypass = false;
    if current.match_ip(&dst.ip()) {
        should_bypass = true;
        if debug {
            crate::logs::udp_nat_bypass_ip(src, dst);
        }
    } else if let Some(name) = current
        .excluded_process(crate::tunnel::process_lookup::Proto::Udp, src)
        .await
    {
        should_bypass = true;
        if debug {
            crate::logs::udp_nat_bypass_process(&name, src, dst);
        }
    }

    let p_if_name = phys_if_name.clone();
    tokio::spawn(async move {
        if should_bypass {
            if debug {
                tracing::info!("Starting UDP BYPASS session for {}", src);
            }
            let res = start_udp_bypass_session(src, phys_if_index, p_if_name, &mut session_rx, tx_clone).await;
            if let Err(e) = res {
                crate::logs::udp_session_ended("UDP BYPASS", src, &format!("{:?}", e));
            }
        } else {
            tracing::debug!("Starting UDP NAT session for {}", src);
            let res = start_udp_session(src, proxy_addr_clone, &mut session_rx, tx_clone).await;
            if let Err(e) = res {
                crate::logs::udp_session_ended("UDP NAT", src, &format!("{:?}", e));
            }
        }
    });
    session_tx
}

/// Idle time after which a UDP session (bypass or tunnel) is torn down.
const UDP_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

async fn start_udp_bypass_session(
    client_src: SocketAddr,
    // Windows binds bypass sockets by interface index, Linux by name.
    #[cfg_attr(not(target_os = "windows"), allow(unused_variables))] phys_if_index: Option<u32>,
    _phys_if_name: Option<String>,
    session_rx: &mut mpsc::Receiver<(Vec<u8>, SocketAddr)>,
    smoltcp_tx: Arc<Mutex<netstack_smoltcp::udp::WriteHalf>>,
) -> anyhow::Result<()> {
    let socket = match client_src {
        SocketAddr::V4(_) => UdpSocket::bind("0.0.0.0:0").await?,
        SocketAddr::V6(_) => UdpSocket::bind("[::]:0").await?,
    };

    // The current interface (ostp_tun moves it on a network change).
    #[cfg(target_os = "windows")]
    if let Some(idx) = ostp_tun::physical_if_index().or(phys_if_index) {
        if let Err(e) = crate::tunnel::proxy::bind_socket_to_interface(&socket, client_src.is_ipv6(), idx) {
            tracing::error!("TUN UDP BYPASS failed to bind to physical interface {}: {}", idx, e);
        } else {
            // Keep debug log
        }
    } else {
        tracing::warn!("TUN UDP BYPASS has no physical interface index!");
    }
    
    #[cfg(target_os = "linux")]
    if let Some(ref name) = ostp_tun::physical_if_name().or_else(|| _phys_if_name.clone()) {
        let _ = crate::tunnel::proxy::bind_socket_to_interface(&socket, name);
    }

    // A single select! loop over both directions, so the whole session - physical
    // socket included - is torn down the moment this function returns: when
    // session_rx closes or after UDP_IDLE_TIMEOUT without outbound packets
    // (the timer restarts on every loop iteration, i.e. on any activity).
    use futures::SinkExt;
    let mut buf = [0u8; 65536];
    loop {
        tokio::select! {
            outbound = tokio::time::timeout(UDP_IDLE_TIMEOUT, session_rx.recv()) => {
                match outbound {
                    Ok(Some((payload, dst))) => { socket.send_to(&payload, dst).await?; }
                    // Channel closed or idle: dropping the socket ends the flow.
                    Ok(None) | Err(_) => break,
                }
            }
            inbound = socket.recv_from(&mut buf) => {
                match inbound {
                    Ok((n, peer)) => {
                        let mut lock = smoltcp_tx.lock().await;
                        let _ = lock.send((buf[..n].to_vec(), peer, client_src)).await;
                    }
                    Err(_) => break,
                }
            }
        }
    }

    Ok(())
}


async fn start_udp_session(
    client_src: SocketAddr,
    proxy_addr: String,
    session_rx: &mut mpsc::Receiver<(Vec<u8>, SocketAddr)>,
    smoltcp_tx: Arc<Mutex<netstack_smoltcp::udp::WriteHalf>>,
) -> anyhow::Result<()> {
    // 1. TCP Connect to SOCKS5 proxy
    let mut tcp = TcpStream::connect(&proxy_addr).await?;
    
    // Auth
    tcp.write_all(&[5, 1, 0]).await?;
    let mut buf = [0u8; 2];
    tcp.read_exact(&mut buf).await?;
    if buf[0] != 5 || buf[1] != 0 {
        return Err(anyhow::anyhow!("socks5 auth rejected"));
    }

    // UDP ASSOCIATE to 0.0.0.0:0
    tcp.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    let mut rep_hdr = [0u8; 4];
    tcp.read_exact(&mut rep_hdr).await?;
    if rep_hdr[1] != 0 {
        return Err(anyhow::anyhow!("socks5 udp associate rejected"));
    }

    let mut relay_addr = match rep_hdr[3] {
        1 => {
            let mut addr_buf = [0u8; 6];
            tcp.read_exact(&mut addr_buf).await?;
            let ip = std::net::Ipv4Addr::new(addr_buf[0], addr_buf[1], addr_buf[2], addr_buf[3]);
            let port = u16::from_be_bytes([addr_buf[4], addr_buf[5]]);
            SocketAddr::new(std::net::IpAddr::V4(ip), port)
        }
        4 => {
            let mut addr_buf = [0u8; 18];
            tcp.read_exact(&mut addr_buf).await?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&addr_buf[0..16]);
            let ip = std::net::Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([addr_buf[16], addr_buf[17]]);
            SocketAddr::new(std::net::IpAddr::V6(ip), port)
        }
        _ => return Err(anyhow::anyhow!("unsupported ATYP in UDP ASSOCIATE response")),
    };
    
    // If proxy returned 0.0.0.0 or ::, use the proxy's IP
    if relay_addr.ip().is_unspecified() {
        if let Ok(proxy_sock) = proxy_addr.parse::<SocketAddr>() {
            relay_addr.set_ip(proxy_sock.ip());
        }
    }

    // Local SOCKS5 proxy always returns 127.0.0.1 (IPv4), so always bind IPv4
    let udp = UdpSocket::bind("127.0.0.1:0").await?;

    // CRITICAL for Android: protect this UDP socket so it goes out via the
    // real physical interface, not back into the TUN (which would cause an
    // infinite routing loop for DNS and all other UDP traffic).
    #[cfg(target_os = "android")]
    {
        use std::os::unix::io::AsRawFd;
        crate::bridge::protect_socket(udp.as_raw_fd());
    }
    
    let mut buf = vec![0u8; 65536];
    
    let timeout = UDP_IDLE_TIMEOUT;
    let mut tcp_buf = [0u8; 1];

    loop {
        tokio::select! {
            res = tokio::time::timeout(timeout, session_rx.recv()) => {
                match res {
                    Ok(Some((payload, dst))) => {
                        let mut packet = vec![0u8; 3]; // RSV, FRAG
                        match dst.ip() {
                            std::net::IpAddr::V4(v4) => { packet.push(1); packet.extend_from_slice(&v4.octets()); }
                            std::net::IpAddr::V6(v6) => { packet.push(4); packet.extend_from_slice(&v6.octets()); }
                        }
                        packet.extend_from_slice(&dst.port().to_be_bytes());
                        packet.extend_from_slice(&payload);
                        crate::logs::udp_nat_send(payload.len(), relay_addr, dst);
                        let _ = udp.send_to(&packet, relay_addr).await;
                    }
                    Ok(None) => break,
                    Err(_) => break, // timeout
                }
            }
            res = udp.recv_from(&mut buf) => {
                match res {
                    Err(e) => {
                        tracing::debug!("udp_nat recv_from error: {}", e);
                        continue; // transient error, don't kill the session
                    }
                    Ok((len, _peer)) => {
                        if len < 4 { continue; }
                        let frag = buf[2];
                        if frag != 0 { continue; } // fragment not supported
                        let atyp = buf[3];
                        let (header_len, remote_dst) = match atyp {
                            1 => {
                                if len < 10 { continue; }
                                let ip = std::net::Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
                                let port = u16::from_be_bytes([buf[8], buf[9]]);
                                (10, SocketAddr::new(std::net::IpAddr::V4(ip), port))
                            }
                            4 => {
                                if len < 22 { continue; }
                                let mut octets = [0u8; 16];
                                octets.copy_from_slice(&buf[4..20]);
                                let ip = std::net::Ipv6Addr::from(octets);
                                let port = u16::from_be_bytes([buf[20], buf[21]]);
                                (22, SocketAddr::new(std::net::IpAddr::V6(ip), port))
                            }
                            _ => continue,
                        };
                        let payload = buf[header_len..len].to_vec();
                        crate::logs::udp_nat_reply(remote_dst, client_src, payload.len());
                        use futures::SinkExt;
                        if let Err(e) = smoltcp_tx.lock().await.send((payload, remote_dst, client_src)).await {
                            tracing::error!("udp_nat failed to inject packet into smoltcp: {}", e);
                        } else {
                            crate::logs::udp_nat_injected(remote_dst, client_src);
                        }
                    }
                }
            }
            // If TCP drops, UDP association is over
            res = tcp.read(&mut tcp_buf) => {
                match res {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        }
    }
    
    Ok(())
}
