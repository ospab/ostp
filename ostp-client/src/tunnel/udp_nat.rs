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

                        if !sessions.contains_key(&src) {
                            let (session_tx, mut session_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(1024);
                            sessions.insert(src, session_tx);

                            let proxy_addr_clone = proxy_addr.clone();
                            let tx_clone = tx.clone();
                            
                            let current = matcher.read().await.clone();
                            let mut should_bypass = false;
                            if current.match_ip(&dst.ip()) {
                                should_bypass = true;
                                if debug {
                                    tracing::info!("TUN UDP BYPASS (IP match): {} → {}", src, dst);
                                }
                            } else if let Some(name) = current
                                .excluded_process(crate::tunnel::process_lookup::Proto::Udp, src)
                                .await
                            {
                                should_bypass = true;
                                if debug {
                                    tracing::info!("TUN UDP BYPASS (process {name}): {src} → {dst}");
                                }
                            }

                            let p_if_idx = phys_if_index;
                            let p_if_name = phys_if_name.clone();

                            tokio::spawn(async move {
                                if should_bypass {
                                    if debug {
                                        tracing::info!("Starting UDP BYPASS session for {}", src);
                                    }
                                    let res = start_udp_bypass_session(src, p_if_idx, p_if_name, &mut session_rx, tx_clone).await;
                                    if res.is_err() {
                                        tracing::debug!("UDP BYPASS session for {} ended: {:?}", src, res.err());
                                    }
                                } else {
                                    tracing::debug!("Starting UDP NAT session for {}", src);
                                    let res = start_udp_session(src, proxy_addr_clone, &mut session_rx, tx_clone).await;
                                    if res.is_err() {
                                        tracing::debug!("UDP NAT session for {} ended: {:?}", src, res.err());
                                    }
                                }
                            });
                        }

                        if let Some(sender) = sessions.get(&src) {
                            match sender.try_send((payload, dst)) {
                                Err(mpsc::error::TrySendError::Closed(_)) => {
                                    sessions.remove(&src);
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

    #[cfg(target_os = "windows")]
    if let Some(idx) = phys_if_index {
        if let Err(e) = crate::tunnel::proxy::bind_socket_to_interface(&socket, client_src.is_ipv6(), idx) {
            tracing::error!("TUN UDP BYPASS failed to bind to physical interface {}: {}", idx, e);
        } else {
            // Keep debug log
        }
    } else {
        tracing::warn!("TUN UDP BYPASS has no physical interface index!");
    }
    
    #[cfg(target_os = "linux")]
    if let Some(ref name) = _phys_if_name {
        let _ = crate::tunnel::proxy::bind_socket_to_interface(&socket, name);
    }

    // A single select! loop over both directions, rather than spawning a
    // separate task for the read side, so the whole session - physical
    // socket included - is torn down the moment this function returns
    // (e.g. when session_rx closes). The previous spawned-task version left
    // that task (and its Arc<UdpSocket> clone, keeping the OS socket fd
    // alive) running forever after this function returned: nothing ever
    // cancelled it, so every bypassed UDP flow (any excluded app/IP in TUN
    // mode) leaked one socket + one task for the lifetime of the process.
    use futures::SinkExt;
    let mut buf = [0u8; 65536];
    loop {
        tokio::select! {
            outbound = session_rx.recv() => {
                match outbound {
                    Some((payload, dst)) => { socket.send_to(&payload, dst).await?; }
                    None => break,
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
    
    let timeout = std::time::Duration::from_secs(300); // 5 min idle timeout
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
                        tracing::debug!("udp_nat SENDING UDP ASSOCIATE payload len={} to relay_addr={} (original dst: {})", payload.len(), relay_addr, dst);
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
                        tracing::debug!("udp_nat RECEIVED UDP ASSOCIATE REPLY from {} for {} len={}", remote_dst, client_src, payload.len());
                        use futures::SinkExt;
                        if let Err(e) = smoltcp_tx.lock().await.send((payload, remote_dst, client_src)).await {
                            tracing::error!("udp_nat failed to inject packet into smoltcp: {}", e);
                        } else {
                            tracing::debug!("udp_nat successfully injected packet into smoltcp from {} to {}", remote_dst, client_src);
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
