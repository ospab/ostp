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
) {
    let (mut rx, tx) = udp_socket.split();
    let tx = Arc::new(Mutex::new(tx));
    
    // map from internal client src to a channel that sends (payload, external_dst)
    let mut sessions: HashMap<SocketAddr, mpsc::Sender<(Vec<u8>, SocketAddr)>> = HashMap::new();

    while let Some((payload, src, dst)) = rx.next().await {
        if payload.is_empty() { continue; }

        if !sessions.contains_key(&src) {
            let (session_tx, mut session_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(100000);
            sessions.insert(src, session_tx);

            let proxy_addr_clone = proxy_addr.clone();
            let tx_clone = tx.clone();
            
            tokio::spawn(async move {
                if debug { tracing::info!("Starting UDP NAT session for {}", src); }
                let res = start_udp_session(src, proxy_addr_clone, &mut session_rx, tx_clone).await;
                if debug && res.is_err() {
                    tracing::info!("UDP NAT session for {} ended: {:?}", src, res.err());
                }
            });
        }

        if let Some(sender) = sessions.get(&src) {
            if sender.send((payload, dst)).await.is_err() {
                sessions.remove(&src);
            }
        }
    }
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

    let udp = UdpSocket::bind("127.0.0.1:0").await?;
    
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
                        udp.send_to(&packet, relay_addr).await?;
                    }
                    Ok(None) => break,
                    Err(_) => break, // timeout
                }
            }
            res = udp.recv_from(&mut buf) => {
                let (len, _peer) = res?;
                if len < 10 { continue; } // At least 10 bytes for SOCKS5 header
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
                    _ => continue, // Domain name not supported for incoming packets in typical UDP associate
                };
                let payload = buf[header_len..len].to_vec();
                use futures::SinkExt;
                let _ = smoltcp_tx.lock().await.send((payload, remote_dst, client_src)).await;
            }
            // If TCP drops, UDP association is over
            res = tcp.read(&mut tcp_buf) => {
                let n = res?;
                if n == 0 { break; }
            }
        }
    }
    
    Ok(())
}
