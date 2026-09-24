//! The server's DNS: the filtering resolver from `ostp-dns`, answering the
//! port-53 queries clients send through the tunnel. It is never reachable
//! from the internet.

pub use ostp_dns::{Dns as DnsServer, DnsSettings as DnsConfig};

/// DoH and list downloads go through the outbound proxy when it is on.
pub fn proxy_url(outbound: Option<&crate::outbound::OutboundConfig>) -> Option<String> {
    let o = outbound.filter(|o| o.enabled)?;
    let auth = if o.username.is_empty() { String::new() } else { format!("{}:{}@", o.username, o.password) };
    match o.protocol.as_str() {
        "socks5" => Some(format!("socks5h://{auth}{}:{}", o.address, o.port)),
        "http" => Some(format!("http://{auth}{}:{}", o.address, o.port)),
        _ => None,
    }
}

/// Serves DNS over TCP on a loopback port with the resolver; the relay sends
/// clients' TCP connections to port 53 here, so they are filtered too.
pub async fn spawn_tcp_listener(dns: std::sync::Arc<DnsServer>) -> std::io::Result<std::net::SocketAddr> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            let Ok((mut s, peer)) = listener.accept().await else { continue };
            let dns = dns.clone();
            tokio::spawn(async move {
                loop {
                    let mut len = [0u8; 2];
                    if tokio::time::timeout(std::time::Duration::from_secs(30), s.read_exact(&mut len)).await.is_err()
                        || len == [0, 0]
                    {
                        break;
                    }
                    let mut q = vec![0u8; u16::from_be_bytes(len) as usize];
                    if s.read_exact(&mut q).await.is_err() {
                        break;
                    }
                    let Some(a) = dns.handle(&q, peer.ip()).await else { break };
                    let mut out = Vec::with_capacity(a.len() + 2);
                    out.extend_from_slice(&(a.len() as u16).to_be_bytes());
                    out.extend_from_slice(&a);
                    if s.write_all(&out).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    Ok(addr)
}
