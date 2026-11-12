//! Reaching an upstream resolver through the server's outbound proxy.
//!
//! With the proxy on, the resolver's plain UDP, TCP and DoT upstreams must
//! not leave the server directly (that would show the server's own address
//! and defeat a proxy such as WARP). They are carried as DNS over TCP through
//! the proxy (SOCKS5 `CONNECT`, or HTTP `CONNECT`); a UDP upstream is asked
//! over TCP port 53 of the same address. DoH goes through reqwest's proxy.

use anyhow::{anyhow, bail, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    Socks5,
    Http,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proxy {
    pub kind: Kind,
    /// `host:port` of the proxy itself.
    pub addr: String,
    pub username: String,
    pub password: String,
}

impl Proxy {
    /// `socks5://`, `socks5h://` or `http://` with optional `user:pass@`.
    pub fn parse(url: &str) -> Result<Self> {
        let (kind, rest) = if let Some(r) = url.strip_prefix("socks5h://").or_else(|| url.strip_prefix("socks5://")) {
            (Kind::Socks5, r)
        } else if let Some(r) = url.strip_prefix("http://") {
            (Kind::Http, r)
        } else {
            bail!("unsupported proxy scheme in \"{}\"", url.split("://").next().unwrap_or(url));
        };
        let rest = rest.trim_end_matches('/');
        let (auth, addr) = match rest.rsplit_once('@') {
            Some((a, h)) => (a, h),
            None => ("", rest),
        };
        let (username, password) = auth.split_once(':').map(|(u, p)| (u.to_string(), p.to_string())).unwrap_or((auth.to_string(), String::new()));
        if addr.is_empty() || !addr.contains(':') {
            bail!("the proxy address needs host:port");
        }
        Ok(Self { kind, addr: addr.to_string(), username, password })
    }

    /// A TCP stream to `host:port` through the proxy; the name is sent to the
    /// proxy as a name, never resolved here.
    pub async fn connect(&self, host: &str, port: u16) -> Result<TcpStream> {
        if host.is_empty() || host.len() > 255 || host.bytes().any(|b| b <= b' ' || b == 0x7f) {
            bail!("invalid host for the proxy");
        }
        let mut s = TcpStream::connect(self.addr.as_str()).await.map_err(|e| anyhow!("cannot reach the proxy {}: {e}", self.addr))?;
        match self.kind {
            Kind::Socks5 => {
                if self.username.is_empty() {
                    s.write_all(&[5, 1, 0]).await?;
                } else {
                    s.write_all(&[5, 2, 0, 2]).await?;
                }
                let mut r = [0u8; 2];
                s.read_exact(&mut r).await?;
                match r {
                    [5, 0] => {}
                    [5, 2] if !self.username.is_empty() => {
                        let (u, p) = (self.username.as_bytes(), self.password.as_bytes());
                        if u.len() > 255 || p.len() > 255 {
                            bail!("proxy credentials are too long");
                        }
                        let mut m = vec![1, u.len() as u8];
                        m.extend_from_slice(u);
                        m.push(p.len() as u8);
                        m.extend_from_slice(p);
                        s.write_all(&m).await?;
                        let mut a = [0u8; 2];
                        s.read_exact(&mut a).await?;
                        if a[1] != 0 {
                            bail!("the proxy refused the credentials");
                        }
                    }
                    _ => bail!("the proxy accepts none of the offered authentication methods"),
                }
                let mut req = vec![5, 1, 0];
                match host.parse::<std::net::IpAddr>() {
                    Ok(std::net::IpAddr::V4(a)) => {
                        req.push(1);
                        req.extend_from_slice(&a.octets());
                    }
                    Ok(std::net::IpAddr::V6(a)) => {
                        req.push(4);
                        req.extend_from_slice(&a.octets());
                    }
                    Err(_) => {
                        req.push(3);
                        req.push(host.len() as u8);
                        req.extend_from_slice(host.as_bytes());
                    }
                }
                req.extend_from_slice(&port.to_be_bytes());
                s.write_all(&req).await?;
                let mut h = [0u8; 4];
                s.read_exact(&mut h).await?;
                if h[1] != 0 {
                    bail!("the proxy refused the connection to {host}:{port} (SOCKS5 reply {})", h[1]);
                }
                let skip = match h[3] {
                    1 => 6,
                    4 => 18,
                    3 => s.read_u8().await? as usize + 2,
                    _ => bail!("the proxy answered with an unknown address type"),
                };
                let mut sink = vec![0u8; skip];
                s.read_exact(&mut sink).await?;
            }
            Kind::Http => {
                let target = if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") };
                s.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes()).await?;
                let mut head = Vec::new();
                let mut b = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if s.read(&mut b).await? == 0 || head.len() > 8192 {
                        bail!("the proxy closed the connection during CONNECT");
                    }
                    head.push(b[0]);
                }
                let line = String::from_utf8_lossy(&head);
                if !line.starts_with("HTTP/1.1 200") && !line.starts_with("HTTP/1.0 200") {
                    bail!("the proxy refused CONNECT: {}", line.lines().next().unwrap_or(""));
                }
            }
        }
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn urls_parse() {
        let p = Proxy::parse("socks5h://127.0.0.1:40000").unwrap();
        assert_eq!((p.kind, p.addr.as_str(), p.username.as_str()), (Kind::Socks5, "127.0.0.1:40000", ""));
        let p = Proxy::parse("socks5://u:p@host:1080").unwrap();
        assert_eq!((p.username.as_str(), p.password.as_str(), p.addr.as_str()), ("u", "p", "host:1080"));
        assert_eq!(Proxy::parse("http://h:3128").unwrap().kind, Kind::Http);
        assert!(Proxy::parse("ftp://h:1").is_err());
        assert!(Proxy::parse("socks5://nohost").is_err());
    }

    /// A SOCKS5 server that records the request and then echoes.
    async fn socks_echo() -> (String, tokio::sync::oneshot::Receiver<(u8, String, u16)>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut g = [0u8; 3];
            s.read_exact(&mut g).await.unwrap();
            s.write_all(&[5, 0]).await.unwrap();
            let mut h = [0u8; 4];
            s.read_exact(&mut h).await.unwrap();
            let host = match h[3] {
                3 => {
                    let n = s.read_u8().await.unwrap() as usize;
                    let mut b = vec![0u8; n];
                    s.read_exact(&mut b).await.unwrap();
                    String::from_utf8(b).unwrap()
                }
                1 => {
                    let mut b = [0u8; 4];
                    s.read_exact(&mut b).await.unwrap();
                    std::net::Ipv4Addr::from(b).to_string()
                }
                _ => unreachable!(),
            };
            let port = s.read_u16().await.unwrap();
            let _ = tx.send((h[3], host, port));
            s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
            let mut b = [0u8; 16];
            while let Ok(n) = s.read(&mut b).await {
                if n == 0 || s.write_all(&b[..n]).await.is_err() {
                    break;
                }
            }
        });
        (addr, rx)
    }

    #[tokio::test]
    async fn socks5_connect_sends_names_as_names() {
        let (addr, rx) = socks_echo().await;
        let p = Proxy::parse(&format!("socks5h://{addr}")).unwrap();
        let mut s = p.connect("dns.example", 853).await.unwrap();
        assert_eq!(rx.await.unwrap(), (3, "dns.example".to_string(), 853));
        s.write_all(b"ping").await.unwrap();
        let mut b = [0u8; 4];
        s.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"ping");

        let (addr, rx) = socks_echo().await;
        Proxy::parse(&format!("socks5://{addr}")).unwrap().connect("1.1.1.1", 53).await.unwrap();
        assert_eq!(rx.await.unwrap(), (1, "1.1.1.1".to_string(), 53));
    }

    #[tokio::test]
    async fn a_dead_proxy_is_an_error_not_a_direct_connection() {
        let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        let p = Proxy::parse(&format!("socks5h://{free}")).unwrap();
        assert!(p.connect("1.1.1.1", 53).await.is_err());
    }
}
