//! Upstream resolvers: plain UDP/TCP, DNS over HTTPS, DNS over TLS.

use anyhow::{anyhow, bail, Context, Result};
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::settings::UpstreamMode;

const TIMEOUT: Duration = Duration::from_secs(4);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Upstream {
    Udp(SocketAddr),
    Tcp(SocketAddr),
    Doh(String),
    Dot { host: String, port: u16 },
}

fn with_port(s: &str, default: u16) -> Result<SocketAddr> {
    if let Ok(a) = s.parse::<SocketAddr>() {
        return Ok(a);
    }
    let ip: std::net::IpAddr = s.trim_matches(['[', ']']).parse().map_err(|_| anyhow!("\"{s}\" is not an IP address (with an optional port)"))?;
    Ok(SocketAddr::new(ip, default))
}

impl Upstream {
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.starts_with("https://") {
            return Ok(Upstream::Doh(s.to_string()));
        }
        if let Some(rest) = s.strip_prefix("tls://") {
            let rest = rest.trim_end_matches('/');
            let (host, port) = match rest.rsplit_once(':') {
                Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => (h.to_string(), p.parse()?),
                _ => (rest.to_string(), 853),
            };
            if host.is_empty() {
                bail!("\"{s}\": no host");
            }
            return Ok(Upstream::Dot { host, port });
        }
        if let Some(rest) = s.strip_prefix("tcp://") {
            return Ok(Upstream::Tcp(with_port(rest, 53)?));
        }
        let rest = s.strip_prefix("udp://").unwrap_or(s);
        with_port(rest, 53).map(Upstream::Udp).with_context(|| {
            format!("upstream \"{s}\": use https://host/dns-query, tls://host, tcp://ip, udp://ip or a bare IP")
        })
    }

    pub fn label(&self) -> String {
        match self {
            Upstream::Udp(a) => format!("udp://{a}"),
            Upstream::Tcp(a) => format!("tcp://{a}"),
            Upstream::Doh(u) => u.clone(),
            Upstream::Dot { host, port } => format!("tls://{host}:{port}"),
        }
    }
}

pub struct Upstreams {
    list: Vec<Upstream>,
    mode: UpstreamMode,
    http: reqwest::Client,
}

fn tls_config() -> Arc<rustls::ClientConfig> {
    static CFG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CFG.get_or_init(|| {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("ring supports TLS 1.2 and 1.3")
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    })
    .clone()
}

async fn framed<S: AsyncRead + AsyncWrite + Unpin>(mut s: S, q: &[u8]) -> Result<Vec<u8>> {
    let mut msg = Vec::with_capacity(q.len() + 2);
    msg.extend_from_slice(&(q.len() as u16).to_be_bytes());
    msg.extend_from_slice(q);
    s.write_all(&msg).await?;
    s.flush().await?;
    let mut len = [0u8; 2];
    s.read_exact(&mut len).await?;
    let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
    s.read_exact(&mut body).await?;
    Ok(body)
}

async fn udp(addr: SocketAddr, q: &[u8]) -> Result<Vec<u8>> {
    let bind: SocketAddr = if addr.is_ipv6() { "[::]:0".parse()? } else { "0.0.0.0:0".parse()? };
    let sock = tokio::net::UdpSocket::bind(bind).await?;
    sock.connect(addr).await?;
    sock.send(q).await?;
    let mut buf = vec![0u8; 4096];
    loop {
        let n = sock.recv(&mut buf).await?;
        // Ignore anything that is not the answer to this query.
        if n >= 12 && buf[..2] == q[..2] {
            buf.truncate(n);
            return Ok(buf);
        }
    }
}

async fn tcp(addr: SocketAddr, q: &[u8]) -> Result<Vec<u8>> {
    let s = tokio::net::TcpStream::connect(addr).await?;
    framed(s, q).await
}

impl Upstreams {
    pub fn new(specs: &[String], mode: UpstreamMode, proxy: Option<&str>) -> Result<Self> {
        let list = specs.iter().map(|s| Upstream::parse(s)).collect::<Result<Vec<_>>>()?;
        let mut builder = reqwest::Client::builder().timeout(TIMEOUT);
        if let Some(p) = proxy {
            builder = builder.proxy(reqwest::Proxy::all(p)?);
        }
        Ok(Self { list, mode, http: builder.build()? })
    }

    pub fn labels(&self) -> Vec<String> {
        self.list.iter().map(Upstream::label).collect()
    }

    async fn one(&self, u: &Upstream, q: &[u8]) -> Result<Vec<u8>> {
        let answer = tokio::time::timeout(TIMEOUT, async {
            match u {
                Upstream::Udp(a) => {
                    let r = udp(*a, q).await?;
                    // Truncated: ask again over TCP.
                    if r.len() > 2 && r[2] & 0x02 != 0 {
                        tcp(*a, q).await
                    } else {
                        Ok(r)
                    }
                }
                Upstream::Tcp(a) => tcp(*a, q).await,
                Upstream::Doh(url) => {
                    let resp = self
                        .http
                        .post(url)
                        .header("content-type", "application/dns-message")
                        .header("accept", "application/dns-message")
                        .body(q.to_vec())
                        .send()
                        .await?;
                    if !resp.status().is_success() {
                        bail!("HTTP {}", resp.status());
                    }
                    Ok(resp.bytes().await?.to_vec())
                }
                Upstream::Dot { host, port } => {
                    let tcp = tokio::net::TcpStream::connect((host.as_str(), *port)).await?;
                    let name = rustls::pki_types::ServerName::try_from(host.clone())?;
                    let tls = tokio_rustls::TlsConnector::from(tls_config()).connect(name, tcp).await?;
                    framed(tls, q).await
                }
            }
        })
        .await
        .map_err(|_| anyhow!("no answer within {}s", TIMEOUT.as_secs()))??;
        if answer.len() < 12 {
            bail!("short answer");
        }
        Ok(answer)
    }

    /// The answer and the upstream that gave it.
    pub async fn query(self: &Arc<Self>, q: &[u8]) -> Result<(Vec<u8>, String)> {
        if self.list.is_empty() {
            bail!("no upstream resolvers configured");
        }
        match self.mode {
            UpstreamMode::Fallback => {
                let mut last = None;
                for u in &self.list {
                    match self.one(u, q).await {
                        Ok(a) => return Ok((a, u.label())),
                        Err(e) => last = Some(anyhow!("{}: {e:#}", u.label())),
                    }
                }
                Err(last.unwrap())
            }
            UpstreamMode::Parallel => {
                let (tx, mut rx) = tokio::sync::mpsc::channel(self.list.len());
                for u in self.list.clone() {
                    let (me, tx, q) = (self.clone(), tx.clone(), q.to_vec());
                    tokio::spawn(async move {
                        let r = me.one(&u, &q).await.map(|a| (a, u.label())).map_err(|e| anyhow!("{}: {e:#}", u.label()));
                        let _ = tx.send(r).await;
                    });
                }
                drop(tx);
                let mut last = None;
                while let Some(r) = rx.recv().await {
                    match r {
                        Ok(v) => return Ok(v),
                        Err(e) => last = Some(e),
                    }
                }
                Err(last.unwrap_or_else(|| anyhow!("no upstream answered")))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_forms() {
        assert_eq!(Upstream::parse("1.1.1.1").unwrap(), Upstream::Udp("1.1.1.1:53".parse().unwrap()));
        assert_eq!(Upstream::parse("udp://9.9.9.9:5353").unwrap(), Upstream::Udp("9.9.9.9:5353".parse().unwrap()));
        assert_eq!(Upstream::parse("tcp://[2606:4700::1111]").unwrap(), Upstream::Tcp("[2606:4700::1111]:53".parse().unwrap()));
        assert_eq!(Upstream::parse("tls://dns.quad9.net").unwrap(), Upstream::Dot { host: "dns.quad9.net".into(), port: 853 });
        assert_eq!(Upstream::parse("tls://1.1.1.1:8853").unwrap(), Upstream::Dot { host: "1.1.1.1".into(), port: 8853 });
        assert!(matches!(Upstream::parse("https://dns.google/dns-query").unwrap(), Upstream::Doh(_)));
        assert!(Upstream::parse("dns.google").is_err());
    }

    /// A local UDP "resolver" that echoes the query id: fallback skips a
    /// dead first upstream and answers from the second.
    #[tokio::test]
    async fn fallback_to_the_next_upstream() {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 512];
            while let Ok((n, peer)) = sock.recv_from(&mut b).await {
                let mut r = b[..n].to_vec();
                r[2] |= 0x80;
                let _ = sock.send_to(&r, peer).await;
            }
        });
        let ups = Arc::new(Upstreams::new(&["tcp://127.0.0.1:1".into(), format!("udp://{addr}")], UpstreamMode::Fallback, None).unwrap());
        let q = [0xAB, 0xCD, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1];
        let (a, label) = ups.query(&q).await.unwrap();
        assert_eq!(&a[..2], &[0xAB, 0xCD]);
        assert_eq!(label, format!("udp://{addr}"));
    }
}
