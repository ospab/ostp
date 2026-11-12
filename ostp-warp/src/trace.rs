//! `https://www.cloudflare.com/cdn-cgi/trace` fetched through the tunnel:
//! `warp=on` (or `plus`) and `ip=` are what a site sees.

use anyhow::{anyhow, bail, Result};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const HOST: &str = "www.cloudflare.com";
pub const PATH: &str = "/cdn-cgi/trace";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Trace {
    /// `on`, `plus` or `off`.
    pub warp: Option<String>,
    pub ip: Option<String>,
    pub loc: Option<String>,
    pub colo: Option<String>,
}

impl Trace {
    /// Traffic really leaves through WARP.
    pub fn is_warp(&self) -> bool {
        matches!(self.warp.as_deref(), Some("on") | Some("plus"))
    }
}

pub fn parse_trace(body: &str) -> Trace {
    let mut t = Trace::default();
    for line in body.lines() {
        let Some((k, v)) = line.split_once('=') else { continue };
        let v = v.trim().to_string();
        match k.trim() {
            "warp" => t.warp = Some(v),
            "ip" => t.ip = Some(v),
            "loc" => t.loc = Some(v),
            "colo" => t.colo = Some(v),
            _ => {}
        }
    }
    t
}

/// Sends the HTTP/1.1 request over an established stream (TLS or not) and
/// parses the answer.
pub async fn http_trace<S: AsyncRead + AsyncWrite + Unpin>(mut s: S, host: &str) -> Result<Trace> {
    let req = format!("GET {PATH} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ostp-warp\r\nAccept: */*\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).await?;
    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match s.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&buf[..n]);
                if raw.len() > 64 * 1024 {
                    bail!("the trace answer is too long");
                }
            }
            // TLS peers that close without close_notify: what was read counts.
            Err(e) if !raw.is_empty() && e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
    }
    let text = String::from_utf8_lossy(&raw);
    let (head, body) = text.split_once("\r\n\r\n").ok_or_else(|| anyhow!("the trace answer is not HTTP"))?;
    let status = head.lines().next().unwrap_or("");
    if !status.contains(" 200") {
        bail!("the trace answered: {status}");
    }
    let chunked = head.to_ascii_lowercase().contains("transfer-encoding: chunked");
    let body = if chunked { dechunk(body)? } else { body.to_string() };
    let t = parse_trace(&body);
    if t.warp.is_none() && t.ip.is_none() {
        bail!("the trace answer has no warp= or ip= line");
    }
    Ok(t)
}

fn dechunk(body: &str) -> Result<String> {
    let mut out = String::new();
    let mut rest = body;
    loop {
        let (size_line, after) = rest.split_once("\r\n").ok_or_else(|| anyhow!("bad chunked body"))?;
        let size = usize::from_str_radix(size_line.split(';').next().unwrap_or("").trim(), 16).map_err(|_| anyhow!("bad chunk size"))?;
        if size == 0 {
            return Ok(out);
        }
        if after.len() < size {
            bail!("short chunk");
        }
        out.push_str(&after[..size]);
        rest = after[size..].strip_prefix("\r\n").unwrap_or(&after[size..]);
    }
}

/// TLS over any stream, verifying the name against the web PKI roots.
pub async fn tls<S: AsyncRead + AsyncWrite + Unpin>(s: S, host: &str) -> Result<tokio_rustls::client::TlsStream<S>> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| anyhow!("TLS setup: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from(host.to_string()).map_err(|_| anyhow!("invalid host name {host}"))?;
    tokio_rustls::TlsConnector::from(Arc::new(cfg)).connect(name, s).await.map_err(|e| anyhow!("TLS to {host}: {e}"))
}

/// The whole fetch over a stream that already reaches `www.cloudflare.com:443`.
pub async fn fetch_over<S: AsyncRead + AsyncWrite + Unpin>(stream: S) -> Result<Trace> {
    let s = tls(stream, HOST).await?;
    http_trace(s, HOST).await
}

#[cfg(test)]
mod tests {
    use super::*;

    const BODY: &str = "fl=29f\nh=www.cloudflare.com\nip=203.0.113.9\nts=1700000000.1\nvisit_scheme=https\nuag=ostp\ncolo=AMS\nsliver=none\nhttp=http/1.1\nloc=NL\ntls=TLSv1.3\nsni=plaintext\nwarp=on\ngateway=off\nrbi=off\nkex=X25519\n";

    #[test]
    fn trace_lines_are_read() {
        let t = parse_trace(BODY);
        assert_eq!(t.warp.as_deref(), Some("on"));
        assert_eq!(t.ip.as_deref(), Some("203.0.113.9"));
        assert_eq!(t.loc.as_deref(), Some("NL"));
        assert_eq!(t.colo.as_deref(), Some("AMS"));
        assert!(t.is_warp());
        assert!(!parse_trace("warp=off\nip=1.1.1.1").is_warp());
        assert!(parse_trace("warp=plus").is_warp());
        assert!(!parse_trace("").is_warp());
    }

    async fn serve_once(reply: String) -> tokio::io::DuplexStream {
        let (client, mut server) = tokio::io::duplex(8192);
        tokio::spawn(async move {
            let mut b = [0u8; 1024];
            let _ = server.read(&mut b).await;
            let _ = server.write_all(reply.as_bytes()).await;
            let _ = server.shutdown().await;
        });
        client
    }

    #[tokio::test]
    async fn plain_and_chunked_answers_parse() {
        let ok = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{BODY}", BODY.len());
        let t = http_trace(serve_once(ok).await, HOST).await.unwrap();
        assert_eq!(t.ip.as_deref(), Some("203.0.113.9"));
        let (a, b) = BODY.split_at(40);
        let chunked = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{a}\r\n{:x}\r\n{b}\r\n0\r\n\r\n", a.len(), b.len());
        let t = http_trace(serve_once(chunked).await, HOST).await.unwrap();
        assert!(t.is_warp());
    }

    #[tokio::test]
    async fn errors_are_loud() {
        assert!(http_trace(serve_once("HTTP/1.1 403 Forbidden\r\n\r\nno".into()).await, HOST).await.is_err());
        assert!(http_trace(serve_once("garbage".into()).await, HOST).await.is_err());
        assert!(http_trace(serve_once("HTTP/1.1 200 OK\r\n\r\nnothing useful".into()).await, HOST).await.is_err());
    }
}
