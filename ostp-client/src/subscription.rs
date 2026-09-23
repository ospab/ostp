//! Fetching a subscription: `https://<domain>/sub/<token>` -> the user's
//! current links. Plain HTTP is refused: the URL is a credential.

use anyhow::{anyhow, bail, Context, Result};
use ostp_core::subscription::SubscriptionDoc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::transport::tls::{wrap_tls, TlsClientOptions};

const TIMEOUT: Duration = Duration::from_secs(15);
const MAX_BODY: usize = 1024 * 1024;

/// `https://host[:port]/path?query` split into its parts.
#[derive(Debug, PartialEq, Eq)]
struct Url {
    host: String,
    port: u16,
    /// Path and query, always starting with '/'.
    target: String,
}

fn parse_url(url: &str) -> Result<Url> {
    let url = url.trim();
    let rest = match url.split_once("://") {
        Some((scheme, rest)) if scheme.eq_ignore_ascii_case("https") => rest,
        Some((scheme, _)) => bail!("subscription URLs must use https (got {scheme}://): the link is a credential"),
        None => bail!("not a subscription URL: expected https://..."),
    };
    let (authority, target) = match rest.find(['/', '?']) {
        Some(i) if rest[i..].starts_with('/') => (&rest[..i], rest[i..].to_string()),
        Some(i) => (&rest[..i], format!("/{}", &rest[i..])),
        None => (rest, "/".to_string()),
    };
    let target = target.split('#').next().unwrap_or("/").to_string();
    if authority.contains('@') {
        bail!("subscription URLs must not contain user info");
    }
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let (h, after) = v6.split_once(']').ok_or_else(|| anyhow!("bad IPv6 address in the URL"))?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().context("bad port in the URL")?,
            None => 443,
        };
        (h.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().context("bad port in the URL")?),
            None => (authority.to_string(), 443),
        }
    };
    if host.is_empty() {
        bail!("subscription URL has no host");
    }
    Ok(Url { host, port, target })
}

/// Downloads and parses a subscription.
pub async fn fetch(url: &str) -> Result<SubscriptionDoc> {
    let u = parse_url(url)?;
    let body = tokio::time::timeout(TIMEOUT, get(&u))
        .await
        .map_err(|_| anyhow!("{} did not answer within {}s", u.host, TIMEOUT.as_secs()))??;
    let text = String::from_utf8(body).map_err(|_| anyhow!("the subscription is not text"))?;
    let doc = SubscriptionDoc::parse(&text)?;
    if doc.valid_links().is_empty() {
        bail!("the subscription has no usable ostp:// links");
    }
    Ok(doc)
}

async fn get(u: &Url) -> Result<Vec<u8>> {
    let tcp = tokio::net::TcpStream::connect((u.host.as_str(), u.port))
        .await
        .with_context(|| format!("cannot connect to {}:{}", u.host, u.port))?;
    let _ = tcp.set_nodelay(true);
    let opts = TlsClientOptions { sni: u.host.clone(), insecure: false };
    let mut s = wrap_tls(tcp, &opts, TIMEOUT).await?;

    let host_header = if u.host.contains(':') { format!("[{}]", u.host) } else { u.host.clone() };
    let host_header = if u.port == 443 { host_header } else { format!("{host_header}:{}", u.port) };
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {host_header}\r\nAccept: application/json\r\nUser-Agent: ostp/{}\r\nConnection: close\r\n\r\n",
        u.target,
        env!("CARGO_PKG_VERSION")
    );
    s.write_all(req.as_bytes()).await?;
    s.flush().await?;

    let mut raw = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = match s.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => n,
            // Servers that close without close_notify: whatever arrived counts.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        };
        raw.extend_from_slice(&chunk[..n]);
        if raw.len() > MAX_BODY + 16 * 1024 {
            bail!("the subscription is larger than {} KiB", MAX_BODY / 1024);
        }
    }
    parse_response(&raw)
}

fn parse_response(raw: &[u8]) -> Result<Vec<u8>> {
    let mut headers = [httparse::EMPTY_HEADER; 48];
    let mut resp = httparse::Response::new(&mut headers);
    let head_len = match resp.parse(raw) {
        Ok(httparse::Status::Complete(n)) => n,
        Ok(httparse::Status::Partial) => bail!("the server closed the connection before answering"),
        Err(e) => bail!("not an HTTP response: {e}"),
    };
    let code = resp.code.unwrap_or(0);
    match code {
        200 => {}
        404 => bail!("the server does not know this subscription (404): the link is wrong or the key was removed"),
        301 | 302 | 307 | 308 => bail!("the server redirected ({code}); use the final https URL"),
        _ => bail!("the server answered HTTP {code}"),
    }
    let header = |name: &str| {
        resp.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .and_then(|h| std::str::from_utf8(h.value).ok())
            .map(str::trim)
    };
    let body = &raw[head_len..];
    if header("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked")) {
        return dechunk(body);
    }
    match header("content-length").and_then(|v| v.parse::<usize>().ok()) {
        Some(n) if n <= body.len() => Ok(body[..n].to_vec()),
        Some(_) => bail!("the subscription download was cut short"),
        None => Ok(body.to_vec()),
    }
}

fn dechunk(mut body: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = body.windows(2).position(|w| w == b"\r\n").ok_or_else(|| anyhow!("bad chunked encoding"))?;
        let size_str = std::str::from_utf8(&body[..line_end])?.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_str, 16).map_err(|_| anyhow!("bad chunk size"))?;
        body = &body[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if body.len() < size + 2 {
            bail!("the subscription download was cut short");
        }
        out.extend_from_slice(&body[..size]);
        body = &body[size + 2..];
        if out.len() > MAX_BODY {
            bail!("the subscription is larger than {} KiB", MAX_BODY / 1024);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_parsing() {
        assert_eq!(
            parse_url("https://vpn.example.com/sub/abc").unwrap(),
            Url { host: "vpn.example.com".into(), port: 443, target: "/sub/abc".into() }
        );
        assert_eq!(parse_url("https://vpn.example.com:8443/sub/x?format=json#f").unwrap().target, "/sub/x?format=json");
        assert_eq!(parse_url("https://vpn.example.com:8443/s").unwrap().port, 8443);
        let v6 = parse_url("https://[2001:db8::1]:444/sub/t").unwrap();
        assert_eq!((v6.host.as_str(), v6.port), ("2001:db8::1", 444));
        assert_eq!(parse_url("HTTPS://h").unwrap().target, "/");
        assert!(parse_url("http://vpn.example.com/sub/abc").is_err());
        assert!(parse_url("ostp://k@h:1").is_err());
        assert!(parse_url("vpn.example.com/sub").is_err());
        assert!(parse_url("https://u:p@h/sub").is_err());
    }

    #[test]
    fn response_bodies() {
        let r = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloEXTRA";
        assert_eq!(parse_response(r).unwrap(), b"hello");
        let c = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6;x=y\r\n world\r\n0\r\n\r\n";
        assert_eq!(parse_response(c).unwrap(), b"hello world");
        let e = parse_response(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").unwrap_err();
        assert!(e.to_string().contains("404"));
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\nshort").is_err());
    }
}
