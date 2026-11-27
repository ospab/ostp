//! Fetching a subscription: `https://<domain>/sub/<token>` -> the user's
//! current links. Plain HTTP is refused: the URL is a credential.

use anyhow::{anyhow, bail, Context, Result};
use ostp_core::subscription::SubscriptionDoc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::hwid::Device;
use crate::transport::tls::{wrap_tls, TlsClientOptions};

const TIMEOUT: Duration = Duration::from_secs(15);
const MAX_BODY: usize = 1024 * 1024;

/// `https://host[:port]/path?query` split into its parts.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Url {
    pub(crate) host: String,
    pub(crate) port: u16,
    /// Path and query, always starting with '/'.
    pub(crate) target: String,
}

pub(crate) fn parse_url(url: &str) -> Result<Url> {
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

/// The server refused the subscription because of its device limit (HTTP 403 with a
/// JSON body). Apps tell the two kinds apart with [`device_error`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceError {
    /// The user has a device limit and the request carried no device ID.
    HwidRequired(String),
    /// A new device and no free slot.
    DeviceLimit(String),
}

impl DeviceError {
    /// The server's `error` code: `hwid_required` or `device_limit`.
    pub fn code(&self) -> &'static str {
        match self {
            DeviceError::HwidRequired(_) => "hwid_required",
            DeviceError::DeviceLimit(_) => "device_limit",
        }
    }

    /// The server's own text.
    pub fn message(&self) -> &str {
        match self {
            DeviceError::HwidRequired(m) | DeviceError::DeviceLimit(m) => m,
        }
    }
}

impl std::fmt::Display for DeviceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for DeviceError {}

/// The device error inside `e`, if that is what it is.
pub fn device_error(e: &anyhow::Error) -> Option<&DeviceError> {
    e.downcast_ref::<DeviceError>()
}

/// The error as the apps pass it to their UI: `device:<code>:<server message>` for a
/// device error, the plain text otherwise.
pub fn error_text(e: &anyhow::Error) -> String {
    match device_error(e) {
        Some(d) => format!("device:{}:{}", d.code(), d.message().replace(['\r', '\n'], " ")),
        None => e.to_string(),
    }
}

/// Reads a 403 body: `{"error":"hwid_required"|"device_limit","message":"..."}`.
/// Any other 403 is not a device error.
fn parse_device_error(body: &[u8]) -> Option<DeviceError> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    let message = |default: &str| {
        v.get("message").and_then(|m| m.as_str()).map(str::trim).filter(|m| !m.is_empty()).unwrap_or(default).to_string()
    };
    match v.get("error").and_then(|e| e.as_str())? {
        "hwid_required" => Some(DeviceError::HwidRequired(message("this subscription needs a device ID"))),
        "device_limit" => Some(DeviceError::DeviceLimit(message("the device limit of this subscription is reached"))),
        _ => None,
    }
}

/// Header values are printable ASCII, at most 64 characters (what the server keeps).
fn header_value(s: &str) -> String {
    s.chars().map(|c| if (' '..='~').contains(&c) { c } else { '?' }).take(64).collect::<String>().trim().to_string()
}

/// The three device headers, each ending in CRLF; empty without a device.
fn device_headers(device: Option<&Device>) -> String {
    let Some(d) = device else { return String::new() };
    let mut out = format!("x-hwid: {}\r\n", header_value(&d.hwid));
    for (name, value) in [("x-device-os", &d.os), ("x-device-model", &d.model)] {
        let v = header_value(value);
        if !v.is_empty() {
            out.push_str(&format!("{name}: {v}\r\n"));
        }
    }
    out
}

/// Downloads and parses a subscription, sending no device identity.
pub async fn fetch(url: &str) -> Result<SubscriptionDoc> {
    fetch_with_device(url, None).await
}

/// Like [`fetch`], and sends `x-hwid`, `x-device-os` and `x-device-model` when a
/// device is given. A server that limits devices answers with a [`DeviceError`].
pub async fn fetch_with_device(url: &str, device: Option<&Device>) -> Result<SubscriptionDoc> {
    fetch_via(url, device, None).await
}

/// Like [`fetch_with_device`], through the running core's local SOCKS5 proxy when
/// `proxy` is given (`host:port` or `socks5h://host:port`): the name is resolved by
/// the tunnel's far end, so neither the provider's DNS nor its network sees the
/// subscription domain. A failure through the proxy is an error; the request is
/// never repeated outside the tunnel.
pub async fn fetch_via(url: &str, device: Option<&Device>, proxy: Option<&str>) -> Result<SubscriptionDoc> {
    let u = parse_url(url)?;
    let body = tokio::time::timeout(TIMEOUT, get(&u, "application/json", device, proxy))
        .await
        .map_err(|_| anyhow!("{} did not answer within {}s", u.host, TIMEOUT.as_secs()))??;
    let text = String::from_utf8(body).map_err(|_| anyhow!("the subscription is not text"))?;
    let doc = SubscriptionDoc::parse(&text)?;
    if doc.valid_links().is_empty() {
        bail!("the subscription has no usable ostp:// links");
    }
    Ok(doc)
}

/// GET over verified TLS; returns the status code and the body.
pub(crate) async fn https_get(url: &str, accept: &str, proxy: Option<&str>) -> Result<(u16, Vec<u8>)> {
    let u = parse_url(url)?;
    let raw = tokio::time::timeout(TIMEOUT, get_raw(&u, accept, None, proxy))
        .await
        .map_err(|_| anyhow!("{} did not answer within {}s", u.host, TIMEOUT.as_secs()))??;
    split_response(&raw)
}

async fn get(u: &Url, accept: &str, device: Option<&Device>, proxy: Option<&str>) -> Result<Vec<u8>> {
    parse_response(&get_raw(u, accept, device, proxy).await?)
}

/// The request head as sent.
fn request_head(u: &Url, accept: &str, device: Option<&Device>) -> String {
    let host_header = if u.host.contains(':') { format!("[{}]", u.host) } else { u.host.clone() };
    let host_header = if u.port == 443 { host_header } else { format!("{host_header}:{}", u.port) };
    format!(
        "GET {} HTTP/1.1\r\nHost: {host_header}\r\nAccept: {accept}\r\nUser-Agent: ostp/{}\r\n{}Connection: close\r\n\r\n",
        u.target,
        env!("CARGO_PKG_VERSION"),
        device_headers(device)
    )
}

/// The local proxy address (`host:port`, with or without `socks5h://`) the core
/// listens on, as something to connect to: a wildcard bind (`0.0.0.0`, `[::]`)
/// is reached on loopback. Empty text means no proxy.
pub fn proxy_endpoint(proxy: &str) -> Result<Option<(String, u16)>> {
    let p = proxy.trim();
    if p.is_empty() {
        return Ok(None);
    }
    let p = match p.split_once("://") {
        Some((scheme, rest)) if scheme.eq_ignore_ascii_case("socks5h") || scheme.eq_ignore_ascii_case("socks5") => rest,
        Some((scheme, _)) => bail!("unsupported proxy scheme {scheme}://: only socks5h:// is supported"),
        None => p,
    };
    let p = p.trim_end_matches('/');
    let (host, port) = p.rsplit_once(':').ok_or_else(|| anyhow!("the proxy address must be host:port"))?;
    let port: u16 = port.parse().map_err(|_| anyhow!("bad proxy port"))?;
    if port == 0 {
        bail!("bad proxy port");
    }
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let host = match host.parse::<std::net::IpAddr>() {
        Ok(ip) if ip.is_unspecified() => (if ip.is_ipv4() { "127.0.0.1" } else { "::1" }).to_string(),
        _ if host.is_empty() => "127.0.0.1".to_string(),
        _ => host.to_string(),
    };
    Ok(Some((host, port)))
}

/// The proxy for the app's own requests (subscription refresh, update check and download):
/// the core's local SOCKS5 proxy, but only when the person wants requests through the tunnel
/// (`via_tunnel`) and the tunnel is running. Otherwise `None`, a direct request, as before.
/// `bind` is `local_proxy.bind_addr` (default `127.0.0.1:1088`).
pub fn app_proxy(via_tunnel: bool, tunnel_running: bool, bind: Option<&str>) -> Option<String> {
    if !(via_tunnel && tunnel_running) {
        return None;
    }
    let bind = bind.map(str::trim).filter(|b| !b.is_empty()).unwrap_or("127.0.0.1:1088");
    Some(format!("socks5h://{bind}"))
}

/// The SOCKS5 CONNECT request (no authentication). A name is sent as text so the
/// proxy resolves it: what `socks5h` means.
fn socks5_connect_request(host: &str, port: u16) -> Result<Vec<u8>> {
    let mut req = vec![5, 1, 0];
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => {
            req.push(1);
            req.extend_from_slice(&ip.octets());
        }
        Ok(std::net::IpAddr::V6(ip)) => {
            req.push(4);
            req.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            if host.is_empty() || host.len() > 255 {
                bail!("bad host name");
            }
            req.push(3);
            req.push(host.len() as u8);
            req.extend_from_slice(host.as_bytes());
        }
    }
    req.extend_from_slice(&port.to_be_bytes());
    Ok(req)
}

/// TCP to `host:port`: direct, or through the SOCKS5 proxy at `proxy`. A proxy
/// that refuses or cannot be reached is an error, never a reason to go direct.
pub(crate) async fn connect_tcp(host: &str, port: u16, proxy: Option<&str>) -> Result<tokio::net::TcpStream> {
    let Some((ph, pp)) = proxy.map(proxy_endpoint).transpose()?.flatten() else {
        return tokio::net::TcpStream::connect((host, port))
            .await
            .with_context(|| format!("cannot connect to {host}:{port}"));
    };
    let mut s = tokio::net::TcpStream::connect((ph.as_str(), pp))
        .await
        .with_context(|| format!("cannot reach the local proxy at {ph}:{pp} (is the tunnel up?)"))?;
    s.write_all(&[5, 1, 0]).await?;
    let mut greet = [0u8; 2];
    s.read_exact(&mut greet).await.context("the local proxy closed the connection")?;
    if greet != [5, 0] {
        bail!("the local proxy at {ph}:{pp} did not accept an unauthenticated SOCKS5 connection");
    }
    s.write_all(&socks5_connect_request(host, port)?).await?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await.context("the local proxy closed the connection")?;
    if head[0] != 5 {
        bail!("{ph}:{pp} is not a SOCKS5 proxy");
    }
    if head[1] != 0 {
        let why = match head[1] {
            2 => "not allowed",
            3 => "network unreachable",
            4 => "host unreachable",
            5 => "connection refused",
            6 => "TTL expired",
            _ => "failed",
        };
        bail!("the tunnel could not reach {host}:{port} ({why}); nothing was sent outside the tunnel");
    }
    let rest = match head[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            l[0] as usize + 2
        }
        _ => bail!("bad answer from the local proxy"),
    };
    let mut skip = vec![0u8; rest];
    s.read_exact(&mut skip).await?;
    Ok(s)
}

async fn get_raw(u: &Url, accept: &str, device: Option<&Device>, proxy: Option<&str>) -> Result<Vec<u8>> {
    let tcp = connect_tcp(&u.host, u.port, proxy).await?;
    let _ = tcp.set_nodelay(true);
    let opts = TlsClientOptions { sni: u.host.clone(), insecure: false };
    let mut s = wrap_tls(tcp, &opts, TIMEOUT).await?;

    let req = request_head(u, accept, device);
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
            bail!("the answer is larger than {} KiB", MAX_BODY / 1024);
        }
    }
    Ok(raw)
}

/// Status code and body (de-chunked, cut to Content-Length).
fn split_response(raw: &[u8]) -> Result<(u16, Vec<u8>)> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut resp = httparse::Response::new(&mut headers);
    let head_len = match resp.parse(raw) {
        Ok(httparse::Status::Complete(n)) => n,
        Ok(httparse::Status::Partial) => bail!("the server closed the connection before answering"),
        Err(e) => bail!("not an HTTP response: {e}"),
    };
    let code = resp.code.unwrap_or(0);
    let header = |name: &str| {
        resp.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .and_then(|h| std::str::from_utf8(h.value).ok())
            .map(str::trim)
    };
    let body = &raw[head_len..];
    let body = if header("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked")) {
        dechunk(body)?
    } else {
        match header("content-length").and_then(|v| v.parse::<usize>().ok()) {
            Some(n) if n <= body.len() => body[..n].to_vec(),
            Some(_) => bail!("the download was cut short"),
            None => body.to_vec(),
        }
    };
    Ok((code, body))
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
        403 => {
            return Err(match split_response(raw).ok().and_then(|(_, body)| parse_device_error(&body)) {
                Some(e) => e.into(),
                None => anyhow!("the server answered HTTP 403"),
            });
        }
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

    fn forbidden(body: &str) -> Vec<u8> {
        format!("HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len()).into_bytes()
    }

    #[test]
    fn device_errors_are_told_apart() {
        let e = parse_response(&forbidden(r#"{"error":"hwid_required","message":"This subscription limits devices."}"#)).unwrap_err();
        let d = device_error(&e).expect("a typed error");
        assert_eq!(d, &DeviceError::HwidRequired("This subscription limits devices.".into()));
        assert_eq!(d.code(), "hwid_required");
        assert_eq!(e.to_string(), "This subscription limits devices.");

        let e = parse_response(&forbidden(r#"{"error":"device_limit","message":"3 of 3 devices."}"#)).unwrap_err();
        assert_eq!(device_error(&e), Some(&DeviceError::DeviceLimit("3 of 3 devices.".into())));
        assert_eq!(device_error(&e).unwrap().code(), "device_limit");

        // A missing message gets a plain default, never an empty error.
        let e = parse_response(&forbidden(r#"{"error":"device_limit"}"#)).unwrap_err();
        assert!(!device_error(&e).unwrap().message().is_empty());
    }

    #[test]
    fn other_403_answers_are_ordinary_errors() {
        for body in [r#"{"error":"something_else","message":"x"}"#, "<html>Forbidden</html>", "", r#"{"message":"x"}"#] {
            let e = parse_response(&forbidden(body)).unwrap_err();
            assert!(device_error(&e).is_none(), "{body}");
            assert!(e.to_string().contains("403"), "{e}");
        }
        // Other codes keep their old messages.
        assert!(parse_response(b"HTTP/1.1 500 X\r\nContent-Length: 0\r\n\r\n").unwrap_err().to_string().contains("500"));
    }

    #[test]
    fn error_text_for_the_apps() {
        let e = parse_response(&forbidden(r#"{"error":"device_limit","message":"3 of 3 devices."}"#)).unwrap_err();
        assert_eq!(error_text(&e), "device:device_limit:3 of 3 devices.");
        let e = parse_response(&forbidden(r#"{"error":"hwid_required","message":"a\nb"}"#)).unwrap_err();
        assert_eq!(error_text(&e), "device:hwid_required:a b");
        let e = parse_response(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").unwrap_err();
        assert!(error_text(&e).contains("404") && !error_text(&e).starts_with("device:"));
    }

    fn url() -> Url {
        parse_url("https://vpn.example.com/sub/tok").unwrap()
    }

    #[test]
    fn proxy_strings_become_a_loopback_endpoint() {
        let ep = |s: &str| proxy_endpoint(s).unwrap();
        assert_eq!(ep("socks5h://127.0.0.1:1088"), Some(("127.0.0.1".into(), 1088)));
        assert_eq!(ep("127.0.0.1:1088"), Some(("127.0.0.1".into(), 1088)));
        // A wildcard bind is reached on loopback.
        assert_eq!(ep("0.0.0.0:9050"), Some(("127.0.0.1".into(), 9050)));
        assert_eq!(ep("[::]:9050"), Some(("::1".into(), 9050)));
        assert_eq!(ep("localhost:1"), Some(("localhost".into(), 1)));
        assert_eq!(ep("  "), None);
        assert!(proxy_endpoint("http://127.0.0.1:8080").is_err());
        assert!(proxy_endpoint("127.0.0.1").is_err());
        assert!(proxy_endpoint("127.0.0.1:0").is_err());
    }

    #[test]
    fn the_app_uses_the_proxy_only_when_asked_and_the_tunnel_is_up() {
        assert_eq!(app_proxy(true, true, None).as_deref(), Some("socks5h://127.0.0.1:1088"));
        assert_eq!(app_proxy(true, true, Some("127.0.0.1:9050")).as_deref(), Some("socks5h://127.0.0.1:9050"));
        assert_eq!(app_proxy(true, true, Some(" ")).as_deref(), Some("socks5h://127.0.0.1:1088"));
        assert_eq!(app_proxy(false, true, None), None, "setting off: direct");
        assert_eq!(app_proxy(true, false, None), None, "tunnel down: direct");
        // What it returns is what the connector understands, wildcard binds included.
        let p = app_proxy(true, true, Some("0.0.0.0:1088")).unwrap();
        assert_eq!(proxy_endpoint(&p).unwrap(), Some(("127.0.0.1".into(), 1088)));
    }

    #[test]
    fn socks5_request_sends_the_name_not_an_address() {
        let r = socks5_connect_request("api.github.com", 443).unwrap();
        assert_eq!(&r[..4], &[5, 1, 0, 3]);
        assert_eq!(r[4] as usize, "api.github.com".len());
        assert_eq!(&r[5..5 + 14], b"api.github.com");
        assert_eq!(&r[19..], &443u16.to_be_bytes());
        assert_eq!(socks5_connect_request("1.2.3.4", 80).unwrap(), vec![5, 1, 0, 1, 1, 2, 3, 4, 0, 80]);
        assert_eq!(socks5_connect_request("::1", 80).unwrap()[3], 4);
    }

    /// A one-shot SOCKS5 proxy: returns the address it listens on and the
    /// (host, port) it was asked for; `reply` is the SOCKS reply code.
    async fn fake_proxy(reply: u8) -> (String, tokio::task::JoinHandle<(String, u16)>) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let h = tokio::spawn(async move {
            let (mut c, _) = l.accept().await.unwrap();
            let mut g = [0u8; 3];
            c.read_exact(&mut g).await.unwrap();
            assert_eq!(g, [5, 1, 0]);
            c.write_all(&[5, 0]).await.unwrap();
            let mut h = [0u8; 5];
            c.read_exact(&mut h).await.unwrap();
            assert_eq!(&h[..4], &[5, 1, 0, 3]);
            let mut name = vec![0u8; h[4] as usize + 2];
            c.read_exact(&mut name).await.unwrap();
            let port = u16::from_be_bytes([name[name.len() - 2], name[name.len() - 1]]);
            let host = String::from_utf8(name[..name.len() - 2].to_vec()).unwrap();
            c.write_all(&[5, reply, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
            (host, port)
        });
        (addr, h)
    }

    #[tokio::test]
    async fn connects_through_the_proxy_with_the_name() {
        let (addr, asked) = fake_proxy(0).await;
        let s = connect_tcp("vpn.example.com", 443, Some(&format!("socks5h://{addr}"))).await;
        assert!(s.is_ok(), "{:?}", s.err());
        assert_eq!(asked.await.unwrap(), ("vpn.example.com".to_string(), 443));
    }

    #[tokio::test]
    async fn a_refusal_from_the_tunnel_is_an_error_not_a_direct_retry() {
        let (addr, _asked) = fake_proxy(4).await;
        let e = connect_tcp("vpn.example.com", 443, Some(&addr)).await.unwrap_err();
        assert!(e.to_string().contains("nothing was sent outside the tunnel"), "{e}");
    }

    #[tokio::test]
    async fn a_dead_proxy_is_an_error_not_a_direct_retry() {
        // Bind and drop: nothing listens on this port any more.
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        drop(l);
        let e = connect_tcp("vpn.example.com", 443, Some(&addr)).await.unwrap_err();
        assert!(e.to_string().contains("local proxy"), "{e}");
    }

    #[test]
    fn no_device_means_no_device_headers() {
        let head = request_head(&url(), "application/json", None);
        assert!(head.starts_with("GET /sub/tok HTTP/1.1\r\nHost: vpn.example.com\r\n"), "{head}");
        let lower = head.to_ascii_lowercase();
        assert!(!lower.contains("x-hwid") && !lower.contains("x-device"), "{head}");
        assert!(head.ends_with("Connection: close\r\n\r\n"));
    }

    #[test]
    fn a_device_adds_the_three_headers() {
        let d = Device { hwid: "572c291ff9921f090783fd3d22d69228".into(), os: "Windows 11".into(), model: "x86_64".into() };
        let head = request_head(&url(), "application/json", Some(&d));
        assert!(head.contains("\r\nx-hwid: 572c291ff9921f090783fd3d22d69228\r\n"), "{head}");
        assert!(head.contains("\r\nx-device-os: Windows 11\r\n"), "{head}");
        assert!(head.contains("\r\nx-device-model: x86_64\r\n"), "{head}");
        assert!(head.ends_with("Connection: close\r\n\r\n"));
    }

    #[test]
    fn header_values_cannot_break_the_request() {
        let d = Device { hwid: "abc".into(), os: "A\r\nEvil: 1".into(), model: "é".repeat(100) + &"x".repeat(100) };
        let head = request_head(&url(), "application/json", Some(&d));
        assert_eq!(head.matches("\r\n\r\n").count(), 1, "{head:?}");
        assert!(!head.contains("\nEvil"), "{head:?}");
        let model = head.lines().find(|l| l.starts_with("x-device-model: ")).unwrap();
        assert!(model.len() <= "x-device-model: ".len() + 64, "{model}");
        assert!(head.is_ascii());
        // An empty model is left out instead of sent empty.
        let d = Device { hwid: "abc".into(), os: "Linux".into(), model: "  ".into() };
        assert!(!request_head(&url(), "application/json", Some(&d)).contains("x-device-model"));
    }
}
