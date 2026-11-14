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
    let u = parse_url(url)?;
    let body = tokio::time::timeout(TIMEOUT, get(&u, "application/json", device))
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
pub(crate) async fn https_get(url: &str, accept: &str) -> Result<(u16, Vec<u8>)> {
    let u = parse_url(url)?;
    let raw = tokio::time::timeout(TIMEOUT, get_raw(&u, accept, None))
        .await
        .map_err(|_| anyhow!("{} did not answer within {}s", u.host, TIMEOUT.as_secs()))??;
    split_response(&raw)
}

async fn get(u: &Url, accept: &str, device: Option<&Device>) -> Result<Vec<u8>> {
    parse_response(&get_raw(u, accept, device).await?)
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

async fn get_raw(u: &Url, accept: &str, device: Option<&Device>) -> Result<Vec<u8>> {
    let tcp = tokio::net::TcpStream::connect((u.host.as_str(), u.port))
        .await
        .with_context(|| format!("cannot connect to {}:{}", u.host, u.port))?;
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
