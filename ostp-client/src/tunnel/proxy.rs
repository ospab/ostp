use std::collections::HashMap;
use anyhow::{anyhow, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio::time::{timeout, Duration};

use crate::config::{ExclusionConfig, LocalProxyConfig, OstpConfig};
use crate::tunnel::{ProxyEvent, ProxyToClientMsg};

pub async fn run_local_socks5_proxy(
    cfg: LocalProxyConfig,
    ostp: OstpConfig,
    exclusions: ExclusionConfig,
    debug: bool,
    mut shutdown: watch::Receiver<bool>,
    proxy_events_tx: mpsc::Sender<ProxyEvent>,
    mut client_msgs_rx: mpsc::UnboundedReceiver<(u16, ProxyToClientMsg)>,
) -> Result<()> {
    let connect_timeout = Duration::from_millis(cfg.connect_timeout_ms.max(1));
    let listener = TcpListener::bind(&cfg.bind_addr)
        .await
        .with_context(|| format!("failed to bind local HTTP/SOCKS5 proxy at {}", cfg.bind_addr))?;

    if debug {
        tracing::info!("local HTTP/SOCKS5 proxy listening at {}", cfg.bind_addr);
        tracing::info!("Windows system proxy: set HTTP proxy to {}. tun2socks: SOCKS5 on same address.", cfg.bind_addr);
    }

    let matcher = ExclusionMatcher::new(&exclusions);
    let (connect_tx, mut connect_rx) = mpsc::channel(128);
    let max_chunk = ostp.mtu.saturating_sub(150).max(512);

    let mut next_stream_id: u16 = 1;
    let mut active_streams: HashMap<u16, mpsc::UnboundedSender<ProxyToClientMsg>> = HashMap::new();

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let (socket, _) = accepted?;
                let stream_id = next_stream_id;
                // Advance, skipping zero and any stream_id still in active_streams
                loop {
                    next_stream_id = next_stream_id.wrapping_add(1);
                    if next_stream_id == 0 { next_stream_id = 1; }
                    if !active_streams.contains_key(&next_stream_id) { break; }
                }

                let (tx, rx) = mpsc::unbounded_channel();
                active_streams.insert(stream_id, tx);

                let event_tx = proxy_events_tx.clone();
                let c_tx = connect_tx.clone();
                let matcher_clone = matcher.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_proxy_client(
                        socket,
                        stream_id,
                        event_tx,
                        rx,
                        c_tx,
                        connect_timeout,
                        debug,
                        matcher_clone,
                        max_chunk,
                    ).await {
                        let msg = err.to_string();
                        // Suppress routine disconnects and unsupported SOCKS5 command attempts (like UDP) from spam logs
                        if !msg.contains("UnexpectedEof")
                            && !msg.contains("Connection reset")
                            && !msg.contains("Broken pipe")
                            && !msg.contains("unsupported SOCKS5 command")
                            && debug {
                                tracing::warn!("proxy client error: {err}");
                            }
                    }
                });
            }
            Some((stream_id, msg)) = client_msgs_rx.recv() => {
                if stream_id == 0 {
                    if let ProxyToClientMsg::Close = msg {
                        if debug {
                            tracing::info!("Resetting all active proxy streams on reconnect");
                        }
                        for (_, tx) in active_streams.drain() {
                            let _ = tx.send(ProxyToClientMsg::Close);
                        }
                    }
                } else if let Some(tx) = active_streams.get(&stream_id) {
                    if tx.send(msg).is_err() {
                        active_streams.remove(&stream_id);
                    }
                }
            }
            Some(stream_id) = connect_rx.recv() => {
                active_streams.remove(&stream_id);
            }
        }
    }

    Ok(())
}

/// Extracts `host:port` from an HTTP absolute-URI like `http://example.com/path` or `https://example.com`.
/// Falls back to the raw target if already in `host:port` form.
fn extract_host_port(uri: &str, default_port: u16) -> String {
    let without_scheme = if let Some(rest) = uri.strip_prefix("https://") {
        rest
    } else if let Some(rest) = uri.strip_prefix("http://") {
        rest
    } else {
        uri
    };
    // Trim path/query fragment
    let host_part = without_scheme.split('/').next().unwrap_or(without_scheme);
    if host_part.contains(':') {
        host_part.to_string()
    } else {
        format!("{}:{}", host_part, default_port)
    }
}

struct StreamGuard {
    stream_id: u16,
    close_tx: mpsc::Sender<u16>,
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        let tx = self.close_tx.clone();
        let id = self.stream_id;
        tokio::spawn(async move {
            let _ = tx.send(id).await;
        });
    }
}

async fn handle_proxy_client(
    mut client: TcpStream,
    stream_id: u16,
    event_tx: mpsc::Sender<ProxyEvent>,
    mut rx: mpsc::UnboundedReceiver<ProxyToClientMsg>,
    close_tx: mpsc::Sender<u16>,
    connect_timeout: Duration,
    debug: bool,
    matcher: ExclusionMatcher,
    max_chunk: usize,
) -> Result<()> {
    let _guard = StreamGuard { stream_id, close_tx: close_tx.clone() };

    // Peek the first byte to distinguish SOCKS5 (0x05) from HTTP (any printable ASCII)
    let mut first_byte = [0_u8; 1];
    client.read_exact(&mut first_byte).await?;

    let target: String;
    let is_socks5 = first_byte[0] == 0x05;

    if is_socks5 {
        // ── SOCKS5 Handshake ──────────────────────────────────────────
        let mut second_byte = [0_u8; 1];
        client.read_exact(&mut second_byte).await?;
        let nmethods = second_byte[0] as usize;
        if nmethods > 0 {
            let mut methods_buf = vec![0_u8; nmethods];
            client.read_exact(&mut methods_buf).await?;
        }
        // Reply: version=5, NO AUTHENTICATION
        client.write_all(&[0x05, 0x00]).await?;

        // ── SOCKS5 Request ────────────────────────────────────────────
        let mut req = [0_u8; 4];
        client.read_exact(&mut req).await?;
        if req[0] != 0x05 {
            return Err(anyhow!("SOCKS5 request version mismatch"));
        }
        if req[1] != 0x01 {
            // Not CONNECT — send COMMAND NOT SUPPORTED
            client.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            return Err(anyhow!("unsupported SOCKS5 command {}", req[1]));
        }

        let mut addr_buf = [0_u8; 256];
        target = match req[3] {
            0x01 => {
                // IPv4: 4 bytes address + 2 bytes port
                client.read_exact(&mut addr_buf[0..6]).await?;
                let ip = std::net::Ipv4Addr::new(addr_buf[0], addr_buf[1], addr_buf[2], addr_buf[3]);
                let port = u16::from_be_bytes([addr_buf[4], addr_buf[5]]);
                format!("{}:{}", ip, port)
            }
            0x03 => {
                // Domain: 1 byte length, then domain, then 2 bytes port
                client.read_exact(&mut addr_buf[0..1]).await?;
                let domain_len = addr_buf[0] as usize;
                client.read_exact(&mut addr_buf[0..domain_len + 2]).await?;
                let domain = String::from_utf8_lossy(&addr_buf[0..domain_len]);
                let port = u16::from_be_bytes([addr_buf[domain_len], addr_buf[domain_len + 1]]);
                format!("{}:{}", domain, port)
            }
            0x04 => {
                // IPv6: 16 bytes + 2 bytes port
                client.read_exact(&mut addr_buf[0..18]).await?;
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&addr_buf[0..16]);
                let ip = std::net::Ipv6Addr::from(octets);
                let port = u16::from_be_bytes([addr_buf[16], addr_buf[17]]);
                format!("[{}]:{}", ip, port)
            }
            atyp => {
                client.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
                return Err(anyhow!("unsupported SOCKS5 address type: {}", atyp));
            }
        };

        if debug {
            tracing::info!("proxy CONNECT stream_id={stream_id} target={target}");
        }
        if matcher.should_bypass(&target, connect_timeout).await {
            return direct_connect_socks5(client, stream_id, &target, close_tx, debug).await;
        }
        event_tx.send(ProxyEvent::NewStream { stream_id, target: target.clone() }).await?;

        match timeout(connect_timeout, rx.recv()).await {
            Ok(Some(ProxyToClientMsg::ConnectOk)) => {
                // SUCCESS: version, 0=success, reserved, IPv4 type, 4 bytes addr, 2 bytes port
                client.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            }
            Ok(Some(ProxyToClientMsg::Error(msg))) => {
                client.write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
                let _ = close_tx.send(stream_id).await;
                return Err(anyhow!("SOCKS5 connect error: {msg}"));
            }
            Ok(_) => {
                client.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
                let _ = close_tx.send(stream_id).await;
                return Err(anyhow!("connect dropped"));
            }
            Err(_) => {
                client.write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
                let _ = close_tx.send(stream_id).await;
                return Err(anyhow!("connect timeout"));
            }
        }
    } else {
        // ── HTTP Proxy (CONNECT and plain GET/POST) ───────────────────
        // Read the rest of the HTTP request headers byte-by-byte
        let mut header_bytes = Vec::with_capacity(512);
        header_bytes.push(first_byte[0]);
        let mut chunk = [0_u8; 512];
        loop {
            let n = client.read(&mut chunk).await?;
            if n == 0 {
                return Err(anyhow!("connection closed during HTTP header read"));
            }
            header_bytes.extend_from_slice(&chunk[..n]);
            if header_bytes.len() >= 4 {
                let tail = &header_bytes[header_bytes.len().saturating_sub(4)..];
                if tail.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            if header_bytes.len() > 8192 {
                client.write_all(b"HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n").await?;
                return Err(anyhow!("HTTP header too large"));
            }
        }

        let req_str = String::from_utf8_lossy(&header_bytes);
        let first_line = req_str.lines().next().unwrap_or("");
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() < 2 {
            client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await?;
            return Err(anyhow!("malformed HTTP request line: {:?}", first_line));
        }

        let method = parts[0].to_uppercase();
        let raw_uri = parts[1];

        target = if method == "CONNECT" {
            // CONNECT uses host:port directly — e.g. "CONNECT example.com:443 HTTP/1.1"
            if raw_uri.contains(':') {
                raw_uri.to_string()
            } else {
                format!("{}:443", raw_uri)
            }
        } else {
            // Plain HTTP: absolute URI like "GET http://example.com/path HTTP/1.1"
            let default_port = if raw_uri.starts_with("https://") { 443u16 } else { 80u16 };
            extract_host_port(raw_uri, default_port)
        };

        if debug {
            tracing::info!("proxy CONNECT stream_id={stream_id} target={target}");
        }
        if matcher.should_bypass(&target, connect_timeout).await {
            return direct_connect_http(
                client,
                stream_id,
                &target,
                method.as_str(),
                header_bytes,
                close_tx,
                debug,
            ).await;
        }
        event_tx.send(ProxyEvent::NewStream { stream_id, target: target.clone() }).await?;

        match timeout(connect_timeout, rx.recv()).await {
            Ok(Some(ProxyToClientMsg::ConnectOk)) => {
                if method == "CONNECT" {
                    // For CONNECT, tell client the tunnel is ready
                    client.write_all(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: ostp/1.0\r\n\r\n").await?;
                } else {
                    // For plain HTTP (GET/POST), we MUST forward the request headers we consumed
                    // to the server over the newly established tunnel.
                    event_tx.send(ProxyEvent::Data {
                        stream_id,
                        payload: bytes::Bytes::copy_from_slice(&header_bytes),
                    }).await?;
                }
            }
            Ok(Some(ProxyToClientMsg::Error(msg))) => {
                client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await?;
                let _ = close_tx.send(stream_id).await;
                return Err(anyhow!("HTTP connect error: {msg}"));
            }
            Ok(_) => {
                client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await?;
                let _ = close_tx.send(stream_id).await;
                return Err(anyhow!("connect dropped"));
            }
            Err(_) => {
                client.write_all(b"HTTP/1.1 504 Gateway Timeout\r\n\r\n").await?;
                let _ = close_tx.send(stream_id).await;
                return Err(anyhow!("connect timeout"));
            }
        }
    }

    // ── Bidirectional raw data forwarding ─────────────────────────────
    let mut tcp_buf = vec![0_u8; 65536];
    loop {
        tokio::select! {
            read_res = client.read(&mut tcp_buf) => {
                match read_res {
                    Ok(0) => {
                        let _ = event_tx.send(ProxyEvent::Close { stream_id }).await;
                        if debug {
                            tracing::info!("proxy CLOSE stream_id={stream_id}");
                        }
                        break;
                    }
                    Ok(n) => {
                        let mut offset = 0;
                        while offset < n {
                            let end = (offset + max_chunk).min(n);
                            let _ = event_tx.send(ProxyEvent::Data {
                                stream_id,
                                payload: bytes::Bytes::copy_from_slice(&tcp_buf[offset..end]),
                            }).await;
                            offset = end;
                        }
                    }
                    Err(_) => {
                        let _ = event_tx.send(ProxyEvent::Close { stream_id }).await;
                        if debug {
                            tracing::info!("proxy CLOSE stream_id={stream_id}");
                        }
                        break;
                    }
                }
            }
            msg = rx.recv() => {
                match msg {
                    Some(ProxyToClientMsg::Data(data)) => {
                        if client.write_all(&data).await.is_err() {
                            let _ = event_tx.send(ProxyEvent::Close { stream_id }).await;
                            break;
                        }
                    }
                    Some(ProxyToClientMsg::Close) | Some(ProxyToClientMsg::Error(_)) | None => {
                        break;
                    }
                    Some(ProxyToClientMsg::ConnectOk) => {} // ignored after connect phase
                }
            }
        }
    }

    let _ = close_tx.send(stream_id).await;
    Ok(())
}

#[derive(Clone)]
struct ExclusionMatcher {
    domain_suffix: Vec<String>,
    cidrs: Vec<Cidr>,
}

impl ExclusionMatcher {
    fn new(exclusions: &ExclusionConfig) -> Self {
        let mut cidrs = Vec::new();
        for ip in &exclusions.ips {
            if let Some(cidr) = parse_cidr(ip) {
                cidrs.push(cidr);
            }
        }

        Self {
            domain_suffix: exclusions
                .domains
                .iter()
                .map(|d| d.trim().trim_start_matches('.').to_lowercase())
                .filter(|d| !d.is_empty())
                .collect(),
            cidrs,
        }
    }

    async fn should_bypass(&self, target: &str, timeout_value: Duration) -> bool {
        let (host, port) = match split_host_port(target) {
            Some(v) => v,
            None => return false,
        };

        if self.match_domain(&host) {
            return true;
        }

        if self.cidrs.is_empty() {
            return false;
        }

        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            return self.match_ip(&ip);
        }

        let lookup_target = (host.clone(), port);
        match timeout(timeout_value, tokio::net::lookup_host(lookup_target)).await {
            Ok(Ok(addrs)) => addrs.into_iter().any(|addr| self.match_ip(&addr.ip())),
            _ => false,
        }
    }

    fn match_domain(&self, host: &str) -> bool {
        if self.domain_suffix.is_empty() {
            return false;
        }
        let host = host.trim_end_matches('.').to_lowercase();
        self.domain_suffix.iter().any(|suffix| {
            host == *suffix || host.ends_with(&format!(".{suffix}"))
        })
    }

    fn match_ip(&self, ip: &std::net::IpAddr) -> bool {
        self.cidrs.iter().any(|cidr| cidr.contains(ip))
    }
}

#[derive(Clone)]
enum Cidr {
    V4(u32, u8),
    V6(u128, u8),
}

impl Cidr {
    fn contains(&self, ip: &std::net::IpAddr) -> bool {
        match (self, ip) {
            (Cidr::V4(net, bits), std::net::IpAddr::V4(addr)) => {
                let mask = if *bits == 0 { 0 } else { u32::MAX << (32 - bits) };
                let ip = u32::from_be_bytes(addr.octets());
                (ip & mask) == (*net & mask)
            }
            (Cidr::V6(net, bits), std::net::IpAddr::V6(addr)) => {
                let mask = if *bits == 0 { 0 } else { u128::MAX << (128 - bits) };
                let ip = u128::from_be_bytes(addr.octets());
                (ip & mask) == (*net & mask)
            }
            _ => false,
        }
    }
}

fn parse_cidr(value: &str) -> Option<Cidr> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    if let Some((addr_str, bits_str)) = value.split_once('/') {
        let bits: u8 = bits_str.parse().ok()?;
        if let Ok(addr) = addr_str.parse::<std::net::IpAddr>() {
            return match addr {
                std::net::IpAddr::V4(v4) => Some(Cidr::V4(u32::from_be_bytes(v4.octets()), bits.min(32))),
                std::net::IpAddr::V6(v6) => Some(Cidr::V6(u128::from_be_bytes(v6.octets()), bits.min(128))),
            };
        }
    }

    if let Ok(addr) = value.parse::<std::net::IpAddr>() {
        return match addr {
            std::net::IpAddr::V4(v4) => Some(Cidr::V4(u32::from_be_bytes(v4.octets()), 32)),
            std::net::IpAddr::V6(v6) => Some(Cidr::V6(u128::from_be_bytes(v6.octets()), 128)),
        };
    }

    None
}

fn split_host_port(target: &str) -> Option<(String, u16)> {
    if let Some((host, port)) = target.rsplit_once(':') {
        if host.starts_with('[') && host.ends_with(']') {
            let host = host.trim_start_matches('[').trim_end_matches(']').to_string();
            let port = port.parse().ok()?;
            return Some((host, port));
        }
        if host.contains(':') {
            return None;
        }
        let port = port.parse().ok()?;
        return Some((host.to_string(), port));
    }
    None
}

async fn direct_connect_socks5(
    mut client: TcpStream,
    stream_id: u16,
    target: &str,
    close_tx: mpsc::Sender<u16>,
    debug: bool,
) -> Result<()> {
    if debug {
        tracing::info!("proxy BYPASS stream_id={stream_id} target={target}");
    }
    let mut remote = TcpStream::connect(target).await
        .with_context(|| format!("direct connect failed: {target}"))?;

    client.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
    let _ = tokio::io::copy_bidirectional(&mut client, &mut remote).await;
    let _ = close_tx.send(stream_id).await;
    Ok(())
}

async fn direct_connect_http(
    mut client: TcpStream,
    stream_id: u16,
    target: &str,
    method: &str,
    header_bytes: Vec<u8>,
    close_tx: mpsc::Sender<u16>,
    debug: bool,
) -> Result<()> {
    if debug {
        tracing::info!("proxy BYPASS stream_id={stream_id} target={target}");
    }
    let mut remote = TcpStream::connect(target).await
        .with_context(|| format!("direct connect failed: {target}"))?;

    if method == "CONNECT" {
        client.write_all(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: ostp/1.0\r\n\r\n").await?;
    } else {
        remote.write_all(&header_bytes).await?;
    }

    let _ = tokio::io::copy_bidirectional(&mut client, &mut remote).await;
    let _ = close_tx.send(stream_id).await;
    Ok(())
}
