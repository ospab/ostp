//! TCP listener that tells OSTP apart from everything else on the same port.
//!
//! Classification is by the first byte:
//! - `0x00..=0x05`: a raw UoT stream (high byte of a u16 frame length <= 1350);
//! - `0x16`: a TLS ClientHello;
//! - `A..=Z`: an HTTP request, which is either the secret-path upgrade that a
//!   local web server (or a client) uses to reach OSTP, or anything else,
//!   which gets the decoy;
//! - anything else is handed to the UoT reader exactly as before, so random
//!   probe bytes see the same behaviour as they always have.

use anyhow::Result;
use bytes::{Bytes, BytesMut};
use ostp_core::http_upgrade::{build_upgrade_response, find_head_end, ws_accept_key, MAX_HEAD_BYTES};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, OwnedSemaphorePermit, RwLock, Semaphore};
use tokio::time::{timeout_at, Instant};

use super::limiter::{is_trusted_proxy, ConnLimiter};
use super::rewind::Rewind;

pub type TcpMap = Arc<RwLock<HashMap<SocketAddr, mpsc::Sender<Bytes>>>>;

/// Time a connection gets to show what it is (first byte, TLS handshake, HTTP head).
const CLASSIFY_TIMEOUT: Duration = Duration::from_secs(10);
/// Connections still being classified; beyond this new ones are dropped.
pub const MAX_PENDING: usize = 2048;

/// What non-OSTP traffic gets.
#[derive(Debug, Clone)]
pub enum Decoy {
    /// A bare 404 for HTTP; anything else is closed.
    NotFound,
    /// Spliced to a real web server (the old `fallback.target`).
    Proxy(String),
}

pub struct SniffCtx {
    pub ws_path: Option<String>,
    pub decoy: Decoy,
    pub limiter: Arc<ConnLimiter>,
    pub pending: Arc<Semaphore>,
    pub tcp_map: TcpMap,
    pub udp_tx: mpsc::Sender<(Bytes, SocketAddr)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    Uot,
    Tls,
    Http,
    Legacy,
}

fn classify(first: u8) -> Class {
    match first {
        0x00..=0x05 => Class::Uot,
        0x16 => Class::Tls,
        b'A'..=b'Z' => Class::Http,
        _ => Class::Legacy,
    }
}

pub async fn serve_listener(listener: TcpListener, ctx: Arc<SniffCtx>) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!("TCP accept error: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        // Nagle batches the download direction against the client's delayed
        // ACKs, stalling streams; every TCP tunnel sets nodelay.
        let _ = stream.set_nodelay(true);

        // Loopback peers are a local web server fronting OSTP; they are limited
        // per forwarded client address once the request head is read.
        if !is_trusted_proxy(peer) && !ctx.limiter.check(peer.ip()) {
            tracing::debug!("TCP rate limit exceeded for {}, dropping connection", peer.ip());
            continue;
        }
        let Ok(permit) = ctx.pending.clone().try_acquire_owned() else {
            tracing::debug!("too many unclassified TCP connections, dropping {peer}");
            continue;
        };

        let ctx = ctx.clone();
        tokio::spawn(async move {
            let deadline = Instant::now() + CLASSIFY_TIMEOUT;
            if let Err(e) = dispatch(stream, BytesMut::new(), peer, ctx, permit, deadline).await {
                tracing::debug!("TCP connection from {peer} closed: {e}");
            }
        });
    }
}

/// Routes a connection given the bytes already read off it (possibly none).
async fn dispatch<S>(
    mut s: S,
    mut buf: BytesMut,
    peer: SocketAddr,
    ctx: Arc<SniffCtx>,
    permit: OwnedSemaphorePermit,
    deadline: Instant,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if buf.is_empty() {
        buf.reserve(2048);
        if read_more(&mut s, &mut buf, deadline).await? == 0 {
            return Ok(());
        }
    }

    match classify(buf[0]) {
        Class::Uot | Class::Legacy => {
            drop(permit);
            crate::transport::uot::handle_tcp_connection(
                Rewind::new(s, buf.freeze()),
                peer,
                ctx.tcp_map.clone(),
                ctx.udp_tx.clone(),
            )
            .await
        }
        Class::Tls => decoy(s, buf, &ctx).await,
        Class::Http => route_http(s, buf, peer, ctx, permit, deadline).await,
    }
}

async fn route_http<S>(
    mut s: S,
    mut buf: BytesMut,
    peer: SocketAddr,
    ctx: Arc<SniffCtx>,
    permit: OwnedSemaphorePermit,
    deadline: Instant,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let head_len = loop {
        if let Some(n) = find_head_end(&buf) {
            break n;
        }
        if buf.len() >= MAX_HEAD_BYTES {
            return decoy(s, buf, &ctx).await;
        }
        if read_more(&mut s, &mut buf, deadline).await? == 0 {
            return Ok(());
        }
    };

    let upgrade = parse_upgrade(&buf[..head_len], ctx.ws_path.as_deref(), peer);
    let Some(upgrade) = upgrade else {
        return decoy(s, buf, &ctx).await;
    };

    if let Some(real_ip) = upgrade.forwarded_for {
        if !ctx.limiter.check(real_ip) {
            tracing::debug!("TCP rate limit exceeded for {real_ip} (via {peer}), dropping connection");
            return Ok(());
        }
    }
    tracing::debug!(
        "UoT upgrade from {} (via {peer})",
        upgrade.forwarded_for.map(|ip| ip.to_string()).unwrap_or_else(|| peer.ip().to_string())
    );

    s.write_all(&build_upgrade_response(&ws_accept_key(&upgrade.ws_key))).await?;
    let leftover = buf.split_off(head_len).freeze();
    drop(permit);
    crate::transport::uot::handle_tcp_connection(
        Rewind::new(s, leftover),
        peer,
        ctx.tcp_map.clone(),
        ctx.udp_tx.clone(),
    )
    .await
}

struct Upgrade {
    ws_key: String,
    /// The client address a trusted local proxy reported, if any.
    forwarded_for: Option<IpAddr>,
}

/// Accepts only `GET <ws_path>` with a complete WebSocket-shaped upgrade.
/// Anything else, including the right path with wrong headers, is `None`, so
/// a prober cannot tell the secret path from any other 404.
fn parse_upgrade(head: &[u8], ws_path: Option<&str>, peer: SocketAddr) -> Option<Upgrade> {
    let ws_path = ws_path?;
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(head) {
        Ok(httparse::Status::Complete(_)) => {}
        _ => return None,
    }
    if req.method != Some("GET") {
        return None;
    }
    let path = req.path.unwrap_or("");
    if path.len() != ws_path.len() || !bool::from(path.as_bytes().ct_eq(ws_path.as_bytes())) {
        return None;
    }

    let header = |name: &str| {
        req.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .and_then(|h| std::str::from_utf8(h.value).ok())
            .map(str::trim)
    };
    if !header("upgrade").is_some_and(|v| v.eq_ignore_ascii_case("websocket")) {
        return None;
    }
    if !header("connection")
        .is_some_and(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("upgrade")))
    {
        return None;
    }
    let ws_key = header("sec-websocket-key").filter(|k| !k.is_empty())?.to_string();

    // Only a local web server is trusted to say who the client is; on a public
    // port these headers are attacker-controlled and ignored.
    let forwarded_for = if is_trusted_proxy(peer) {
        header("x-real-ip")
            .and_then(|v| v.parse::<IpAddr>().ok())
            .or_else(|| {
                header("x-forwarded-for")
                    .and_then(|v| v.rsplit(',').next())
                    .and_then(|v| v.trim().parse::<IpAddr>().ok())
            })
    } else {
        None
    };

    Some(Upgrade { ws_key, forwarded_for })
}

async fn read_more<S: AsyncRead + Unpin>(s: &mut S, buf: &mut BytesMut, deadline: Instant) -> Result<usize> {
    if buf.capacity() - buf.len() < 1024 {
        buf.reserve(2048);
    }
    match timeout_at(deadline, s.read_buf(buf)).await {
        Ok(r) => Ok(r?),
        Err(_) => Ok(0),
    }
}

const NOT_FOUND: &[u8] = b"HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\nContent-Length: 48\r\nConnection: close\r\n\r\n<html><body><h1>404 Not Found</h1></body></html>";

async fn decoy<S>(mut s: S, buf: BytesMut, ctx: &SniffCtx) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    match &ctx.decoy {
        Decoy::Proxy(target) => crate::fallback::proxy_with_prefix(s, buf.freeze(), target).await,
        Decoy::NotFound => {
            if buf.first().is_some_and(|b| b.is_ascii_uppercase()) {
                s.write_all(NOT_FOUND).await?;
            }
            let _ = s.shutdown().await;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ostp_core::http_upgrade::build_upgrade_request;

    fn public() -> SocketAddr {
        "203.0.113.7:4000".parse().unwrap()
    }
    fn local() -> SocketAddr {
        "127.0.0.1:4000".parse().unwrap()
    }

    #[test]
    fn classification_table() {
        for b in 0x00..=0x05u8 {
            assert_eq!(classify(b), Class::Uot);
        }
        assert_eq!(classify(0x16), Class::Tls);
        assert_eq!(classify(b'G'), Class::Http);
        assert_eq!(classify(b'C'), Class::Http);
        assert_eq!(classify(0x06), Class::Legacy);
        assert_eq!(classify(0xff), Class::Legacy);
        assert_eq!(classify(b'g'), Class::Legacy);
    }

    #[test]
    fn accepts_exact_upgrade_on_secret_path() {
        let req = build_upgrade_request("/s3cr3t", "vpn.example.com", "dGhlIHNhbXBsZSBub25jZQ==");
        let up = parse_upgrade(&req, Some("/s3cr3t"), public()).expect("valid upgrade");
        assert_eq!(up.ws_key, "dGhlIHNhbXBsZSBub25jZQ==");
        assert_eq!(up.forwarded_for, None);
    }

    #[test]
    fn rejects_wrong_path_missing_headers_or_no_ws_path() {
        let req = build_upgrade_request("/s3cr3t", "h", "k");
        assert!(parse_upgrade(&req, Some("/other"), public()).is_none());
        assert!(parse_upgrade(&req, Some("/s3cr3t/"), public()).is_none());
        assert!(parse_upgrade(&req, None, public()).is_none());

        let no_key = b"GET /s3cr3t HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
        assert!(parse_upgrade(no_key, Some("/s3cr3t"), public()).is_none());
        let plain = b"GET /s3cr3t HTTP/1.1\r\nHost: h\r\n\r\n";
        assert!(parse_upgrade(plain, Some("/s3cr3t"), public()).is_none());
        let post = b"POST /s3cr3t HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: k\r\n\r\n";
        assert!(parse_upgrade(post, Some("/s3cr3t"), public()).is_none());
    }

    #[test]
    fn header_names_and_connection_tokens_are_case_insensitive() {
        let req = b"GET /p HTTP/1.1\r\nupgrade: WebSocket\r\nconnection: keep-alive, Upgrade\r\nsec-websocket-key: k\r\n\r\n";
        assert!(parse_upgrade(req, Some("/p"), public()).is_some());
    }

    #[test]
    fn forwarded_address_is_trusted_only_from_loopback() {
        let req = b"GET /p HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: k\r\nX-Forwarded-For: 10.0.0.1, 198.51.100.4\r\n\r\n";
        let ip: IpAddr = "198.51.100.4".parse().unwrap();
        assert_eq!(parse_upgrade(req, Some("/p"), local()).unwrap().forwarded_for, Some(ip));
        assert_eq!(parse_upgrade(req, Some("/p"), public()).unwrap().forwarded_for, None);

        let real = b"GET /p HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: k\r\nX-Real-IP: 192.0.2.9\r\nX-Forwarded-For: 198.51.100.4\r\n\r\n";
        assert_eq!(
            parse_upgrade(real, Some("/p"), local()).unwrap().forwarded_for,
            Some("192.0.2.9".parse().unwrap())
        );
    }

    fn ctx(ws_path: Option<&str>) -> (Arc<SniffCtx>, mpsc::Receiver<(Bytes, SocketAddr)>) {
        let (udp_tx, udp_rx) = mpsc::channel(16);
        (
            Arc::new(SniffCtx {
                ws_path: ws_path.map(str::to_string),
                decoy: Decoy::NotFound,
                limiter: Arc::new(ConnLimiter::new()),
                pending: Arc::new(Semaphore::new(MAX_PENDING)),
                tcp_map: Arc::new(RwLock::new(HashMap::new())),
                udp_tx,
            }),
            udp_rx,
        )
    }

    async fn run(ctx: Arc<SniffCtx>) -> tokio::io::DuplexStream {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let permit = ctx.pending.clone().try_acquire_owned().unwrap();
        tokio::spawn(dispatch(server, BytesMut::new(), public(), ctx, permit, Instant::now() + CLASSIFY_TIMEOUT));
        client
    }

    #[tokio::test]
    async fn raw_uot_frames_reach_the_dispatcher() {
        let (ctx, mut udp_rx) = ctx(None);
        let mut c = run(ctx).await;
        c.write_all(&[0x00, 0x03, b'a', b'b', b'c']).await.unwrap();
        let (frame, from) = udp_rx.recv().await.unwrap();
        assert_eq!(frame.as_ref(), b"abc");
        assert_eq!(from, public());
    }

    #[tokio::test]
    async fn upgrade_then_frames_pipelined_in_the_same_write() {
        let (ctx, mut udp_rx) = ctx(Some("/s3cr3t"));
        let mut c = run(ctx).await;
        let mut req = build_upgrade_request("/s3cr3t", "h", "dGhlIHNhbXBsZSBub25jZQ==");
        req.extend_from_slice(&[0x00, 0x02, b'h', b'i']);
        c.write_all(&req).await.unwrap();

        let mut resp = vec![0u8; 256];
        let n = c.read(&mut resp).await.unwrap();
        let resp = String::from_utf8_lossy(&resp[..n]);
        assert!(resp.starts_with("HTTP/1.1 101 "), "{resp}");
        assert!(resp.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="), "{resp}");

        let (frame, _) = udp_rx.recv().await.unwrap();
        assert_eq!(frame.as_ref(), b"hi");
    }

    #[tokio::test]
    async fn wrong_path_gets_a_plain_404_and_never_reaches_the_dispatcher() {
        let (ctx, mut udp_rx) = ctx(Some("/s3cr3t"));
        let mut c = run(ctx).await;
        c.write_all(&build_upgrade_request("/guess", "h", "k")).await.unwrap();
        let mut resp = Vec::new();
        c.read_to_end(&mut resp).await.unwrap();
        assert!(resp.starts_with(b"HTTP/1.1 404 Not Found"));
        assert!(udp_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn oversized_head_gets_the_decoy() {
        let (ctx, _udp_rx) = ctx(Some("/p"));
        let mut c = run(ctx).await;
        let mut req = b"GET /p HTTP/1.1\r\nX: ".to_vec();
        req.extend(std::iter::repeat(b'a').take(MAX_HEAD_BYTES));
        c.write_all(&req).await.unwrap();
        let mut resp = Vec::new();
        c.read_to_end(&mut resp).await.unwrap();
        assert!(resp.starts_with(b"HTTP/1.1 404 Not Found"));
    }

    #[tokio::test(start_paused = true)]
    async fn slow_head_is_dropped_at_the_deadline() {
        let (ctx, _udp_rx) = ctx(Some("/p"));
        let mut c = run(ctx).await;
        c.write_all(b"GET /p HTTP/1.1\r\n").await.unwrap();
        tokio::time::advance(CLASSIFY_TIMEOUT + Duration::from_secs(1)).await;
        let mut resp = Vec::new();
        let n = tokio::time::timeout(Duration::from_secs(1), c.read_to_end(&mut resp)).await;
        assert!(matches!(n, Ok(Ok(0))), "connection should be closed without a response");
    }
}
