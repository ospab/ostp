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

/// `/{webpath}` on the built-in HTTPS listener, proxied to the management API.
#[derive(Debug, Clone)]
pub struct PanelRoute {
    /// e.g. "/panel"
    pub prefix: String,
    /// The API's own listen address, reached over loopback.
    pub upstream: String,
}

impl PanelRoute {
    fn matches(&self, path: &str) -> bool {
        path == self.prefix || path.strip_prefix(self.prefix.as_str()).is_some_and(|rest| rest.starts_with('/'))
    }
}

pub struct SniffCtx {
    /// Terminates TLS on this port when a certificate is configured.
    pub tls: Option<tokio_rustls::TlsAcceptor>,
    /// The built-in 443: plaintext of any kind is closed.
    pub tls_required: bool,
    pub panel: Option<PanelRoute>,
    pub ws_path: Option<String>,
    /// `<prefix>/<token>` subscription documents (TLS or a local proxy only).
    pub subscription: Option<Arc<crate::subscription::SubscriptionService>>,
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
            if let Err(e) = handle_conn(stream, peer, ctx, permit, deadline).await {
                tracing::debug!("TCP connection from {peer} closed: {e}");
            }
        });
    }
}

/// First look at a connection: TLS is terminated here (once), everything
/// else goes straight to `dispatch`.
async fn handle_conn<S>(
    mut s: S,
    peer: SocketAddr,
    ctx: Arc<SniffCtx>,
    permit: OwnedSemaphorePermit,
    deadline: Instant,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut buf = BytesMut::with_capacity(2048);
    if read_more(&mut s, &mut buf, deadline).await? == 0 {
        return Ok(());
    }
    if ctx.tls_required && classify(buf[0]) != Class::Tls {
        return Ok(());
    }
    if classify(buf[0]) == Class::Tls {
        if let Some(acceptor) = ctx.tls.clone() {
            let tls = match timeout_at(deadline, acceptor.accept(Rewind::new(s, buf.freeze()))).await {
                Ok(Ok(tls)) => tls,
                Ok(Err(e)) => {
                    tracing::debug!("TLS handshake from {peer} failed: {e}");
                    return Ok(());
                }
                Err(_) => return Ok(()),
            };
            return dispatch(tls, BytesMut::new(), peer, ctx, permit, deadline, true).await;
        }
    }
    dispatch(s, buf, peer, ctx, permit, deadline, false).await
}

/// Routes a connection given the bytes already read off it (possibly none).
/// Never terminates TLS itself: TLS inside TLS is not ours.
async fn dispatch<S>(
    mut s: S,
    mut buf: BytesMut,
    peer: SocketAddr,
    ctx: Arc<SniffCtx>,
    permit: OwnedSemaphorePermit,
    deadline: Instant,
    via_tls: bool,
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
        Class::Http => route_http(s, buf, peer, ctx, permit, deadline, via_tls).await,
    }
}

async fn route_http<S>(
    mut s: S,
    mut buf: BytesMut,
    peer: SocketAddr,
    ctx: Arc<SniffCtx>,
    permit: OwnedSemaphorePermit,
    deadline: Instant,
    via_tls: bool,
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
        // From a local web server this is our own frontend misrouting, not a
        // probe: say why, so a 404/502 in front can be traced.
        if is_trusted_proxy(peer) {
            if let Some(why) = upgrade_problem(&buf[..head_len], ctx.ws_path.as_deref()) {
                tracing::info!("request from the local web server is not an OSTP upgrade: {why}");
            }
        }
        // The token is a credential: never answered over plaintext from the
        // internet, only inside TLS or from a local web server that ended it.
        if let Some(sub) = ctx.subscription.as_ref().filter(|_| via_tls || is_trusted_proxy(peer)) {
            if request_path(&buf[..head_len]).is_some_and(|p| sub.wants(&p)) {
                if let Some(resp) = sub.respond(&buf[..head_len]).await {
                    drop(permit);
                    s.write_all(&resp).await?;
                    let _ = s.shutdown().await;
                    return Ok(());
                }
            }
        }
        if let Some(panel) = &ctx.panel {
            if request_path(&buf[..head_len]).is_some_and(|p| panel.matches(&p)) {
                drop(permit);
                return crate::fallback::proxy_with_prefix(s, buf.freeze(), &panel.upstream).await;
            }
        }
        return decoy(s, buf, &ctx).await;
    };

    if let Some(real_ip) = upgrade.forwarded_for {
        if !ctx.limiter.check(real_ip) {
            // A bare close would reach the client as a 502 from the web
            // server; an explicit 429 says what happened.
            tracing::info!("rate limit: too many connections from {real_ip} (via the local web server)");
            s.write_all(TOO_MANY).await?;
            let _ = s.shutdown().await;
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

/// Why a request is not an upgrade to `ws_path`, for the log. `None` when
/// it is not aimed at the upgrade path at all (panel, subscription, other).
fn upgrade_problem(head: &[u8], ws_path: Option<&str>) -> Option<String> {
    let Some(ws_path) = ws_path else { return Some("no ws_path is configured (tls.ws_path)".into()) };
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut req = httparse::Request::new(&mut headers);
    if !matches!(req.parse(head), Ok(httparse::Status::Complete(_))) {
        return Some("malformed HTTP request".into());
    }
    let path = req.path.unwrap_or("");
    let header = |name: &str| req.headers.iter().find(|h| h.name.eq_ignore_ascii_case(name)).and_then(|h| std::str::from_utf8(h.value).ok());
    if path != ws_path {
        // Anything that looks like an upgrade attempt on another path is a
        // path mismatch between the web server and OSTP.
        return header("upgrade").map(|_| format!("upgrade for {path}, but tls.ws_path is a different path"));
    }
    if req.method != Some("GET") {
        return Some(format!("{} instead of GET", req.method.unwrap_or("?")));
    }
    if !header("upgrade").is_some_and(|v| v.trim().eq_ignore_ascii_case("websocket")) {
        return Some("no \"Upgrade: websocket\" header (the web server must pass it: proxy_set_header Upgrade $http_upgrade)".into());
    }
    if !header("connection").is_some_and(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("upgrade"))) {
        return Some("no \"Connection: upgrade\" header (proxy_set_header Connection \"upgrade\")".into());
    }
    if header("sec-websocket-key").map_or(true, |k| k.trim().is_empty()) {
        return Some("no Sec-WebSocket-Key header".into());
    }
    None
}

fn request_path(head: &[u8]) -> Option<String> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(head) {
        Ok(httparse::Status::Complete(_)) => req.path.map(|p| p.split('?').next().unwrap_or(p).to_string()),
        _ => None,
    }
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

const TOO_MANY: &[u8] = b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
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
    fn upgrade_problems_are_named_for_the_log() {
        let ok = build_upgrade_request("/p", "h", "k");
        assert_eq!(upgrade_problem(&ok, Some("/p")), None);
        assert!(upgrade_problem(&ok, Some("/q")).unwrap().contains("different path"));
        assert!(upgrade_problem(b"GET /x HTTP/1.1\r\nHost: h\r\n\r\n", Some("/p")).is_none());
        let no_conn = b"GET /p HTTP/1.1\r\nUpgrade: websocket\r\nSec-WebSocket-Key: k\r\n\r\n";
        assert!(upgrade_problem(no_conn, Some("/p")).unwrap().contains("Connection"));
        assert!(upgrade_problem(&ok, None).unwrap().contains("ws_path"));
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
                tls: None,
                tls_required: false,
                panel: None,
                ws_path: ws_path.map(str::to_string),
                subscription: None,
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
        tokio::spawn(handle_conn(server, public(), ctx, permit, Instant::now() + CLASSIFY_TIMEOUT));
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

#[cfg(test)]
mod tls_tests {
    use super::*;
    use crate::tls::{build_acceptor, test_util::ca_and_leaf, write_pem_pair, HotCertResolver};
    use ostp_core::http_upgrade::build_upgrade_request;
    use rustls::pki_types::{pem::PemObject, CertificateDer, ServerName};

    fn setup(name: &str) -> (tokio_rustls::TlsAcceptor, tokio_rustls::TlsConnector) {
        let (ca, leaf, key) = ca_and_leaf(name);
        let dir = std::env::temp_dir().join(format!("ostp-sniff-tls-{}", rand::random::<u64>()));
        let (cp, kp) = (dir.join("fullchain.pem"), dir.join("privkey.pem"));
        write_pem_pair(&cp, &leaf, &kp, &key).unwrap();
        let resolver = HotCertResolver::new(&cp, &kp);
        resolver.reload().unwrap();

        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from_pem_slice(ca.as_bytes()).unwrap()).unwrap();
        let mut client = rustls::ClientConfig::builder_with_provider(crate::tls::provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client.alpn_protocols = vec![b"http/1.1".to_vec()];
        (build_acceptor(resolver).unwrap(), tokio_rustls::TlsConnector::from(Arc::new(client)))
    }

    fn ctx(tls: tokio_rustls::TlsAcceptor, ws_path: Option<&str>) -> (Arc<SniffCtx>, mpsc::Receiver<(Bytes, SocketAddr)>) {
        let (udp_tx, udp_rx) = mpsc::channel(16);
        (
            Arc::new(SniffCtx {
                tls: Some(tls),
                tls_required: false,
                panel: None,
                ws_path: ws_path.map(str::to_string),
                subscription: None,
                decoy: Decoy::NotFound,
                limiter: Arc::new(ConnLimiter::new()),
                pending: Arc::new(Semaphore::new(MAX_PENDING)),
                tcp_map: Arc::new(RwLock::new(HashMap::new())),
                udp_tx,
            }),
            udp_rx,
        )
    }

    async fn connect(
        ctx: Arc<SniffCtx>,
        connector: tokio_rustls::TlsConnector,
        sni: &str,
    ) -> std::io::Result<tokio_rustls::client::TlsStream<tokio::io::DuplexStream>> {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let permit = ctx.pending.clone().try_acquire_owned().unwrap();
        let peer: SocketAddr = "203.0.113.7:4000".parse().unwrap();
        tokio::spawn(handle_conn(server, peer, ctx, permit, Instant::now() + CLASSIFY_TIMEOUT));
        connector.connect(ServerName::try_from(sni.to_string()).unwrap(), client).await
    }

    #[tokio::test]
    async fn uot_frames_inside_tls_reach_the_dispatcher() {
        let (acceptor, connector) = setup("vpn.example.test");
        let (ctx, mut udp_rx) = ctx(acceptor, None);
        let mut tls = connect(ctx, connector, "vpn.example.test").await.unwrap();
        tls.write_all(&[0x00, 0x03, b'a', b'b', b'c']).await.unwrap();
        tls.flush().await.unwrap();
        let (frame, _) = udp_rx.recv().await.unwrap();
        assert_eq!(frame.as_ref(), b"abc");
    }

    #[tokio::test]
    async fn upgrade_inside_tls_then_frames() {
        let (acceptor, connector) = setup("vpn.example.test");
        let (ctx, mut udp_rx) = ctx(acceptor, Some("/s3cr3t"));
        let mut tls = connect(ctx, connector, "vpn.example.test").await.unwrap();
        tls.write_all(&build_upgrade_request("/s3cr3t", "vpn.example.test", "dGhlIHNhbXBsZSBub25jZQ==")).await.unwrap();
        tls.flush().await.unwrap();
        let mut resp = vec![0u8; 256];
        let n = tls.read(&mut resp).await.unwrap();
        assert!(resp[..n].starts_with(b"HTTP/1.1 101 "));
        tls.write_all(&[0x00, 0x02, b'o', b'k']).await.unwrap();
        tls.flush().await.unwrap();
        let (frame, _) = udp_rx.recv().await.unwrap();
        assert_eq!(frame.as_ref(), b"ok");
    }

    #[tokio::test]
    async fn wrong_sni_fails_certificate_verification() {
        let (acceptor, connector) = setup("vpn.example.test");
        let (ctx, _udp_rx) = ctx(acceptor, None);
        let err = connect(ctx, connector, "other.example.test").await.unwrap_err();
        assert!(err.to_string().to_lowercase().contains("certificate"), "{err}");
    }

    #[tokio::test]
    async fn builtin_https_proxies_panel_and_refuses_plaintext() {
        let panel = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = panel.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut s, _) = panel.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = s.read(&mut buf).await.unwrap();
            assert!(buf[..n].starts_with(b"GET /panel/api/server/status "));
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\npanel").await.unwrap();
        });

        let (acceptor, connector) = setup("vpn.example.test");
        let (udp_tx, mut udp_rx) = mpsc::channel(16);
        let ctx = Arc::new(SniffCtx {
            tls: Some(acceptor),
            tls_required: true,
            panel: Some(PanelRoute { prefix: "/panel".into(), upstream }),
            ws_path: Some("/s3cr3t".into()),
            subscription: None,
            decoy: Decoy::NotFound,
            limiter: Arc::new(ConnLimiter::new()),
            pending: Arc::new(Semaphore::new(MAX_PENDING)),
            tcp_map: Arc::new(RwLock::new(HashMap::new())),
            udp_tx,
        });

        let mut tls = connect(ctx.clone(), connector, "vpn.example.test").await.unwrap();
        tls.write_all(b"GET /panel/api/server/status HTTP/1.1\r\nHost: vpn.example.test\r\n\r\n").await.unwrap();
        tls.flush().await.unwrap();
        let mut resp = Vec::new();
        let _ = tls.read_to_end(&mut resp).await;
        assert!(resp.ends_with(b"panel"), "{}", String::from_utf8_lossy(&resp));

        // Raw UoT on the TLS-only port is dropped without reaching the dispatcher.
        let (mut client, server) = tokio::io::duplex(1024);
        let permit = ctx.pending.clone().try_acquire_owned().unwrap();
        let peer: SocketAddr = "203.0.113.7:4001".parse().unwrap();
        tokio::spawn(handle_conn(server, peer, ctx, permit, Instant::now() + CLASSIFY_TIMEOUT));
        client.write_all(&[0x00, 0x02, b'n', b'o']).await.unwrap();
        let mut rest = Vec::new();
        client.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
        assert!(udp_rx.try_recv().is_err());
    }

    #[test]
    fn panel_prefix_matching() {
        let p = PanelRoute { prefix: "/wp".into(), upstream: String::new() };
        assert!(p.matches("/wp"));
        assert!(p.matches("/wp/x"));
        assert!(!p.matches("/wpx"));
        assert!(!p.matches("/"));
    }
}
