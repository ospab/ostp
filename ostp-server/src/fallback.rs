//! Fallback web server for traffic that is not OSTP.
//!
//! Every TCP listener sniffs incoming connections (see `transport::sniff`);
//! HTTP and TLS that aren't ours are spliced to `target` (e.g. a local nginx),
//! so an active prober sees an ordinary web server. `listen` adds one more
//! sniffing listener, typically on 80 or 443, that OSTP clients can use too.

use bytes::Bytes;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::Instant;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
/// A splice with no bytes in either direction for this long is closed. Longer
/// than the keep-alive of common web servers (60-75 s), so an ordinary
/// browser connection is never cut mid-use, and short enough that probes
/// cannot hoard descriptors. Applies to the panel route too.
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// Notes when bytes last moved through the client side, which sees both
/// directions of a splice.
struct Active<S> {
    inner: S,
    start: Instant,
    last_ms: Arc<AtomicU64>,
}

impl<S> Active<S> {
    fn touch(&self) {
        self.last_ms.store(self.start.elapsed().as_millis() as u64, Ordering::Relaxed);
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Active<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(r, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            self.touch();
        }
        r
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Active<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<std::io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write(cx, data);
        if matches!(r, Poll::Ready(Ok(n)) if n > 0) {
            self.touch();
        }
        r
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

async fn idle_for(start: Instant, last_ms: &AtomicU64, idle: Duration) {
    loop {
        let seen = last_ms.load(Ordering::Relaxed);
        tokio::time::sleep_until(start + Duration::from_millis(seen) + idle).await;
        if last_ms.load(Ordering::Relaxed) == seen {
            return;
        }
    }
}

/// Fallback server configuration.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct FallbackConfig {
    /// Enable the fallback target and the extra listener.
    pub enabled: bool,
    /// Extra TCP listen address (e.g., "0.0.0.0:443" or "0.0.0.0:80")
    pub listen: String,
    /// Target to proxy non-OSTP traffic to (e.g., "127.0.0.1:8080" for local nginx)
    pub target: String,
}

/// Splices `client` to `target`, first sending the bytes already read off it.
pub async fn proxy_with_prefix<S>(client: S, prefix: Bytes, target: &str) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    proxy_with_idle(client, prefix, target, IDLE_TIMEOUT).await
}

async fn proxy_with_idle<S>(client: S, prefix: Bytes, target: &str, idle: Duration) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut upstream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(target))
        .await
        .map_err(|_| anyhow::anyhow!("fallback target {target} connect timed out"))??;
    let _ = upstream.set_nodelay(true);
    upstream.write_all(&prefix).await?;
    let start = Instant::now();
    let last_ms = Arc::new(AtomicU64::new(0));
    let mut client = Active { inner: client, start, last_ms: last_ms.clone() };
    tokio::select! {
        r = tokio::io::copy_bidirectional(&mut client, &mut upstream) => { r?; }
        _ = idle_for(start, &last_ms, idle) => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn an_idle_splice_is_closed_and_a_busy_one_is_not() {
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = target.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            // Echoes, so traffic flows both ways, and never closes first.
            let (mut s, _) = target.accept().await.unwrap();
            let mut b = [0u8; 16];
            while let Ok(n) = s.read(&mut b).await {
                if n == 0 || s.write_all(&b[..n]).await.is_err() { break; }
            }
        });
        let (mut client, server) = tokio::io::duplex(1024);
        let idle = Duration::from_millis(300);
        let proxy = tokio::spawn(async move { proxy_with_idle(server, Bytes::new(), &addr, idle).await });
        // Chatter for longer than `idle`: stays open.
        for _ in 0..6 {
            client.write_all(b"x").await.unwrap();
            let mut b = [0u8; 1];
            client.read_exact(&mut b).await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(!proxy.is_finished());
        // Then silence: closed within a moment.
        tokio::time::timeout(Duration::from_secs(2), proxy).await.expect("idle splice must end").unwrap().unwrap();
    }

    #[tokio::test]
    async fn prefix_reaches_target_before_the_rest_of_the_stream() {
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = target.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut s, _) = target.accept().await.unwrap();
            let mut got = [0u8; 11];
            s.read_exact(&mut got).await.unwrap();
            assert_eq!(&got, b"GET / HTTP/");
            s.write_all(b"ok").await.unwrap();
        });

        let (mut client, server) = tokio::io::duplex(1024);
        let proxy = tokio::spawn(async move { proxy_with_prefix(server, Bytes::from_static(b"GET "), &addr).await });
        client.write_all(b"/ HTTP/").await.unwrap();
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"ok");
        drop(client);
        let _ = proxy.await;
    }
}
