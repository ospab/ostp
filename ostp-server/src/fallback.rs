//! Fallback web server for traffic that is not OSTP.
//!
//! Every TCP listener sniffs incoming connections (see `transport::sniff`);
//! HTTP and TLS that aren't ours are spliced to `target` (e.g. a local nginx),
//! so an active prober sees an ordinary web server. `listen` adds one more
//! sniffing listener, typically on 80 or 443, that OSTP clients can use too.

use bytes::Bytes;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);

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
pub async fn proxy_with_prefix<S>(mut client: S, prefix: Bytes, target: &str) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut upstream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(target))
        .await
        .map_err(|_| anyhow::anyhow!("fallback target {target} connect timed out"))??;
    let _ = upstream.set_nodelay(true);
    upstream.write_all(&prefix).await?;
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

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
