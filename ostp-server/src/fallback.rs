//! Fallback TCP server for anti-DPI camouflage.
//!
//! When a connection arrives that doesn't match the OSTP protocol
//! (e.g., a DPI probe, web spider, or direct HTTP request),
//! it gets transparently proxied to a fallback web server (e.g., nginx).
//!
//! This makes the OSTP server indistinguishable from a regular web server
//! during active probing.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Fallback server configuration.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct FallbackConfig {
    /// Enable fallback TCP listener
    pub enabled: bool,
    /// TCP listen address (e.g., "0.0.0.0:443" or "0.0.0.0:80")
    pub listen: String,
    /// Target to proxy to (e.g., "127.0.0.1:8080" for local nginx)
    pub target: String,
}

/// Start the fallback TCP proxy server.
pub async fn start_fallback_server(config: FallbackConfig) {
    let listener = match TcpListener::bind(&config.listen).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("fallback server failed to bind on {}: {}", config.listen, e);
            return;
        }
    };

    tracing::info!("fallback server listening on {} -> {}", config.listen, config.target);

    loop {
        match listener.accept().await {
            Ok((client, peer_addr)) => {
                let target = config.target.clone();
                tokio::spawn(async move {
                    if let Err(e) = proxy_connection(client, &target).await {
                        tracing::debug!(peer = %peer_addr, "fallback proxy error: {}", e);
                    }
                });
            }
            Err(e) => {
                tracing::warn!("fallback accept error: {}", e);
            }
        }
    }
}

pub async fn proxy_connection(mut client: TcpStream, target: &str) -> anyhow::Result<()> {
    let mut upstream = TcpStream::connect(target).await?;

    let (mut client_read, mut client_write) = client.split();
    let (mut upstream_read, mut upstream_write) = upstream.split();

    let client_to_upstream = async {
        let mut buf = vec![0u8; 8192];
        loop {
            let n = client_read.read(&mut buf).await?;
            if n == 0 { break; }
            upstream_write.write_all(&buf[..n]).await?;
        }
        upstream_write.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    };

    let upstream_to_client = async {
        let mut buf = vec![0u8; 8192];
        loop {
            let n = upstream_read.read(&mut buf).await?;
            if n == 0 { break; }
            client_write.write_all(&buf[..n]).await?;
        }
        client_write.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    };

    tokio::select! {
        r = client_to_upstream => { r?; }
        r = upstream_to_client => { r?; }
    }

    Ok(())
}
