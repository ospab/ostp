mod proxy;
mod wintun_downloader;
mod wintun_handler;
mod linux_handler;

pub use wintun_downloader::download_wintun_dll;
pub use wintun_downloader::download_tun2socks;

pub async fn run_tun_tunnel(
    config: crate::config::ClientConfig,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    #[cfg(target_os = "windows")]
    {
        wintun_handler::run_wintun_tunnel(config, shutdown).await
    }

    #[cfg(target_os = "linux")]
    {
        linux_handler::run_linux_tunnel(config, shutdown).await
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        let _ = shutdown;
        let _ = config;
        anyhow::bail!("Operating system unsupported, text an issue at github.");
    }
}

use tokio::sync::{mpsc, watch};

use crate::config::{ExclusionConfig, LocalProxyConfig, OstpConfig};

pub use proxy::run_local_socks5_proxy;

#[derive(Debug)]
pub enum ProxyEvent {
    NewStream {
        stream_id: u16,
        target: String,
    },
    Data {
        stream_id: u16,
        payload: bytes::Bytes,
    },
    Close {
        stream_id: u16,
    },
}

#[derive(Debug)]
pub enum ProxyToClientMsg {
    ConnectOk,
    Data(bytes::Bytes),
    Close,
    Error(String),
}

#[allow(dead_code)]
pub struct TunnelConfig {
    pub local_bind: String,
    pub remote_addr: String,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            local_bind: "127.0.0.1:1080".to_string(),
            remote_addr: "127.0.0.1:443".to_string(),
        }
    }
}

pub async fn cleanup() -> anyhow::Result<()> {
    Ok(())
}

pub async fn run_local_proxy(
    cfg: LocalProxyConfig,
    ostp: OstpConfig,
    exclusions: ExclusionConfig,
    debug: bool,
    shutdown: watch::Receiver<bool>,
    proxy_events_tx: mpsc::Sender<ProxyEvent>,
    client_msgs_rx: mpsc::Receiver<(u16, ProxyToClientMsg)>,
) -> anyhow::Result<()> {
    run_local_socks5_proxy(cfg, ostp, exclusions, debug, shutdown, proxy_events_tx, client_msgs_rx).await
}


