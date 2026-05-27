mod proxy;
mod wintun_handler;
mod linux_handler;
pub mod native_handler;

pub async fn run_tun_tunnel(
    config: crate::config::ClientConfig,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    if config.tun_stack == "ostp" {
        return native_handler::run_native_tunnel(config, shutdown).await;
    }

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


pub async fn run_local_proxy(
    cfg: LocalProxyConfig,
    ostp: OstpConfig,
    exclusions: ExclusionConfig,
    debug: bool,
    shutdown: watch::Receiver<bool>,
    proxy_events_tx: mpsc::Sender<ProxyEvent>,
    client_msgs_rx: mpsc::UnboundedReceiver<(u16, ProxyToClientMsg)>,
) -> anyhow::Result<()> {
    run_local_socks5_proxy(cfg, ostp, exclusions, debug, shutdown, proxy_events_tx, client_msgs_rx).await
}


