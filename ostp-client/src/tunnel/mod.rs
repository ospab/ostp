mod proxy;
pub mod native_handler;
pub mod windows_route;
mod udp_nat;

pub async fn run_tun_tunnel(
    config: crate::config::ClientConfig,
    shutdown: tokio::sync::watch::Receiver<bool>,
    exclusions_rx: tokio::sync::watch::Receiver<crate::config::ExclusionConfig>,
) -> anyhow::Result<()> {
    native_handler::run_native_tunnel(config, shutdown, exclusions_rx).await
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
    UdpAssociate {
        stream_id: u16,
    },
    UdpData {
        stream_id: u16,
        target: String,
        payload: bytes::Bytes,
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
    UdpData(String, bytes::Bytes),
    Close,
    Error(String),
}


pub async fn run_local_proxy(
    cfg: LocalProxyConfig,
    ostp: OstpConfig,
    exclusions_rx: watch::Receiver<ExclusionConfig>,
    debug: bool,
    shutdown: watch::Receiver<bool>,
    proxy_events_tx: mpsc::Sender<ProxyEvent>,
    client_msgs_rx: mpsc::UnboundedReceiver<(u16, ProxyToClientMsg)>,
) -> anyhow::Result<()> {
    run_local_socks5_proxy(cfg, ostp, exclusions_rx, debug, shutdown, proxy_events_tx, client_msgs_rx).await
}

pub mod exclusion;
pub mod process_lookup;
pub mod sni_sniff;
