pub(crate) mod proxy;
mod ip_reasm;
pub mod native_handler;

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

/// A local connection's id: the proxy's own, never reused while the
/// connection lives (the bridge maps it to a stream id of a session).
pub type LocalStreamId = u32;

#[derive(Debug)]
pub enum ProxyEvent {
    NewStream {
        stream_id: LocalStreamId,
        target: String,
    },
    UdpAssociate {
        stream_id: LocalStreamId,
    },
    UdpData {
        stream_id: LocalStreamId,
        target: String,
        payload: bytes::Bytes,
    },
    Data {
        stream_id: LocalStreamId,
        payload: bytes::Bytes,
    },
    /// The local program closed the connection (v5), or an error ended it:
    /// the stream is aborted.
    Close {
        stream_id: LocalStreamId,
    },
    /// The local program will send no more (its end of stream) and the
    /// connection stays open for the reply. Only sent for a stream the bridge
    /// answered with `ProxyToClientMsg::ConnectOkV6`.
    Fin {
        stream_id: LocalStreamId,
    },
    /// The proxy is done with the connection, whatever happened to it. The
    /// bridge frees the stream if it is still open (a v6 stream that did not
    /// finish is aborted); for one that is over already it means nothing.
    Gone {
        stream_id: LocalStreamId,
    },
    /// Flow control: this many bytes of the stream reached the local program,
    /// so the server may send as much more.
    Consumed {
        stream_id: LocalStreamId,
        bytes: u32,
    },
}

#[derive(Debug)]
pub enum ProxyToClientMsg {
    ConnectOk,
    /// `ConnectOk` of a v6 stream: the program's end of stream goes out as a
    /// half-close (`ProxyEvent::Fin`) and the stream's window starts at
    /// `ostp_core::relay::INITIAL_STREAM_WINDOW` without a `Window` message.
    ConnectOkV6,
    Data(bytes::Bytes),
    UdpData(String, bytes::Bytes),
    /// The peer's end of stream (v6): nothing more comes, the program's side
    /// may still write.
    Fin,
    Close,
    /// The stream was aborted or lost (v6): the program's connection is reset,
    /// not closed gracefully.
    Reset,
    Error(String),
    /// Flow control: the server allows this many more bytes on the stream.
    /// The first one switches a v5 stream to flow control.
    Window(u32),
}


pub async fn run_local_proxy(
    cfg: LocalProxyConfig,
    ostp: OstpConfig,
    exclusions_rx: watch::Receiver<ExclusionConfig>,
    debug: bool,
    shutdown: watch::Receiver<bool>,
    proxy_events_tx: mpsc::Sender<ProxyEvent>,
    client_msgs_rx: mpsc::UnboundedReceiver<(LocalStreamId, ProxyToClientMsg)>,
) -> anyhow::Result<()> {
    run_local_socks5_proxy(cfg, ostp, exclusions_rx, debug, shutdown, proxy_events_tx, client_msgs_rx).await
}

pub mod exclusion;
pub mod process_lookup;
pub mod sni_sniff;
