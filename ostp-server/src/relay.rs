use anyhow::Result;
use bytes::Bytes;
use std::collections::HashMap;

use ostp_core::relay::RelayMessage;
use tokio::io::AsyncReadExt;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::dispatcher::Dispatcher;
use crate::outbound::{self, OutboundConfig};
use crate::{RemoteState, UiEvent};

pub async fn handle_relay_message(
    peer_addr: std::net::SocketAddr,
    session_id: u32,
    stream_id: u16,
    payload: Bytes,
    dispatcher: &mut Dispatcher,
    socket: &UdpSocket,
    remotes: &mut HashMap<(u32, u16), RemoteState>,
    ui_event_tx: &mpsc::UnboundedSender<UiEvent>,
    stream_tx: mpsc::UnboundedSender<(u32, u16, Vec<u8>)>,
    connect_tx: mpsc::UnboundedSender<(u32, u16, String, Result<(tokio::net::tcp::OwnedWriteHalf, mpsc::Sender<()>), String>)>,
    outbound_cfg: Option<OutboundConfig>,
    debug: bool,
) -> Result<()> {
    match RelayMessage::decode(&payload)? {
        RelayMessage::Connect(target) => {
            let _ = ui_event_tx.send(UiEvent::Log(format!("Relay CONNECT start for [{session_id}:{stream_id}] -> {target}")));
            let target_clone = target.clone();
            let connect_tx_clone = connect_tx.clone();
            let stream_tx_clone = stream_tx.clone();
            let outbound_clone = outbound_cfg.clone();
            tokio::spawn(async move {
                let stream_res = outbound::connect_target(&target_clone, outbound_clone.as_ref(), debug).await;
                match stream_res {
                    Ok(stream) => {
                        let (mut reader, writer) = stream.into_split();
                        let (cancel_tx, mut cancel_rx) = mpsc::channel::<()>(1);
                        tokio::spawn(async move {
                            let mut buf = [0_u8; 4096];
                            loop {
                                tokio::select! {
                                    _ = cancel_rx.recv() => break,
                                    read_res = reader.read(&mut buf) => {
                                        match read_res {
                                            Ok(0) | Err(_) => {
                                                let _ = stream_tx_clone.send((session_id, stream_id, Vec::new()));
                                                break;
                                            }
                                            Ok(n) => {
                                                if stream_tx_clone.send((session_id, stream_id, buf[..n].to_vec())).is_err() {
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        });
                        let _ = connect_tx_clone.send((session_id, stream_id, target_clone, Ok((writer, cancel_tx))));
                    }
                    Err(e) => {
                        let _ = connect_tx_clone.send((session_id, stream_id, target_clone, Err(e.to_string())));
                    }
                }
            });
        }
        RelayMessage::Data(data) => {
            if let Some(remote) = remotes.get_mut(&(session_id, stream_id)) {
                let _ = remote.data_tx.send(bytes::Bytes::from(data));
            } else {
                let _ = ui_event_tx.send(UiEvent::Log(format!("Relay DATA for unknown stream [{session_id}:{stream_id}] ({})", data.len())));
            }
        }
        RelayMessage::KeepAlive => {}
        RelayMessage::Close => {
            if let Some(state) = remotes.remove(&(session_id, stream_id)) {
                let _ = state.cancel_tx.try_send(());
                let _ = ui_event_tx.send(UiEvent::Log(format!("Relay CLOSE [{session_id}:{stream_id}]")));
            }
        }
        RelayMessage::ConnectOk => {}
        RelayMessage::Error(msg) => {
            let _ = ui_event_tx.send(UiEvent::Log(format!("Relay error from [{session_id}:{stream_id}]: {msg}")));
        }
        RelayMessage::Ping(ts) => {
            send_relay_to_stream(session_id, stream_id, RelayMessage::Pong(ts), dispatcher, socket, ui_event_tx).await?;
        }
        RelayMessage::Pong(_) => {}
    }
    Ok(())
}



pub async fn send_relay_to_stream(
    session_id: u32,
    stream_id: u16,
    msg: RelayMessage,
    dispatcher: &mut Dispatcher,
    socket: &UdpSocket,
    ui_event_tx: &mpsc::UnboundedSender<UiEvent>,
) -> Result<()> {
    let payload = Bytes::from(msg.encode());
    if let Some((frame, peer_addr)) = dispatcher.outbound_to_session(session_id, stream_id, payload)? {
        let response_len = frame.len();
        let _ = socket.send_to(&frame, peer_addr).await?;
        let _ = ui_event_tx.send(UiEvent::Tx {
            peer: peer_addr.ip(),
            bytes: response_len,
        });
    }
    Ok(())
}
