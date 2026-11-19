use anyhow::Result;
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::Arc;

use ostp_core::relay::RelayMessage;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;

use crate::dispatcher::Dispatcher;
use crate::send_gate::{SendGate, StreamWindow};
use crate::{RemoteState, SessionBackpressure, StreamOut, UiEvent};

/// Largest read from a target at once. 4 KiB meant a syscall and a message
/// per three datagrams plus a short fourth one; 64 KiB fills whole frames.
const READ_BUF: usize = 64 * 1024;

/// Datagrams from the client waiting to go out of one UDP-associate stream;
/// past this they are dropped, as UDP may.
const UDP_STREAM_QUEUE: usize = 256;

fn clean_ipv6_mapped_v4(addr: std::net::SocketAddr) -> std::net::SocketAddr {
    match addr {
        std::net::SocketAddr::V6(v6) => {
            if let Some(v4) = v6.ip().to_ipv4() {
                std::net::SocketAddr::new(std::net::IpAddr::V4(v4), v6.port())
            } else {
                addr
            }
        }
        _ => addr,
    }
}


/// The stream is over on the server's side: the target's connection is closed
/// and, in a v6 session, the stream's state is released (its id is not used
/// again).
pub fn end_stream(
    session_id: u32,
    stream_id: u32,
    remotes: &mut HashMap<(u32, u32), RemoteState>,
    dispatcher: &mut Dispatcher,
) {
    if let Some(state) = remotes.remove(&(session_id, stream_id)) {
        let _ = state.cancel_tx.try_send(());
    }
    dispatcher.release_stream(session_id, stream_id);
}

/// A v6 stream was reset (the peer said so, or this side gave up on a frame of
/// it): its target is closed. Stream 0 is the session's own control stream, and
/// without it the session is unusable, so it ends like an expired one.
pub fn reset_stream(
    session_id: u32,
    stream_id: u32,
    remotes: &mut HashMap<(u32, u32), RemoteState>,
    dispatcher: &mut Dispatcher,
    ui_event_tx: &mpsc::UnboundedSender<UiEvent>,
) {
    if stream_id == 0 {
        let _ = ui_event_tx.send(UiEvent::Info(format!("Session {session_id}: the control stream was lost, ending the session")));
        dispatcher.drop_session(session_id);
        return;
    }
    let _ = ui_event_tx.send(UiEvent::Log(format!("Stream [{session_id}:{stream_id}] reset, closing its target")));
    end_stream(session_id, stream_id, remotes, dispatcher);
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_relay_message(
    peer_addr: std::net::SocketAddr,
    session_id: u32,
    stream_id: u32,
    payload: Bytes,
    dispatcher: &mut Dispatcher,
    socket: &crate::transport::udp::UdpSockets,
    remotes: &mut HashMap<(u32, u32), RemoteState>,
    ui_event_tx: &mpsc::UnboundedSender<UiEvent>,
    stream_tx: mpsc::UnboundedSender<(u32, u32, StreamOut)>,
    udp_reply_tx: mpsc::Sender<(u32, u32, String, Vec<u8>)>,
    connect_tx: mpsc::UnboundedSender<(u32, u32, String, Result<(tokio::net::tcp::OwnedWriteHalf, mpsc::Sender<()>, Option<Arc<StreamWindow>>), String>)>,
    router: std::sync::Arc<crate::router::Router>,
    tcp_map: &std::sync::Arc<tokio::sync::RwLock<HashMap<std::net::SocketAddr, tokio::sync::mpsc::Sender<Bytes>>>>,
    session_backpressure: &SessionBackpressure,
) -> Result<()> {
    let msg = RelayMessage::decode(&payload)?;
    handle_message(
        peer_addr, session_id, stream_id, msg, dispatcher, socket, remotes, ui_event_tx, stream_tx, udp_reply_tx,
        connect_tx, router, tcp_map, session_backpressure,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_message(
    peer_addr: std::net::SocketAddr,
    session_id: u32,
    stream_id: u32,
    msg: RelayMessage,
    dispatcher: &mut Dispatcher,
    socket: &crate::transport::udp::UdpSockets,
    remotes: &mut HashMap<(u32, u32), RemoteState>,
    ui_event_tx: &mpsc::UnboundedSender<UiEvent>,
    stream_tx: mpsc::UnboundedSender<(u32, u32, StreamOut)>,
    udp_reply_tx: mpsc::Sender<(u32, u32, String, Vec<u8>)>,
    connect_tx: mpsc::UnboundedSender<(u32, u32, String, Result<(tokio::net::tcp::OwnedWriteHalf, mpsc::Sender<()>, Option<Arc<StreamWindow>>), String>)>,
    router: std::sync::Arc<crate::router::Router>,
    tcp_map: &std::sync::Arc<tokio::sync::RwLock<HashMap<std::net::SocketAddr, tokio::sync::mpsc::Sender<Bytes>>>>,
    session_backpressure: &SessionBackpressure,
) -> Result<()> {
    match msg {
        RelayMessage::Connect(target) => {
            if !open_v6_stream(session_id, stream_id, dispatcher, socket, ui_event_tx, tcp_map).await {
                return Ok(());
            }
            let Some(permit) = dispatcher.stream_permit(session_id) else {
                let _ = connect_tx.send((session_id, stream_id, target, Err("too many open connections for this key".into())));
                return Ok(());
            };

            let mut connect_target = target.clone();
            if connect_target.starts_with("10.1.0.1:") {
                connect_target = connect_target.replace("10.1.0.1:", "127.0.0.1:");
            }
            // DNS over TCP goes to the server's resolver like UDP does; DNS
            // over TLS is refused while it would skip the filtering (Android's
            // "Private DNS: automatic" then falls back to port 53).
            let port = connect_target.rsplit(':').next().unwrap_or("");
            if port == "53" && router.dns_server.answers(&target) {
                if let Some(addr) = router.dns_tcp.get() {
                    connect_target = addr.to_string();
                }
            } else if router.dns_server.is_dns_bypass(&connect_target) {
                // Encrypted DNS would skip the filtering; refused, the device
                // falls back to plain port 53 (Android's "Private DNS:
                // automatic", Chrome's secure DNS upgrade).
                let _ = connect_tx.send((session_id, stream_id, target, Err("encrypted DNS is blocked: this server filters DNS".into())));
                return Ok(());
            } else if router.overnet().refuses_encrypted_dns(&connect_target) {
                // Same fallback, so `.ov` names reach the server's port-53 answer.
                let _ = connect_tx.send((session_id, stream_id, target, Err("encrypted DNS is blocked: this server serves .ov".into())));
                return Ok(());
            }

            let target_clone = connect_target.clone();
            let connect_tx_clone = connect_tx.clone();
            let stream_tx_clone = stream_tx.clone();
            let router_clone = router.clone();
            // Get-or-create this session's gate. A brand new session may not
            // have had its first update yet, so it starts open (a fresh
            // congestion window) rather than stalling the very first read.
            let gate: Arc<SendGate> = {
                let mut map = session_backpressure.write().unwrap_or_else(|e| e.into_inner());
                map.entry(session_id).or_insert_with(|| Arc::new(SendGate::new(32))).clone()
            };
            // How much stream data one datagram of this session carries: read
            // anew for each read, because it grows while the session finds
            // the path's MTU (a handle shared with the machine).
            let payload_handle = dispatcher.max_payload_handle(session_id);
            let frame_payload_now = move || {
                payload_handle
                    .as_ref()
                    .map_or(1300, |h| h.load(std::sync::atomic::Ordering::Relaxed))
                    .saturating_sub(ostp_core::relay::DATA_OVERHEAD)
                    .max(1)
            };
            // The client grants this stream's download as its program reads it.
            let window = dispatcher
                .flow_control(session_id)
                .then(|| Arc::new(StreamWindow::new(ostp_core::relay::INITIAL_STREAM_WINDOW as i64)));
            let reader_window = window.clone();
            // v6: the target's end of stream is a half-close (`Fin`), not the
            // end of the stream; in v5 it is the `Close` it always was.
            let v6 = dispatcher.is_v6(session_id);
            tokio::spawn(async move {
                let stream_res = router_clone.route_tcp(&target_clone, peer_addr.ip()).await;
                // Held by the reader below: released when the connection ends,
                // or right here when it fails.
                let permit = permit;
                match stream_res {
                    Ok(stream) => {
                        let (mut reader, writer) = stream.into_split();
                        let (cancel_tx, mut cancel_rx) = mpsc::channel::<()>(1);
                        tokio::spawn(async move {
                            let _permit = permit;
                            let mut buf = vec![0_u8; READ_BUF];
                            loop {
                                // Read no more than the client-facing session may
                                // send now (its congestion window and pacing), so a
                                // fast target does not flood a slower client path.
                                // The budget is updated on every ACK and tick and
                                // wakes this task at once.
                                let budget = gate.acquire().await;
                                let frame_payload = frame_payload_now();
                                let mut want = (budget as usize).saturating_mul(frame_payload).clamp(1, READ_BUF);
                                if let Some(window) = &reader_window {
                                    let credit = tokio::select! {
                                        _ = cancel_rx.recv() => break,
                                        credit = window.acquire() => credit,
                                    };
                                    want = want.min(credit as usize).max(1);
                                }
                                tokio::select! {
                                    _ = cancel_rx.recv() => break,
                                    read_res = reader.read(&mut buf[..want]) => {
                                        match read_res {
                                            Ok(0) if v6 => {
                                                let _ = stream_tx_clone.send((session_id, stream_id, StreamOut::Fin));
                                                break;
                                            }
                                            Ok(0) | Err(_) => {
                                                let _ = stream_tx_clone.send((session_id, stream_id, StreamOut::Close));
                                                break;
                                            }
                                            Ok(n) => {
                                                gate.spend(n.div_ceil(frame_payload) as i64);
                                                if let Some(window) = &reader_window {
                                                    window.spend(n as i64);
                                                }
                                                if stream_tx_clone.send((session_id, stream_id, StreamOut::Data(buf[..n].to_vec()))).is_err() {
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        });
                        let _ = connect_tx_clone.send((session_id, stream_id, target_clone, Ok((writer, cancel_tx, window))));
                    }
                    Err(e) => {
                        let _ = connect_tx_clone.send((session_id, stream_id, target_clone, Err(e.to_string())));
                    }
                }
            });
        }
        RelayMessage::Data(data) => {
            let v6 = dispatcher.is_v6(session_id);
            if let Some(remote) = remotes.get_mut(&(session_id, stream_id)) {
                use std::sync::atomic::Ordering;
                let queued = remote.queued.fetch_add(data.len(), Ordering::Relaxed) + data.len();
                // v5: a fixed cap on what waits for the target. v6: the stream's
                // window holds a sender that keeps the rules; only one that
                // broke them gets here.
                let limit = if v6 { crate::V6_QUEUED_UPLOAD_LIMIT } else { crate::MAX_QUEUED_UPLOAD };
                if queued > limit {
                    // The target does not take the data as fast as the client
                    // sends it; reset the stream rather than buffer without end.
                    tracing::warn!("Stream [{session_id}:{stream_id}]: over {} MB waiting for the target, resetting it", limit >> 20);
                    let msg = if v6 {
                        RelayMessage::Abort(ostp_core::relay::ABORT_FLOW_CONTROL)
                    } else {
                        RelayMessage::Error("the target does not accept data this fast".into())
                    };
                    // Told first: a released v6 stream can no longer send.
                    let sent = send_relay_to_stream(session_id, stream_id, msg, dispatcher, socket, ui_event_tx, tcp_map).await;
                    end_stream(session_id, stream_id, remotes, dispatcher);
                    sent?;
                    return Ok(());
                }
                match &remote.data_tx {
                    Some(tx) => {
                        let _ = tx.send(bytes::Bytes::from(data));
                    }
                    // Data after the client's own Fin: nothing is written.
                    None => {
                        let _ = ui_event_tx.send(UiEvent::Log(format!("Relay DATA after FIN [{session_id}:{stream_id}] ({})", data.len())));
                    }
                }
            } else {
                let _ = ui_event_tx.send(UiEvent::Log(format!("Relay DATA for unknown stream [{session_id}:{stream_id}] ({})", data.len())));
            }
        }
        RelayMessage::KeepAlive => {}
        RelayMessage::Features(bits) => {
            let both = bits & ostp_core::relay::FEATURE_FLOW_CONTROL;
            if both != 0 {
                dispatcher.set_flow_control(session_id);
            }
            send_relay_to_stream(session_id, stream_id, RelayMessage::Features(both), dispatcher, socket, ui_event_tx, tcp_map).await?;
        }
        RelayMessage::Window(bytes) => {
            if let Some(window) = remotes.get(&(session_id, stream_id)).and_then(|r| r.window.as_ref()) {
                window.grant(bytes as i64);
            }
        }
        RelayMessage::Fin => {
            // The client will write no more: the target gets its end of
            // stream after what is queued, and its reply keeps coming.
            if let Some(remote) = remotes.get_mut(&(session_id, stream_id)) {
                remote.data_tx = None;
                if remote.halves.remote_fin() {
                    end_stream(session_id, stream_id, remotes, dispatcher);
                }
            } else {
                let _ = ui_event_tx.send(UiEvent::Log(format!("Relay FIN for unknown stream [{session_id}:{stream_id}]")));
            }
        }
        RelayMessage::Close | RelayMessage::Abort(_) => {
            if remotes.contains_key(&(session_id, stream_id)) {
                let _ = ui_event_tx.send(UiEvent::Log(format!("Relay CLOSE [{session_id}:{stream_id}]")));
            }
            end_stream(session_id, stream_id, remotes, dispatcher);
        }
        RelayMessage::ConnectOk => {}
        RelayMessage::Error(msg) => {
            let _ = ui_event_tx.send(crate::logs::client_stream_error(session_id, stream_id, &msg));
        }
        RelayMessage::Ping(ts) => {
            send_relay_to_stream(session_id, stream_id, RelayMessage::Pong(ts), dispatcher, socket, ui_event_tx, tcp_map).await?;
        }
        RelayMessage::Pong(_) => {}
        RelayMessage::UdpAssociate => {
            if !open_v6_stream(session_id, stream_id, dispatcher, socket, ui_event_tx, tcp_map).await {
                return Ok(());
            }
            let Some(permit) = dispatcher.stream_permit(session_id) else {
                let _ = ui_event_tx.send(UiEvent::Log(format!("UDP associate refused for session {session_id}: too many open connections for its key")));
                // v6: the stream was opened above and will never run; the
                // client is told and the slot is given back. (v5: silent, as before.)
                if dispatcher.is_v6(session_id) {
                    let _ = send_relay_to_stream(session_id, stream_id, RelayMessage::Error("too many open connections for this key".into()), dispatcher, socket, ui_event_tx, tcp_map).await;
                    dispatcher.release_stream(session_id, stream_id);
                }
                return Ok(());
            };
            if router.debug {
                let _ = ui_event_tx.send(UiEvent::Log(format!("Relay UDP ASSOCIATE stream_id={stream_id}")));
            }
            
            let udp_bind_result = if let Some(ref bind_ip) = router.bind_ip {
                tokio::net::UdpSocket::bind(format!("{}:0", bind_ip)).await
            } else {
                match tokio::net::UdpSocket::bind("[::]:0").await {
                    Ok(s) => Ok(s),
                    Err(_) => tokio::net::UdpSocket::bind("0.0.0.0:0").await,
                }
            };
            
            let server_udp = match udp_bind_result {
                Ok(s) => std::sync::Arc::new(s),
                Err(e) => {
                    let _ = ui_event_tx.send(UiEvent::Log(format!("UDP bind failed: {e}")));
                    return Ok(());
                }
            };
            
            let (udp_tx, mut udp_rx) = mpsc::channel::<(String, Bytes)>(UDP_STREAM_QUEUE);
            let (cancel_tx, mut cancel_rx) = mpsc::channel::<()>(1);

            // Set up in its own task: with an outbound SOCKS5 proxy this is a
            // UDP ASSOCIATE handshake with it, and awaited on the server's
            // packet loop a slow or dead proxy stopped every client. Datagrams
            // the client sends meanwhile wait in `udp_rx`.
            let router_task = router.clone();
            let udp_reply_clone = udp_reply_tx.clone();
            tokio::spawn(async move {
                let session_router = std::sync::Arc::new(router_task.route_udp_associate(server_udp.clone()).await);

                // Outbound UDP loop (tunnel -> target)
                let tx_router = session_router.clone();
                tokio::spawn(async move {
                    // Ends when the stream is closed (udp_tx dropped).
                    let _permit = permit;
                    while let Some((target, data)) = udp_rx.recv().await {
                        let mut forward_target = target.clone();
                        if forward_target.starts_with("10.1.0.1:") {
                            forward_target = forward_target.replace("10.1.0.1:", "127.0.0.1:");
                        }
                        let _ = tx_router.send_to(&data, &forward_target).await;
                    }
                });

                // Inbound UDP loop (target -> tunnel)
                let rx_sock = server_udp.clone();
                let proxy_sock = session_router.get_proxy_sock();
                let mut direct_buf = vec![0u8; 65536];
                let mut proxy_buf = vec![0u8; 65536];
                loop {
                    if let Some(ref p) = proxy_sock {
                        tokio::select! {
                            _ = cancel_rx.recv() => break,
                            res = rx_sock.recv_from(&mut direct_buf) => {
                                if let Ok((len, addr)) = res {
                                    let _ = udp_reply_clone.try_send((session_id, stream_id, clean_ipv6_mapped_v4(addr).to_string(), direct_buf[..len].to_vec()));
                                } else { break; }
                            }
                            res = p.recv_from(&mut proxy_buf) => {
                                if let Ok((len, target_str)) = res {
                                    let _ = udp_reply_clone.try_send((session_id, stream_id, target_str, proxy_buf[..len].to_vec()));
                                }
                            }
                        }
                    } else {
                        tokio::select! {
                            _ = cancel_rx.recv() => break,
                            res = rx_sock.recv_from(&mut direct_buf) => {
                                if let Ok((len, addr)) = res {
                                    let _ = udp_reply_clone.try_send((session_id, stream_id, clean_ipv6_mapped_v4(addr).to_string(), direct_buf[..len].to_vec()));
                                } else { break; }
                            }
                        }
                    }
                }
            });


            remotes.insert((session_id, stream_id), RemoteState {
                data_tx: None,
                halves: Default::default(),
                queued: Default::default(),
                udp_tx: Some(udp_tx),
                cancel_tx,
                is_dns: false,
                window: None,
            });

            send_relay_to_stream(session_id, stream_id, RelayMessage::ConnectOk, dispatcher, socket, ui_event_tx, tcp_map).await?;
        }
        RelayMessage::UdpData(target, data) => {
            if let Some(remote) = remotes.get_mut(&(session_id, stream_id)) {
                // Если целевой порт 53 — пробуем перехватить через встроенный DNS
                if target.ends_with(":53") {
                    // `.ov` is answered here whatever the DNS settings: a fake
                    // address for the overnet gateway, never a public resolver.
                    if let Some(response) = router.overnet().answer_dns(&data) {
                        let _ = udp_reply_tx.try_send((session_id, stream_id, target, response));
                        return Ok(());
                    }
                    let should_intercept = router.dns_server.answers(&target);

                    if should_intercept {
                        // Resolved in its own task: this runs on the server's
                        // only packet loop, and a cache miss waits for the
                        // upstream (up to 4 s per resolver). Awaited here, it
                        // stopped every packet of every client meanwhile.
                        let router = router.clone();
                        let udp_reply_tx = udp_reply_tx.clone();
                        let ui_event_tx = ui_event_tx.clone();
                        let client_ip = peer_addr.ip();
                        tokio::spawn(async move {
                            match router.route_dns(client_ip, &data).await {
                                Some(response) => {
                                    let _ = udp_reply_tx.try_send((session_id, stream_id, target, response));
                                }
                                None => {
                                    // route_dns вернул None — значит DoH упал и enabled=true
                                    // в режиме перехвата уже вернул SERVFAIL
                                    // просто блокируем, не пускаем к 8.8.8.8 с IP сервера
                                    if router.debug {
                                        let _ = ui_event_tx.send(UiEvent::Log(format!(
                                            "DNS [{session_id}:{stream_id}] DoH failed for {target}, dropping (intercept=true)"
                                        )));
                                    }
                                }
                            }
                        });
                        return Ok(());
                    } else {
                        // intercept отключён: forward как обычный UDP
                        if router.debug {
                            let _ = ui_event_tx.send(UiEvent::Log(format!(
                                "DNS [{session_id}:{stream_id}] passthrough to {target} (intercept disabled)"
                            )));
                        }
                    }
                }

                // DNS over QUIC (853) and DoH over HTTP/3 to a public resolver
                // (443) skip the filtering the same way; dropped, so the device
                // falls back to plain port 53.
                if router.dns_server.is_dns_bypass(&target) || router.overnet().refuses_encrypted_dns(&target) {
                    if router.debug {
                        let _ = ui_event_tx.send(UiEvent::Log(format!("DNS [{session_id}:{stream_id}] encrypted DNS over UDP to {target} dropped")));
                    }
                    return Ok(());
                }

                if let Some(ref udp_tx) = remote.udp_tx {
                    let _ = udp_tx.try_send((target, Bytes::from(data)));
                }
            } else {
                let _ = ui_event_tx.send(UiEvent::Log(format!("Relay UDP DATA for unknown stream [{session_id}:{stream_id}]")));
            }
        }
    }
    Ok(())
}

/// v6: the client opens `stream_id`. Returns false (after telling the client)
/// when it is refused: a reused or misnumbered id, or 1024 streams open.
/// A v5 session has no such rules and always gets true.
async fn open_v6_stream(
    session_id: u32,
    stream_id: u32,
    dispatcher: &mut Dispatcher,
    socket: &crate::transport::udp::UdpSockets,
    ui_event_tx: &mpsc::UnboundedSender<UiEvent>,
    tcp_map: &std::sync::Arc<tokio::sync::RwLock<HashMap<std::net::SocketAddr, tokio::sync::mpsc::Sender<Bytes>>>>,
) -> bool {
    if !dispatcher.is_v6(session_id) {
        return true;
    }
    let Err(refused) = dispatcher.open_stream(session_id, stream_id) else {
        return true;
    };
    let _ = ui_event_tx.send(UiEvent::Log(format!("Stream [{session_id}:{stream_id}] refused: {refused}")));
    let msg = RelayMessage::Error(format!("stream refused: {refused}"));
    let _ = send_relay_to_stream(session_id, stream_id, msg, dispatcher, socket, ui_event_tx, tcp_map).await;
    // A reused id is a stream that exists (or existed): its state is not ours
    // to release.
    if refused != ostp_core::streams::StreamError::Reused {
        dispatcher.release_stream(session_id, stream_id);
    }
    false
}

pub async fn send_relay_to_stream(
    session_id: u32,
    stream_id: u32,
    msg: RelayMessage,
    dispatcher: &mut Dispatcher,
    socket: &crate::transport::udp::UdpSockets,
    ui_event_tx: &mpsc::UnboundedSender<UiEvent>,
    tcp_map: &std::sync::Arc<tokio::sync::RwLock<HashMap<std::net::SocketAddr, tokio::sync::mpsc::Sender<Bytes>>>>,
) -> Result<()> {
    // Stream data goes out in datagrams that fit the MTU (reads are up to
    // 4 KiB: as one datagram that was three IP fragments).
    if let RelayMessage::Data(data) = &msg {
        let max = dispatcher.max_payload(session_id).unwrap_or(usize::MAX);
        if data.len() + ostp_core::relay::DATA_OVERHEAD > max {
            for chunk in ostp_core::relay::data_chunks(data, max) {
                send_one(session_id, stream_id, RelayMessage::Data(chunk.to_vec()), dispatcher, socket, ui_event_tx, tcp_map).await?;
            }
            return Ok(());
        }
    }
    send_one(session_id, stream_id, msg, dispatcher, socket, ui_event_tx, tcp_map).await
}

async fn send_one(
    session_id: u32,
    stream_id: u32,
    msg: RelayMessage,
    dispatcher: &mut Dispatcher,
    socket: &crate::transport::udp::UdpSockets,
    _ui_event_tx: &mpsc::UnboundedSender<UiEvent>,
    tcp_map: &std::sync::Arc<tokio::sync::RwLock<HashMap<std::net::SocketAddr, tokio::sync::mpsc::Sender<Bytes>>>>,
) -> Result<()> {
    // UDP of a v6 session goes as an unsequenced datagram that is never
    // resent; everything else is stream data.
    let datagram = matches!(msg, RelayMessage::UdpData(..)) && dispatcher.is_v6(session_id);
    let payload = Bytes::from(msg.encode());
    let outbound = if datagram {
        dispatcher.datagram_to_session(session_id, stream_id, payload)?
    } else {
        dispatcher.outbound_to_session(session_id, stream_id, payload)?
    };
    if let Some((frame, peer_addr)) = outbound {
        let mut sent_tcp = false;
        {
            let map = tcp_map.read().await;
            if let Some(tx) = map.get(&peer_addr) {
                crate::queue_to_tcp(tx, frame.clone());
                sent_tcp = true;
            }
        }
        if !sent_tcp {
            if let Err(e) = socket.send_to(&frame, peer_addr).await {
                crate::logs::send_failed(peer_addr, &e);
            }
        }
    }
    Ok(())
}
