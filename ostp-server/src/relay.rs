use anyhow::Result;
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::Arc;

use ostp_core::relay::RelayMessage;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;

use crate::dispatcher::Dispatcher;
use crate::send_gate::{SendGate, StreamWindow};
use crate::{FromTarget, RemoteState, SessionBackpressure, StreamOut, UiEvent};

/// A target connection that is up. The server loop starts its reader and
/// writer (`start`) only if the stream is still wanted; dropped instead, it
/// closes the connection and gives the key's connection slot back.
pub(crate) struct Connected {
    reader: tokio::net::tcp::OwnedReadHalf,
    writer: tokio::net::tcp::OwnedWriteHalf,
    permit: tokio::sync::OwnedSemaphorePermit,
    gate: Arc<SendGate>,
    payload: Option<Arc<std::sync::atomic::AtomicUsize>>,
    window: Option<Arc<StreamWindow>>,
    v6: bool,
}

/// The outcome of a stream's `Connect`, for the server loop. `token` tells
/// this attempt apart from the stream ending meanwhile or a newer session
/// under the same id (`Dispatcher::finish_connect`).
pub(crate) struct ConnectDone {
    pub session_id: u32,
    pub stream_id: u32,
    pub token: u64,
    pub target: String,
    pub result: Result<Connected, String>,
}

pub(crate) type ConnectTx = mpsc::UnboundedSender<ConnectDone>;

/// What the server loop keeps of a started target connection.
pub(crate) struct Started {
    pub writer: tokio::net::tcp::OwnedWriteHalf,
    pub cancel_tx: mpsc::Sender<()>,
    pub window: Option<Arc<StreamWindow>>,
}

impl Connected {
    /// Starts reading the target toward the client.
    pub fn start(self, session_id: u32, stream_id: u32, stream_tx: mpsc::UnboundedSender<FromTarget>) -> Started {
        let Connected { reader, writer, permit, gate, payload, window, v6 } = self;
        let (cancel_tx, cancel_rx) = mpsc::channel::<()>(1);
        let reader_window = window.clone();
        tokio::spawn(async move {
            let _permit = permit;
            read_target(reader, cancel_rx, gate, payload, reader_window, v6, session_id, stream_id, stream_tx).await;
        });
        Started { writer, cancel_tx, window }
    }
}

/// How much stream data one datagram of the session carries: read anew for
/// each read, because it grows while the session finds the path's MTU (a
/// handle shared with the machine).
fn frame_payload(handle: &Option<Arc<std::sync::atomic::AtomicUsize>>) -> usize {
    handle
        .as_ref()
        .map_or(1300, |h| h.load(std::sync::atomic::Ordering::Relaxed))
        .saturating_sub(ostp_core::relay::DATA_OVERHEAD)
        .max(1)
}

/// Reads a target and hands its data to the server loop, no faster than the
/// client-facing session may send it.
///
/// Before a read the reader waits until the session has room, and sizes the
/// read to it; after the read it claims frames for what it got (`claim`,
/// atomic) and hands over only what it claimed, waiting for more room for
/// the rest. A target that answers long after the reader parked therefore
/// cannot push its read past the budget, and readers woken together share
/// the budget rather than each spending all of it.
#[allow(clippy::too_many_arguments)]
async fn read_target(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    mut cancel_rx: mpsc::Receiver<()>,
    gate: Arc<SendGate>,
    payload: Option<Arc<std::sync::atomic::AtomicUsize>>,
    window: Option<Arc<StreamWindow>>,
    v6: bool,
    session_id: u32,
    stream_id: u32,
    stream_tx: mpsc::UnboundedSender<FromTarget>,
) {
    let message = |out: StreamOut| FromTarget { session_id, stream_id, gate: gate.clone(), out };
    let mut buf = vec![0_u8; READ_BUF];
    'reading: loop {
        let room = tokio::select! {
            _ = cancel_rx.recv() => break,
            room = gate.wait_for_room() => room,
        };
        let fp = frame_payload(&payload);
        let mut want = (room as usize).saturating_mul(fp).clamp(1, READER_QUANTUM.min(READ_BUF));
        if let Some(window) = &window {
            let credit = tokio::select! {
                _ = cancel_rx.recv() => break,
                credit = window.acquire() => credit,
            };
            want = want.min(credit as usize).max(1);
        }
        let n = tokio::select! {
            _ = cancel_rx.recv() => break,
            read_res = reader.read(&mut buf[..want]) => match read_res {
                Ok(0) if v6 => {
                    let _ = stream_tx.send(message(StreamOut::Fin));
                    break;
                }
                Ok(0) | Err(_) => {
                    let _ = stream_tx.send(message(StreamOut::Close));
                    break;
                }
                Ok(n) => n,
            },
        };
        if let Some(window) = &window {
            window.spend(n as i64);
        }
        let mut off = 0;
        while off < n {
            let need = (n - off).div_ceil(fp) as i64;
            let got = tokio::select! {
                _ = cancel_rx.recv() => break 'reading,
                got = gate.claim(need) => got,
            };
            let len = (got as usize).saturating_mul(fp).min(n - off);
            if stream_tx.send(message(StreamOut::Data(buf[off..off + len].to_vec(), got))).is_err() {
                gate.sent(got);
                break 'reading;
            }
            off += len;
            // The other streams' turn before this one takes from the budget
            // again.
            tokio::task::yield_now().await;
        }
    }
}

/// Largest read from a target at once. 4 KiB meant a syscall and a message
/// per three datagrams plus a short fourth one; 64 KiB fills whole frames.
const READ_BUF: usize = 64 * 1024;
/// The most one reader takes from the session's send budget at a time. All
/// readers of a session wake when the budget is refreshed and the first one
/// used to take all of it: a bulk download, always ready, kept a page or a
/// video waiting behind it. Taking turns in quanta gives each busy stream a
/// share, as a round-robin scheduler does (deficit round robin, Shreedhar and
/// Varghese 1996; the flow queueing of RFC 8290).
const READER_QUANTUM: usize = 16 * 1024;

/// Datagrams from the client waiting to go out of one UDP-associate stream;
/// past this they are dropped, as UDP may.
const UDP_STREAM_QUEUE: usize = 256;

/// Errors in a row after which a UDP association stops reading its outbound
/// proxy's socket (direct replies still arrive), and the pause after each.
const PROXY_UDP_MAX_ERRORS: u32 = 64;
const PROXY_UDP_ERROR_BACKOFF: std::time::Duration = std::time::Duration::from_millis(50);

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
    udp_reply_tx: mpsc::Sender<(u32, u32, String, Vec<u8>)>,
    connect_tx: ConnectTx,
    router: std::sync::Arc<crate::router::Router>,
    tcp_map: &std::sync::Arc<tokio::sync::RwLock<HashMap<std::net::SocketAddr, tokio::sync::mpsc::Sender<Bytes>>>>,
    session_backpressure: &SessionBackpressure,
) -> Result<()> {
    let msg = RelayMessage::decode(&payload)?;
    handle_message(
        peer_addr, session_id, stream_id, msg, dispatcher, socket, remotes, ui_event_tx, udp_reply_tx,
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
    udp_reply_tx: mpsc::Sender<(u32, u32, String, Vec<u8>)>,
    connect_tx: ConnectTx,
    router: std::sync::Arc<crate::router::Router>,
    tcp_map: &std::sync::Arc<tokio::sync::RwLock<HashMap<std::net::SocketAddr, tokio::sync::mpsc::Sender<Bytes>>>>,
    session_backpressure: &SessionBackpressure,
) -> Result<()> {
    match msg {
        RelayMessage::Connect(target) => {
            if !open_v6_stream(session_id, stream_id, dispatcher, socket, ui_event_tx, tcp_map).await {
                return Ok(());
            }
            let token = dispatcher.begin_connect(session_id, stream_id);
            let refuse = |target: String, why: &str| {
                let _ = connect_tx.send(ConnectDone { session_id, stream_id, token, target, result: Err(why.into()) });
            };
            let Some(permit) = dispatcher.stream_permit(session_id) else {
                refuse(target, "too many open connections for this key");
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
                refuse(target, "encrypted DNS is blocked: this server filters DNS");
                return Ok(());
            } else if router.overnet().refuses_encrypted_dns(&connect_target) {
                // Same fallback, so `.ov` names reach the server's port-53 answer.
                refuse(target, "encrypted DNS is blocked: this server serves .ov");
                return Ok(());
            }

            let target_clone = connect_target.clone();
            let connect_tx_clone = connect_tx.clone();
            let router_clone = router.clone();
            // Get-or-create this session's gate. A brand new session may not
            // have had its first update yet, so it starts open (a fresh
            // congestion window) rather than stalling the very first read.
            let gate: Arc<SendGate> = {
                let mut map = session_backpressure.write().unwrap_or_else(|e| e.into_inner());
                map.entry(session_id).or_insert_with(|| Arc::new(SendGate::new(32))).clone()
            };
            let payload = dispatcher.max_payload_handle(session_id);
            // The client grants this stream's download as its program reads it.
            let window = dispatcher
                .flow_control(session_id)
                .then(|| Arc::new(StreamWindow::new(ostp_core::relay::INITIAL_STREAM_WINDOW as i64)));
            // v6: the target's end of stream is a half-close (`Fin`), not the
            // end of the stream; in v5 it is the `Close` it always was.
            let v6 = dispatcher.is_v6(session_id);
            tokio::spawn(async move {
                let stream_res = router_clone.route_tcp(&target_clone, peer_addr.ip()).await;
                // The reader is started by the server loop, and only if the
                // stream is still open by then: a stream (or session) that
                // ended while this connect was under way used to keep the
                // target's connection, its reader and the key's slot forever.
                let result = stream_res.map_err(|e| e.to_string()).map(|stream| {
                    let (reader, writer) = stream.into_split();
                    Connected { reader, writer, permit, gate, payload, window, v6 }
                });
                let _ = connect_tx_clone.send(ConnectDone { session_id, stream_id, token, target: target_clone, result });
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
                    // As when the slot is refused above: v6 opened the stream,
                    // so the client is told and the stream is released (v5:
                    // silent, as before). The permit goes back when dropped.
                    if dispatcher.is_v6(session_id) {
                        let _ = send_relay_to_stream(session_id, stream_id, RelayMessage::Error(format!("UDP associate failed: {e}")), dispatcher, socket, ui_event_tx, tcp_map).await;
                        dispatcher.release_stream(session_id, stream_id);
                    }
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
                // Errors in a row from the proxy's socket. One error is a bad
                // packet; a socket failing every time (closed, or ICMP
                // errors) used to spin this loop at full speed.
                let mut proxy_errors = 0_u32;
                loop {
                    if let Some(p) = proxy_sock.as_ref().filter(|_| proxy_errors < PROXY_UDP_MAX_ERRORS) {
                        tokio::select! {
                            _ = cancel_rx.recv() => break,
                            res = rx_sock.recv_from(&mut direct_buf) => {
                                if let Ok((len, addr)) = res {
                                    let _ = udp_reply_clone.try_send((session_id, stream_id, clean_ipv6_mapped_v4(addr).to_string(), direct_buf[..len].to_vec()));
                                } else { break; }
                            }
                            res = p.recv_from(&mut proxy_buf) => {
                                match res {
                                    Ok((len, target_str)) => {
                                        proxy_errors = 0;
                                        let _ = udp_reply_clone.try_send((session_id, stream_id, target_str, proxy_buf[..len].to_vec()));
                                    }
                                    Err(e) => {
                                        proxy_errors += 1;
                                        if proxy_errors == PROXY_UDP_MAX_ERRORS {
                                            tracing::debug!("UDP association [{session_id}:{stream_id}]: the proxy socket keeps failing ({e}), no longer read");
                                        }
                                        tokio::time::sleep(PROXY_UDP_ERROR_BACKOFF).await;
                                    }
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
                    // No IPv6 here: an IPv6 address would only give the
                    // device a connection that is reset (see `ipv6_egress`).
                    if !router.ipv6_egress {
                        if let Some(response) = ostp_dns::empty_answer_for_aaaa(&data) {
                            let _ = udp_reply_tx.try_send((session_id, stream_id, target, response));
                            return Ok(());
                        }
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
    // Data (TCP or UDP) may be dropped from a full TCP/TLS queue; the stream
    // and session control messages wait for room.
    let urgency = if matches!(msg, RelayMessage::Data(_) | RelayMessage::UdpData(..)) {
        crate::Urgency::Data
    } else {
        crate::Urgency::Control
    };
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
                crate::queue_to_tcp(tx, frame.clone(), urgency);
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
