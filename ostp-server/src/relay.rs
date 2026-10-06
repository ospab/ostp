use anyhow::Result;
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::Arc;

use ostp_core::relay::RelayMessage;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;

use crate::dispatcher::Dispatcher;
use crate::send_gate::SendGate;
use crate::{RemoteState, SessionBackpressure, UiEvent};

/// Largest read from a target at once. 4 KiB meant a syscall and a message
/// per three datagrams plus a short fourth one; 64 KiB fills whole frames.
const READ_BUF: usize = 64 * 1024;

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


pub async fn handle_relay_message(
    peer_addr: std::net::SocketAddr,
    session_id: u32,
    stream_id: u16,
    payload: Bytes,
    dispatcher: &mut Dispatcher,
    socket: &crate::transport::udp::UdpSockets,
    remotes: &mut HashMap<(u32, u16), RemoteState>,
    ui_event_tx: &mpsc::UnboundedSender<UiEvent>,
    stream_tx: mpsc::UnboundedSender<(u32, u16, Vec<u8>)>,
    udp_reply_tx: mpsc::UnboundedSender<(u32, u16, String, Vec<u8>)>,
    connect_tx: mpsc::UnboundedSender<(u32, u16, String, Result<(tokio::net::tcp::OwnedWriteHalf, mpsc::Sender<()>), String>)>,
    router: std::sync::Arc<crate::router::Router>,
    tcp_map: &std::sync::Arc<tokio::sync::RwLock<HashMap<std::net::SocketAddr, tokio::sync::mpsc::Sender<Bytes>>>>,
    session_backpressure: &SessionBackpressure,
) -> Result<()> {
    match RelayMessage::decode(&payload)? {
        RelayMessage::Connect(target) => {
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
            if port == "53" && router.dns_server.intercepts() {
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
            let frame_payload = dispatcher
                .max_payload(session_id)
                .unwrap_or(1300)
                .saturating_sub(ostp_core::relay::DATA_OVERHEAD)
                .max(1);
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
                                let want = (budget as usize).saturating_mul(frame_payload).clamp(1, READ_BUF);
                                tokio::select! {
                                    _ = cancel_rx.recv() => break,
                                    read_res = reader.read(&mut buf[..want]) => {
                                        match read_res {
                                            Ok(0) | Err(_) => {
                                                let _ = stream_tx_clone.send((session_id, stream_id, Vec::new()));
                                                break;
                                            }
                                            Ok(n) => {
                                                gate.spend(n.div_ceil(frame_payload) as i64);
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
                use std::sync::atomic::Ordering;
                let queued = remote.queued.fetch_add(data.len(), Ordering::Relaxed) + data.len();
                if queued > crate::MAX_QUEUED_UPLOAD {
                    // The target does not take the data as fast as the client
                    // sends it; reset the stream rather than buffer without end.
                    tracing::warn!("Stream [{session_id}:{stream_id}]: over {} MB waiting for the target, resetting it", crate::MAX_QUEUED_UPLOAD >> 20);
                    if let Some(state) = remotes.remove(&(session_id, stream_id)) {
                        let _ = state.cancel_tx.try_send(());
                    }
                    send_relay_to_stream(session_id, stream_id, RelayMessage::Error("the target does not accept data this fast".into()), dispatcher, socket, ui_event_tx, tcp_map).await?;
                    return Ok(());
                }
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
            send_relay_to_stream(session_id, stream_id, RelayMessage::Pong(ts), dispatcher, socket, ui_event_tx, tcp_map).await?;
        }
        RelayMessage::Pong(_) => {}
        RelayMessage::UdpAssociate => {
            let Some(permit) = dispatcher.stream_permit(session_id) else {
                let _ = ui_event_tx.send(UiEvent::Log(format!("UDP associate refused for session {session_id}: too many open connections for its key")));
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
            
            let (udp_tx, mut udp_rx) = mpsc::unbounded_channel::<(String, Bytes)>();
            let (cancel_tx, mut cancel_rx) = mpsc::channel::<()>(1);
            let (dummy_data_tx, _) = mpsc::unbounded_channel::<Bytes>();

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
                                    let _ = udp_reply_clone.send((session_id, stream_id, clean_ipv6_mapped_v4(addr).to_string(), direct_buf[..len].to_vec()));
                                } else { break; }
                            }
                            res = p.recv_from(&mut proxy_buf) => {
                                if let Ok((len, target_str)) = res {
                                    let _ = udp_reply_clone.send((session_id, stream_id, target_str, proxy_buf[..len].to_vec()));
                                }
                            }
                        }
                    } else {
                        tokio::select! {
                            _ = cancel_rx.recv() => break,
                            res = rx_sock.recv_from(&mut direct_buf) => {
                                if let Ok((len, addr)) = res {
                                    let _ = udp_reply_clone.send((session_id, stream_id, clean_ipv6_mapped_v4(addr).to_string(), direct_buf[..len].to_vec()));
                                } else { break; }
                            }
                        }
                    }
                }
            });


            remotes.insert((session_id, stream_id), RemoteState {
                data_tx: dummy_data_tx,
                queued: Default::default(),
                udp_tx: Some(udp_tx),
                cancel_tx,
                is_dns: false,
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
                        let _ = udp_reply_tx.send((session_id, stream_id, target, response));
                        return Ok(());
                    }
                    let should_intercept = router.dns_server.intercepts();

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
                                    let _ = udp_reply_tx.send((session_id, stream_id, target, response));
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
                    let _ = udp_tx.send((target, Bytes::from(data)));
                }
            } else {
                let _ = ui_event_tx.send(UiEvent::Log(format!("Relay UDP DATA for unknown stream [{session_id}:{stream_id}]")));
            }
        }
    }
    Ok(())
}

pub async fn send_relay_to_stream(
    session_id: u32,
    stream_id: u16,
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
    stream_id: u16,
    msg: RelayMessage,
    dispatcher: &mut Dispatcher,
    socket: &crate::transport::udp::UdpSockets,
    _ui_event_tx: &mpsc::UnboundedSender<UiEvent>,
    tcp_map: &std::sync::Arc<tokio::sync::RwLock<HashMap<std::net::SocketAddr, tokio::sync::mpsc::Sender<Bytes>>>>,
) -> Result<()> {
    let payload = Bytes::from(msg.encode());
    if let Some((frame, peer_addr)) = dispatcher.outbound_to_session(session_id, stream_id, payload)? {
        let mut sent_tcp = false;
        {
            let map = tcp_map.read().await;
            if let Some(tx) = map.get(&peer_addr) {
                crate::queue_to_tcp(tx, frame.clone());
                sent_tcp = true;
            }
        }
        if !sent_tcp {
            let _ = socket.send_to(&frame, peer_addr).await?;
        }
    }
    Ok(())
}
