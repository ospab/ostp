use anyhow::Result;
use tokio::net::TcpStream;
use crate::config::{TransportConfig, MultiplexConfig};

use ostp_core::{OstpEvent, ProtocolAction, ProtocolConfig, ProtocolMachine};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Build the handshake payload the server expects:
/// [timestamp_u64_be (8 bytes)] [session_id_u32_be (4 bytes)] [access_key bytes]
fn build_handshake_payload(session_id: u32, access_key: &str) -> Vec<u8> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut payload = Vec::with_capacity(12 + access_key.len());
    payload.extend_from_slice(&ts.to_be_bytes());
    payload.extend_from_slice(&session_id.to_be_bytes());
    payload.extend_from_slice(access_key.as_bytes());
    payload
}

/// Build a correctly configured ProtocolConfig for an outgoing OSTP connection.
fn make_initiator_config(
    session_id: u32,
    access_key: &str,
    transport_cfg: &TransportConfig,
) -> ProtocolConfig {
    let secrets = ostp_core::crypto::derive_all_secrets(access_key.as_bytes());
    let payload = build_handshake_payload(session_id, access_key);
    
    let mtu = match transport_cfg.r#type.as_str() {
        "dns" => 1100,
        _ => 1350,
    };
    // For DNS transport: use larger ack_delay and rto to match DNS round-trip latency
    // (each DNS query + reply takes 300-800ms end-to-end through Cloudflare).
    // For UDP: minimize ack_delay to 1ms (ACK asap) and let CC drive the RTO.
    let (ack_delay_ms, rto_ms) = match transport_cfg.r#type.as_str() {
        "dns" => (50, 1500),
        _ => (1, 200),
    };

    ProtocolConfig {
        role: ostp_core::NoiseRole::Initiator,
        psk: secrets.psk,
        session_id,
        handshake_payload: payload,
        max_padding: 1024,
        padding_strategy: ostp_core::framing::PaddingStrategy::Adaptive,
        obfuscation_key: secrets.obfuscation_key,
        max_reorder: 16384,
        max_reorder_buffer: 8192,
        ack_delay_ms,
        rto_ms,
        max_retries: 8,
        max_sent_history: 32768,
        handshake_pad_min: secrets.handshake_pad_min,
        handshake_pad_max: secrets.handshake_pad_max,
        mtu,
    }
}

fn random_session_id() -> u32 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    std::time::Instant::now().hash(&mut h);
    std::thread::current().id().hash(&mut h);
    h.finish() as u32
}

pub async fn dial_tcp(
    target_host: &str,
    target_port: u16,
    server: &str,
    port: u16,
    access_key: &str,
    transport_cfg: &TransportConfig,
    _multiplex: &MultiplexConfig,
    metrics: Option<std::sync::Arc<crate::bridge::BridgeMetrics>>,
) -> Result<TcpStream> {
    tracing::info!("Dialing OSTP server {}:{} for target {}:{}", server, port, target_host, target_port);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let local_addr = listener.local_addr()?;
    let client_stream = tokio::net::TcpStream::connect(local_addr).await?;
    let (mut server_stream, _) = listener.accept().await?;

    let transport = make_transport(transport_cfg, server, port).await?;

    let session_id = random_session_id();
    let config = make_initiator_config(session_id, access_key, transport_cfg);
    let mut machine = ProtocolMachine::new(config).unwrap();

    let target_host_str = target_host.to_string();

        let server_str = server.to_string();
        
        // Spawn bridge task
        tokio::spawn(async move {
            // Send initial handshake
            if let Ok(action) = machine.on_event(OstpEvent::Start) {
                handle_action(action, &transport, &mut server_stream).await;
            }
    
            // Wait for handshake response (server sends HandshakePayload back)
            let mut buf = [0u8; 8192];
            let mut handshake_success = false;
            match tokio::time::timeout(
                std::time::Duration::from_millis(15000),
                transport.recv(&mut buf),
            ).await {
                Ok(Ok(n)) => {
                    if let Ok(action) = machine.on_event(OstpEvent::Inbound(bytes::Bytes::copy_from_slice(&buf[..n]))) {
                        handle_action(action, &transport, &mut server_stream).await;
                        handshake_success = true;
                    }
                }
                _ => {
                    tracing::warn!("OSTP handshake timeout for {}:{}", server_str, port);
                    return;
                }
            }

        if !handshake_success {
            // A single proxied connection failing must NOT mark the whole tunnel
            // as disconnected — global connection_state is owned by the health
            // probe in run_client_core, not by per-target dials.
            tracing::warn!("TCP handshake failed or protocol machine error");
            return;
        }

        // The global health probe (in runner.rs) is the only authoritative source of connection state.

        // Send connection request
        let connect_msg = ostp_core::relay::RelayMessage::Connect(format!("{}:{}", target_host_str, target_port));
        let connect_encoded = connect_msg.encode();
        if let Ok(action) = machine.on_event(OstpEvent::Outbound(1, bytes::Bytes::from(connect_encoded))) {
            handle_action(action, &transport, &mut server_stream).await;
        }

        // ── Wait for ConnectOk before forwarding any data ─────────────────
        // This is critical: if we enter the data loop immediately, the TLS
        // ClientHello arrives at the server before it has established the
        // outbound TCP connection, causing it to drop the packet as
        // "Relay DATA for unknown stream".
        // The kernel will buffer incoming data from server_stream while we wait.
        let mut connect_ok = false;
        match tokio::time::timeout(
            std::time::Duration::from_secs(30),
            async {
                let mut wait_buf = [0u8; 8192];
                loop {
                    tokio::select! {
                        Ok(n) = transport.recv(&mut wait_buf) => {
                            if let Ok(action) = machine.on_event(OstpEvent::Inbound(
                                bytes::Bytes::copy_from_slice(&wait_buf[..n]),
                            )) {
                                // Check for ConnectOk or Error before dispatching
                                let result = check_connect_result(&action);
                                handle_action(action, &transport, &mut server_stream).await;
                                match result {
                                    Some(true) => return true,
                                    Some(false) => return false,
                                    None => {}
                                }
                            }
                        }
                        _ = tokio::time::sleep(std::time::Duration::from_millis(10)) => {
                            if let Ok(action) = machine.on_event(OstpEvent::Tick) {
                                handle_action(action, &transport, &mut server_stream).await;
                            }
                        }
                    }
                }
            },
        )
        .await
        {
            Ok(true) => {
                tracing::debug!("ConnectOk received for {}:{}, starting data forwarding", target_host_str, target_port);
                connect_ok = true;
            }
            Ok(false) => {
                tracing::warn!("Server refused connection to {}:{}", target_host_str, target_port);
            }
            Err(_) => {
                tracing::warn!("ConnectOk timeout for {}:{}", target_host_str, target_port);
            }
        }

        if !connect_ok {
            return;
        }

        // ── Main bidirectional data forwarding loop ───────────────────────
        // Backpressure: we track how many frames are in-flight vs the congestion
        // window. When the window is full we stop reading from the TCP stream
        // (the kernel buffers it) until the remote ACKs enough frames.
        // This prevents overrunning the sender's sent_history and collapsing cwnd.
        let mut buf = [0u8; 65535];
        let mut udp_buf = [0u8; 65535];

        loop {
            // Compute adaptive tick interval:
            //   - If there is a pending ACK: tick = ack_delay (flush it quickly)
            //   - Otherwise: tick = rto/4 (check retransmits without busy-spinning)
            //   Floor at 1ms, ceiling at 50ms.
            let tick_ms = (machine.rto().as_millis() / 4).clamp(1, 50) as u64;

            let can_send = machine.in_flight_count() < machine.cwnd_packets().max(4);

            tokio::select! {
                // Only read from the application TCP stream when cwnd allows
                Ok(n) = server_stream.read(&mut buf), if can_send => {
                    if n == 0 { break; }
                    let data_msg = ostp_core::relay::RelayMessage::Data(buf[..n].to_vec());
                    let encoded = data_msg.encode();
                    if let Ok(action) = machine.on_event(OstpEvent::Outbound(1, bytes::Bytes::from(encoded))) {
                        handle_action(action, &transport, &mut server_stream).await;
                    }
                }
                Ok(n) = transport.recv(&mut udp_buf) => {
                    if let Ok(action) = machine.on_event(OstpEvent::Inbound(bytes::Bytes::copy_from_slice(&udp_buf[..n]))) {
                        handle_action(action, &transport, &mut server_stream).await;
                    }
                }
                _ = tokio::time::sleep(std::time::Duration::from_millis(tick_ms)) => {
                    if let Ok(action) = machine.on_event(OstpEvent::Tick) {
                        handle_action(action, &transport, &mut server_stream).await;
                    }
                }
            }
        }
    });


    Ok(client_stream)
}

pub async fn handle_udp(
    client_src: std::net::SocketAddr,
    target_dst: std::net::SocketAddr,
    payload: bytes::Bytes,
    server: &str,
    port: u16,
    access_key: &str,
    transport_cfg: &TransportConfig,
    _multiplex: &MultiplexConfig,
    metrics: Option<std::sync::Arc<crate::bridge::BridgeMetrics>>,
) -> Result<()> {
    let transport = make_transport(transport_cfg, server, port).await?;

    // Derive session_id from client source addr for stable per-flow sessions
    let ip_bytes = match client_src.ip() {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            u32::from_be_bytes(o)
        }
        std::net::IpAddr::V6(v6) => {
            let o = v6.octets();
            u32::from_be_bytes([o[12], o[13], o[14], o[15]])
        }
    };
    let session_id = ip_bytes ^ (client_src.port() as u32);

    let config = make_initiator_config(session_id, access_key, transport_cfg);
    let mut machine = ProtocolMachine::new(config)?;

    // Amnezia-style junk to break DPI heuristics — but ONLY over stream
    // transports (UoT/TCP), where it rides inside the connection. Over plain
    // UDP each junk is a standalone datagram of random bytes that the server
    // cannot tell from a port scan: it logs every one as an "Unauthorized
    // probe", wastes CPU trying every key on it, and can trip the server's
    // anti-probe defenses against this very client. The server is not
    // coordinated to expect/discard junk (unlike AmneziaWG's Jc/Jmin/Jmax), so
    // junk-over-UDP is pure self-inflicted noise. Gate it to stream transports.
    use rand::Rng;
    let junk_enabled = matches!(transport_cfg.r#type.as_str(), "uot" | "tcp");
    if junk_enabled {
        let num_junk = rand::thread_rng().gen_range(2..=5);
        for _ in 0..num_junk {
            let junk_len = rand::thread_rng().gen_range(100..=1000);
            let mut junk = vec![0u8; junk_len];
            rand::thread_rng().fill(&mut junk[..]);
            let junk_bytes = bytes::Bytes::from(junk);
            let _ = transport.send(&junk_bytes).await;
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }

    // Send handshake first
    let hs_start = std::time::Instant::now();
    if let Ok(action) = machine.on_event(OstpEvent::Start) {
        handle_udp_action(action, &transport).await;
    }

    // Wait for handshake response (server sends HandshakePayload back)
    let mut buf = [0u8; 8192];
    match tokio::time::timeout(
        std::time::Duration::from_millis(15000),
        transport.recv(&mut buf),
    ).await {
        Ok(Ok(n)) => {
            // Real round-trip to the server over the already-protected transport.
            // On Android the separate health-probe socket is NOT VPN-protected
            // (it would route into the tunnel and never reach the server), so this
            // handshake timing is the only reliable RTT source on mobile. We only
            // set rtt here; connection_state stays owned by the health probe.
            if let Some(m) = &metrics {
                m.rtt_ms.store(hs_start.elapsed().as_millis() as u32, std::sync::atomic::Ordering::Relaxed);
            }
            let _ = machine.on_event(OstpEvent::Inbound(bytes::Bytes::copy_from_slice(&buf[..n])));
        }
        _ => {
            // Per-dial timeout: do not touch global connection_state (owned by the
            // health probe). Just give up on this one target connection.
            tracing::warn!("OSTP handshake timeout for {}:{}", server, port);
            return Ok(());
        }
    }

    // Send relay UdpAssociate + data
    let assoc_msg = ostp_core::relay::RelayMessage::UdpAssociate;
    let encoded = assoc_msg.encode();
    if let Ok(action) = machine.on_event(OstpEvent::Outbound(1, bytes::Bytes::from(encoded))) {
        handle_udp_action(action, &transport).await;
    }

    let data_msg = ostp_core::relay::RelayMessage::UdpData(
        format!("{}:{}", target_dst.ip(), target_dst.port()),
        payload.to_vec()
    );
    let encoded = data_msg.encode();
    if let Ok(action) = machine.on_event(OstpEvent::Outbound(1, bytes::Bytes::from(encoded))) {
        handle_udp_action(action, &transport).await;
    }

    // Keep-alive for a short time to receive response
    for _ in 0..5 {
        match tokio::time::timeout(
            std::time::Duration::from_millis(100),
            transport.recv(&mut buf),
        ).await {
            Ok(Ok(n)) => {
                if let Ok(action) = machine.on_event(OstpEvent::Inbound(bytes::Bytes::copy_from_slice(&buf[..n]))) {
                    // Just process incoming UDP response internally
                    let _ = action;
                }
            }
            _ => break,
        }
    }

    Ok(())
}

async fn make_transport(
    transport_cfg: &TransportConfig,
    server: &str,
    port: u16,
) -> Result<crate::transport::Transport> {
    let debug = tracing::enabled!(tracing::Level::DEBUG);
    match transport_cfg.r#type.as_str() {
        "dns" => {
            let domain = transport_cfg.domain.clone()
                .unwrap_or_else(|| "tunnel.example.com".to_string());
            let pubkey = transport_cfg.pubkey.clone()
                .unwrap_or_else(|| "".to_string());
            let resolver = transport_cfg.resolver.clone()
                .unwrap_or_else(|| server.to_string());
            let resolver_with_port = if resolver.contains(':') {
                resolver.clone()
            } else {
                format!("{}:53", resolver)
            };
                
            let (local_port, process) = ostp_core::dnstt::spawn_client(&pubkey, &domain, &resolver_with_port, debug)?;
            
            // Wait for dnstt-client to start its local TCP listener
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            
            // Connect TCP to the local dnstt-client port
            let stream = tokio::net::TcpStream::connect(("127.0.0.1", local_port)).await?;
            let (mut rh, mut wh) = stream.into_split();
            
            let (tx_send, mut tx_recv) = tokio::sync::mpsc::channel::<bytes::Bytes>(1024);
            let (rx_send, rx_recv) = tokio::sync::mpsc::channel::<bytes::Bytes>(1024);
            
            // Writer task
            tokio::spawn(async move {
                use tokio::io::AsyncWriteExt;
                while let Some(data) = tx_recv.recv().await {
                    let len = data.len() as u16;
                    if wh.write_u16(len).await.is_err() { break; }
                    if wh.write_all(&data).await.is_err() { break; }
                }
            });
            
            // Reader task
            tokio::spawn(async move {
                use tokio::io::AsyncReadExt;
                loop {
                    let len = match rh.read_u16().await {
                        Ok(l) => l,
                        Err(_) => break,
                    };
                    let mut buf = vec![0u8; len as usize];
                    if rh.read_exact(&mut buf).await.is_err() { break; }
                    if rx_send.send(bytes::Bytes::from(buf)).await.is_err() { break; }
                }
            });
            
            Ok(crate::transport::Transport::Dnstt {
                tx: tx_send,
                rx: std::sync::Arc::new(tokio::sync::Mutex::new(rx_recv)),
                _guard: std::sync::Arc::new(tokio::sync::Mutex::new(process)),
            })
        }
        "uot" | "tcp" => {
            let stream = tokio::net::TcpStream::connect((server, port)).await?;
            let _ = stream.set_nodelay(true);
            let (mut rh, mut wh) = stream.into_split();
            
            let (tx_send, mut tx_recv) = tokio::sync::mpsc::channel::<bytes::Bytes>(1024);
            let (rx_send, rx_recv) = tokio::sync::mpsc::channel::<bytes::Bytes>(1024);
            
            let tcp_fragmentation = transport_cfg.tcp_fragmentation;

            // Writer task
            tokio::spawn(async move {
                use tokio::io::AsyncWriteExt;
                let mut first_packet = true;
                while let Some(data) = tx_recv.recv().await {
                    let mut len_buf = [0u8; 2];
                    len_buf.copy_from_slice(&(data.len() as u16).to_be_bytes());
                    
                    if first_packet && tcp_fragmentation {
                        first_packet = false;
                        // Split the length header and first byte of payload
                        if wh.write_all(&len_buf[0..1]).await.is_err() { break; }
                        tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
                        if wh.write_all(&len_buf[1..2]).await.is_err() { break; }
                        tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
                        
                        // Send data in 1-2 byte chunks for the first packet (handshake)
                        for chunk in data.chunks(2) {
                            if wh.write_all(chunk).await.is_err() { break; }
                            tokio::time::sleep(tokio::time::Duration::from_millis(2)).await;
                        }
                    } else {
                        if wh.write_all(&len_buf).await.is_err() { break; }
                        if wh.write_all(&data).await.is_err() { break; }
                    }
                }
            });
            
            // Reader task
            tokio::spawn(async move {
                use tokio::io::AsyncReadExt;
                loop {
                    let mut len_buf = [0u8; 2];
                    if rh.read_exact(&mut len_buf).await.is_err() { break; }
                    let len = u16::from_be_bytes(len_buf) as usize;
                    let mut buf = vec![0u8; len];
                    if rh.read_exact(&mut buf).await.is_err() { break; }
                    if rx_send.send(bytes::Bytes::from(buf)).await.is_err() { break; }
                }
            });
            
            Ok(crate::transport::Transport::Uot {
                tx: tx_send,
                rx: std::sync::Arc::new(tokio::sync::Mutex::new(rx_recv)),
            })
        }
        _ => {
            let udp = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
            udp.connect((server, port)).await?;
            Ok(crate::transport::Transport::Udp(std::sync::Arc::new(udp)))
        }
    }
}

async fn handle_udp_action(action: ProtocolAction, transport: &crate::transport::Transport) {
    match action {
        ProtocolAction::SendDatagram(data) => {
            let _ = transport.send(&data).await;
        }
        ProtocolAction::Multiple(actions) => {
            for a in actions {
                if let ProtocolAction::SendDatagram(data) = a {
                    let _ = transport.send(&data).await;
                }
            }
        }
        _ => {}
    }
}

async fn handle_action(action: ProtocolAction, transport: &crate::transport::Transport, server_stream: &mut tokio::net::TcpStream) {
    match action {
        ProtocolAction::SendDatagram(data) => {
            let _ = transport.send(&data).await;
        }
        ProtocolAction::DeliverApp(_stream_id, payload) => {
            if let Ok(msg) = ostp_core::relay::RelayMessage::decode(&payload) {
                match msg {
                    ostp_core::relay::RelayMessage::Data(data) => {
                        let _ = server_stream.write_all(&data).await;
                    }
                    ostp_core::relay::RelayMessage::ConnectOk => {
                        tracing::debug!("TCP Connection established successfully");
                    }
                    ostp_core::relay::RelayMessage::Error(err) => {
                        tracing::warn!("Server returned TCP connection error: {}", err);
                    }
                    _ => {}
                }
            }
        }
        ProtocolAction::Multiple(actions) => {
            for a in actions {
                Box::pin(handle_action(a, transport, server_stream)).await;
            }
        }
        _ => {}
    }
}

/// Inspect a ProtocolAction for ConnectOk / Error relay messages.
/// Returns Some(true) on ConnectOk, Some(false) on Error, None if neither.
/// Works recursively through Multiple actions.
fn check_connect_result(action: &ProtocolAction) -> Option<bool> {
    match action {
        ProtocolAction::DeliverApp(_stream_id, payload) => {
            if let Ok(msg) = ostp_core::relay::RelayMessage::decode(payload) {
                match msg {
                    ostp_core::relay::RelayMessage::ConnectOk => return Some(true),
                    ostp_core::relay::RelayMessage::Error(_) => return Some(false),
                    _ => {}
                }
            }
            None
        }
        ProtocolAction::Multiple(actions) => {
            for a in actions {
                if let Some(result) = check_connect_result(a) {
                    return Some(result);
                }
            }
            None
        }
        _ => None,
    }
}
