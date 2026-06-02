import sys
import re

with open("d:/ospab-projects/ostp/ostp-client/src/bridge.rs", "r", encoding="utf-8") as f:
    code = f.read()

start_idx = code.find("    pub async fn run(")
end_idx = -1
brace_count = 0
in_run = False
for i in range(start_idx, len(code)):
    if code[i] == '{':
        in_run = True
        brace_count += 1
    elif code[i] == '}':
        if in_run:
            brace_count -= 1
            if brace_count == 0:
                end_idx = i + 1
                break

prefix = code[:start_idx]
suffix = code[end_idx:]

# Define the new run function and helpers
new_run_and_helpers = """
    pub async fn run(
        mut self,
        tx: mpsc::Sender<UiEvent>,
        mut bridge_rx: mpsc::Receiver<BridgeCommand>,
        mut shutdown: watch::Receiver<bool>,
        mut proxy_rx: mpsc::Receiver<ProxyEvent>,
        proxy_tx: mpsc::UnboundedSender<(u16, ProxyToClientMsg)>,
    ) -> Result<()> {
        let mut metrics_tick = interval(Duration::from_millis(500));
        let mut keepalive_tick = tokio::time::interval(Duration::from_secs(self.keepalive_interval_sec.max(1)));
        let mut retransmit_tick = tokio::time::interval(Duration::from_millis(10));
        let init_msg = if self.mode == "tun" {
            "Bridge initialized (TUN mode)".to_string()
        } else {
            "Bridge initialized (proxy mode)".to_string()
        };
        tx.send(UiEvent::Log(init_msg)).await.ok();

        let mut sessions_opt: Option<Vec<SessionState>> = None;
        let mut udp_rx_opt: Option<mpsc::Receiver<(usize, Bytes)>> = None;
        let mut proxy_guard: Option<crate::sysproxy::SystemProxyGuard> = None;
        let mut stream_map: std::collections::HashMap<u16, usize> = std::collections::HashMap::new();

        loop {
            tokio::select! {
                biased;
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        self.running = false;
                        self.metrics.connection_state.store(0, Ordering::Relaxed);
                        proxy_guard = None;
                        sessions_opt = None;
                        udp_rx_opt = None;
                        stream_map.clear();
                        self.reset_proxy_streams(&tx, &proxy_tx, "manual stop");
                        break;
                    }
                }
                udp_msg = async {
                    match udp_rx_opt.as_mut() {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                }, if self.running => {
                    self.handle_inbound_udp(udp_msg, &mut sessions_opt, &mut udp_rx_opt, &mut proxy_guard, &mut stream_map, &tx, &proxy_tx).await;
                }
                cmd = bridge_rx.recv() => {
                    if !self.handle_bridge_cmd(cmd, &mut sessions_opt, &mut udp_rx_opt, &mut proxy_guard, &mut stream_map, &tx, &proxy_tx).await {
                        break;
                    }
                }
                _ = metrics_tick.tick() => {
                    if self.running {
                        self.emit_metrics(&tx).await;
                    }
                }
                _ = keepalive_tick.tick() => {
                    if self.running {
                        self.handle_keepalive(&mut sessions_opt, &mut udp_rx_opt, &mut proxy_guard, &mut stream_map, &tx, &proxy_tx, &mut proxy_rx).await;
                    }
                }
                _ = retransmit_tick.tick() => {
                    if self.running {
                        self.handle_retransmit(&mut sessions_opt, &mut udp_rx_opt, &mut proxy_guard, &mut stream_map, &tx, &proxy_tx).await;
                    }
                }
                proxy_ev = proxy_rx.recv(), if self.running && sessions_opt.as_ref().map(|s| {
                    s.iter().any(|ses| ses.machine.in_flight_count() < ses.machine.cwnd_packets().clamp(16, 16384))
                }).unwrap_or(true) => {
                    self.handle_proxy_event(proxy_ev, &mut sessions_opt, &mut stream_map, &tx, &proxy_tx).await;
                }
            }
        }

        tx.send(UiEvent::Log("Bridge stopped".to_string())).await.ok();
        Ok(())
    }

    async fn handle_inbound_udp(
        &mut self,
        udp_msg: Option<(usize, Bytes)>,
        sessions_opt: &mut Option<Vec<SessionState>>,
        udp_rx_opt: &mut Option<mpsc::Receiver<(usize, Bytes)>>,
        proxy_guard: &mut Option<crate::sysproxy::SystemProxyGuard>,
        stream_map: &mut std::collections::HashMap<u16, usize>,
        tx: &mpsc::Sender<UiEvent>,
        proxy_tx: &mpsc::UnboundedSender<(u16, ProxyToClientMsg)>,
    ) {
        match udp_msg {
            Some((session_index, inbound)) => {
                self.metrics.bytes_recv.fetch_add(inbound.len() as u64, Ordering::Relaxed);
                self.last_valid_recv = Instant::now();
                if let Some(sessions) = sessions_opt.as_mut() {
                    if session_index < sessions.len() {
                        let session = &mut sessions[session_index];
                        let initial_action = match session.machine.on_event(OstpEvent::Inbound(inbound)) {
                            Ok(a) => a,
                            Err(e) => {
                                let _ = tx.send(UiEvent::Log(format!("Protocol decrypt error: {e}"))).await;
                                tracing::warn!("Inbound protocol error (session {}): {}", session_index, e);
                                return;
                            }
                        };

                        let mut actions_queue = std::collections::VecDeque::new();
                        actions_queue.push_back(initial_action);

                        while let Some(current_action) = actions_queue.pop_front() {
                            match current_action {
                                ProtocolAction::Multiple(nested) => {
                                    for a in nested {
                                        actions_queue.push_back(a);
                                    }
                                }
                                ProtocolAction::DeliverApp(stream_id, dec_payload) => {
                                    match RelayMessage::decode(&dec_payload) {
                                        Ok(relay_msg) => {
                                            match relay_msg {
                                                RelayMessage::ConnectOk => {
                                                    let _ = tx.send(UiEvent::Log(format!("Relay CONNECT OK stream_id={stream_id}"))).await;
                                                    let _ = proxy_tx.send((stream_id, ProxyToClientMsg::ConnectOk));
                                                }
                                                RelayMessage::Data(data) => {
                                                    let _ = proxy_tx.send((stream_id, ProxyToClientMsg::Data(Bytes::from(data))));
                                                }
                                                RelayMessage::Close => {
                                                    let _ = proxy_tx.send((stream_id, ProxyToClientMsg::Close));
                                                }
                                                RelayMessage::Error(msg) => {
                                                    let _ = tx.send(UiEvent::Log(format!("Relay error for stream {stream_id}: {msg}"))).await;
                                                    let _ = proxy_tx.send((stream_id, ProxyToClientMsg::Error(msg)));
                                                }
                                                RelayMessage::Pong(ts) => {
                                                    let now = SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
                                                    self.last_rtt_ms = now.saturating_sub(ts) as f64;
                                                    self.metrics.rtt_ms.store(self.last_rtt_ms as u32, Ordering::Relaxed);
                                                }
                                                RelayMessage::UdpAssociate => {}
                                                RelayMessage::UdpData(target, data) => {
                                                    let _ = proxy_tx.send((stream_id, ProxyToClientMsg::UdpData(target, Bytes::from(data))));
                                                }
                                                RelayMessage::KeepAlive | RelayMessage::Ping(_) | RelayMessage::Connect(_) => {}
                                            }
                                        }
                                        Err(err) => {
                                            let _ = tx.send(UiEvent::Log(format!("Relay decode error for stream {stream_id}: {err}"))).await;
                                            let _ = proxy_tx.send((stream_id, ProxyToClientMsg::Error("relay decode failed".to_string())));
                                        }
                                    }
                                }
                                ProtocolAction::SendDatagram(frame) => {
                                    let _ = send_datagram(&session.socket, &frame, self.transport_mode == "udp" ).await;
                                    self.metrics.bytes_sent.fetch_add(frame.len() as u64, Ordering::Relaxed);
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
            None => {
                let _ = tx.send(UiEvent::Log("UDP channel closed, resetting connection".to_string())).await;
                self.running = false;
                crate::sysproxy::disable_system_proxy();
                *sessions_opt = None;
                *udp_rx_opt = None;
                stream_map.clear();
                self.reset_proxy_streams(&tx, &proxy_tx, "udp reader closed");
                let _ = tx.send(UiEvent::TunnelStopped).await;
            }
        }
    }

    async fn handle_bridge_cmd(
        &mut self,
        cmd: Option<BridgeCommand>,
        sessions_opt: &mut Option<Vec<SessionState>>,
        udp_rx_opt: &mut Option<mpsc::Receiver<(usize, Bytes)>>,
        proxy_guard: &mut Option<crate::sysproxy::SystemProxyGuard>,
        stream_map: &mut std::collections::HashMap<u16, usize>,
        tx: &mpsc::Sender<UiEvent>,
        proxy_tx: &mpsc::UnboundedSender<(u16, ProxyToClientMsg)>,
    ) -> bool {
        match cmd {
            Some(BridgeCommand::ToggleTunnel) => {
                if self.running {
                    self.running = false;
                    self.metrics.connection_state.store(0, Ordering::Relaxed);
                    *proxy_guard = None;
                    *sessions_opt = None;
                    *udp_rx_opt = None;
                    stream_map.clear();
                    self.reset_proxy_streams(&tx, &proxy_tx, "manual stop");
                    tx.send(UiEvent::TunnelStopped).await.ok();
                    let stop_msg = if self.mode == "tun" { "TUN tunnel stopped" } else { "Bridge stopped" };
                    tx.send(UiEvent::Log(stop_msg.to_string())).await.ok();
                } else {
                    tx.send(UiEvent::Log("Connecting to remote server...".to_string())).await.ok();
                    tx.send(UiEvent::Metrics { status: ConnectionStatus::Handshaking, rtt_ms: 0.0, throughput_bps: 0 }).await.ok();
                    self.metrics.connection_state.store(1, Ordering::Relaxed);
                    
                    let session_count = if self.mux_enabled { self.mux_sessions.max(1) } else { 1 };
                    let (udp_tx, udp_rx) = mpsc::channel(100000);
                    let mut sessions = Vec::with_capacity(session_count);
                    let mut rtt_sum = 0.0;
                    let mut successful_sessions = 0;

                    for idx in 0..session_count {
                        let session_id: u32 = rand::thread_rng().gen();
                        match self.perform_handshake_with_id(&tx, session_id).await {
                            Ok((sock, mach, rtt)) => {
                                let session_index = sessions.len();
                                let socket_clone = sock.clone();
                                let udp_tx_clone = udp_tx.clone();

                                tokio::spawn(async move {
                                    let mut buf = vec![0_u8; 65535];
                                    loop {
                                        match socket_clone.recv(&mut buf).await {
                                            Ok(n) => {
                                                let inbound = Bytes::copy_from_slice(&buf[..n]);
                                                if udp_tx_clone.send((session_index, inbound)).await.is_err() {
                                                    break;
                                                }
                                            }
                                            Err(e) => {
                                                tracing::warn!("UDP socket recv error (session {}): {}", session_index, e);
                                                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                                            }
                                        }
                                    }
                                });

                                sessions.push(SessionState { socket: sock, machine: mach });
                                rtt_sum += rtt;
                                successful_sessions += 1;
                            }
                            Err(err) => {
                                tx.send(UiEvent::Log(format!("Multiplex session {}/{} handshake failed: {}. Continuing with remaining sessions...", idx + 1, session_count, err))).await.ok();
                            }
                        }
                    }

                    if sessions.is_empty() {
                        *proxy_guard = None;
                        tx.send(UiEvent::Log("All multiplexed handshake attempts failed. Connection aborted.".to_string())).await.ok();
                        tx.send(UiEvent::TunnelStopped).await.ok();
                        self.metrics.connection_state.store(0, Ordering::Relaxed);
                        return True;
                    }

                    *udp_rx_opt = Some(udp_rx);
                    *sessions_opt = Some(sessions);
                    self.last_rtt_ms = rtt_sum / successful_sessions as f64;
                    self.running = true;
                    self.last_sample_at = Instant::now();
                    self.last_valid_recv = Instant::now();
                    
                    let sys_proxy_addr = self.proxy_addr.replace("0.0.0.0:", "127.0.0.1:");
                    *proxy_guard = Some(crate::sysproxy::SystemProxyGuard::enable(&sys_proxy_addr));

                    tx.send(UiEvent::Metrics {
                        status: ConnectionStatus::Established,
                        rtt_ms: self.last_rtt_ms,
                        throughput_bps: 0,
                    }).await.ok();
                    self.metrics.connection_state.store(2, Ordering::Relaxed);
                    let start_msg = if self.mode == "tun" { "TUN tunnel established" } else { "Connection established" };
                    tx.send(UiEvent::Log(start_msg.to_string())).await.ok();

                    for session in sessions_opt.as_mut().unwrap().iter_mut() {
                        let ts = SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
                        let ping_payload = Bytes::from(RelayMessage::Ping(ts).encode());
                        if let Ok(ProtocolAction::SendDatagram(frame)) = session.machine.on_event(OstpEvent::Outbound(0, ping_payload)) {
                            let _ = send_datagram(&session.socket, &frame, self.transport_mode == "udp").await;
                            self.metrics.bytes_sent.fetch_add(frame.len() as u64, Ordering::Relaxed);
                        }
                    }
                }
            }
            Some(BridgeCommand::NextProfile) => {
                self.profile = next_profile(self.profile);
                tx.send(UiEvent::ProfileChanged(self.profile)).await.ok();
                tx.send(UiEvent::Log(format!("Obfuscation profile switched to {:?}", self.profile))).await.ok();
            }
            Some(BridgeCommand::NetworkChanged) => {
                if self.running {
                    let _ = tx.send(UiEvent::Log("Network changed — starting immediate reconnect".to_string())).await;
                    self.metrics.connection_state.store(1, Ordering::Relaxed);
                    self.last_valid_recv = Instant::now() - Duration::from_secs(100);

                    let session_count = if self.mux_enabled { self.mux_sessions.max(1) } else { 1 };
                    let (udp_tx, udp_rx) = mpsc::channel(100000);
                    let mut new_sessions = Vec::with_capacity(session_count);
                    let mut successful_sessions = 0;
                    let mut rtt_sum = 0.0;

                    for idx in 0..session_count {
                        let session_id: u32 = rand::thread_rng().gen();
                        match self.perform_handshake_with_id(&tx, session_id).await {
                            Ok((sock, mach, rtt)) => {
                                let session_index = new_sessions.len();
                                let socket_clone = sock.clone();
                                let udp_tx_clone = udp_tx.clone();

                                tokio::spawn(async move {
                                    let mut buf = vec![0_u8; 65535];
                                    loop {
                                        match socket_clone.recv(&mut buf).await {
                                            Ok(n) => {
                                                let inbound = Bytes::copy_from_slice(&buf[..n]);
                                                if udp_tx_clone.send((session_index, inbound)).await.is_err() { break; }
                                            }
                                            Err(e) => {
                                                tracing::warn!("UDP recv error (network-change session {}): {}", session_index, e);
                                                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                                            }
                                        }
                                    }
                                });
                                new_sessions.push(SessionState { socket: sock, machine: mach });
                                rtt_sum += rtt;
                                successful_sessions += 1;
                            }
                            Err(err) => {
                                let _ = tx.send(UiEvent::Log(format!("NetworkChanged reconnect session {}/{} failed: {}", idx + 1, session_count, err))).await;
                            }
                        }
                    }

                    if !new_sessions.is_empty() {
                        *sessions_opt = Some(new_sessions);
                        *udp_rx_opt = Some(udp_rx);
                        self.last_rtt_ms = rtt_sum / successful_sessions as f64;
                        self.last_valid_recv = Instant::now();
                        stream_map.clear();
                        self.reset_proxy_streams(&tx, &proxy_tx, "network changed");
                        self.metrics.connection_state.store(2, Ordering::Relaxed);
                        let _ = tx.send(UiEvent::Log("NetworkChanged reconnect successful!".to_string())).await;
                    } else {
                        let _ = tx.send(UiEvent::Log("NetworkChanged reconnect failed — will retry on keepalive tick".to_string())).await;
                    }
                }
            }
            Some(BridgeCommand::ReloadConfig) => {
                match ClientConfig::reload_from_json_near_binary() {
                    Ok(cfg) => {
                        self.apply_runtime_config(&cfg);
                        tx.send(UiEvent::Log("Runtime config reloaded".to_string())).await.ok();
                        if self.running {
                            self.running = false;
                            self.metrics.connection_state.store(0, Ordering::Relaxed);
                            *proxy_guard = None;
                            *sessions_opt = None;
                            stream_map.clear();
                            self.reset_proxy_streams(&tx, &proxy_tx, "config reload");
                            let _ = tx.send(UiEvent::TunnelStopped).await;
                        }
                    }
                    Err(err) => {
                        let _ = tx.send(UiEvent::Log(format!("Config reload failed: {err}"))).await;
                    }
                }
            }
            Some(BridgeCommand::Shutdown) | None => {
                self.running = false;
                *proxy_guard = None;
                return False;
            }
        }
        True
    }

    async fn handle_keepalive(
        &mut self,
        sessions_opt: &mut Option<Vec<SessionState>>,
        udp_rx_opt: &mut Option<mpsc::Receiver<(usize, Bytes)>>,
        proxy_guard: &mut Option<crate::sysproxy::SystemProxyGuard>,
        stream_map: &mut std::collections::HashMap<u16, usize>,
        tx: &mpsc::Sender<UiEvent>,
        proxy_tx: &mpsc::UnboundedSender<(u16, ProxyToClientMsg)>,
        proxy_rx: &mut mpsc::Receiver<ProxyEvent>,
    ) {
        if self.last_valid_recv.elapsed().as_secs() > 25 {
            let elapsed = self.last_valid_recv.elapsed().as_secs();
            if elapsed > 180 {
                let _ = tx.send(UiEvent::Log("Connection permanently lost (3-minute hard timeout). Stopping tunnel.".into())).await;
                self.running = false;
                *proxy_guard = None;
                *sessions_opt = None;
                stream_map.clear();
                self.reset_proxy_streams(&tx, &proxy_tx, "keepalive hard timeout");
                let _ = tx.send(UiEvent::TunnelStopped).await;
                self.metrics.connection_state.store(0, Ordering::Relaxed);
                return;
            }

            let _ = tx.send(UiEvent::Log(format!("Connection stall detected ({}s silence). Attempting background reconnect...", elapsed))).await;
            self.metrics.connection_state.store(1, Ordering::Relaxed);

            let session_count = if self.mux_enabled { self.mux_sessions.max(1) } else { 1 };
            let (udp_tx, udp_rx) = mpsc::channel(100000);
            let mut new_sessions = Vec::with_capacity(session_count);
            let mut successful_sessions = 0;
            let mut rtt_sum = 0.0;

            for idx in 0..session_count {
                let session_id: u32 = rand::thread_rng().gen();
                match self.perform_handshake_with_id(&tx, session_id).await {
                    Ok((sock, mach, rtt)) => {
                        let session_index = new_sessions.len();
                        let socket_clone = sock.clone();
                        let udp_tx_clone = udp_tx.clone();

                        tokio::spawn(async move {
                            let mut buf = vec![0_u8; 65535];
                            loop {
                                match socket_clone.recv(&mut buf).await {
                                    Ok(n) => {
                                        let inbound = Bytes::copy_from_slice(&buf[..n]);
                                        if udp_tx_clone.send((session_index, inbound)).await.is_err() {
                                            break;
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!("UDP socket recv error (reconnect session {}): {}", session_index, e);
                                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                                    }
                                }
                            }
                        });

                        new_sessions.push(SessionState { socket: sock, machine: mach });
                        rtt_sum += rtt;
                        successful_sessions += 1;
                    }
                    Err(err) => {
                        let _ = tx.send(UiEvent::Log(format!("Background reconnect session {}/{} failed: {}", idx + 1, session_count, err))).await;
                    }
                }
            }

            if !new_sessions.is_empty() {
                *sessions_opt = Some(new_sessions);
                *udp_rx_opt = Some(udp_rx);
                self.last_rtt_ms = rtt_sum / successful_sessions as f64;
                self.last_valid_recv = Instant::now();
                self.metrics.connection_state.store(2, Ordering::Relaxed);
                let _ = tx.send(UiEvent::Log("Background reconnect successful! Connection restored.".into())).await;

                for session in sessions_opt.as_mut().unwrap().iter_mut() {
                    let ts = SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
                    let ping_payload = Bytes::from(RelayMessage::Ping(ts).encode());
                    if let Ok(ProtocolAction::SendDatagram(frame)) = session.machine.on_event(OstpEvent::Outbound(0, ping_payload)) {
                        let _ = send_datagram(&session.socket, &frame, self.transport_mode == "udp").await;
                        self.metrics.bytes_sent.fetch_add(frame.len() as u64, Ordering::Relaxed);
                    }
                }
                
                stream_map.clear();
                self.reset_proxy_streams(&tx, &proxy_tx, "background reconnect");

                let mut flushed = 0;
                while let Ok(stale) = proxy_rx.try_recv() {
                    if let ProxyEvent::NewStream { stream_id, .. } = stale {
                        let _ = proxy_tx.send((stream_id, ProxyToClientMsg::Error("connection reset".into())));
                    }
                    flushed += 1;
                }
                if flushed > 0 {
                    let _ = tx.send(UiEvent::Log(format!("Flushed {} stale proxy messages to prevent UDP burst", flushed))).await;
                }
            } else {
                let _ = tx.send(UiEvent::Log("Background reconnect failed. Will retry on next tick...".into())).await;
            }
        }

        if let Some(sessions) = sessions_opt.as_mut() {
            for session in sessions.iter_mut() {
                let ts = SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
                let ping_payload = Bytes::from(RelayMessage::Ping(ts).encode());
                if let Ok(ProtocolAction::SendDatagram(frame)) = session.machine.on_event(OstpEvent::Outbound(0, ping_payload)) {
                    let _ = send_datagram(&session.socket, &frame, self.transport_mode == "udp" ).await;
                    self.metrics.bytes_sent.fetch_add(frame.len() as u64, Ordering::Relaxed);
                }

                let ka_payload = Bytes::from(RelayMessage::KeepAlive.encode());
                if let Ok(ProtocolAction::SendDatagram(frame)) = session.machine.on_event(OstpEvent::Outbound(0, ka_payload)) {
                    let _ = send_datagram(&session.socket, &frame, self.transport_mode == "udp" ).await;
                    self.metrics.bytes_sent.fetch_add(frame.len() as u64, Ordering::Relaxed);
                }
            }
        }
    }

    async fn handle_retransmit(
        &mut self,
        sessions_opt: &mut Option<Vec<SessionState>>,
        udp_rx_opt: &mut Option<mpsc::Receiver<(usize, Bytes)>>,
        proxy_guard: &mut Option<crate::sysproxy::SystemProxyGuard>,
        stream_map: &mut std::collections::HashMap<u16, usize>,
        tx: &mpsc::Sender<UiEvent>,
        proxy_tx: &mpsc::UnboundedSender<(u16, ProxyToClientMsg)>,
    ) {
        let mut fatal_err = None;
        if let Some(sessions) = sessions_opt.as_mut() {
            for session in sessions.iter_mut() {
                match session.machine.on_event(OstpEvent::Tick) {
                    Ok(action) => {
                        let mut queue = vec![action];
                        while let Some(current_action) = queue.pop() {
                            match current_action {
                                ProtocolAction::Multiple(nested) => {
                                    for a in nested {
                                        queue.push(a);
                                    }
                                }
                                ProtocolAction::SendDatagram(frame) => {
                                    let _ = send_datagram(&session.socket, &frame, self.transport_mode == "udp" ).await;
                                    self.metrics.bytes_sent.fetch_add(frame.len() as u64, Ordering::Relaxed);
                                }
                                _ => {}
                            }
                        }
                    }
                    Err(e) => {
                        fatal_err = Some(e);
                        break;
                    }
                }
            }
        }

        if let Some(e) = fatal_err {
            let _ = tx.send(UiEvent::Log(format!("Protocol tick fatal error: {e}"))).await;
            self.running = false;
            *proxy_guard = None;
            *sessions_opt = None;
            *udp_rx_opt = None;
            stream_map.clear();
            self.reset_proxy_streams(&tx, &proxy_tx, "protocol fatal error");
            let _ = tx.send(UiEvent::TunnelStopped).await;
            self.metrics.connection_state.store(0, Ordering::Relaxed);
        }
    }

    async fn handle_proxy_event(
        &mut self,
        proxy_ev: Option<ProxyEvent>,
        sessions_opt: &mut Option<Vec<SessionState>>,
        stream_map: &mut std::collections::HashMap<u16, usize>,
        tx: &mpsc::Sender<UiEvent>,
        proxy_tx: &mpsc::UnboundedSender<(u16, ProxyToClientMsg)>,
    ) {
        if let Some(ev) = proxy_ev {
            if let Some(sessions) = sessions_opt.as_mut() {
                if sessions.is_empty() {
                    if let ProxyEvent::NewStream { stream_id, .. } = ev {
                        let _ = proxy_tx.send((stream_id, ProxyToClientMsg::Error("tunnel stopped".into())));
                    }
                    return;
                }
                let (stream_id, relay_msg, is_close) = match ev {
                    ProxyEvent::NewStream { stream_id, target } => {
                        let _ = tx.send(UiEvent::Log(format!("Proxy CONNECT stream_id={stream_id} target={target}"))).await;
                        (stream_id, RelayMessage::Connect(target), false)
                    }
                    ProxyEvent::UdpAssociate { stream_id } => {
                        let _ = tx.send(UiEvent::Log(format!("Proxy UDP ASSOCIATE stream_id={stream_id}"))).await;
                        (stream_id, RelayMessage::UdpAssociate, false)
                    }
                    ProxyEvent::UdpData { stream_id, target, payload } => {
                        (stream_id, RelayMessage::UdpData(target, payload.to_vec()), false)
                    }
                    ProxyEvent::Data { stream_id, payload } => (stream_id, RelayMessage::Data(payload.to_vec()), false),
                    ProxyEvent::Close { stream_id } => {
                        let _ = tx.send(UiEvent::Log(format!("Proxy CLOSE stream_id={stream_id}"))).await;
                        (stream_id, RelayMessage::Close, true)
                    }
                };
                let len = sessions.len();
                let session_index = *stream_map.entry(stream_id).or_insert_with(|| {
                    rand::thread_rng().gen_range(0..len)
                });
                if is_close {
                    stream_map.remove(&stream_id);
                }
                let session = &mut sessions[session_index];
                let out_payload = Bytes::from(relay_msg.encode());
                match session.machine.on_event(OstpEvent::Outbound(stream_id, out_payload)) {
                    Ok(ProtocolAction::SendDatagram(frame)) => {
                        if send_datagram(&session.socket, &frame, self.transport_mode == "udp" ).await.is_ok() {
                            self.metrics.bytes_sent.fetch_add(frame.len() as u64, Ordering::Relaxed);
                            tracing::trace!("Outbound datagram sent stream_id={stream_id} bytes={}", frame.len());
                        }
                    }
                    Ok(ProtocolAction::Multiple(list)) => {
                        let mut sent = 0usize;
                        for item in list {
                            if let ProtocolAction::SendDatagram(frame) = item {
                                if send_datagram(&session.socket, &frame, self.transport_mode == "udp" ).await.is_ok() {
                                    self.metrics.bytes_sent.fetch_add(frame.len() as u64, Ordering::Relaxed);
                                    sent += 1;
                                }
                            }
                        }
                        tracing::trace!("Outbound datagram batch stream_id={stream_id} sent={sent}");
                    }
                    Ok(ProtocolAction::Noop) => {
                        tracing::trace!("Outbound datagram noop stream_id={stream_id}");
                    }
                    Ok(_) => {
                        tracing::trace!("Outbound datagram unexpected action stream_id={stream_id}");
                    }
                    Err(e) => {
                        tracing::warn!("Protocol error packing outbound stream_id={}: {}", stream_id, e);
                        let _ = tx.send(UiEvent::Log(format!("Protocol error packing TCP: {e}"))).await;
                    }
                }
            } else {
                if let ProxyEvent::NewStream { stream_id, .. } = ev {
                    let _ = proxy_tx.send((stream_id, ProxyToClientMsg::Error("tunnel stopped".into())));
                }
            }
        }
    }
"""

with open("d:/ospab-projects/ostp/ostp-client/src/bridge.rs", "w", encoding="utf-8") as f:
    f.write(prefix + new_run_and_helpers + suffix)

print("Done")
