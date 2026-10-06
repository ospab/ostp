use anyhow::Result;
use bytes::Bytes;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

use dispatcher::{DispatchOutcome, Dispatcher};
use ostp_core::relay::RelayMessage;
use signal::wait_for_shutdown_signal;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration, Instant};

/// Shared per-session download-direction congestion headroom (packets),
/// published by `handle_tick` from `Dispatcher::snapshot_backpressure` and
/// read lock-free by relay reader tasks. See that method's doc comment for
/// why this exists.
pub(crate) type SessionBackpressure = Arc<RwLock<HashMap<u32, Arc<send_gate::SendGate>>>>;

mod dispatcher;
pub mod outbound;
pub mod api;
pub mod fallback;
pub mod transport;
pub mod tls;
pub mod relay_node;
mod relay;
mod signal;
pub mod dns;
pub mod router;
pub mod overnet;
pub mod password;
pub mod target_policy;
mod admission;
mod send_gate;
mod subscription;

pub use subscription::SubscriptionSettings;

pub use outbound::{OutboundAction, OutboundConfig, OutboundRule};
pub use api::ApiConfig;
pub use dispatcher::UserStatsSnapshot;
pub use fallback::FallbackConfig;
pub use relay_node::RelayConfig;
pub use overnet::OvernetConfig;

// ── Internal event types ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
#[allow(dead_code)]
enum UiCommand {
    Shutdown,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) enum UiEvent {
    #[allow(dead_code)]
    PeerSeen { peer: IpAddr },
    #[allow(dead_code)] Rx { peer: IpAddr, bytes: usize },
    #[allow(dead_code)] Tx { peer: IpAddr, bytes: usize },
    UnauthorizedProbe { peer: IpAddr, bytes: usize },
    KeyCreated { key: String },
    Log(String),
    #[allow(dead_code)]
    KeyCount(usize),
}

/// Bytes a stream may have waiting for its target to accept them. Without a
/// limit a client sending faster than the target reads (an upload to a slow
/// site, or on purpose) grew the server's memory without bound. Past it the
/// stream is reset; per-stream flow control is for protocol v6.
pub(crate) const MAX_QUEUED_UPLOAD: usize = 32 * 1024 * 1024;

pub(crate) struct RemoteState {
    pub data_tx: mpsc::UnboundedSender<Bytes>,
    /// Bytes in `data_tx` not yet written to the target.
    pub queued: Arc<std::sync::atomic::AtomicUsize>,
    pub udp_tx: Option<mpsc::UnboundedSender<(String, Bytes)>>,
    pub cancel_tx: mpsc::Sender<()>,
    #[allow(dead_code)]
    pub is_dns: bool,
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Everything `run_server` needs, resolved from the on-disk config by the CLI.
pub struct ServerParams {
    pub bind_addrs: Vec<String>,
    pub server_public_ip: Option<String>,
    pub bind_ip: Option<String>,
    pub access_keys: Vec<(String, crate::api::UserMeta)>,
    pub outbound: Option<OutboundConfig>,
    pub api_config: Option<ApiConfig>,
    pub fallback_config: Option<FallbackConfig>,
    pub debug: bool,
    pub dns_config: Option<dns::DnsConfig>,
    pub config_path: Option<std::path::PathBuf>,
    /// Enabled `tls` section, resolved.
    pub tls: Option<tls::TlsSettings>,
    /// Enabled `subscription` section, resolved (needs `tls`).
    pub subscription: Option<SubscriptionSettings>,
    /// The `overnet` section: `.ov` for clients and the overnet exit.
    pub overnet: Option<OvernetConfig>,
    /// Clients may reach this machine's services and private networks.
    pub local_access: bool,
}

pub async fn run_server(params: ServerParams) -> Result<()> {
    let ServerParams {
        bind_addrs,
        server_public_ip,
        bind_ip,
        access_keys,
        outbound,
        api_config,
        fallback_config,
        debug,
        dns_config,
        config_path,
        tls,
        subscription,
        overnet,
        local_access,
    } = params;
    let mut keys_map = HashMap::new();
    for (key, meta) in access_keys {
        keys_map.insert(key, meta);
    }
    let shared_keys = std::sync::Arc::new(std::sync::RwLock::new(keys_map));

    let mut sockets = Vec::new();
    for bind_addr in &bind_addrs {
        let addr = bind_addr.parse::<std::net::SocketAddr>()
            .map_err(|e| anyhow::anyhow!("invalid bind addr '{}': {}", bind_addr, e))?;
        let domain = if addr.is_ipv6() { socket2::Domain::IPV6 } else { socket2::Domain::IPV4 };
        let sock = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
        let _ = sock.set_recv_buffer_size(33554432);
        let _ = sock.set_send_buffer_size(33554432);
        sock.bind(&addr.into())?;
        sock.set_nonblocking(true)?;
        let udp_sock = UdpSocket::from_std(sock.into())?;
        tracing::info!("UDP socket bound to {}", bind_addr);
        sockets.push(std::sync::Arc::new(udp_sock));
    }
    if sockets.is_empty() { anyhow::bail!("no bind addresses specified"); }

    use ostp_core::{NoiseRole, PaddingStrategy, ProtocolConfig};
    let protocol_config = ProtocolConfig {
        role: NoiseRole::Responder,
        psk: [0u8; 32],
        session_id: 0,
        handshake_payload: vec![],
        max_padding: 256,
        padding_strategy: PaddingStrategy::Adaptive,
        obfuscation_key: [0u8; 8],
        max_reorder: 16384,
        max_reorder_buffer: 8192,
        ack_delay_ms: 5,
        rto_ms: 100,
        max_retries: 8,
        max_sent_history: 32768,
        // Defaults -- overridden per-session by dispatcher using derive_all_secrets()
        handshake_pad_min: 32,
        handshake_pad_max: 128,
        mtu: 1350,
    };

    let dispatcher = Dispatcher::new(protocol_config, shared_keys.clone());

    // Traffic per user carries over restarts and updates: without this every
    // restart zeroed the counters, and with them the traffic limits.
    let stats_file = config_path.as_ref().and_then(|p| p.parent()).map(|d| d.join(STATS_FILE));
    let process_started = std::time::SystemTime::now();
    if let Some(path) = &stats_file {
        let restored = restore_user_traffic(path, &dispatcher.user_stats_ref(), &shared_keys);
        if restored > 0 {
            tracing::info!("traffic of {restored} user(s) restored from {}", path.display());
        }
    }
    let traffic = dispatcher.user_stats_ref();

    // Background config hot-reloader for access keys
    let shared_keys_clone = shared_keys.clone();
    let user_stats_clone = dispatcher.user_stats_ref();
    let config_path_clone = config_path.clone();
    tokio::spawn(async move {
        let path_to_watch = if let Some(p) = config_path_clone {
            p
        } else {
            let exe = match std::env::current_exe() {
                Ok(e) => e,
                Err(_) => return,
            };
            let dir = match exe.parent() {
                Some(d) => d,
                None => return,
            };
            dir.join("config.json")
        };
        
        let path_to_watch = match std::fs::canonicalize(&path_to_watch) {
            Ok(p) => p,
            Err(_) => path_to_watch,
        };

        tracing::info!("Watching configuration file for hot-reload: {:?}", path_to_watch);

        let mut last_mtime = None;
        let mut _updated_outbound: Option<OutboundConfig> = None;
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            if let Ok(metadata) = std::fs::metadata(&path_to_watch) {
                if let Ok(mtime) = metadata.modified() {
                    if last_mtime != Some(mtime) {
                        last_mtime = Some(mtime);
                        match std::fs::read_to_string(&path_to_watch) {
                            Ok(content) => {
                                #[derive(serde::Deserialize)]
                                #[serde(untagged)]
                                enum ReloadUser {
                                    Detailed { access_key: String, name: Option<String>, limit_bytes: Option<u64> },
                                    KeyOnly(String),
                                }
                                #[derive(serde::Deserialize)]
                                struct ServerReloadConfig {
                                    mode: String,
                                    #[serde(default)]
                                    access_keys: Vec<ReloadUser>,
                                }
                                
                                let mut stripped = json_comments::StripComments::new(content.as_bytes());
                                let mut content_str = String::new();
                                use std::io::Read;
                                if let Err(e) = stripped.read_to_string(&mut content_str) {
                                    tracing::error!("Failed to strip comments from config during hot-reload: {}", e);
                                    continue;
                                }

                                match serde_json::from_str::<ServerReloadConfig>(&content_str) {
                                    Ok(cfg) => {
                                        if cfg.mode == "server" {
                                            let mut new_keys = HashMap::new();
                                            for uc in cfg.access_keys {
                                                let (k, m) = match uc {
                                                    ReloadUser::Detailed { access_key, name, limit_bytes } => (access_key, crate::api::UserMeta { name, limit_bytes }),
                                                    ReloadUser::KeyOnly(k) => (k, crate::api::UserMeta { name: None, limit_bytes: None }),
                                                };
                                                new_keys.insert(k, m);
                                            }
                                            
                                            // 1. Update shared_keys
                                            let mut keys_lock = shared_keys_clone.write().unwrap_or_else(|e| e.into_inner());
                                            *keys_lock = new_keys.clone();
                                            
                                            // 2. Synchronize user_stats limits & cleanup deleted keys
                                            let mut stats_lock = user_stats_clone.write().unwrap_or_else(|e| e.into_inner());
                                            stats_lock.retain(|k, _| new_keys.contains_key(k));
                                            
                                            for (k, meta) in &new_keys {
                                                let entry_info = stats_lock.get(k).map(|e| {
                                                    (
                                                        e.limit_bytes,
                                                        e.bytes_up.load(std::sync::atomic::Ordering::Relaxed),
                                                        e.bytes_down.load(std::sync::atomic::Ordering::Relaxed),
                                                        e.connections.load(std::sync::atomic::Ordering::Relaxed),
                                                        e.created_at,
                                                    )
                                                });
                                                if let Some((limit_bytes, bytes_up, bytes_down, connections, created_at)) = entry_info {
                                                    if limit_bytes != meta.limit_bytes {
                                                        stats_lock.insert(k.clone(), std::sync::Arc::new(dispatcher::UserStats {
                                                            bytes_up: portable_atomic::AtomicU64::new(bytes_up),
                                                            bytes_down: portable_atomic::AtomicU64::new(bytes_down),
                                                            connections: portable_atomic::AtomicU64::new(connections),
                                                            limit_bytes: meta.limit_bytes,
                                                            created_at,
                                                        }));
                                                    }
                                                } else {
                                                    stats_lock.insert(k.clone(), std::sync::Arc::new(dispatcher::UserStats::new(meta.limit_bytes)));
                                                }
                                            }
                                            
                                            tracing::info!("Hot-reloaded {} access keys from {:?}", keys_lock.len(), path_to_watch);
                                        }
                                    }
                                    Err(e) => {
                                        tracing::error!("Failed to parse config file during hot-reload: {}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::error!("Failed to read config file during hot-reload: {}", e);
                            }
                        }
                    }
                }
            }
        }
    });

    // Инициализируем DNS-сервер
    let dns_cfg = dns_config.unwrap_or_default();
    // Lists are cached next to the config (…/dns/lists).
    let dns_data = config_path.as_ref().and_then(|p| p.parent().map(|d| d.to_path_buf()));
    let dns_server = dns::DnsServer::new(dns_cfg, dns_data);
    dns_server.set_proxy(dns::proxy_url(outbound.as_ref()));
    dns_server.start();
    // Initialize Router
    let router = std::sync::Arc::new(router::Router::new(
        outbound.clone(),
        bind_ip,
        dns_server.clone(),
        debug,
    ));
    {
        let panel_port = api_config
            .as_ref()
            .filter(|a| a.enabled)
            .and_then(|a| a.bind.rsplit_once(':'))
            .and_then(|(_, p)| p.parse::<u16>().ok());
        router.set_local_policy(local_access, panel_port);
        if local_access {
            tracing::warn!("local_access: clients may reach this server's own services and private networks");
        }
    }
    if let Some(cfg) = overnet.filter(|o| o.enabled) {
        if let Err(e) = overnet::apply(cfg, &router).await {
            tracing::error!("overnet: {e:#}");
        }
    }
    match dns::spawn_tcp_listener(dns_server.clone(), router.overnet.clone()).await {
        Ok(addr) => {
            let _ = router.dns_tcp.set(addr);
        }
        Err(e) => tracing::warn!("DNS over TCP for clients is off: {e}"),
    }

    // The panel is also served on the built-in HTTPS frontend at /{webpath},
    // but only at a secret path: at the default /panel/ anyone probing the
    // site would find an OSTP sign-in page. Without one it stays on its bind
    // address and the tunnel (10.1.0.1).
    let panel_route = api_config.as_ref().filter(|a| a.enabled).and_then(|a| {
        let webpath = a.webpath.trim_matches('/');
        if webpath.is_empty() {
            tracing::warn!("panel: no secret webpath, so it is not served on the HTTPS site (ostp panel set --webpath ...)");
            return None;
        }
        Some(transport::sniff::PanelRoute { prefix: format!("/{webpath}"), upstream: loopback_for(&a.bind) })
    });

    // Where clients reach this server, for subscription links.
    let primary = bind_addrs.first().cloned().unwrap_or_else(|| "0.0.0.0:50000".to_string());
    let parts: Vec<&str> = primary.rsplitn(2, ':').collect();
    let server_port: u16 = parts.first().and_then(|p| p.parse().ok()).unwrap_or(50000);
    let server_host = server_public_ip.unwrap_or_else(|| parts.get(1).unwrap_or(&"0.0.0.0").trim_matches(['[', ']']).to_string());
    let tls_link = tls.as_ref().and_then(|t| {
        Some(api::TlsLink {
            host: t.domain.clone()?,
            port: t.public_port,
            // Through a web server the upgrade path is required.
            path: (t.frontend != tls::Frontend::Builtin).then(|| t.ws_path.clone()),
        })
    });
    let subscription = match (subscription, &tls_link) {
        (Some(settings), Some(_)) => {
            tracing::info!("Subscriptions served at https://<domain>{}/<token>", settings.prefix);
            Some(Arc::new(subscription::SubscriptionService {
                settings,
                tls: tls_link.clone(),
                udp: (server_host.clone(), server_port),
                dns: dns_server.clone(),
                keys: shared_keys.clone(),
                stats: dispatcher.user_stats_ref(),
            }))
        }
        (Some(_), None) => {
            tracing::warn!("subscription is enabled but TLS with a domain is not; subscriptions are off");
            None
        }
        _ => None,
    };

    // Spawn Management API if configured
    if let Some(api_cfg) = api_config {
        if api_cfg.enabled {
            let api_keys = shared_keys.clone();
            let api_stats = dispatcher.user_stats_ref();
            let server_host = server_host.clone();
            let config_path_api = config_path.clone();
            let dns_server_api = dns_server.clone();
            let router_api = router.clone();
            let tls_link = tls_link.clone();
            let sub_prefix = subscription.as_ref().map(|s| s.settings.prefix.clone());
            tokio::spawn(async move {
                api::start_api_server(api_cfg, api_keys, api_stats, server_host, server_port, tls_link, sub_prefix, config_path_api, dns_server_api, router_api).await;
            });
        }
    }

    // Every TCP listener sniffs; the fallback target (if any) is where
    // non-OSTP traffic goes, and its listen address is one more listener.
    let fallback = fallback_config.filter(|f| f.enabled);
    let mut tcp_listen = bind_addrs.clone();
    if let Some(fb) = &fallback {
        if !tcp_listen.contains(&fb.listen) {
            tcp_listen.push(fb.listen.clone());
        }
    }
    let prepared = tls.as_ref().and_then(prepare_tls);
    let (acceptor, resolver) = match prepared {
        Some((a, r)) => (Some(a), Some(r)),
        None => (None, None),
    };
    let builtin = tls.as_ref().filter(|t| t.frontend == tls::Frontend::Builtin);
    // ACME challenges: answered on the built-in port 80, or on a local
    // responder that the web-server frontend proxies /.well-known/ to.
    let acme = tls.as_ref().filter(|t| t.cert == tls::CertSource::Acme && t.frontend != tls::Frontend::Caddy);
    let challenges = acme.map(|t| tls::acme::ChallengeStore::new(&tls::acme::state_dir(&t.config_dir)));
    let responder = match (acme, &challenges) {
        (Some(t), Some(store)) if t.frontend != tls::Frontend::Builtin => Some((t.acme.responder.clone(), store.clone())),
        _ => None,
    };
    let sniff = SniffSettings {
        tcp_listen,
        ws_path: tls.as_ref().map(|t| t.ws_path.clone()),
        subscription,
        decoy: match &fallback {
            Some(fb) => transport::sniff::Decoy::Proxy(fb.target.clone()),
            None => transport::sniff::Decoy::NotFound,
        },
        https_listen: match (builtin, &acceptor) {
            (Some(t), Some(_)) => t.https_listen.clone(),
            _ => Vec::new(),
        },
        tls: acceptor,
        panel: panel_route,
        http_listen: builtin.map(|t| t.http_listen.clone()).unwrap_or_default(),
        redirect: builtin
            .and_then(|t| t.domain.as_deref().map(|d| tls::http_frontend::RedirectTarget::new(d, t.public_port))),
        challenges: challenges.clone(),
        responder,
    };
    if let (Some(t), Some(store)) = (acme, challenges) {
        tokio::spawn(tls::acme::renewal_task(t.clone(), store, resolver));
    }

    let (_ui_cmd_tx, ui_cmd_rx) = mpsc::unbounded_channel::<UiCommand>();
    let (ui_event_tx, mut ui_event_rx) = mpsc::unbounded_channel::<UiEvent>();

    // Headless event logger
    tokio::spawn(async move {
        // Rate-limit unauthorized-probe logging so a junk/probe flood can't spam the log
        // (and so a client running junk-over-UDP can't trigger a self-ban via log noise).
        let mut probe_window_start: Option<Instant> = None;
        let mut probe_suppressed: u64 = 0;
        while let Some(ev) = ui_event_rx.recv().await {
            match ev {
                UiEvent::Log(msg) => {
                    // Essential logs always visible; debug logs gated behind flag
                    let is_essential = msg.starts_with("Client ")
                        || msg.starts_with("Listening")
                        || msg.starts_with("Shutdown")
                        || msg.starts_with("Session ")
                        || msg.starts_with("Relay error");
                    if debug || is_essential {
                        tracing::info!("{msg}");
                    }
                }
                UiEvent::KeyCreated { key } => {
                    // Never log the access key verbatim — it's a shared secret.
                    tracing::info!("Access key created (fp={})", crate::dispatcher::key_fp(&key));
                }
                UiEvent::UnauthorizedProbe { peer, bytes } => {
                    if debug {
                        let now = Instant::now();
                        let elapsed = probe_window_start
                            .map(|s| now.duration_since(s))
                            .unwrap_or(Duration::MAX);
                        if elapsed >= Duration::from_secs(30) {
                            if probe_suppressed > 0 {
                                tracing::debug!(
                                    "(+{} more unauthorized probes suppressed in the previous ~30s)",
                                    probe_suppressed
                                );
                            }
                            probe_window_start = Some(now);
                            probe_suppressed = 0;
                            tracing::debug!("Unauthorized probe from {peer} ({bytes} bytes)");
                        } else {
                            probe_suppressed += 1;
                        }
                    }
                }
                UiEvent::PeerSeen { .. } => {}
                _ => {}
            }
        }
    });

    let key_count = shared_keys.read().unwrap_or_else(|e| e.into_inner()).len();
    tracing::info!(listeners = bind_addrs.len(), keys = key_count, "server started");
    tracing::info!("ARQ config: max_reorder=16384, reorder_buf=8192, sent_history=32768, rto=100ms");
    tokio::select! {
        res = run_server_loop(sniff, sockets, dispatcher, ui_cmd_rx, ui_event_tx, shared_keys, router, stats_file.clone()) => {
            if let Err(e) = res {
                tracing::error!("Server error: {e}");
            }
        }
        _ = wait_for_shutdown_signal() => {
            tracing::info!("Shutdown signal received");
        }
    }

    // A restart or an update stops the service here: keep what was counted
    // since the last periodic write (up to STATS_INTERVAL of traffic, and the
    // DNS counters and query log).
    if let Some(path) = &stats_file {
        if let Err(e) = write_stats_file(path, &final_stats(&traffic, process_started)) {
            tracing::warn!("could not save traffic to {}: {e}", path.display());
        }
    }
    dns_server.persist();

    Ok(())
}

// ── Server main loop ─────────────────────────────────────────────────────────

/// TCP-side settings for the sniffing listeners.
struct SniffSettings {
    tcp_listen: Vec<String>,
    ws_path: Option<String>,
    subscription: Option<Arc<subscription::SubscriptionService>>,
    decoy: transport::sniff::Decoy,
    tls: Option<tokio_rustls::TlsAcceptor>,
    /// Built-in frontend: TLS-only listeners that also serve the panel.
    https_listen: Vec<String>,
    panel: Option<transport::sniff::PanelRoute>,
    /// Built-in frontend: plain HTTP, redirected to https.
    http_listen: Vec<String>,
    redirect: Option<tls::http_frontend::RedirectTarget>,
    challenges: Option<Arc<tls::acme::ChallengeStore>>,
    /// Local ACME responder for a web-server frontend: (address, store).
    responder: Option<(String, Arc<tls::acme::ChallengeStore>)>,
}

/// "0.0.0.0:9090" -> "127.0.0.1:9090", "[::]:9090" -> "[::1]:9090".
fn loopback_for(bind: &str) -> String {
    match bind.parse::<std::net::SocketAddr>() {
        Ok(mut a) if a.ip().is_unspecified() => {
            a.set_ip(if a.is_ipv6() {
                std::net::Ipv6Addr::LOCALHOST.into()
            } else {
                std::net::Ipv4Addr::LOCALHOST.into()
            });
            a.to_string()
        }
        _ => bind.to_string(),
    }
}

/// Loads (or, before the first issuance, stands in) the certificate and
/// starts watching it. None when OSTP terminates no TLS itself.
fn prepare_tls(t: &tls::TlsSettings) -> Option<(tokio_rustls::TlsAcceptor, Arc<tls::HotCertResolver>)> {
    if t.cert == tls::CertSource::None {
        return None;
    }
    if !t.cert_path.exists() || !t.key_path.exists() {
        match (t.cert, t.domain.as_deref()) {
            (tls::CertSource::Acme, Some(domain)) => {
                if let Err(e) = tls::write_placeholder(domain, &t.cert_path, &t.key_path) {
                    tracing::error!("TLS disabled: cannot write a placeholder certificate: {e:#}");
                    return None;
                }
                tracing::warn!(
                    "No certificate yet for {domain}; serving a self-signed placeholder until it is issued (ostp cert issue)"
                );
            }
            _ => {
                tracing::error!(
                    "TLS disabled: certificate {} or key {} not found",
                    t.cert_path.display(),
                    t.key_path.display()
                );
                return None;
            }
        }
    }
    let resolver = tls::HotCertResolver::new(&t.cert_path, &t.key_path);
    if let Err(e) = resolver.reload() {
        tracing::error!("TLS disabled: {e:#}");
        return None;
    }
    resolver.spawn_watch();
    match tls::build_acceptor(resolver.clone()) {
        Ok(a) => {
            tracing::info!("TLS enabled ({} frontend), certificate {}", t.frontend.as_str(), t.cert_path.display());
            Some((a, resolver))
        }
        Err(e) => {
            tracing::error!("TLS disabled: {e:#}");
            None
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_server_loop(
    sniff: SniffSettings,
    sockets: Vec<std::sync::Arc<UdpSocket>>,
    mut dispatcher: Dispatcher,
    mut ui_cmd_rx: mpsc::UnboundedReceiver<UiCommand>,
    ui_event_tx: mpsc::UnboundedSender<UiEvent>,
    shared_keys: std::sync::Arc<std::sync::RwLock<HashMap<String, crate::api::UserMeta>>>,
    router: std::sync::Arc<crate::router::Router>,
    stats_file: Option<std::path::PathBuf>,
) -> Result<()> {
    let mut remotes: HashMap<(u32, u16), RemoteState> = HashMap::new();
    let (stream_tx, mut stream_rx) = mpsc::unbounded_channel::<(u32, u16, Vec<u8>)>();
    let (udp_reply_tx, mut udp_reply_rx) = mpsc::unbounded_channel::<(u32, u16, String, Vec<u8>)>();
    let (connect_tx, mut connect_rx) = mpsc::unbounded_channel::<(u32, u16, String, Result<(tokio::net::tcp::OwnedWriteHalf, mpsc::Sender<()>), String>)>();

    let tcp_map = std::sync::Arc::new(tokio::sync::RwLock::new(HashMap::new()));

    // Replies go out of the socket the client reached us on (see
    // transport::udp), not a fixed "primary" one.
    let socket = std::sync::Arc::new(transport::udp::UdpSockets::new(sockets));
    // Spawn a recv task for each socket, all feeding into the same channel
    let (udp_tx, mut udp_rx) = mpsc::channel(100000);
    for (index, sock) in socket.sockets().iter().enumerate() {
        let sock_clone = sock.clone();
        let sockets = socket.clone();
        let tx = udp_tx.clone();
        tokio::spawn(async move {
            let mut buf = vec![0_u8; 65535];
            loop {
                match sock_clone.recv_from(&mut buf).await {
                    Ok((size, peer)) => {
                        sockets.received(index, peer);
                        let packet = Bytes::copy_from_slice(&buf[..size]);
                        if tx.send((packet, peer)).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
    }

    // TCP listeners (UoT, plus HTTP upgrade and decoy on the same ports)
    let limiter = Arc::new(transport::limiter::ConnLimiter::new());
    let pending = Arc::new(tokio::sync::Semaphore::new(transport::sniff::MAX_PENDING));
    let sniff_ctx = Arc::new(transport::sniff::SniffCtx {
        tls: sniff.tls.clone(),
        tls_required: false,
        panel: None,
        ws_path: sniff.ws_path.clone(),
        subscription: sniff.subscription.clone(),
        decoy: sniff.decoy.clone(),
        limiter: limiter.clone(),
        pending: pending.clone(),
        tcp_map: tcp_map.clone(),
        udp_tx: udp_tx.clone(),
    });
    for addr in &sniff.tcp_listen {
        match tokio::net::TcpListener::bind(addr).await {
            Ok(listener) => {
                tracing::info!("TCP listener bound to {}", addr);
                tokio::spawn(transport::sniff::serve_listener(listener, sniff_ctx.clone()));
            }
            Err(e) => tracing::warn!("Failed to bind TCP listener to {}: {}", addr, e),
        }
    }
    drop(sniff_ctx);

    if !sniff.https_listen.is_empty() {
        let https_ctx = Arc::new(transport::sniff::SniffCtx {
            tls: sniff.tls.clone(),
            tls_required: true,
            panel: sniff.panel.clone(),
            ws_path: sniff.ws_path.clone(),
            subscription: sniff.subscription.clone(),
            decoy: sniff.decoy.clone(),
            limiter,
            pending,
            tcp_map: tcp_map.clone(),
            udp_tx: udp_tx.clone(),
        });
        for addr in &sniff.https_listen {
            match tokio::net::TcpListener::bind(addr).await {
                Ok(listener) => {
                    tracing::info!("HTTPS listener bound to {}", addr);
                    tokio::spawn(transport::sniff::serve_listener(listener, https_ctx.clone()));
                }
                Err(e) => tracing::error!(
                    "Failed to bind HTTPS on {addr}: {e} (another web server on 443, or not running as root?)"
                ),
            }
        }
    }
    if let Some(target) = sniff.redirect {
        let store = sniff
            .challenges
            .clone()
            .unwrap_or_else(|| tls::acme::ChallengeStore::new(std::path::Path::new(".")));
        let app = tls::acme::challenge_router(store, Some(target));
        for addr in &sniff.http_listen {
            match tokio::net::TcpListener::bind(addr).await {
                Ok(listener) => {
                    tracing::info!("HTTP listener bound to {} (redirect to https)", addr);
                    tokio::spawn(tls::http_frontend::serve(listener, app.clone()));
                }
                Err(e) => tracing::error!(
                    "Failed to bind HTTP on {addr}: {e} (another web server on 80, or not running as root?)"
                ),
            }
        }
    }
    if let Some((addr, store)) = sniff.responder {
        match tokio::net::TcpListener::bind(&addr).await {
            Ok(listener) => {
                tracing::info!("ACME responder bound to {}", addr);
                tokio::spawn(tls::http_frontend::serve(listener, tls::acme::challenge_router(store, None)));
            }
            Err(e) => tracing::error!("Failed to bind the ACME responder on {addr}: {e}"),
        }
    }

    drop(udp_tx); // Drop the original sender so the channel closes when all tasks end

    if router.debug {
        let _ = ui_event_tx.send(UiEvent::Log("Server loop started".to_string()));
        let _ = ui_event_tx.send(UiEvent::KeyCount(shared_keys.read().unwrap_or_else(|e| e.into_inner()).len()));
    }

    let mut retransmit_tick = interval(Duration::from_millis(10));
    let mut last_empty_app_log = Instant::now() - Duration::from_secs(10);
    let mut peer_last_seen: HashMap<IpAddr, Instant> = HashMap::new();
    let mut peer_available: HashMap<IpAddr, bool> = HashMap::new();
    let session_backpressure: SessionBackpressure = Arc::new(RwLock::new(HashMap::new()));
    let started_at = std::time::SystemTime::now();
    let mut stats_tick = interval(STATS_INTERVAL);

    loop {
        tokio::select! {
            _ = stats_tick.tick(), if stats_file.is_some() => {
                let snapshot = StatsFile {
                    written_at: unix_secs(std::time::SystemTime::now()),
                    started_at: unix_secs(started_at),
                    sessions: dispatcher.active_sessions(),
                    users: dispatcher.snapshot_all_users(),
                };
                let path = stats_file.clone().unwrap();
                tokio::task::spawn_blocking(move || {
                    if let Err(e) = write_stats_file(&path, &snapshot) {
                        tracing::debug!("could not write {}: {e}", path.display());
                    }
                });
            }
            cmd = ui_cmd_rx.recv() => {
                match cmd {
                    Some(UiCommand::Shutdown) | None => {
                        let _ = ui_event_tx.send(UiEvent::Log("Shutdown command received".to_string()));
                        break;
                    }
                }
            }
            received = udp_rx.recv() => {
                if let Some((packet, peer)) = received {
                    if let Err(e) = handle_udp_packet(
                        packet, peer, &mut dispatcher, &tcp_map, &socket, &mut remotes, &ui_event_tx,
                        stream_tx.clone(), udp_reply_tx.clone(), connect_tx.clone(),
                        router.clone(),
                        &mut peer_last_seen, &mut peer_available, &mut last_empty_app_log,
                        &session_backpressure
                    ).await {
                        tracing::error!("handle_udp_packet error: {}", e);
                    }
                }
            }
            Some((session_id, stream_id, data)) = stream_rx.recv() => {
                if data.is_empty() {
                    let _ = relay::send_relay_to_stream(session_id, stream_id, RelayMessage::Close, &mut dispatcher, &socket, &ui_event_tx, &tcp_map).await;
                    if let Some(state) = remotes.remove(&(session_id, stream_id)) {
                        let _ = state.cancel_tx.try_send(());
                    }
                } else {
                    let _ = relay::send_relay_to_stream(session_id, stream_id, RelayMessage::Data(data), &mut dispatcher, &socket, &ui_event_tx, &tcp_map).await;
                }
            }
            Some((session_id, stream_id, target, data)) = udp_reply_rx.recv() => {
                let _ = relay::send_relay_to_stream(session_id, stream_id, RelayMessage::UdpData(target, data), &mut dispatcher, &socket, &ui_event_tx, &tcp_map).await;
            }
            Some((session_id, stream_id, target, res)) = connect_rx.recv() => {
                match res {
                    Ok((writer, cancel_tx)) => {
                        let (data_tx, mut data_rx) = mpsc::unbounded_channel::<Bytes>();
                        let queued = Arc::new(std::sync::atomic::AtomicUsize::new(0));
                        let writer_queued = queued.clone();
                        let mut writer_task = writer;
                        tokio::spawn(async move {
                            while let Some(data) = data_rx.recv().await {
                                if tokio::io::AsyncWriteExt::write_all(&mut writer_task, &data).await.is_err() {
                                    break;
                                }
                                writer_queued.fetch_sub(data.len(), std::sync::atomic::Ordering::Relaxed);
                            }
                        });
                        remotes.insert((session_id, stream_id), RemoteState { data_tx, queued, udp_tx: None, cancel_tx, is_dns: false });
                        let _ = relay::send_relay_to_stream(session_id, stream_id, RelayMessage::ConnectOk, &mut dispatcher, &socket, &ui_event_tx, &tcp_map).await;
                        let _ = ui_event_tx.send(UiEvent::Log(format!("Relay CONNECT ok for [{session_id}:{stream_id}] -> {target}")));
                    }
                    Err(err) => {
                        let _ = ui_event_tx.send(UiEvent::Log(format!("Relay error: CONNECT failed for [{session_id}:{stream_id}] -> {target}: {err}")));
                        let _ = relay::send_relay_to_stream(session_id, stream_id, RelayMessage::Error(format!("connect failed: {err}")), &mut dispatcher, &socket, &ui_event_tx, &tcp_map).await;
                    }
                }
            }
            _ = retransmit_tick.tick() => {
                if let Err(e) = handle_tick(
                    &mut dispatcher, &tcp_map, &socket, &mut remotes, &ui_event_tx,
                    &mut peer_last_seen, &mut peer_available, &session_backpressure
                ).await {
                    tracing::error!("handle_tick error: {}", e);
                }
            }
        }
    }

    Ok(())
}

/// Traffic per user, written next to the config every `STATS_INTERVAL` and on
/// a clean stop, so that `ostp manage` (what the desktop app runs over SSH)
/// can show it without the management API. Read back on start: the counters
/// (and the traffic limits that depend on them) survive restarts and updates.
pub const STATS_FILE: &str = ".ostp_stats.json";
const STATS_INTERVAL: Duration = Duration::from_secs(30);

#[derive(serde::Serialize, serde::Deserialize)]
pub struct StatsFile {
    pub written_at: u64,
    pub started_at: u64,
    pub sessions: usize,
    pub users: Vec<dispatcher::UserStatsSnapshot>,
}

/// Seeds the per-user counters from the stats file of the previous run. Only
/// users still in the config are restored; live sessions start from zero.
/// Returns how many users got their traffic back.
fn restore_user_traffic(
    path: &std::path::Path,
    stats: &Arc<RwLock<HashMap<String, Arc<dispatcher::UserStats>>>>,
    keys: &Arc<RwLock<HashMap<String, api::UserMeta>>>,
) -> usize {
    let Ok(body) = std::fs::read(path) else { return 0 };
    let saved: StatsFile = match serde_json::from_slice(&body) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("{} is unreadable, traffic starts from zero: {e}", path.display());
            return 0;
        }
    };
    let keys = keys.read().unwrap_or_else(|e| e.into_inner());
    let mut stats = stats.write().unwrap_or_else(|e| e.into_inner());
    let mut restored = 0;
    for u in saved.users {
        let Some(meta) = keys.get(&u.access_key) else { continue };
        let entry = dispatcher::UserStats::new(meta.limit_bytes);
        entry.bytes_up.store(u.bytes_up, std::sync::atomic::Ordering::Relaxed);
        entry.bytes_down.store(u.bytes_down, std::sync::atomic::Ordering::Relaxed);
        stats.insert(u.access_key, Arc::new(entry));
        restored += 1;
    }
    restored
}

/// The stats file as the service stops: no sessions are left.
fn final_stats(stats: &Arc<RwLock<HashMap<String, Arc<dispatcher::UserStats>>>>, started: std::time::SystemTime) -> StatsFile {
    use std::sync::atomic::Ordering;
    let stats = stats.read().unwrap_or_else(|e| e.into_inner());
    StatsFile {
        written_at: unix_secs(std::time::SystemTime::now()),
        started_at: unix_secs(started),
        sessions: 0,
        users: stats
            .iter()
            .map(|(key, us)| dispatcher::UserStatsSnapshot {
                access_key: key.clone(),
                name: None,
                bytes_up: us.bytes_up.load(Ordering::Relaxed),
                bytes_down: us.bytes_down.load(Ordering::Relaxed),
                connections: 0,
                limit_bytes: us.limit_bytes,
                online: false,
                last_seen: None,
            })
            .collect(),
    }
}

/// Frames dropped because a TCP/TLS client's send queue was full.
static TCP_QUEUE_DROPS: portable_atomic::AtomicU64 = portable_atomic::AtomicU64::new(0);

/// Hands a frame to a TCP/TLS client's writer. The queue is bounded, and the
/// main loop must not wait on one slow client, so a full queue drops the
/// frame; the client then NACKs the gap. That used to happen silently, which
/// hid the cause of stalls on TLS: now it is logged (the first time, then at
/// every power of two).
pub(crate) fn queue_to_tcp(tx: &tokio::sync::mpsc::Sender<bytes::Bytes>, frame: bytes::Bytes) {
    if let Err(tokio::sync::mpsc::error::TrySendError::Full(_)) = tx.try_send(frame) {
        let n = TCP_QUEUE_DROPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        if n.is_power_of_two() {
            tracing::warn!("a TCP/TLS client does not keep up: frame dropped from its full send queue ({n} so far)");
        }
    }
}

fn unix_secs(t: std::time::SystemTime) -> u64 {
    t.duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Written to a temporary file and renamed, so a reader never sees half of it.
/// Only root can read it: it holds the access keys.
fn write_stats_file(path: &std::path::Path, stats: &StatsFile) -> std::io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    let body = serde_json::to_vec(stats).map_err(std::io::Error::other)?;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    std::io::Write::write_all(&mut opts.open(&tmp)?, &body)?;
    std::fs::rename(&tmp, path)
}

async fn handle_udp_packet(
    packet: Bytes,
    peer: std::net::SocketAddr,
    dispatcher: &mut Dispatcher,
    tcp_map: &std::sync::Arc<tokio::sync::RwLock<HashMap<std::net::SocketAddr, tokio::sync::mpsc::Sender<Bytes>>>>,
    socket: &transport::udp::UdpSockets,
    remotes: &mut HashMap<(u32, u16), RemoteState>,
    ui_event_tx: &mpsc::UnboundedSender<UiEvent>,
    stream_tx: mpsc::UnboundedSender<(u32, u16, Vec<u8>)>,
    udp_reply_tx: mpsc::UnboundedSender<(u32, u16, String, Vec<u8>)>,
    connect_tx: mpsc::UnboundedSender<(u32, u16, String, Result<(tokio::net::tcp::OwnedWriteHalf, mpsc::Sender<()>), String>)>,
    router: std::sync::Arc<crate::router::Router>,
    peer_last_seen: &mut HashMap<IpAddr, Instant>,
    peer_available: &mut HashMap<IpAddr, bool>,
    last_empty_app_log: &mut Instant,
    session_backpressure: &SessionBackpressure,
) -> Result<()> {
    let size = packet.len();
    match dispatcher.on_datagram(peer, packet.clone()) {
        Ok(DispatchOutcome::Junk) => return Ok(()),
        Ok(DispatchOutcome::Unauthorized) => {
            let _ = ui_event_tx.send(UiEvent::UnauthorizedProbe { peer: peer.ip(), bytes: size });
        }
        Ok(DispatchOutcome::Accepted { responses, app_payloads, peer_addr }) => {
            let peer_ip = peer_addr.ip();
            let now = Instant::now();
            peer_last_seen.insert(peer_ip, now);
            let is_tcp = tcp_map.read().await.contains_key(&peer_addr);
            dispatcher.set_carrier_reliable(peer_addr, is_tcp);
            // An ACK may have opened the window: the readers learn it now, not
            // at the next tick.
            if let Some((sid, available)) = dispatcher.budget_for_addr(peer_addr) {
                if let Some(gate) = session_backpressure.read().unwrap_or_else(|e| e.into_inner()).get(&sid) {
                    gate.set(available);
                }
            }
            if !peer_available.get(&peer_ip).copied().unwrap_or(false) {
                peer_available.insert(peer_ip, true);
                let proto = if is_tcp { "TCP (UoT)" } else { "UDP" };
                let _ = ui_event_tx.send(UiEvent::Log(format!("Client {peer_ip} connected via {proto}")));
            }

            if app_payloads.is_empty() && now.duration_since(*last_empty_app_log) > Duration::from_secs(5) {
                *last_empty_app_log = now;
                let _ = ui_event_tx.send(UiEvent::Log(format!(
                    "Accepted datagrams from {peer_ip} with no app payloads (responses={})",
                    responses.len()
                )));
            }
            for resp in responses {
                let mut sent_tcp = false;
                {
                    let map = tcp_map.read().await;
                    if let Some(tx) = map.get(&peer_addr) {
                        queue_to_tcp(tx, resp.clone());
                        sent_tcp = true;
                    }
                }
                if !sent_tcp {
                    let _ = socket.send_to(&resp, peer_addr).await?;
                }
            }

            // No per-packet events or log lines here: nothing consumes Rx/Tx,
            // and a formatted line per data packet was work thrown away
            // tens of thousands of times a second.
            for (session_id, stream_id, payload) in app_payloads {
                if router.debug {
                    let _ = ui_event_tx.send(UiEvent::Log(format!(
                        "Deliver app payload sid={session_id} stream={stream_id} bytes={}",
                        payload.len()
                    )));
                }
                relay::handle_relay_message(
                    peer_addr,
                    session_id,
                    stream_id,
                    payload,
                    dispatcher,
                    socket,
                    remotes,
                    ui_event_tx,
                    stream_tx.clone(),
                    udp_reply_tx.clone(),
                    connect_tx.clone(),
                    router.clone(),
                    tcp_map,
                    session_backpressure,
                ).await?;
            }
        }
        Err(err) => {
            let _ = ui_event_tx.send(UiEvent::Log(format!("Protocol error for {peer}: {err}")));
        }
    }
    Ok(())
}

async fn handle_tick(
    dispatcher: &mut Dispatcher,
    tcp_map: &std::sync::Arc<tokio::sync::RwLock<HashMap<std::net::SocketAddr, tokio::sync::mpsc::Sender<Bytes>>>>,
    socket: &transport::udp::UdpSockets,
    remotes: &mut HashMap<(u32, u16), RemoteState>,
    ui_event_tx: &mpsc::UnboundedSender<UiEvent>,
    peer_last_seen: &mut HashMap<IpAddr, Instant>,
    peer_available: &mut HashMap<IpAddr, bool>,
    session_backpressure: &SessionBackpressure,
) -> Result<()> {
    let now = Instant::now();
    let peer_timeout = Duration::from_secs(45);
    for (peer_ip, last_seen) in peer_last_seen.iter() {
        let is_available = peer_available.get(peer_ip).copied().unwrap_or(false);
        if is_available && now.duration_since(*last_seen) > peer_timeout {
            peer_available.insert(*peer_ip, false);
            let _ = ui_event_tx.send(UiEvent::Log(format!("Client {peer_ip} disconnected (timeout)")));
        }
    }
    // Publish each active session's current download-direction headroom so
    // relay reader tasks (running on other tasks, no access to `dispatcher`)
    // can throttle without touching a lock on every read. New sessions get an
    // entry created here on their first tick after the handshake; entries for
    // sessions that no longer exist are pruned below alongside dropped_sessions.
    {
        let snapshot = dispatcher.snapshot_backpressure();
        let mut map = session_backpressure.write().unwrap_or_else(|e| e.into_inner());
        for (sid, available) in snapshot {
            match map.get(&sid) {
                Some(gate) => gate.set(available),
                None => { map.insert(sid, Arc::new(send_gate::SendGate::new(available))); }
            }
        }
    }

    let (frames, dropped_sessions) = dispatcher.on_tick();
    for (frame, peer_addr) in frames {
        let mut sent_tcp = false;
        {
            let map = tcp_map.read().await;
            if let Some(tx) = map.get(&peer_addr) {
                queue_to_tcp(tx, frame.clone());
                sent_tcp = true;
            }
        }
        if !sent_tcp {
            let _ = socket.send_to(&frame, peer_addr).await?;
        }
    }
    if !dropped_sessions.is_empty() {
        let mut map = session_backpressure.write().unwrap_or_else(|e| e.into_inner());
        for sid in &dropped_sessions {
            map.remove(sid);
        }
    }
    for sid in dropped_sessions {
        let _ = ui_event_tx.send(UiEvent::Log(format!("Session {sid} expired, releasing resources")));
        let mut streams_to_cancel = Vec::new();
        for &(session_id, stream_id) in remotes.keys() {
            if session_id == sid {
                streams_to_cancel.push((session_id, stream_id));
            }
        }
        for key in streams_to_cancel {
            if let Some(state) = remotes.remove(&key) {
                let _ = state.cancel_tx.try_send(());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod traffic_tests {
    use super::*;
    use std::sync::atomic::Ordering;

    fn meta(limit: Option<u64>) -> api::UserMeta {
        api::UserMeta { name: None, limit_bytes: limit }
    }

    #[test]
    fn traffic_written_on_stop_comes_back_on_start() {
        let path = std::env::temp_dir().join(format!("ostp-stats-{}.json", rand::random::<u64>()));
        let stats: Arc<RwLock<HashMap<String, Arc<dispatcher::UserStats>>>> = Arc::new(RwLock::new(HashMap::new()));
        let alice = dispatcher::UserStats::new(Some(5000));
        alice.bytes_up.store(100, Ordering::Relaxed);
        alice.bytes_down.store(4000, Ordering::Relaxed);
        alice.connections.store(2, Ordering::Relaxed);
        stats.write().unwrap().insert("key-a".into(), Arc::new(alice));
        let gone = dispatcher::UserStats::new(None);
        gone.bytes_down.store(7, Ordering::Relaxed);
        stats.write().unwrap().insert("key-gone".into(), Arc::new(gone));
        write_stats_file(&path, &final_stats(&stats, std::time::SystemTime::now())).unwrap();

        // The next start: key-gone was removed from the config meanwhile,
        // and key-a's limit changed.
        let keys = Arc::new(RwLock::new(HashMap::from([
            ("key-a".to_string(), meta(Some(4096))),
            ("key-b".to_string(), meta(None)),
        ])));
        let fresh: Arc<RwLock<HashMap<String, Arc<dispatcher::UserStats>>>> = Arc::new(RwLock::new(HashMap::new()));
        assert_eq!(restore_user_traffic(&path, &fresh, &keys), 1);
        let fresh = fresh.read().unwrap();
        let a = &fresh["key-a"];
        assert_eq!((a.bytes_up.load(Ordering::Relaxed), a.bytes_down.load(Ordering::Relaxed)), (100, 4000));
        assert_eq!(a.connections.load(Ordering::Relaxed), 0, "no session survives a restart");
        assert_eq!(a.limit_bytes, Some(4096), "the limit comes from the config, not the old file");
        assert!(a.is_over_limit(), "a restart no longer resets the traffic limit");
        assert!(!fresh.contains_key("key-gone"));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn a_missing_or_broken_file_starts_from_zero() {
        let keys = Arc::new(RwLock::new(HashMap::from([("k".to_string(), meta(None))])));
        let stats = Arc::new(RwLock::new(HashMap::new()));
        let missing = std::env::temp_dir().join(format!("ostp-stats-missing-{}.json", rand::random::<u64>()));
        assert_eq!(restore_user_traffic(&missing, &stats, &keys), 0);
        let broken = std::env::temp_dir().join(format!("ostp-stats-broken-{}.json", rand::random::<u64>()));
        std::fs::write(&broken, b"{not json").unwrap();
        assert_eq!(restore_user_traffic(&broken, &stats, &keys), 0);
        assert!(stats.read().unwrap().is_empty());
        std::fs::remove_file(broken).unwrap();
    }
}
