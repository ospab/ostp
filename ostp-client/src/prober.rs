//! Connectivity diagnostics for a configured ostp server: which resolved
//! address × transport combination actually completes a real, authenticated
//! handshake from the current network, and — for a chosen combo — at which
//! IP_TTL/hop-limit a middlebox (e.g. a Russian TSPU) starts answering in
//! place of the real server.
//!
//! Every probe here is a genuine OSTP handshake attempt using the caller's
//! own `access_key`, reusing the exact wire format the live client uses
//! (`ostp-core::ProtocolMachine`, `transport::connect_uot`'s junk/fragmentation).
//! There is no separate prober protocol and no new server-side code: the
//! existing dispatcher's key-based authentication is what already restricts
//! this to authorized clients.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use rand::Rng;
use serde::Serialize;
use tokio::net::UdpSocket;

use ostp_core::{NoiseRole, OstpEvent, PaddingStrategy, ProtocolAction, ProtocolConfig, ProtocolMachine, TrafficProfile};

use crate::debug_preview::describe_foreign_bytes;
use crate::transport::{connect_uot, Transport, UotOptions};

/// MTU used for probe handshakes. Only affects handshake padding bounds, not
/// whether the attempt succeeds — the live client's actual MTU setting is
/// irrelevant here, so a fixed sane default keeps the prober self-contained.
const PROBE_MTU: usize = 1140;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportKind {
    Udp,
    Uot,
    UotFrag,
    /// UoT inside TLS (and the upgrade path, when set), as a TLS profile connects.
    UotTls,
}

impl TransportKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            TransportKind::Udp => "udp",
            TransportKind::Uot => "uot",
            TransportKind::UotFrag => "uot_frag",
            TransportKind::UotTls => "uot_tls",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "udp" => Some(TransportKind::Udp),
            "uot" => Some(TransportKind::Uot),
            "uot_frag" => Some(TransportKind::UotFrag),
            "uot_tls" => Some(TransportKind::UotTls),
            _ => None,
        }
    }

    pub const ALL: [TransportKind; 3] = [TransportKind::Udp, TransportKind::Uot, TransportKind::UotFrag];
}

/// TLS settings of the profile being probed.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct ProbeTls {
    /// Server name; the host of the server address when empty.
    #[serde(default)]
    pub sni: String,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default)]
    pub ws_path: Option<String>,
}

/// Outcome of a single handshake attempt.
#[derive(Debug, Clone, Serialize)]
pub struct AttemptOutcome {
    pub success: bool,
    pub rtt_ms: Option<f64>,
    pub error: Option<String>,
    /// Present when a response arrived (or a connection died mid-frame) that
    /// does not look like it came from the real ostp server — see
    /// `describe_foreign_bytes`. Never set when `success` is true.
    pub foreign_bytes: Option<String>,
}

async fn connect_udp(target_ip: IpAddr, port: u16, ttl: Option<u32>) -> anyhow::Result<Transport> {
    let bind_addr: SocketAddr = if target_ip.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    let socket = UdpSocket::bind(bind_addr).await?;
    if let Some(ttl) = ttl {
        let _ = socket.set_ttl(ttl);
    }
    let connect_addr = SocketAddr::new(target_ip, port);
    socket.connect(connect_addr).await?;
    Ok(Transport::Udp(Arc::new(socket)))
}

/// Waits briefly for a foreign-bytes note from a UoT connection's reader
/// task. Used after a send/recv failure, where the note (if any) is racing
/// the failure itself rather than already queued.
async fn drain_foreign(rx: &mut Option<tokio::sync::mpsc::UnboundedReceiver<String>>) -> Option<String> {
    match rx {
        Some(r) => tokio::time::timeout(Duration::from_millis(200), r.recv()).await.ok().flatten(),
        None => None,
    }
}

/// Performs one real, authenticated handshake attempt against `target_ip`
/// over the given transport, with an optional IP_TTL/hop-limit override.
pub async fn attempt_handshake(
    target_ip: IpAddr,
    port: u16,
    transport: TransportKind,
    access_key: &[u8],
    ttl: Option<u32>,
    attempt_timeout: Duration,
    tls: Option<&ProbeTls>,
) -> AttemptOutcome {
    let secrets = ostp_core::crypto::derive_all_secrets(access_key);
    let session_id: u32 = rand::thread_rng().gen();
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

    let mut handshake_payload = Vec::with_capacity(8 + 4 + access_key.len());
    handshake_payload.extend_from_slice(&timestamp.to_be_bytes());
    handshake_payload.extend_from_slice(&session_id.to_be_bytes());
    handshake_payload.extend_from_slice(access_key);

    let mut machine = match ProtocolMachine::new(ProtocolConfig {
        role: NoiseRole::Initiator,
        psk: secrets.psk,
        session_id,
        handshake_payload,
        padding_strategy: PaddingStrategy::Profile(TrafficProfile::JsonRpc),
        obfuscation_key: secrets.obfuscation_key,
        max_reorder: 16384,
        max_reorder_buffer: 8192,
        ack_delay_ms: 5,
        rto_ms: 100,
        max_retries: 8,
        max_sent_history: 32768,
        handshake_pad_min: secrets.handshake_pad_min,
        handshake_pad_max: secrets.handshake_pad_max,
        mtu: PROBE_MTU,
        max_padding: PROBE_MTU.saturating_sub(48).max(256),
    }) {
        Ok(m) => m,
        Err(e) => return AttemptOutcome { success: false, rtt_ms: None, error: Some(format!("protocol init error: {e}")), foreign_bytes: None },
    };

    let handshake_frame = match machine.on_event(OstpEvent::Start) {
        Ok(ProtocolAction::SendDatagram(frame)) => frame,
        Ok(_) => return AttemptOutcome { success: false, rtt_ms: None, error: Some("protocol did not emit handshake datagram".into()), foreign_bytes: None },
        Err(e) => return AttemptOutcome { success: false, rtt_ms: None, error: Some(format!("protocol start error: {e}")), foreign_bytes: None },
    };

    let (transport_obj, mut foreign_rx) = match transport {
        TransportKind::Udp => match connect_udp(target_ip, port, ttl).await {
            Ok(t) => (t, None),
            Err(e) => return AttemptOutcome { success: false, rtt_ms: None, error: Some(format!("udp connect failed: {e}")), foreign_bytes: None },
        },
        TransportKind::Uot | TransportKind::UotFrag | TransportKind::UotTls => {
            let tls = if transport == TransportKind::UotTls {
                match tls {
                    Some(t) if !t.sni.is_empty() => Some(t),
                    _ => return AttemptOutcome { success: false, rtt_ms: None, error: Some("uot_tls needs the TLS server name".into()), foreign_bytes: None },
                }
            } else {
                None
            };
            let opts = UotOptions {
                tcp_fragmentation: transport == TransportKind::UotFrag,
                frag_chunk: 2,
                frag_sleep: 2,
                junk_pc: [2, 5],
                junk_ps: [100, 1000],
                access_key: Bytes::copy_from_slice(access_key),
                ttl,
                connect_timeout: attempt_timeout,
                tls: tls.map(|t| crate::transport::TlsClientOptions { sni: t.sni.clone(), insecure: t.insecure }),
                ws_path: tls.and_then(|t| t.ws_path.clone()).filter(|p| !p.is_empty()),
                http_host: tls.map(|t| t.sni.clone()).unwrap_or_default(),
            };
            match connect_uot(target_ip, port, opts).await {
                Ok((t, rx)) => (t, Some(rx)),
                Err(e) => return AttemptOutcome { success: false, rtt_ms: None, error: Some(format!("uot connect failed: {e}")), foreign_bytes: None },
            }
        }
    };

    let start = Instant::now();
    if transport_obj.send(&handshake_frame).await.is_err() {
        let foreign_bytes = drain_foreign(&mut foreign_rx).await;
        return AttemptOutcome { success: false, rtt_ms: None, error: Some("send failed".into()), foreign_bytes };
    }

    let mut buf = vec![0u8; 4096];
    match tokio::time::timeout(attempt_timeout, transport_obj.recv(&mut buf)).await {
        Ok(Ok(n)) => {
            let rtt_ms = start.elapsed().as_secs_f64() * 1000.0;
            let inbound = Bytes::copy_from_slice(&buf[..n]);
            match machine.on_event(OstpEvent::Inbound(inbound)) {
                Ok(_) => AttemptOutcome { success: true, rtt_ms: Some(rtt_ms), error: None, foreign_bytes: None },
                Err(e) => AttemptOutcome {
                    success: false,
                    rtt_ms: Some(rtt_ms),
                    error: Some(format!("response failed validation: {e}")),
                    foreign_bytes: Some(describe_foreign_bytes(&buf[..n])),
                },
            }
        }
        Ok(Err(e)) => {
            let foreign_bytes = drain_foreign(&mut foreign_rx).await;
            AttemptOutcome { success: false, rtt_ms: None, error: Some(format!("recv error: {e}")), foreign_bytes }
        }
        Err(_) => {
            let foreign_bytes = drain_foreign(&mut foreign_rx).await;
            AttemptOutcome { success: false, rtt_ms: None, error: Some("timed out waiting for a response".into()), foreign_bytes }
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct MatrixEntry {
    pub address: String,
    pub port: u16,
    pub address_kind: String,
    pub transport: String,
    pub outcome: AttemptOutcome,
}

/// Resolves `server_addr` and tries a real handshake over every
/// address × transport combination: each of the resolved IPv4/IPv6
/// addresses plus a NAT64-synthesized address (for IPv6-only networks, same
/// synthesis the live client falls back to), each over UDP / UoT / UoT with
/// TCP fragmentation.
///
/// With `tls` set (a TLS profile) the only carrier probed is UoT inside TLS,
/// on the profile's port: that is how the profile connects, and UDP/raw UoT
/// on a 443 served by a web server would only fail for unrelated reasons.
pub async fn run_matrix(
    server_addr: &str,
    access_key: &[u8],
    attempt_timeout: Duration,
    tls: Option<ProbeTls>,
) -> anyhow::Result<Vec<MatrixEntry>> {
    let tls = tls.map(|mut t| {
        if t.sni.is_empty() {
            t.sni = crate::bridge::server_host(server_addr);
        }
        t
    });
    let transports: Vec<TransportKind> =
        if tls.is_some() { vec![TransportKind::UotTls] } else { TransportKind::ALL.to_vec() };
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(server_addr).await?.collect();
    if addrs.is_empty() {
        anyhow::bail!("no addresses resolved for {server_addr}");
    }

    let mut candidates: Vec<(&'static str, IpAddr, u16)> = Vec::new();
    for addr in &addrs {
        let kind = if addr.is_ipv6() { "ipv6" } else { "ipv4" };
        candidates.push((kind, addr.ip(), addr.port()));
    }
    if let Some(SocketAddr::V4(v4)) = addrs.iter().find(|a| a.is_ipv4()) {
        let nat64 = crate::bridge::synthesize_nat64(*v4.ip()).await;
        candidates.push(("nat64", IpAddr::V6(nat64), v4.port()));
    }

    let mut results = Vec::with_capacity(candidates.len() * transports.len());
    for (kind, ip, port) in candidates {
        for &transport in &transports {
            let outcome = attempt_handshake(ip, port, transport, access_key, None, attempt_timeout, tls.as_ref()).await;
            results.push(MatrixEntry {
                address: ip.to_string(),
                port,
                address_kind: kind.to_string(),
                transport: transport.as_str().to_string(),
                outcome,
            });
        }
    }
    Ok(results)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TtlOutcomeKind {
    /// No response at all before the timeout — the probe likely expired
    /// before reaching anything that would answer.
    None,
    /// A response arrived and validated as a genuine ostp server reply.
    Genuine,
    /// A response arrived (or the connection died mid-frame) that does not
    /// look like it came from the real server.
    Foreign,
}

#[derive(Debug, Clone, Serialize)]
pub struct TtlStep {
    pub ttl: u32,
    pub outcome: TtlOutcomeKind,
    pub rtt_ms: Option<f64>,
    pub preview: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TtlScanReport {
    pub transport: String,
    pub address: String,
    pub steps: Vec<TtlStep>,
    /// Lowest TTL at which a foreign/injected response was observed.
    pub first_foreign_ttl: Option<u32>,
    /// Lowest TTL at which a genuine server response was observed.
    pub first_genuine_ttl: Option<u32>,
}

/// Repeats a real handshake attempt at increasing IP_TTL/hop-limit values
/// against one already-known-reachable address × transport combination.
///
/// The underlying idea: an inline middlebox (e.g. a TSPU) that intercepts
/// and answers in place of the real server does so as soon as a probe
/// physically reaches its position on the path, regardless of whether that
/// probe's TTL would also have been enough to reach the real server further
/// downstream. So as TTL increases from 1, expect: no response (the probe
/// dies before reaching anything) — then, once TTL reaches the middlebox's
/// hop distance, a *foreign* response — then, once TTL reaches the real
/// server's hop distance, a *genuine* one. `first_foreign_ttl` before
/// `first_genuine_ttl` is the signature of exactly that. This is a heuristic,
/// not a guarantee: asymmetric routing, ECMP load-balancing across parallel
/// paths, and stacked middleboxes can all produce a noisier picture — the
/// caller should present it as an estimate, not an exact hop count.
pub async fn run_ttl_scan(
    target_ip: IpAddr,
    port: u16,
    transport: TransportKind,
    access_key: &[u8],
    max_ttl: u32,
    attempt_timeout: Duration,
    tls: Option<ProbeTls>,
) -> TtlScanReport {
    let mut steps = Vec::new();
    let mut first_foreign_ttl = None;
    let mut first_genuine_ttl = None;

    for ttl in 1..=max_ttl.max(1) {
        let outcome = attempt_handshake(target_ip, port, transport, access_key, Some(ttl), attempt_timeout, tls.as_ref()).await;
        let (kind, preview) = if outcome.success {
            first_genuine_ttl.get_or_insert(ttl);
            (TtlOutcomeKind::Genuine, None)
        } else if let Some(fb) = outcome.foreign_bytes.clone() {
            first_foreign_ttl.get_or_insert(ttl);
            (TtlOutcomeKind::Foreign, Some(fb))
        } else {
            (TtlOutcomeKind::None, None)
        };
        let reached_real_server = kind == TtlOutcomeKind::Genuine;
        steps.push(TtlStep { ttl, outcome: kind, rtt_ms: outcome.rtt_ms, preview });
        // Once we've reached the real server, every higher TTL behaves the
        // same — no point spending more probes (and more of the user's time
        // on a mobile connection) confirming that.
        if reached_real_server {
            break;
        }
    }

    TtlScanReport {
        transport: transport.as_str().to_string(),
        address: target_ip.to_string(),
        steps,
        first_foreign_ttl,
        first_genuine_ttl,
    }
}
