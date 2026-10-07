//! Generic (non-ostp-specific) DPI/TSPU fingerprinting, ported from the
//! standalone `ostp-prober` desktop tool's `probes/dpi.rs` — the same raw
//! TCP/UDP differential tests, same target hosts and block-page signatures,
//! so a report from this module reads the same way as one from the desktop
//! tool. Where `prober.rs` in this crate answers "does *my* ostp server work
//! from here", this module answers "what does this network filter in
//! general" — useful context when the former fails: is it the network, or
//! just this server/transport?
//!
//! Every socket here is opened through [`protected_tcp_connect`] /
//! [`protected_udp_socket`], which calls [`crate::bridge::protect_socket`]
//! on the raw fd before it touches the network. Without that, running this
//! battery while the ostp VPN tunnel is active would route these probes
//! through the tunnel itself and always report a clean network — exactly
//! the case this module exists to diagnose.
//!
//! No stubbed results: a test that can't run on this platform/permission
//! level is simply not run, never faked.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::path_probe::{locate, react, Hop, Localization, Reaction};

// Cross-SNI targets: (IP, native SNI for that IP, port). Stable Russian IPs
// that answer their own SNI — same pair the desktop tool uses, so results
// from both tools are directly comparable.
const CROSS_SNI_TARGETS: &[(&str, &str, u16)] = &[
    ("87.240.132.78", "vk.com", 443), // VKontakte
    ("77.88.55.242", "ya.ru", 443),   // Yandex
];

const BLOCKED_SNIS: &[&str] = &["instagram.com", "twitter.com", "facebook.com"];
const BLOCKED_DOMAINS: &[&str] = &["instagram.com", "twitter.com", "facebook.com"];

// ── Protected socket primitives ─────────────────────────────────────────────

// Around the VPN tunnel on every platform: on Windows the tunnel used to
// carry these probes, so a desktop with TUN on measured the VPN server's
// network instead of its own.
async fn protected_tcp_connect(addr: SocketAddr, timeout: Duration) -> std::io::Result<TcpStream> {
    crate::path_probe::bypass_tcp_connect(addr, timeout).await
}

async fn protected_udp_socket(v6: bool) -> std::io::Result<UdpSocket> {
    crate::path_probe::bypass_udp_socket(v6).await
}

// ── Probe primitives ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeOutcome {
    /// The server answered the request.
    ServerResponded,
    /// Closed or reset sooner than half the RTT after the request went out:
    /// faster than the server could have, so something on the path did it.
    FastReset,
    /// Closed without an answer, but no sooner than the server itself could.
    SlowClose,
    /// No answer and no close within the window.
    Dropped,
    /// No TCP connection at all. Nothing was sent, so this says nothing
    /// about what is in the request (SNI, Host).
    Unreachable,
}

fn is_blocked(outcome: &ProbeOutcome) -> bool {
    matches!(outcome, ProbeOutcome::FastReset | ProbeOutcome::Dropped)
}

/// Sends `request` on a new connection to `addr` and classifies what comes
/// back. The clock starts when the request is sent: started before the
/// connect, it counted the handshake too, and a reset injected right after
/// the request never looked faster than the RTT.
async fn probe_request(addr: SocketAddr, request: &[u8], rtt: u64) -> ProbeOutcome {
    let timeout = Duration::from_millis((rtt * 5).max(2000));
    let Ok(mut stream) = protected_tcp_connect(addr, timeout).await else {
        return ProbeOutcome::Unreachable;
    };
    let sent = Instant::now();
    if stream.write_all(request).await.is_err() {
        return ProbeOutcome::FastReset;
    }
    let mut buf = [0u8; 128];
    match tokio::time::timeout(timeout, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => ProbeOutcome::ServerResponded,
        Ok(Ok(_)) | Ok(Err(_)) => {
            if (sent.elapsed().as_millis() as u64) < rtt / 2 {
                ProbeOutcome::FastReset
            } else {
                ProbeOutcome::SlowClose
            }
        }
        Err(_) => ProbeOutcome::Dropped,
    }
}

async fn measure_rtt(ip: &str, port: u16) -> Option<u64> {
    let addr: SocketAddr = format!("{ip}:{port}").parse().ok()?;
    let mut samples: Vec<u64> = Vec::with_capacity(4);
    for _ in 0..4 {
        let t = Instant::now();
        if protected_tcp_connect(addr, Duration::from_millis(3000)).await.is_ok() {
            samples.push(t.elapsed().as_millis() as u64);
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    if samples.len() < 2 {
        return None;
    }
    samples.sort_unstable();
    Some(samples[samples.len() / 2])
}

async fn probe_tls(ip: &str, port: u16, sni: &str, rtt: u64) -> ProbeOutcome {
    let Ok(addr) = format!("{ip}:{port}").parse::<SocketAddr>() else { return ProbeOutcome::Unreachable };
    probe_request(addr, &build_tls_client_hello(sni), rtt).await
}

async fn probe_http(ip: &str, host: &str, rtt: u64) -> ProbeOutcome {
    let Ok(addr) = format!("{ip}:80").parse::<SocketAddr>() else { return ProbeOutcome::Unreachable };
    let req = format!("GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: curl/8.0\r\nConnection: close\r\n\r\n");
    probe_request(addr, req.as_bytes(), rtt).await
}

/// What a differential test (blocked names against a clean baseline on the
/// same IP) saw.
#[derive(Debug, Default, Clone, Copy)]
struct Differential {
    /// Comparisons made (the baseline answered, the blocked name was sent).
    votes: usize,
    /// Of them, blocked (a fast reset or a drop).
    blocked: usize,
    /// Of the blocked, by a reset faster than the server could send one.
    forged_resets: usize,
}

impl Differential {
    fn measured(&self, min_votes: usize) -> bool {
        self.votes >= min_votes
    }

    fn is_blocked(&self, min_votes: usize) -> bool {
        self.measured(min_votes) && self.blocked * 2 > self.votes
    }

    fn add(&mut self, outcome: ProbeOutcome) {
        if outcome == ProbeOutcome::Unreachable {
            return;
        }
        self.votes += 1;
        if is_blocked(&outcome) {
            self.blocked += 1;
        }
        if outcome == ProbeOutcome::FastReset {
            self.forged_resets += 1;
        }
    }
}

fn http_status(line: &str) -> Option<u16> {
    let mut it = line.split_whitespace();
    let proto = it.next()?;
    if !proto.starts_with("HTTP/") {
        return None;
    }
    it.next()?.parse::<u16>().ok()
}

fn looks_like_block_page(resp: &str) -> bool {
    let low = resp.to_lowercase();
    ["доступ ограничен", "доступ заблокирован", "запрещён", "заблокирован",
     "blocklist.rkn", "eais.rkn", "единый реестр", "rkn.gov", "warning.rt.ru"]
        .iter()
        .any(|m| low.contains(m))
}

// ── Test 1: Cross-SNI differential ──────────────────────────────────────────
//
// Measure RTT to a clean RU host, confirm its own SNI answers, then send
// blocked SNIs to the SAME IP. Without DPI the server itself replies with a
// TLS alert (ServerResponded); with DPI a RST/drop arrives faster than RTT
// would allow.
/// Blocked SNIs against the same IP's own name. Counts only when the
/// baseline answered, so "not blocked" is never a guess.
async fn test_differential_sni() -> Differential {
    let mut d = Differential::default();
    for &(ip, clean_sni, port) in CROSS_SNI_TARGETS {
        let rtt = match measure_rtt(ip, port).await {
            Some(r) if r < 1000 => r,
            _ => continue,
        };
        if probe_tls(ip, port, clean_sni, rtt).await != ProbeOutcome::ServerResponded {
            continue;
        }
        for &sni in BLOCKED_SNIS {
            d.add(probe_tls(ip, port, sni, rtt).await);
        }
    }
    d
}

async fn test_differential_http_host() -> Differential {
    let http_targets: &[(&str, &str)] = &[("87.240.132.78", "vk.com"), ("77.88.55.242", "ya.ru")];
    let mut d = Differential::default();
    for &(ip, clean_host) in http_targets {
        let rtt = match measure_rtt(ip, 80).await {
            Some(r) if r < 1000 => r,
            _ => continue,
        };
        if probe_http(ip, clean_host, rtt).await != ProbeOutcome::ServerResponded {
            continue;
        }
        for &host in BLOCKED_DOMAINS.iter().take(2) {
            d.add(probe_http(ip, host, rtt).await);
        }
    }
    d
}

// ── Test: TCP fragmentation bypass (GoodbyeDPI-style) ───────────────────────
async fn test_tcp_fragmentation_bypass() -> bool {
    let (ip, _, port) = CROSS_SNI_TARGETS[0];
    let rtt = match measure_rtt(ip, port).await {
        Some(r) => r,
        None => return false,
    };
    let baseline = probe_tls(ip, port, BLOCKED_SNIS[0], rtt).await;
    if !is_blocked(&baseline) {
        return false;
    }
    let Ok(addr) = format!("{ip}:{port}").parse::<SocketAddr>() else { return false };
    let mut stream = match protected_tcp_connect(addr, Duration::from_millis(rtt * 5 + 500)).await {
        Ok(s) => s,
        Err(_) => return false,
    };
    let _ = stream.set_nodelay(true);
    let hello = build_tls_client_hello(BLOCKED_SNIS[0]);
    if hello.len() < 10 {
        return false;
    }
    if stream.write_all(&hello[..5]).await.is_err() {
        return false;
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    if stream.write_all(&hello[5..]).await.is_err() {
        return false;
    }
    let mut buf = [0u8; 128];
    matches!(
        tokio::time::timeout(Duration::from_millis(rtt * 5 + 500), stream.read(&mut buf)).await,
        Ok(Ok(n)) if n > 0
    )
}

// ── Checks with a verdict and, where possible, the censor's position ────────

/// One check for the report: `ok` true = passes, false = interference found,
/// null = could not be tested from here.
#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub id: &'static str,
    pub title: String,
    pub ok: Option<bool>,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locate: Option<Localization>,
}

/// A request every web server answers (400): the benign probe for finding
/// the server's own hop distance.
const BENIGN_HTTP: &[u8] = b"GET / HTTP/1.0\r\n\r\n";

fn junk_payload() -> Vec<u8> {
    (0u64..64)
        .map(|i| i.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407).wrapping_shr(33) as u8)
        .collect()
}

fn window_for(rtt: Option<u64>) -> Duration {
    Duration::from_millis(rtt.map(|r| r * 4).unwrap_or(1200).clamp(700, 2500))
}

fn describe_locate(l: &Localization) -> String {
    match l.verdict {
        "on_path" => format!(
            "a box at hop {}{} answers ({:?}) before the server{}",
            l.reaction_hop.unwrap_or(0),
            l.reaction_hop_address.as_deref().map(|a| format!(" ({a})")).unwrap_or_default(),
            l.reaction.clone().unwrap_or(Reaction::None),
            l.server_hop.map(|h| format!(", which is at hop {h}")).unwrap_or_default()
        ),
        "server" => format!("only the server reacts (hop {}): not interference", l.server_hop.unwrap_or(0)),
        _ => "nothing reacts at any TTL: dropped silently; the position cannot be measured without raw sockets".into(),
    }
}

/// Random bytes on 443 of a clean Russian host. The server answers them
/// (HTTP 400); a whitelist DPI cuts or drops them. A close or reset is only
/// counted when it comes from a hop before the server: the old timing-only
/// test counted the server's own immediate close as censorship.
async fn check_unknown_443() -> Check {
    let (ip, _, port) = CROSS_SNI_TARGETS[0];
    let title = "Unknown protocol on port 443 (vk.com)".to_string();
    let addr: SocketAddr = format!("{ip}:{port}").parse().unwrap();
    let window = window_for(measure_rtt(ip, port).await);
    let junk = junk_payload();
    let first = react(addr, &junk, None, window).await;
    match first {
        Err(e) => Check { id: "unknown_443", title, ok: None, detail: format!("could not connect: {e}"), locate: None },
        Ok((Reaction::Data, _, t)) => Check {
            id: "unknown_443",
            title,
            ok: Some(true),
            detail: format!("the server answered the random bytes in {} ms: unknown data passes", t.as_millis()),
            locate: None,
        },
        Ok((Reaction::None, _, _)) => Check {
            id: "unknown_443",
            title,
            ok: Some(false),
            detail: "no answer to random bytes (this server normally answers them): dropped on the way".into(),
            locate: None,
        },
        Ok(_) => {
            let l = locate(addr, &junk, BENIGN_HTTP, window).await;
            Check {
                id: "unknown_443",
                title,
                ok: Some(l.verdict != "on_path"),
                detail: describe_locate(&l),
                locate: Some(l),
            }
        }
    }
}

/// Where the SNI block sits, when the SNI test found one: the blocked name
/// to a clean Russian IP, against its own name (which the server answers).
async fn check_sni_position() -> Check {
    let (ip, clean, port) = CROSS_SNI_TARGETS[0];
    let addr: SocketAddr = format!("{ip}:{port}").parse().unwrap();
    let window = window_for(measure_rtt(ip, port).await);
    let l = locate(addr, &build_tls_client_hello(BLOCKED_SNIS[0]), &build_tls_client_hello(clean), window).await;
    Check {
        id: "sni_position",
        title: format!("Where the SNI block is ({} to {clean})", BLOCKED_SNIS[0]),
        ok: Some(l.verdict != "on_path"),
        detail: describe_locate(&l),
        locate: Some(l),
    }
}

/// Foreign hosting the way a VPS is used: is the IP reachable at all, and do
/// TLS (with a neutral and with the host's own name) and HTTP get through?
/// On Russian networks the TSPU drops recognised protocols to many foreign
/// hosting ranges while unrecognised bytes pass.
const FOREIGN_HOSTS: &[(&str, &str, &str)] = &[
    ("fsn1-speed.hetzner.com", "78.46.170.2", "Hetzner, Germany"),
    ("proof.ovh.net", "141.95.207.211", "OVH, France"),
];

async fn resolve_v4(name: &str, fallback: &str) -> IpAddr {
    if let Ok(mut it) = tokio::net::lookup_host((name, 443)).await {
        if let Some(a) = it.find(|a| a.is_ipv4()) {
            return a.ip();
        }
    }
    fallback.parse().unwrap()
}

/// The check and whether a TCP connection to the host could be opened at all.
async fn check_foreign(name: &'static str, fallback: &'static str, label: &'static str) -> (Check, bool) {
    let c = check_foreign_inner(name, fallback, label).await;
    let connected = !c.detail.ends_with(FOREIGN_NO_TCP);
    (c, connected)
}

const FOREIGN_NO_TCP: &str = "TCP connect failed";

async fn check_foreign_inner(name: &'static str, fallback: &'static str, label: &'static str) -> Check {
    let ip = resolve_v4(name, fallback).await;
    let tls: SocketAddr = (ip, 443).into();
    let window = window_for(measure_rtt(&ip.to_string(), 443).await);
    let title = format!("Foreign hosting: {label}");
    let junk = junk_payload();
    let raw = react(tls, &junk, None, window).await;
    let Ok((raw_r, _, _)) = raw else {
        return Check { id: "foreign", title, ok: None, detail: format!("{ip}: {FOREIGN_NO_TCP}"), locate: None };
    };
    if raw_r == Reaction::None {
        return Check { id: "foreign", title, ok: Some(false), detail: format!("{ip}: nothing gets an answer, even raw bytes"), locate: None };
    }
    let neutral = react(tls, &build_tls_client_hello("example.com"), None, window).await.map(|r| r.0).unwrap_or(Reaction::None);
    let own = react(tls, &build_tls_client_hello(name), None, window).await.map(|r| r.0).unwrap_or(Reaction::None);
    let http_req = format!("GET / HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n\r\n");
    let http = react((ip, 80).into(), http_req.as_bytes(), None, window).await.map(|r| r.0).unwrap_or(Reaction::None);
    let word = |r: &Reaction| match r {
        Reaction::Data => "answered",
        Reaction::None => "dropped",
        Reaction::Rst => "reset",
        Reaction::Fin => "closed",
    };
    let detail = format!(
        "{ip}: raw bytes {} · TLS with SNI example.com {} · TLS with SNI {name} {} · HTTP {}",
        word(&raw_r),
        word(&neutral),
        word(&own),
        word(&http)
    );
    let blocked = [&neutral, &own, &http].iter().any(|r| **r != Reaction::Data);
    // An injected reset can be placed; a silent drop cannot.
    let locate = if own == Reaction::Rst || own == Reaction::Fin {
        Some(locate(tls, &build_tls_client_hello(name), &junk, window).await)
    } else {
        None
    };
    let detail = match (&locate, blocked) {
        (Some(l), _) => format!("{detail}. {}", describe_locate(l)),
        (None, true) => format!("{detail}. Recognised protocols are filtered while raw bytes pass: content filtering toward this hosting"),
        (None, false) => detail,
    };
    Check { id: "foreign", title, ok: Some(!blocked), detail, locate }
}

/// The TSPU "freeze": TLS to foreign hosting stalls after roughly 16 KB.
/// Downloads 128 KB over real TLS from OVH.
async fn check_freeze() -> Check {
    let (name, fallback, _) = FOREIGN_HOSTS[1];
    let title = "Download over TLS from abroad (freeze after ~16 KB)".to_string();
    let ip = resolve_v4(name, fallback).await;
    let want: usize = 128 * 1024;
    let run = async {
        let tcp = protected_tcp_connect((ip, 443).into(), Duration::from_secs(5)).await?;
        let opts = crate::transport::TlsClientOptions { sni: name.to_string(), insecure: true };
        let mut tls = crate::transport::tls::wrap_tls(tcp, &opts, Duration::from_secs(6)).await?;
        let req = format!(
            "GET /files/1Mb.dat HTTP/1.1\r\nHost: {name}\r\nRange: bytes=0-{}\r\nUser-Agent: ostp-prober\r\nConnection: close\r\n\r\n",
            want - 1
        );
        tls.write_all(req.as_bytes()).await?;
        let started = Instant::now();
        let mut got = 0usize;
        let mut buf = vec![0u8; 16384];
        loop {
            match tokio::time::timeout(Duration::from_secs(5), tls.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) => return anyhow::Ok((got, false, started.elapsed())),
                Ok(Ok(n)) => {
                    got += n;
                    if got >= want {
                        return Ok((got, false, started.elapsed()));
                    }
                }
                Err(_) => return Ok((got, true, started.elapsed())),
            }
        }
    };
    match run.await {
        Err(e) => Check { id: "freeze", title, ok: None, detail: format!("{name}: {e}"), locate: None },
        Ok((got, _, t)) if got >= want => Check {
            id: "freeze",
            title,
            ok: Some(true),
            detail: format!("{name}: 128 KB in {} ms", t.as_millis()),
            locate: None,
        },
        Ok((got, stalled, _)) => Check {
            id: "freeze",
            title,
            ok: Some(false),
            detail: format!(
                "{name}: {} after {} KB{}",
                if stalled { "stalled" } else { "cut" },
                got / 1024,
                if (8 * 1024..=40 * 1024).contains(&got) { " — the typical TSPU freeze of foreign TLS" } else { "" }
            ),
            locate: None,
        },
    }
}

/// QUIC (HTTP/3) on UDP 443: a long-header packet with an unknown version
/// makes any QUIC server answer with Version Negotiation.
async fn check_quic() -> Check {
    let title = "QUIC (UDP 443)".to_string();
    let targets: [(&str, &str); 2] = [("1.1.1.1", "Cloudflare"), ("8.8.8.8", "Google")];
    let mut answered = Vec::new();
    for (ip, who) in targets {
        let Ok(sock) = protected_udp_socket(false).await else { continue };
        let mut pkt = vec![0xC0u8, 0x1A, 0x2A, 0x3A, 0x4A, 8];
        pkt.extend_from_slice(&rand::random::<[u8; 8]>());
        pkt.push(8);
        pkt.extend_from_slice(&rand::random::<[u8; 8]>());
        while pkt.len() < 1200 {
            pkt.push(rand::random());
        }
        let Ok(dst) = format!("{ip}:443").parse::<SocketAddr>() else { continue };
        if sock.send_to(&pkt, dst).await.is_err() {
            continue;
        }
        let mut buf = [0u8; 1500];
        if let Ok(Ok((n, _))) = tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf)).await {
            // Version Negotiation: long header with version 0.
            if n >= 7 && buf[0] & 0x80 != 0 && buf[1..5] == [0, 0, 0, 0] {
                answered.push(who);
            }
        }
    }
    if answered.is_empty() {
        Check { id: "quic", title, ok: Some(false), detail: "no QUIC server answered (Cloudflare, Google): UDP 443 is blocked".into(), locate: None }
    } else {
        Check { id: "quic", title, ok: Some(true), detail: format!("answered: {}", answered.join(", ")), locate: None }
    }
}

// ── CONNECT to a web server: transparent proxy, hijacked block pages ────────

/// The first bytes a web server (vk.com on port 80) sends back to an HTTP
/// CONNECT for `target`; `None` if nothing came back.
async fn connect_answer(target: &str) -> Option<String> {
    let (ip, _, _) = CROSS_SNI_TARGETS[0];
    let rtt = measure_rtt(ip, 80).await?;
    let addr: SocketAddr = format!("{ip}:80").parse().ok()?;
    let mut stream = protected_tcp_connect(addr, Duration::from_millis(rtt * 4 + 500)).await.ok()?;
    let req = format!("CONNECT {target}:443 HTTP/1.1\r\nHost: {target}:443\r\nProxy-Connection: keep-alive\r\n\r\n");
    stream.write_all(req.as_bytes()).await.ok()?;
    let mut buf = [0u8; 512];
    match tokio::time::timeout(Duration::from_millis(rtt * 4 + 1000), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => Some(String::from_utf8_lossy(&buf[..n]).into_owned()),
        _ => None,
    }
}

/// A web server refuses CONNECT (400 or 405). Agreeing to it (200) or asking
/// for proxy credentials (407) is a proxy in between. `None`: no answer.
/// (A `Via` header used to count as well; a site's own CDN adds one.)
async fn test_transparent_proxy() -> Option<bool> {
    let (_, clean_host, _) = CROSS_SNI_TARGETS[0];
    let resp = connect_answer(clean_host).await?;
    Some(matches!(http_status(resp.lines().next().unwrap_or("")), Some(200) | Some(407)))
}

/// A block page in place of the server's answer: CONNECT to a blocked name
/// gets 403/451 or a page with registry wording while the same CONNECT to a
/// clean name does not. Compared against that baseline, because the server
/// may refuse every CONNECT with a 403 of its own. `None`: no baseline.
async fn test_connect_hijacking() -> Option<bool> {
    let (_, clean_host, _) = CROSS_SNI_TARGETS[0];
    let baseline = connect_answer(clean_host).await?;
    let blocked = connect_answer(BLOCKED_DOMAINS[0]).await?;
    Some(connect_hijacked(&baseline, &blocked))
}

fn connect_hijacked(baseline: &str, blocked: &str) -> bool {
    let status = |r: &str| http_status(r.lines().next().unwrap_or(""));
    let block_page = looks_like_block_page(blocked) && !looks_like_block_page(baseline);
    let block_status = matches!(status(blocked), Some(403) | Some(451)) && status(blocked) != status(baseline);
    block_page || block_status
}

// ── DNS hijack / injection ──────────────────────────────────────────────────

/// A query to 8.8.8.8 answered from another address. `None` in the first
/// place: no answer at all, so nothing was learned. (An interceptor that
/// answers from 8.8.8.8's own address is not seen here; the injection test
/// below catches that kind.)
async fn test_dns_hijacking_detailed() -> (Option<bool>, Option<String>) {
    let Ok(socket) = protected_udp_socket(false).await else { return (None, None) };
    let target: SocketAddr = "8.8.8.8:53".parse().unwrap();
    if socket.send_to(&build_dns_query("google.com"), target).await.is_err() {
        return (None, None);
    }
    let mut buf = [0u8; 512];
    match tokio::time::timeout(Duration::from_millis(3000), socket.recv_from(&mut buf)).await {
        Ok(Ok((_, from))) => {
            let from_ip = from.ip().to_string();
            let hijacked = from_ip != "8.8.8.8";
            (Some(hijacked), hijacked.then_some(from_ip))
        }
        _ => (None, None),
    }
}

async fn dns_query_collect(ip: &str, domain: &str) -> Option<(String, Option<[u8; 4]>)> {
    let socket = protected_udp_socket(false).await.ok()?;
    let target: SocketAddr = format!("{ip}:53").parse().ok()?;
    let id: u16 = 0x33CC;
    let query = build_dns_query_id(id, domain);
    socket.send_to(&query, target).await.ok()?;

    let mut buf = [0u8; 512];
    match tokio::time::timeout(Duration::from_millis(1500), socket.recv_from(&mut buf)).await {
        Ok(Ok((len, from))) if len >= 12 && u16::from_be_bytes([buf[0], buf[1]]) == id && (buf[2] & 0x80) != 0 => {
            Some((from.ip().to_string(), parse_dns_a_record(&buf[..len])))
        }
        _ => None,
    }
}

async fn dns_race_two_answers(resolver_ip: &str, domain: &str) -> Option<String> {
    let socket = protected_udp_socket(false).await.ok()?;
    let target: SocketAddr = format!("{resolver_ip}:53").parse().ok()?;
    let id: u16 = 0x55AA;
    let query = build_dns_query_id(id, domain);
    socket.send_to(&query, target).await.ok()?;

    let deadline = Instant::now() + Duration::from_millis(1500);
    let mut seen: Vec<[u8; 4]> = Vec::new();
    let mut buf = [0u8; 512];
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, _))) if len >= 12 && u16::from_be_bytes([buf[0], buf[1]]) == id => {
                if let Some(a) = parse_dns_a_record(&buf[..len]) {
                    if !seen.contains(&a) {
                        seen.push(a);
                    }
                }
            }
            _ => break,
        }
    }

    if seen.len() >= 2 {
        let fmt = |a: &[u8; 4]| format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3]);
        Some(format!(
            "two different A records for one query ({}, {}): a forged answer raced the real one",
            fmt(&seen[0]),
            fmt(&seen[1])
        ))
    } else {
        None
    }
}

/// Method A: query a BLOCKED domain against a host that is NOT a DNS server
/// (the VK web IP on :53). No legitimate answer can physically arrive — any
/// reply is a middlebox forging one. Method B: race two answers from a real
/// resolver — two different A records under the same query ID means an
/// injected reply beat the genuine one.
async fn test_dns_injection() -> (bool, Option<String>) {
    let dead_host = CROSS_SNI_TARGETS[0].0;
    for domain in BLOCKED_DOMAINS.iter().take(2) {
        if let Some((from_ip, a_rec)) = dns_query_collect(dead_host, domain).await {
            let a = a_rec.map(|i| format!("{}.{}.{}.{}", i[0], i[1], i[2], i[3])).unwrap_or_else(|| "no A record".into());
            return (true, Some(format!("{domain}: an answer came from {from_ip} ({a}) though that host runs no DNS server: forged on the way")));
        }
    }
    for domain in BLOCKED_DOMAINS.iter().take(2) {
        if let Some(detail) = dns_race_two_answers("8.8.8.8", domain).await {
            return (true, Some(format!("{domain}: {detail}")));
        }
    }
    (false, None)
}

// ── DNS server reachability/interception table ──────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct DnsServerStatus {
    pub server: String,
    pub reachable: bool,
    pub rtt_ms: u64,
    pub actual_responder: Option<String>,
    pub intercepted: bool,
}

async fn test_system_dns_servers() -> Vec<DnsServerStatus> {
    let servers: &[(&str, &str)] = &[
        ("8.8.8.8:53", "8.8.8.8"),
        ("1.1.1.1:53", "1.1.1.1"),
        ("9.9.9.9:53", "9.9.9.9"),
        ("77.88.8.8:53", "77.88.8.8"),
        ("94.140.14.14:53", "94.140.14.14"),
    ];

    let mut results = Vec::new();
    let test_domain = "google.com";

    for (server_addr, expected_ip) in servers {
        let Ok(socket) = protected_udp_socket(false).await else { continue };
        let Ok(target) = server_addr.parse::<SocketAddr>() else { continue };
        let query = build_dns_query(test_domain);
        let t = Instant::now();

        if socket.send_to(&query, target).await.is_err() {
            results.push(DnsServerStatus { server: server_addr.to_string(), reachable: false, rtt_ms: 0, actual_responder: None, intercepted: false });
            continue;
        }

        let mut buf = [0u8; 512];
        match tokio::time::timeout(Duration::from_millis(2000), socket.recv_from(&mut buf)).await {
            Ok(Ok((_, from))) => {
                let rtt_ms = t.elapsed().as_millis() as u64;
                let from_ip = from.ip().to_string();
                let intercepted = &from_ip != expected_ip;
                results.push(DnsServerStatus {
                    server: server_addr.to_string(),
                    reachable: true,
                    rtt_ms,
                    actual_responder: if intercepted { Some(from_ip) } else { None },
                    intercepted,
                });
            }
            _ => results.push(DnsServerStatus { server: server_addr.to_string(), reachable: false, rtt_ms: 0, actual_responder: None, intercepted: false }),
        }
    }

    results
}

fn parse_dns_a_record(data: &[u8]) -> Option<[u8; 4]> {
    if data.len() < 12 {
        return None;
    }
    let ancount = u16::from_be_bytes([data[6], data[7]]);
    if ancount == 0 {
        return None;
    }
    let mut pos = 12;
    while pos < data.len() {
        let len = data[pos] as usize;
        if len == 0 { pos += 1; break; }
        if len >= 0xC0 { pos += 2; break; }
        pos += 1 + len;
    }
    if pos + 4 > data.len() {
        return None;
    }
    pos += 4;
    while pos + 10 < data.len() {
        if data[pos] >= 0xC0 {
            pos += 2;
        } else {
            while pos < data.len() && data[pos] != 0 { pos += 1; }
            pos += 1;
        }
        if pos + 10 > data.len() { break; }
        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let rdlen = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10;
        if rtype == 1 && rdlen == 4 && pos + 4 <= data.len() {
            return Some([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        }
        pos += rdlen;
    }
    None
}

fn build_dns_query(name: &str) -> Vec<u8> {
    build_dns_query_id(0xABCD, name)
}

fn build_dns_query_id(id: u16, name: &str) -> Vec<u8> {
    let mut msg = Vec::with_capacity(name.len() + 18);
    msg.extend_from_slice(&id.to_be_bytes());
    msg.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for part in name.split('.') {
        msg.push(part.len() as u8);
        msg.extend_from_slice(part.as_bytes());
    }
    msg.push(0x00);
    msg.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    msg
}

// ── TLS ClientHello builder ───────────────────────────────────────────────────

fn build_tls_client_hello(sni: &str) -> Vec<u8> {
    let sni_bytes = sni.as_bytes();
    let sni_len = sni_bytes.len();
    let mut h = vec![];
    h.push(0x16); h.push(0x03); h.push(0x01);
    let rec_len_pos = h.len(); h.push(0x00); h.push(0x00);
    let hs_start = h.len();
    h.push(0x01);
    let hs_len_pos = h.len(); h.push(0x00); h.push(0x00); h.push(0x00);
    let ch_start = h.len();
    h.push(0x03); h.push(0x03);
    h.extend_from_slice(&[0x5B; 32]);
    h.push(0x00);
    h.extend_from_slice(&[0x00, 0x04, 0x13, 0x01, 0xc0, 0x2b]);
    h.push(0x01); h.push(0x00);
    let ext_len_pos = h.len(); h.push(0x00); h.push(0x00);
    h.push(0x00); h.push(0x00);
    let ext_data_len = (2 + 1 + 2 + sni_len) as u16;
    h.push((ext_data_len >> 8) as u8); h.push((ext_data_len & 0xff) as u8);
    let name_list_len = (1 + 2 + sni_len) as u16;
    h.push((name_list_len >> 8) as u8); h.push((name_list_len & 0xff) as u8);
    h.push(0x00);
    h.push((sni_len >> 8) as u8); h.push((sni_len & 0xff) as u8);
    h.extend_from_slice(sni_bytes);
    h.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);
    h.extend_from_slice(&[0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x1d, 0x00, 0x17]);
    let ext_total = h.len() - ext_len_pos - 2;
    h[ext_len_pos] = (ext_total >> 8) as u8; h[ext_len_pos + 1] = (ext_total & 0xff) as u8;
    let ch_len = h.len() - ch_start;
    h[hs_len_pos + 1] = (ch_len >> 8) as u8; h[hs_len_pos + 2] = (ch_len & 0xff) as u8;
    let rec_len = h.len() - hs_start;
    h[rec_len_pos] = (rec_len >> 8) as u8; h[rec_len_pos + 1] = (rec_len & 0xff) as u8;
    h
}

// ── Orchestrator ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct DpiBatteryReport {
    /// A reset arrived faster than the server could send one, after a
    /// blocked name, or a hop before the server reset the connection.
    pub rst_injection_detected: bool,
    pub http_host_blocked: bool,
    pub sni_blocked: bool,
    pub vulnerable_to_fragmentation: bool,
    pub random_payload_blocked: bool,
    pub dns_hijacked: bool,
    pub dns_hijacker_ip: Option<String>,
    pub dns_injected: bool,
    pub dns_injection_msg: Option<String>,
    pub transparent_proxy_detected: bool,
    pub connect_hijacked: bool,
    pub dns_servers: Vec<DnsServerStatus>,
    /// The most severe finding, 0 (none) to 1 (allowlist); see `assess`.
    pub dpi_score: f32,
    /// One line: the most severe finding.
    pub verdict: String,
    /// What to do about it with OSTP, most important first.
    pub advice: Vec<String>,
    /// Only allowlisted (mostly Russian) addresses are reachable: foreign
    /// hosts refuse even a TCP connection while Russian ones answer. Every
    /// content test below is moot then, and the score is 100%.
    pub whitelist: bool,
    /// Tests that could not compare anything: "sni", "http_host", "rst",
    /// "dns_hijack", "proxy", "connect". Their `false` means "not measured",
    /// not "clean".
    pub unmeasured: Vec<String>,
    /// Checks with a verdict, detail and, where measurable, the censor's hop.
    pub checks: Vec<Check>,
    /// Routers toward a foreign host, hop by hop (ICMP via the system ping):
    /// where the path leaves the provider and where a silent drop can be.
    pub path_target: String,
    pub path: Vec<Hop>,
    /// Where the destination's network begins and who owns the hops before.
    pub path_summary: Option<String>,
}

/// Foreign addresses besides the hosting checks, for telling an allowlist from
/// one unlucky provider: Cloudflare and Google on 443.
const WHITELIST_FOREIGN: &[&str] = &["1.1.1.1:443", "8.8.8.8:443", "9.9.9.9:443"];

/// Whether a TCP connection opens to any of `addrs`.
async fn any_tcp(addrs: &[&str]) -> bool {
    let tries = addrs.iter().filter_map(|a| a.parse::<SocketAddr>().ok()).map(|a| async move {
        protected_tcp_connect(a, Duration::from_secs(4)).await.is_ok()
    });
    futures::future::join_all(tries).await.into_iter().any(|ok| ok)
}

fn whitelist_check(whitelist: bool, ru_rtt: Option<u64>, more_foreign: bool, hosting: bool) -> Check {
    let title = "Allowlist (\"white lists\")".to_string();
    let ru = match ru_rtt {
        Some(ms) => format!("vk.com answers in {ms} ms"),
        None => "vk.com does not answer either".to_string(),
    };
    let (ok, detail) = if whitelist {
        (Some(false), format!(
            "{ru}, but no foreign address accepts even a TCP connection (Hetzner, OVH, Cloudflare, Google, Quad9): \
             only allowlisted addresses are reachable. The content tests below talk to Russian hosts, which the \
             allowlist lets through, so they cannot see it. A VPN works here only through an allowlisted address"
        ))
    } else if ru_rtt.is_none() {
        (None, "Russian hosts do not answer: no network, or everything is blocked".to_string())
    } else if !hosting && more_foreign {
        (None, format!("{ru}; the hosting checks get no TCP, but Cloudflare/Google do: foreign hosting is filtered, not everything foreign"))
    } else {
        (Some(true), format!("{ru}, and foreign addresses accept TCP"))
    };
    Check { id: "whitelist", title, ok, detail, locate: None }
}

/// What the battery found, for `assess`.
#[derive(Debug, Default, Clone, Copy)]
struct Findings {
    whitelist: bool,
    /// A foreign hosting address refuses even TCP (and it is not an allowlist).
    hosting_unreachable: bool,
    /// Random bytes on 443 to a clean Russian host are dropped or cut on the way.
    random_dropped: bool,
    /// TLS or HTTP to foreign hosting is filtered while TCP connects.
    foreign_filtered: bool,
    /// TLS from abroad stalls or is cut (the ~16 KB freeze).
    frozen: bool,
    sni_or_host: bool,
    dns_tampered: bool,
    quic_blocked: bool,
    connect_hijacked: bool,
    transparent_proxy: bool,
}

/// Severity of the worst finding (0 none .. 1 allowlist), a one-line verdict
/// and advice for OSTP.
///
/// The score is the level of the most severe finding, not a sum: the old
/// sum of hand-picked weights (with a "below 0.4" special case) gave numbers
/// nobody could interpret, and two harmless findings outweighed a serious one.
/// Levels, by what they do to a VPN:
/// 1.0 allowlist · 0.9 foreign hosting unreachable · 0.8 unknown data dropped
/// · 0.6 TLS/HTTP abroad filtered or frozen · 0.5 blocking by site name
/// · 0.3 DNS tampering, QUIC blocked, CONNECT hijacked · 0.2 transparent proxy.
fn assess(f: &Findings) -> (f32, String, Vec<String>) {
    let levels: [(bool, f32, &str); 10] = [
        (f.whitelist, 1.0, "Allowlist: only allowlisted (mostly Russian) addresses are reachable"),
        (f.hosting_unreachable, 0.9, "Foreign hosting is blocked by address: no TCP connection opens"),
        (f.random_dropped, 0.8, "Unrecognised data is dropped on the way"),
        (f.foreign_filtered, 0.6, "TLS and HTTP to foreign hosting are filtered"),
        (f.frozen, 0.6, "TLS from abroad stalls after the first kilobytes"),
        (f.sni_or_host, 0.5, "Sites are blocked by name (SNI or HTTP Host)"),
        (f.dns_tampered, 0.3, "DNS answers are forged or intercepted"),
        (f.quic_blocked, 0.3, "QUIC (UDP 443) is blocked"),
        (f.connect_hijacked, 0.3, "Block pages are injected in place of real answers"),
        (f.transparent_proxy, 0.2, "A transparent proxy sits on the path"),
    ];
    let (score, verdict) = levels
        .iter()
        .filter(|(hit, _, _)| *hit)
        .map(|(_, level, text)| (*level, text.to_string()))
        .fold((0.0f32, "No filtering found".to_string()), |best, cur| if cur.0 > best.0 { cur } else { best });

    let mut advice = Vec::new();
    if f.whitelist {
        advice.push("A server abroad cannot be reached directly from this network. Put a relay on an allowlisted address (a Russian VPS: `ostp init relay`) in front of it.".into());
    } else if f.hosting_unreachable {
        advice.push("A server at a blocked hoster is unreachable from here. Use a hoster this network reaches, or a relay on an address it allows.".into());
    }
    if f.random_dropped && !f.whitelist {
        advice.push("OSTP over UDP and plain TCP (UoT) look like random data, which this network drops: use the TLS transport with your domain.".into());
    } else if (f.foreign_filtered || f.frozen) && !f.whitelist && !f.hosting_unreachable {
        advice.push("Recognised protocols to foreign servers are filtered while random data passes: OSTP over UDP or UoT is the carrier to use; TLS may stall here.".into());
    }
    if f.quic_blocked && !f.whitelist {
        advice.push("UDP 443 is blocked: if OSTP over UDP does not connect, switch to UoT or TLS.".into());
    }
    if f.sni_or_host && advice.is_empty() {
        advice.push("Blocking by site name does not affect OSTP: it never sends the names of the sites you open.".into());
    }
    if f.dns_tampered {
        advice.push("Keep DNS inside the tunnel (the default) so forged answers do not reach your apps.".into());
    }
    if advice.is_empty() {
        advice.push("Nothing found here gets in OSTP's way. Whether your own server is reachable is what the server check shows.".into());
    }
    (score, verdict, advice)
}

/// Runs the full battery against fixed, well-known public targets (not the
/// user's ostp server) to characterize what the current network path filters
/// in general. Takes ~10s. Every socket is protected against the VPN tunnel
/// (see module docs), so this is safe to run while connected.
pub async fn run_dpi_battery() -> DpiBatteryReport {
    let (path_target_name, path_fallback, _) = FOREIGN_HOSTS[0];
    let path_ip = resolve_v4(path_target_name, path_fallback).await;
    let (
        sni,
        http,
        unknown_443,
        (dns_hijacked, dns_hijacker_ip),
        (dns_injected, dns_injection_msg),
        transparent_proxy,
        connect_hijacked,
        dns_servers,
        ((foreign_a, foreign_a_tcp), (foreign_b, foreign_b_tcp), more_foreign_tcp, ru_rtt),
        freeze,
        quic,
        path,
    ) = tokio::join!(
        test_differential_sni(),
        test_differential_http_host(),
        check_unknown_443(),
        test_dns_hijacking_detailed(),
        test_dns_injection(),
        test_transparent_proxy(),
        test_connect_hijacking(),
        test_system_dns_servers(),
        async {
            tokio::join!(
                check_foreign(FOREIGN_HOSTS[0].0, FOREIGN_HOSTS[0].1, FOREIGN_HOSTS[0].2),
                check_foreign(FOREIGN_HOSTS[1].0, FOREIGN_HOSTS[1].1, FOREIGN_HOSTS[1].2),
                any_tcp(WHITELIST_FOREIGN),
                measure_rtt(CROSS_SNI_TARGETS[0].0, CROSS_SNI_TARGETS[0].2),
            )
        },
        check_freeze(),
        check_quic(),
        crate::path_probe::path(path_ip, 24),
    );
    let mut path = path;
    crate::path_probe::annotate_owners(&mut path).await;
    let path_summary = crate::path_probe::path_summary(&path);
    let sni_blocked = sni.is_blocked(2);
    let http_host_blocked = http.is_blocked(1);
    let whitelist = !foreign_a_tcp && !foreign_b_tcp && !more_foreign_tcp && ru_rtt.is_some();

    let vulnerable_to_fragmentation = if sni_blocked { test_tcp_fragmentation_bypass().await } else { false };
    let sni_position = if sni_blocked { Some(check_sni_position().await) } else { None };

    let mut checks = vec![unknown_443, foreign_a, foreign_b, freeze, quic];
    if let Some(c) = sni_position {
        checks.insert(0, c);
    }
    checks.insert(0, whitelist_check(whitelist, ru_rtt, more_foreign_tcp, foreign_a_tcp || foreign_b_tcp));

    // Forged resets: a blocked name reset faster than the server could, or a
    // hop before the server resetting a connection (placed by TTL).
    let reset_on_path = checks.iter().filter_map(|c| c.locate.as_ref()).any(|l| {
        l.verdict == "on_path" && matches!(l.reaction, Some(Reaction::Rst) | Some(Reaction::Fin))
    });
    let located = checks.iter().any(|c| c.locate.is_some());
    let rst_injection = reset_on_path || (sni_blocked && sni.forged_resets > 0) || (http_host_blocked && http.forged_resets > 0);
    let rst_measured = rst_injection || sni.measured(2) || http.measured(1) || located;

    let mut unmeasured = Vec::new();
    for (id, measured) in [
        ("sni", sni.measured(2)),
        ("http_host", http.measured(1)),
        ("rst", rst_measured),
        ("dns_hijack", dns_hijacked.is_some()),
        ("proxy", transparent_proxy.is_some()),
        ("connect", connect_hijacked.is_some()),
    ] {
        if !measured {
            unmeasured.push(id.to_string());
        }
    }

    let check_failed = |id: &str| checks.iter().any(|c| c.id == id && c.ok == Some(false));
    let findings = Findings {
        whitelist,
        hosting_unreachable: !whitelist && (!foreign_a_tcp || !foreign_b_tcp),
        random_dropped: check_failed("unknown_443"),
        foreign_filtered: check_failed("foreign"),
        frozen: check_failed("freeze"),
        sni_or_host: sni_blocked || http_host_blocked,
        dns_tampered: dns_hijacked == Some(true) || dns_injected,
        quic_blocked: check_failed("quic"),
        connect_hijacked: connect_hijacked == Some(true),
        transparent_proxy: transparent_proxy == Some(true),
    };
    let (score, verdict, advice) = assess(&findings);
    let random_payload_blocked = findings.random_dropped;

    DpiBatteryReport {
        rst_injection_detected: rst_injection,
        http_host_blocked,
        sni_blocked,
        vulnerable_to_fragmentation,
        random_payload_blocked,
        dns_hijacked: dns_hijacked == Some(true),
        dns_hijacker_ip,
        dns_injected,
        dns_injection_msg,
        transparent_proxy_detected: findings.transparent_proxy,
        connect_hijacked: findings.connect_hijacked,
        dns_servers,
        dpi_score: score,
        verdict,
        advice,
        whitelist,
        unmeasured,
        checks,
        path_target: format!("{path_target_name} ({path_ip})"),
        path,
        path_summary,
    }
}

#[cfg(test)]
mod whitelist_tests {
    use super::whitelist_check;

    #[test]
    fn allowlist_is_a_failure_not_inconclusive() {
        let c = whitelist_check(true, Some(30), false, false);
        assert_eq!(c.ok, Some(false));
        assert!(c.detail.contains("allowlisted"));
        // Hosting blocked but Cloudflare/Google reachable: not an allowlist.
        assert_eq!(whitelist_check(false, Some(30), true, false).ok, None);
        assert_eq!(whitelist_check(false, Some(30), true, true).ok, Some(true));
        // Nothing answers at all: no verdict.
        assert_eq!(whitelist_check(false, None, false, false).ok, None);
    }
}

#[cfg(test)]
mod assess_tests {
    use super::*;

    #[test]
    fn the_score_is_the_worst_finding_not_a_sum() {
        let minor = Findings { dns_tampered: true, quic_blocked: true, transparent_proxy: true, ..Default::default() };
        assert_eq!(assess(&minor).0, 0.3, "three minor findings stay minor");
        let serious = Findings { random_dropped: true, dns_tampered: true, ..Default::default() };
        let (score, verdict, advice) = assess(&serious);
        assert_eq!(score, 0.8);
        assert!(verdict.contains("Unrecognised data"));
        assert!(advice[0].contains("TLS transport"));
        assert_eq!(assess(&Findings { whitelist: true, ..Default::default() }).0, 1.0);
    }

    #[test]
    fn advice_points_to_the_carrier_that_passes() {
        let (_, _, advice) = assess(&Findings { frozen: true, ..Default::default() });
        assert!(advice.iter().any(|a| a.contains("UDP or UoT")), "{advice:?}");
        let (_, _, advice) = assess(&Findings { whitelist: true, ..Default::default() });
        assert!(advice[0].contains("relay"), "{advice:?}");
        let (score, verdict, advice) = assess(&Findings::default());
        assert_eq!(score, 0.0);
        assert_eq!(verdict, "No filtering found");
        assert_eq!(advice.len(), 1);
    }

    #[test]
    fn a_server_that_refuses_every_connect_is_not_a_hijack() {
        let refused = "HTTP/1.1 403 Forbidden\r\nServer: nginx\r\n\r\n";
        assert!(!connect_hijacked(refused, refused));
        let page = "HTTP/1.1 403 Forbidden\r\n\r\n<html>Доступ ограничен по решению ... eais.rkn.gov.ru</html>";
        assert!(connect_hijacked(refused, page), "same status, but a registry block page");
        assert!(connect_hijacked("HTTP/1.1 400 Bad Request\r\n\r\n", "HTTP/1.1 451 Unavailable\r\n\r\n"));
    }
}
