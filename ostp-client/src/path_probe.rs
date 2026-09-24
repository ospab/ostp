//! Probes that go around the VPN tunnel, and finding *where* on the path a
//! censor sits by limiting the TTL of the segment that triggers it.
//!
//! Localization: the TCP handshake is made normally, then only the data
//! segment is sent with IP_TTL = t (its retransmissions keep that TTL). The
//! segment dies at hop t, so whatever reacts to it (RST, FIN, a block page,
//! the server's answer) sits at hop t or closer. The smallest t that gets a
//! reaction is where the reacting box is. The server's own hop distance
//! comes from a harmless request the server always answers; a reaction to
//! the trigger at a smaller TTL than that is an on-path box, not the server.
//!
//! What this cannot do without raw sockets: place a censor that drops
//! silently. A dropped segment and one that expired look the same from
//! here, so for silent drops only the path (router per hop, from ICMP via
//! the system ping) is reported, with the drop somewhere along it.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

/// The deepest hop searched.
pub const MAX_HOPS: u32 = 32;

// ── Sockets that bypass the tunnel ───────────────────────────────────────────

/// A TCP socket that leaves through the physical network even while the
/// ostp tunnel is up: VpnService.protect on Android, the physical interface
/// (IP_UNICAST_IF) on Windows, SO_BINDTODEVICE on Linux when permitted.
pub fn bypass_tcp_socket(v6: bool) -> std::io::Result<TcpSocket> {
    let socket = if v6 { TcpSocket::new_v6()? } else { TcpSocket::new_v4()? };
    #[cfg(target_os = "android")]
    {
        use std::os::unix::io::AsRawFd;
        crate::bridge::protect_socket(socket.as_raw_fd());
    }
    #[cfg(target_os = "windows")]
    if let Some(idx) = crate::tunnel::proxy::get_windows_physical_if_index() {
        let _ = crate::tunnel::proxy::bind_socket_to_interface(&socket, v6, idx);
    }
    #[cfg(target_os = "linux")]
    if let Some(name) = crate::tunnel::proxy::get_linux_physical_if_name() {
        let _ = crate::tunnel::proxy::bind_socket_to_interface(&socket, &name);
    }
    Ok(socket)
}

pub async fn bypass_tcp_connect(addr: SocketAddr, timeout: Duration) -> std::io::Result<TcpStream> {
    // Loopback never goes through the tunnel, and a socket pinned to the
    // physical interface cannot reach it.
    let socket = if addr.ip().is_loopback() {
        if addr.is_ipv6() { TcpSocket::new_v6()? } else { TcpSocket::new_v4()? }
    } else {
        bypass_tcp_socket(addr.is_ipv6())?
    };
    match tokio::time::timeout(timeout, socket.connect(addr)).await {
        Ok(r) => r,
        Err(_) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timed out")),
    }
}

pub async fn bypass_udp_socket(v6: bool) -> std::io::Result<UdpSocket> {
    let domain = if v6 { socket2::Domain::IPV6 } else { socket2::Domain::IPV4 };
    let sock = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    #[cfg(target_os = "android")]
    {
        use std::os::unix::io::AsRawFd;
        crate::bridge::protect_socket(sock.as_raw_fd());
    }
    #[cfg(target_os = "windows")]
    if let Some(idx) = crate::tunnel::proxy::get_windows_physical_if_index() {
        let _ = crate::tunnel::proxy::bind_socket_to_interface(&sock, v6, idx);
    }
    #[cfg(target_os = "linux")]
    if let Some(name) = crate::tunnel::proxy::get_linux_physical_if_name() {
        let _ = crate::tunnel::proxy::bind_socket_to_interface(&sock, &name);
    }
    let bind: SocketAddr = if v6 { "[::]:0".parse().unwrap() } else { "0.0.0.0:0".parse().unwrap() };
    sock.bind(&bind.into())?;
    sock.set_nonblocking(true)?;
    UdpSocket::from_std(sock.into())
}

// ── Reactions ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reaction {
    /// Bytes came back (the first few, for the report).
    Data,
    /// The connection was closed (FIN).
    Fin,
    /// The connection was reset.
    Rst,
    /// Nothing within the window.
    None,
}

/// Connects normally, sends `payload` (with `ttl` on the data segment when
/// set) and reports what came back within `window`, with the first bytes.
pub async fn react(addr: SocketAddr, payload: &[u8], ttl: Option<u32>, window: Duration) -> std::io::Result<(Reaction, Vec<u8>, Duration)> {
    let mut s = bypass_tcp_connect(addr, Duration::from_secs(4)).await?;
    if let Some(t) = ttl {
        s.set_ttl(t)?;
    }
    let started = Instant::now();
    s.write_all(payload).await?;
    let mut buf = [0u8; 256];
    let result = match tokio::time::timeout(window, s.read(&mut buf)).await {
        Ok(Ok(0)) => (Reaction::Fin, Vec::new()),
        Ok(Ok(n)) => (Reaction::Data, buf[..n].to_vec()),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionReset || e.kind() == std::io::ErrorKind::ConnectionAborted => {
            (Reaction::Rst, Vec::new())
        }
        Ok(Err(_)) => (Reaction::Rst, Vec::new()),
        Err(_) => (Reaction::None, Vec::new()),
    };
    Ok((result.0, result.1, started.elapsed()))
}

/// The smallest TTL at which `payload` draws any reaction, with that
/// reaction. Binary search over [1, max] (reactions are monotonic in TTL:
/// once a segment reaches a box, a larger TTL reaches it too), then the
/// boundary is confirmed.
pub async fn first_reacting_ttl(addr: SocketAddr, payload: &[u8], max: u32, window: Duration) -> Option<(u32, Reaction)> {
    let reacts = |t: u32| async move {
        match react(addr, payload, Some(t), window).await {
            Ok((r, _, _)) if r != Reaction::None => Some(r),
            _ => None,
        }
    };
    let top = reacts(max).await?;
    let (mut lo, mut hi, mut hi_reaction) = (1u32, max, top);
    while lo < hi {
        let mid = (lo + hi) / 2;
        match reacts(mid).await {
            Some(r) => {
                hi = mid;
                hi_reaction = r;
            }
            None => lo = mid + 1,
        }
    }
    // Confirm: one below must stay silent (guards against route flaps).
    if hi > 1 && reacts(hi - 1).await.is_some() {
        return None;
    }
    Some((hi, hi_reaction))
}

#[derive(Debug, Clone, Serialize)]
pub struct Localization {
    /// Hop at which the server first answers a harmless request.
    pub server_hop: Option<u32>,
    /// Smallest TTL at which the trigger draws a reaction.
    pub reaction_hop: Option<u32>,
    pub reaction: Option<Reaction>,
    /// Router at `reaction_hop` (ICMP, via the system ping), when it answers.
    pub reaction_hop_address: Option<String>,
    /// "on_path" (a box before the server reacts), "server" (only the server
    /// reacts: not interference), "silent" (the trigger draws nothing at
    /// any TTL: dropped, position unmeasurable without raw sockets).
    pub verdict: &'static str,
}

/// Where does the reaction to `trigger` come from? `benign` must be a request
/// the server itself always answers (it gives the server's hop distance).
pub async fn locate(addr: SocketAddr, trigger: &[u8], benign: &[u8], window: Duration) -> Localization {
    let server = first_reacting_ttl(addr, benign, MAX_HOPS, window).await;
    let reaction = first_reacting_ttl(addr, trigger, server.as_ref().map(|s| s.0).unwrap_or(MAX_HOPS), window).await;
    let verdict = match (&server, &reaction) {
        (_, None) => "silent",
        (Some((sh, _)), Some((rh, _))) if rh < sh => "on_path",
        (None, Some(_)) => "on_path",
        _ => "server",
    };
    let reaction_hop_address = match (&reaction, verdict) {
        (Some((hop, _)), "on_path") => hop_address(addr.ip(), *hop).await.map(|a| a.to_string()),
        _ => None,
    };
    Localization {
        server_hop: server.map(|s| s.0),
        reaction_hop: reaction.as_ref().map(|r| r.0),
        reaction: reaction.map(|r| r.1),
        reaction_hop_address,
        verdict,
    }
}

// ── Path (routers per hop, via the system ping) ──────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct Hop {
    pub ttl: u32,
    /// Router that returned "TTL exceeded" (or the target itself), if any.
    pub address: Option<String>,
    pub is_target: bool,
    /// Network (autonomous system) the router belongs to, from Team Cymru.
    pub asn: Option<u32>,
    pub as_name: Option<String>,
}

/// Source address of the physical network toward `target` (for `ping -S`
/// on Windows, so the ping does not go into the tunnel).
async fn physical_source(target: IpAddr) -> Option<IpAddr> {
    let u = bypass_udp_socket(target.is_ipv6()).await.ok()?;
    u.connect(SocketAddr::new(target, 9)).await.ok()?;
    u.local_addr().ok().map(|a| a.ip())
}

/// The router at hop `ttl` toward `target`, from one TTL-limited ping.
pub async fn hop_address(target: IpAddr, ttl: u32) -> Option<IpAddr> {
    let source = physical_source(target).await;
    tokio::task::spawn_blocking(move || ping_once(target, ttl, source)).await.ok().flatten()
}

fn ping_once(target: IpAddr, ttl: u32, source: Option<IpAddr>) -> Option<IpAddr> {
    let mut cmd = std::process::Command::new("ping");
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        cmd.args(["-n", "1", "-w", "1000", "-i", &ttl.to_string()]);
        if let Some(src) = source {
            cmd.args(["-S", &src.to_string()]);
        }
        if target.is_ipv6() {
            cmd.arg("-6");
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = source;
        cmd.args(["-c", "1", "-W", "1", "-t", &ttl.to_string()]);
    }
    cmd.arg(target.to_string());
    let out = cmd.output().ok()?;
    parse_ping(&String::from_utf8_lossy(&out.stdout), target)
}

/// The address in the first answer line of a ping's output, in any locale:
/// after the header line (which names the target) and before the first
/// blank line that follows an answer (the statistics block).
fn parse_ping(output: &str, target: IpAddr) -> Option<IpAddr> {
    let target_s = target.to_string();
    let mut lines = output.lines().skip_while(|l| !l.contains(&target_s));
    lines.next()?; // header
    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            break;
        }
        let found = line
            .split(|c: char| c.is_whitespace() || matches!(c, ':' | '(' | ')' | ',' | '='))
            .find_map(|tok| tok.parse::<IpAddr>().ok());
        if let Some(ip) = found {
            return Some(ip);
        }
        // IPv6 addresses contain ':' and are split above; try the raw token.
        if let Some(ip) = line.split_whitespace().find_map(|tok| tok.trim_end_matches(':').parse::<IpAddr>().ok()) {
            return Some(ip);
        }
    }
    None
}

/// Routers toward `target`, hop by hop, until the target answers.
pub async fn path(target: IpAddr, max: u32) -> Vec<Hop> {
    let source = physical_source(target).await;
    let mut hops = Vec::new();
    // In batches of 4 to keep it quick without flooding.
    let mut ttl = 1;
    while ttl <= max {
        let batch: Vec<u32> = (ttl..(ttl + 4).min(max + 1)).collect();
        let results = futures_join(batch.iter().map(|&t| {
            tokio::task::spawn_blocking(move || (t, ping_once(target, t, source)))
        }))
        .await;
        let mut reached = false;
        for (t, addr) in results {
            let is_target = addr == Some(target);
            if reached {
                break;
            }
            hops.push(Hop { ttl: t, address: addr.map(|a| a.to_string()), is_target, asn: None, as_name: None });
            reached = is_target;
        }
        if reached {
            break;
        }
        ttl += 4;
    }
    hops
}

// ── Who owns each hop (Team Cymru IP-to-ASN over DNS) ────────────────────────

/// One TXT record, asked over UDP from the physical network.
async fn dns_txt(name: &str) -> Option<String> {
    for server in ["8.8.8.8:53", "1.1.1.1:53"] {
        let Ok(sock) = bypass_udp_socket(false).await else { continue };
        let id: u16 = rand::random();
        let mut q = Vec::with_capacity(64);
        q.extend_from_slice(&id.to_be_bytes());
        q.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.extend_from_slice(&[0x00, 0x00, 0x10, 0x00, 0x01]);
        let Ok(dst) = server.parse::<SocketAddr>() else { continue };
        if sock.send_to(&q, dst).await.is_err() {
            continue;
        }
        let mut buf = [0u8; 1500];
        let Ok(Ok((n, _))) = tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf)).await else { continue };
        if let Some(txt) = parse_txt_answer(&buf[..n], id) {
            return Some(txt);
        }
    }
    None
}

fn skip_name(msg: &[u8], mut i: usize) -> Option<usize> {
    loop {
        let len = *msg.get(i)? as usize;
        if len == 0 {
            return Some(i + 1);
        }
        if len & 0xC0 == 0xC0 {
            return Some(i + 2);
        }
        i += 1 + len;
    }
}

fn parse_txt_answer(msg: &[u8], id: u16) -> Option<String> {
    if msg.len() < 12 || u16::from_be_bytes([msg[0], msg[1]]) != id {
        return None;
    }
    let answers = u16::from_be_bytes([msg[6], msg[7]]);
    let mut i = skip_name(msg, 12)? + 4;
    for _ in 0..answers {
        i = skip_name(msg, i)?;
        let rtype = u16::from_be_bytes([*msg.get(i)?, *msg.get(i + 1)?]);
        let rdlen = u16::from_be_bytes([*msg.get(i + 8)?, *msg.get(i + 9)?]) as usize;
        let rdata = msg.get(i + 10..i + 10 + rdlen)?;
        if rtype == 16 {
            let mut out = String::new();
            let mut j = 0;
            while j < rdata.len() {
                let l = rdata[j] as usize;
                out.push_str(&String::from_utf8_lossy(rdata.get(j + 1..j + 1 + l)?));
                j += 1 + l;
            }
            return Some(out);
        }
        i += 10 + rdlen;
    }
    None
}

fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => !(v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified() || v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64),
        IpAddr::V6(v6) => !(v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xffc0) == 0xfe80),
    }
}

/// (ASN, AS name) of a public IPv4 address.
async fn asn_of(ip: IpAddr) -> Option<(u32, Option<String>)> {
    let IpAddr::V4(v4) = ip else { return None };
    if !is_public(ip) {
        return None;
    }
    let o = v4.octets();
    let origin = dns_txt(&format!("{}.{}.{}.{}.origin.asn.cymru.com", o[3], o[2], o[1], o[0])).await?;
    // "24940 | 213.239.192.0/18 | DE | ripencc | 2003-05-28"
    let asn: u32 = origin.split('|').next()?.split_whitespace().next()?.parse().ok()?;
    // "24940 | DE | ripencc | 2002-06-03 | HETZNER-AS, DE"
    let name = dns_txt(&format!("AS{asn}.asn.cymru.com"))
        .await
        .and_then(|t| t.rsplit('|').next().map(|s| s.trim().to_string()))
        .filter(|s| !s.is_empty());
    Some((asn, name))
}

/// Fills in who owns each hop.
pub async fn annotate_owners(hops: &mut [Hop]) {
    let lookups = hops.iter().map(|h| {
        let ip = h.address.as_deref().and_then(|a| a.parse::<IpAddr>().ok());
        async move {
            match ip {
                Some(ip) => asn_of(ip).await,
                None => None,
            }
        }
    });
    let results = futures::future::join_all(lookups).await;
    for (h, r) in hops.iter_mut().zip(results) {
        if let Some((asn, name)) = r {
            h.asn = Some(asn);
            h.as_name = name;
        }
    }
}

/// Where the destination's own network begins on the path, and who owns the
/// hops before it: a silent drop toward that destination happens there.
pub fn path_summary(hops: &[Hop]) -> Option<String> {
    let target_asn = hops.iter().find(|h| h.is_target)?.asn?;
    let first = hops.iter().find(|h| h.asn == Some(target_asn))?;
    let dest_name = first.as_name.clone().unwrap_or_else(|| format!("AS{target_asn}"));
    let mut before: Vec<String> = Vec::new();
    for h in hops.iter().take_while(|h| h.ttl < first.ttl) {
        if let (Some(asn), name) = (h.asn, &h.as_name) {
            let label = format!("AS{asn} {}", name.clone().unwrap_or_default()).trim().to_string();
            if !before.contains(&label) {
                before.push(label);
            }
        }
    }
    Some(if first.ttl <= 2 {
        format!("the destination network ({dest_name}) begins at hop {}", first.ttl)
    } else {
        format!(
            "the destination network ({dest_name}) begins at hop {}; a drop before it happens on hops 1–{}{}",
            first.ttl,
            first.ttl - 1,
            if before.is_empty() { String::new() } else { format!(": {}", before.join(", ")) }
        )
    })
}

async fn futures_join<I>(handles: I) -> Vec<(u32, Option<IpAddr>)>
where
    I: Iterator<Item = tokio::task::JoinHandle<(u32, Option<IpAddr>)>>,
{
    let mut out = Vec::new();
    for h in handles.collect::<Vec<_>>() {
        if let Ok(v) = h.await {
            out.push(v);
        }
    }
    out.sort_by_key(|v| v.0);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txt_answer_and_summary() {
        // Answer for "<rev>.origin.asn.cymru.com" TXT "24940 | 78.46.0.0/15 | DE".
        let id = 0x1234u16;
        let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        for l in ["x", "cymru", "com"] {
            m.push(l.len() as u8);
            m.extend_from_slice(l.as_bytes());
        }
        m.extend_from_slice(&[0, 0, 16, 0, 1]);
        let txt = b"24940 | 78.46.0.0/15 | DE";
        m.extend_from_slice(&[0xC0, 0x0C, 0, 16, 0, 1, 0, 0, 0, 60, 0, (txt.len() + 1) as u8, txt.len() as u8]);
        m.extend_from_slice(txt);
        assert_eq!(parse_txt_answer(&m, id).as_deref(), Some("24940 | 78.46.0.0/15 | DE"));
        assert_eq!(parse_txt_answer(&m, 0x9999), None);

        let hop = |ttl, asn: Option<u32>, name: Option<&str>, target| Hop {
            ttl,
            address: Some(format!("10.0.0.{ttl}")),
            is_target: target,
            asn,
            as_name: name.map(str::to_string),
        };
        let hops = vec![
            hop(1, None, None, false),
            hop(2, Some(39578), Some("ISP"), false),
            hop(3, Some(39578), Some("ISP"), false),
            hop(4, Some(24940), Some("HETZNER-AS, DE"), false),
            hop(5, Some(24940), Some("HETZNER-AS, DE"), true),
        ];
        let s = path_summary(&hops).unwrap();
        assert!(s.contains("begins at hop 4"), "{s}");
        assert!(s.contains("hops 1–3: AS39578 ISP"), "{s}");
        assert!(!is_public("192.168.1.1".parse().unwrap()));
        assert!(!is_public("100.64.0.1".parse().unwrap()));
        assert!(is_public("78.46.170.2".parse().unwrap()));
    }

    #[test]
    fn ping_output_in_several_locales() {
        let t: IpAddr = "78.46.170.2".parse().unwrap();
        let win_en = "\r\nPinging 78.46.170.2 with 32 bytes of data:\r\nReply from 192.168.88.1: TTL expired in transit.\r\n\r\nPing statistics for 78.46.170.2:\r\n";
        assert_eq!(parse_ping(win_en, t), Some("192.168.88.1".parse().unwrap()));
        let win_ru = "\r\nОбмен пакетами с 78.46.170.2 по с 32 байтами данных:\r\nОтвет от 31.204.180.1: Превышен срок жизни (TTL) при передаче пакета.\r\n\r\nСтатистика Ping для 78.46.170.2:\r\n";
        assert_eq!(parse_ping(win_ru, t), Some("31.204.180.1".parse().unwrap()));
        let reached = "Pinging 78.46.170.2 with 32 bytes of data:\r\nReply from 78.46.170.2: bytes=32 time=53ms TTL=57\r\n\r\n";
        assert_eq!(parse_ping(reached, t), Some(t));
        let timeout = "Pinging 78.46.170.2 with 32 bytes of data:\r\nRequest timed out.\r\n\r\nPing statistics for 78.46.170.2:\r\n";
        assert_eq!(parse_ping(timeout, t), None);
        let linux = "PING 78.46.170.2 (78.46.170.2) 56(84) bytes of data.\nFrom 88.151.88.1 icmp_seq=1 Time to live exceeded\n\n--- 78.46.170.2 ping statistics ---\n";
        assert_eq!(parse_ping(linux, t), Some("88.151.88.1".parse().unwrap()));
        let linux_timeout = "PING 78.46.170.2 (78.46.170.2) 56(84) bytes of data.\n\n--- 78.46.170.2 ping statistics ---\n1 packets transmitted, 0 received\n";
        assert_eq!(parse_ping(linux_timeout, t), None);
    }

    /// A local server that answers everything: the only reaction comes from
    /// the "server" itself, so the verdict must be `server`, and the plain
    /// `react` sees its data.
    #[tokio::test]
    async fn local_server_reacts_as_the_server() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else { break };
                tokio::spawn(async move {
                    let mut b = [0u8; 64];
                    let _ = s.read(&mut b).await;
                    let _ = s.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
                });
            }
        });
        let (r, data, _) = react(addr, b"junk", None, Duration::from_millis(500)).await.unwrap();
        assert_eq!(r, Reaction::Data);
        assert!(data.starts_with(b"HTTP/1.1 400"));
    }
}
