use anyhow::Result;
use tokio::net::TcpStream;
use tokio::time::Duration;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutboundAction {
    Proxy,
    Direct,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundRule {
    #[serde(default)]
    pub domain_suffix: Vec<String>,
    #[serde(default)]
    pub ip_cidr: Vec<String>,
    #[serde(default)]
    pub protocol: Option<String>,
    pub action: OutboundAction,
    /// Local source IP to egress from when this rule matches. Overrides the
    /// server's global `bind_ip` for this rule only, so different destinations
    /// can leave the machine from different addresses — e.g. one clean IP
    /// direct to a picky site, another via the proxy for everything else. None
    /// falls back to the global `bind_ip`.
    #[serde(default)]
    pub send_from: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundConfig {
    pub enabled: bool,
    pub protocol: String,
    pub address: String,
    pub port: u16,
    /// SOCKS5 credentials for an upstream proxy that requires auth (e.g. a
    /// residential-proxy service). Empty = no-auth SOCKS5.
    pub username: String,
    pub password: String,
    pub rules: Vec<OutboundRule>,
    pub default_action: OutboundAction,
}

// ── Target connection with outbound routing ──────────────────────────────────

pub async fn connect_target(
    target: &str,
    outbound: Option<&OutboundConfig>,
    bind_ip: Option<&str>,
    debug: bool,
) -> Result<TcpStream> {
    let connect_timeout = Duration::from_secs(10);
    if let Some(outbound) = outbound {
        if outbound.enabled {
            let (action, rule_src) = select_outbound_action(target, "tcp", outbound, debug).await;
            // Per-rule source wins; otherwise the server's global bind_ip.
            let eff_bind = rule_src.as_deref().or(bind_ip);
            if action == OutboundAction::Block {
                return Err(anyhow::anyhow!("blocked by outbound rule: {}", target));
            }
            if action == OutboundAction::Proxy {
                let proxy_addr = format!("{}:{}", outbound.address, outbound.port);
                // Case-insensitive: a config saying "SOCKS5" means the same thing
                // as "socks5", and silently treating it as unknown is a trap.
                return match outbound.protocol.to_ascii_lowercase().as_str() {
                    "socks5" => connect_via_socks5(&proxy_addr, target, eff_bind, &outbound.username, &outbound.password).await,
                    "http" => connect_via_http(&proxy_addr, target, eff_bind).await,
                    // FAIL CLOSED. This used to fall through to a direct
                    // connection, so any unrecognised protocol string — a typo,
                    // a case difference, an empty value — silently sent ALL TCP
                    // straight out of the server while the operator believed it
                    // was proxied. Combined with the same bug on the UDP path,
                    // that is how one session ends up presenting two different
                    // exit addresses to the remote site.
                    other => Err(anyhow::anyhow!(
                        "outbound.protocol is \"{other}\", which is not a supported proxy type \
                         (expected \"socks5\" or \"http\"); refusing to connect to {target} \
                         directly, because the rules asked for the proxy"
                    )),
                };
            }
            // action == Direct: egress directly, but still honour this rule's
            // send_from (falling back to the global bind_ip) — that is the whole
            // point of "direct from THIS ip to that destination".
            return connect_direct(target, connect_timeout, eff_bind).await;
        }
    }

    connect_direct(target, connect_timeout, bind_ip).await
}

/// Per-candidate-address connect attempt, tried in turn (see `connect_direct`
/// below). Short enough that a single dead-end address can't eat the whole
/// outer `connect_timeout` budget.
const PER_ADDR_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Resolve `target` ("host:port") and connect to it, trying candidate
/// addresses in turn rather than handing the raw string straight to
/// `TcpStream::connect` (which resolves and tries addresses internally but
/// shares ONE timeout across the whole attempt).
///
/// IPv4 candidates are tried first. Some VPS hosts (observed on a
/// DigitalOcean droplet) assign the machine an IPv6 address that the OS
/// prefers by RFC 6724 ordering but that has no actually-working outbound
/// route - the connect attempt doesn't get refused, it just hangs. With a
/// single shared timeout across all candidates, that one dead IPv6 address
/// eats the entire budget and the working IPv4 candidate is never even
/// attempted: every dual-stack destination (i.e. most popular sites) never
/// loads, while IPv4-only destinations work fine - exactly the "traffic
/// counter moves but sites don't open" symptom this fixes.
async fn connect_tcp_with_bind(addr: std::net::SocketAddr, bind_ip: Option<&str>) -> Result<TcpStream> {
    if let Some(ip_str) = bind_ip {
        let ip: std::net::IpAddr = ip_str.parse().map_err(|e| anyhow::anyhow!("invalid bind_ip: {}", e))?;
        let socket = match addr {
            std::net::SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4()?,
            std::net::SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6()?,
        };
        if (addr.is_ipv4() && ip.is_ipv4()) || (addr.is_ipv6() && ip.is_ipv6()) {
            socket.bind(std::net::SocketAddr::new(ip, 0))?;
        }
        Ok(socket.connect(addr).await?)
    } else {
        Ok(TcpStream::connect(addr).await?)
    }
}

async fn connect_direct(target: &str, connect_timeout: Duration, bind_ip: Option<&str>) -> Result<TcpStream> {
    tokio::time::timeout(connect_timeout, async {
        let mut addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host(target)
            .await
            .map_err(|e| anyhow::anyhow!("dns resolution failed for {}: {}", target, e))?
            .collect();
        if addrs.is_empty() {
            return Err(anyhow::anyhow!("no addresses resolved for {}", target));
        }
        prefer_ipv4_first(&mut addrs);

        let mut last_err = None;
        for addr in addrs {
            match tokio::time::timeout(PER_ADDR_CONNECT_TIMEOUT, connect_tcp_with_bind(addr, bind_ip)).await {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(e)) => last_err = Some(anyhow::anyhow!("{}: {}", addr, e)),
                Err(_) => last_err = Some(anyhow::anyhow!("{}: connect timeout ({}s)", addr, PER_ADDR_CONNECT_TIMEOUT.as_secs())),
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("all candidates failed for {}", target)))
    })
    .await
    .map_err(|_| anyhow::anyhow!("connect timeout ({}s): {}", connect_timeout.as_secs(), target))?
}

/// Stable-sort so IPv4 candidates come before IPv6 ones, without otherwise
/// disturbing the resolver's original ordering within each family.
fn prefer_ipv4_first(addrs: &mut [std::net::SocketAddr]) {
    addrs.sort_by_key(|a| a.is_ipv6());
}

// ── Rule matching ────────────────────────────────────────────────────────────

pub async fn select_outbound_action(
    target: &str,
    protocol: &str,
    outbound: &OutboundConfig,
    debug: bool,
) -> (OutboundAction, Option<String>) {
    let (host, port) = match split_host_port(target) {
        Some(v) => v,
        None => return (outbound.default_action, None),
    };

    // Capture the matched rule's action AND its per-rule source IP together, so
    // the caller egresses from the address that rule asked for.
    let mut matched: Option<(OutboundAction, Option<String>)> = None;
    for rule in &outbound.rules {
        if let Some(ref rule_proto) = rule.protocol {
            if !rule_proto.is_empty() && rule_proto.to_lowercase() != protocol {
                continue;
            }
        }
        let hit = (rule.domain_suffix.is_empty() && rule.ip_cidr.is_empty())
            || match_domain_rule(&host, &rule.domain_suffix)
            || match_ip_rule(&host, port, &rule.ip_cidr).await;
        if hit {
            matched = Some((rule.action, rule.send_from.clone()));
            break;
        }
    }

    let (action, send_from) = matched.unwrap_or((outbound.default_action, None));
    if debug {
        tracing::debug!("Outbound routing: target={target} action={action:?} send_from={send_from:?}");
    }
    (action, send_from)
}

fn match_domain_rule(host: &str, suffixes: &[String]) -> bool {
    if suffixes.is_empty() {
        return false;
    }
    let host = host.trim_end_matches('.').to_lowercase();
    suffixes.iter().any(|suffix| {
        let suffix = suffix.trim().trim_start_matches('.').to_lowercase();
        !suffix.is_empty() && (host == suffix || host.ends_with(&format!(".{suffix}")))
    })
}

async fn match_ip_rule(host: &str, _port: u16, cidrs: &[String]) -> bool {
    if cidrs.is_empty() {
        return false;
    }
    let parsed: Vec<Cidr> = cidrs.iter().filter_map(|c| parse_cidr(c)).collect();
    if parsed.is_empty() {
        return false;
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return parsed.iter().any(|cidr| cidr.contains(&ip));
    }

    false
}

// ── SOCKS5 / HTTP CONNECT upstream proxy ─────────────────────────────────────

/// SOCKS5 method negotiation plus RFC 1929 username/password auth when
/// credentials are supplied. Shared by the TCP-connect and UDP-associate paths
/// so both authenticate identically to an upstream that requires it.
async fn socks5_negotiate_auth<S>(stream: &mut S, username: &str, password: &str) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let use_auth = !username.is_empty();
    if use_auth && (username.len() > 255 || password.len() > 255) {
        anyhow::bail!("SOCKS5 username/password must each be at most 255 bytes");
    }
    // Offer username/password (0x02) alongside no-auth (0x00) when we have
    // credentials, so a residential-proxy service that demands auth is satisfied
    // while a plain proxy still works.
    if use_auth {
        stream.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
    } else {
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
    }
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await?;
    if reply[0] != 0x05 {
        anyhow::bail!("SOCKS5: unexpected version 0x{:02x} in method reply", reply[0]);
    }
    match reply[1] {
        0x00 => {} // no authentication required
        0x02 => {
            let mut auth = vec![0x01u8];
            auth.push(username.len() as u8);
            auth.extend_from_slice(username.as_bytes());
            auth.push(password.len() as u8);
            auth.extend_from_slice(password.as_bytes());
            stream.write_all(&auth).await?;
            let mut ar = [0u8; 2];
            stream.read_exact(&mut ar).await?;
            if ar[1] != 0x00 {
                anyhow::bail!("SOCKS5 username/password auth rejected (status 0x{:02x})", ar[1]);
            }
        }
        0xFF => anyhow::bail!(
            "SOCKS5 proxy rejected all offered auth methods — it likely requires \
             credentials; set outbound.username / outbound.password"
        ),
        other => anyhow::bail!("SOCKS5 proxy chose unsupported auth method 0x{:02x}", other),
    }
    Ok(())
}

async fn connect_via_socks5(
    proxy_addr: &str,
    target: &str,
    bind_ip: Option<&str>,
    username: &str,
    password: &str,
) -> Result<TcpStream> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host(proxy_addr).await?.collect();
    let mut stream = if let Some(addr) = addrs.into_iter().next() {
        connect_tcp_with_bind(addr, bind_ip).await?
    } else {
        anyhow::bail!("could not resolve proxy address");
    };
    socks5_negotiate_auth(&mut stream, username, password).await?;

    let (host, port) = split_host_port(target).ok_or_else(|| anyhow::anyhow!("invalid target"))?;
    let mut req = Vec::new();
    req.extend_from_slice(&[0x05, 0x01, 0x00]);
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(v4) => {
                req.push(0x01);
                req.extend_from_slice(&v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                req.push(0x04);
                req.extend_from_slice(&v6.octets());
            }
        }
    } else {
        req.push(0x03);
        req.push(host.len() as u8);
        req.extend_from_slice(host.as_bytes());
    }
    req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&req).await?;

    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    if header[1] != 0x00 {
        anyhow::bail!("SOCKS5 connect failed: 0x{:02x}", header[1]);
    }

    let addr_len = match header[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            len[0] as usize
        }
        _ => 0,
    };
    if addr_len > 0 {
        let mut skip = vec![0u8; addr_len + 2];
        stream.read_exact(&mut skip).await?;
    }

    Ok(stream)
}

async fn connect_via_http(proxy_addr: &str, target: &str, bind_ip: Option<&str>) -> Result<TcpStream> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host(proxy_addr).await?.collect();
    let mut stream = if let Some(addr) = addrs.into_iter().next() {
        connect_tcp_with_bind(addr, bind_ip).await?
    } else {
        anyhow::bail!("could not resolve proxy address");
    };
    let request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
    stream.write_all(request.as_bytes()).await?;

    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).await?;
    let response = String::from_utf8_lossy(&buf[..n]);
    if !response.starts_with("HTTP/1.1 200") && !response.starts_with("HTTP/1.0 200") {
        anyhow::bail!("HTTP CONNECT failed: {response}");
    }
    Ok(stream)
}

pub enum UdpProxySocket {
    Direct(std::sync::Arc<tokio::net::UdpSocket>),
    Socks5 {
        tcp_keepalive: TcpStream,
        udp_sock: std::sync::Arc<tokio::net::UdpSocket>,
        proxy_bnd_addr: std::net::SocketAddr,
    },
}

impl UdpProxySocket {
    pub async fn send_to(&self, data: &[u8], target: &str) -> Result<usize> {
        match self {
            UdpProxySocket::Direct(sock) => {
                sock.send_to(data, target).await.map_err(Into::into)
            }
            UdpProxySocket::Socks5 { udp_sock, proxy_bnd_addr, .. } => {
                let (host, port) = split_host_port(target).ok_or_else(|| anyhow::anyhow!("invalid target"))?;
                let mut req = Vec::with_capacity(10 + host.len() + data.len());
                req.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV, FRAG
                if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                    match ip {
                        std::net::IpAddr::V4(v4) => {
                            req.push(0x01);
                            req.extend_from_slice(&v4.octets());
                        }
                        std::net::IpAddr::V6(v6) => {
                            req.push(0x04);
                            req.extend_from_slice(&v6.octets());
                        }
                    }
                } else {
                    req.push(0x03);
                    req.push(host.len() as u8);
                    req.extend_from_slice(host.as_bytes());
                }
                req.extend_from_slice(&port.to_be_bytes());
                req.extend_from_slice(data);
                
                udp_sock.send_to(&req, proxy_bnd_addr).await.map_err(Into::into)
            }
        }
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, String)> {
        match self {
            UdpProxySocket::Direct(sock) => {
                let (len, addr) = sock.recv_from(buf).await?;
                Ok((len, addr.to_string()))
            }
            UdpProxySocket::Socks5 { udp_sock, proxy_bnd_addr, .. } => {
                loop {
                    let (len, src) = udp_sock.recv_from(buf).await?;
                    if src != *proxy_bnd_addr {
                        continue; // ignore rogue packets
                    }
                    if len < 10 {
                        continue;
                    }
                    if buf[0] != 0x00 || buf[1] != 0x00 {
                        continue; // Invalid RSV
                    }
                    let frag = buf[2];
                    if frag != 0x00 {
                        continue; // Fragments not supported
                    }
                    let atyp = buf[3];
                    let (addr_str, port, payload_offset) = match atyp {
                        0x01 if len >= 10 => {
                            let ip = std::net::Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
                            let port = u16::from_be_bytes([buf[8], buf[9]]);
                            (ip.to_string(), port, 10)
                        }
                        0x04 if len >= 22 => {
                            let mut ip_bytes = [0u8; 16];
                            ip_bytes.copy_from_slice(&buf[4..20]);
                            let ip = std::net::Ipv6Addr::from(ip_bytes);
                            let port = u16::from_be_bytes([buf[20], buf[21]]);
                            (ip.to_string(), port, 22)
                        }
                        0x03 if len >= 5 => {
                            let domain_len = buf[4] as usize;
                            if len >= 5 + domain_len + 2 {
                                let domain = String::from_utf8_lossy(&buf[5..5 + domain_len]).into_owned();
                                let port = u16::from_be_bytes([buf[5 + domain_len], buf[5 + domain_len + 1]]);
                                (domain, port, 5 + domain_len + 2)
                            } else {
                                continue;
                            }
                        }
                        _ => continue,
                    };
                    
                    let target = format!("{}:{}", addr_str, port);
                    let payload_len = len - payload_offset;
                    // Move payload to start of buffer
                    buf.copy_within(payload_offset..len, 0);
                    return Ok((payload_len, target));
                }
            }
        }
    }
}

pub async fn connect_udp_target(
    target: &str,
    outbound: Option<&OutboundConfig>,
    bind_ip: Option<&str>,
    debug: bool,
    server_udp: std::sync::Arc<tokio::net::UdpSocket>,
) -> Result<UdpProxySocket> {
    if let Some(outbound) = outbound {
        if outbound.enabled {
            let (action, rule_src) = select_outbound_action(target, "udp", outbound, debug).await;
            let eff_bind = rule_src.as_deref().or(bind_ip);
            if action == OutboundAction::Block {
                return Err(anyhow::anyhow!("blocked by outbound udp rule: {}", target));
            }
            if action == OutboundAction::Proxy {
                let proxy_addr = format!("{}:{}", outbound.address, outbound.port);
                if outbound.protocol.eq_ignore_ascii_case("socks5") {
                    return connect_udp_via_socks5(&proxy_addr, server_udp, eff_bind, &outbound.username, &outbound.password).await;
                }
                // FAIL CLOSED. HTTP CONNECT genuinely cannot carry UDP — but the
                // answer to that is not to send the datagrams in the clear. The
                // previous "fallback to direct" honoured a Proxy rule by
                // egressing from the server's own address, so with an HTTP
                // upstream every UDP flow (QUIC, DNS) leaked while TCP stayed
                // proxied, presenting two exit IPs to the same remote site.
                return Err(anyhow::anyhow!(
                    "outbound rules route UDP to {target} through the proxy, but the upstream \
                     protocol is \"{}\", which cannot carry UDP. Refusing to send directly. \
                     Use a socks5 upstream, or add an explicit udp rule with action \"direct\" \
                     or \"block\" so the intent is recorded in the config.",
                    outbound.protocol
                ));
            }
        }
    }
    Ok(UdpProxySocket::Direct(server_udp))
}

pub async fn connect_udp_via_socks5(
    proxy_addr: &str,
    server_udp: std::sync::Arc<tokio::net::UdpSocket>,
    bind_ip: Option<&str>,
    username: &str,
    password: &str,
) -> Result<UdpProxySocket> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host(proxy_addr).await?.collect();
    let mut stream = if let Some(addr) = addrs.into_iter().next() {
        connect_tcp_with_bind(addr, bind_ip).await?
    } else {
        anyhow::bail!("could not resolve proxy address");
    };
    socks5_negotiate_auth(&mut stream, username, password).await?;

    // Send UDP Associate request
    let local_addr = server_udp.local_addr()?;
    let mut req = vec![0x05, 0x03, 0x00];
    match local_addr.ip() {
        std::net::IpAddr::V4(v4) => {
            req.push(0x01);
            req.extend_from_slice(&v4.octets());
        }
        std::net::IpAddr::V6(v6) => {
            req.push(0x04);
            req.extend_from_slice(&v6.octets());
        }
    }
    req.extend_from_slice(&local_addr.port().to_be_bytes());
    stream.write_all(&req).await?;

    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    if header[1] != 0x00 {
        anyhow::bail!("SOCKS5 UDP associate failed: 0x{:02x}", header[1]);
    }

    let bnd_addr = match header[3] {
        0x01 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            std::net::IpAddr::V4(ip.into())
        }
        0x04 => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await?;
            std::net::IpAddr::V6(ip.into())
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            stream.read_exact(&mut domain).await?;
            let domain_str = String::from_utf8_lossy(&domain);
            // SOCKS5 specifies BND.ADDR. If it's a domain, we must resolve it.
            // Typically proxies return an IP address for BND.ADDR.
            let resolved = tokio::net::lookup_host(format!("{}:0", domain_str))
                .await?
                .next()
                .ok_or_else(|| anyhow::anyhow!("could not resolve proxy BND.ADDR"))?;
            resolved.ip()
        }
        _ => anyhow::bail!("unknown address type in SOCKS5 reply"),
    };

    let mut port_bytes = [0u8; 2];
    stream.read_exact(&mut port_bytes).await?;
    let bnd_port = u16::from_be_bytes(port_bytes);

    let proxy_bnd_addr = std::net::SocketAddr::new(bnd_addr, bnd_port);

    Ok(UdpProxySocket::Socks5 {
        tcp_keepalive: stream,
        udp_sock: server_udp,
        proxy_bnd_addr,
    })
}

// ── CIDR utilities ───────────────────────────────────────────────────────────


enum Cidr {
    V4(u32, u8),
    V6(u128, u8),
}

impl Cidr {
    fn contains(&self, ip: &std::net::IpAddr) -> bool {
        match (self, ip) {
            (Cidr::V4(net, bits), std::net::IpAddr::V4(addr)) => {
                let mask = if *bits == 0 { 0 } else { u32::MAX << (32 - bits) };
                let ip = u32::from_be_bytes(addr.octets());
                (ip & mask) == (*net & mask)
            }
            (Cidr::V6(net, bits), std::net::IpAddr::V6(addr)) => {
                let mask = if *bits == 0 { 0 } else { u128::MAX << (128 - bits) };
                let ip = u128::from_be_bytes(addr.octets());
                (ip & mask) == (*net & mask)
            }
            _ => false,
        }
    }
}

fn parse_cidr(value: &str) -> Option<Cidr> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if let Some((addr_str, bits_str)) = value.split_once('/') {
        let bits: u8 = bits_str.parse().ok()?;
        if let Ok(addr) = addr_str.parse::<std::net::IpAddr>() {
            return match addr {
                std::net::IpAddr::V4(v4) => Some(Cidr::V4(u32::from_be_bytes(v4.octets()), bits.min(32))),
                std::net::IpAddr::V6(v6) => Some(Cidr::V6(u128::from_be_bytes(v6.octets()), bits.min(128))),
            };
        }
    }
    if let Ok(addr) = value.parse::<std::net::IpAddr>() {
        return match addr {
            std::net::IpAddr::V4(v4) => Some(Cidr::V4(u32::from_be_bytes(v4.octets()), 32)),
            std::net::IpAddr::V6(v6) => Some(Cidr::V6(u128::from_be_bytes(v6.octets()), 128)),
        };
    }
    None
}

pub fn split_host_port(target: &str) -> Option<(String, u16)> {
    if let Some((host, port)) = target.rsplit_once(':') {
        if host.starts_with('[') && host.ends_with(']') {
            let host = host.trim_start_matches('[').trim_end_matches(']').to_string();
            let port = port.parse().ok()?;
            return Some((host, port));
        }
        if host.contains(':') {
            return None;
        }
        let port = port.parse().ok()?;
        return Some((host.to_string(), port));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_host_port() {
        assert_eq!(split_host_port("example.com:443"), Some(("example.com".to_string(), 443)));
        assert_eq!(split_host_port("127.0.0.1:80"), Some(("127.0.0.1".to_string(), 80)));
        assert_eq!(split_host_port("[::1]:8080"), Some(("::1".to_string(), 8080)));
        assert_eq!(split_host_port("noport"), None);
        assert_eq!(split_host_port("::1:8080"), None); // ambiguous IPv6 without brackets
    }

    #[test]
    fn test_parse_cidr_v4() {
        let cidr = parse_cidr("10.0.0.0/8").unwrap();
        assert!(cidr.contains(&"10.1.2.3".parse().unwrap()));
        assert!(cidr.contains(&"10.255.255.255".parse().unwrap()));
        assert!(!cidr.contains(&"11.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_parse_cidr_v4_exact() {
        let cidr = parse_cidr("192.168.1.1").unwrap();
        assert!(cidr.contains(&"192.168.1.1".parse().unwrap()));
        assert!(!cidr.contains(&"192.168.1.2".parse().unwrap()));
    }

    #[test]
    fn test_parse_cidr_v6() {
        let cidr = parse_cidr("::1/128").unwrap();
        assert!(cidr.contains(&"::1".parse().unwrap()));
        assert!(!cidr.contains(&"::2".parse().unwrap()));
    }

    #[test]
    fn test_parse_cidr_invalid() {
        assert!(parse_cidr("").is_none());
        assert!(parse_cidr("not-an-ip/24").is_none());
    }

    #[test]
    fn test_match_domain_rule() {
        assert!(match_domain_rule("example.com", &[".example.com".to_string()]));
        assert!(match_domain_rule("sub.example.com", &[".example.com".to_string()]));
        assert!(!match_domain_rule("notexample.com", &[".example.com".to_string()]));
        assert!(match_domain_rule("test.onion", &[".onion".to_string()]));
        assert!(!match_domain_rule("onion.com", &[".onion".to_string()]));
    }

    #[test]
    fn test_match_domain_rule_exact() {
        // Without dot prefix, the rule matches both exact and subdomains
        // because the implementation treats "example.com" as a suffix match
        assert!(match_domain_rule("example.com", &["example.com".to_string()]));
        assert!(match_domain_rule("sub.example.com", &["example.com".to_string()]));
    }

    #[test]
    fn test_match_domain_rule_empty() {
        assert!(!match_domain_rule("example.com", &[]));
    }

    #[test]
    fn test_prefer_ipv4_first_reorders_mixed_list() {
        let v6: std::net::SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let v4: std::net::SocketAddr = "192.0.2.1:443".parse().unwrap();
        let mut addrs = vec![v6, v4];
        prefer_ipv4_first(&mut addrs);
        assert_eq!(addrs, vec![v4, v6], "IPv4 candidate must sort before IPv6");
    }

    #[test]
    fn test_prefer_ipv4_first_preserves_order_within_family() {
        // Two IPv4 addresses: relative order should be untouched (stable sort).
        let a: std::net::SocketAddr = "192.0.2.1:443".parse().unwrap();
        let b: std::net::SocketAddr = "192.0.2.2:443".parse().unwrap();
        let mut addrs = vec![a, b];
        prefer_ipv4_first(&mut addrs);
        assert_eq!(addrs, vec![a, b]);
    }

    #[tokio::test]
    async fn test_connect_direct_succeeds_against_live_listener() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let result = connect_direct(&addr.to_string(), Duration::from_secs(2), None).await;
        assert!(result.is_ok(), "expected connect_direct to reach a live local listener: {:?}", result.err());
    }

    #[tokio::test]
    async fn test_connect_direct_fails_fast_on_refused_port() {
        // Bind and immediately drop to get a port nothing is listening on,
        // so the OS sends RST and the attempt fails well under the timeout.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let start = std::time::Instant::now();
        let result = connect_direct(&addr.to_string(), Duration::from_secs(5), None).await;
        assert!(result.is_err(), "connecting to a closed port should fail");
        assert!(start.elapsed() < Duration::from_secs(4), "a refused connection must not wait out the full timeout");
    }
}
