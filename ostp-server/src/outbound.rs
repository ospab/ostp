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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundConfig {
    pub enabled: bool,
    pub protocol: String,
    pub address: String,
    pub port: u16,
    pub rules: Vec<OutboundRule>,
    pub default_action: OutboundAction,
}

// ── Target connection with outbound routing ──────────────────────────────────

pub async fn connect_target(
    target: &str,
    outbound: Option<&OutboundConfig>,
    debug: bool,
) -> Result<TcpStream> {
    let connect_timeout = Duration::from_secs(10);
    if let Some(outbound) = outbound {
        if outbound.enabled {
            let action = select_outbound_action(target, "tcp", outbound, debug).await;
            if action == OutboundAction::Block {
                return Err(anyhow::anyhow!("blocked by outbound rule: {}", target));
            }
            if action == OutboundAction::Proxy {
                let proxy_addr = format!("{}:{}", outbound.address, outbound.port);
                return match outbound.protocol.as_str() {
                    "socks5" => connect_via_socks5(&proxy_addr, target).await,
                    "http" => connect_via_http(&proxy_addr, target).await,
                    _ => tokio::time::timeout(connect_timeout, TcpStream::connect(target))
                        .await
                        .map_err(|_| anyhow::anyhow!("connect timeout ({}s): {}", connect_timeout.as_secs(), target))?
                        .map_err(Into::into),
                };
            }
        }
    }

    tokio::time::timeout(connect_timeout, TcpStream::connect(target))
        .await
        .map_err(|_| anyhow::anyhow!("connect timeout ({}s): {}", connect_timeout.as_secs(), target))?
        .map_err(Into::into)
}

// ── Rule matching ────────────────────────────────────────────────────────────

pub async fn select_outbound_action(
    target: &str,
    protocol: &str,
    outbound: &OutboundConfig,
    debug: bool,
) -> OutboundAction {
    let (host, port) = match split_host_port(target) {
        Some(v) => v,
        None => return outbound.default_action,
    };

    let mut matched = None;
    for rule in &outbound.rules {
        if let Some(ref rule_proto) = rule.protocol {
            if !rule_proto.is_empty() && rule_proto.to_lowercase() != protocol {
                continue;
            }
        }
        if rule.domain_suffix.is_empty() && rule.ip_cidr.is_empty() {
            // Protocol-only rule match
            matched = Some(rule.action);
            break;
        }
        if match_domain_rule(&host, &rule.domain_suffix) {
            matched = Some(rule.action);
            break;
        }
        if match_ip_rule(&host, port, &rule.ip_cidr).await {
            matched = Some(rule.action);
            break;
        }
    }

    let action = matched.unwrap_or(outbound.default_action);
    if debug {
        tracing::debug!("Outbound routing: target={target} action={action:?}");
    }
    action
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

async fn match_ip_rule(host: &str, port: u16, cidrs: &[String]) -> bool {
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

async fn connect_via_socks5(proxy_addr: &str, target: &str) -> Result<TcpStream> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = TcpStream::connect(proxy_addr).await?;
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await?;
    if reply != [0x05, 0x00] {
        anyhow::bail!("SOCKS5 auth not accepted");
    }

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

async fn connect_via_http(proxy_addr: &str, target: &str) -> Result<TcpStream> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = TcpStream::connect(proxy_addr).await?;
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
    debug: bool,
    server_udp: std::sync::Arc<tokio::net::UdpSocket>,
) -> Result<UdpProxySocket> {
    if let Some(outbound) = outbound {
        if outbound.enabled {
            let action = select_outbound_action(target, "udp", outbound, debug).await;
            if action == OutboundAction::Block {
                return Err(anyhow::anyhow!("blocked by outbound udp rule: {}", target));
            }
            if action == OutboundAction::Proxy {
                let proxy_addr = format!("{}:{}", outbound.address, outbound.port);
                if outbound.protocol == "socks5" {
                    return connect_udp_via_socks5(&proxy_addr, server_udp).await;
                }
                // HTTP CONNECT does not support UDP. Fallback to direct.
            }
        }
    }
    Ok(UdpProxySocket::Direct(server_udp))
}

pub async fn connect_udp_via_socks5(
    proxy_addr: &str,
    server_udp: std::sync::Arc<tokio::net::UdpSocket>,
) -> Result<UdpProxySocket> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = TcpStream::connect(proxy_addr).await?;
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await?;
    if reply != [0x05, 0x00] {
        anyhow::bail!("SOCKS5 auth not accepted");
    }

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
}
