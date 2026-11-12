//! The local SOCKS5 proxy: TCP `CONNECT` and `UDP ASSOCIATE`, no
//! authentication (loopback only, enforced by `WarpConfig::listen_addr`),
//! domain names and IPv4/IPv6 targets. Everything it opens goes into the
//! tunnel and nowhere else: this module has no other way to reach the
//! network than `Tunnel`, which is what makes the proxy fail closed.

use anyhow::{anyhow, bail, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::tunnel::Tunnel;

const VER: u8 = 5;
const CMD_CONNECT: u8 = 1;
const CMD_UDP_ASSOCIATE: u8 = 3;

pub const REP_OK: u8 = 0;
pub const REP_GENERAL: u8 = 1;
pub const REP_NET_UNREACHABLE: u8 = 3;
pub const REP_HOST_UNREACHABLE: u8 = 4;
pub const REP_REFUSED: u8 = 5;
pub const REP_TTL: u8 = 6;
pub const REP_CMD_UNSUPPORTED: u8 = 7;
pub const REP_ATYP_UNSUPPORTED: u8 = 8;

/// How long a client gets to finish the SOCKS5 handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
/// How long a connection through the tunnel gets to be established.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Addr(SocketAddr),
    Domain(String, u16),
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Target::Addr(a) => write!(f, "{a}"),
            Target::Domain(h, p) => write!(f, "{h}:{p}"),
        }
    }
}

/// Reads ATYP, the address and the port.
pub async fn read_target<R: AsyncRead + Unpin>(r: &mut R) -> Result<Target, ProtoError> {
    let atyp = r.read_u8().await.map_err(ProtoError::Io)?;
    match atyp {
        0x01 => {
            let mut b = [0u8; 6];
            r.read_exact(&mut b).await.map_err(ProtoError::Io)?;
            Ok(Target::Addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3])), u16::from_be_bytes([b[4], b[5]]))))
        }
        0x04 => {
            let mut b = [0u8; 18];
            r.read_exact(&mut b).await.map_err(ProtoError::Io)?;
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&b[..16]);
            Ok(Target::Addr(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), u16::from_be_bytes([b[16], b[17]]))))
        }
        0x03 => {
            let len = r.read_u8().await.map_err(ProtoError::Io)? as usize;
            let mut b = vec![0u8; len + 2];
            r.read_exact(&mut b).await.map_err(ProtoError::Io)?;
            let host = domain_from_bytes(&b[..len])?;
            Ok(Target::Domain(host, u16::from_be_bytes([b[len], b[len + 1]])))
        }
        _ => Err(ProtoError::Reply(REP_ATYP_UNSUPPORTED, "unsupported address type")),
    }
}

fn domain_from_bytes(b: &[u8]) -> Result<String, ProtoError> {
    let s = std::str::from_utf8(b).map_err(|_| ProtoError::Reply(REP_GENERAL, "the host name is not text"))?;
    if s.is_empty() || s.bytes().any(|c| c <= b' ' || c == 0x7f) {
        return Err(ProtoError::Reply(REP_GENERAL, "invalid host name"));
    }
    Ok(s.to_string())
}

#[derive(Debug)]
pub enum ProtoError {
    Io(std::io::Error),
    /// Answer the client with this reply code, then close.
    Reply(u8, &'static str),
}

impl std::fmt::Display for ProtoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtoError::Io(e) => write!(f, "{e}"),
            ProtoError::Reply(_, m) => write!(f, "{m}"),
        }
    }
}

pub fn encode_addr(out: &mut Vec<u8>, a: &SocketAddr) {
    match a.ip() {
        IpAddr::V4(v4) => {
            out.push(0x01);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(0x04);
            out.extend_from_slice(&v6.octets());
        }
    }
    out.extend_from_slice(&a.port().to_be_bytes());
}

pub fn reply_bytes(rep: u8, bnd: Option<SocketAddr>) -> Vec<u8> {
    let mut v = vec![VER, rep, 0x00];
    encode_addr(&mut v, &bnd.unwrap_or_else(|| SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)));
    v
}

/// A UDP request header and payload as a client sends them to the relay.
pub fn parse_udp_datagram(buf: &[u8]) -> Result<(Target, &[u8])> {
    if buf.len() < 4 || buf[0] != 0 || buf[1] != 0 {
        bail!("not a SOCKS5 UDP datagram");
    }
    if buf[2] != 0 {
        bail!("fragmented SOCKS5 UDP datagrams are not supported");
    }
    let (target, off) = match buf[3] {
        0x01 if buf.len() >= 10 => (
            Target::Addr(SocketAddr::new(Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]).into(), u16::from_be_bytes([buf[8], buf[9]]))),
            10,
        ),
        0x04 if buf.len() >= 22 => {
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&buf[4..20]);
            (Target::Addr(SocketAddr::new(Ipv6Addr::from(ip).into(), u16::from_be_bytes([buf[20], buf[21]]))), 22)
        }
        0x03 if buf.len() >= 5 && buf.len() >= 5 + buf[4] as usize + 2 => {
            let n = buf[4] as usize;
            let host = domain_from_bytes(&buf[5..5 + n]).map_err(|e| anyhow!("{e}"))?;
            (Target::Domain(host, u16::from_be_bytes([buf[5 + n], buf[6 + n]])), 7 + n)
        }
        _ => bail!("a SOCKS5 UDP datagram of an unknown or short address type"),
    };
    Ok((target, &buf[off..]))
}

pub fn encode_udp_datagram(from: &SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0, 0, 0];
    encode_addr(&mut v, from);
    v.extend_from_slice(payload);
    v
}

/// Reads the greeting and the request. Answers nothing.
pub async fn read_request<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S) -> Result<(u8, Target), ProtoError> {
    let mut head = [0u8; 2];
    s.read_exact(&mut head).await.map_err(ProtoError::Io)?;
    if head[0] != VER {
        return Err(ProtoError::Reply(REP_GENERAL, "not SOCKS5"));
    }
    let mut methods = vec![0u8; head[1] as usize];
    s.read_exact(&mut methods).await.map_err(ProtoError::Io)?;
    if !methods.contains(&0x00) {
        s.write_all(&[VER, 0xFF]).await.map_err(ProtoError::Io)?;
        return Err(ProtoError::Reply(REP_GENERAL, "the client offers no usable authentication method (this proxy takes none)"));
    }
    s.write_all(&[VER, 0x00]).await.map_err(ProtoError::Io)?;
    let mut req = [0u8; 3];
    s.read_exact(&mut req).await.map_err(ProtoError::Io)?;
    if req[0] != VER {
        return Err(ProtoError::Reply(REP_GENERAL, "not SOCKS5"));
    }
    let target = read_target(s).await?;
    Ok((req[1], target))
}

/// Maps a connection failure to the reply code a client understands.
pub fn reply_for_error(e: &anyhow::Error) -> u8 {
    let m = e.to_string().to_ascii_lowercase();
    if m.contains("refused") || m.contains("reset") {
        REP_REFUSED
    } else if m.contains("timed out") || m.contains("timeout") {
        REP_TTL
    } else if m.contains("no address") || m.contains("resolve") || m.contains("nxdomain") {
        REP_HOST_UNREACHABLE
    } else if m.contains("tunnel is down") {
        REP_NET_UNREACHABLE
    } else {
        REP_GENERAL
    }
}

/// Serves the proxy until the listener fails.
pub async fn serve(listener: TcpListener, tunnel: Tunnel) {
    let local = listener.local_addr().ok();
    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                // Out of descriptors, say: retrying at once is a busy loop.
                tracing::warn!("warp socks: accept: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let tunnel = tunnel.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(sock, tunnel, local).await {
                tracing::debug!("warp socks {peer}: {e}");
            }
        });
    }
}

async fn handle(mut sock: TcpStream, tunnel: Tunnel, local: Option<SocketAddr>) -> Result<()> {
    let _ = sock.set_nodelay(true);
    let (cmd, target) = match tokio::time::timeout(HANDSHAKE_TIMEOUT, read_request(&mut sock)).await {
        Err(_) => bail!("handshake timed out"),
        Ok(Ok(x)) => x,
        Ok(Err(ProtoError::Reply(rep, msg))) => {
            let _ = sock.write_all(&reply_bytes(rep, None)).await;
            bail!("{msg}");
        }
        Ok(Err(ProtoError::Io(e))) => return Err(e.into()),
    };
    match cmd {
        CMD_CONNECT => connect(sock, tunnel, target).await,
        CMD_UDP_ASSOCIATE => udp_associate(sock, tunnel, target, local).await,
        _ => {
            let _ = sock.write_all(&reply_bytes(REP_CMD_UNSUPPORTED, None)).await;
            bail!("command {cmd} is not supported")
        }
    }
}

/// Addresses to try for a target, resolved inside the tunnel.
async fn addresses(tunnel: &Tunnel, target: &Target) -> Result<Vec<SocketAddr>> {
    match target {
        Target::Addr(a) => Ok(vec![*a]),
        Target::Domain(h, p) => {
            let ips = tunnel.resolve(h).await?;
            Ok(ips.into_iter().map(|ip| SocketAddr::new(ip, *p)).collect())
        }
    }
}

async fn connect(mut sock: TcpStream, tunnel: Tunnel, target: Target) -> Result<()> {
    let attempt = async {
        let addrs = addresses(&tunnel, &target).await?;
        let mut last = anyhow!("no address for {target}");
        for a in addrs.into_iter().take(4) {
            match tunnel.connect_tcp(a).await {
                Ok(s) => return Ok(s),
                Err(e) => last = e,
            }
        }
        Err(last)
    };
    let upstream = match tokio::time::timeout(CONNECT_TIMEOUT + Duration::from_secs(5), attempt).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            let _ = sock.write_all(&reply_bytes(reply_for_error(&e), None)).await;
            bail!("connect {target}: {e}");
        }
        Err(_) => {
            let _ = sock.write_all(&reply_bytes(REP_TTL, None)).await;
            bail!("connect {target}: timed out");
        }
    };
    sock.write_all(&reply_bytes(REP_OK, None)).await?;
    let (mut a, mut b) = (sock, upstream);
    // An error here is a connection that ended badly, nothing more.
    let _ = tokio::io::copy_bidirectional(&mut a, &mut b).await;
    Ok(())
}

async fn udp_associate(mut ctl: TcpStream, tunnel: Tunnel, hint: Target, local: Option<SocketAddr>) -> Result<()> {
    let ip = local.map(|l| l.ip()).unwrap_or(Ipv4Addr::LOCALHOST.into());
    let relay = match UdpSocket::bind(SocketAddr::new(ip, 0)).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            let _ = ctl.write_all(&reply_bytes(REP_GENERAL, None)).await;
            bail!("cannot open the UDP relay: {e}");
        }
    };
    let flow = match tunnel.udp_flow().await {
        Ok(f) => f,
        Err(e) => {
            let _ = ctl.write_all(&reply_bytes(reply_for_error(&e), None)).await;
            bail!("udp associate: {e}");
        }
    };
    let bnd = relay.local_addr()?;
    ctl.write_all(&reply_bytes(REP_OK, Some(bnd))).await?;
    // RFC 1928: the request names where the client will send from. A port
    // of 0 means it does not know.
    let expected_port = match hint {
        Target::Addr(a) if a.port() != 0 => Some(a.port()),
        _ => None,
    };
    let (flow_tx, mut flow_rx) = flow.split();
    let client: Arc<std::sync::Mutex<Option<SocketAddr>>> = Arc::new(std::sync::Mutex::new(None));

    // client -> tunnel
    let up = {
        let relay = relay.clone();
        let client = client.clone();
        let tunnel = tunnel.clone();
        async move {
            let mut buf = vec![0u8; 65_536];
            loop {
                let (n, src) = relay.recv_from(&mut buf).await?;
                if !src.ip().is_loopback() {
                    continue;
                }
                {
                    let mut c = client.lock().unwrap_or_else(|e| e.into_inner());
                    match *c {
                        None if expected_port.is_none_or(|p| p == src.port()) => *c = Some(src),
                        Some(first) if first == src => {}
                        _ => continue, // somebody else on the machine
                    }
                }
                let Ok((target, payload)) = parse_udp_datagram(&buf[..n]) else { continue };
                if payload.is_empty() {
                    continue;
                }
                let dst = match &target {
                    Target::Addr(a) => *a,
                    Target::Domain(h, p) => match tunnel.resolve(h).await {
                        Ok(ips) if !ips.is_empty() => SocketAddr::new(ips[0], *p),
                        _ => continue,
                    },
                };
                // Gone when the tunnel is down: the datagram is dropped, as
                // UDP allows, never sent another way.
                flow_tx.send_to(dst, payload);
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        }
    };
    // tunnel -> client
    let down = {
        let relay = relay.clone();
        let client = client.clone();
        async move {
            while let Some((from, payload)) = flow_rx.recv().await {
                let Some(c) = *client.lock().unwrap_or_else(|e| e.into_inner()) else { continue };
                let _ = relay.send_to(&encode_udp_datagram(&from, &payload), c).await;
            }
            Ok::<(), anyhow::Error>(())
        }
    };
    // The association lives as long as the control connection.
    let control = async move {
        let mut b = [0u8; 64];
        loop {
            match ctl.read(&mut b).await {
                Ok(0) | Err(_) => return Ok::<(), anyhow::Error>(()),
                Ok(_) => {}
            }
        }
    };
    tokio::select! {
        r = up => r,
        r = down => r,
        r = control => r,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn request(bytes: &[u8]) -> (Result<(u8, Target), ProtoError>, Vec<u8>) {
        let (mut client, mut server) = tokio::io::duplex(1024);
        client.write_all(bytes).await.unwrap();
        let r = read_request(&mut server).await;
        drop(server);
        let mut answered = Vec::new();
        client.read_to_end(&mut answered).await.unwrap();
        (r, answered)
    }

    #[tokio::test]
    async fn connect_to_a_domain_is_read_with_its_name_intact() {
        let mut req = vec![5, 1, 0, 5, 1, 0, 3, 11];
        req.extend_from_slice(b"example.com");
        req.extend_from_slice(&443u16.to_be_bytes());
        let (r, answered) = request(&req).await;
        let (cmd, t) = r.unwrap();
        assert_eq!(cmd, CMD_CONNECT);
        assert_eq!(t, Target::Domain("example.com".into(), 443));
        assert_eq!(answered, vec![5, 0], "no authentication is chosen");
    }

    #[tokio::test]
    async fn connect_to_v4_and_v6_addresses() {
        let (r, _) = request(&[5, 1, 0, 5, 1, 0, 1, 93, 184, 216, 34, 0x01, 0xbb]).await;
        assert_eq!(r.unwrap().1, Target::Addr("93.184.216.34:443".parse().unwrap()));
        let mut v6 = vec![5, 1, 0, 5, 3, 0, 4];
        v6.extend_from_slice(&"2606:4700::1111".parse::<Ipv6Addr>().unwrap().octets());
        v6.extend_from_slice(&53u16.to_be_bytes());
        let (r, _) = request(&v6).await;
        let (cmd, t) = r.unwrap();
        assert_eq!(cmd, CMD_UDP_ASSOCIATE);
        assert_eq!(t, Target::Addr("[2606:4700::1111]:53".parse().unwrap()));
    }

    #[tokio::test]
    async fn a_client_that_wants_authentication_is_refused_with_ff() {
        let (r, answered) = request(&[5, 1, 2]).await;
        assert!(r.is_err());
        assert_eq!(answered, vec![5, 0xFF]);
    }

    #[tokio::test]
    async fn bad_versions_address_types_and_names_are_refused() {
        assert!(request(&[4, 1, 0]).await.0.is_err());
        let (r, _) = request(&[5, 1, 0, 5, 1, 0, 9, 0, 0]).await;
        assert!(matches!(r, Err(ProtoError::Reply(REP_ATYP_UNSUPPORTED, _))));
        let (r, _) = request(&[5, 1, 0, 5, 1, 0, 3, 3, b'a', b' ', b'b', 0, 80]).await;
        assert!(matches!(r, Err(ProtoError::Reply(REP_GENERAL, _))), "a space in a name could split a request elsewhere");
        let (r, _) = request(&[5, 1, 0, 5, 1, 0, 3, 0, 0, 80]).await;
        assert!(r.is_err(), "empty name");
    }

    #[test]
    fn reply_has_the_shape_clients_read() {
        assert_eq!(reply_bytes(REP_OK, None), vec![5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(reply_bytes(REP_REFUSED, Some("127.0.0.1:1080".parse().unwrap())), vec![5, 5, 0, 1, 127, 0, 0, 1, 0x04, 0x38]);
        let v6 = reply_bytes(REP_OK, Some("[::1]:2".parse().unwrap()));
        assert_eq!(v6.len(), 22);
        assert_eq!(v6[3], 4);
    }

    #[test]
    fn udp_datagrams_round_trip_for_all_address_kinds() {
        let a: SocketAddr = "1.1.1.1:53".parse().unwrap();
        let d = encode_udp_datagram(&a, b"hello");
        let (t, p) = parse_udp_datagram(&d).unwrap();
        assert_eq!((t, p), (Target::Addr(a), &b"hello"[..]));
        let a6: SocketAddr = "[2606:4700:4700::1111]:853".parse().unwrap();
        let d = encode_udp_datagram(&a6, b"x");
        assert_eq!(parse_udp_datagram(&d).unwrap().0, Target::Addr(a6));
        // The form outbound.rs sends: a domain name.
        let mut d = vec![0, 0, 0, 3, 7];
        d.extend_from_slice(b"a.b.com");
        d.extend_from_slice(&443u16.to_be_bytes());
        d.extend_from_slice(b"quic");
        let (t, p) = parse_udp_datagram(&d).unwrap();
        assert_eq!(t, Target::Domain("a.b.com".into(), 443));
        assert_eq!(p, b"quic");
    }

    #[test]
    fn broken_udp_datagrams_are_refused() {
        assert!(parse_udp_datagram(&[]).is_err());
        assert!(parse_udp_datagram(&[0, 0, 1, 1, 1, 1, 1, 1, 0, 53]).is_err(), "FRAG != 0");
        assert!(parse_udp_datagram(&[1, 0, 0, 1, 1, 1, 1, 1, 0, 53]).is_err(), "RSV != 0");
        assert!(parse_udp_datagram(&[0, 0, 0, 1, 1, 1, 1]).is_err(), "short v4");
        assert!(parse_udp_datagram(&[0, 0, 0, 3, 9, b'a', 0, 53]).is_err(), "short name");
    }

    #[test]
    fn errors_map_to_the_replies_a_client_can_act_on() {
        assert_eq!(reply_for_error(&anyhow!("connection refused")), REP_REFUSED);
        assert_eq!(reply_for_error(&anyhow!("connect timed out")), REP_TTL);
        assert_eq!(reply_for_error(&anyhow!("cannot resolve x")), REP_HOST_UNREACHABLE);
        assert_eq!(reply_for_error(&anyhow!("WARP tunnel is down")), REP_NET_UNREACHABLE);
        assert_eq!(reply_for_error(&anyhow!("other")), REP_GENERAL);
    }
}
