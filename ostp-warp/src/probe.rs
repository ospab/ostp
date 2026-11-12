//! A small SOCKS5 client for `ostp warp test` and `status`: it checks the
//! running proxy from outside, through the same path the server uses, rather
//! than opening a second WireGuard session with the same keys.

use anyhow::{anyhow, bail, Result};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::dnsq;
use crate::socks::{encode_addr, encode_udp_datagram, parse_udp_datagram, Target};
use crate::trace::{self, Trace};

const STEP: Duration = Duration::from_secs(15);

async fn greet(s: &mut TcpStream) -> Result<()> {
    s.write_all(&[5, 1, 0]).await?;
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await?;
    if r != [5, 0] {
        bail!("the proxy did not accept an unauthenticated session");
    }
    Ok(())
}

async fn read_reply(s: &mut TcpStream) -> Result<Target> {
    let mut h = [0u8; 4];
    s.read_exact(&mut h).await?;
    if h[0] != 5 {
        bail!("not a SOCKS5 answer");
    }
    if h[1] != 0 {
        bail!("the proxy refused: reply code {} ({})", h[1], reply_name(h[1]));
    }
    let t = match h[3] {
        1 => {
            let mut b = [0u8; 6];
            s.read_exact(&mut b).await?;
            Target::Addr(SocketAddr::new(IpAddr::from([b[0], b[1], b[2], b[3]]), u16::from_be_bytes([b[4], b[5]])))
        }
        4 => {
            let mut b = [0u8; 18];
            s.read_exact(&mut b).await?;
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&b[..16]);
            Target::Addr(SocketAddr::new(IpAddr::from(ip), u16::from_be_bytes([b[16], b[17]])))
        }
        _ => bail!("an answer with an address type of {}", h[3]),
    };
    Ok(t)
}

fn reply_name(c: u8) -> &'static str {
    match c {
        1 => "general failure",
        3 => "network unreachable: the tunnel is down",
        4 => "host unreachable: the name did not resolve",
        5 => "connection refused",
        6 => "timed out",
        7 => "command not supported",
        8 => "address type not supported",
        _ => "unknown",
    }
}

/// A TCP connection to `host:port` through the proxy (the name goes to the
/// proxy as a name).
pub async fn connect(proxy: SocketAddr, host: &str, port: u16) -> Result<TcpStream> {
    tokio::time::timeout(STEP, async {
        let mut s = TcpStream::connect(proxy).await.map_err(|e| anyhow!("nothing answers at {proxy}: {e}"))?;
        greet(&mut s).await?;
        let mut req = vec![5, 1, 0];
        match host.parse::<IpAddr>() {
            Ok(ip) => encode_addr(&mut req, &SocketAddr::new(ip, port)),
            Err(_) => {
                req.push(3);
                req.push(host.len() as u8);
                req.extend_from_slice(host.as_bytes());
                req.extend_from_slice(&port.to_be_bytes());
            }
        }
        s.write_all(&req).await?;
        read_reply(&mut s).await?;
        Ok(s)
    })
    .await
    .map_err(|_| anyhow!("the proxy did not answer in {}s", STEP.as_secs()))?
}

/// `warp=` and `ip=` as seen from `www.cloudflare.com`, over TCP through the proxy.
pub async fn trace_via(proxy: SocketAddr) -> Result<Trace> {
    let s = connect(proxy, trace::HOST, 443).await?;
    tokio::time::timeout(STEP, trace::fetch_over(s)).await.map_err(|_| anyhow!("no trace answer in {}s", STEP.as_secs()))?
}

/// A DNS query for `name` sent as a UDP datagram to `server:53` through the
/// proxy (UDP ASSOCIATE). Returns the addresses in the answer.
pub async fn dns_via(proxy: SocketAddr, server: SocketAddr, name: &str) -> Result<Vec<IpAddr>> {
    tokio::time::timeout(STEP, async {
        let mut ctl = TcpStream::connect(proxy).await.map_err(|e| anyhow!("nothing answers at {proxy}: {e}"))?;
        greet(&mut ctl).await?;
        let mut req = vec![5, 3, 0];
        encode_addr(&mut req, &SocketAddr::from(([0, 0, 0, 0], 0)));
        ctl.write_all(&req).await?;
        let Target::Addr(mut bnd) = read_reply(&mut ctl).await? else { bail!("no relay address") };
        if bnd.ip().is_unspecified() {
            bnd.set_ip(proxy.ip());
        }
        let sock = UdpSocket::bind(SocketAddr::new(proxy.ip(), 0)).await?;
        let id = rand::random::<u16>();
        let q = dnsq::build_query(id, name, dnsq::Kind::A)?;
        // UDP is lossy: ask a few times.
        for _ in 0..3 {
            sock.send_to(&encode_udp_datagram(&server, &q), bnd).await?;
            let mut buf = vec![0u8; 2048];
            if let Ok(Ok((n, _))) = tokio::time::timeout(Duration::from_secs(3), sock.recv_from(&mut buf)).await {
                let Ok((_, payload)) = parse_udp_datagram(&buf[..n]) else { continue };
                let a = dnsq::parse_answer(payload)?;
                if a.id != id {
                    continue;
                }
                if a.nxdomain {
                    bail!("the resolver in the tunnel says {name} does not exist");
                }
                return Ok(a.ips);
            }
        }
        bail!("no UDP answer from {server} through the tunnel")
    })
    .await
    .map_err(|_| anyhow!("the UDP test did not finish in {}s", STEP.as_secs()))?
}
