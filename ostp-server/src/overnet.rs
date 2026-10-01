//! overnet on an OSTP server: the `.ov` zone for clients (entry) and clearnet
//! egress for the overnet network (exit).
//!
//! overnet runs as its own process next to the server; the two talk through
//! local proxies only, so neither links the other's code and the OSTP wire
//! protocol is unchanged.
//!
//! - **Entry.** A client connection to `name.ov:port` (proxy mode, the client
//!   passes the name) or to a fake address the server's DNS gave for
//!   `name.ov` (TUN mode) goes to the overnet gateway's SOCKS5 port. Names in
//!   `.ov` never reach the DNS upstreams or the internet: with entry off they
//!   are refused, not leaked.
//! - **Exit.** A SOCKS5 listener on loopback through which the local overnet
//!   node sends its users' clearnet connections. They take the same route as
//!   client traffic (outbound rules, upstream proxy, `bind_ip`, DNS
//!   filtering). Off by default: an exit answers for what leaves it.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use simple_dns::rdata::{RData, A};
use simple_dns::{Packet, PacketFlag, ResourceRecord, CLASS, QTYPE, RCODE, TYPE};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// The `overnet` section of the server config.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OvernetConfig {
    pub enabled: bool,
    /// Clients reach `.ov` through this server.
    pub entry: bool,
    /// SOCKS5 address of the local overnet gateway (`overnet gateway`).
    pub gateway: String,
    /// The local overnet node may send clearnet traffic out through this server.
    pub exit: bool,
    /// Where the exit SOCKS5 listener binds; loopback only.
    pub exit_listen: String,
}

impl Default for OvernetConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            entry: true,
            gateway: "127.0.0.1:9150".into(),
            exit: false,
            exit_listen: "127.0.0.1:9151".into(),
        }
    }
}

/// Fake addresses handed out for `.ov` names in TUN mode: 198.18.0.0/15
/// (RFC 2544 benchmarking), not routed on the internet.
const FAKE_NET: u32 = 0xC612_0000; // 198.18.0.0
const FAKE_SIZE: u32 = 1 << 17;
const FAKE_TTL: u32 = 60;

pub fn is_ov(host: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    h == "ov" || h.ends_with(".ov")
}

fn is_fake(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => u32::from(v4) & !(FAKE_SIZE - 1) == FAKE_NET,
        IpAddr::V6(_) => false,
    }
}

#[derive(Default)]
struct FakePool {
    by_name: HashMap<String, Ipv4Addr>,
    by_ip: HashMap<Ipv4Addr, String>,
    next: u32,
}

impl FakePool {
    fn get(&mut self, name: &str) -> Ipv4Addr {
        if let Some(ip) = self.by_name.get(name) {
            return *ip;
        }
        // .0 and .1 are skipped; when the pool wraps, the oldest mapping at
        // that slot is replaced (128k names before that happens).
        let ip = Ipv4Addr::from(FAKE_NET + 2 + self.next % (FAKE_SIZE - 2));
        self.next = self.next.wrapping_add(1);
        if let Some(old) = self.by_ip.insert(ip, name.to_string()) {
            self.by_name.remove(&old);
        }
        self.by_name.insert(name.to_string(), ip);
        ip
    }
}

pub struct Overnet {
    cfg: OvernetConfig,
    fake: Mutex<FakePool>,
}

/// What the router should do with a client's TCP target.
pub enum Route {
    /// Not overnet's: route as usual.
    Pass,
    /// `name.ov:port`: through the overnet gateway.
    Gateway(String),
}

impl Overnet {
    pub fn new(cfg: OvernetConfig) -> Arc<Self> {
        Arc::new(Self { cfg, fake: Mutex::new(FakePool::default()) })
    }

    pub fn config(&self) -> &OvernetConfig {
        &self.cfg
    }

    fn entry(&self) -> bool {
        self.cfg.enabled && self.cfg.entry
    }

    /// Classifies a client's `host:port` target. Errors when the target is
    /// in `.ov` but entry is off, so it is not tried on the internet.
    pub fn route(&self, target: &str) -> Result<Route> {
        let Some((host, port)) = target.rsplit_once(':') else { return Ok(Route::Pass) };
        let host = host.trim_matches(['[', ']']);
        let name = if is_ov(host) {
            host.trim_end_matches('.').to_ascii_lowercase()
        } else if let Ok(ip) = host.parse::<IpAddr>() {
            if !is_fake(ip) {
                return Ok(Route::Pass);
            }
            let IpAddr::V4(v4) = ip else { return Ok(Route::Pass) };
            match self.fake.lock().unwrap().by_ip.get(&v4) {
                Some(n) => n.clone(),
                None => bail!("{ip} is an overnet address this server did not hand out (or it expired)"),
            }
        } else {
            return Ok(Route::Pass);
        };
        if !self.entry() {
            bail!("{name}: overnet (.ov) is not enabled on this server");
        }
        Ok(Route::Gateway(format!("{name}:{port}")))
    }

    /// Answers a DNS query for a `.ov` name: a fake address with entry on,
    /// NXDOMAIN otherwise. `None` for any other name.
    pub fn answer_dns(&self, query: &[u8]) -> Option<Vec<u8>> {
        let q = Packet::parse(query).ok()?;
        let question = q.questions.first()?;
        let name = question.qname.to_string().trim_end_matches('.').to_ascii_lowercase();
        if !is_ov(&name) {
            return None;
        }
        let mut reply = Packet::new_reply(q.id());
        reply.set_flags(PacketFlag::RECURSION_DESIRED | PacketFlag::RECURSION_AVAILABLE | PacketFlag::AUTHORITATIVE_ANSWER);
        reply.questions.push(question.clone());
        if !self.entry() || name == "ov" {
            *reply.rcode_mut() = RCODE::NameError;
        } else if question.qtype == QTYPE::TYPE(TYPE::A) {
            let ip = self.fake.lock().unwrap().get(&name);
            reply.answers.push(ResourceRecord::new(
                question.qname.clone(),
                CLASS::IN,
                FAKE_TTL,
                RData::A(A::from(ip)),
            ));
        }
        // Other types (AAAA and so on): an empty NOERROR answer, so the
        // client falls back to A.
        reply.build_bytes_vec().ok()
    }
}

/// Is this an address an overnet user must not reach through the exit: the
/// server itself, its tunnel network, private and special ranges.
fn forbidden_for_exit(ip: IpAddr) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    };
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || o[0] == 0
                || (o[0] == 100 && (64..128).contains(&o[1])) // CGNAT
                || is_fake(ip)
                || o[0] >= 240
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // unique local
                || (s[0] & 0xffc0) == 0xfe80 // link local
        }
    }
}

/// Starts the exit listener. Every CONNECT goes through `router` like a
/// client's would, except that `.ov`, the server itself and private
/// networks are refused.
pub async fn spawn_exit(cfg: &OvernetConfig, router: Arc<crate::router::Router>) -> Result<SocketAddr> {
    let bind: SocketAddr = cfg
        .exit_listen
        .parse()
        .map_err(|e| anyhow!("overnet.exit_listen '{}': {e}", cfg.exit_listen))?;
    if !bind.ip().is_loopback() {
        bail!("overnet.exit_listen must be a loopback address, not {bind}: the exit has no authentication");
    }
    let listener = TcpListener::bind(bind).await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = listener.accept().await else { continue };
            let router = router.clone();
            tokio::spawn(async move {
                if let Err(e) = exit_conn(s, router).await {
                    tracing::debug!("overnet exit: {e:#}");
                }
            });
        }
    });
    Ok(addr)
}

/// The target as the exit will dial it: a vetted IP, or the name itself when
/// an outbound proxy does the resolving.
async fn vet_exit_target(host: &str, port: u16, router: &crate::router::Router) -> Result<String> {
    if is_ov(host) {
        bail!("{host}: .ov is not reached through the exit");
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        if forbidden_for_exit(ip) {
            bail!("{ip}: not a public address");
        }
        return Ok(SocketAddr::new(ip, port).to_string());
    }
    if router.resolves_remotely(&format!("{host}:{port}")).await {
        // The upstream proxy resolves and connects on its own machine.
        return Ok(format!("{host}:{port}"));
    }
    // Resolve here and dial the address checked, so a name cannot point the
    // exit at this machine (or flip to it between the check and the connect).
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
    if addrs.is_empty() {
        bail!("{host}: no addresses");
    }
    if let Some(bad) = addrs.iter().find(|a| forbidden_for_exit(a.ip())) {
        bail!("{host} resolves to {}, not a public address", bad.ip());
    }
    let pick = addrs.iter().find(|a| a.is_ipv4()).unwrap_or(&addrs[0]);
    Ok(pick.to_string())
}

async fn exit_conn(mut s: TcpStream, router: Arc<crate::router::Router>) -> Result<()> {
    // Greeting: only "no authentication" (the listener is loopback-only).
    let mut head = [0u8; 2];
    s.read_exact(&mut head).await?;
    if head[0] != 5 {
        bail!("not SOCKS5");
    }
    let mut methods = vec![0u8; head[1] as usize];
    s.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        s.write_all(&[5, 0xff]).await?;
        bail!("client offers no usable auth method");
    }
    s.write_all(&[5, 0]).await?;

    let mut req = [0u8; 4];
    s.read_exact(&mut req).await?;
    if req[1] != 1 {
        reply(&mut s, 7).await?; // command not supported
        bail!("only CONNECT is supported");
    }
    let host = match req[3] {
        1 => {
            let mut b = [0u8; 4];
            s.read_exact(&mut b).await?;
            Ipv4Addr::from(b).to_string()
        }
        4 => {
            let mut b = [0u8; 16];
            s.read_exact(&mut b).await?;
            std::net::Ipv6Addr::from(b).to_string()
        }
        3 => {
            let mut len = [0u8; 1];
            s.read_exact(&mut len).await?;
            let mut b = vec![0u8; len[0] as usize];
            s.read_exact(&mut b).await?;
            String::from_utf8(b)?
        }
        _ => {
            reply(&mut s, 8).await?;
            bail!("bad address type");
        }
    };
    let mut port = [0u8; 2];
    s.read_exact(&mut port).await?;
    let port = u16::from_be_bytes(port);

    let target = match vet_exit_target(&host, port, &router).await {
        Ok(t) => t,
        Err(e) => {
            reply(&mut s, 2).await?; // not allowed by ruleset
            return Err(e);
        }
    };
    let mut up = match router.route_tcp_exit(&target).await {
        Ok(u) => u,
        Err(e) => {
            reply(&mut s, 5).await?; // connection refused
            return Err(e);
        }
    };
    reply(&mut s, 0).await?;
    tokio::io::copy_bidirectional(&mut s, &mut up).await?;
    Ok(())
}

async fn reply(s: &mut TcpStream, code: u8) -> Result<()> {
    s.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn on() -> Arc<Overnet> {
        Overnet::new(OvernetConfig { enabled: true, ..Default::default() })
    }

    fn a_query(name: &str, qtype: TYPE) -> Vec<u8> {
        let mut p = Packet::new_query(7);
        p.questions.push(simple_dns::Question::new(
            simple_dns::Name::new_unchecked(name),
            QTYPE::TYPE(qtype),
            simple_dns::QCLASS::CLASS(CLASS::IN),
            false,
        ));
        p.build_bytes_vec().unwrap()
    }

    fn answer_ip(resp: &[u8]) -> Option<Ipv4Addr> {
        let p = Packet::parse(resp).unwrap();
        p.answers.iter().find_map(|r| match &r.rdata {
            RData::A(a) => Some(Ipv4Addr::from(a.address)),
            _ => None,
        })
    }

    #[test]
    fn ov_names_get_a_fake_address_that_routes_back_to_the_name() {
        let o = on();
        let resp = o.answer_dns(&a_query("Search.OV", TYPE::A)).unwrap();
        let ip = answer_ip(&resp).expect("an A record");
        assert!(is_fake(IpAddr::V4(ip)));
        // Same name, same address.
        assert_eq!(answer_ip(&o.answer_dns(&a_query("search.ov.", TYPE::A)).unwrap()), Some(ip));
        match o.route(&format!("{ip}:80")).unwrap() {
            Route::Gateway(t) => assert_eq!(t, "search.ov:80"),
            Route::Pass => panic!("fake address must go to the gateway"),
        }
        match o.route("mail.search.ov:443").unwrap() {
            Route::Gateway(t) => assert_eq!(t, "mail.search.ov:443"),
            Route::Pass => panic!(),
        }
    }

    #[test]
    fn other_names_and_addresses_are_not_touched() {
        let o = on();
        assert!(o.answer_dns(&a_query("example.com", TYPE::A)).is_none());
        assert!(o.answer_dns(&a_query("example.overnet", TYPE::A)).is_none());
        assert!(matches!(o.route("example.com:443").unwrap(), Route::Pass));
        assert!(matches!(o.route("1.1.1.1:53").unwrap(), Route::Pass));
    }

    #[test]
    fn with_entry_off_ov_is_refused_not_leaked() {
        let o = Overnet::new(OvernetConfig::default()); // enabled: false
        assert!(o.route("search.ov:80").is_err());
        let resp = o.answer_dns(&a_query("search.ov", TYPE::A)).unwrap();
        let p = Packet::parse(&resp).unwrap();
        assert_eq!(p.rcode(), RCODE::NameError);
        assert!(p.answers.is_empty());
        // A fake address nobody handed out is refused too.
        assert!(o.route("198.18.0.9:80").is_err());
    }

    #[test]
    fn aaaa_for_ov_is_empty_so_clients_use_a() {
        let resp = on().answer_dns(&a_query("search.ov", TYPE::AAAA)).unwrap();
        let p = Packet::parse(&resp).unwrap();
        assert_eq!(p.rcode(), RCODE::NoError);
        assert!(p.answers.is_empty());
    }

    #[test]
    fn exit_refuses_the_server_and_private_networks() {
        for ip in ["127.0.0.1", "10.1.0.1", "192.168.1.1", "172.16.0.1", "100.64.0.1", "169.254.1.1",
                   "0.0.0.0", "198.18.0.5", "::1", "fd00::1", "fe80::1", "::ffff:127.0.0.1"] {
            assert!(forbidden_for_exit(ip.parse().unwrap()), "{ip} must be refused");
        }
        for ip in ["1.1.1.1", "93.184.216.34", "2606:4700::1111"] {
            assert!(!forbidden_for_exit(ip.parse().unwrap()), "{ip} is public");
        }
    }

    #[tokio::test]
    async fn exit_listener_must_be_loopback() {
        let router = Arc::new(crate::router::Router::new(
            None, None, crate::dns::DnsServer::new(Default::default(), None), false,
        ));
        let cfg = OvernetConfig { enabled: true, exit: true, exit_listen: "0.0.0.0:0".into(), ..Default::default() };
        assert!(spawn_exit(&cfg, router).await.is_err());
    }

    #[tokio::test]
    async fn exit_refuses_loopback_targets_over_socks() {
        let router = Arc::new(crate::router::Router::new(
            None, None, crate::dns::DnsServer::new(Default::default(), None), false,
        ));
        let cfg = OvernetConfig { enabled: true, exit: true, exit_listen: "127.0.0.1:0".into(), ..Default::default() };
        let addr = spawn_exit(&cfg, router).await.unwrap();
        let mut c = TcpStream::connect(addr).await.unwrap();
        c.write_all(&[5, 1, 0]).await.unwrap();
        let mut g = [0u8; 2];
        c.read_exact(&mut g).await.unwrap();
        assert_eq!(g, [5, 0]);
        c.write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 80]).await.unwrap();
        let mut r = [0u8; 10];
        c.read_exact(&mut r).await.unwrap();
        assert_eq!(r[1], 2, "loopback must be refused by the ruleset");
    }

    /// A stand-in overnet gateway: accepts one SOCKS5 CONNECT and reports
    /// the requested `host:port`.
    async fn fake_gateway() -> (String, tokio::sync::oneshot::Receiver<String>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut g = [0u8; 3];
            s.read_exact(&mut g).await.unwrap();
            s.write_all(&[5, 0]).await.unwrap();
            let mut h = [0u8; 5];
            s.read_exact(&mut h).await.unwrap();
            assert_eq!(&h[..4], &[5, 1, 0, 3]);
            let mut name = vec![0u8; h[4] as usize];
            s.read_exact(&mut name).await.unwrap();
            let mut port = [0u8; 2];
            s.read_exact(&mut port).await.unwrap();
            s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
            let _ = tx.send(format!("{}:{}", String::from_utf8(name).unwrap(), u16::from_be_bytes(port)));
        });
        (addr, rx)
    }

    #[tokio::test]
    async fn router_sends_ov_to_the_gateway_by_name_and_by_fake_address() {
        let me: IpAddr = "203.0.113.5".parse().unwrap();
        for by_fake in [false, true] {
            let (gw, got) = fake_gateway().await;
            let router = crate::router::Router::new(
                None, None, crate::dns::DnsServer::new(Default::default(), None), false,
            );
            let o = Overnet::new(OvernetConfig { enabled: true, gateway: gw, ..Default::default() });
            *router.overnet.write().unwrap() = o.clone();
            let target = if by_fake {
                let ip = answer_ip(&o.answer_dns(&a_query("search.ov", TYPE::A)).unwrap()).unwrap();
                format!("{ip}:80")
            } else {
                "search.ov:80".to_string()
            };
            router.route_tcp(&target, me).await.unwrap();
            assert_eq!(got.await.unwrap(), "search.ov:80");
        }
    }
}
