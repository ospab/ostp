//! The WireGuard client and the TCP/UDP stack over it, all in user space.
//!
//! One task (`Driver`) owns everything: the outer UDP socket to the peer, the
//! `boringtun` state, a `smoltcp` interface whose "device" is a pair of packet
//! queues, and the sockets. Connections are handed out as channels (see
//! `Tunnel::connect_tcp` and `Tunnel::udp_flow`). There is no way out of this
//! module except encrypted packets to the peer's endpoint: a dead tunnel
//! means connections fail, they are never made another way.

use anyhow::{anyhow, bail, Result};
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use bytes::Bytes;
use smoltcp::iface::{Config as IfConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::{Duration as SDuration, Instant as SInstant};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Notify};

use crate::dnsq;

/// Inside the tunnel, as WARP's own clients have it.
pub const DEFAULT_MTU: usize = 1280;
pub const KEEPALIVE_SECS: u16 = 25;
/// A handshake older than this is a dead tunnel (WireGuard's REJECT_AFTER_TIME).
const HANDSHAKE_VALID: Duration = Duration::from_secs(180);
const TCP_BUF: usize = 128 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const WAIT_UP: Duration = Duration::from_secs(5);
/// Resolvers reachable inside WARP.
pub fn default_dns() -> Vec<IpAddr> {
    vec![
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
        IpAddr::V6("2606:4700:4700::1111".parse().unwrap()),
    ]
}

#[derive(Clone)]
pub struct TunnelConfig {
    pub private_key: [u8; 32],
    pub peer_public: [u8; 32],
    pub endpoint: SocketAddr,
    pub address_v4: Ipv4Addr,
    pub address_v6: Option<Ipv6Addr>,
    /// Bytes 1..4 of every packet sent to the peer (see `reserved_from_client_id`).
    pub reserved: [u8; 3],
    pub keepalive: Option<u16>,
    pub mtu: usize,
    pub dns: Vec<IpAddr>,
    /// Local address of the outer UDP socket (`0.0.0.0:0` or `[::]:0`).
    pub bind: SocketAddr,
}

impl TunnelConfig {
    pub fn new(private_key: [u8; 32], peer_public: [u8; 32], endpoint: SocketAddr, address_v4: Ipv4Addr) -> Self {
        let bind = if endpoint.is_ipv4() { SocketAddr::from(([0, 0, 0, 0], 0)) } else { SocketAddr::from(([0u16; 8], 0)) };
        Self {
            private_key,
            peer_public,
            endpoint,
            address_v4,
            address_v6: None,
            reserved: [0; 3],
            keepalive: Some(KEEPALIVE_SECS),
            mtu: DEFAULT_MTU,
            dns: default_dns(),
            bind,
        }
    }
}

/// The first 3 bytes of the base64 `client_id` are the "reserved" bytes that
/// WARP expects in bytes 1..4 of the WireGuard header (zero in plain
/// WireGuard). `Ok(None)`: no client id, or fewer than 3 bytes.
pub fn reserved_from_client_id(client_id: &str) -> Result<Option<[u8; 3]>> {
    use base64::Engine;
    let s = client_id.trim();
    if s.is_empty() {
        return Ok(None);
    }
    let raw = base64::engine::general_purpose::STANDARD
        .decode(s)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(s.trim_end_matches('=')))
        .map_err(|e| anyhow!("client_id is not base64: {e}"))?;
    Ok(raw.get(..3).map(|b| [b[0], b[1], b[2]]))
}

/// Puts the reserved bytes into a finished WireGuard message. They are set
/// after the message is built, so the MACs were computed over zeros, as in
/// the implementations that support them.
pub fn stamp_reserved(packet: &mut [u8], reserved: [u8; 3]) {
    if packet.len() >= 4 {
        packet[1..4].copy_from_slice(&reserved);
    }
}

/// The reverse, on what arrives.
pub fn clear_reserved(packet: &mut [u8]) {
    stamp_reserved(packet, [0; 3]);
}

#[derive(Debug, Clone, Default)]
pub struct TunnelStatus {
    /// A handshake completed in the last 180 s.
    pub up: bool,
    /// Seconds since the last completed handshake.
    pub last_handshake_secs: Option<u64>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub endpoint: Option<SocketAddr>,
    pub tcp_connections: usize,
    pub udp_flows: usize,
    /// UDP datagrams dropped because they do not fit the tunnel's MTU.
    pub udp_too_big: u64,
}

struct Shared {
    status: Mutex<TunnelStatus>,
    dns_cache: Mutex<HashMap<String, (Vec<IpAddr>, Instant)>>,
}

struct TcpApp {
    to_net: mpsc::Sender<Bytes>,
    from_net: mpsc::Receiver<Bytes>,
}

pub struct UdpFlow {
    to_net: mpsc::Sender<(SocketAddr, Bytes)>,
    from_net: mpsc::Receiver<(SocketAddr, Bytes)>,
    wake: Arc<Notify>,
}

#[derive(Clone)]
pub struct UdpSender {
    to_net: mpsc::Sender<(SocketAddr, Bytes)>,
    wake: Arc<Notify>,
}

impl UdpSender {
    /// Queues a datagram; dropped when the queue is full or the tunnel is
    /// gone, as UDP allows.
    pub fn send_to(&self, dst: SocketAddr, payload: &[u8]) {
        if self.to_net.try_send((dst, Bytes::copy_from_slice(payload))).is_ok() {
            self.wake.notify_one();
        }
    }
}

impl UdpFlow {
    pub fn split(self) -> (UdpSender, mpsc::Receiver<(SocketAddr, Bytes)>) {
        (UdpSender { to_net: self.to_net, wake: self.wake }, self.from_net)
    }

    pub async fn recv(&mut self) -> Option<(SocketAddr, Bytes)> {
        self.from_net.recv().await
    }

    pub fn send_to(&self, dst: SocketAddr, payload: &[u8]) {
        UdpSender { to_net: self.to_net.clone(), wake: self.wake.clone() }.send_to(dst, payload);
    }
}

enum Cmd {
    Tcp { addr: SocketAddr, reply: oneshot::Sender<Result<TcpApp>> },
    Udp { reply: oneshot::Sender<Result<UdpFlow>> },
}

/// A handle to a running tunnel; clone freely.
#[derive(Clone)]
pub struct Tunnel {
    cmd: mpsc::UnboundedSender<Cmd>,
    wake: Arc<Notify>,
    shared: Arc<Shared>,
    dns: Arc<Vec<IpAddr>>,
    has_v6: bool,
    stop: Arc<Notify>,
}

impl Tunnel {
    /// Opens the outer socket and starts the driver task. The tunnel is
    /// "up" once the first handshake has completed; until then connections
    /// wait (at most 5 s) and fail.
    pub async fn start(cfg: TunnelConfig) -> Result<Tunnel> {
        let udp = UdpSocket::bind(cfg.bind).await.map_err(|e| anyhow!("cannot open the UDP socket for WireGuard: {e}"))?;
        let secret = StaticSecret::from(cfg.private_key);
        let peer = PublicKey::from(cfg.peer_public);
        let index = rand::random::<u32>() & 0x00ff_ffff;
        let tunn = Tunn::new(secret, peer, None, cfg.keepalive, index, None);

        let mut dev = QueueDevice { rx: VecDeque::new(), tx: VecDeque::new(), mtu: cfg.mtu };
        let mut ifcfg = IfConfig::new(HardwareAddress::Ip);
        ifcfg.random_seed = rand::random();
        let started = Instant::now();
        let mut iface = Interface::new(ifcfg, &mut dev, SInstant::from_micros(0));
        iface.update_ip_addrs(|a| {
            let _ = a.push(IpCidr::new(IpAddress::Ipv4(cfg.address_v4), 32));
            if let Some(v6) = cfg.address_v6 {
                let _ = a.push(IpCidr::new(IpAddress::Ipv6(v6), 128));
            }
        });
        // Everything goes into the tunnel. The gateway address is nominal on
        // an IP-medium device.
        iface.routes_mut().add_default_ipv4_route(Ipv4Addr::new(10, 255, 255, 254)).map_err(|_| anyhow!("route table full"))?;
        if cfg.address_v6.is_some() {
            iface.routes_mut().add_default_ipv6_route(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)).map_err(|_| anyhow!("route table full"))?;
        }

        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let wake = Arc::new(Notify::new());
        let stop = Arc::new(Notify::new());
        let shared = Arc::new(Shared {
            status: Mutex::new(TunnelStatus { endpoint: Some(cfg.endpoint), ..Default::default() }),
            dns_cache: Mutex::new(HashMap::new()),
        });
        let driver = Driver {
            tunn,
            udp,
            endpoint: cfg.endpoint,
            reserved: cfg.reserved,
            iface,
            dev,
            sockets: SocketSet::new(Vec::new()),
            tcps: HashMap::new(),
            udps: HashMap::new(),
            ports: HashSet::new(),
            cmd_rx,
            wake: wake.clone(),
            shared: shared.clone(),
            scratch: vec![0u8; 4096],
            started,
            last_timers: Instant::now(),
            last_hs_try: Instant::now() - Duration::from_secs(60),
            has_v6: cfg.address_v6.is_some(),
            udp_too_big: 0,
            mtu: cfg.mtu,
        };
        let stop2 = stop.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = driver.run() => {}
                _ = stop2.notified() => {}
            }
        });
        Ok(Tunnel { cmd: cmd_tx, wake, shared, dns: Arc::new(cfg.dns), has_v6: cfg.address_v6.is_some(), stop })
    }

    /// Stops the driver; every connection through it ends.
    pub fn shutdown(&self) {
        self.stop.notify_one();
    }

    pub fn status(&self) -> TunnelStatus {
        self.shared.status.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn is_up(&self) -> bool {
        self.status().up
    }

    async fn wait_up(&self) -> Result<()> {
        let deadline = Instant::now() + WAIT_UP;
        loop {
            if self.is_up() {
                return Ok(());
            }
            if self.cmd.is_closed() {
                bail!("WARP tunnel is down (stopped)");
            }
            if Instant::now() >= deadline {
                bail!("WARP tunnel is down (no WireGuard handshake with the peer)");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// A TCP connection to `addr` through the tunnel, as a byte stream.
    pub async fn connect_tcp(&self, addr: SocketAddr) -> Result<tokio::io::DuplexStream> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        if addr.is_ipv6() && !self.has_v6 {
            bail!("no route: the WARP device has no IPv6 address");
        }
        self.wait_up().await?;
        let (tx, rx) = oneshot::channel();
        self.cmd.send(Cmd::Tcp { addr, reply: tx }).map_err(|_| anyhow!("WARP tunnel is down (stopped)"))?;
        self.wake.notify_one();
        let app = rx.await.map_err(|_| anyhow!("WARP tunnel is down (stopped)"))??;
        let (mine, theirs) = tokio::io::duplex(64 * 1024);
        let TcpApp { to_net, mut from_net } = app;
        let (w_up, w_down) = (self.wake.clone(), self.wake.clone());
        tokio::spawn(async move {
            let (mut rd, mut wr) = tokio::io::split(theirs);
            let up = async move {
                let mut buf = vec![0u8; 16 * 1024];
                loop {
                    match rd.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if to_net.send(Bytes::copy_from_slice(&buf[..n])).await.is_err() {
                                break;
                            }
                            w_up.notify_one();
                        }
                    }
                }
                // Dropping `to_net` is the FIN.
                drop(to_net);
                w_up.notify_one();
            };
            let down = async move {
                while let Some(b) = from_net.recv().await {
                    w_down.notify_one(); // room again in the channel
                    if wr.write_all(&b).await.is_err() {
                        break;
                    }
                }
                let _ = wr.shutdown().await;
            };
            tokio::join!(up, down);
        });
        Ok(mine)
    }

    /// A UDP socket in the tunnel: datagrams to and from any address.
    pub async fn udp_flow(&self) -> Result<UdpFlow> {
        self.wait_up().await?;
        let (tx, rx) = oneshot::channel();
        self.cmd.send(Cmd::Udp { reply: tx }).map_err(|_| anyhow!("WARP tunnel is down (stopped)"))?;
        self.wake.notify_one();
        rx.await.map_err(|_| anyhow!("WARP tunnel is down (stopped)"))?
    }

    /// Resolves a name inside the tunnel, with the tunnel's resolvers. IPv4
    /// addresses come first.
    pub async fn resolve(&self, name: &str) -> Result<Vec<IpAddr>> {
        if let Ok(ip) = name.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let key = name.to_ascii_lowercase();
        if let Some((ips, until)) = self.shared.dns_cache.lock().unwrap_or_else(|e| e.into_inner()).get(&key) {
            if *until > Instant::now() {
                return Ok(ips.clone());
            }
        }
        let flow = self.udp_flow().await?;
        let (tx, mut rx) = flow.split();
        let mut last = anyhow!("cannot resolve {name}: no answer from the resolvers in the tunnel");
        for server in self.dns.iter().copied().filter(|s| s.is_ipv4() || self.has_v6) {
            let dst = SocketAddr::new(server, 53);
            let (id_a, id_aaaa) = (rand::random::<u16>(), rand::random::<u16>());
            tx.send_to(dst, &dnsq::build_query(id_a, name, dnsq::Kind::A)?);
            if self.has_v6 {
                tx.send_to(dst, &dnsq::build_query(id_aaaa, name, dnsq::Kind::Aaaa)?);
            }
            let want = if self.has_v6 { 2 } else { 1 };
            let (mut got, mut v4, mut v6, mut ttl, mut nx) = (0, Vec::new(), Vec::new(), u32::MAX, false);
            let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
            while got < want {
                let Ok(Some((from, data))) = tokio::time::timeout_at(deadline, rx.recv()).await else { break };
                if from != dst {
                    continue;
                }
                let Ok(a) = dnsq::parse_answer(&data) else { continue };
                if a.id != id_a && a.id != id_aaaa {
                    continue;
                }
                got += 1;
                nx |= a.nxdomain;
                if let Some(t) = a.ttl {
                    ttl = ttl.min(t);
                }
                for ip in a.ips {
                    if ip.is_ipv4() { v4.push(ip) } else { v6.push(ip) }
                }
            }
            v4.extend(v6);
            if !v4.is_empty() {
                let keep = Duration::from_secs(u64::from(ttl.clamp(30, 300)));
                self.shared.dns_cache.lock().unwrap_or_else(|e| e.into_inner()).insert(key, (v4.clone(), Instant::now() + keep));
                return Ok(v4);
            }
            if nx {
                bail!("cannot resolve {name}: no such name (NXDOMAIN)");
            }
            if got > 0 {
                last = anyhow!("cannot resolve {name}: the resolver has no address for it");
            }
        }
        Err(last)
    }
}

// ── smoltcp device: two queues ───────────────────────────────────────────────

struct QueueDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    mtu: usize,
}

struct QRx(Vec<u8>);
struct QTx<'a>(&'a mut VecDeque<Vec<u8>>);

impl RxToken for QRx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl<'a> TxToken for QTx<'a> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut b = vec![0u8; len];
        let r = f(&mut b);
        self.0.push_back(b);
        r
    }
}

impl Device for QueueDevice {
    type RxToken<'a> = QRx where Self: 'a;
    type TxToken<'a> = QTx<'a> where Self: 'a;

    fn receive(&mut self, _ts: SInstant) -> Option<(QRx, QTx<'_>)> {
        let p = self.rx.pop_front()?;
        Some((QRx(p), QTx(&mut self.tx)))
    }

    fn transmit(&mut self, _ts: SInstant) -> Option<QTx<'_>> {
        if self.tx.len() >= 2048 {
            return None;
        }
        Some(QTx(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = self.mtu;
        c
    }
}

// ── the driver ───────────────────────────────────────────────────────────────

enum Phase {
    Connecting { reply: oneshot::Sender<Result<TcpApp>>, app: Option<TcpApp>, deadline: Instant },
    Open,
}

struct TcpEntry {
    phase: Phase,
    to_app: Option<mpsc::Sender<Bytes>>,
    from_app: mpsc::Receiver<Bytes>,
    pending: Option<(Bytes, usize)>,
    fin_sent: bool,
    port: u16,
}

struct UdpEntry {
    to_app: mpsc::Sender<(SocketAddr, Bytes)>,
    from_app: mpsc::Receiver<(SocketAddr, Bytes)>,
    port: u16,
}

struct Driver {
    tunn: Tunn,
    udp: UdpSocket,
    endpoint: SocketAddr,
    reserved: [u8; 3],
    iface: Interface,
    dev: QueueDevice,
    sockets: SocketSet<'static>,
    tcps: HashMap<SocketHandle, TcpEntry>,
    udps: HashMap<SocketHandle, UdpEntry>,
    ports: HashSet<u16>,
    cmd_rx: mpsc::UnboundedReceiver<Cmd>,
    wake: Arc<Notify>,
    shared: Arc<Shared>,
    scratch: Vec<u8>,
    started: Instant,
    last_timers: Instant,
    last_hs_try: Instant,
    has_v6: bool,
    udp_too_big: u64,
    mtu: usize,
}

fn to_ip_endpoint(a: SocketAddr) -> IpEndpoint {
    IpEndpoint::new(IpAddress::from(a.ip()), a.port())
}

fn from_ip_endpoint(e: IpEndpoint) -> SocketAddr {
    SocketAddr::new(IpAddr::from(e.addr), e.port)
}

impl Driver {
    fn now(&self) -> SInstant {
        SInstant::from_micros(self.started.elapsed().as_micros() as i64)
    }

    fn free_port(&mut self) -> u16 {
        loop {
            let p = 49152 + (rand::random::<u16>() % 16000);
            if self.ports.insert(p) {
                return p;
            }
        }
    }

    async fn run(mut self) {
        // Do not wait for traffic to start the handshake: `status` should say
        // "up" without it.
        self.start_handshake();
        let mut buf = vec![0u8; 4096];
        loop {
            let delay = {
                let now = self.now();
                self.iface
                    .poll_delay(now, &self.sockets)
                    .map(|d| Duration::from_micros(d.total_micros()))
                    .unwrap_or(Duration::from_millis(250))
                    .clamp(Duration::from_millis(1), Duration::from_millis(250))
            };
            tokio::select! {
                r = self.udp.recv_from(&mut buf) => {
                    match r {
                        Ok((n, src)) => self.on_datagram(&mut buf[..n], src.ip()),
                        Err(e) => {
                            // A connection-refused style error from an earlier
                            // send; nothing to do but go on.
                            tracing::debug!("warp: udp recv: {e}");
                        }
                    }
                    // More may be waiting.
                    while let Ok((n, src)) = self.udp.try_recv_from(&mut buf) {
                        self.on_datagram(&mut buf[..n], src.ip());
                    }
                }
                cmd = self.cmd_rx.recv() => match cmd {
                    Some(c) => self.on_cmd(c),
                    None => return, // every handle is gone
                },
                _ = self.wake.notified() => {}
                _ = tokio::time::sleep(delay) => {}
            }
            while let Ok(c) = self.cmd_rx.try_recv() {
                self.on_cmd(c);
            }
            self.timers();
            self.pump();
        }
    }

    fn start_handshake(&mut self) {
        let Driver { tunn, udp, endpoint, reserved, scratch, .. } = self;
        if let TunnResult::WriteToNetwork(p) = tunn.format_handshake_initiation(scratch, false) {
            send_net(udp, *endpoint, *reserved, p);
        }
    }

    fn timers(&mut self) {
        if self.last_timers.elapsed() < Duration::from_millis(250) {
            return;
        }
        self.last_timers = Instant::now();
        {
            let Driver { tunn, udp, endpoint, reserved, scratch, .. } = self;
            match tunn.update_timers(scratch) {
                TunnResult::WriteToNetwork(p) => send_net(udp, *endpoint, *reserved, p),
                TunnResult::Err(e) => tracing::debug!("warp: timers: {e:?}"),
                _ => {}
            }
        }
        let (since, tx, rx, _, _) = self.tunn.stats();
        let up = since.is_some_and(|d| d < HANDSHAKE_VALID);
        // A tunnel that is not up retries the handshake every 5 s, for as
        // long as it takes; it never gives up and never lets traffic pass.
        if !up && self.last_hs_try.elapsed() >= Duration::from_secs(5) {
            self.last_hs_try = Instant::now();
            self.start_handshake();
        }
        let mut st = self.shared.status.lock().unwrap_or_else(|e| e.into_inner());
        if st.up != up {
            if up {
                tracing::info!("warp: tunnel up ({})", self.endpoint);
            } else {
                tracing::warn!("warp: tunnel down (no handshake in 180 s); connections fail until it is back");
            }
        }
        st.up = up;
        st.last_handshake_secs = since.map(|d| d.as_secs());
        st.tx_bytes = tx as u64;
        st.rx_bytes = rx as u64;
        st.tcp_connections = self.tcps.len();
        st.udp_flows = self.udps.len();
        st.udp_too_big = self.udp_too_big;
        // The first handshake should show at once, not after the next tick.
    }

    fn on_datagram(&mut self, data: &mut [u8], src: IpAddr) {
        // The peer may fill the reserved bytes in what it sends; WireGuard
        // itself wants zeros there.
        clear_reserved(data);
        let Driver { tunn, udp, endpoint, reserved, scratch, dev, .. } = self;
        let mut first = true;
        loop {
            let res = if first { tunn.decapsulate(Some(src), data, scratch) } else { tunn.decapsulate(None, &[], scratch) };
            first = false;
            match res {
                TunnResult::WriteToNetwork(p) => send_net(udp, *endpoint, *reserved, p),
                TunnResult::WriteToTunnelV4(p, _) | TunnResult::WriteToTunnelV6(p, _) => {
                    if dev.rx.len() < 4096 {
                        dev.rx.push_back(p.to_vec());
                    }
                    break;
                }
                TunnResult::Done => break,
                TunnResult::Err(e) => {
                    tracing::debug!("warp: wireguard: {e:?}");
                    break;
                }
            }
        }
        // A handshake that just completed shows in the status right away.
        self.last_timers = Instant::now() - Duration::from_secs(1);
    }

    fn on_cmd(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::Tcp { addr, reply } => {
                if addr.is_ipv6() && !self.has_v6 {
                    let _ = reply.send(Err(anyhow!("no route: the WARP device has no IPv6 address")));
                    return;
                }
                let port = self.free_port();
                let mut s = tcp::Socket::new(tcp::SocketBuffer::new(vec![0u8; TCP_BUF]), tcp::SocketBuffer::new(vec![0u8; TCP_BUF]));
                s.set_nagle_enabled(false);
                s.set_timeout(Some(SDuration::from_secs(120)));
                if let Err(e) = s.connect(self.iface.context(), to_ip_endpoint(addr), IpListenEndpoint::from(port)) {
                    self.ports.remove(&port);
                    let _ = reply.send(Err(anyhow!("cannot connect to {addr}: {e}")));
                    return;
                }
                let (to_app, from_net) = mpsc::channel::<Bytes>(16);
                let (to_net, from_app) = mpsc::channel::<Bytes>(16);
                let h = self.sockets.add(s);
                self.tcps.insert(
                    h,
                    TcpEntry {
                        phase: Phase::Connecting { reply, app: Some(TcpApp { to_net, from_net }), deadline: Instant::now() + CONNECT_TIMEOUT },
                        to_app: Some(to_app),
                        from_app,
                        pending: None,
                        fin_sent: false,
                        port,
                    },
                );
            }
            Cmd::Udp { reply } => {
                let port = self.free_port();
                let mut s = udp::Socket::new(
                    udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 64], vec![0u8; 64 * 1024]),
                    udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 64], vec![0u8; 64 * 1024]),
                );
                if let Err(e) = s.bind(port) {
                    self.ports.remove(&port);
                    let _ = reply.send(Err(anyhow!("cannot open a UDP socket in the tunnel: {e}")));
                    return;
                }
                let (to_app, from_net) = mpsc::channel(256);
                let (to_net, from_app) = mpsc::channel(256);
                let h = self.sockets.add(s);
                self.udps.insert(h, UdpEntry { to_app, from_app, port });
                let _ = reply.send(Ok(UdpFlow { to_net, from_net, wake: self.wake.clone() }));
            }
        }
    }

    /// Runs the stack and moves bytes between it and the applications until
    /// nothing moves.
    fn pump(&mut self) {
        for _ in 0..16 {
            let now = self.now();
            self.iface.poll(now, &mut self.dev, &mut self.sockets);
            let moved = self.service_tcp() | self.service_udp();
            let sent = self.flush();
            if !moved && !sent && self.dev.rx.is_empty() {
                break;
            }
        }
    }

    /// Encrypts what the stack wants to send.
    fn flush(&mut self) -> bool {
        let mut any = false;
        let Driver { tunn, udp, endpoint, reserved, scratch, dev, .. } = self;
        while let Some(pkt) = dev.tx.pop_front() {
            any = true;
            if pkt.len() + 64 > scratch.len() {
                continue;
            }
            match tunn.encapsulate(&pkt, scratch) {
                TunnResult::WriteToNetwork(p) => send_net(udp, *endpoint, *reserved, p),
                TunnResult::Err(e) => tracing::debug!("warp: encapsulate: {e:?}"),
                _ => {}
            }
        }
        any
    }

    fn service_tcp(&mut self) -> bool {
        let mut moved = false;
        let mut dead: Vec<SocketHandle> = Vec::new();
        let mut chunk = [0u8; 16 * 1024];
        for (h, e) in self.tcps.iter_mut() {
            let s = self.sockets.get_mut::<tcp::Socket>(*h);
            if let Phase::Connecting { .. } = e.phase {
                let state = s.state();
                let established = matches!(state, tcp::State::Established | tcp::State::CloseWait);
                let deadline_passed = matches!(&e.phase, Phase::Connecting { deadline, .. } if *deadline <= Instant::now());
                if established || state == tcp::State::Closed || deadline_passed {
                    let Phase::Connecting { reply, app, .. } = std::mem::replace(&mut e.phase, Phase::Open) else { unreachable!() };
                    if established {
                        let _ = reply.send(Ok(app.expect("the app ends are kept until the connection is established")));
                        moved = true;
                    } else {
                        let why = if deadline_passed && state != tcp::State::Closed { "connect timed out" } else { "connection refused" };
                        let _ = reply.send(Err(anyhow!("{why}")));
                        s.abort();
                        dead.push(*h);
                        continue;
                    }
                } else {
                    continue;
                }
            }
            // network -> application
            if let Some(to_app) = &e.to_app {
                while s.can_recv() {
                    match to_app.try_reserve() {
                        Ok(permit) => {
                            let n = s.recv_slice(&mut chunk).unwrap_or(0);
                            if n == 0 {
                                break;
                            }
                            permit.send(Bytes::copy_from_slice(&chunk[..n]));
                            moved = true;
                        }
                        Err(mpsc::error::TrySendError::Full(())) => break,
                        Err(mpsc::error::TrySendError::Closed(())) => {
                            // Nobody reads any more.
                            s.abort();
                            break;
                        }
                    }
                }
            }
            if !s.may_recv() && !s.can_recv() && e.to_app.is_some() {
                // The peer is done sending: the application sees the end.
                e.to_app = None;
                moved = true;
            }
            // application -> network
            loop {
                if e.pending.is_none() {
                    match e.from_app.try_recv() {
                        Ok(b) => e.pending = Some((b, 0)),
                        Err(mpsc::error::TryRecvError::Empty) => break,
                        Err(mpsc::error::TryRecvError::Disconnected) => {
                            if !e.fin_sent && s.may_send() {
                                s.close();
                                e.fin_sent = true;
                                moved = true;
                            }
                            break;
                        }
                    }
                }
                if let Some((b, off)) = &mut e.pending {
                    if !s.may_send() {
                        e.pending = None;
                        continue;
                    }
                    let n = s.send_slice(&b[*off..]).unwrap_or(0);
                    if n > 0 {
                        moved = true;
                    }
                    *off += n;
                    if *off < b.len() {
                        break; // the send buffer is full; wait for acks
                    }
                    e.pending = None;
                }
            }
            if matches!(s.state(), tcp::State::Closed | tcp::State::TimeWait) && !s.can_recv() {
                dead.push(*h);
            }
        }
        for h in dead {
            if let Some(e) = self.tcps.remove(&h) {
                self.ports.remove(&e.port);
            }
            self.sockets.remove(h);
            moved = true;
        }
        moved
    }

    fn service_udp(&mut self) -> bool {
        let mut moved = false;
        let mut dead = Vec::new();
        let mut buf = vec![0u8; 2048];
        for (h, e) in self.udps.iter_mut() {
            let s = self.sockets.get_mut::<udp::Socket>(*h);
            while s.can_recv() {
                match s.recv_slice(&mut buf) {
                    Ok((n, meta)) => {
                        let _ = e.to_app.try_send((from_ip_endpoint(meta.endpoint), Bytes::copy_from_slice(&buf[..n])));
                        moved = true;
                    }
                    Err(_) => break,
                }
            }
            loop {
                match e.from_app.try_recv() {
                    Ok((dst, data)) => {
                        // The stack does not fragment: a datagram that does
                        // not fit one packet of the tunnel is dropped.
                        let max = self.mtu - if dst.is_ipv4() { 20 + 8 } else { 40 + 8 };
                        if data.len() > max {
                            self.udp_too_big += 1;
                            continue;
                        }
                        if dst.is_ipv6() && !self.has_v6 {
                            continue;
                        }
                        if s.send_slice(&data, to_ip_endpoint(dst)).is_ok() {
                            moved = true;
                        }
                    }
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        dead.push(*h);
                        break;
                    }
                }
            }
            if e.to_app.is_closed() && !dead.contains(h) {
                dead.push(*h);
            }
        }
        for h in dead {
            if let Some(e) = self.udps.remove(&h) {
                self.ports.remove(&e.port);
            }
            self.sockets.remove(h);
            moved = true;
        }
        moved
    }
}

/// Sends one WireGuard message to the peer. A full socket buffer drops the
/// packet: WireGuard and what runs over it are built for loss.
fn send_net(udp: &UdpSocket, endpoint: SocketAddr, reserved: [u8; 3], packet: &mut [u8]) {
    stamp_reserved(packet, reserved);
    if let Err(e) = udp.try_send_to(packet, endpoint) {
        if e.kind() != std::io::ErrorKind::WouldBlock {
            tracing::debug!("warp: send to {endpoint}: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_comes_from_the_first_three_bytes_of_client_id() {
        assert_eq!(reserved_from_client_id("AQID").unwrap(), Some([1, 2, 3]));
        // Longer ids: the first three bytes only.
        assert_eq!(reserved_from_client_id("AQIDBAUG").unwrap(), Some([1, 2, 3]));
        // Missing padding is tolerated.
        assert_eq!(reserved_from_client_id("AQIDBA").unwrap(), Some([1, 2, 3]));
        assert_eq!(reserved_from_client_id("").unwrap(), None);
        assert_eq!(reserved_from_client_id("AQI=").unwrap(), None, "two bytes are not enough");
        assert!(reserved_from_client_id("!!!").is_err());
    }

    #[test]
    fn reserved_bytes_are_set_after_the_type_and_cleared_again() {
        let mut p = [4u8, 0, 0, 0, 9, 9, 9, 9];
        stamp_reserved(&mut p, [7, 8, 9]);
        assert_eq!(p, [4, 7, 8, 9, 9, 9, 9, 9], "the message type in byte 0 is untouched");
        clear_reserved(&mut p);
        assert_eq!(p, [4, 0, 0, 0, 9, 9, 9, 9]);
        let mut short = [1u8, 2];
        stamp_reserved(&mut short, [7, 8, 9]);
        assert_eq!(short, [1, 2]);
    }
}
