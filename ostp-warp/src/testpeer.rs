//! A stand-in for Cloudflare's WARP endpoint, for tests: a real WireGuard
//! peer (`boringtun`) behind a UDP socket on loopback, whose tunnel is
//! terminated by `netstack-smoltcp` (the stack the client's TUN mode uses),
//! so it accepts TCP and UDP to *any* address. Every TCP connection is
//! forwarded to `tcp_target` and every UDP datagram to `udp_target` (port 53
//! is answered from a small table of names), and the peer records what it was
//! asked for. It also puts the "reserved" bytes into what it sends, as the
//! real service does, and records the ones it receives.

use anyhow::Result;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use futures::{SinkExt, StreamExt};
use netstack_smoltcp::StackBuilder;
use simple_dns::rdata::RData;
use simple_dns::{Name, Packet, ResourceRecord, CLASS, RCODE};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;

#[derive(Clone)]
pub struct FakeConfig {
    pub server_private: [u8; 32],
    pub client_public: [u8; 32],
    /// What the peer puts into bytes 1..4 of what it sends.
    pub reserved: [u8; 3],
    pub tcp_target: SocketAddr,
    pub udp_target: SocketAddr,
    /// Names the peer's resolver knows.
    pub names: Vec<(String, Vec<IpAddr>)>,
    /// Where the peer's UDP socket listens (`127.0.0.1:0`).
    pub bind: SocketAddr,
}

#[derive(Default)]
pub struct Seen {
    pub tcp_dsts: Mutex<Vec<SocketAddr>>,
    pub udp_dsts: Mutex<Vec<SocketAddr>>,
    pub dns_queries: Mutex<Vec<String>>,
    /// Bytes 1..4 of every message that arrived.
    pub reserved: Mutex<Vec<[u8; 3]>>,
    pub datagrams: Mutex<u64>,
}

pub struct FakeCloudflare {
    pub endpoint: SocketAddr,
    pub server_public: [u8; 32],
    pub seen: Arc<Seen>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl FakeCloudflare {
    pub async fn start(cfg: FakeConfig) -> Result<Self> {
        let sock = Arc::new(UdpSocket::bind(cfg.bind).await?);
        let endpoint = sock.local_addr()?;
        let secret = StaticSecret::from(cfg.server_private);
        let server_public = *PublicKey::from(&secret).as_bytes();
        let tunn = Arc::new(Mutex::new(Tunn::new(secret, PublicKey::from(cfg.client_public), None, None, 7, None)));
        let seen = Arc::new(Seen::default());
        let client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

        let (stack, runner, udp_socket, tcp_listener) = StackBuilder::default()
            .stack_buffer_size(1024)
            .tcp_buffer_size(1024)
            .udp_buffer_size(1024)
            .enable_tcp(true)
            .enable_udp(true)
            .mtu(1280)
            .build()?;
        let (mut stack_sink, mut stack_stream) = stack.split();
        let mut tasks = Vec::new();

        if let Some(r) = runner {
            tasks.push(tokio::spawn(async move {
                let _ = r.await;
            }));
        }

        // network -> WireGuard -> stack
        {
            let (sock, tunn, seen, client) = (sock.clone(), tunn.clone(), seen.clone(), client.clone());
            tasks.push(tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let mut out = vec![0u8; 4096];
                loop {
                    let Ok((n, src)) = sock.recv_from(&mut buf).await else { continue };
                    *seen.datagrams.lock().unwrap() += 1;
                    if n >= 4 {
                        seen.reserved.lock().unwrap().push([buf[1], buf[2], buf[3]]);
                        buf[1..4].copy_from_slice(&[0, 0, 0]);
                    }
                    *client.lock().unwrap() = Some(src);
                    let mut ip_packets = Vec::new();
                    let mut replies = Vec::new();
                    {
                        let mut t = tunn.lock().unwrap();
                        let mut first = true;
                        loop {
                            let r = if first { t.decapsulate(Some(src.ip()), &buf[..n], &mut out) } else { t.decapsulate(None, &[], &mut out) };
                            first = false;
                            match r {
                                TunnResult::WriteToNetwork(p) => {
                                    if p.len() >= 4 {
                                        p[1..4].copy_from_slice(&cfg.reserved);
                                    }
                                    replies.push(p.to_vec());
                                }
                                TunnResult::WriteToTunnelV4(p, _) | TunnResult::WriteToTunnelV6(p, _) => {
                                    ip_packets.push(p.to_vec());
                                    break;
                                }
                                _ => break,
                            }
                        }
                    }
                    for r in replies {
                        let _ = sock.send_to(&r, src).await;
                    }
                    for p in ip_packets {
                        let _ = stack_sink.send(p).await;
                    }
                }
            }));
        }
        // stack -> WireGuard -> network
        {
            let (sock, tunn, client) = (sock.clone(), tunn.clone(), client.clone());
            let reserved = cfg.reserved;
            tasks.push(tokio::spawn(async move {
                let mut out = vec![0u8; 4096];
                while let Some(Ok(pkt)) = stack_stream.next().await {
                    let Some(dst) = *client.lock().unwrap() else { continue };
                    let wire = {
                        let mut t = tunn.lock().unwrap();
                        match t.encapsulate(&pkt, &mut out) {
                            TunnResult::WriteToNetwork(p) => {
                                if p.len() >= 4 {
                                    p[1..4].copy_from_slice(&reserved);
                                }
                                Some(p.to_vec())
                            }
                            _ => None,
                        }
                    };
                    if let Some(w) = wire {
                        let _ = sock.send_to(&w, dst).await;
                    }
                }
            }));
        }
        // timers: the peer must answer keepalives and rekey like a real one
        {
            let (sock, tunn, client) = (sock.clone(), tunn.clone(), client.clone());
            let reserved = cfg.reserved;
            tasks.push(tokio::spawn(async move {
                let mut out = vec![0u8; 4096];
                loop {
                    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                    let Some(dst) = *client.lock().unwrap() else { continue };
                    let wire = {
                        let mut t = tunn.lock().unwrap();
                        match t.update_timers(&mut out) {
                            TunnResult::WriteToNetwork(p) => {
                                if p.len() >= 4 {
                                    p[1..4].copy_from_slice(&reserved);
                                }
                                Some(p.to_vec())
                            }
                            _ => None,
                        }
                    };
                    if let Some(w) = wire {
                        let _ = sock.send_to(&w, dst).await;
                    }
                }
            }));
        }
        // TCP: every connection goes to tcp_target
        if let Some(mut listener) = tcp_listener {
            let seen = seen.clone();
            let target = cfg.tcp_target;
            tasks.push(tokio::spawn(async move {
                while let Some((mut stream, _src, dst)) = listener.next().await {
                    seen.tcp_dsts.lock().unwrap().push(dst);
                    tokio::spawn(async move {
                        match tokio::net::TcpStream::connect(target).await {
                            Ok(mut up) => {
                                let _ = tokio::io::copy_bidirectional(&mut stream, &mut up).await;
                            }
                            Err(_) => {
                                let _ = stream.shutdown().await;
                            }
                        }
                    });
                }
            }));
        }
        // UDP: port 53 is a resolver, the rest goes to udp_target
        if let Some(udp) = udp_socket {
            let (mut rx, tx) = udp.split();
            let tx = Arc::new(tokio::sync::Mutex::new(tx));
            let seen = seen.clone();
            let names: HashMap<String, Vec<IpAddr>> = cfg.names.iter().cloned().collect();
            let target = cfg.udp_target;
            tasks.push(tokio::spawn(async move {
                let mut flows: HashMap<(SocketAddr, SocketAddr), Arc<UdpSocket>> = HashMap::new();
                while let Some((payload, src, dst)) = rx.next().await {
                    if dst.port() == 53 {
                        if let Some(answer) = answer_dns(&payload, &names, &seen) {
                            let _ = tx.lock().await.send((answer, dst, src)).await;
                        }
                        continue;
                    }
                    seen.udp_dsts.lock().unwrap().push(dst);
                    let up = match flows.get(&(src, dst)) {
                        Some(s) => s.clone(),
                        None => {
                            let Ok(s) = UdpSocket::bind("127.0.0.1:0").await else { continue };
                            let s = Arc::new(s);
                            flows.insert((src, dst), s.clone());
                            let (s2, tx2) = (s.clone(), tx.clone());
                            tokio::spawn(async move {
                                let mut b = vec![0u8; 2048];
                                while let Ok((n, _)) = s2.recv_from(&mut b).await {
                                    // The reply comes "from" the address that was asked.
                                    if tx2.lock().await.send((b[..n].to_vec(), dst, src)).await.is_err() {
                                        break;
                                    }
                                }
                            });
                            s
                        }
                    };
                    let _ = up.send_to(&payload, target).await;
                }
            }));
        }
        Ok(Self { endpoint, server_public, seen, tasks })
    }

    /// Kills the peer: its socket closes and nothing answers any more.
    pub fn stop(&mut self) {
        for t in self.tasks.drain(..) {
            t.abort();
        }
    }
}

impl Drop for FakeCloudflare {
    fn drop(&mut self) {
        self.stop();
    }
}

fn answer_dns(query: &[u8], names: &HashMap<String, Vec<IpAddr>>, seen: &Seen) -> Option<Vec<u8>> {
    let q = Packet::parse(query).ok()?;
    let question = q.questions.first()?;
    let name = question.qname.to_string().to_ascii_lowercase();
    seen.dns_queries.lock().unwrap().push(name.clone());
    let mut r = Packet::new_reply(q.id());
    r.questions.push(question.clone());
    match names.get(&name) {
        None => *r.rcode_mut() = RCODE::NameError,
        Some(ips) => {
            let want_v6 = matches!(question.qtype, simple_dns::QTYPE::TYPE(simple_dns::TYPE::AAAA));
            for ip in ips {
                match (ip, want_v6) {
                    (IpAddr::V4(a), false) => r.answers.push(ResourceRecord::new(
                        Name::new_unchecked(&name).into_owned(),
                        CLASS::IN,
                        60,
                        RData::A(simple_dns::rdata::A { address: u32::from(*a) }),
                    )),
                    (IpAddr::V6(a), true) => r.answers.push(ResourceRecord::new(
                        Name::new_unchecked(&name).into_owned(),
                        CLASS::IN,
                        60,
                        RData::AAAA(simple_dns::rdata::AAAA { address: u128::from(*a) }),
                    )),
                    _ => {}
                }
            }
        }
    }
    r.build_bytes_vec().ok()
}
