//! Transparent relay node.
//!
//! Forwards traffic to a fixed upstream OSTP server:
//!
//!   Client -> [Relay] -> [Target server]
//!
//! ## Why this performs no authentication of its own
//!
//! The previous design had the relay authenticate clients itself, with an
//! HMAC handshake and a background job that pulled the access-key list from the
//! target server's management API. That was wrong on two counts.
//!
//! It did not work: no OSTP client has ever produced those credentials. The TCP
//! path expected an HTTP request (`GET /stream` with an `Authorization: Bearer`
//! header) and the UDP path expected a `timestamp || HMAC` preamble, while the
//! client sends junk frames followed by length-prefixed OSTP frames, and an
//! obfuscated Noise handshake, respectively. Every connection was rejected.
//!
//! It was also weak where it did apply: the HMAC covered only an 8-byte
//! timestamp, so a captured signature was a bearer token that anyone could
//! replay from any address for the length of the clock-skew window. And the
//! HTTP handshake was a plaintext `GET /stream` on the wire, a greppable
//! signature in a protocol whose entire premise is that no byte is
//! recognisable.
//!
//! Authentication belongs where it is cryptographically meaningful: the target
//! server already authenticates every session end-to-end via Noise with a PSK
//! derived from the access key, and silently drops anything that fails. A relay
//! that re-checks credentials adds a second, weaker gate and a copy of the key
//! list on a machine that has no need for it. So this relay makes no security
//! decisions at all — it is a pipe, and says so.
//!
//! What it does need is protection against being used as a resource sink, which
//! is what the session cap and admission rate limit below are for. It forwards
//! only to one fixed upstream and returns replies only to the sender, so it is
//! not a reflector: the amplification factor is one.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;

/// Configuration for a relay node.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Address(es) to accept client traffic on (UDP and TCP both bind here).
    pub listen_addrs: Vec<String>,
    /// Upstream target for TCP (UoT) traffic.
    pub upstream_tcp: String,
    /// Upstream target for UDP traffic.
    pub upstream_udp: String,
}

/// Maximum concurrent UDP client sessions. Each holds one upstream socket and
/// one reader task, so this bounds both file descriptors and tasks.
const MAX_UDP_SESSIONS: usize = 4096;
/// A UDP session with no traffic for this long is reclaimed. Mobile NAT
/// bindings are typically shorter-lived than this, so it is generous enough not
/// to break roaming clients.
const UDP_SESSION_IDLE: Duration = Duration::from_secs(120);
/// Maximum concurrent relayed TCP connections.
const MAX_TCP_CONNECTIONS: usize = 4096;
/// Sustained rate (and burst ceiling) for admitting NEW sessions, per second.
/// Established sessions are never rate limited; this only bounds how fast an
/// unknown source can cause state to be allocated.
const NEW_SESSION_RATE: f64 = 200.0;
/// How long to wait for the upstream TCP connection before giving up.
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(8);

/// Token bucket bounding how fast new sessions may be created.
struct AdmissionLimiter {
    tokens: f64,
    last_refill: Instant,
}

impl AdmissionLimiter {
    fn new() -> Self {
        Self { tokens: NEW_SESSION_RATE, last_refill: Instant::now() }
    }

    /// Consume one admission slot, or report that the caller should drop.
    fn try_admit(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.last_refill = now;
        self.tokens = (self.tokens + elapsed * NEW_SESSION_RATE).min(NEW_SESSION_RATE);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Entry point.
pub async fn run_relay_node(cfg: RelayConfig) -> Result<()> {
    let udp_cfg = cfg.clone();
    tokio::spawn(async move {
        if let Err(e) = run_udp_relay(udp_cfg).await {
            tracing::error!("Relay UDP loop error: {e}");
        }
    });

    run_tcp_relay(cfg).await
}

// ── UDP ──────────────────────────────────────────────────────────────────────

struct UdpSession {
    upstream: Arc<UdpSocket>,
    last_seen: Instant,
}

async fn run_udp_relay(cfg: RelayConfig) -> Result<()> {
    // client address -> the upstream socket carrying that client's flow
    let sessions: Arc<Mutex<HashMap<SocketAddr, UdpSession>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let limiter = Arc::new(Mutex::new(AdmissionLimiter::new()));

    for bind_addr in &cfg.listen_addrs {
        let sock = Arc::new(
            UdpSocket::bind(bind_addr)
                .await
                .with_context(|| format!("relay: failed to bind UDP on {bind_addr}"))?,
        );
        tracing::info!("Relay UDP listening on {bind_addr} -> {}", cfg.upstream_udp);

        let upstream_addr = cfg.upstream_udp.clone();
        let sessions = sessions.clone();
        let limiter = limiter.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let (len, peer) = match sock.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!("Relay UDP recv error: {e}");
                        continue;
                    }
                };

                // Fast path: an established session just forwards.
                {
                    let mut map = sessions.lock().await;
                    if let Some(session) = map.get_mut(&peer) {
                        session.last_seen = Instant::now();
                        let upstream = session.upstream.clone();
                        drop(map);
                        let _ = upstream.send(&buf[..len]).await;
                        continue;
                    }
                }

                // New client: bounded by both a hard cap and an admission rate,
                // so a flood of spoofed sources cannot exhaust sockets or tasks.
                {
                    let map = sessions.lock().await;
                    if map.len() >= MAX_UDP_SESSIONS {
                        continue;
                    }
                }
                if !limiter.lock().await.try_admit() {
                    continue;
                }

                let upstream = match new_upstream_socket(&upstream_addr).await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!("Relay UDP: cannot reach upstream {upstream_addr}: {e}");
                        continue;
                    }
                };

                sessions.lock().await.insert(
                    peer,
                    UdpSession { upstream: upstream.clone(), last_seen: Instant::now() },
                );

                // Send the first datagram before the reader task exists: if the
                // upstream is unreachable that task can remove the session the
                // moment it starts, so it must not be looked up again here.
                let _ = upstream.send(&buf[..len]).await;

                // Reverse direction for this client.
                let back_sock = sock.clone();
                let sessions_rx = sessions.clone();
                tokio::spawn(async move {
                    let mut rbuf = vec![0u8; 65535];
                    loop {
                        match upstream.recv(&mut rbuf).await {
                            Ok(n) => {
                                if back_sock.send_to(&rbuf[..n], peer).await.is_err() {
                                    break;
                                }
                                if let Some(s) = sessions_rx.lock().await.get_mut(&peer) {
                                    s.last_seen = Instant::now();
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    sessions_rx.lock().await.remove(&peer);
                });
            }
        });
    }

    // Reclaim idle sessions. Dropping the entry closes the upstream socket,
    // which ends that session's reader task.
    loop {
        tokio::time::sleep(Duration::from_secs(30)).await;
        let now = Instant::now();
        let mut map = sessions.lock().await;
        let before = map.len();
        map.retain(|_, s| now.duration_since(s.last_seen) < UDP_SESSION_IDLE);
        let reclaimed = before - map.len();
        if reclaimed > 0 {
            tracing::debug!("Relay UDP: reclaimed {reclaimed} idle session(s), {} active", map.len());
        }
    }
}

/// One upstream socket per client, `connect`ed so replies can be read with
/// `recv` and cannot come from anywhere else.
async fn new_upstream_socket(upstream: &str) -> Result<Arc<UdpSocket>> {
    // Resolve first, then bind the SAME address family. Binding "[::]:0" and
    // connecting to an IPv4 upstream fails anywhere IPV6_V6ONLY defaults on
    // (Windows, and many Linux configurations) — which is every deployment with
    // an IPv4 target server, i.e. the common case.
    let addr: SocketAddr = tokio::net::lookup_host(upstream)
        .await
        .with_context(|| format!("resolve upstream {upstream}"))?
        .next()
        .ok_or_else(|| anyhow::anyhow!("upstream {upstream} resolved to no addresses"))?;

    let bind: SocketAddr = if addr.is_ipv6() {
        "[::]:0".parse().expect("valid literal")
    } else {
        "0.0.0.0:0".parse().expect("valid literal")
    };

    let sock = UdpSocket::bind(bind).await?;
    sock.connect(addr)
        .await
        .with_context(|| format!("connect to upstream {addr}"))?;
    Ok(Arc::new(sock))
}

// ── TCP (UoT) ────────────────────────────────────────────────────────────────

async fn run_tcp_relay(cfg: RelayConfig) -> Result<()> {
    let live = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    for bind_addr in &cfg.listen_addrs {
        let listener = TcpListener::bind(bind_addr)
            .await
            .with_context(|| format!("relay: failed to bind TCP on {bind_addr}"))?;
        tracing::info!("Relay TCP (UoT) listening on {bind_addr} -> {}", cfg.upstream_tcp);

        let upstream = cfg.upstream_tcp.clone();
        let live = live.clone();

        tokio::spawn(async move {
            loop {
                let (client, peer) = match listener.accept().await {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!("Relay TCP accept error: {e}");
                        continue;
                    }
                };

                use std::sync::atomic::Ordering;
                if live.load(Ordering::Relaxed) >= MAX_TCP_CONNECTIONS {
                    // Close immediately rather than queueing unbounded work.
                    drop(client);
                    continue;
                }
                live.fetch_add(1, Ordering::Relaxed);

                let upstream = upstream.clone();
                let live = live.clone();
                tokio::spawn(async move {
                    if let Err(e) = splice_tcp(client, &upstream).await {
                        tracing::debug!("Relay TCP {peer} closed: {e}");
                    }
                    live.fetch_sub(1, Ordering::Relaxed);
                });
            }
        });
    }

    futures_util::future::pending::<()>().await;
    Ok(())
}

/// Splice a client connection to the upstream, byte for byte.
///
/// Nothing is parsed or rewritten: the relay must stay agnostic to the payload,
/// both because the payload is an opaque encrypted stream and because any
/// parsing would be a place for the relay to disagree with the endpoints.
async fn splice_tcp(mut client: TcpStream, upstream_addr: &str) -> Result<()> {
    let mut upstream = tokio::time::timeout(
        UPSTREAM_CONNECT_TIMEOUT,
        TcpStream::connect(upstream_addr),
    )
    .await
    .map_err(|_| anyhow::anyhow!("upstream {upstream_addr} connect timed out"))?
    .with_context(|| format!("connect to upstream {upstream_addr}"))?;

    // Both sides carry latency-sensitive framed traffic; Nagle would add delay
    // for no benefit on an already-batched stream.
    let _ = client.set_nodelay(true);
    let _ = upstream.set_nodelay(true);

    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The admission limiter is what replaced per-client authentication as the
    /// defence against resource abuse, so it has to actually stop admitting.
    #[test]
    fn admission_limiter_stops_at_the_burst_ceiling() {
        let mut limiter = AdmissionLimiter::new();
        let mut admitted = 0usize;
        // Ask for far more than one burst without letting time pass.
        for _ in 0..(NEW_SESSION_RATE as usize * 3) {
            if limiter.try_admit() {
                admitted += 1;
            }
        }
        assert!(
            admitted <= NEW_SESSION_RATE as usize + 1,
            "admitted {admitted} sessions in one instant, ceiling is {NEW_SESSION_RATE}"
        );
        assert!(admitted > 0, "limiter admitted nothing at all");
    }

    /// It must also refill, or the relay would accept a burst once and then
    /// refuse every client forever.
    #[test]
    fn admission_limiter_refills_over_time() {
        let mut limiter = AdmissionLimiter::new();
        while limiter.try_admit() {}
        assert!(!limiter.try_admit(), "bucket should be empty");

        std::thread::sleep(Duration::from_millis(50));
        assert!(
            limiter.try_admit(),
            "limiter never refilled; the relay would stop accepting new clients"
        );
    }

    /// End-to-end through the real UDP path: a client datagram reaches the
    /// upstream and the reply comes back to that same client. This is the whole
    /// job of the relay, and it is what the previous implementation could not do
    /// with a real client, because it demanded credentials no client sends.
    #[tokio::test]
    async fn udp_relay_forwards_both_directions() {
        // Stand-in upstream that echoes with a marker.
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            while let Ok((n, from)) = upstream.recv_from(&mut buf).await {
                let mut reply = b"echo:".to_vec();
                reply.extend_from_slice(&buf[..n]);
                let _ = upstream.send_to(&reply, from).await;
            }
        });

        let relay_listen = {
            let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let a = probe.local_addr().unwrap();
            drop(probe);
            a
        };

        tokio::spawn(run_udp_relay(RelayConfig {
            listen_addrs: vec![relay_listen.to_string()],
            upstream_tcp: upstream_addr.to_string(),
            upstream_udp: upstream_addr.to_string(),
        }));
        tokio::time::sleep(Duration::from_millis(150)).await;

        // A plain OSTP-looking datagram: no credentials, no preamble.
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(b"opaque-payload", relay_listen).await.unwrap();

        let mut buf = [0u8; 1500];
        let (n, _) = tokio::time::timeout(Duration::from_secs(3), client.recv_from(&mut buf))
            .await
            .expect("relay did not deliver a reply within 3s")
            .unwrap();

        assert_eq!(
            &buf[..n],
            b"echo:opaque-payload",
            "relay did not forward the payload verbatim in both directions"
        );
    }

    /// Same for TCP: bytes must cross unmodified in both directions, with no
    /// handshake demanded of the client.
    #[tokio::test]
    async fn tcp_relay_splices_both_directions() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = upstream.accept().await {
                let mut buf = [0u8; 128];
                if let Ok(n) = sock.read(&mut buf).await {
                    let mut reply = b"echo:".to_vec();
                    reply.extend_from_slice(&buf[..n]);
                    let _ = sock.write_all(&reply).await;
                }
            }
        });

        let relay_listen = {
            let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let a = probe.local_addr().unwrap();
            drop(probe);
            a
        };

        tokio::spawn(run_tcp_relay(RelayConfig {
            listen_addrs: vec![relay_listen.to_string()],
            upstream_tcp: upstream_addr.to_string(),
            upstream_udp: upstream_addr.to_string(),
        }));
        tokio::time::sleep(Duration::from_millis(150)).await;

        let mut client = TcpStream::connect(relay_listen).await.unwrap();
        client.write_all(b"opaque-stream").await.unwrap();

        let mut buf = [0u8; 128];
        let n = tokio::time::timeout(Duration::from_secs(3), client.read(&mut buf))
            .await
            .expect("relay did not deliver a reply within 3s")
            .unwrap();

        assert_eq!(&buf[..n], b"echo:opaque-stream");
    }
}
