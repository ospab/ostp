//! Queue diagnostics on the server, off by default (`OSTP_DIAG=1`, see
//! `ostp_core::diag`). Once a second:
//!
//! - per TCP/TLS connection (`conn N`): frames in its carrier channel, the
//!   measured drain rate and the target size of that channel, what the writer
//!   wrote and how long it was blocked in `write`, what the reader read, and
//!   the kernel's socket queues (`SIOCOUTQ`, `SIOCOUTQNSD`, `SIOCINQ`,
//!   `SO_SNDBUF`, `TCP_INFO`);
//! - per session: the congestion window, frames in flight, the send budget
//!   and the readers' gate, and what was resent and why.
//!
//! No address is written: a connection is a local number, a session its id.

use ostp_core::diag::{Counters, MachineDiag};
use portable_atomic::AtomicU64;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

pub fn enabled() -> bool {
    ostp_core::diag::enabled()
}

struct Conn {
    id: u64,
    fd: Option<i32>,
}

static NEXT_CONN: AtomicU64 = AtomicU64::new(1);
static CONNS: LazyLock<Mutex<HashMap<SocketAddr, Conn>>> = LazyLock::new(Default::default);

/// A TCP connection was accepted from `peer`; `fd` is its socket.
pub fn accepted(peer: SocketAddr, fd: Option<i32>) {
    if !enabled() {
        return;
    }
    let id = NEXT_CONN.fetch_add(1, Ordering::Relaxed);
    CONNS.lock().unwrap_or_else(|e| e.into_inner()).insert(peer, Conn { id, fd });
}

/// The connection from `peer` is closed.
pub fn closed(peer: SocketAddr) {
    if !enabled() {
        return;
    }
    CONNS.lock().unwrap_or_else(|e| e.into_inner()).remove(&peer);
}

/// The UoT connection from `peer` ended; `why` says which half ended it.
pub fn conn_ended(peer: SocketAddr, why: &str) {
    if !enabled() {
        return;
    }
    let id = conn_of(peer).map_or(0, |(id, _)| id);
    let sock = conn_of(peer)
        .and_then(|(_, fd)| fd)
        .and_then(ostp_core::diag::sock_stats)
        .map(|s| s.line())
        .unwrap_or_default();
    tracing::info!(target: "ostp_diag", "conn {id}: UoT connection ended by its {why} | {sock}");
}

fn conn_of(peer: SocketAddr) -> Option<(u64, Option<i32>)> {
    CONNS.lock().unwrap_or_else(|e| e.into_inner()).get(&peer).map(|c| (c.id, c.fd))
}

/// What one UoT connection's writer and reader did.
#[derive(Default)]
pub struct ConnStats {
    frames_out: AtomicU64,
    bytes_out: AtomicU64,
    write_ns: AtomicU64,
    write_max_ns: AtomicU64,
    frames_in: AtomicU64,
    bytes_in: AtomicU64,
}

impl ConnStats {
    pub fn wrote(&self, bytes: usize, took: Duration) {
        self.frames_out.fetch_add(1, Ordering::Relaxed);
        self.bytes_out.fetch_add(bytes as u64, Ordering::Relaxed);
        let ns = took.as_nanos() as u64;
        self.write_ns.fetch_add(ns, Ordering::Relaxed);
        self.write_max_ns.fetch_max(ns, Ordering::Relaxed);
    }

    pub fn read(&self, bytes: usize) {
        self.frames_in.fetch_add(1, Ordering::Relaxed);
        self.bytes_in.fetch_add(bytes as u64, Ordering::Relaxed);
    }
}

/// Starts the once-a-second line of the UoT connection from `peer`. `queued`
/// tells how many frames wait in its carrier channel. Abort the handle when
/// the connection ends.
pub fn start_conn_log(
    peer: SocketAddr,
    stats: Arc<ConnStats>,
    drain: Arc<crate::carrier_queue::Drain>,
    queued: impl Fn() -> Option<usize> + Send + 'static,
) -> Option<tokio::task::AbortHandle> {
    if !enabled() {
        return None;
    }
    let started = Instant::now();
    let task = tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let (mut fo, mut bo, mut wns, mut fi, mut bi) = (0u64, 0u64, 0u64, 0u64, 0u64);
        loop {
            tick.tick().await;
            let (id, fd) = conn_of(peer).unwrap_or((0, None));
            let f_out = stats.frames_out.load(Ordering::Relaxed);
            let b_out = stats.bytes_out.load(Ordering::Relaxed);
            let w_ns = stats.write_ns.load(Ordering::Relaxed);
            let w_max = stats.write_max_ns.swap(0, Ordering::Relaxed);
            let f_in = stats.frames_in.load(Ordering::Relaxed);
            let b_in = stats.bytes_in.load(Ordering::Relaxed);
            let sock = fd.and_then(ostp_core::diag::sock_stats).map(|s| s.line()).unwrap_or_else(|| "no socket stats".into());
            tracing::info!(
                target: "ostp_diag",
                "conn {id} t={}s chan={} target={} drain={}kB/s drops_total={} | out {} fr {} kB write {} ms (max {} ms) | \
                 in {} fr {} kB | {sock}",
                started.elapsed().as_secs(),
                queued().map_or("-".to_string(), |q| q.to_string()),
                drain.target_frames(),
                drain.rate() / 1000,
                crate::tcp_queue_drops(),
                f_out - fo,
                (b_out - bo) / 1000,
                (w_ns - wns) / 1_000_000,
                w_max / 1_000_000,
                f_in - fi,
                (b_in - bi) / 1000,
            );
            (fo, bo, wns, fi, bi) = (f_out, b_out, w_ns, f_in, b_in);
        }
    });
    Some(task.abort_handle())
}

static LAST_SESSION_LOG: LazyLock<Mutex<(Option<Instant>, HashMap<u32, Counters>)>> = LazyLock::new(Default::default);

/// Called on every tick of the packet loop; writes the session lines once a
/// second. `gate` is each session's readers' budget as last published.
pub fn sessions_tick(sessions: Vec<(u32, SocketAddr, MachineDiag)>, gate: impl Fn(u32) -> Option<i64>) {
    if !enabled() {
        return;
    }
    let mut last = LAST_SESSION_LOG.lock().unwrap_or_else(|e| e.into_inner());
    let now = Instant::now();
    if last.0.is_some_and(|t| now.duration_since(t) < Duration::from_secs(1)) {
        return;
    }
    last.0 = Some(now);
    let mut seen = HashMap::new();
    for (sid, addr, d) in sessions {
        let before = last.1.get(&sid).copied().unwrap_or_default();
        let conn = conn_of(addr).map_or("udp/none".to_string(), |(id, _)| format!("conn {id}"));
        tracing::info!(
            target: "ostp_diag",
            "session {sid} ({conn}) gate={} {}",
            gate(sid).map_or("-".to_string(), |g| g.to_string()),
            d.line(&before)
        );
        seen.insert(sid, d.counters);
    }
    last.1 = seen;
}
