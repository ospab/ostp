//! Queue diagnostics, off by default: `OSTP_DIAG=1` in the environment turns
//! them on. Then the server and the client write one line a second per
//! TCP/TLS connection and per session (target `ostp_diag`, level `info`): what
//! is queued where (the carrier channel, the kernel's socket buffer), what the
//! congestion controller allows, and what was resent and why.
//!
//! The lines carry no address and no destination: connection numbers are
//! counted locally, session ids are the protocol's own random ids.

use std::sync::LazyLock;

static ENABLED: LazyLock<bool> =
    LazyLock::new(|| std::env::var("OSTP_DIAG").is_ok_and(|v| !v.is_empty() && v != "0"));

/// Whether `OSTP_DIAG` asks for the diagnostic lines.
pub fn enabled() -> bool {
    *ENABLED
}

/// Counters a `ProtocolMachine` keeps for the diagnostics (cumulative).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counters {
    /// New retransmittable frames sent.
    pub data_sent: u64,
    /// Frames acknowledged (left the history acknowledged).
    pub acked: u64,
    /// Resent by the retransmit timer.
    pub resent_timer: u64,
    /// Resent because they were in flight before the session moved
    /// (`on_path_change`), reliable carrier only.
    pub resent_path: u64,
    /// Resent because the peer NACKed them.
    pub resent_nack: u64,
    /// Resent as a stall's tail probe (datagram carrier only).
    pub resent_probe: u64,
    /// `on_path_change` calls, all of them.
    pub path_changes: u64,
    /// Of those, the ones made because the peer was heard again after
    /// `OUTAGE_SILENCE` of silence with data in flight.
    pub outage_path_changes: u64,
    /// NACKs this side sent.
    pub nacks_sent: u64,
    /// Frames given up (zombie eviction or pushed out of the history).
    pub given_up: u64,
    /// Authenticated datagrams received.
    pub recv: u64,
}

impl Counters {
    /// What changed since `before`.
    pub fn since(&self, before: &Counters) -> Counters {
        Counters {
            data_sent: self.data_sent.wrapping_sub(before.data_sent),
            acked: self.acked.wrapping_sub(before.acked),
            resent_timer: self.resent_timer.wrapping_sub(before.resent_timer),
            resent_path: self.resent_path.wrapping_sub(before.resent_path),
            resent_nack: self.resent_nack.wrapping_sub(before.resent_nack),
            resent_probe: self.resent_probe.wrapping_sub(before.resent_probe),
            path_changes: self.path_changes.wrapping_sub(before.path_changes),
            outage_path_changes: self.outage_path_changes.wrapping_sub(before.outage_path_changes),
            nacks_sent: self.nacks_sent.wrapping_sub(before.nacks_sent),
            given_up: self.given_up.wrapping_sub(before.given_up),
            recv: self.recv.wrapping_sub(before.recv),
        }
    }
}

/// A snapshot of one session's sending side.
#[derive(Debug, Clone, Copy, Default)]
pub struct MachineDiag {
    pub reliable: bool,
    pub cwnd_packets: usize,
    pub in_flight: usize,
    pub bytes_in_flight: u64,
    pub history: usize,
    pub srtt_ms: u64,
    pub min_rtt_ms: u64,
    pub rto_ms: u64,
    /// `send_budget` over 10 ms.
    pub budget_10ms: usize,
    pub pacing_kbps: u64,
    /// Since the peer was last heard (authenticated), ms; `u64::MAX` never.
    pub heard_ago_ms: u64,
    pub reorder_buffered: usize,
    pub counters: Counters,
}

impl MachineDiag {
    /// One line: the state now and the counters' change since `before`.
    pub fn line(&self, before: &Counters) -> String {
        let d = self.counters.since(before);
        let heard = if self.heard_ago_ms == u64::MAX { "never".to_string() } else { format!("{}ms", self.heard_ago_ms) };
        format!(
            "reliable={} cwnd={} inflight={} ({} kB) hist={} srtt={}ms minrtt={}ms rto={}ms budget10ms={} pace={}kbit/s \
             heard={} reorder={} | 1s: sent={} acked={} recv={} resent timer={} path={} nack={} probe={} \
             pathchg={} (outage {}) nacks_out={} given_up={}",
            self.reliable as u8,
            self.cwnd_packets,
            self.in_flight,
            self.bytes_in_flight / 1000,
            self.history,
            self.srtt_ms,
            self.min_rtt_ms,
            self.rto_ms,
            self.budget_10ms,
            self.pacing_kbps,
            heard,
            self.reorder_buffered,
            d.data_sent,
            d.acked,
            d.recv,
            d.resent_timer,
            d.resent_path,
            d.resent_nack,
            d.resent_probe,
            d.path_changes,
            d.outage_path_changes,
            d.nacks_sent,
            d.given_up,
        )
    }
}

/// A TCP socket's queues as the kernel sees them (Linux).
#[derive(Debug, Clone, Copy, Default)]
pub struct SockStats {
    /// Bytes in the send queue: unsent and sent-but-unacknowledged (SIOCOUTQ).
    pub outq: u32,
    /// Of those, not yet sent (SIOCOUTQNSD).
    pub notsent: u32,
    /// Bytes received and not yet read by the process (SIOCINQ).
    pub inq: u32,
    pub sndbuf: u32,
    pub rcvbuf: u32,
    /// From TCP_INFO (0 where the kernel did not fill the field).
    pub rtt_ms: u32,
    pub rttvar_ms: u32,
    pub snd_cwnd: u32,
    pub unacked: u32,
    pub lost: u32,
    pub retrans: u32,
    pub total_retrans: u32,
    pub backoff: u8,
    pub ca_state: u8,
    pub snd_wnd: u32,
    pub rcv_space: u32,
    pub bytes_retrans: u64,
    pub rwnd_limited_ms: u64,
    pub sndbuf_limited_ms: u64,
    pub busy_ms: u64,
    /// Since the last data segment / ACK came in from the peer, ms.
    pub last_data_recv_ms: u32,
    pub last_ack_recv_ms: u32,
}

impl SockStats {
    pub fn line(&self) -> String {
        format!(
            "outq={} notsent={} inq={} sndbuf={} rcvbuf={} | tcp rtt={}ms var={}ms cwnd={} unacked={} lost={} \
             retrans={} total_retrans={} bytes_retrans={} backoff={} ca={} snd_wnd={} rcv_space={} \
             last_data_in={}ms last_ack_in={}ms busy={}ms rwnd_lim={}ms sndbuf_lim={}ms",
            self.outq,
            self.notsent,
            self.inq,
            self.sndbuf,
            self.rcvbuf,
            self.rtt_ms,
            self.rttvar_ms,
            self.snd_cwnd,
            self.unacked,
            self.lost,
            self.retrans,
            self.total_retrans,
            self.bytes_retrans,
            self.backoff,
            self.ca_state,
            self.snd_wnd,
            self.rcv_space,
            self.last_data_recv_ms,
            self.last_ack_recv_ms,
            self.busy_ms,
            self.rwnd_limited_ms,
            self.sndbuf_limited_ms,
        )
    }
}

/// The queues of the TCP socket `fd` (Linux, Android); `None` elsewhere or on
/// an error (a closed socket).
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn sock_stats(fd: i32) -> Option<SockStats> {
    // From linux/sockios.h; the same numbers on every architecture.
    const SIOCINQ: libc::c_ulong = 0x541B;
    const SIOCOUTQ: libc::c_ulong = 0x5411;
    const SIOCOUTQNSD: libc::c_ulong = 0x894B;

    fn ioctl_int(fd: i32, req: libc::c_ulong) -> Option<u32> {
        let mut v: libc::c_int = 0;
        // SAFETY: the request writes one int into `v`; a bad fd returns -1.
        let r = unsafe { libc::ioctl(fd, req as _, &mut v as *mut libc::c_int) };
        (r == 0).then_some(v.max(0) as u32)
    }
    fn sockopt_int(fd: i32, level: i32, name: i32) -> u32 {
        let mut v: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: `v` and `len` describe a buffer of one int.
        let r = unsafe { libc::getsockopt(fd, level, name, &mut v as *mut _ as *mut libc::c_void, &mut len) };
        if r == 0 { v.max(0) as u32 } else { 0 }
    }

    let mut s = SockStats {
        outq: ioctl_int(fd, SIOCOUTQ)?,
        notsent: ioctl_int(fd, SIOCOUTQNSD).unwrap_or(0),
        inq: ioctl_int(fd, SIOCINQ).unwrap_or(0),
        sndbuf: sockopt_int(fd, libc::SOL_SOCKET, libc::SO_SNDBUF),
        rcvbuf: sockopt_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF),
        ..Default::default()
    };

    // struct tcp_info, read as bytes: the kernel fills as much as it has, and
    // the layout below is fixed (only ever extended at the end).
    let mut buf = [0u8; 256];
    let mut len = buf.len() as libc::socklen_t;
    // SAFETY: `buf` is `len` bytes long; the kernel writes at most that.
    let r = unsafe {
        libc::getsockopt(fd, libc::IPPROTO_TCP, libc::TCP_INFO, buf.as_mut_ptr() as *mut libc::c_void, &mut len)
    };
    if r == 0 {
        let len = len as usize;
        let u8_at = |o: usize| if o < len { buf[o] } else { 0 };
        let u32_at = |o: usize| {
            if o + 4 <= len { u32::from_ne_bytes([buf[o], buf[o + 1], buf[o + 2], buf[o + 3]]) } else { 0 }
        };
        let u64_at = |o: usize| {
            if o + 8 <= len {
                let mut b = [0u8; 8];
                b.copy_from_slice(&buf[o..o + 8]);
                u64::from_ne_bytes(b)
            } else {
                0
            }
        };
        s.ca_state = u8_at(1);
        s.backoff = u8_at(4);
        s.unacked = u32_at(24);
        s.last_data_recv_ms = u32_at(52);
        s.last_ack_recv_ms = u32_at(56);
        s.lost = u32_at(32);
        s.retrans = u32_at(36);
        s.rtt_ms = u32_at(68) / 1000;
        s.rttvar_ms = u32_at(72) / 1000;
        s.snd_cwnd = u32_at(80);
        s.rcv_space = u32_at(96);
        s.total_retrans = u32_at(100);
        s.busy_ms = u64_at(168) / 1000;
        s.rwnd_limited_ms = u64_at(176) / 1000;
        s.sndbuf_limited_ms = u64_at(184) / 1000;
        s.bytes_retrans = u64_at(208);
        s.snd_wnd = u32_at(228);
    }
    Some(s)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn sock_stats(_fd: i32) -> Option<SockStats> {
    None
}
