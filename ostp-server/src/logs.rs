//! The server's log lines that name a client or a destination.
//!
//! They are all here, and all go through `ostp_core::logpriv`, so what a line
//! says in `strict`, `normal` and `debug` is decided in one place (see the
//! module documentation there). A new line that mentions a peer address or a
//! target belongs in this file.

use crate::UiEvent;
use ostp_core::logpriv::{fmt_error, fmt_ip, fmt_peer, fmt_target, is_debug};
use std::net::{IpAddr, SocketAddr};

const DISPATCHER: &str = "ostp_server::dispatcher";
const TRANSPORT: &str = "ostp_server::transport";

pub(crate) fn roamed(session_id: u32, from: SocketAddr, to: SocketAddr) {
    tracing::info!(target: DISPATCHER, "Client roamed: session {session_id} from {} to {}", fmt_peer(from), fmt_peer(to));
}

pub(crate) fn handshake_drift(drift: u64, peer: SocketAddr) {
    tracing::warn!(target: DISPATCHER, "Handshake rejected: timestamp drift {drift}s exceeds 300s limit (peer={})", fmt_peer(peer));
}

pub(crate) fn max_sessions(max: usize, peer: SocketAddr) {
    tracing::warn!(target: DISPATCHER, "Max sessions reached ({max}), rejecting handshake from {}", fmt_peer(peer));
}

pub(crate) fn over_limit(key_fp: &str, peer: SocketAddr) {
    tracing::warn!(target: DISPATCHER, "User {key_fp} exceeded traffic limit, rejecting handshake from {}", fmt_peer(peer));
}

pub(crate) fn key_expired(key_fp: &str, peer: SocketAddr) {
    tracing::warn!(target: DISPATCHER, "User {key_fp}: the key has expired, refusing the session from {}", fmt_peer(peer));
}

pub(crate) fn new_session(session_id: u32, peer: SocketAddr, v6: bool, active: usize, replay: usize) {
    tracing::info!(
        target: DISPATCHER,
        "New session authenticated: sid={session_id} peer={} v{} (active_sessions={active}, replay_cache={replay})",
        fmt_peer(peer),
        if v6 { 6 } else { 5 }
    );
}

pub(crate) fn send_failed(peer: SocketAddr, e: &std::io::Error) {
    tracing::debug!(target: TRANSPORT, "send to {} failed: {e}", fmt_peer(peer));
}

pub(crate) fn rate_limited_forwarded(real_ip: IpAddr) {
    tracing::info!(target: TRANSPORT, "rate limit: too many connections from {} (via the local web server)", fmt_ip(real_ip));
}

pub(crate) fn rate_limited(ip: IpAddr) {
    tracing::debug!(target: TRANSPORT, "TCP rate limit exceeded for {}, dropping connection", fmt_ip(ip));
}

pub(crate) fn too_many_unclassified(peer: SocketAddr) {
    tracing::debug!(target: TRANSPORT, "too many unclassified TCP connections, dropping {}", fmt_peer(peer));
}

pub(crate) fn connection_closed(peer: SocketAddr, e: &dyn std::fmt::Display) {
    tracing::debug!(target: TRANSPORT, "TCP connection from {} closed: {e}", fmt_peer(peer));
}

pub(crate) fn tls_failed(peer: SocketAddr, e: &dyn std::fmt::Display) {
    tracing::debug!(target: TRANSPORT, "TLS handshake from {} failed: {e}", fmt_peer(peer));
}

pub(crate) fn too_many_unauthenticated(ip: IpAddr) {
    tracing::debug!(target: TRANSPORT, "too many unauthenticated connections from {}, dropping", fmt_ip(ip));
}

pub(crate) fn upgrade_from(forwarded: Option<IpAddr>, peer: SocketAddr) {
    tracing::debug!(
        target: TRANSPORT,
        "UoT upgrade from {} (via {})",
        fmt_ip(forwarded.unwrap_or(peer.ip())),
        fmt_peer(peer)
    );
}

pub(crate) fn uot_connected(peer: SocketAddr) {
    tracing::debug!(target: TRANSPORT, "UoT client connected from {}", fmt_peer(peer));
}

pub(crate) fn uot_idle(peer: SocketAddr, limit: std::time::Duration) {
    tracing::debug!(target: TRANSPORT, "UoT client {} idle or unauthenticated for {limit:?}, closing", fmt_peer(peer));
}

pub(crate) fn uot_disconnected(peer: SocketAddr) {
    tracing::debug!(target: TRANSPORT, "UoT client disconnected: {}", fmt_peer(peer));
}

pub(crate) fn relay_tcp_closed(peer: SocketAddr, e: &dyn std::fmt::Display) {
    tracing::debug!(target: "ostp_server::relay_node", "Relay TCP {} closed: {e}", fmt_peer(peer));
}

pub(crate) fn unauthorized_probe(peer: IpAddr, bytes: usize) {
    tracing::debug!(target: "ostp_server", "Unauthorized probe from {} ({bytes} bytes)", fmt_ip(peer));
}

pub(crate) fn relay_rejected(session_id: u32, stream_id: u32, e: &anyhow::Error) {
    // The reasons name the target a client asked for ("10.0.0.1:80: closed to clients").
    tracing::debug!(target: "ostp_server::relay", "relay message [{session_id}:{stream_id}] rejected: {}", fmt_error(&format!("{e:#}")));
}

// Events for the headless logger in `run_server`. `Info` always reaches the log;
// `Log` only in `debug` (and never carries more than `debug` may show).

pub(crate) fn client_connected(ip: IpAddr, proto: &str) -> UiEvent {
    UiEvent::Info(format!("Client {} connected via {proto}", fmt_ip(ip)))
}

pub(crate) fn client_timeout(ip: IpAddr) -> UiEvent {
    UiEvent::Info(format!("Client {} disconnected (timeout)", fmt_ip(ip)))
}

pub(crate) fn protocol_error(peer: SocketAddr, err: &dyn std::fmt::Display) -> UiEvent {
    UiEvent::Log(format!("Protocol error for {}: {err}", fmt_peer(peer)))
}

pub(crate) fn no_app_payloads(ip: IpAddr, responses: usize) -> UiEvent {
    UiEvent::Log(format!("Accepted datagrams from {} with no app payloads (responses={responses})", fmt_ip(ip)))
}

pub(crate) fn connect_ok(session_id: u32, stream_id: u32, target: &str) -> UiEvent {
    UiEvent::Log(format!("Relay CONNECT ok for [{session_id}:{stream_id}] -> {}", fmt_target(target)))
}

/// A connect the server could not make. Always logged; `normal` and `strict`
/// say which stream and what kind of failure, not where to.
pub(crate) fn connect_failed(session_id: u32, stream_id: u32, target: &str, err: &str) -> UiEvent {
    if is_debug() {
        UiEvent::Info(format!("Relay error: CONNECT failed for [{session_id}:{stream_id}] -> {target}: {err}"))
    } else {
        UiEvent::Info(format!("Relay error: CONNECT failed for stream [{session_id}:{stream_id}]: {}", fmt_error(err)))
    }
}

/// The client reported an error on a stream; its text can name a target.
pub(crate) fn client_stream_error(session_id: u32, stream_id: u32, msg: &str) -> UiEvent {
    if is_debug() {
        UiEvent::Info(format!("Relay error from [{session_id}:{stream_id}]: {msg}"))
    } else {
        UiEvent::Info(format!("Relay error from [{session_id}:{stream_id}]: {}", fmt_error(msg)))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ostp_core::logpriv::{set_privacy, Privacy};
    use std::sync::{Arc, Mutex};

    /// The privacy mode is one per process: tests that set it take this lock.
    pub(crate) static MODE_LOCK: Mutex<()> = Mutex::new(());

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Capture {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
        type Writer = Capture;
        fn make_writer(&'a self) -> Capture {
            self.clone()
        }
    }

    /// Everything `f` logs, at debug level and above, in the format of the real log.
    fn captured(f: impl FnOnce()) -> String {
        let cap = Capture::default();
        let sub = tracing_subscriber::fmt()
            .with_writer(cap.clone())
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .without_time()
            .finish();
        tracing::subscriber::with_default(sub, f);
        let bytes = cap.0.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap()
    }

    const IP: &str = "203.0.113.77";
    const TARGET: &str = "secret-site.example:443";

    fn run_all() -> String {
        let peer: SocketAddr = format!("{IP}:40123").parse().unwrap();
        let other: SocketAddr = "198.51.100.200:5000".parse().unwrap();
        let ip: IpAddr = IP.parse().unwrap();
        // Errors of the client's own socket do not carry a destination.
        let io_err = std::io::Error::other("connection reset by peer");
        captured(|| {
            roamed(7, peer, other);
            handshake_drift(900, peer);
            max_sessions(100, peer);
            over_limit("a1b2c3", peer);
            new_session(7, peer, true, 3, 9);
            send_failed(peer, &io_err);
            rate_limited_forwarded(ip);
            rate_limited(ip);
            too_many_unclassified(peer);
            connection_closed(peer, &io_err);
            tls_failed(peer, &io_err);
            too_many_unauthenticated(ip);
            upgrade_from(Some(ip), peer);
            uot_connected(peer);
            uot_idle(peer, std::time::Duration::from_secs(5));
            uot_disconnected(peer);
            relay_tcp_closed(peer, &io_err);
            unauthorized_probe(ip, 64);
            relay_rejected(7, 1, &anyhow::anyhow!("{TARGET}: closed to clients"));
            for ev in [
                client_connected(ip, "UDP"),
                client_timeout(ip),
                protocol_error(peer, &"bad frame"),
                no_app_payloads(ip, 2),
                connect_ok(7, 1, TARGET),
                connect_failed(7, 1, TARGET, &format!("{TARGET}: no addresses for {TARGET}")),
                connect_failed(7, 2, TARGET, "connect to 192.0.2.55:443 timed out"),
                client_stream_error(7, 1, &format!("connect failed: {TARGET} refused")),
            ] {
                match ev {
                    UiEvent::Info(m) | UiEvent::Log(m) => tracing::info!("{m}"),
                    _ => unreachable!(),
                }
            }
        })
    }

    #[test]
    fn normal_and_strict_write_no_destination_and_no_full_address() {
        let _g = MODE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        for mode in [Privacy::Normal, Privacy::Strict] {
            set_privacy(mode);
            let out = run_all();
            set_privacy(Privacy::Normal);
            assert!(!out.is_empty());
            for secret in ["secret-site", "443", "203.0.113.77", "198.51.100.200", "192.0.2.55", "40123", "5000"] {
                assert!(!out.contains(secret), "{mode:?} wrote {secret}:\n{out}");
            }
            // The failure itself is still reported.
            assert!(out.contains("CONNECT failed for stream [7:1]: name not resolved"), "{out}");
            assert!(out.contains("CONNECT failed for stream [7:2]: timed out"), "{out}");
        }
    }

    #[test]
    fn normal_keeps_the_network_and_strict_a_tag() {
        let _g = MODE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        set_privacy(Privacy::Normal);
        let out = run_all();
        assert!(out.contains("203.0.113.0/24"), "{out}");
        set_privacy(Privacy::Strict);
        let out = run_all();
        set_privacy(Privacy::Normal);
        assert!(out.contains("peer-") && !out.contains("/24"), "{out}");
    }

    #[test]
    fn debug_writes_everything() {
        let _g = MODE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        set_privacy(Privacy::Debug);
        let out = run_all();
        set_privacy(Privacy::Normal);
        assert!(out.contains("203.0.113.77:40123") && out.contains(TARGET), "{out}");
    }
}
