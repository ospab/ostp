//! The client's log lines that name a destination.
//!
//! They all go through `ostp_core::logpriv`: in `normal` and `strict` a line
//! says what happened (a stream opened, a connection bypassed) and not where
//! to; `debug` adds the destination. A new line that mentions a target, a
//! name from a TLS hello or a remote address belongs in this file.

use ostp_core::logpriv::{fmt_error, is_debug};
use std::fmt::Display;
use std::net::SocketAddr;

const TUNNEL: &str = "ostp_client::tunnel";

/// ` target=...` in `debug`, nothing otherwise.
fn target_suffix(target: impl Display) -> String {
    if is_debug() { format!(" target={target}") } else { String::new() }
}

/// `: ...` in `debug`, nothing otherwise.
fn detail(d: impl Display) -> String {
    if is_debug() { format!(": {d}") } else { String::new() }
}

// The text of a UI event (the log screen of the apps, `[ostp]` lines of the CLI).

pub(crate) fn ui_proxy_connect(stream_id: u32, target: &str) -> String {
    format!("Proxy CONNECT stream_id={stream_id}{}", target_suffix(target))
}

/// What the server answered to a stream: its text can name the target.
pub(crate) fn ui_relay_error(stream_id: u32, msg: &str) -> String {
    format!("Relay error for stream {stream_id}: {}", fmt_error(msg))
}

// The local proxy.

pub(crate) fn proxy_connect(stream_id: u32, target: &str) {
    tracing::info!(target: TUNNEL, "proxy CONNECT stream_id={stream_id}{}", target_suffix(target));
}

pub(crate) fn proxy_connect_request(stream_id: u32, target: &str) {
    tracing::debug!(target: TUNNEL, "proxy CONNECT stream_id={stream_id}{}", target_suffix(target));
}

pub(crate) fn proxy_bypass(stream_id: u32, target: &str) {
    tracing::info!(target: TUNNEL, "proxy BYPASS stream_id={stream_id}{}", target_suffix(target));
}

pub(crate) fn udp_bypass(target: &str) {
    tracing::debug!(target: TUNNEL, "proxy UDP BYPASS{}", target_suffix(target));
}

pub(crate) fn udp_send_failed(target: SocketAddr, e: &dyn Display) {
    tracing::warn!(target: TUNNEL, "failed to send bypass UDP packet{}: {}", target_suffix(target), fmt_error(&e.to_string()));
}

pub(crate) fn udp_forward(target: &str, len: usize) {
    tracing::debug!(target: TUNNEL, "proxy forwarding UDP DATA to server{} payload len={len}", target_suffix(target));
}

pub(crate) fn udp_reply(target: &str, len: usize) {
    tracing::debug!(target: TUNNEL, "proxy forwarding UDP REPLY from server{} payload len={len}", target_suffix(target));
}

pub(crate) fn bad_target(target: &str) {
    tracing::error!(target: TUNNEL, "proxy failed to parse a UDP target as SocketAddr{}", target_suffix(target));
}

// The TUN stack.

pub(crate) fn tun_tcp(local: impl Display, remote: impl Display) {
    tracing::debug!(target: TUNNEL, "TUN TCP{}", detail(format_args!("{local} → {remote}")));
}

pub(crate) fn tun_bypass_process(name: &str, local: impl Display, remote: impl Display) {
    tracing::info!(target: TUNNEL, "TUN TCP BYPASS (process {name}){}", detail(format_args!("{local} → {remote}")));
}

pub(crate) fn tun_sni(sni: &str) {
    tracing::debug!(target: TUNNEL, "TUN SNI{}", detail(sni));
}

pub(crate) fn tun_bypass_sni(sni: &str, remote: impl Display) {
    tracing::info!(target: TUNNEL, "TUN TCP BYPASS (SNI domain){}", detail(format_args!("{sni} → {remote}")));
}

pub(crate) fn tun_bypass_ip(remote: impl Display) {
    tracing::info!(target: TUNNEL, "TUN TCP BYPASS (IP match){}", detail(remote));
}

pub(crate) fn bypass_connect_failed(remote: impl Display) {
    tracing::debug!(target: TUNNEL, "Direct bypass connect failed{}", detail(remote));
}

pub(crate) fn preresolve_failed(domain: &str, e: &dyn Display) {
    tracing::warn!(target: TUNNEL, "Failed to pre-resolve an excluded domain{}: {}", detail(domain), fmt_error(&e.to_string()));
}

pub(crate) fn udp_nat_bypass_ip(src: impl Display, dst: impl Display) {
    tracing::info!(target: TUNNEL, "TUN UDP BYPASS (IP match){}", detail(format_args!("{src} → {dst}")));
}

pub(crate) fn udp_nat_bypass_process(name: &str, src: impl Display, dst: impl Display) {
    tracing::info!(target: TUNNEL, "TUN UDP BYPASS (process {name}){}", detail(format_args!("{src} → {dst}")));
}

pub(crate) fn udp_session_ended(what: &str, src: impl Display, outcome: &str) {
    tracing::debug!(target: TUNNEL, "{what} session for {src} ended: {}", fmt_error(outcome));
}

pub(crate) fn udp_nat_send(len: usize, relay: impl Display, dst: impl Display) {
    tracing::debug!(target: TUNNEL, "udp_nat SENDING UDP ASSOCIATE payload len={len} to relay_addr={relay}{}", detail(format_args!("original dst {dst}")));
}

pub(crate) fn udp_nat_reply(remote_dst: impl Display, client_src: impl Display, len: usize) {
    tracing::debug!(target: TUNNEL, "udp_nat RECEIVED UDP ASSOCIATE REPLY for {client_src} len={len}{}", detail(format_args!("from {remote_dst}")));
}

pub(crate) fn udp_nat_injected(remote_dst: impl Display, client_src: impl Display) {
    tracing::debug!(target: TUNNEL, "udp_nat injected a packet into smoltcp for {client_src}{}", detail(format_args!("from {remote_dst}")));
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

    const DEST: &str = "secret-site.example:443";
    const SNI: &str = "secret-site.example";
    const REMOTE: &str = "192.0.2.55:443";

    fn run_all() -> String {
        let cap = Capture::default();
        let sub = tracing_subscriber::fmt()
            .with_writer(cap.clone())
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .without_time()
            .finish();
        let target_addr: SocketAddr = REMOTE.parse().unwrap();
        let io_err = std::io::Error::other(format!("failed to resolve {SNI}"));
        let mut ui = Vec::new();
        tracing::subscriber::with_default(sub, || {
            ui.push(ui_proxy_connect(5, DEST));
            ui.push(ui_relay_error(5, &format!("connect failed: {DEST}: no addresses for {SNI}")));
            proxy_connect(5, DEST);
            proxy_connect_request(5, DEST);
            proxy_bypass(6, DEST);
            udp_bypass(DEST);
            udp_send_failed(target_addr, &io_err);
            udp_forward(DEST, 100);
            udp_reply(DEST, 100);
            bad_target(DEST);
            tun_tcp("10.1.0.2:50000", REMOTE);
            tun_bypass_process("browser.exe", "10.1.0.2:50000", REMOTE);
            tun_sni(SNI);
            tun_bypass_sni(SNI, REMOTE);
            tun_bypass_ip(REMOTE);
            bypass_connect_failed(REMOTE);
            preresolve_failed(SNI, &io_err);
            udp_nat_bypass_ip("10.1.0.2:50000", REMOTE);
            udp_nat_bypass_process("browser.exe", "10.1.0.2:50000", REMOTE);
            udp_session_ended("UDP BYPASS", "10.1.0.2:50000", &format!("Some(connect to {REMOTE} failed)"));
            udp_nat_send(10, "10.1.0.1:9", REMOTE);
            udp_nat_reply(REMOTE, "10.1.0.2:50000", 10);
            udp_nat_injected(REMOTE, "10.1.0.2:50000");
        });
        let mut out = String::from_utf8(cap.0.lock().unwrap().clone()).unwrap();
        out.push_str(&ui.join("\n"));
        out
    }

    #[test]
    fn normal_and_strict_write_no_destination() {
        let _g = MODE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        for mode in [Privacy::Normal, Privacy::Strict] {
            set_privacy(mode);
            let out = run_all();
            set_privacy(Privacy::Normal);
            assert!(out.contains("proxy CONNECT stream_id=5"), "{out}");
            for secret in ["secret-site", "192.0.2.55", ":443", "443"] {
                assert!(!out.contains(secret), "{mode:?} wrote {secret}:\n{out}");
            }
        }
    }

    #[test]
    fn debug_writes_the_destination() {
        let _g = MODE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        set_privacy(Privacy::Debug);
        let out = run_all();
        set_privacy(Privacy::Normal);
        assert!(out.contains(DEST) && out.contains(REMOTE) && out.contains(SNI), "{out}");
    }
}
