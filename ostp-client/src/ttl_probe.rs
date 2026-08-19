//! Lightweight "how many hops to the server" probe, for auto-calibrating the
//! TTL-desync decoys — without pulling in the full ostp-prober, and without any
//! new server code or exposed port.
//!
//! The trick: the OSTP server answers only a *valid* handshake and silently
//! drops everything else. So we send the real handshake datagram with a rising
//! IP TTL and watch for the first TTL that draws a reply. A datagram whose TTL
//! is too low dies on a router before the server and creates no state there;
//! only the TTL that actually reaches the server elicits a response. That first
//! responding TTL is the hop distance to the server.
//!
//! This is inherently key-gated (no key → no valid handshake → no reply, so an
//! unauthenticated caller learns nothing) and rides the existing UDP port, which
//! is exactly the "works for key holders, no prober-server, no extra ports"
//! property we want. Decoys are then sent at `hops - 1`, so they clear the DPI
//! (which sits far closer than the server) yet die before the server.

use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;

/// Upper bound on the hop sweep. Beyond ~30 the internet does not go, and a
/// server we cannot reach within that many hops is unreachable for other
/// reasons the caller will already be handling.
const MAX_HOPS: u8 = 30;
/// Per-TTL wait for a reply. Kept short so the whole sweep is quick; each TTL is
/// tried a couple of times to ride out isolated loss.
const PER_TTL_TIMEOUT: Duration = Duration::from_millis(400);
const SENDS_PER_TTL: usize = 2;

/// Measure the hop distance to `server` by sweeping the TTL of `handshake`.
///
/// `make_handshake` is called once per TTL step to produce a fresh handshake
/// datagram — fresh because the server's anti-replay cache drops a repeat of the
/// same (session id, timestamp), so each probe must be distinct to be answered.
/// Returns the first TTL that drew a reply, or None if none did within MAX_HOPS.
pub async fn measure_hops<F>(server: SocketAddr, mut make_handshake: F) -> Option<u8>
where
    F: FnMut() -> Vec<u8>,
{
    let bind: SocketAddr = if server.is_ipv6() {
        "[::]:0".parse().ok()?
    } else {
        "0.0.0.0:0".parse().ok()?
    };
    let sock = UdpSocket::bind(bind).await.ok()?;
    sock.connect(server).await.ok()?;

    let mut buf = [0u8; 2048];
    for ttl in 1..=MAX_HOPS {
        if sock.set_ttl(ttl as u32).is_err() {
            continue;
        }
        for _ in 0..SENDS_PER_TTL {
            let frame = make_handshake();
            let _ = sock.send(&frame).await;
        }
        match tokio::time::timeout(PER_TTL_TIMEOUT, sock.recv(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => return Some(ttl),
            _ => {}
        }
    }
    None
}

/// Given a measured server distance, the TTL to stamp on decoys: one hop short
/// of the server, so they die before it, and clamped to at least 1.
pub fn decoy_ttl_for(server_hops: u8) -> u8 {
    server_hops.saturating_sub(1).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Against a local responder, the very first TTL reaches it (localhost is
    /// zero routers away), so the sweep returns 1 — exercising the "first reply
    /// wins" path end to end over a real socket.
    #[tokio::test]
    async fn measures_against_a_local_responder() {
        let responder = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = responder.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 512];
            while let Ok((n, from)) = responder.recv_from(&mut b).await {
                let _ = responder.send_to(&b[..n], from).await;
            }
        });

        let hops = measure_hops(addr, || b"handshake-probe".to_vec()).await;
        assert_eq!(hops, Some(1), "a local responder must answer at the first TTL");
    }

    #[test]
    fn decoy_ttl_is_one_short_of_the_server() {
        assert_eq!(decoy_ttl_for(12), 11);
        assert_eq!(decoy_ttl_for(1), 1);
        assert_eq!(decoy_ttl_for(0), 1);
    }
}
