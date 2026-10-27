//! Hop distance to the server, to calibrate the TTL-desync decoys.
//!
//! The server answers only a valid handshake, so the real handshake datagram is sent with
//! a rising IP TTL and the first TTL that draws a reply is the distance. Without the key
//! there is no valid handshake and no reply. Decoys are then sent at `hops - 1`: past the
//! DPI, short of the server.

use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;

/// Upper bound on the hop sweep.
const MAX_HOPS: u8 = 30;
/// Per-TTL wait for a reply; each TTL is tried twice to ride out loss.
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
