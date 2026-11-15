//! OSTP: `TcpStream::abort` ends a flow with a TCP RST, while dropping the stream
//! ends it with a FIN.
//!
//! The test drives the netstack the way a TUN does, with raw IP packets: it plays
//! the program's side of a TCP connection (SYN, ACK) by hand, takes the accepted
//! `TcpStream` from the listener and looks at the IP/TCP packets the stack emits.

use std::{net::IpAddr, time::Duration};

use etherparse::{PacketBuilder, SlicedPacket, TransportSlice};
use futures::{SinkExt, StreamExt};
use netstack_smoltcp::{Stack, StackBuilder, TcpListener, TcpStream};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};

#[derive(Debug, Clone, Copy, Default)]
struct Seg {
    syn: bool,
    ack: bool,
    fin: bool,
    rst: bool,
    seq: u32,
    ack_no: u32,
    payload: usize,
}

struct Peer {
    stack: Stack,
    src: IpAddr,
    dst: IpAddr,
    sport: u16,
    dport: u16,
    seq: u32,
}

impl Peer {
    fn packet(&self, seq: u32, ack_no: Option<u32>, syn: bool, payload: &[u8]) -> Vec<u8> {
        let b = match (self.src, self.dst) {
            (IpAddr::V4(s), IpAddr::V4(d)) => PacketBuilder::ipv4(s.octets(), d.octets(), 64),
            (IpAddr::V6(s), IpAddr::V6(d)) => PacketBuilder::ipv6(s.octets(), d.octets(), 64),
            _ => unreachable!(),
        };
        let mut b = b.tcp(self.sport, self.dport, seq, 65535);
        if syn {
            b = b.syn();
        }
        if let Some(a) = ack_no {
            b = b.ack(a);
        }
        let mut out = Vec::new();
        b.write(&mut out, payload).unwrap();
        out
    }

    async fn send(&mut self, pkt: Vec<u8>) {
        timeout(Duration::from_secs(2), self.stack.send(pkt))
            .await
            .expect("stack accepts the packet in time")
            .expect("stack accepts the packet");
    }

    /// The next TCP segment the stack emits for this flow, or None after `wait`.
    async fn next_seg(&mut self, wait: Duration) -> Option<Seg> {
        loop {
            let frame = timeout(wait, self.stack.next()).await.ok()??.unwrap();
            let sliced = SlicedPacket::from_ip(&frame).expect("the stack emits valid IP");
            if let Some(TransportSlice::Tcp(t)) = sliced.transport {
                return Some(Seg {
                    syn: t.syn(),
                    ack: t.ack(),
                    fin: t.fin(),
                    rst: t.rst(),
                    seq: t.sequence_number(),
                    ack_no: t.acknowledgment_number(),
                    payload: t.payload().len(),
                });
            }
        }
    }

    /// Every segment until the stack is quiet for `quiet`.
    async fn drain(&mut self, quiet: Duration) -> Vec<Seg> {
        let mut all = Vec::new();
        while let Some(s) = self.next_seg(quiet).await {
            all.push(s);
        }
        all
    }
}

/// A TCP handshake from the test (the program) to the stack (the TUN's netstack).
/// Returns the program's side and the stream the listener accepted.
async fn connected(v6: bool) -> (Peer, TcpStream, TcpListener) {
    let (stack, runner, _udp, listener) = StackBuilder::default()
        .enable_tcp(true)
        .enable_udp(false)
        .build()
        .unwrap();
    tokio::spawn(runner.expect("tcp runner"));
    let mut listener = listener.expect("tcp listener");

    let (src, dst): (IpAddr, IpAddr) = if v6 {
        ("fd00::1".parse().unwrap(), "2001:db8::50".parse().unwrap())
    } else {
        ("10.0.0.1".parse().unwrap(), "93.184.216.34".parse().unwrap())
    };
    let mut peer = Peer { stack, src, dst, sport: 40000, dport: 443, seq: 1000 };

    let syn = peer.packet(peer.seq, None, true, &[]);
    peer.send(syn).await;
    let synack = peer.next_seg(Duration::from_secs(2)).await.expect("SYN|ACK");
    assert!(synack.syn && synack.ack, "expected SYN|ACK, got {synack:?}");
    peer.seq += 1;
    let ack = peer.packet(peer.seq, Some(synack.seq.wrapping_add(1)), false, &[]);
    peer.send(ack).await;

    // The listener hands the stream out at the SYN, before the stack has seen the
    // ACK. One byte from the program, and its acknowledgement, prove the
    // connection is established before the test ends it.
    let data = peer.packet(peer.seq, Some(synack.seq.wrapping_add(1)), false, b"x");
    peer.send(data).await;
    peer.seq += 1;
    let acked = peer.next_seg(Duration::from_secs(2)).await.expect("ACK of the byte");
    assert!(acked.ack && acked.ack_no == peer.seq, "expected an ACK of the byte, got {acked:?}");

    let (stream, local, remote) = timeout(Duration::from_secs(2), listener.next())
        .await
        .expect("accept in time")
        .expect("a stream");
    assert_eq!(local.ip(), src);
    assert_eq!(remote.ip(), dst);
    (peer, stream, listener)
}

async fn check_abort(v6: bool) {
    let (mut peer, mut stream, _l) = connected(v6).await;

    // Data the stack has queued for the program: the RST discards it.
    stream.write_all(b"hello").await.unwrap();
    // let the data go out, so the reset is the first segment that follows
    let data = peer.next_seg(Duration::from_secs(2)).await.expect("data segment");
    assert_eq!(data.payload, 5, "{data:?}");

    stream.abort();

    let segs = peer.drain(Duration::from_millis(500)).await;
    assert!(segs.iter().any(|s| s.rst), "abort must send a RST, got {segs:?}");
    assert!(!segs.iter().any(|s| s.fin), "abort must not send a FIN, got {segs:?}");

    // The abort ended the stream on the local side too.
    let mut buf = [0u8; 8];
    let n = timeout(Duration::from_secs(1), stream.read(&mut buf))
        .await
        .expect("read returns")
        .unwrap();
    assert_eq!(n, 0, "a read after abort is EOF");
    assert!(stream.write_all(b"x").await.is_err(), "a write after abort fails");
}

async fn check_drop_is_fin(v6: bool) {
    let (mut peer, stream, _l) = connected(v6).await;

    drop(stream);

    let segs = peer.drain(Duration::from_millis(500)).await;
    assert!(segs.iter().any(|s| s.fin), "a dropped stream must send a FIN, got {segs:?}");
    assert!(!segs.iter().any(|s| s.rst), "a dropped stream must not send a RST, got {segs:?}");
}

#[tokio::test]
async fn abort_sends_rst_ipv4() {
    check_abort(false).await;
}

#[tokio::test]
async fn abort_sends_rst_ipv6() {
    check_abort(true).await;
}

#[tokio::test]
async fn drop_sends_fin_ipv4() {
    check_drop_is_fin(false).await;
}

#[tokio::test]
async fn drop_sends_fin_ipv6() {
    check_drop_is_fin(true).await;
}

#[tokio::test]
async fn shutdown_sends_fin_not_rst() {
    let (mut peer, mut stream, _l) = connected(false).await;

    // poll_shutdown stays pending until the socket closes; the FIN goes out first
    let _ = timeout(Duration::from_millis(100), stream.shutdown()).await;
    let segs = peer.drain(Duration::from_millis(500)).await;
    assert!(segs.iter().any(|s| s.fin), "shutdown must send a FIN, got {segs:?}");
    assert!(!segs.iter().any(|s| s.rst), "shutdown must not send a RST, got {segs:?}");
}
