use anyhow::Result;
use bytes::{BufMut, Bytes, BytesMut};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};

/// A connection that delivers no datagram for this long is closed. Clients
/// send a keepalive every few seconds (5 s by default), so only a dead or
/// abandoned connection gets here; before, one stayed open until the kernel
/// noticed, holding a task and, behind a web server, one of its connections.
/// Sessions themselves survive: they time out separately and a client can
/// carry on over a new connection.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(300);

pub async fn handle_tcp_connection<S>(
    stream: S,
    peer_addr: SocketAddr,
    tcp_map: Arc<RwLock<HashMap<SocketAddr, mpsc::Sender<Bytes>>>>,
    udp_tx: mpsc::Sender<(Bytes, SocketAddr)>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    handle_tcp_connection_with_idle(stream, peer_addr, tcp_map, udp_tx, IDLE_TIMEOUT).await
}

async fn handle_tcp_connection_with_idle<S>(
    stream: S,
    peer_addr: SocketAddr,
    tcp_map: Arc<RwLock<HashMap<SocketAddr, mpsc::Sender<Bytes>>>>,
    udp_tx: mpsc::Sender<(Bytes, SocketAddr)>,
    idle: Duration,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    tracing::debug!("UoT client connected from {}", peer_addr);

    // Register this connection in the map
    let (tx, mut rx) = mpsc::channel::<Bytes>(16384);
    // Weak: a strong sender kept here would stop a replaced connection from
    // ending (its writer waits for every sender to go away).
    let me = tx.downgrade();
    {
        tcp_map.write().await.insert(peer_addr, tx);
    }

    let (mut read_half, mut write_half) = tokio::io::split(stream);

    // Writer: length-prefix (u16 BE) each outbound datagram. OSTP datagrams are
    // always well under 64 KiB (MTU-bounded), so the u16 prefix never truncates.
    let writer = async move {
        while let Some(packet) = rx.recv().await {
            let mut out = BytesMut::with_capacity(2 + packet.len());
            out.put_u16(packet.len() as u16);
            out.put_slice(&packet);
            if write_half.write_all(&out).await.is_err() { break; }
        }
    };

    // Reader: reassemble length-prefixed frames off the TCP stream (read_exact
    // handles TCP segmentation) and forward each to the UDP dispatch path.
    let reader = async move {
        let mut len_buf = [0u8; 2];
        loop {
            // The whole frame must arrive within `idle`: a peer that stops
            // halfway through one is as dead as one that sends nothing.
            let frame = tokio::time::timeout(idle, async {
                read_half.read_exact(&mut len_buf).await?;
                let mut data = vec![0u8; u16::from_be_bytes(len_buf) as usize];
                read_half.read_exact(&mut data).await?;
                Ok::<_, std::io::Error>(data)
            })
            .await;
            let data = match frame {
                Ok(Ok(data)) => data,
                Ok(Err(_)) => break,
                Err(_) => {
                    tracing::debug!("UoT client {} idle for {:?}, closing", peer_addr, idle);
                    break;
                }
            };
            if udp_tx.send((Bytes::from(data), peer_addr)).await.is_err() { break; }
        }
    };

    // Either half completing means the connection is dead in that direction, so
    // tear the whole thing down: `select!` drops (cancels) the other half. The
    // old code `join!`ed both, so a half-open connection (client's read side
    // gone but no outbound data pending) left the writer parked on rx.recv()
    // forever, leaking the task and its stale tcp_map entry.
    tokio::select! {
        _ = writer => {},
        _ = reader => {},
    }

    // A newer connection from the same address (a local web server reuses
    // ports) has its own entry by now; it is not ours to remove.
    {
        let mut map = tcp_map.write().await;
        if map.get(&peer_addr).zip(me.upgrade()).is_some_and(|(m, t)| m.same_channel(&t)) {
            map.remove(&peer_addr);
        }
    }
    tracing::debug!("UoT client disconnected: {}", peer_addr);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> SocketAddr {
        "127.0.0.1:40000".parse().unwrap()
    }

    /// Inbound framing: length-prefixed frames written by the client are
    /// reassembled (even when split across reads) and forwarded to udp_tx.
    #[tokio::test]
    async fn reader_reassembles_framed_datagrams() {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let tcp_map: Arc<RwLock<HashMap<SocketAddr, mpsc::Sender<Bytes>>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let (udp_tx, mut udp_rx) = mpsc::channel(16);
        let handle = tokio::spawn(handle_tcp_connection(server, peer(), tcp_map.clone(), udp_tx));

        // Two datagrams; write the second one byte-at-a-time to exercise the
        // read_exact reassembly across TCP segment boundaries.
        let d1 = b"hello".to_vec();
        client.write_all(&(d1.len() as u16).to_be_bytes()).await.unwrap();
        client.write_all(&d1).await.unwrap();

        let d2 = vec![0xAB_u8; 1400];
        let framed2: Vec<u8> = (d2.len() as u16).to_be_bytes().iter().chain(d2.iter()).copied().collect();
        for b in &framed2 {
            client.write_all(&[*b]).await.unwrap();
        }

        let (got1, _) = udp_rx.recv().await.unwrap();
        assert_eq!(got1.as_ref(), d1.as_slice());
        let (got2, from) = udp_rx.recv().await.unwrap();
        assert_eq!(got2.as_ref(), d2.as_slice());
        assert_eq!(from, peer());

        drop(client);
        let _ = handle.await;
    }

    /// Outbound framing + teardown: a datagram sent via the tcp_map sender is
    /// written to the wire with its u16 length prefix, and once the client
    /// hangs up the connection is torn down and its tcp_map entry removed.
    #[tokio::test]
    async fn writer_frames_outbound_and_cleans_up_on_close() {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let tcp_map: Arc<RwLock<HashMap<SocketAddr, mpsc::Sender<Bytes>>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let (udp_tx, _udp_rx) = mpsc::channel(16);
        let handle = tokio::spawn(handle_tcp_connection(server, peer(), tcp_map.clone(), udp_tx));

        // Wait for registration, then push an outbound datagram.
        let tx = loop {
            if let Some(tx) = tcp_map.read().await.get(&peer()).cloned() { break tx; }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        };
        tx.send(Bytes::from_static(b"world!")).await.unwrap();

        let mut len_buf = [0u8; 2];
        client.read_exact(&mut len_buf).await.unwrap();
        assert_eq!(u16::from_be_bytes(len_buf) as usize, 6);
        let mut body = [0u8; 6];
        client.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"world!");

        // Client hangs up -> reader hits EOF -> select! tears down -> entry gone.
        drop(client);
        let _ = handle.await;
        assert!(!tcp_map.read().await.contains_key(&peer()), "tcp_map entry must be removed on close");
    }

    /// A local web server reuses ports: when an old connection from an address
    /// ends after a newer one from the same address registered, the newer
    /// one's entry must stay.
    #[tokio::test]
    async fn a_closing_connection_leaves_a_newer_one_registered() {
        let tcp_map: Arc<RwLock<HashMap<SocketAddr, mpsc::Sender<Bytes>>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let (udp_tx, _udp_rx) = mpsc::channel(16);

        let (client_a, server_a) = tokio::io::duplex(1024);
        let handle_a = tokio::spawn(handle_tcp_connection(server_a, peer(), tcp_map.clone(), udp_tx.clone()));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let (_client_b, server_b) = tokio::io::duplex(1024);
        let _handle_b = tokio::spawn(handle_tcp_connection(server_b, peer(), tcp_map.clone(), udp_tx));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        drop(client_a);
        let _ = handle_a.await;
        assert!(tcp_map.read().await.contains_key(&peer()), "the newer connection was unregistered");
    }

    /// A connection that goes quiet is closed and unregistered, while one
    /// that keeps sending stays open past the same interval.
    #[tokio::test]
    async fn an_idle_connection_is_closed() {
        let idle = std::time::Duration::from_millis(200);
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let tcp_map: Arc<RwLock<HashMap<SocketAddr, mpsc::Sender<Bytes>>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let (udp_tx, mut udp_rx) = mpsc::channel(16);
        let handle = tokio::spawn(handle_tcp_connection_with_idle(server, peer(), tcp_map.clone(), udp_tx, idle));

        // Keepalives every 100 ms for 500 ms: longer than `idle` in total.
        for _ in 0..5 {
            client.write_all(&[0, 1, 7]).await.unwrap();
            assert_eq!(udp_rx.recv().await.unwrap().0.as_ref(), &[7]);
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert!(!handle.is_finished(), "an active connection must stay open");

        // Half a frame, then silence.
        client.write_all(&[0, 10, 1, 2]).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), handle)
            .await
            .expect("an idle connection must be closed")
            .unwrap()
            .unwrap();
        assert!(!tcp_map.read().await.contains_key(&peer()));
        // The server side is gone, so the client sees the end of the stream.
        let mut buf = [0u8; 1];
        assert_eq!(client.read(&mut buf).await.unwrap(), 0);
    }
}
