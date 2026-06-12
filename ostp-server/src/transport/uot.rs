use anyhow::Result;
use bytes::{BufMut, Bytes, BytesMut};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, RwLock};
use tracing::info;

pub async fn handle_tcp_connection<S>(
    stream: S,
    peer_addr: SocketAddr,
    tcp_map: Arc<RwLock<HashMap<SocketAddr, mpsc::Sender<Bytes>>>>,
    udp_tx: mpsc::Sender<(Bytes, SocketAddr)>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    info!("UoT client connected from {}", peer_addr);

    // Register this connection in the map
    let (tx, mut rx) = mpsc::channel::<Bytes>(16384);
    {
        tcp_map.write().await.insert(peer_addr, tx);
    }

    // Process streams
    let (mut read_half, mut write_half) = tokio::io::split(stream);

    // Spawn writer task
    let peer_clone = peer_addr;
    let tcp_map_clone = tcp_map.clone();
    let writer_task = tokio::spawn(async move {
        while let Some(packet) = rx.recv().await {
            let mut out = BytesMut::with_capacity(2 + packet.len());
            out.put_u16(packet.len() as u16);
            out.put_slice(&packet);
            if write_half.write_all(&out).await.is_err() { break; }
        }
        let _ = tcp_map_clone.write().await.remove(&peer_clone);
    });

    // Spawn reader task
    let reader_task = tokio::spawn(async move {
        let mut len_buf = [0u8; 2];
        loop {
            if read_half.read_exact(&mut len_buf).await.is_err() { break; }
            let len = u16::from_be_bytes(len_buf) as usize;
            if len > 65536 { break; }
            let mut data = vec![0u8; len];
            if read_half.read_exact(&mut data).await.is_err() { break; }
            if udp_tx.send((Bytes::from(data), peer_clone)).await.is_err() { return; }
        }
    });

    let _ = tokio::join!(writer_task, reader_task);
    info!("UoT client disconnected: {}", peer_addr);
    Ok(())
}
