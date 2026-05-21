use anyhow::Result;
use bytes::{BufMut, Bytes, BytesMut};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock as StdRwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, RwLock};
use tracing::info;

pub async fn handle_tcp_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    shared_keys: Arc<StdRwLock<HashMap<String, ()>>>,
    udp_tx: mpsc::Sender<(Bytes, SocketAddr)>,
    tcp_map: Arc<RwLock<HashMap<SocketAddr, mpsc::Sender<Bytes>>>>,
) -> Result<()> {
    // 1. Read HTTP Handshake
    let mut buf = [0u8; 4096];
    let mut header_len = 0;
    loop {
        let n = stream.read(&mut buf[header_len..]).await?;
        if n == 0 {
            anyhow::bail!("connection closed before handshake complete");
        }
        header_len += n;
        if buf[..header_len].windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if header_len == buf.len() {
            anyhow::bail!("handshake headers too large");
        }
    }

    let headers_str = String::from_utf8_lossy(&buf[..header_len]);

    // Fast-fail scanner bots
    if !headers_str.starts_with("GET /stream HTTP/1.1\r\n") {
        send_404(&mut stream).await?;
        anyhow::bail!("invalid request line");
    }

    // Extract Authorization or Cookie for signature
    let mut signature_base64 = None;
    for line in headers_str.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("authorization: bearer ") {
            signature_base64 = Some(line[22..].trim().to_string());
        } else if lower.starts_with("cookie: ostp_token=") {
            signature_base64 = Some(line[19..].trim().to_string());
        }
    }

    let sig_b64 = match signature_base64 {
        Some(s) => s,
        None => {
            send_404(&mut stream).await?;
            anyhow::bail!("missing authorization");
        }
    };

    let sig_bytes = match base64::Engine::decode(&base64::engine::general_purpose::STANDARD_NO_PAD, &sig_b64) {
        Ok(b) => b,
        Err(_) => {
            send_404(&mut stream).await?;
            anyhow::bail!("invalid base64 signature");
        }
    };

    if sig_bytes.len() < 8 {
        send_404(&mut stream).await?;
        anyhow::bail!("signature too short");
    }

    let ts_bytes: [u8; 8] = sig_bytes[0..8].try_into().unwrap();
    let client_ts = u64::from_be_bytes(ts_bytes);
    let provided_mac = &sig_bytes[8..];

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    if client_ts > now + 30 || client_ts < now.saturating_sub(60) {
        send_404(&mut stream).await?;
        anyhow::bail!("timestamp out of bounds (replay protection)");
    }

    // Verify HMAC against known keys
    let keys = {
        let guard = shared_keys.read().unwrap();
        guard.keys().cloned().collect::<Vec<_>>()
    };

    let mut authenticated = false;
    for key in keys {
        let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes())
            .unwrap_or_else(|_| Hmac::<Sha256>::new_from_slice(b"default").unwrap());
        mac.update(&ts_bytes);
        if mac.verify_slice(provided_mac).is_ok() {
            authenticated = true;
            break;
        }
    }

    if !authenticated {
        send_404(&mut stream).await?;
        anyhow::bail!("unauthorized (invalid HMAC)");
    }

    // Reply 101 Switching Protocols
    let response = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nX-Ostp-Server: 1\r\n\r\n";
    stream.write_all(response.as_bytes()).await?;

    info!("UoT client authenticated from {}", peer_addr);

    // Register this connection in the map
    let (tx, mut rx) = mpsc::channel::<Bytes>(1024);
    {
        tcp_map.write().await.insert(peer_addr, tx);
    }

    let headers_end = buf[..header_len].windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let leftover = &buf[headers_end..header_len];

    // Process streams
    let (mut read_half, mut write_half) = stream.into_split();

    // Spawn writer task
    let peer_clone = peer_addr;
    let tcp_map_clone = tcp_map.clone();
    let writer_task = tokio::spawn(async move {
        while let Some(packet) = rx.recv().await {
            let mut out = BytesMut::with_capacity(2 + packet.len());
            out.put_u16(packet.len() as u16);
            out.put_slice(&packet);
            if write_half.write_all(&out).await.is_err() {
                break;
            }
        }
        // Cleanup on writer exit
        tcp_map_clone.write().await.remove(&peer_clone);
    });

    // Reader loop
    let mut buffer = BytesMut::from(leftover);
    loop {
        while buffer.len() < 2 {
            let mut temp = [0u8; 1024];
            match read_half.read(&mut temp).await {
                Ok(0) | Err(_) => {
                    writer_task.abort();
                    tcp_map.write().await.remove(&peer_addr);
                    return Ok(());
                }
                Ok(n) => buffer.extend_from_slice(&temp[..n]),
            }
        }
        
        let len = u16::from_be_bytes([buffer[0], buffer[1]]) as usize;
        
        while buffer.len() < 2 + len {
            let mut temp = [0u8; 1024];
            match read_half.read(&mut temp).await {
                Ok(0) | Err(_) => {
                    writer_task.abort();
                    tcp_map.write().await.remove(&peer_addr);
                    return Ok(());
                }
                Ok(n) => buffer.extend_from_slice(&temp[..n]),
            }
        }
        
        let packet = buffer.split_to(2 + len);
        if udp_tx.send((Bytes::from(packet[2..].to_vec()), peer_addr)).await.is_err() {
            break;
        }
    }

    writer_task.abort();
    tcp_map.write().await.remove(&peer_addr);
    Ok(())
}

async fn send_404(stream: &mut TcpStream) -> Result<()> {
    let body = "Not Found";
    let resp = format!(
        "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(resp.as_bytes()).await;
    Ok(())
}
