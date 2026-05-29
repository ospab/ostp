use anyhow::Result;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock as StdRwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, RwLock};
use tracing::info;
use tokio::net::TcpStream;
use base64::Engine;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use chacha20poly1305::{aead::{Aead, KeyInit, Payload}, ChaCha20Poly1305, Nonce};
use x25519_dalek::{StaticSecret, PublicKey};

use ostp_core::framing::wss::{encode_wss_frame, decode_wss_frame, WssFrameResult};
use ostp_core::crypto::reality::{parse_client_hello, derive_keys, verify_session_id};
use crate::RealityServerConfig;

pub async fn handle_tcp_connection<S>(
    mut stream: S,
    peer_addr: SocketAddr,
    shared_keys: Arc<StdRwLock<HashMap<String, crate::api::UserMeta>>>,
    udp_tx: mpsc::Sender<(Bytes, SocketAddr)>,
    tcp_map: Arc<RwLock<HashMap<SocketAddr, mpsc::Sender<Bytes>>>>,
    reality_config: Option<Arc<RealityServerConfig>>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut initial_buf = vec![0u8; 16384];
    let mut header_len = 0;
    
    // Read the first chunk to determine if it's TLS or HTTP
    let n = stream.read(&mut initial_buf).await?;
    if n == 0 {
        anyhow::bail!("connection closed before data received");
    }
    header_len += n;

    // Check if it's a TLS record (0x16 0x03 0x01)
    if initial_buf[0] == 0x16 && initial_buf[1] == 0x03 && initial_buf[2] == 0x01 {
        if let Some(rc) = reality_config {
            return handle_reality_connection(stream, initial_buf[..header_len].to_vec(), peer_addr, shared_keys, udp_tx, tcp_map, rc).await;
        } else {
            // Received TLS but Reality is not enabled, maybe forward to a default fallback?
            // For now, just drop
            anyhow::bail!("received TLS but Reality is not configured");
        }
    }

    // Otherwise, assume it's HTTP (Standard xhttp/wss)
    loop {
        if initial_buf[..header_len].windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if header_len == initial_buf.len() {
            anyhow::bail!("handshake headers too large");
        }
        let n = stream.read(&mut initial_buf[header_len..]).await?;
        if n == 0 {
            anyhow::bail!("connection closed before HTTP handshake complete");
        }
        header_len += n;
    }

    let headers_str = String::from_utf8_lossy(&initial_buf[..header_len]);
    
    let wss = if headers_str.starts_with("GET /wss HTTP/1.1\r\n") {
        true
    } else if headers_str.starts_with("GET /stream HTTP/1.1\r\n") {
        false
    } else {
        // Not a valid OSTP path. If Reality fallback was configured but we received plain HTTP, maybe fallback?
        // Actually fallback is handled above for TLS. For HTTP, we just 404.
        let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\n\r\n").await;
        anyhow::bail!("invalid request line");
    };

    // Extract Authorization
    let mut signature_base64 = None;
    for line in headers_str.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("authorization: bearer ") {
            signature_base64 = Some(line[22..].trim().to_string());
        }
    }

    let sig_b64 = match signature_base64 {
        Some(s) => s,
        None => {
            let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\n\r\n").await;
            anyhow::bail!("missing authorization");
        }
    };

    let sig_bytes = match base64::Engine::decode(&base64::engine::general_purpose::STANDARD_NO_PAD, &sig_b64) {
        Ok(b) => b,
        Err(_) => {
            let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\n\r\n").await;
            anyhow::bail!("invalid base64 signature");
        }
    };

    if sig_bytes.len() < 8 {
        let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\n\r\n").await;
        anyhow::bail!("signature too short");
    }

    let ts_bytes: [u8; 8] = sig_bytes[0..8].try_into().unwrap();
    let client_ts = u64::from_be_bytes(ts_bytes);
    let provided_mac = &sig_bytes[8..];

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    if client_ts > now + 30 || client_ts < now.saturating_sub(60) {
        let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\n\r\n").await;
        anyhow::bail!("timestamp out of bounds (replay protection)");
    }

    // Verify HMAC against known keys
    let keys = {
        let guard = shared_keys.read().unwrap();
        guard.keys().cloned().collect::<Vec<_>>()
    };

    let mut authenticated = false;
    for key in keys {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key.as_bytes())
            .unwrap_or_else(|_| <Hmac<Sha256> as Mac>::new_from_slice(b"default").unwrap());
        mac.update(&ts_bytes);
        if mac.verify_slice(provided_mac).is_ok() {
            authenticated = true;
            break;
        }
    }

    if !authenticated {
        let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\n\r\n").await;
        anyhow::bail!("unauthorized (invalid HMAC)");
    }

    if wss {
        let response = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nX-Ostp-Server: 1\r\n\r\n";
        stream.write_all(response.as_bytes()).await?;
    } else {
        let response = "HTTP/1.1 200 OK\r\nX-Ostp-Server: 1\r\nContent-Type: application/octet-stream\r\n\r\n";
        stream.write_all(response.as_bytes()).await?;
    }

    info!("UoT client authenticated from {} (xhttp)", peer_addr);

    start_uot_loops(stream, peer_addr, wss, tcp_map, udp_tx).await
}

async fn handle_reality_connection<S>(
    mut stream: S,
    initial_buf: Vec<u8>,
    peer_addr: SocketAddr,
    _shared_keys: Arc<StdRwLock<HashMap<String, crate::api::UserMeta>>>, // Note: Reality uses its own keys (sid)
    udp_tx: mpsc::Sender<(Bytes, SocketAddr)>,
    tcp_map: Arc<RwLock<HashMap<SocketAddr, mpsc::Sender<Bytes>>>>,
    reality_config: Arc<RealityServerConfig>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // Try to parse ClientHello
    let parsed_ch = parse_client_hello(&initial_buf);
    
    let mut authenticated = false;
    let mut data_key_opt = None;
    
    if let Some(ch) = parsed_ch {
        // Validate SNI
        if reality_config.sni_list.contains(&ch.sni) {
            // Decode Server Private Key
            if let Ok(priv_bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&reality_config.private_key) {
                if priv_bytes.len() == 32 {
                    let mut secret_bytes = [0u8; 32];
                    secret_bytes.copy_from_slice(&priv_bytes);
                    let server_priv = StaticSecret::from(secret_bytes);
                    
                    let shared_secret = server_priv.diffie_hellman(&ch.c_pub);
                    let (auth_key, data_key) = derive_keys(shared_secret.as_bytes());
                    
                    // Attempt to decrypt Session ID
                    if let Some((sid, _ts)) = verify_session_id(&auth_key, &ch.session_id) {
                        // Check if sid is in config
                        let sid_hex = hex::encode(sid);
                        if reality_config.sid == sid_hex {
                            authenticated = true;
                            data_key_opt = Some(data_key);
                        }
                    }
                }
            }
        }
    }

    if authenticated {
        let data_key = data_key_opt.unwrap();
        info!("Reality client authenticated from {} (sid matched)", peer_addr);
        
        // Send a fake ServerHello. For now, a static, valid-looking TLS 1.3 ServerHello.
        let server_hello = hex::decode("160303007a0200007603030000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000130100002e002b0002030400330024001d0020e29b191a62d0572e9a30d0fb9d08e50bc78d591dfc1dbafbfa533411db1c8e111403030001011603030030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000170303001300000000000000000000000000000000000000").unwrap();
        stream.write_all(&server_hello).await?;
        
        // At this point, the Reality tunnel is established. We need to wrap the stream with RealityStream.
        let reality_stream = RealityStream::new(stream, data_key);
        
        // But wait! Inside the Reality stream, the client might send an xhttp or wss HTTP request!
        // Because xhttp_handshake_and_loop does `GET /wss` *inside* the stream.
        // So we must read the HTTP request *from the Reality stream*!
        
        return process_inner_reality_stream(reality_stream, peer_addr, tcp_map, udp_tx).await;
        
    } else {
        // Fallback: act as a transparent proxy to `reality_config.dest`
        info!("Reality fallback triggered for {} -> {}", peer_addr, reality_config.dest);
        let mut dest_stream: TcpStream = TcpStream::connect(&reality_config.dest).await?;
        dest_stream.write_all(&initial_buf).await?;
        
        tokio::io::copy_bidirectional(&mut stream, &mut dest_stream).await?;
        return Ok(());
    }
}

async fn process_inner_reality_stream<S>(
    mut stream: S,
    peer_addr: SocketAddr,
    tcp_map: Arc<RwLock<HashMap<SocketAddr, mpsc::Sender<Bytes>>>>,
    udp_tx: mpsc::Sender<(Bytes, SocketAddr)>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // 1. Read the inner HTTP Handshake
    let mut buf = [0u8; 4096];
    let mut header_len = 0;
    loop {
        let n = stream.read(&mut buf[header_len..]).await?;
        if n == 0 {
            anyhow::bail!("inner connection closed before handshake complete");
        }
        header_len += n;
        if buf[..header_len].windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if header_len == buf.len() {
            anyhow::bail!("inner handshake headers too large");
        }
    }

    let headers_str = String::from_utf8_lossy(&buf[..header_len]);
    
    let wss = if headers_str.starts_with("GET /wss HTTP/1.1\r\n") {
        true
    } else if headers_str.starts_with("GET /stream HTTP/1.1\r\n") {
        false
    } else {
        anyhow::bail!("invalid inner request line");
    };

    // We skip signature validation because Reality already authenticated the user via Session ID!

    if wss {
        let response = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nX-Ostp-Server: 1\r\n\r\n";
        stream.write_all(response.as_bytes()).await?;
    } else {
        let response = "HTTP/1.1 200 OK\r\nX-Ostp-Server: 1\r\nContent-Type: application/octet-stream\r\n\r\n";
        stream.write_all(response.as_bytes()).await?;
    }

    start_uot_loops(stream, peer_addr, wss, tcp_map, udp_tx).await
}

async fn start_uot_loops<S>(
    stream: S,
    peer_addr: SocketAddr,
    wss: bool,
    tcp_map: Arc<RwLock<HashMap<SocketAddr, mpsc::Sender<Bytes>>>>,
    udp_tx: mpsc::Sender<(Bytes, SocketAddr)>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
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
            if wss {
                let header = encode_wss_frame(&packet, false); // Server sends unmasked WSS frames
                if write_half.write_all(&header).await.is_err() { break; }
            } else {
                let mut out = BytesMut::with_capacity(2 + packet.len());
                out.put_u16(packet.len() as u16);
                out.put_slice(&packet);
                if write_half.write_all(&out).await.is_err() { break; }
            }
        }
        let _ = tcp_map_clone.write().await.remove(&peer_clone);
    });

    // Spawn reader task
    let tcp_map_clone2 = tcp_map.clone();
    let reader_task = tokio::spawn(async move {
        if wss {
            let mut read_buf = BytesMut::with_capacity(65536);
            let mut tmp = [0u8; 8192];
            loop {
                match read_half.read(&mut tmp).await {
                    Ok(0) => break,
                    Ok(n) => {
                        read_buf.put_slice(&tmp[..n]);
                        loop {
                            match decode_wss_frame(&mut read_buf) {
                                WssFrameResult::Frame { payload, total_len } => {
                                    if udp_tx.send((Bytes::from(payload), peer_clone)).await.is_err() { return; }
                                    read_buf.advance(total_len);
                                }
                                WssFrameResult::Incomplete => break,
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
        } else {
            let mut len_buf = [0u8; 2];
            loop {
                if read_half.read_exact(&mut len_buf).await.is_err() { break; }
                let len = u16::from_be_bytes(len_buf) as usize;
                if len > 65535 { break; }
                let mut data = vec![0u8; len];
                if read_half.read_exact(&mut data).await.is_err() { break; }
                if udp_tx.send((Bytes::from(data), peer_clone)).await.is_err() { break; }
            }
        }
        let _ = tcp_map_clone2.write().await.remove(&peer_clone);
    });

    let _ = tokio::join!(writer_task, reader_task);
    Ok(())
}

// -----------------------------------------------------------------------
// RealityStream: Wraps a TCP stream in fake TLS Application Data Records
// -----------------------------------------------------------------------
struct RealityStream<S> {
    inner: S,
    data_key: ChaCha20Poly1305,
    rx_nonce: u64,
    tx_nonce: u64,
    rx_buf: BytesMut,
}

impl<S> RealityStream<S> {
    fn new(inner: S, data_key: ChaCha20Poly1305) -> Self {
        Self {
            inner,
            data_key,
            rx_nonce: 0,
            tx_nonce: 0,
            rx_buf: BytesMut::with_capacity(16384),
        }
    }
    
    fn make_nonce(seq: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&seq.to_le_bytes());
        nonce
    }
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for RealityStream<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        loop {
            if self.rx_buf.len() >= 5 {
                let len = u16::from_be_bytes([self.rx_buf[3], self.rx_buf[4]]) as usize;
                if self.rx_buf.len() >= 5 + len {
                    if self.rx_buf[0] != 0x17 {
                        return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "expected application data record")));
                    }
                    
                    let ciphertext = &self.rx_buf[5..5+len];
                    let nonce_bytes = Self::make_nonce(self.rx_nonce);
                    let nonce = Nonce::from_slice(&nonce_bytes);
                    
                    match self.data_key.decrypt(nonce, ciphertext) {
                        Ok(plaintext) => {
                            self.rx_nonce += 1;
                            let out_len = std::cmp::min::<usize>(buf.remaining(), plaintext.len());
                            buf.put_slice(&plaintext[..out_len]);
                            self.rx_buf.advance(5 + len);
                            return Poll::Ready(Ok(()));
                        }
                        Err(_) => return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "reality decrypt failed"))),
                    }
                }
            }
            
            let mut read_buf = [0u8; 4096];
            let mut tokio_buf = tokio::io::ReadBuf::new(&mut read_buf);
            match Pin::new(&mut self.inner).poll_read(cx, &mut tokio_buf) {
                Poll::Ready(Ok(())) => {
                    if tokio_buf.filled().is_empty() { return Poll::Ready(Ok(())); }
                    self.rx_buf.put_slice(tokio_buf.filled());
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for RealityStream<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let nonce_bytes = Self::make_nonce(self.tx_nonce);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        match self.data_key.encrypt(nonce, buf) {
            Ok(ciphertext) => {
                let mut record: BytesMut = BytesMut::with_capacity(5 + ciphertext.len());
                record.put_u8(0x17);
                record.put_u16(0x0303);
                record.put_u16(ciphertext.len() as u16);
                record.put_slice(&ciphertext);
                
                match tokio::io::AsyncWrite::poll_write(Pin::new(&mut self.inner), cx, &record) {
                    Poll::Ready(Ok(n)) if n == record.len() => {
                        self.tx_nonce += 1;
                        Poll::Ready(Ok(buf.len()))
                    }
                    Poll::Ready(Ok(_n)) => Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, "partial write not supported"))),
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                    Poll::Pending => Poll::Pending,
                }
            }
            Err(_) => Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, "reality encrypt failed"))),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
