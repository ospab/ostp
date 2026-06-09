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
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Nonce};
use x25519_dalek::StaticSecret;

use ostp_core::framing::wss::{encode_wss_frame, decode_wss_frame, WssFrameResult};
use ostp_core::crypto::reality::{parse_client_hello, derive_keys, verify_session_id, REALITY_SERVER_HANDSHAKE_RECORDS};
use crate::RealityServerConfig;

pub async fn handle_tcp_connection<S>(
    mut stream: S,
    peer_addr: SocketAddr,
    shared_keys: Arc<StdRwLock<HashMap<String, crate::api::UserMeta>>>,
    udp_tx: mpsc::Sender<(Bytes, SocketAddr)>,
    tcp_map: Arc<RwLock<HashMap<SocketAddr, mpsc::Sender<Bytes>>>>,
    reality_config: Option<Arc<RealityServerConfig>>,
    fb_target: Option<String>,
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

    // Check if it's a TLS record (0x16 0x03 0x01 or 0x16 0x03 0x03)
    if initial_buf[0] == 0x16 && initial_buf[1] == 0x03 {
        // It's a TLS record. We need to ensure we read the entire record.
        if header_len >= 5 {
            let record_len = 5 + u16::from_be_bytes([initial_buf[3], initial_buf[4]]) as usize;
            if record_len > initial_buf.len() {
                anyhow::bail!("TLS record too large");
            }
            while header_len < record_len {
                let n = stream.read(&mut initial_buf[header_len..record_len]).await?;
                if n == 0 {
                    anyhow::bail!("connection closed while reading TLS record");
                }
                header_len += n;
            }
        }
        
        if let Some(rc) = reality_config {
            return handle_reality_connection(stream, initial_buf[..header_len].to_vec(), peer_addr, shared_keys, udp_tx, tcp_map, rc).await;
        } else {
            // Received TLS but Reality is not enabled
            if let Some(target) = fb_target {
                tracing::info!("Fallback triggered for {} -> {}", peer_addr, target);
                let mut dest_stream: TcpStream = TcpStream::connect(&target).await?;
                dest_stream.write_all(&initial_buf[..header_len]).await?;
                tokio::io::copy_bidirectional(&mut stream, &mut dest_stream).await?;
                return Ok(());
            } else {
                anyhow::bail!("received TLS but Reality is not configured and no fallback target");
            }
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
        if let Some(target) = fb_target {
            tracing::info!("Fallback triggered for {} -> {}", peer_addr, target);
            let mut dest_stream: TcpStream = TcpStream::connect(&target).await?;
            dest_stream.write_all(&initial_buf[..header_len]).await?;
            tokio::io::copy_bidirectional(&mut stream, &mut dest_stream).await?;
            return Ok(());
        } else {
            let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\n\r\n").await;
            anyhow::bail!("invalid request line");
        }
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
            if let Some(target) = fb_target {
                tracing::info!("Fallback triggered for {} -> {}", peer_addr, target);
                let mut dest_stream: TcpStream = TcpStream::connect(&target).await?;
                dest_stream.write_all(&initial_buf[..header_len]).await?;
                tokio::io::copy_bidirectional(&mut stream, &mut dest_stream).await?;
                return Ok(());
            } else {
                let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\n\r\n").await;
                anyhow::bail!("missing authorization");
            }
        }
    };

    let sig_bytes = match base64::Engine::decode(&base64::engine::general_purpose::STANDARD_NO_PAD, &sig_b64) {
        Ok(b) => b,
        Err(_) => {
            if let Some(target) = fb_target {
                tracing::info!("Fallback triggered for {} -> {}", peer_addr, target);
                let mut dest_stream: TcpStream = TcpStream::connect(&target).await?;
                dest_stream.write_all(&initial_buf[..header_len]).await?;
                tokio::io::copy_bidirectional(&mut stream, &mut dest_stream).await?;
                return Ok(());
            } else {
                let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\n\r\n").await;
                anyhow::bail!("invalid base64 signature");
            }
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
        if let Some(target) = fb_target {
            tracing::info!("Fallback triggered for {} -> {}", peer_addr, target);
            let mut dest_stream: TcpStream = TcpStream::connect(&target).await?;
            dest_stream.write_all(&initial_buf[..header_len]).await?;
            tokio::io::copy_bidirectional(&mut stream, &mut dest_stream).await?;
            return Ok(());
        } else {
            let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\n\r\n").await;
            anyhow::bail!("unauthorized (invalid HMAC)");
        }
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
        
        // Build a fake TLS 1.3 server flight that matches what a real server sends.
        // Must be exactly REALITY_SERVER_HANDSHAKE_RECORDS (5) TLS records:
        //   1. ServerHello        (0x16)  - static blob with fake key share
        //   2. ChangeCipherSpec   (0x14)  - RFC 8446 §D.4 middlebox compat
        //   3. Fake EE            (0x17)  - simulates EncryptedExtensions
        //   4. Fake Certificate   (0x17)  - simulates Certificate (big, DPI-realistic)
        //   5. Fake Finished      (0x17)  - simulates CertificateVerify + Finished
        let _ = REALITY_SERVER_HANDSHAKE_RECORDS; // assert constant is imported (= 5)

        // Record 1: ServerHello (0x16), same static blob as before (valid structure)
        let server_hello_rec = hex::decode(
            "160303007a0200007603030000000000000000000000000000000000000000000000\
             000000000000000000000000200000000000000000000000000000000000000000\
             0000000000000000000000000000130100002e002b0002030400330024001d0020\
             e29b191a62d0572e9a30d0fb9d08e50bc78d591dfc1dbafbfa533411db1c8e11"
        ).unwrap();

        // Record 2: ChangeCipherSpec (0x14)
        let ccs_rec: &[u8] = &[0x14, 0x03, 0x03, 0x00, 0x01, 0x01];

        // Record 3: Fake EncryptedExtensions (0x17), 108 zero bytes payload
        let mut fake_ee = vec![0x17u8, 0x03, 0x03, 0x00, 108];
        fake_ee.extend_from_slice(&[0u8; 108]);

        // Record 4: Fake Certificate (0x17), 812 zero bytes (realistic cert size for DPI)
        let cert_payload_len: u16 = 812;
        let mut fake_cert = vec![0x17u8, 0x03, 0x03,
            (cert_payload_len >> 8) as u8, (cert_payload_len & 0xff) as u8];
        fake_cert.extend_from_slice(&vec![0u8; cert_payload_len as usize]);

        // Record 5: Fake Finished (0x17), 52 zero bytes (CertificateVerify + Finished)
        let mut fake_fin = vec![0x17u8, 0x03, 0x03, 0x00, 52];
        fake_fin.extend_from_slice(&[0u8; 52]);

        let mut server_flight = Vec::with_capacity(
            server_hello_rec.len() + ccs_rec.len() +
            fake_ee.len() + fake_cert.len() + fake_fin.len()
        );
        server_flight.extend_from_slice(&server_hello_rec);
        server_flight.extend_from_slice(ccs_rec);
        server_flight.extend_from_slice(&fake_ee);
        server_flight.extend_from_slice(&fake_cert);
        server_flight.extend_from_slice(&fake_fin);

        stream.write_all(&server_flight).await?;

        // The client now sends ClientHello + CCS (6 bytes) as two separate TLS records.
        // The ClientHello was already consumed into initial_buf above.
        // The CCS may arrive as a separate TCP segment - drain it from the raw stream
        // before wrapping in RealityStream so RealityStream only ever sees 0x17 records.
        {
            let mut ccs_head = [0u8; 5];
            if stream.read_exact(&mut ccs_head).await.is_ok() {
                // Expected: CCS record 0x14 0x03 0x03 0x00 0x01
                // If it's something else (unlikely), we still drain its payload to stay in sync.
                let ccs_payload_len = u16::from_be_bytes([ccs_head[3], ccs_head[4]]) as usize;
                if ccs_payload_len <= 64 {
                    let mut _discard = vec![0u8; ccs_payload_len];
                    let _ = stream.read_exact(&mut _discard).await;
                }
            }
        }

        let reality_stream = RealityStream::new(stream, data_key);
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
    plaintext_buf: BytesMut,
    tx_buf: BytesMut,
}

impl<S> RealityStream<S> {
    fn new(inner: S, data_key: ChaCha20Poly1305) -> Self {
        Self {
            inner,
            data_key,
            rx_nonce: 0,
            tx_nonce: 0,
            rx_buf: BytesMut::with_capacity(16384),
            plaintext_buf: BytesMut::new(),
            tx_buf: BytesMut::new(),
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
            if !self.plaintext_buf.is_empty() {
                let out_len = std::cmp::min(buf.remaining(), self.plaintext_buf.len());
                buf.put_slice(&self.plaintext_buf[..out_len]);
                self.plaintext_buf.advance(out_len);
                return Poll::Ready(Ok(()));
            }

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
                            self.plaintext_buf.put_slice(&plaintext);
                            self.rx_buf.advance(5 + len);
                            continue;
                        }
                        Err(_) => return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "reality decrypt failed"))),
                    }
                }
            }
            
            let mut read_buf = [0u8; 8192];
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
        let this = self.get_mut();
        while !this.tx_buf.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.tx_buf) {
                Poll::Ready(Ok(n)) => this.tx_buf.advance(n),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        let nonce_bytes = Self::make_nonce(this.tx_nonce);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        match this.data_key.encrypt(nonce, buf) {
            Ok(ciphertext) => {
                this.tx_nonce += 1;
                this.tx_buf.reserve(5 + ciphertext.len());
                this.tx_buf.put_u8(0x17);
                this.tx_buf.put_u16(0x0303);
                this.tx_buf.put_u16(ciphertext.len() as u16);
                this.tx_buf.put_slice(&ciphertext);
                
                match Pin::new(&mut this.inner).poll_write(cx, &this.tx_buf) {
                    Poll::Ready(Ok(n)) => this.tx_buf.advance(n),
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {}
                }
                Poll::Ready(Ok(buf.len()))
            }
            Err(_) => Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, "reality encrypt failed"))),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        while !this.tx_buf.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.tx_buf) {
                Poll::Ready(Ok(n)) => this.tx_buf.advance(n),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        while !this.tx_buf.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.tx_buf) {
                Poll::Ready(Ok(n)) => this.tx_buf.advance(n),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}
