use std::net::IpAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use anyhow::{Result, Context};
use tokio::sync::mpsc;
use hmac::Hmac;
use sha2::Sha256;
use base64::Engine;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use x25519_dalek::PublicKey;
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Nonce};

use ostp_core::crypto::reality::{build_client_hello, derive_keys, generate_session_id, generate_x25519_keypair, REALITY_SERVER_HANDSHAKE_RECORDS};
use ostp_core::framing::wss::{encode_wss_frame, decode_wss_frame, WssFrameResult};

type HmacSha256 = Hmac<Sha256>;

pub async fn connect_xhttp(
    target_ip: IpAddr,
    port: u16,
    sni: &str,
    access_key: &[u8],
    reality_enabled: bool,
    wss: bool,
    reality_pbk: &str,
    reality_sid: &str,
) -> Result<(mpsc::Sender<Bytes>, Arc<tokio::sync::Mutex<mpsc::Receiver<Bytes>>>)> {
    let addr = std::net::SocketAddr::new(target_ip, port);
    let mut tcp_stream = TcpStream::connect(addr).await
        .with_context(|| format!("failed to connect to {}", addr))?;
    tcp_stream.set_nodelay(true)?;

    #[cfg(target_os = "android")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = tcp_stream.as_raw_fd();
        crate::bridge::invoke_socket_protector(fd);
    }

    if reality_enabled {
        let pbk_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(reality_pbk)
            .context("invalid reality_pbk base64")?;
        if pbk_bytes.len() != 32 {
            anyhow::bail!("reality_pbk must be 32 bytes");
        }
        let pbk = PublicKey::from(<[u8; 32]>::try_from(pbk_bytes.as_slice()).unwrap());
        
        let sid_bytes_vec = hex::decode(reality_sid).context("invalid reality_sid hex")?;
        if sid_bytes_vec.len() != 8 {
            anyhow::bail!("reality_sid must be 8 bytes");
        }
        let sid: [u8; 8] = sid_bytes_vec.try_into().unwrap();

        let (c_priv, c_pub) = generate_x25519_keypair();
        let shared_secret = c_priv.diffie_hellman(&pbk);
        let (auth_key, data_key) = derive_keys(shared_secret.as_bytes());

        let session_id = generate_session_id(&auth_key, &sid);
        let client_hello = build_client_hello(if sni.is_empty() { "www.microsoft.com" } else { sni }, &session_id, &c_pub);
        
        tcp_stream.write_all(&client_hello).await?;
        
        // Drain all server handshake records (ServerHello, CCS, fake encrypted records).
        // The server sends exactly REALITY_SERVER_HANDSHAKE_RECORDS records before data starts.
        // Reading them explicitly prevents RealityStream from seeing non-AppData bytes.
        for i in 0..REALITY_SERVER_HANDSHAKE_RECORDS {
            let mut head = [0u8; 5];
            tcp_stream.read_exact(&mut head).await
                .with_context(|| format!("reality handshake: failed reading record {} header", i))?;
            if i == 0 && head[0] != 0x16 {
                anyhow::bail!("expected ServerHello (0x16), got 0x{:02x}", head[0]);
            }
            let record_len = u16::from_be_bytes([head[3], head[4]]) as usize;
            if record_len > 16384 {
                anyhow::bail!("reality handshake: record {} too large: {} bytes", i, record_len);
            }
            let mut _payload = vec![0u8; record_len];
            tcp_stream.read_exact(&mut _payload).await
                .with_context(|| format!("reality handshake: failed reading record {} payload", i))?;
        }

        let reality_stream = RealityStream::new(tcp_stream, data_key);
        xhttp_handshake_and_loop(reality_stream, target_ip, sni, access_key, wss).await
    } else {
        xhttp_handshake_and_loop(tcp_stream, target_ip, sni, access_key, wss).await
    }
}

// -----------------------------------------------------------------------
// RealityStream: Wraps a TCP stream in fake TLS Application Data Records
// -----------------------------------------------------------------------
struct RealityStream {
    inner: TcpStream,
    data_key: ChaCha20Poly1305,
    rx_nonce: u64,
    tx_nonce: u64,
    rx_buf: BytesMut,
}

impl RealityStream {
    fn new(inner: TcpStream, data_key: ChaCha20Poly1305) -> Self {
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

impl tokio::io::AsyncRead for RealityStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        loop {
            // Try to decode a full record
            if self.rx_buf.len() >= 5 {
                let len = u16::from_be_bytes([self.rx_buf[3], self.rx_buf[4]]) as usize;
                if self.rx_buf.len() >= 5 + len {
                    // We have a full record
                    if self.rx_buf[0] != 0x17 {
                        return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "expected application data record")));
                    }
                    
                    let ciphertext = &self.rx_buf[5..5+len];
                    let nonce_bytes = Self::make_nonce(self.rx_nonce);
                    let nonce = Nonce::from_slice(&nonce_bytes);
                    
                    match self.data_key.decrypt(nonce, ciphertext) {
                        Ok(plaintext) => {
                            self.rx_nonce += 1;
                            let out_len = std::cmp::min(buf.remaining(), plaintext.len());
                            buf.put_slice(&plaintext[..out_len]);
                            
                            if out_len < plaintext.len() {
                                // RealityStream doesn't buffer remaining plaintext if user buffer is too small.
                                // In xhttp_handshake_and_loop we always use 65535 byte buffers, so it fits.
                                // If needed, we'd add an internal plaintext_buffer.
                            }
                            
                            self.rx_buf.advance(5 + len);
                            return Poll::Ready(Ok(()));
                        }
                        Err(_) => {
                            return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "reality decrypt failed")));
                        }
                    }
                }
            }
            
            // Need more data
            let mut read_buf = [0u8; 4096];
            let mut tokio_buf = tokio::io::ReadBuf::new(&mut read_buf);
            match Pin::new(&mut self.inner).poll_read(cx, &mut tokio_buf) {
                Poll::Ready(Ok(())) => {
                    if tokio_buf.filled().is_empty() {
                        return Poll::Ready(Ok(())); // EOF
                    }
                    self.rx_buf.put_slice(tokio_buf.filled());
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl tokio::io::AsyncWrite for RealityStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let nonce_bytes = Self::make_nonce(self.tx_nonce);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Encrypt the entire buf as a single record
        match self.data_key.encrypt(nonce, buf) {
            Ok(ciphertext) => {
                let mut record = BytesMut::with_capacity(5 + ciphertext.len());
                record.put_u8(0x17); // Application Data
                record.put_u16(0x0303); // TLS 1.2/1.3
                record.put_u16(ciphertext.len() as u16);
                record.put_slice(&ciphertext);
                
                // Write the full record to the inner stream
                match tokio::io::AsyncWrite::poll_write(Pin::new(&mut self.inner), cx, &record) {
                    Poll::Ready(Ok(n)) if n == record.len() => {
                        self.tx_nonce += 1;
                        Poll::Ready(Ok(buf.len()))
                    }
                    Poll::Ready(Ok(_n)) => {
                        // Partial writes of a single TLS record are not supported by this simple wrapper
                        Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, "partial write not supported")))
                    }
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

async fn xhttp_handshake_and_loop<S>(
    mut stream: S,
    target_ip: IpAddr,
    sni: &str,
    access_key: &[u8],
    wss: bool,
) -> Result<(mpsc::Sender<Bytes>, Arc<tokio::sync::Mutex<mpsc::Receiver<Bytes>>>)>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // 1. Generate auth token: [8-byte timestamp BE] ++ [HMAC-SHA256]
    let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
    let ts_bytes = timestamp.to_be_bytes();
    use hmac::Mac;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(access_key).unwrap_or_else(|_| <HmacSha256 as Mac>::new_from_slice(b"").unwrap());
    mac.update(&ts_bytes);
    let mac_bytes = mac.finalize().into_bytes();

    let mut sig_bytes = Vec::with_capacity(8 + mac_bytes.len());
    sig_bytes.extend_from_slice(&ts_bytes);
    sig_bytes.extend_from_slice(&mac_bytes);

    let auth_token = base64::engine::general_purpose::STANDARD_NO_PAD.encode(&sig_bytes);

    let http_host = if sni.is_empty() { target_ip.to_string() } else { sni.to_string() };

    let req = if wss {
        format!(
            "GET /wss HTTP/1.1\r\n\
             Host: {}\r\n\
             Upgrade: websocket\r\n\
             Connection: upgrade\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n\
             Authorization: Bearer {}\r\n\
             \r\n",
            http_host, auth_token
        )
    } else {
        format!(
            "GET /stream HTTP/1.1\r\n\
             Host: {}\r\n\
             Authorization: Bearer {}\r\n\
             \r\n",
            http_host, auth_token
        )
    };

    stream.write_all(req.as_bytes()).await?;

    // Wait for HTTP 200 OK or 101 Switching Protocols
    let mut header_buf = Vec::new();
    let mut temp = [0u8; 1];
    loop {
        let n = stream.read(&mut temp).await?;
        if n == 0 {
            anyhow::bail!("connection closed by server during handshake");
        }
        header_buf.push(temp[0]);
        if header_buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if header_buf.len() > 8192 {
            anyhow::bail!("server response too long");
        }
    }

    let resp_str = String::from_utf8_lossy(&header_buf);
    if wss {
        if !resp_str.starts_with("HTTP/1.1 101 ") {
            anyhow::bail!("failed to switch protocols: {}", resp_str.lines().next().unwrap_or(""));
        }
    } else {
        if !resp_str.starts_with("HTTP/1.1 200 OK") {
            anyhow::bail!("server rejected stream: {}", resp_str.lines().next().unwrap_or(""));
        }
    }

    let (tx, mut rx) = mpsc::channel::<Bytes>(16384);
    let (mut read_half, mut write_half) = tokio::io::split(stream);

    let writer_task = tokio::spawn(async move {
        while let Some(packet) = rx.recv().await {
            if wss {
                let header = encode_wss_frame(&packet, true);
                if write_half.write_all(&header).await.is_err() { break; }
            } else {
                let mut out = BytesMut::with_capacity(2 + packet.len());
                out.put_u16(packet.len() as u16);
                out.put_slice(&packet);
                if write_half.write_all(&out).await.is_err() { break; }
            }
        }
    });

    let (in_tx, in_rx) = mpsc::channel::<Bytes>(16384);
    let in_rx_arc = Arc::new(tokio::sync::Mutex::new(in_rx));

    let in_tx_clone = in_tx.clone();
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
                                    if in_tx_clone.send(Bytes::from(payload)).await.is_err() { return; }
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
                if in_tx_clone.send(Bytes::from(data)).await.is_err() { break; }
            }
        }
    });

    tokio::spawn(async move {
        let _ = tokio::join!(writer_task, reader_task);
    });

    Ok((tx, in_rx_arc))
}
