use std::net::IpAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use bytes::{Bytes, BytesMut};
use anyhow::{Result, Context};
use tokio::sync::mpsc;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use base64::Engine;

type HmacSha256 = Hmac<Sha256>;

pub async fn connect_xhttp(
    target_ip: IpAddr,
    port: u16,
    sni: &str,
    access_key: &[u8],
) -> Result<(mpsc::Sender<Bytes>, Arc<tokio::sync::Mutex<mpsc::Receiver<Bytes>>>)> {
    let addr = std::net::SocketAddr::new(target_ip, port);
    let mut tcp_stream = TcpStream::connect(addr).await
        .with_context(|| format!("failed to connect to {}", addr))?;
    tcp_stream.set_nodelay(true)?;

    // 1. Generate auth token: [8-byte timestamp BE] ++ [HMAC-SHA256]
    let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
    let ts_bytes = timestamp.to_be_bytes();
    let mut mac = HmacSha256::new_from_slice(access_key).unwrap_or_else(|_| HmacSha256::new_from_slice(b"").unwrap());
    mac.update(&ts_bytes);
    let mac_bytes = mac.finalize().into_bytes();

    let mut sig_bytes = Vec::with_capacity(8 + mac_bytes.len());
    sig_bytes.extend_from_slice(&ts_bytes);
    sig_bytes.extend_from_slice(&mac_bytes);

    let auth_token = base64::engine::general_purpose::STANDARD_NO_PAD.encode(&sig_bytes);

    let http_host = if sni.is_empty() { target_ip.to_string() } else { sni.to_string() };

    // 2. Send fake WebSocket upgrade — looks like a legit browser request to bypass DPI/proxies.
    //    The server responds with 101 Switching Protocols and we stream raw UoT frames after that.
    //    NOTE: always plain TCP — TLS is NOT used. Obfuscation comes from the fake WS headers.
    let req = format!(
        "GET /stream HTTP/1.1\r\n\
         Host: {}\r\n\
         Upgrade: websocket\r\n\
         Connection: upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Authorization: Bearer {}\r\n\
         \r\n",
        http_host, auth_token
    );

    tcp_stream.write_all(req.as_bytes()).await?;
    tcp_stream.flush().await?;

    // 3. Read server response headers
    let mut buf = vec![0u8; 4096];
    let mut header_len = 0;
    loop {
        let n = tcp_stream.read(&mut buf[header_len..]).await?;
        if n == 0 { anyhow::bail!("connection closed before handshake complete"); }
        header_len += n;
        if buf[..header_len].windows(4).any(|w| w == b"\r\n\r\n") { break; }
        if header_len >= buf.len() { anyhow::bail!("server response headers too large"); }
    }

    let resp = String::from_utf8_lossy(&buf[..header_len]);
    if !resp.starts_with("HTTP/1.1 101 ") && !resp.starts_with("HTTP/1.1 200 ") {
        anyhow::bail!("xHTTP handshake failed: expected 101 or 200, got: {}", resp.lines().next().unwrap_or(""));
    }
    if !resp.to_ascii_lowercase().contains("x-ostp-server:") {
        let safe_resp = resp.chars().take(200).collect::<String>().replace("\r\n", " | ");
        anyhow::bail!("xHTTP handshake failed: endpoint is not an OSTP server. Got: {}", safe_resp);
    }

    // 4. Extract leftover bytes after headers (data that arrived together with the response)
    let headers_end = buf[..header_len].windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let leftover = buf[headers_end..header_len].to_vec();

    // 5. Split into read/write halves and start UoT loops
    let (rx, tx) = tcp_stream.into_split();
    start_uot_loops(rx, tx, leftover)
}

fn start_uot_loops<R, W>(
    mut net_rx: R,
    mut net_tx: W,
    leftover: Vec<u8>
) -> Result<(mpsc::Sender<Bytes>, Arc<tokio::sync::Mutex<mpsc::Receiver<Bytes>>>)>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (app_tx, bridge_rx) = mpsc::channel::<Bytes>(1024);
    let (bridge_tx, app_rx) = mpsc::channel::<Bytes>(1024);

    // TX Loop (App -> UoT -> Network): prefix each frame with u16 BE length
    tokio::spawn(async move {
        let mut rx = bridge_rx;
        while let Some(frame) = rx.recv().await {
            let len = frame.len() as u16;
            if net_tx.write_u16(len).await.is_err() { break; }
            if net_tx.write_all(&frame).await.is_err() { break; }
        }
    });

    // RX Loop (Network -> UoT -> App): parse [u16 len][payload] frames
    tokio::spawn(async move {
        let mut buffer = BytesMut::from(&leftover[..]);
        loop {
            while buffer.len() < 2 {
                let mut temp = [0u8; 4096];
                match net_rx.read(&mut temp).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => buffer.extend_from_slice(&temp[..n]),
                }
            }
            let len = u16::from_be_bytes([buffer[0], buffer[1]]) as usize;

            while buffer.len() < 2 + len {
                let mut temp = [0u8; 4096];
                match net_rx.read(&mut temp).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => buffer.extend_from_slice(&temp[..n]),
                }
            }

            let packet = buffer.split_to(2 + len);
            if app_tx.send(Bytes::from(packet[2..].to_vec())).await.is_err() {
                break;
            }
        }
    });

    Ok((bridge_tx, Arc::new(tokio::sync::Mutex::new(app_rx))))
}
