use std::net::IpAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use bytes::{Bytes, BytesMut};
use anyhow::{Result, Context};
use tokio::sync::mpsc;
use rustls::pki_types::{ServerName, CertificateDer, UnixTime};
use rustls::client::danger::{ServerCertVerifier, ServerCertVerified, HandshakeSignatureValid};
use rustls::DigitallySignedStruct;
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use base64::Engine;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug)]
struct NoAuthVerifier;

impl ServerCertVerifier for NoAuthVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

pub async fn connect_xhttp(
    target_ip: IpAddr,
    port: u16,
    sni: &str,
    access_key: &[u8],
) -> Result<(mpsc::Sender<Bytes>, Arc<tokio::sync::Mutex<mpsc::Receiver<Bytes>>>)> {
    let addr = std::net::SocketAddr::new(target_ip, port);
    let tcp_stream = TcpStream::connect(addr).await
        .with_context(|| format!("failed to connect to {}", addr))?;
    tcp_stream.set_nodelay(true)?;

    // 1. Generate auth token
    let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
    let mut mac = HmacSha256::new_from_slice(access_key).unwrap_or_else(|_| HmacSha256::new_from_slice(b"").unwrap());
    mac.update(&timestamp.to_be_bytes());
    let sig = base64::prelude::BASE64_STANDARD.encode(mac.finalize().into_bytes());
    let auth_token = format!("{}:{}", timestamp, sig);

    let http_host = if sni.is_empty() { target_ip.to_string() } else { sni.to_string() };
    
    let req = format!(
        "GET /stream HTTP/1.1\r\n\
         Host: {}\r\n\
         Authorization: Bearer {}\r\n\
         Connection: keep-alive\r\n\
         \r\n",
        http_host, auth_token
    );

    // 2. TLS wrapping (if port 443)
    if port == 443 {
        let mut config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoAuthVerifier))
            .with_no_client_auth();
        config.alpn_protocols.push(b"http/1.1".to_vec());
        let tls_connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        
        let server_name = ServerName::try_from(http_host.as_str())
            .unwrap_or_else(|_| ServerName::try_from("localhost").unwrap())
            .to_owned();
            
        let mut tls_stream = tls_connector.connect(server_name, tcp_stream).await?;
        
        // HTTP Handshake
        tls_stream.write_all(req.as_bytes()).await?;
        tls_stream.flush().await?;
        
        let mut buf = vec![0u8; 4096];
        let mut header_len = 0;
        loop {
            let n = tls_stream.read(&mut buf[header_len..]).await?;
            if n == 0 { anyhow::bail!("connection closed before handshake complete"); }
            header_len += n;
            if buf[..header_len].windows(4).any(|w| w == b"\r\n\r\n") { break; }
        }
        let resp = String::from_utf8_lossy(&buf[..header_len]);
        if !resp.contains("200 OK") {
            anyhow::bail!("xHTTP handshake failed: expected 200 OK, got: {}", resp.lines().next().unwrap_or(""));
        }
        
        // Extract leftover payload if any
        let headers_end = buf[..header_len].windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let leftover = buf[headers_end..header_len].to_vec();
        
        // Split stream
        let (rx, tx) = tokio::io::split(tls_stream);
        start_uot_loops(rx, tx, leftover)
    } else {
        let mut tcp_stream = tcp_stream;
        tcp_stream.write_all(req.as_bytes()).await?;
        tcp_stream.flush().await?;
        
        let mut buf = vec![0u8; 4096];
        let mut header_len = 0;
        loop {
            let n = tcp_stream.read(&mut buf[header_len..]).await?;
            if n == 0 { anyhow::bail!("connection closed before handshake complete"); }
            header_len += n;
            if buf[..header_len].windows(4).any(|w| w == b"\r\n\r\n") { break; }
        }
        let resp = String::from_utf8_lossy(&buf[..header_len]);
        if !resp.contains("200 OK") {
            anyhow::bail!("xHTTP handshake failed: expected 200 OK, got: {}", resp.lines().next().unwrap_or(""));
        }
        
        let headers_end = buf[..header_len].windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let leftover = buf[headers_end..header_len].to_vec();
        
        let (rx, tx) = tcp_stream.into_split();
        start_uot_loops(rx, tx, leftover)
    }
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

    // TX Loop (App -> UoT -> Network)
    tokio::spawn(async move {
        let mut rx = bridge_rx;
        while let Some(frame) = rx.recv().await {
            let len = frame.len() as u16;
            if net_tx.write_u16(len).await.is_err() { break; }
            if net_tx.write_all(&frame).await.is_err() { break; }
        }
    });

    // RX Loop (Network -> UoT -> App)
    tokio::spawn(async move {
        let mut buffer = BytesMut::from(&leftover[..]);
        loop {
            // Read more data if buffer has less than 2 bytes
            while buffer.len() < 2 {
                let mut temp = [0u8; 1024];
                match net_rx.read(&mut temp).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => buffer.extend_from_slice(&temp[..n]),
                }
            }
            let len = u16::from_be_bytes([buffer[0], buffer[1]]) as usize;
            
            while buffer.len() < 2 + len {
                let mut temp = [0u8; 1024];
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
