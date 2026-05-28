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
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use std::sync::Arc as StdArc;
use tokio_rustls::TlsConnector;

mod danger {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::DigitallySignedStruct;
    

    #[derive(Debug)]
    pub struct NoCertificateVerification;

    impl ServerCertVerifier for NoCertificateVerification {
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
                rustls::SignatureScheme::RSA_PKCS1_SHA384,
                rustls::SignatureScheme::RSA_PKCS1_SHA512,
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                rustls::SignatureScheme::ED25519,
            ]
        }
    }
}

type HmacSha256 = Hmac<Sha256>;

pub async fn connect_xhttp(
    target_ip: IpAddr,
    port: u16,
    sni: &str,
    access_key: &[u8],
    tls_enabled: bool,
) -> Result<(mpsc::Sender<Bytes>, Arc<tokio::sync::Mutex<mpsc::Receiver<Bytes>>>)> {
    let addr = std::net::SocketAddr::new(target_ip, port);
    let tcp_stream = TcpStream::connect(addr).await
        .with_context(|| format!("failed to connect to {}", addr))?;
    tcp_stream.set_nodelay(true)?;

    if tls_enabled {
        // Setup rustls client skipping cert validation (Reality self-signed certs)
        let mut config = ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(StdArc::new(danger::NoCertificateVerification))
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        let connector = TlsConnector::from(StdArc::new(config));
        let server_name = ServerName::try_from(sni.to_string())
            .unwrap_or_else(|_| ServerName::try_from("www.microsoft.com").unwrap())
            .to_owned();

        let tls_stream = connector.connect(server_name, tcp_stream).await
            .with_context(|| "TLS handshake failed")?;
        xhttp_handshake_and_loop(tls_stream, target_ip, sni, access_key).await
    } else {
        xhttp_handshake_and_loop(tcp_stream, target_ip, sni, access_key).await
    }
}

async fn xhttp_handshake_and_loop<S>(
    mut stream: S,
    target_ip: IpAddr,
    sni: &str,
    access_key: &[u8],
) -> Result<(mpsc::Sender<Bytes>, Arc<tokio::sync::Mutex<mpsc::Receiver<Bytes>>>)>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
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

    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;

    // 3. Read server response headers
    let mut buf = vec![0u8; 4096];
    let mut header_len = 0;
    loop {
        let n = stream.read(&mut buf[header_len..]).await?;
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
    let (rx, tx) = tokio::io::split(stream);
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
    let (app_tx, mut tx_rx) = mpsc::channel::<Bytes>(16384);
    let (rx_tx, app_rx) = mpsc::channel::<Bytes>(16384);

    // TX Loop (App -> UoT -> Network): prefix each frame with u16 BE length
    tokio::spawn(async move {
        while let Some(frame) = tx_rx.recv().await {
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
            if rx_tx.send(Bytes::from(packet[2..].to_vec())).await.is_err() {
                break;
            }
        }
    });

    Ok((app_tx, Arc::new(tokio::sync::Mutex::new(app_rx))))
}
