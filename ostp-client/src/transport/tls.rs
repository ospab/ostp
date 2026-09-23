//! Client side of the optional TLS carrier and of the HTTP-upgrade handshake
//! used to reach OSTP through a web server on 443.

use anyhow::{anyhow, bail, Result};
use bytes::{Bytes, BytesMut};
use ostp_core::http_upgrade::{build_upgrade_request, find_head_end, generate_ws_key, ws_accept_key, MAX_HEAD_BYTES};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{timeout_at, Instant};
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

#[derive(Debug, Clone)]
pub struct TlsClientOptions {
    /// Name sent as SNI and checked against the certificate.
    pub sni: String,
    /// Skip certificate verification entirely.
    pub insecure: bool,
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn client_config(insecure: bool) -> Arc<rustls::ClientConfig> {
    static VERIFIED: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    static INSECURE: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    let cell = if insecure { &INSECURE } else { &VERIFIED };
    cell.get_or_init(|| {
        let builder = rustls::ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .expect("ring supports TLS 1.2 and 1.3");
        let mut cfg = if insecure {
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoCertificateVerification(provider())))
                .with_no_client_auth()
        } else {
            // Bundled Mozilla roots: identical on Android, Windows and minimal
            // Linux images, none of which reliably expose a system store.
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            builder.with_root_certificates(roots).with_no_client_auth()
        };
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(cfg)
    })
    .clone()
}

/// Accepts any certificate; the handshake signature is still checked, so the
/// peer must at least hold the key of the certificate it presents.
#[derive(Debug)]
struct NoCertificateVerification(Arc<CryptoProvider>);

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
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

pub async fn wrap_tls<S>(stream: S, opts: &TlsClientOptions, timeout: Duration) -> Result<TlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let name = ServerName::try_from(opts.sni.clone())
        .map_err(|_| anyhow!("\"{}\" is not a valid TLS server name", opts.sni))?;
    let connector = TlsConnector::from(client_config(opts.insecure));
    match tokio::time::timeout(timeout, connector.connect(name, stream)).await {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => {
            let msg = e.to_string();
            if msg.to_ascii_lowercase().contains("certificate") {
                bail!(
                    "TLS certificate check failed for \"{}\": {msg}. The server's certificate is not valid \
                     for this name (tls_insecure skips the check, for testing only)",
                    opts.sni
                )
            }
            bail!("TLS handshake with \"{}\" failed: {msg}", opts.sni)
        }
        Err(_) => bail!("TLS handshake with \"{}\" timed out after {:?}", opts.sni, timeout),
    }
}

/// What an upgrade status most likely means, for the error shown to the user.
fn upgrade_status_hint(code: u16) -> &'static str {
    match code {
        404 => "the server does not know this path: the link's path differs from the server's tls.ws_path",
        429 => "the server is rate-limiting this address; wait a few seconds",
        502 | 503 | 504 => {
            "the web server on 443 could not reach OSTP behind it: check that the ostp service is running and              listening on the port its site forwards to (ostp cert status on the server tests this)"
        }
        301 | 302 | 307 | 308 => "the web server redirects this path instead of forwarding it to OSTP",
        _ => "not an OSTP upgrade answer",
    }
}

/// Sends the upgrade request and waits for `101`; returns whatever arrived
/// after the response head (the start of the UoT stream).
pub async fn http_upgrade<S>(s: &mut S, path: &str, host: &str, timeout: Duration) -> Result<Bytes>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let key = generate_ws_key();
    s.write_all(&build_upgrade_request(path, host, &key)).await?;
    s.flush().await?;

    let deadline = Instant::now() + timeout;
    let mut buf = BytesMut::with_capacity(1024);
    let head_len = loop {
        if let Some(n) = find_head_end(&buf) {
            break n;
        }
        if buf.len() >= MAX_HEAD_BYTES {
            bail!("upgrade response head is too large");
        }
        let n = timeout_at(deadline, s.read_buf(&mut buf))
            .await
            .map_err(|_| anyhow!("no answer to the upgrade request within {:?}", timeout))??;
        if n == 0 {
            bail!("connection closed during the upgrade, before any answer (wrong port, or not an OSTP server)");
        }
    };

    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut resp = httparse::Response::new(&mut headers);
    resp.parse(&buf[..head_len])?;
    let code = resp.code.unwrap_or(0);
    if code != 101 {
        bail!(
            "upgrade rejected: HTTP {code} {} ({})",
            resp.reason.unwrap_or(""),
            upgrade_status_hint(code)
        );
    }
    let accept = resp
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("sec-websocket-accept"))
        .and_then(|h| std::str::from_utf8(h.value).ok())
        .map(str::trim);
    if accept != Some(ws_accept_key(&key).as_str()) {
        bail!("the upgrade was answered by something other than OSTP (bad Sec-WebSocket-Accept)");
    }
    Ok(buf.split_off(head_len).freeze())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn upgrade_returns_bytes_after_the_head() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let srv = tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let n = server.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let key = req
                .lines()
                .find_map(|l| l.strip_prefix("Sec-WebSocket-Key: "))
                .unwrap()
                .trim()
                .to_string();
            assert!(req.starts_with("GET /s3cr3t HTTP/1.1\r\nHost: vpn.example.com\r\n"));
            let mut resp = ostp_core::http_upgrade::build_upgrade_response(&ws_accept_key(&key));
            resp.extend_from_slice(&[0x00, 0x02, b'h', b'i']);
            server.write_all(&resp).await.unwrap();
        });
        let leftover = http_upgrade(&mut client, "/s3cr3t", "vpn.example.com", Duration::from_secs(2)).await.unwrap();
        assert_eq!(leftover.as_ref(), &[0x00, 0x02, b'h', b'i']);
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn upgrade_rejects_404_and_wrong_accept() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let _ = server.read(&mut buf).await;
            let _ = server.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").await;
        });
        let e = http_upgrade(&mut client, "/x", "h", Duration::from_secs(2)).await.unwrap_err();
        assert!(e.to_string().contains("404"), "{e}");

        let (mut client, mut server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let _ = server.read(&mut buf).await;
            let _ = server.write_all(&ostp_core::http_upgrade::build_upgrade_response("bogus")).await;
        });
        let e = http_upgrade(&mut client, "/x", "h", Duration::from_secs(2)).await.unwrap_err();
        assert!(e.to_string().contains("Sec-WebSocket-Accept"), "{e}");
    }

    #[test]
    fn configs_are_built_for_both_modes() {
        assert_eq!(client_config(false).alpn_protocols, vec![b"http/1.1".to_vec()]);
        assert_eq!(client_config(true).alpn_protocols, vec![b"http/1.1".to_vec()]);
    }
}
