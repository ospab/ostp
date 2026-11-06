use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use bytes::Bytes;

use crate::debug_preview::describe_foreign_bytes;

pub mod tls;
pub use tls::TlsClientOptions;

/// Budget for the TLS handshake and the HTTP upgrade, each.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(8);
/// A write that makes no progress this long means the connection is dead (a
/// closed window, a path that swallows segments). The writer then gives up and
/// drops the connection: `Transport::send` waits on the writer's queue from the
/// bridge loop, which also runs the stall detection, so an endless write would
/// freeze the recovery that is meant to replace this connection.
const WRITE_STALL: Duration = Duration::from_secs(10);

/// UoT/TCP connection parameters shared by the live bridge and the prober.
#[derive(Clone)]
pub struct UotOptions {
    /// IP_TTL / hop-limit override for this connection's outbound packets.
    /// `None` leaves the OS default. Used by the prober's TTL/TSPU scan to
    /// find the hop distance at which an operator's middlebox starts
    /// answering in place of the real server.
    pub ttl: Option<u32>,
    pub connect_timeout: Duration,
    /// Run UoT inside TLS.
    pub tls: Option<TlsClientOptions>,
    /// Secret HTTP-upgrade path (reaching OSTP through a web server).
    pub ws_path: Option<String>,
    /// Host header for the upgrade request (the configured server name).
    pub http_host: String,
}

/// Opens a UoT/TCP transport: optionally TLS and an HTTP upgrade, matching what a
/// real ostp server expects.
///
/// The returned receiver carries a human-readable note each time the
/// connection ends or errors with bytes left over that never formed a
/// complete ostp frame — the signature of an operator/DPI transparent proxy
/// answering in place of the real server (see `describe_foreign_bytes`).
/// Callers that don't need this (or that gate it behind their own debug
/// flag) can simply drop the receiver.
pub async fn connect_uot(
    target_ip: IpAddr,
    port: u16,
    opts: UotOptions,
) -> anyhow::Result<(Transport, mpsc::UnboundedReceiver<String>)> {
    let mut stream = tokio::time::timeout(
        opts.connect_timeout,
        tokio::net::TcpStream::connect((target_ip, port)),
    )
    .await
    .map_err(|_| {
        anyhow::anyhow!(
            "TCP connect to {target_ip}:{port} timed out after {:?}",
            opts.connect_timeout
        )
    })??;
    let _ = stream.set_nodelay(true);
    if let Some(ttl) = opts.ttl {
        let _ = stream.set_ttl(ttl);
    }

    match &opts.tls {
        Some(tls_opts) => {
            let mut tls = tls::wrap_tls(stream, tls_opts, TLS_HANDSHAKE_TIMEOUT).await?;
            let prefix = match &opts.ws_path {
                Some(path) => tls::http_upgrade(&mut tls, path, &opts.http_host, TLS_HANDSHAKE_TIMEOUT).await?,
                None => Bytes::new(),
            };
            let (r, w) = tokio::io::split(tls);
            Ok(spawn_uot_io(r, w, prefix).await)
        }
        None => {
            let prefix = match &opts.ws_path {
                Some(path) => tls::http_upgrade(&mut stream, path, &opts.http_host, TLS_HANDSHAKE_TIMEOUT).await?,
                None => Bytes::new(),
            };
            let (r, w) = stream.into_split();
            Ok(spawn_uot_io(r, w, prefix).await)
        }
    }
}

/// Runs the UoT framing over an established byte stream. `prefix` is data
/// already read off it (after an upgrade response).
async fn spawn_uot_io<R, W>(
    mut read_half: R,
    mut write_half: W,
    prefix: Bytes,
) -> (Transport, mpsc::UnboundedReceiver<String>)
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (tx_out, mut rx_out) = mpsc::channel::<Bytes>(1024);
    let (tx_in, rx_in) = mpsc::channel::<Bytes>(1024);
    let (foreign_tx, foreign_rx) = mpsc::unbounded_channel::<String>();

    // Writer: length-prefix each frame; each frame goes out as one write,
    // i.e. one TLS record.
    tokio::spawn(async move {
        while let Some(data) = rx_out.recv().await {
            let len_buf = (data.len() as u16).to_be_bytes();
            let mut frame = Vec::with_capacity(2 + data.len());
            frame.extend_from_slice(&len_buf);
            frame.extend_from_slice(&data);
            if !matches!(tokio::time::timeout(WRITE_STALL, write_half.write_all(&frame)).await, Ok(Ok(_))) { break; }
            if !matches!(tokio::time::timeout(WRITE_STALL, write_half.flush()).await, Ok(Ok(_))) { break; }
        }
        // The transport was dropped (or the stream failed): close our side.
        // Dropping a plain TCP write half already sends FIN, but a write half
        // of a split TLS stream closes nothing while the read half is alive,
        // and the peer may never send anything that would end the reader.
        // shutdown() sends close_notify and FIN, so the server (or the web
        // server in front of it) closes the connection instead of keeping it
        // open forever.
        let _ = tokio::time::timeout(Duration::from_secs(2), write_half.shutdown()).await;
    });

    // Reader: reads whatever is available and only pulls a frame out once the
    // full [len:2][payload] is in hand, instead of read_exact-ing the length
    // prefix and then the body as two separate blocking reads. That
    // distinction matters on mobile networks: some operators' DPI/transparent
    // proxy answers the TCP connection itself with a short block/redirect
    // page (a few hundred bytes) instead of relaying to the real ostp server.
    // Reading those bytes as a bogus length prefix would block on read_exact
    // for a body that never arrives and just time out with nothing to show
    // for it. This version notices the stream ending mid-frame and reports
    // the leftover bytes on `foreign_tx` — which by construction never
    // includes a successfully-parsed (and therefore genuine) ostp frame.
    let tx_in_clone = tx_in.clone();
    tokio::spawn(async move {
        let mut acc: Vec<u8> = prefix.to_vec();
        let mut chunk = [0u8; 4096];
        loop {
            if acc.len() >= 2 {
                let len = u16::from_be_bytes([acc[0], acc[1]]) as usize;
                if acc.len() >= 2 + len {
                    let data = acc[2..2 + len].to_vec();
                    acc.drain(0..2 + len);
                    if tx_in_clone.send(Bytes::from(data)).await.is_err() { break; }
                    continue;
                }
            }
            // Stop as soon as the transport is dropped rather than waiting
            // for bytes a silent peer may never send: this task owns the read
            // half, and with TLS that keeps the whole connection alive.
            let read = tokio::select! {
                read = read_half.read(&mut chunk) => read,
                _ = tx_in_clone.closed() => break,
            };
            match read {
                Ok(0) => {
                    if !acc.is_empty() {
                        let _ = foreign_tx.send(format!(
                            "connection closed with {} unparsed byte(s) left over \
                             (does not look like an ostp frame — possible operator/DPI \
                             interference): {}",
                            acc.len(),
                            describe_foreign_bytes(&acc)
                        ));
                    }
                    break;
                }
                Ok(n) => acc.extend_from_slice(&chunk[..n]),
                Err(e) => {
                    if !acc.is_empty() {
                        let _ = foreign_tx.send(format!(
                            "read error after {} unparsed byte(s) \
                             (does not look like an ostp frame — possible operator/DPI \
                             interference): {} ({})",
                            acc.len(),
                            describe_foreign_bytes(&acc),
                            e
                        ));
                    }
                    break;
                }
            }
        }
    });

    (
        Transport::Uot { tx: tx_out, rx: Arc::new(Mutex::new(rx_in)) },
        foreign_rx,
    )
}

#[derive(Clone)]
pub enum Transport {
    Udp(Arc<UdpSocket>),
    Uot {
        tx: tokio::sync::mpsc::Sender<Bytes>,
        rx: Arc<tokio::sync::Mutex<tokio::sync::mpsc::Receiver<Bytes>>>,
    }
}

impl Transport {
    pub async fn send(&self, frame: &Bytes) -> std::io::Result<usize> {
        match self {
            Self::Udp(sock) => sock.send(frame).await,
            Self::Uot { tx, .. } => {
                tx.send(frame.clone()).await.map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "uot closed"))?;
                Ok(frame.len())
            }
        }
    }

    pub async fn send_to(&self, frame: &Bytes, target: std::net::SocketAddr) -> std::io::Result<usize> {
        match self {
            Self::Udp(sock) => sock.send_to(frame, target).await,
            Self::Uot { .. } => self.send(frame).await,
        }
    }

    pub async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Udp(sock) => sock.recv(buf).await,
            Self::Uot { rx, .. } => {
                let mut rx = rx.lock().await;
                match rx.recv().await {
                    Some(bytes) => {
                        let len = bytes.len().min(buf.len());
                        buf[..len].copy_from_slice(&bytes[..len]);
                        Ok(len)
                    }
                    None => Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "uot closed")),
                }
            }
        }
    }

    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        match self {
            Self::Udp(sock) => sock.local_addr(),
            Self::Uot { .. } => Ok("0.0.0.0:0".parse().unwrap()),
        }
    }

    /// TTL-desync: send `decoys` as datagrams with the IP TTL lowered to `ttl`,
    /// then restore the socket's original TTL. The decoys are meant to reach an
    /// on-path DPI box and expire before the server — poisoning the box's view
    /// of the flow (it classifies on the decoy) while the server never sees
    /// them. Calibrate `ttl` to the injector hop distance the prober reports.
    ///
    /// UDP only: this manipulates individual datagrams' TTL. On UoT the carrier
    /// is one TCP stream, so a socket-level TTL change would apply to the real
    /// traffic too — proper TCP desync needs injected packets (a driver), which
    /// this deliberately does not attempt. No-op there.
    pub async fn send_ttl_decoys(&self, decoys: &[Bytes], ttl: u8) {
        let Self::Udp(sock) = self else { return };
        if decoys.is_empty() {
            return;
        }
        let restore = sock.ttl().unwrap_or(128);
        if sock.set_ttl(ttl as u32).is_err() {
            return;
        }
        for d in decoys {
            let _ = sock.send(d).await;
        }
        let _ = sock.set_ttl(restore);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    fn tls_acceptor() -> tokio_rustls::TlsAcceptor {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let chain = vec![cert.cert.der().clone()];
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap();
        tokio_rustls::TlsAcceptor::from(Arc::new(config))
    }

    fn options(tls: bool) -> UotOptions {
        UotOptions {
            ttl: None,
            connect_timeout: Duration::from_secs(2),
            tls: tls.then(|| TlsClientOptions { sni: "localhost".to_string(), insecure: true }),
            ws_path: None,
            http_host: "localhost".to_string(),
        }
    }

    /// A dropped transport must close its connection even when the server
    /// never sends anything. Inside TLS it did not: the reader task kept the
    /// stream open waiting for data, and every failed handshake or reconnect
    /// left one TLS connection behind. Through a web server each costs two of
    /// its worker connections, so a client retrying for a while exhausted
    /// nginx and every request, subscriptions included, got a 500.
    #[tokio::test]
    async fn dropped_tls_transport_closes_its_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = tls_acceptor();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            let mut buf = [0u8; 256];
            // Silent server: read until the client goes away.
            loop {
                match tls.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {}
                }
            }
        });

        let (transport, _foreign) = connect_uot(addr.ip(), addr.port(), options(true)).await.unwrap();
        drop(transport);

        tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .expect("the TLS connection stayed open after the transport was dropped")
            .unwrap();
    }

    #[tokio::test]
    async fn dropped_tcp_transport_closes_its_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 256];
            loop {
                match tcp.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {}
                }
            }
        });

        let (transport, _foreign) = connect_uot(addr.ip(), addr.port(), options(false)).await.unwrap();
        drop(transport);

        tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .expect("the TCP connection stayed open after the transport was dropped")
            .unwrap();
    }
}
