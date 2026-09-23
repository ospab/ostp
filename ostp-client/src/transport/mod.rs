use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use rand::Rng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use bytes::Bytes;

use crate::debug_preview::describe_foreign_bytes;

pub mod tls;
pub use tls::TlsClientOptions;

/// Budget for the TLS handshake and the HTTP upgrade, each.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(8);
/// Junk frames must keep the first byte of the stream in 0x00..=0x05 (a
/// frame length of at most 1535), which is how the server tells raw UoT
/// apart from TLS and HTTP on the same port.
const MAX_JUNK_LEN: usize = 1400;

/// UoT/TCP connection parameters shared by the live bridge and the prober.
#[derive(Clone)]
pub struct UotOptions {
    pub tcp_fragmentation: bool,
    pub frag_chunk: usize,
    pub frag_sleep: u64,
    pub junk_pc: [usize; 2],
    pub junk_ps: [usize; 2],
    pub access_key: Bytes,
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

/// Opens a UoT/TCP transport: optionally TLS and an HTTP upgrade, then junk
/// packets and an optional fragmented first frame (plain TCP only: inside TLS
/// they are encrypted and pointless), matching what a real ostp server expects.
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
            Ok(spawn_uot_io(r, w, prefix, &opts, false).await)
        }
        None => {
            let prefix = match &opts.ws_path {
                Some(path) => tls::http_upgrade(&mut stream, path, &opts.http_host, TLS_HANDSHAKE_TIMEOUT).await?,
                None => Bytes::new(),
            };
            let (r, w) = stream.into_split();
            Ok(spawn_uot_io(r, w, prefix, &opts, true).await)
        }
    }
}

/// Runs the UoT framing over an established byte stream. `prefix` is data
/// already read off it (after an upgrade response); `obfuscate` enables junk
/// frames and first-frame fragmentation, which only mean something on plain TCP.
async fn spawn_uot_io<R, W>(
    mut read_half: R,
    mut write_half: W,
    prefix: Bytes,
    opts: &UotOptions,
    obfuscate: bool,
) -> (Transport, mpsc::UnboundedReceiver<String>)
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let tcp_fragmentation = obfuscate && opts.tcp_fragmentation;
    let frag_chunk = opts.frag_chunk.max(1);
    let frag_sleep = opts.frag_sleep;

    if obfuscate {
        let [junk_pc_min, junk_pc_max] = opts.junk_pc;
        let [junk_ps_min, junk_ps_max] = opts.junk_ps;
        // Time-rotating per-key junk marker — NOT a global constant and NOT
        // even a static per-user value: it changes every window, so junk
        // carries no fixed DPI signature on the wire. All frames in this
        // burst are sent within milliseconds, so one window applies to all.
        let junk_marker = ostp_core::crypto::derive_junk_marker(
            &opts.access_key,
            ostp_core::crypto::current_junk_window(),
        );
        // Build all junk frames up front so ThreadRng isn't held across an
        // await point (keeps this future Send).
        let junk_frames: Vec<Vec<u8>> = {
            let mut rng = rand::thread_rng();
            let min_c = junk_pc_min;
            let max_c = junk_pc_max.max(min_c);
            let num_junk = rng.gen_range(min_c..=max_c);
            (0..num_junk)
                .map(|_| {
                    let min_s = junk_ps_min.clamp(1, MAX_JUNK_LEN);
                    let max_s = junk_ps_max.clamp(min_s, MAX_JUNK_LEN);
                    let junk_len = rng.gen_range(min_s..=max_s);
                    let mut frame = Vec::with_capacity(2 + junk_len);
                    frame.extend_from_slice(&(junk_len as u16).to_be_bytes());
                    let start = frame.len();
                    frame.resize(start + junk_len, 0);
                    rng.fill(&mut frame[start..]);
                    // Stamp this key's derived junk marker so the server drops it silently.
                    if junk_len >= 4 {
                        frame[start..start + 4].copy_from_slice(&junk_marker);
                    }
                    frame
                })
                .collect()
        };
        for frame in junk_frames {
            if write_half.write_all(&frame).await.is_err() { break; }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    let (tx_out, mut rx_out) = mpsc::channel::<Bytes>(1024);
    let (tx_in, rx_in) = mpsc::channel::<Bytes>(1024);
    let (foreign_tx, foreign_rx) = mpsc::unbounded_channel::<String>();

    // Writer: length-prefix each frame. With tcp_fragmentation on, split
    // the FIRST real frame (the handshake — junk above was written
    // directly, so it doesn't count) into tiny TCP segments with short
    // gaps so DPI can't reassemble/classify the handshake from one read.
    // Otherwise each frame goes out as one write, i.e. one TLS record.
    tokio::spawn(async move {
        let mut first_packet = true;
        while let Some(data) = rx_out.recv().await {
            let len_buf = (data.len() as u16).to_be_bytes();
            if first_packet && tcp_fragmentation {
                first_packet = false;
                if write_half.write_all(&len_buf[0..1]).await.is_err() { break; }
                tokio::time::sleep(Duration::from_millis(5)).await;
                if write_half.write_all(&len_buf[1..2]).await.is_err() { break; }
                tokio::time::sleep(Duration::from_millis(5)).await;
                let mut broke = false;
                for chunk in data.chunks(frag_chunk) {
                    if write_half.write_all(chunk).await.is_err() { broke = true; break; }
                    tokio::time::sleep(Duration::from_millis(frag_sleep)).await;
                }
                if broke { break; }
            } else {
                let mut frame = Vec::with_capacity(2 + data.len());
                frame.extend_from_slice(&len_buf);
                frame.extend_from_slice(&data);
                if write_half.write_all(&frame).await.is_err() { break; }
            }
            if write_half.flush().await.is_err() { break; }
        }
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
            match read_half.read(&mut chunk).await {
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
