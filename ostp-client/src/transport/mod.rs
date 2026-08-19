
use std::sync::Arc;
use tokio::net::UdpSocket;
use bytes::Bytes;

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
