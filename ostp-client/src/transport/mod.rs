
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
}
