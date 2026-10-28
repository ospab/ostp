//! Plain-HTTP side of the built-in frontend (port 80): ACME challenges are
//! answered (see `acme::challenge_router`), everything else is redirected to
//! https on the configured domain.

use axum::http::Uri;
use axum::response::{IntoResponse, Redirect, Response};
use axum::Router;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{sleep, Sleep};

/// This side only answers ACME challenges and redirects: a request that takes
/// longer than this to arrive and be answered is a slowloris, not a client.
const CONNECTION_DEADLINE: Duration = Duration::from_secs(30);
/// Connections served at once; the rest wait in the kernel's accept queue.
const MAX_CONNECTIONS: usize = 256;

#[derive(Clone)]
pub struct RedirectTarget {
    /// `https://domain[:port]`, taken from config, never from the Host header.
    pub base: Arc<str>,
}

impl RedirectTarget {
    pub fn new(domain: &str, public_port: u16) -> Self {
        let base = if public_port == 443 {
            format!("https://{domain}")
        } else {
            format!("https://{domain}:{public_port}")
        };
        Self { base: base.into() }
    }

    pub fn redirect(&self, uri: &Uri) -> Response {
        let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
        Redirect::permanent(&format!("{}{}", self.base, path)).into_response()
    }
}

/// A connection that fails every read and write once `CONNECTION_DEADLINE` has
/// passed (axum's `serve` has no header-read or request timeout of its own),
/// and holds a slot of the connection limit until dropped.
struct Deadline {
    io: TcpStream,
    timer: Pin<Box<Sleep>>,
    _permit: OwnedSemaphorePermit,
}

impl Deadline {
    fn expired(&mut self, cx: &mut Context<'_>) -> Option<io::Error> {
        match self.timer.as_mut().poll(cx) {
            Poll::Ready(()) => Some(io::Error::new(io::ErrorKind::TimedOut, "connection deadline")),
            Poll::Pending => None,
        }
    }
}

impl AsyncRead for Deadline {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if let Some(e) = self.expired(cx) {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for Deadline {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if let Some(e) = self.expired(cx) {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

struct Limited {
    inner: TcpListener,
    slots: Arc<Semaphore>,
}

impl axum::serve::Listener for Limited {
    type Io = Deadline;
    type Addr = std::net::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let permit = self.slots.clone().acquire_owned().await.expect("semaphore is never closed");
            match self.inner.accept().await {
                Ok((io, addr)) => {
                    let timer = Box::pin(sleep(CONNECTION_DEADLINE));
                    return (Deadline { io, timer, _permit: permit }, addr);
                }
                Err(e) => {
                    tracing::debug!("HTTP frontend accept failed: {e}");
                    sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

pub async fn serve(listener: TcpListener, app: Router) {
    let listener = Limited { inner: listener, slots: Arc::new(Semaphore::new(MAX_CONNECTIONS)) };
    if let Err(e) = axum::serve(listener, app).await {
        tracing::error!("HTTP frontend stopped: {e}");
    }
}
