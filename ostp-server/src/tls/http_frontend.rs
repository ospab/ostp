//! Plain-HTTP side of the built-in frontend (port 80): everything is
//! redirected to https on the configured domain.

use axum::extract::State;
use axum::http::Uri;
use axum::response::{IntoResponse, Redirect, Response};
use axum::Router;
use std::sync::Arc;
use tokio::net::TcpListener;

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
}

pub fn redirect_router(target: RedirectTarget) -> Router {
    Router::new().fallback(redirect).with_state(target)
}

async fn redirect(State(t): State<RedirectTarget>, uri: Uri) -> Response {
    let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    Redirect::permanent(&format!("{}{}", t.base, path)).into_response()
}

pub async fn serve(listener: TcpListener, app: Router) {
    if let Err(e) = axum::serve(listener, app).await {
        tracing::error!("HTTP frontend stopped: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn redirects_to_configured_domain_ignoring_host() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, redirect_router(RedirectTarget::new("vpn.example.com", 443))));

        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(b"GET /a/b?c=1 HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n").await.unwrap();
        let mut resp = String::new();
        s.read_to_string(&mut resp).await.unwrap();
        assert!(resp.starts_with("HTTP/1.1 308"), "{resp}");
        assert!(resp.to_lowercase().contains("location: https://vpn.example.com/a/b?c=1"), "{resp}");
    }
}
