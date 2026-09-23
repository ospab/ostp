//! Plain-HTTP side of the built-in frontend (port 80): ACME challenges are
//! answered (see `acme::challenge_router`), everything else is redirected to
//! https on the configured domain.

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

    pub fn redirect(&self, uri: &Uri) -> Response {
        let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
        Redirect::permanent(&format!("{}{}", self.base, path)).into_response()
    }
}

pub async fn serve(listener: TcpListener, app: Router) {
    if let Err(e) = axum::serve(listener, app).await {
        tracing::error!("HTTP frontend stopped: {e}");
    }
}
