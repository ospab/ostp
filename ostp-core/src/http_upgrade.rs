//! Minimal HTTP/1.1 Upgrade handshake used to carry UoT through a web server
//! (nginx/apache/caddy) on 443. Only the handshake is WebSocket-shaped; after
//! the 101 both ends exchange raw length-prefixed UoT frames, which the web
//! server tunnels without inspecting.

use base64::Engine;
use sha1::{Digest, Sha1};

const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Upper bound on a request or response head; anything larger is not ours.
pub const MAX_HEAD_BYTES: usize = 8192;

pub fn generate_ws_key() -> String {
    let nonce: [u8; 16] = rand::random();
    base64::engine::general_purpose::STANDARD.encode(nonce)
}

/// `Sec-WebSocket-Accept` for a given `Sec-WebSocket-Key` (RFC 6455 §4.2.2).
pub fn ws_accept_key(key: &str) -> String {
    let mut h = Sha1::new();
    h.update(key.trim().as_bytes());
    h.update(WS_GUID.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(h.finalize())
}

pub fn build_upgrade_request(path: &str, host: &str, key: &str) -> Vec<u8> {
    format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )
    .into_bytes()
}

pub fn build_upgrade_response(accept: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Accept: {accept}\r\n\r\n"
    )
    .into_bytes()
}

/// Length of the head including the terminating blank line, once complete.
pub fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6455_accept_vector() {
        assert_eq!(ws_accept_key("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn head_end_includes_blank_line() {
        let req = build_upgrade_request("/p", "h", "k");
        assert_eq!(find_head_end(&req), Some(req.len()));
        let mut more = req.clone();
        more.extend_from_slice(b"\x00\x05hello");
        assert_eq!(find_head_end(&more), Some(req.len()));
        assert_eq!(find_head_end(b"GET / HTTP/1.1\r\n"), None);
    }

    #[test]
    fn generated_keys_are_16_bytes() {
        let k = generate_ws_key();
        let raw = base64::engine::general_purpose::STANDARD.decode(k).unwrap();
        assert_eq!(raw.len(), 16);
    }
}
