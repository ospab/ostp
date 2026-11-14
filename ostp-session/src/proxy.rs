//! The local proxy's side of a SOCKS5 or HTTP CONNECT handshake, without I/O: feed it
//! what the program sent, send back what it says, and open a stream to the target it
//! names. Both protocols on one port, told apart by the first byte.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// Longest request accepted (an HTTP CONNECT with its headers).
const MAX_REQUEST: usize = 8 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Socks5,
    HttpConnect,
}

/// What to do after feeding bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Wait for more bytes.
    NeedMore,
    /// Send this to the program, then keep feeding.
    Reply(Vec<u8>),
    /// Open a stream to `target` (`host:port`). Once it is connected send
    /// [`success_reply`], then `leftover` (bytes the program sent after its request)
    /// belongs to the stream.
    Connect { kind: Kind, target: String, leftover: Vec<u8> },
    /// Refuse: send `reply` and close.
    Refuse { reply: Vec<u8>, reason: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    First,
    SocksRequest,
    Done,
}

/// One program's handshake with the proxy.
#[derive(Debug)]
pub struct Handshake {
    buf: Vec<u8>,
    stage: Stage,
}

impl Default for Handshake {
    fn default() -> Self {
        Handshake::new()
    }
}

impl Handshake {
    pub fn new() -> Handshake {
        Handshake { buf: Vec::new(), stage: Stage::First }
    }

    pub fn feed(&mut self, data: &[u8]) -> Step {
        if self.stage == Stage::Done {
            return Step::NeedMore;
        }
        self.buf.extend_from_slice(data);
        if self.buf.len() > MAX_REQUEST {
            self.stage = Stage::Done;
            return Step::Refuse { reply: http_reply(431, "Request Header Fields Too Large"), reason: String::from("request too large") };
        }
        let step = match self.stage {
            Stage::First => match self.buf.first() {
                None => Step::NeedMore,
                Some(5) => self.socks_greeting(),
                Some(_) => self.http(),
            },
            Stage::SocksRequest => self.socks_request(),
            Stage::Done => Step::NeedMore,
        };
        if matches!(step, Step::Connect { .. } | Step::Refuse { .. }) {
            self.stage = Stage::Done;
        }
        step
    }

    fn socks_greeting(&mut self) -> Step {
        // VER NMETHODS METHODS...
        if self.buf.len() < 2 {
            return Step::NeedMore;
        }
        let n = self.buf[1] as usize;
        if self.buf.len() < 2 + n {
            return Step::NeedMore;
        }
        let no_auth = self.buf[2..2 + n].contains(&0);
        self.buf.drain(..2 + n);
        if !no_auth {
            return Step::Refuse { reply: alloc::vec![5, 0xFF], reason: String::from("SOCKS5 client wants authentication") };
        }
        self.stage = Stage::SocksRequest;
        // A client may send its request right behind the greeting.
        if self.buf.is_empty() {
            Step::Reply(alloc::vec![5, 0])
        } else {
            match self.socks_request() {
                Step::NeedMore => Step::Reply(alloc::vec![5, 0]),
                Step::Connect { kind, target, leftover } => {
                    // The method reply goes first; the caller sends it with the success reply.
                    Step::Connect { kind, target, leftover }
                }
                other => other,
            }
        }
    }

    fn socks_request(&mut self) -> Step {
        // VER CMD RSV ATYP DST.ADDR DST.PORT
        let b = &self.buf;
        if b.len() < 5 {
            return Step::NeedMore;
        }
        if b[0] != 5 {
            return Step::Refuse { reply: socks_reply(1), reason: String::from("not a SOCKS5 request") };
        }
        if b[1] != 1 {
            return Step::Refuse { reply: socks_reply(7), reason: format!("SOCKS5 command {} is not supported (only CONNECT)", b[1]) };
        }
        let (host, at) = match b[3] {
            1 => {
                if b.len() < 4 + 4 + 2 {
                    return Step::NeedMore;
                }
                (format!("{}.{}.{}.{}", b[4], b[5], b[6], b[7]), 8)
            }
            3 => {
                let n = b[4] as usize;
                if b.len() < 5 + n + 2 {
                    return Step::NeedMore;
                }
                match core::str::from_utf8(&b[5..5 + n]) {
                    Ok(s) if !s.is_empty() => (s.to_string(), 5 + n),
                    _ => return Step::Refuse { reply: socks_reply(1), reason: String::from("bad SOCKS5 host name") },
                }
            }
            4 => {
                if b.len() < 4 + 16 + 2 {
                    return Step::NeedMore;
                }
                let mut a = [0u8; 16];
                a.copy_from_slice(&b[4..20]);
                (format!("[{}]", core::net::Ipv6Addr::from(a)), 20)
            }
            t => return Step::Refuse { reply: socks_reply(8), reason: format!("SOCKS5 address type {t} is not supported") },
        };
        let port = u16::from_be_bytes([b[at], b[at + 1]]);
        let leftover = b[at + 2..].to_vec();
        self.buf.clear();
        Step::Connect { kind: Kind::Socks5, target: format!("{host}:{port}"), leftover }
    }

    fn http(&mut self) -> Step {
        let end = match self.buf.windows(4).position(|w| w == b"\r\n\r\n") {
            Some(e) => e,
            None => return Step::NeedMore,
        };
        let head = match core::str::from_utf8(&self.buf[..end]) {
            Ok(h) => h,
            Err(_) => return Step::Refuse { reply: http_reply(400, "Bad Request"), reason: String::from("request is not text") },
        };
        let line = head.split("\r\n").next().unwrap_or("");
        let mut parts = line.split(' ');
        let method = parts.next().unwrap_or("");
        let target = parts.next().unwrap_or("");
        if !method.eq_ignore_ascii_case("CONNECT") {
            return Step::Refuse {
                reply: http_reply(405, "Method Not Allowed"),
                reason: format!("HTTP {method} is not supported (only CONNECT)"),
            };
        }
        let ok = target.rsplit_once(':').is_some_and(|(h, p)| !h.is_empty() && p.parse::<u16>().is_ok_and(|p| p != 0));
        if !ok {
            return Step::Refuse { reply: http_reply(400, "Bad Request"), reason: format!("CONNECT target {target:?} is not host:port") };
        }
        let target = target.to_string();
        let leftover = self.buf[end + 4..].to_vec();
        self.buf.clear();
        Step::Connect { kind: Kind::HttpConnect, target, leftover }
    }
}

fn http_reply(code: u16, text: &str) -> Vec<u8> {
    format!("HTTP/1.1 {code} {text}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").into_bytes()
}

fn socks_reply(code: u8) -> Vec<u8> {
    alloc::vec![5, code, 0, 1, 0, 0, 0, 0, 0, 0]
}

/// What tells the program its stream is open. For SOCKS5 a request that came together
/// with the greeting still needs the method reply first: pass `with_method_reply`.
pub fn success_reply(kind: Kind, with_method_reply: bool) -> Vec<u8> {
    match kind {
        Kind::Socks5 => {
            let mut v = Vec::new();
            if with_method_reply {
                v.extend_from_slice(&[5, 0]);
            }
            v.extend_from_slice(&socks_reply(0));
            v
        }
        Kind::HttpConnect => b"HTTP/1.1 200 Connection established\r\n\r\n".to_vec(),
    }
}

/// What tells the program the target could not be reached.
pub fn failure_reply(kind: Kind, with_method_reply: bool) -> Vec<u8> {
    match kind {
        Kind::Socks5 => {
            let mut v = Vec::new();
            if with_method_reply {
                v.extend_from_slice(&[5, 0]);
            }
            v.extend_from_slice(&socks_reply(5));
            v
        }
        Kind::HttpConnect => http_reply(502, "Bad Gateway"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socks5_in_two_steps() {
        let mut h = Handshake::new();
        assert_eq!(h.feed(&[5, 1, 0]), Step::Reply(alloc::vec![5, 0]));
        let mut req = alloc::vec![5, 1, 0, 3, 11];
        req.extend_from_slice(b"example.com");
        req.extend_from_slice(&443u16.to_be_bytes());
        req.extend_from_slice(b"hello");
        assert_eq!(
            h.feed(&req),
            Step::Connect { kind: Kind::Socks5, target: "example.com:443".into(), leftover: b"hello".to_vec() }
        );
    }

    #[test]
    fn socks5_greeting_and_request_together() {
        let mut h = Handshake::new();
        let mut all = alloc::vec![5, 1, 0, 5, 1, 0, 1, 10, 0, 2, 2];
        all.extend_from_slice(&80u16.to_be_bytes());
        assert_eq!(h.feed(&all), Step::Connect { kind: Kind::Socks5, target: "10.0.2.2:80".into(), leftover: Vec::new() });
    }

    #[test]
    fn socks5_refuses_udp_associate_and_auth_only() {
        let mut h = Handshake::new();
        assert!(matches!(h.feed(&[5, 1, 2]), Step::Refuse { .. }));
        let mut h = Handshake::new();
        h.feed(&[5, 1, 0]);
        assert!(matches!(h.feed(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]), Step::Refuse { .. }));
    }

    #[test]
    fn http_connect_byte_by_byte() {
        let req = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\nTLS";
        let mut h = Handshake::new();
        for (i, b) in req.iter().enumerate() {
            let s = h.feed(&[*b]);
            if i < req.len() - 4 {
                assert_eq!(s, Step::NeedMore, "at byte {i}");
            } else if i == req.len() - 4 {
                assert_eq!(s, Step::Connect { kind: Kind::HttpConnect, target: "example.com:443".into(), leftover: Vec::new() });
            }
        }
        let mut h = Handshake::new();
        assert_eq!(
            h.feed(req),
            Step::Connect { kind: Kind::HttpConnect, target: "example.com:443".into(), leftover: b"TLS".to_vec() }
        );
    }

    #[test]
    fn plain_http_is_refused() {
        let mut h = Handshake::new();
        match h.feed(b"GET http://example.com/ HTTP/1.1\r\n\r\n") {
            Step::Refuse { reply, .. } => assert!(reply.starts_with(b"HTTP/1.1 405")),
            other => panic!("{other:?}"),
        }
    }
}
