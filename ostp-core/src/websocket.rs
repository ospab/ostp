//! WebSocket framing (RFC 6455 §5) for the UoT byte stream after an HTTP
//! upgrade. The OSTP stream (length-prefixed datagrams) travels as the payload
//! of binary frames, so web servers, CDNs and proxies that look inside
//! WebSocket connections see a well-formed one: masked client frames, unmasked
//! server frames, pings answered with pongs, a close handshake.
//!
//! The codec here is plain functions; [`WsStream`] (feature `io`) wraps a
//! tokio stream with it.

/// Frame opcodes (RFC 6455 §5.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Opcode {
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
}

impl Opcode {
    fn from_u8(b: u8) -> Option<Opcode> {
        Some(match b {
            0x0 => Opcode::Continuation,
            0x1 => Opcode::Text,
            0x2 => Opcode::Binary,
            0x8 => Opcode::Close,
            0x9 => Opcode::Ping,
            0xA => Opcode::Pong,
            _ => return None,
        })
    }

    fn as_u8(self) -> u8 {
        match self {
            Opcode::Continuation => 0x0,
            Opcode::Text => 0x1,
            Opcode::Binary => 0x2,
            Opcode::Close => 0x8,
            Opcode::Ping => 0x9,
            Opcode::Pong => 0xA,
        }
    }

    pub fn is_control(self) -> bool {
        matches!(self, Opcode::Close | Opcode::Ping | Opcode::Pong)
    }
}

/// Which end of the connection: clients mask what they send and servers
/// require it (RFC 6455 §5.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

/// Largest data frame this side sends, and the largest frame it accepts.
pub const MAX_SEND_PAYLOAD: usize = 16 * 1024;
pub const MAX_RECV_PAYLOAD: usize = 1 << 20;

#[derive(Debug, PartialEq, Eq)]
pub struct Frame {
    pub fin: bool,
    pub opcode: Opcode,
    pub payload: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum WsError {
    /// RFC 6455 §5.1: a server must close on an unmasked client frame, and a
    /// client on a masked server frame.
    BadMasking,
    ReservedBits,
    UnknownOpcode(u8),
    /// Control frames are at most 125 bytes and never fragmented (§5.5).
    BadControlFrame,
    TooLarge(u64),
}

impl std::fmt::Display for WsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WsError::BadMasking => f.write_str("WebSocket frame masked the wrong way for this side"),
            WsError::ReservedBits => f.write_str("WebSocket frame with reserved bits set"),
            WsError::UnknownOpcode(o) => write!(f, "WebSocket frame with unknown opcode {o:#x}"),
            WsError::BadControlFrame => f.write_str("malformed WebSocket control frame"),
            WsError::TooLarge(n) => write!(f, "WebSocket frame of {n} bytes is too large"),
        }
    }
}

impl std::error::Error for WsError {}

/// Encodes one frame. `mask` is `Some` for frames a client sends.
pub fn encode_frame(fin: bool, opcode: Opcode, payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 14);
    out.push(if fin { 0x80 } else { 0 } | opcode.as_u8());
    let mask_bit = if mask.is_some() { 0x80 } else { 0 };
    match payload.len() {
        n if n < 126 => out.push(mask_bit | n as u8),
        n if n <= u16::MAX as usize => {
            out.push(mask_bit | 126);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            out.push(mask_bit | 127);
            out.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    match mask {
        Some(key) => {
            out.extend_from_slice(&key);
            out.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i % 4]));
        }
        None => out.extend_from_slice(payload),
    }
    out
}

/// Decodes one frame from the front of `buf`, as received by `role`.
/// `Ok(None)`: not complete yet. On success returns the frame and how many
/// bytes of `buf` it used.
pub fn decode_frame(buf: &[u8], role: Role) -> Result<Option<(Frame, usize)>, WsError> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let (b0, b1) = (buf[0], buf[1]);
    if b0 & 0x70 != 0 {
        return Err(WsError::ReservedBits);
    }
    let fin = b0 & 0x80 != 0;
    let opcode = Opcode::from_u8(b0 & 0x0F).ok_or(WsError::UnknownOpcode(b0 & 0x0F))?;
    let masked = b1 & 0x80 != 0;
    if masked != (role == Role::Server) {
        return Err(WsError::BadMasking);
    }
    let mut pos = 2;
    let len = match b1 & 0x7F {
        126 => {
            let Some(b) = buf.get(2..4) else { return Ok(None) };
            pos = 4;
            u16::from_be_bytes([b[0], b[1]]) as u64
        }
        127 => {
            let Some(b) = buf.get(2..10) else { return Ok(None) };
            pos = 10;
            u64::from_be_bytes(b.try_into().unwrap())
        }
        n => n as u64,
    };
    if opcode.is_control() && (len > 125 || !fin) {
        return Err(WsError::BadControlFrame);
    }
    if len > MAX_RECV_PAYLOAD as u64 {
        return Err(WsError::TooLarge(len));
    }
    let key = if masked {
        let Some(k) = buf.get(pos..pos + 4) else { return Ok(None) };
        pos += 4;
        Some([k[0], k[1], k[2], k[3]])
    } else {
        None
    };
    let end = pos + len as usize;
    let Some(body) = buf.get(pos..end) else { return Ok(None) };
    let payload = match key {
        Some(k) => body.iter().enumerate().map(|(i, b)| b ^ k[i % 4]).collect(),
        None => body.to_vec(),
    };
    Ok(Some((Frame { fin, opcode, payload }, end)))
}

#[cfg(feature = "io")]
pub use io::WsStream;

#[cfg(feature = "io")]
mod io {
    use super::*;
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    /// A byte stream carried in WebSocket binary frames over `inner`.
    /// Pings are answered, a close is answered and ends the stream, and
    /// shutting down sends a close (status 1000).
    pub struct WsStream<S> {
        inner: S,
        role: Role,
        /// Raw bytes read from `inner`, not yet decoded.
        inbuf: Vec<u8>,
        /// Decoded data waiting for the reader.
        data: Vec<u8>,
        data_pos: usize,
        /// Encoded frames waiting to be written to `inner`.
        out: Vec<u8>,
        out_pos: usize,
        close_sent: bool,
        eof: bool,
    }

    impl<S> WsStream<S> {
        /// `prefix`: bytes already read off `inner` after the upgrade.
        pub fn new(inner: S, role: Role, prefix: &[u8]) -> Self {
            WsStream {
                inner,
                role,
                inbuf: prefix.to_vec(),
                data: Vec::new(),
                data_pos: 0,
                out: Vec::new(),
                out_pos: 0,
                close_sent: false,
                eof: false,
            }
        }

        fn mask(&self) -> Option<[u8; 4]> {
            (self.role == Role::Client).then(rand::random)
        }

        fn queue(&mut self, opcode: Opcode, payload: &[u8]) {
            let frame = encode_frame(true, opcode, payload, self.mask());
            self.out.extend_from_slice(&frame);
        }
    }

    fn invalid(e: WsError) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, e)
    }

    impl<S: AsyncWrite + Unpin> WsStream<S> {
        /// Writes queued frames; `Ready(Ok)` once all are out.
        fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            while self.out_pos < self.out.len() {
                let n = std::task::ready!(Pin::new(&mut self.inner).poll_write(cx, &self.out[self.out_pos..]))?;
                if n == 0 {
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                self.out_pos += n;
            }
            self.out.clear();
            self.out_pos = 0;
            Poll::Ready(Ok(()))
        }
    }

    impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WsStream<S> {
        fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            let this = &mut *self;
            loop {
                if this.data_pos < this.data.len() {
                    let n = (this.data.len() - this.data_pos).min(buf.remaining());
                    buf.put_slice(&this.data[this.data_pos..this.data_pos + n]);
                    this.data_pos += n;
                    if this.data_pos == this.data.len() {
                        this.data.clear();
                        this.data_pos = 0;
                    }
                    return Poll::Ready(Ok(()));
                }
                if this.eof {
                    return Poll::Ready(Ok(()));
                }
                match decode_frame(&this.inbuf, this.role).map_err(invalid)? {
                    Some((frame, used)) => {
                        this.inbuf.drain(..used);
                        match frame.opcode {
                            Opcode::Binary | Opcode::Continuation => this.data = frame.payload,
                            Opcode::Text => return Poll::Ready(Err(invalid(WsError::UnknownOpcode(0x1)))),
                            Opcode::Ping => {
                                this.queue(Opcode::Pong, &frame.payload);
                                // Best effort now; the rest goes out with the next write or flush.
                                let _ = this.poll_drain(cx);
                            }
                            Opcode::Pong => {}
                            Opcode::Close => {
                                if !this.close_sent {
                                    // Echo the status code (§5.5.1).
                                    let code = frame.payload.get(..2).map(<[u8]>::to_vec).unwrap_or_default();
                                    this.queue(Opcode::Close, &code);
                                    this.close_sent = true;
                                    let _ = this.poll_drain(cx);
                                }
                                this.eof = true;
                            }
                        }
                    }
                    None => {
                        let mut chunk = [0u8; 16 * 1024];
                        let mut rb = ReadBuf::new(&mut chunk);
                        std::task::ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb))?;
                        if rb.filled().is_empty() {
                            this.eof = true;
                        } else {
                            this.inbuf.extend_from_slice(rb.filled());
                        }
                    }
                }
            }
        }
    }

    impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WsStream<S> {
        fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            let this = &mut *self;
            // One frame at a time: queued frames go out before new data.
            std::task::ready!(this.poll_drain(cx))?;
            if this.close_sent {
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            }
            let n = buf.len().min(MAX_SEND_PAYLOAD);
            this.queue(Opcode::Binary, &buf[..n]);
            let _ = this.poll_drain(cx)?;
            Poll::Ready(Ok(n))
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            std::task::ready!(self.poll_drain(cx))?;
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            if !self.close_sent {
                self.close_sent = true;
                self.queue(Opcode::Close, &1000u16.to_be_bytes());
            }
            std::task::ready!(self.poll_drain(cx))?;
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        #[tokio::test]
        async fn a_stream_crosses_in_frames_both_ways() {
            let (a, b) = tokio::io::duplex(64 * 1024);
            let mut client = WsStream::new(a, Role::Client, &[]);
            let mut server = WsStream::new(b, Role::Server, &[]);
            let big = vec![0x5Au8; 40_000]; // several frames
            client.write_all(&big).await.unwrap();
            client.flush().await.unwrap();
            let mut got = vec![0u8; big.len()];
            server.read_exact(&mut got).await.unwrap();
            assert_eq!(got, big);
            server.write_all(b"back").await.unwrap();
            server.flush().await.unwrap();
            let mut four = [0u8; 4];
            client.read_exact(&mut four).await.unwrap();
            assert_eq!(&four, b"back");
        }

        #[tokio::test]
        async fn pings_are_answered_and_close_ends_the_stream() {
            let (a, mut raw) = tokio::io::duplex(4096);
            let mut server = WsStream::new(a, Role::Server, &[]);
            // A client ping, then data, then a close with status 1001.
            raw.write_all(&encode_frame(true, Opcode::Ping, b"hi", Some([1, 2, 3, 4]))).await.unwrap();
            raw.write_all(&encode_frame(true, Opcode::Binary, b"data", Some([9, 9, 9, 9]))).await.unwrap();
            raw.write_all(&encode_frame(true, Opcode::Close, &1001u16.to_be_bytes(), Some([5, 6, 7, 8]))).await.unwrap();
            let mut all = Vec::new();
            server.read_to_end(&mut all).await.unwrap();
            assert_eq!(all, b"data");
            // Pong with the ping's payload, then the close echoed, both unmasked.
            let mut reply = vec![0u8; 64];
            let n = raw.read(&mut reply).await.unwrap();
            let (pong, used) = decode_frame(&reply[..n], Role::Client).unwrap().unwrap();
            assert_eq!((pong.opcode, pong.payload.as_slice()), (Opcode::Pong, &b"hi"[..]));
            let (close, _) = decode_frame(&reply[used..n], Role::Client).unwrap().unwrap();
            assert_eq!((close.opcode, close.payload), (Opcode::Close, 1001u16.to_be_bytes().to_vec()));
        }

        #[tokio::test]
        async fn a_server_refuses_unmasked_client_frames() {
            let (a, mut raw) = tokio::io::duplex(4096);
            let mut server = WsStream::new(a, Role::Server, &[]);
            raw.write_all(&encode_frame(true, Opcode::Binary, b"x", None)).await.unwrap();
            let mut buf = [0u8; 8];
            let e = server.read(&mut buf).await.unwrap_err();
            assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
        }

        #[tokio::test]
        async fn bytes_read_before_the_stream_are_decoded_first() {
            let (a, _b) = tokio::io::duplex(64);
            let prefix = encode_frame(true, Opcode::Binary, b"early", None);
            let mut client = WsStream::new(a, Role::Client, &prefix);
            let mut buf = [0u8; 5];
            client.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"early");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6455_examples() {
        // §5.7: a single-frame unmasked text message "Hello".
        let (f, n) = decode_frame(&[0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f], Role::Client).unwrap().unwrap();
        assert_eq!((f.opcode, f.payload.as_slice(), n), (Opcode::Text, &b"Hello"[..], 7));
        // §5.7: the same, masked with 37 fa 21 3d.
        let masked = [0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58];
        let (f, _) = decode_frame(&masked, Role::Server).unwrap().unwrap();
        assert_eq!(f.payload, b"Hello");
        assert_eq!(encode_frame(true, Opcode::Text, b"Hello", Some([0x37, 0xfa, 0x21, 0x3d])), masked);
        // §5.7: 256 bytes binary in a single unmasked frame: 16-bit length.
        let e = encode_frame(true, Opcode::Binary, &[0u8; 256], None);
        assert_eq!(&e[..4], &[0x82, 0x7E, 0x01, 0x00]);
        // 64 KiB: 64-bit length.
        let e = encode_frame(true, Opcode::Binary, &vec![0u8; 65536], None);
        assert_eq!(&e[..10], &[0x82, 0x7F, 0, 0, 0, 0, 0, 1, 0, 0]);
    }

    #[test]
    fn partial_and_bad_frames() {
        let full = encode_frame(true, Opcode::Binary, &[1u8; 300], Some([1, 2, 3, 4]));
        for cut in [0, 1, 3, 7, full.len() - 1] {
            assert_eq!(decode_frame(&full[..cut], Role::Server), Ok(None), "cut at {cut}");
        }
        assert_eq!(decode_frame(&full, Role::Client), Err(WsError::BadMasking));
        assert_eq!(decode_frame(&[0xC2, 0x80, 0, 0, 0, 0], Role::Server), Err(WsError::ReservedBits));
        assert_eq!(decode_frame(&[0x83, 0x80, 0, 0, 0, 0], Role::Server), Err(WsError::UnknownOpcode(3)));
        assert_eq!(decode_frame(&[0x09, 0x80, 0, 0, 0, 0], Role::Server), Err(WsError::BadControlFrame));
        let huge = [0x82, 0xFF, 0, 0, 0, 1, 0, 0, 0, 0];
        assert!(matches!(decode_frame(&huge, Role::Server), Err(WsError::TooLarge(_))));
    }
}
