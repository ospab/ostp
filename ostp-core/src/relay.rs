use anyhow::{anyhow, Result};

#[derive(Debug, Clone)]
pub enum RelayMessage {
    Connect(String),
    Data(Vec<u8>),
    KeepAlive,
    Close,
    ConnectOk,
    Error(String),
    Ping(u64),
    Pong(u64),
    UdpAssociate,
    UdpData(String, Vec<u8>),
    /// Stream 0, once per session: the FEATURE_* bits the sender supports.
    /// The client sends it after the handshake and the server answers with
    /// the bits both support. A 0.4.5 peer does not know the message and
    /// drops it, so nothing changes with it.
    Features(u32),
    /// Flow control: the receiver of a stream allows its sender this many more
    /// bytes of `Data` on it. Only after both sides announced
    /// FEATURE_FLOW_CONTROL.
    Window(u32),
    /// v6 only: "I will write no more on this stream". The other direction
    /// keeps flowing; the stream ends when both sides sent one. It rides in
    /// sequenced `Data`, so it arrives after every byte before it.
    Fin,
    /// v6 only: the stream is aborted (the program or the target dropped the
    /// connection), with the reason (`ABORT_*`). Tag 4 like `Close`; a v5 peer
    /// never gets it.
    Abort(u8),
    /// Stream 0, client to server: "send me your `ServerInfo`". Sent only to
    /// a server that announced FEATURE_SERVER_INFO; an older server would
    /// not know the tag (it drops what it cannot decode).
    InfoRequest,
    /// Stream 0, server to client: one piece of the server-info JSON (see
    /// `server_info_messages`), `more` = further pieces follow. The JSON is
    /// split so each piece fits one datagram; stream 0 keeps them in order.
    ServerInfo { more: bool, chunk: Vec<u8> },
}

/// `RelayMessage::Abort` reasons.
/// The program or the target closed the connection abruptly.
pub const ABORT_CLOSED: u8 = 0;
/// An I/O error on the program's or the target's side.
pub const ABORT_IO_ERROR: u8 = 1;
/// The peer sent more than the stream's window allowed.
pub const ABORT_FLOW_CONTROL: u8 = 2;

/// Per-stream flow control (`Window`).
pub const FEATURE_FLOW_CONTROL: u32 = 1;
/// The server answers `InfoRequest` with `ServerInfo` (who runs it, what it
/// offers, this key's usage and expiry). Asked for in a v6 session too, where
/// flow control needs no negotiation: a server that predates the bit answers
/// without it, and the client then never sends `InfoRequest`.
pub const FEATURE_SERVER_INFO: u32 = 2;
/// The largest server-info JSON a client accepts, in bytes.
pub const SERVER_INFO_MAX: usize = 32 << 10;
/// Bytes a `ServerInfo` piece adds around its chunk: tag, flag and length.
pub const SERVER_INFO_OVERHEAD: usize = 4;
/// What a stream's sender may send before the first `Window`, in each
/// direction. It bounds the memory a slow destination (a site that takes an
/// upload slowly, an app that reads slowly) can make the other side hold,
/// and the throughput of one stream: 8 MiB per round trip is ~670 Mbit/s at
/// 100 ms.
pub const INITIAL_STREAM_WINDOW: u32 = 8 << 20;
/// The receiver grants more once this much has reached the destination.
pub const WINDOW_UPDATE_STEP: u32 = 1 << 20;

impl RelayMessage {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            RelayMessage::Connect(addr) => encode_with_len(1, addr.as_bytes()),
            RelayMessage::Data(data) => encode_with_len(2, data),
            RelayMessage::KeepAlive => vec![3],
            RelayMessage::Close => vec![4],
            RelayMessage::ConnectOk => vec![5],
            RelayMessage::Error(msg) => encode_with_len(6, msg.as_bytes()),
            RelayMessage::Ping(ts) => encode_with_len(7, &ts.to_be_bytes()),
            RelayMessage::Pong(ts) => encode_with_len(8, &ts.to_be_bytes()),
            RelayMessage::UdpAssociate => vec![9],
            RelayMessage::Features(bits) => encode_with_len(11, &bits.to_be_bytes()),
            RelayMessage::Window(bytes) => encode_with_len(12, &bytes.to_be_bytes()),
            RelayMessage::Fin => vec![13],
            RelayMessage::Abort(reason) => vec![4, *reason],
            RelayMessage::InfoRequest => vec![14],
            RelayMessage::ServerInfo { more, chunk } => {
                let mut out = vec![15, u8::from(*more)];
                out.extend_from_slice(&encode_with_len(0, chunk)[1..]);
                out
            }
            RelayMessage::UdpData(addr, data) => {
                let addr_bytes = addr.as_bytes();
                let mut buf = Vec::with_capacity(1 + 2 + addr_bytes.len() + 2 + data.len());
                buf.push(10);
                buf.extend_from_slice(&(addr_bytes.len() as u16).to_be_bytes());
                buf.extend_from_slice(addr_bytes);
                buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
                buf.extend_from_slice(data);
                buf
            }
        }
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.is_empty() {
            return Err(anyhow!("empty relay message"));
        }

        match input[0] {
            1 => {
                let payload = decode_with_len(&input[1..])?;
                let addr = String::from_utf8(payload.to_vec())
                    .map_err(|_| anyhow!("invalid utf8 in connect addr"))?;
                Ok(RelayMessage::Connect(addr))
            }
            2 => Ok(RelayMessage::Data(decode_with_len(&input[1..])?.to_vec())),
            3 => Ok(RelayMessage::KeepAlive),
            4 => Ok(match input.get(1) {
                Some(&reason) => RelayMessage::Abort(reason),
                None => RelayMessage::Close,
            }),
            13 => Ok(RelayMessage::Fin),
            5 => Ok(RelayMessage::ConnectOk),
            6 => {
                let payload = decode_with_len(&input[1..])?;
                let msg = String::from_utf8(payload.to_vec())
                    .map_err(|_| anyhow!("invalid utf8 in error message"))?;
                Ok(RelayMessage::Error(msg))
            }
            7 => {
                let payload = decode_with_len(&input[1..])?;
                if payload.len() != 8 { return Err(anyhow!("invalid ping payload len")); }
                let ts = u64::from_be_bytes(payload.try_into().map_err(|_| anyhow!("invalid ping payload size"))?);
                Ok(RelayMessage::Ping(ts))
            }
            8 => {
                let payload = decode_with_len(&input[1..])?;
                if payload.len() != 8 {
                    return Err(anyhow!("invalid pong payload"));
                }
                let mut ts = [0u8; 8];
                ts.copy_from_slice(payload);
                Ok(RelayMessage::Pong(u64::from_be_bytes(ts)))
            }
            9 => Ok(RelayMessage::UdpAssociate),
            10 => {
                if input.len() < 3 { return Err(anyhow!("invalid udp data")); }
                let addr_len = u16::from_be_bytes([input[1], input[2]]) as usize;
                if input.len() < 3 + addr_len + 2 { return Err(anyhow!("invalid udp data")); }
                let addr = String::from_utf8(input[3..3+addr_len].to_vec())
                    .map_err(|_| anyhow!("invalid utf8 in udp addr"))?;
                
                let data_offset = 3 + addr_len;
                let data_len = u16::from_be_bytes([input[data_offset], input[data_offset+1]]) as usize;
                if input.len() < data_offset + 2 + data_len { return Err(anyhow!("invalid udp data")); }
                
                let data = input[data_offset+2..data_offset+2+data_len].to_vec();
                Ok(RelayMessage::UdpData(addr, data))
            }
            14 => Ok(RelayMessage::InfoRequest),
            15 => {
                let flag = *input.get(1).ok_or_else(|| anyhow!("server info piece too short"))?;
                let chunk = decode_with_len(&input[2..])?.to_vec();
                Ok(RelayMessage::ServerInfo { more: flag & 1 != 0, chunk })
            }
            11 | 12 => {
                let payload = decode_with_len(&input[1..])?;
                let value = u32::from_be_bytes(payload.try_into().map_err(|_| anyhow!("invalid flow control payload"))?);
                Ok(if input[0] == 11 { RelayMessage::Features(value) } else { RelayMessage::Window(value) })
            }
            _ => Err(anyhow!("unknown relay message type {}", input[0])),
        }
    }
}

/// `json` as `ServerInfo` pieces that each fit a datagram carrying at most
/// `max_payload` bytes; the last one has `more: false`.
pub fn server_info_messages(json: &[u8], max_payload: usize) -> Vec<RelayMessage> {
    let size = max_payload.saturating_sub(SERVER_INFO_OVERHEAD).clamp(1, u16::MAX as usize);
    if json.is_empty() {
        return vec![RelayMessage::ServerInfo { more: false, chunk: Vec::new() }];
    }
    let count = json.len().div_ceil(size);
    json.chunks(size)
        .enumerate()
        .map(|(i, c)| RelayMessage::ServerInfo { more: i + 1 < count, chunk: c.to_vec() })
        .collect()
}

/// Puts `ServerInfo` pieces back together.
#[derive(Debug, Default)]
pub struct ServerInfoAssembler {
    buf: Vec<u8>,
    overflow: bool,
}

impl ServerInfoAssembler {
    /// Adds a piece. Returns the whole JSON text after the last piece, or
    /// `None` (more to come, or the document was too large or not UTF-8,
    /// in which case it is dropped and the next one starts clean).
    pub fn push(&mut self, more: bool, chunk: &[u8]) -> Option<String> {
        if !self.overflow {
            if self.buf.len() + chunk.len() > SERVER_INFO_MAX {
                self.overflow = true;
                self.buf = Vec::new();
            } else {
                self.buf.extend_from_slice(chunk);
            }
        }
        if more {
            return None;
        }
        let whole = std::mem::take(&mut self.buf);
        let overflow = std::mem::replace(&mut self.overflow, false);
        if overflow {
            return None;
        }
        String::from_utf8(whole).ok()
    }
}

/// Bytes a `Data` message adds around its payload: tag and length.
pub const DATA_OVERHEAD: usize = 3;

/// `data` as payloads for `Data` messages that each fit a datagram carrying
/// at most `max_payload` bytes (see `ProtocolMachine::max_payload`). A
/// datagram larger than the path MTU is split into IP fragments, which many
/// networks drop and where losing one fragment loses all of it; one over
/// 64 KiB could not be framed at all.
pub fn data_chunks(data: &[u8], max_payload: usize) -> std::slice::Chunks<'_, u8> {
    let size = max_payload.saturating_sub(DATA_OVERHEAD).clamp(1, u16::MAX as usize);
    data.chunks(size)
}

fn encode_with_len(tag: u8, payload: &[u8]) -> Vec<u8> {
    // Callers split with `data_chunks`; a longer payload is a bug, and
    // truncating it would corrupt the stream without a trace.
    debug_assert!(payload.len() <= u16::MAX as usize, "relay payload of {} bytes", payload.len());
    if payload.len() > u16::MAX as usize {
        tracing::error!("relay payload of {} bytes truncated to 65535: the caller did not split it", payload.len());
    }
    let len = payload.len().min(u16::MAX as usize) as u16;
    let mut out = Vec::with_capacity(1 + 2 + len as usize);
    out.push(tag);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&payload[..len as usize]);
    out
}

fn decode_with_len(input: &[u8]) -> Result<&[u8]> {
    if input.len() < 2 {
        return Err(anyhow!("relay payload length prefix missing"));
    }
    let len = u16::from_be_bytes([input[0], input[1]]) as usize;
    if input.len() < 2 + len {
        return Err(anyhow!("relay payload truncated"));
    }
    Ok(&input[2..2 + len])
}

#[cfg(test)]
mod tests {
    #[test]
    fn flow_control_messages_round_trip() {
        for msg in [RelayMessage::Features(FEATURE_FLOW_CONTROL), RelayMessage::Window(INITIAL_STREAM_WINDOW)] {
            let back = RelayMessage::decode(&msg.encode()).unwrap();
            assert_eq!(format!("{back:?}"), format!("{msg:?}"));
        }
        assert!(RelayMessage::decode(&[12, 0, 2, 1, 2]).is_err(), "a short window is refused");
    }

    use super::*;

    #[test]
    fn fin_and_abort_are_new_tags_and_close_is_unchanged() {
        assert_eq!(RelayMessage::Fin.encode(), vec![13]);
        assert!(matches!(RelayMessage::decode(&[13]).unwrap(), RelayMessage::Fin));
        assert_eq!(RelayMessage::Abort(ABORT_IO_ERROR).encode(), vec![4, 1]);
        assert!(matches!(RelayMessage::decode(&[4, 2]).unwrap(), RelayMessage::Abort(2)));
        // The v5 close is the one byte it always was and still decodes as it did.
        assert_eq!(RelayMessage::Close.encode(), vec![4]);
        assert!(matches!(RelayMessage::decode(&[4]).unwrap(), RelayMessage::Close));
    }

    #[test]
    fn server_info_is_split_to_fit_and_put_back_together() {
        assert_eq!(RelayMessage::InfoRequest.encode(), vec![14]);
        assert!(matches!(RelayMessage::decode(&[14]).unwrap(), RelayMessage::InfoRequest));
        let json: Vec<u8> = (0..5000u32).map(|i| b'a' + (i % 26) as u8).collect();
        let pieces = server_info_messages(&json, 1200);
        assert!(pieces.len() > 1);
        let mut asm = ServerInfoAssembler::default();
        let mut out = None;
        for (i, p) in pieces.iter().enumerate() {
            let wire = p.encode();
            assert!(wire.len() <= 1200, "a piece fits the datagram");
            match RelayMessage::decode(&wire).unwrap() {
                RelayMessage::ServerInfo { more, chunk } => {
                    assert_eq!(more, i + 1 < pieces.len());
                    out = asm.push(more, &chunk);
                }
                _ => panic!("expected ServerInfo"),
            }
        }
        assert_eq!(out.unwrap().as_bytes(), &json[..]);
        // Small: one piece.
        let one = server_info_messages(b"{}", 1200);
        assert_eq!(one.len(), 1);
        assert_eq!(ServerInfoAssembler::default().push(false, b"{}").as_deref(), Some("{}"));
        // Too large: dropped, and the next one is read cleanly.
        let mut asm = ServerInfoAssembler::default();
        assert_eq!(asm.push(true, &vec![b'x'; SERVER_INFO_MAX]), None);
        assert_eq!(asm.push(false, b"y"), None);
        assert_eq!(asm.push(false, b"{}").as_deref(), Some("{}"));
        assert!(RelayMessage::decode(&[15]).is_err());
        assert!(RelayMessage::decode(&[15, 0, 0, 5, 1]).is_err());
    }

    #[test]
    fn test_connect_roundtrip() {
        let msg = RelayMessage::Connect("example.com:443".to_string());
        let encoded = msg.encode();
        let decoded = RelayMessage::decode(&encoded).unwrap();
        match decoded {
            RelayMessage::Connect(addr) => assert_eq!(addr, "example.com:443"),
            _ => panic!("expected Connect"),
        }
    }

    #[test]
    fn test_data_roundtrip() {
        let data = vec![1, 2, 3, 4, 5];
        let msg = RelayMessage::Data(data.clone());
        let encoded = msg.encode();
        let decoded = RelayMessage::decode(&encoded).unwrap();
        match decoded {
            RelayMessage::Data(d) => assert_eq!(d, data),
            _ => panic!("expected Data"),
        }
    }

    #[test]
    fn test_simple_tags() {
        assert_eq!(RelayMessage::KeepAlive.encode(), vec![3]);
        assert_eq!(RelayMessage::Close.encode(), vec![4]);
        assert_eq!(RelayMessage::ConnectOk.encode(), vec![5]);

        assert!(matches!(RelayMessage::decode(&[3]).unwrap(), RelayMessage::KeepAlive));
        assert!(matches!(RelayMessage::decode(&[4]).unwrap(), RelayMessage::Close));
        assert!(matches!(RelayMessage::decode(&[5]).unwrap(), RelayMessage::ConnectOk));
    }

    #[test]
    fn test_error_roundtrip() {
        let msg = RelayMessage::Error("connection refused".to_string());
        let encoded = msg.encode();
        match RelayMessage::decode(&encoded).unwrap() {
            RelayMessage::Error(e) => assert_eq!(e, "connection refused"),
            _ => panic!("expected Error"),
        }
    }

    #[test]
    fn test_ping_pong_roundtrip() {
        let ts = 1234567890u64;
        match RelayMessage::decode(&RelayMessage::Ping(ts).encode()).unwrap() {
            RelayMessage::Ping(t) => assert_eq!(t, ts),
            _ => panic!("expected Ping"),
        }
        match RelayMessage::decode(&RelayMessage::Pong(ts).encode()).unwrap() {
            RelayMessage::Pong(t) => assert_eq!(t, ts),
            _ => panic!("expected Pong"),
        }
    }

    #[test]
    fn test_error_cases() {
        assert!(RelayMessage::decode(&[]).is_err());
        assert!(RelayMessage::decode(&[255]).is_err());
        // Truncated: tag=1, len=5, only 2 bytes
        assert!(RelayMessage::decode(&[1, 0, 5, b'a', b'b']).is_err());
    }

    #[test]
    fn test_empty_data_roundtrip() {
        let encoded = RelayMessage::Data(vec![]).encode();
        match RelayMessage::decode(&encoded).unwrap() {
            RelayMessage::Data(d) => assert!(d.is_empty()),
            _ => panic!("expected Data"),
        }
    }

    #[test]
    fn data_chunks_fit_the_datagram() {
        let data = vec![7u8; 65_536];
        let chunks: Vec<&[u8]> = data_chunks(&data, 1100).collect();
        assert!(chunks.iter().all(|c| c.len() + DATA_OVERHEAD <= 1100));
        assert_eq!(chunks.concat(), data, "nothing lost, nothing reordered");
        // Each chunk encodes without truncation.
        for c in chunks {
            match RelayMessage::decode(&RelayMessage::Data(c.to_vec()).encode()).unwrap() {
                RelayMessage::Data(d) => assert_eq!(d, c),
                _ => panic!("expected Data"),
            }
        }
    }
}

