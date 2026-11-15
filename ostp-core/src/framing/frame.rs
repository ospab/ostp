use bytes::{BufMut, Bytes, BytesMut};

use crate::protocol::ProtocolError;

const FRAME_HEADER_LEN: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameKind {
    Handshake = 1,
    Data = 2,
    Close = 3,
    KeepAlive = 4,
    Nack = 5,
    Ack = 6,
    /// v6 only: an unsequenced payload (UDP). Never retransmitted, not part of
    /// any stream's order.
    Datagram = 7,
    /// v6 only: the sender says some of its nonces will never arrive and, with
    /// a reason, that a stream is reset. See `ProtocolMachine`.
    Abandon = 8,
}

impl TryFrom<u8> for FrameKind {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Handshake),
            2 => Ok(Self::Data),
            3 => Ok(Self::Close),
            4 => Ok(Self::KeepAlive),
            5 => Ok(Self::Nack),
            6 => Ok(Self::Ack),
            7 => Ok(Self::Datagram),
            8 => Ok(Self::Abandon),
            _ => Err(ProtocolError::Framing("unknown frame kind".to_string())),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FrameHeader {
    pub version: u8,
    pub kind: FrameKind,
    pub stream_id: u16,
    pub payload_len: u32,
    pub pad_len: u16,
}

impl FrameHeader {
    pub fn encode(&self, out: &mut BytesMut) {
        out.put_u8(self.version);
        out.put_u8(self.kind as u8);
        // Anti-DPI: reserved bytes filled with random data instead of zeros
        // to prevent known-plaintext fingerprinting inside encrypted frames
        let rnd: u16 = rand::random();
        out.put_u16(rnd);
        out.put_u16(self.stream_id);
        out.put_u32(self.payload_len);
        out.put_u16(self.pad_len);
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ProtocolError> {
        if buf.len() < FRAME_HEADER_LEN {
            return Err(ProtocolError::Framing("truncated frame header".to_string()));
        }

        let version = buf[0];
        let kind = FrameKind::try_from(buf[1])?;
        // buf[2] and buf[3] are reserved
        let stream_id = u16::from_be_bytes([buf[4], buf[5]]);
        let payload_len = u32::from_be_bytes([buf[6], buf[7], buf[8], buf[9]]);
        let pad_len = u16::from_be_bytes([buf[10], buf[11]]);

        Ok(Self {
            version,
            kind,
            stream_id,
            payload_len,
            pad_len,
        })
    }
}

#[derive(Debug, Clone)]
pub struct FramedPacket {
    pub header: FrameHeader,
    pub payload: Bytes,
    pub padding: Bytes,
}

impl FramedPacket {
    pub fn encode(&self) -> Bytes {
        let total = FRAME_HEADER_LEN + self.payload.len() + self.padding.len();
        let mut out = BytesMut::with_capacity(total);
        self.header.encode(&mut out);
        out.extend_from_slice(&self.payload);
        out.extend_from_slice(&self.padding);
        out.freeze()
    }

    pub fn decode_zero_copy(buf: Bytes) -> Result<Self, ProtocolError> {
        if buf.len() < FRAME_HEADER_LEN {
            return Err(ProtocolError::Framing("frame too short".to_string()));
        }

        let header = FrameHeader::decode(&buf[..FRAME_HEADER_LEN])?;
        let payload_len = header.payload_len as usize;
        let pad_len = header.pad_len as usize;

        // Use checked arithmetic: payload_len is a u32 from the (decrypted, but
        // still to-be-trusted) header, and on 32-bit targets — MIPS/ARMv7
        // routers are supported build targets — header+payload+pad can overflow
        // usize and wrap to a small value that spuriously passes the length
        // check, causing an out-of-range slice below.
        let expected = FRAME_HEADER_LEN
            .checked_add(payload_len)
            .and_then(|v| v.checked_add(pad_len))
            .ok_or_else(|| ProtocolError::Framing("frame length overflow".to_string()))?;
        if buf.len() < expected {
            return Err(ProtocolError::Framing("frame body truncated".to_string()));
        }

        let payload = buf.slice(FRAME_HEADER_LEN..FRAME_HEADER_LEN + payload_len);
        let padding = buf.slice(FRAME_HEADER_LEN + payload_len..expected);

        Ok(Self {
            header,
            payload,
            padding,
        })
    }
}

// ── Frame header v2 (v6 sessions) ────────────────────────────────────────────

/// The `version` byte of a v6 frame.
pub const FRAME_VERSION_V2: u8 = 2;
/// Bytes of a v6 frame header.
pub const FRAME_HEADER_V2_LEN: usize = 16;

/// The header of a frame in a v6 session:
///
/// ```text
/// version(1)=2 kind(1) random(2) stream_id(4) stream_seq(4) payload_len(2) pad_len(2)
/// ```
///
/// All integers big-endian. `stream_seq` numbers the sequenced frames (`Data`)
/// of one stream from 0; every other kind carries 0 and is not sequenced.
/// `payload_len` is 16 bits: a frame never exceeds the path MTU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeaderV2 {
    pub kind: FrameKind,
    pub stream_id: u32,
    pub stream_seq: u32,
    pub payload_len: u16,
    pub pad_len: u16,
}

impl FrameHeaderV2 {
    pub fn encode(&self, out: &mut BytesMut) {
        // Random, as in v5: no constant bytes inside the encrypted frame.
        self.encode_with_random(rand::random(), out);
    }

    /// `encode` with the two random bytes given (for fixed test vectors).
    pub fn encode_with_random(&self, random: u16, out: &mut BytesMut) {
        out.put_u8(FRAME_VERSION_V2);
        out.put_u8(self.kind as u8);
        out.put_u16(random);
        out.put_u32(self.stream_id);
        out.put_u32(self.stream_seq);
        out.put_u16(self.payload_len);
        out.put_u16(self.pad_len);
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ProtocolError> {
        if buf.len() < FRAME_HEADER_V2_LEN {
            return Err(ProtocolError::Framing("truncated frame header".to_string()));
        }
        if buf[0] != FRAME_VERSION_V2 {
            return Err(ProtocolError::Framing("unexpected frame version".to_string()));
        }
        Ok(Self {
            kind: FrameKind::try_from(buf[1])?,
            // buf[2..4] is random
            stream_id: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
            stream_seq: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
            payload_len: u16::from_be_bytes([buf[12], buf[13]]),
            pad_len: u16::from_be_bytes([buf[14], buf[15]]),
        })
    }
}

/// A v6 frame: header, payload, padding.
#[derive(Debug, Clone)]
pub struct FramedPacketV2 {
    pub header: FrameHeaderV2,
    pub payload: Bytes,
    pub padding: Bytes,
}

impl FramedPacketV2 {
    /// Refuses a payload or padding that does not fit the 16-bit length fields.
    pub fn new(
        kind: FrameKind,
        stream_id: u32,
        stream_seq: u32,
        payload: Bytes,
        padding: Bytes,
    ) -> Result<Self, ProtocolError> {
        let payload_len = u16::try_from(payload.len())
            .map_err(|_| ProtocolError::Framing(format!("payload of {} bytes does not fit a frame", payload.len())))?;
        let pad_len = u16::try_from(padding.len())
            .map_err(|_| ProtocolError::Framing(format!("padding of {} bytes does not fit a frame", padding.len())))?;
        Ok(Self {
            header: FrameHeaderV2 { kind, stream_id, stream_seq, payload_len, pad_len },
            payload,
            padding,
        })
    }

    pub fn encode(&self) -> Bytes {
        let total = FRAME_HEADER_V2_LEN + self.payload.len() + self.padding.len();
        let mut out = BytesMut::with_capacity(total);
        self.header.encode(&mut out);
        out.extend_from_slice(&self.payload);
        out.extend_from_slice(&self.padding);
        out.freeze()
    }

    pub fn decode_zero_copy(buf: Bytes) -> Result<Self, ProtocolError> {
        if buf.len() < FRAME_HEADER_V2_LEN {
            return Err(ProtocolError::Framing("frame too short".to_string()));
        }
        let header = FrameHeaderV2::decode(&buf[..FRAME_HEADER_V2_LEN])?;
        let payload_end = FRAME_HEADER_V2_LEN + header.payload_len as usize;
        let expected = payload_end + header.pad_len as usize;
        if buf.len() < expected {
            return Err(ProtocolError::Framing("frame body truncated".to_string()));
        }
        Ok(Self {
            header,
            payload: buf.slice(FRAME_HEADER_V2_LEN..payload_end),
            padding: buf.slice(payload_end..expected),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed vector: every field lands at its offset, big-endian.
    #[test]
    fn a_v2_header_has_the_documented_layout() {
        let h = FrameHeaderV2 {
            kind: FrameKind::Data,
            stream_id: 0x0102_0304,
            stream_seq: 0x0A0B_0C0D,
            payload_len: 0x0506,
            pad_len: 0x0708,
        };
        let mut out = BytesMut::new();
        h.encode_with_random(0xBEEF, &mut out);
        assert_eq!(
            &out[..],
            &[2, 2, 0xBE, 0xEF, 1, 2, 3, 4, 0x0A, 0x0B, 0x0C, 0x0D, 5, 6, 7, 8]
        );
        assert_eq!(out.len(), FRAME_HEADER_V2_LEN);
        assert_eq!(FrameHeaderV2::decode(&out).unwrap(), h);

        // The random bytes are not part of the header's meaning.
        let mut other = BytesMut::new();
        h.encode_with_random(0, &mut other);
        assert_eq!(FrameHeaderV2::decode(&other).unwrap(), h);
    }

    #[test]
    fn every_kind_round_trips_in_a_v2_header() {
        for kind in [
            FrameKind::Handshake,
            FrameKind::Data,
            FrameKind::Close,
            FrameKind::KeepAlive,
            FrameKind::Nack,
            FrameKind::Ack,
            FrameKind::Datagram,
            FrameKind::Abandon,
        ] {
            let h = FrameHeaderV2 { kind, stream_id: u32::MAX, stream_seq: u32::MAX, payload_len: u16::MAX, pad_len: u16::MAX };
            let mut out = BytesMut::new();
            h.encode(&mut out);
            assert_eq!(FrameHeaderV2::decode(&out).unwrap(), h);
        }
    }

    #[test]
    fn a_v2_header_refuses_what_is_not_one() {
        let h = FrameHeaderV2 { kind: FrameKind::Data, stream_id: 1, stream_seq: 0, payload_len: 0, pad_len: 0 };
        let mut out = BytesMut::new();
        h.encode(&mut out);
        assert!(FrameHeaderV2::decode(&out[..15]).is_err(), "truncated");
        let mut v1 = out.to_vec();
        v1[0] = 1;
        assert!(FrameHeaderV2::decode(&v1).is_err(), "a v5 version byte");
        let mut bad_kind = out.to_vec();
        bad_kind[1] = 99;
        assert!(FrameHeaderV2::decode(&bad_kind).is_err(), "an unknown kind");
    }

    #[test]
    fn a_v2_packet_round_trips_and_refuses_a_lying_length() {
        let p = FramedPacketV2::new(FrameKind::Data, 9, 4, Bytes::from_static(b"hello"), Bytes::from_static(&[7; 11])).unwrap();
        let wire = p.encode();
        assert_eq!(wire.len(), FRAME_HEADER_V2_LEN + 5 + 11);
        let back = FramedPacketV2::decode_zero_copy(wire.clone()).unwrap();
        assert_eq!(back.header, p.header);
        assert_eq!(&back.payload[..], b"hello");
        assert_eq!(back.padding.len(), 11);
        // A header that claims more than the datagram holds.
        assert!(FramedPacketV2::decode_zero_copy(wire.slice(..wire.len() - 1)).is_err());
    }

    /// A frame never exceeds a datagram: a payload past 16 bits is refused,
    /// not truncated.
    #[test]
    fn a_v2_payload_beyond_16_bits_is_refused() {
        let big = Bytes::from(vec![0u8; u16::MAX as usize + 1]);
        assert!(FramedPacketV2::new(FrameKind::Data, 1, 0, big, Bytes::new()).is_err());
        let max = Bytes::from(vec![0u8; u16::MAX as usize]);
        assert!(FramedPacketV2::new(FrameKind::Data, 1, 0, max, Bytes::new()).is_ok());
        assert!(FramedPacketV2::new(FrameKind::Data, 1, 0, Bytes::new(), Bytes::from(vec![0u8; 70_000])).is_err());
    }
}
