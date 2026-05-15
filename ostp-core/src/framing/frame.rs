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
        out.put_u16(0); // 2 reserved bytes
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

        let expected = FRAME_HEADER_LEN + payload_len + pad_len;
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
