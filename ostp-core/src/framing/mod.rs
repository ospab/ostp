pub mod frame;
pub mod padding;

pub use frame::{FrameHeader, FrameHeaderV2, FrameKind, FramedPacket, FramedPacketV2, FRAME_HEADER_V2_LEN};

/// Bytes a data datagram adds around its payload: session id (4), nonce (8),
/// frame header (12) and the AEAD tag (16).
pub const DATAGRAM_OVERHEAD: usize = 4 + 8 + 12 + 16;
/// The same in a v6 session, whose frame header is 16 bytes.
pub const DATAGRAM_OVERHEAD_V6: usize = 4 + 8 + FRAME_HEADER_V2_LEN + 16;
pub use padding::{AdaptivePadder, PaddingStrategy, TrafficProfile};
