pub mod frame;
pub mod padding;

pub use frame::{FrameHeader, FrameKind, FramedPacket};

/// Bytes a data datagram adds around its payload: session id (4), nonce (8),
/// frame header (12) and the AEAD tag (16).
pub const DATAGRAM_OVERHEAD: usize = 4 + 8 + 12 + 16;
pub use padding::{AdaptivePadder, PaddingStrategy, TrafficProfile};
