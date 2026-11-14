//! OSTP protocol core. `no_std + alloc` when the default `std` feature is off;
//! see [`sys`] for the platform hooks such a build must install.
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

/// Re-exported so `no_std` embedders build `OstpEvent::Inbound(Bytes)` with the same `bytes` version.
pub use bytes;
/// Re-exported for `no_std` embedders that keep client configuration as JSON.
pub use serde_json;

#[cfg(feature = "std")]
pub mod access_keys;
pub mod congestion;
pub mod crypto;
pub mod fmt;
pub mod framing;
#[cfg(feature = "std")]
pub mod http_upgrade;
#[cfg(feature = "std")]
pub mod keys;
#[cfg(feature = "std")]
pub mod net;
pub mod protocol;
pub mod relay;
pub mod share_link;
pub mod sys;
pub mod subscription;

pub use crypto::NoiseRole;
pub use fmt::fmt_bytes;
pub use framing::{TrafficProfile, PaddingStrategy};
pub use protocol::{build_handshake_payload, OstpEvent, OstpState, ProtocolAction, ProtocolConfig, ProtocolMachine};
