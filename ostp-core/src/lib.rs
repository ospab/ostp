//! OSTP protocol core. `no_std + alloc` when the default `std` feature is off;
//! see [`sys`] for the platform hooks such a build must install.
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

/// Re-exported so `no_std` embedders build `OstpEvent::Inbound(Bytes)` with the same `bytes` version.
pub use bytes;
/// Re-exported for `no_std` embedders that keep client configuration as JSON.
pub use serde_json;

pub mod congestion;
pub mod crypto;
pub mod framing;
#[cfg(feature = "std")]
pub mod http_upgrade;
pub mod protocol;
pub mod relay;
pub mod share_link;
pub mod sys;
pub mod subscription;

pub use crypto::NoiseRole;
pub use framing::{TrafficProfile, PaddingStrategy};
pub use protocol::{OstpEvent, OstpState, ProtocolAction, ProtocolConfig, ProtocolMachine};
