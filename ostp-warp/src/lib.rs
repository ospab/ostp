//! Cloudflare WARP as the exit of an OSTP server.
//!
//! A WireGuard client (`boringtun`) and a TCP/UDP stack (`smoltcp`) run in
//! user space inside the server process: no tun device, no routes, no root.
//! The only way to use them is a local SOCKS5 proxy (TCP `CONNECT`, UDP
//! `ASSOCIATE`) on a loopback port; the server's `outbound` section points
//! there. See `docs/en/warp-design.md`.

pub mod api;
pub mod config;
pub mod dnsq;
pub mod probe;
pub mod run;
pub mod socks;
pub mod store;
pub mod trace;
pub mod tunnel;

#[cfg(any(test, feature = "testing"))]
pub mod testpeer;

#[cfg(any(test, feature = "testing"))]
pub mod testapi;

pub use config::{WarpConfig, WarpMode};
pub use run::{start, Running};
pub use tunnel::{Tunnel, TunnelConfig, TunnelStatus};
