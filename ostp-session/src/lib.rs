//! An OSTP client session that needs no async runtime and, without the `std`
//! feature, no standard library: the pieces a client CLI is made of, for
//! systems where `ostp-client` (std + tokio) does not run.
//!
//! - [`Platform`]: the OS-specific part (UDP and TCP sockets, name lookup,
//!   clocks, entropy). [`StdPlatform`] implements it over `std::net`; an
//!   embedder without `std` implements it over its own system calls.
//! - [`Session`]: handshake, the UDP and UoT carriers, ARQ ticks, keepalive,
//!   relay streams with per-stream flow control (negotiated, so 0.4.5 servers
//!   work as before), and the liveness signal. It never reconnects by itself.
//! - [`link`]: share links and subscription documents to a server to dial.
//! - [`proxy`]: SOCKS5 and HTTP CONNECT requests, parsed without I/O.
//! - [`subs`]: a client's list of subscriptions, as JSON.
//!
//! The wire protocol is `ostp-core`'s; nothing here changes it.
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod error;
pub mod link;
pub mod platform;
pub mod proxy;
pub mod session;
pub mod subs;

#[cfg(feature = "std")]
mod std_platform;

pub use error::Error;
pub use link::{Carrier as CarrierKind, Server};
pub use platform::{DatagramSocket, Platform, StreamSocket};
pub use session::{Event, Session, SessionConfig, Stats};
#[cfg(feature = "std")]
pub use std_platform::StdPlatform;

pub use ostp_core;

/// Hand the platform's clock and entropy to `ostp-core` (a `no_std` build of it has no
/// other source). Call once at start-up, before [`Session::connect`].
#[cfg(not(feature = "std"))]
pub fn install_core_hooks<P: Platform>() {
    ostp_core::sys::install(ostp_core::sys::Hooks {
        monotonic_ns: P::now_ns,
        unix_secs: P::unix_secs,
        fill_random: P::fill_random,
    });
}
