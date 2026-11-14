//! What a session needs from the operating system.

use core::net::SocketAddr;

use crate::Error;

/// A connected UDP socket.
pub trait DatagramSocket {
    /// Send one datagram to the peer.
    fn send(&mut self, data: &[u8]) -> Result<(), Error>;
    /// Wait up to `timeout_ms` (0: do not wait) for one datagram. `Ok(None)`: nothing came.
    fn recv(&mut self, buf: &mut [u8], timeout_ms: u64) -> Result<Option<usize>, Error>;
}

/// A connected TCP stream.
pub trait StreamSocket {
    /// Write all of `data` (may wait for room).
    fn send_all(&mut self, data: &[u8]) -> Result<(), Error>;
    /// Wait up to `timeout_ms` (0: do not wait) for bytes. `Ok(None)`: nothing came;
    /// `Ok(Some(0))`: the peer closed the stream.
    fn recv(&mut self, buf: &mut [u8], timeout_ms: u64) -> Result<Option<usize>, Error>;
}

/// Sockets, name lookup, clocks and entropy. The clock and entropy functions take no
/// `self` so that a `no_std` build can hand them to `ostp-core` as plain function
/// pointers (see `install_core_hooks`).
pub trait Platform {
    type Datagram: DatagramSocket;
    type Stream: StreamSocket;

    /// Monotonic nanoseconds since an arbitrary start (boot).
    fn now_ns() -> u64;
    /// Seconds since 1970-01-01 UTC. The handshake carries it and the server refuses a
    /// clock that is minutes off.
    fn unix_secs() -> u64;
    /// Cryptographically secure random bytes. Must not fall back to anything weaker.
    fn fill_random(buf: &mut [u8]);

    /// The addresses of `host` (a name or a literal address), best first.
    fn resolve(&mut self, host: &str, port: u16) -> Result<alloc::vec::Vec<SocketAddr>, Error>;
    /// A UDP socket connected to `addr`.
    fn udp_connect(&mut self, addr: SocketAddr) -> Result<Self::Datagram, Error>;
    /// A TCP connection to `addr`.
    fn tcp_connect(&mut self, addr: SocketAddr) -> Result<Self::Stream, Error>;
}
