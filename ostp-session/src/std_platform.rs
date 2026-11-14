//! `Platform` over the standard library: blocking `std::net` sockets with timeouts.

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::platform::{DatagramSocket, Platform, StreamSocket};
use crate::Error;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

fn io_err(what: &str, e: std::io::Error) -> Error {
    Error::Net(format!("{what}: {e}"))
}

/// Remembers whether the socket is in non-blocking mode, to set it only on change.
#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Unset,
    NonBlocking,
    Timeout(u64),
}

pub struct StdDatagram {
    sock: UdpSocket,
    mode: Mode,
}

pub struct StdStream {
    sock: TcpStream,
    mode: Mode,
}

fn is_nothing(e: &std::io::Error) -> bool {
    matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
}

impl DatagramSocket for StdDatagram {
    fn send(&mut self, data: &[u8]) -> Result<(), Error> {
        match self.sock.send(data) {
            Ok(_) => Ok(()),
            // A full send buffer in non-blocking mode: the datagram is lost, the ARQ resends.
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(()),
            Err(e) => Err(io_err("UDP send", e)),
        }
    }

    fn recv(&mut self, buf: &mut [u8], timeout_ms: u64) -> Result<Option<usize>, Error> {
        set_mode(&mut self.mode, timeout_ms, |nb| self.sock.set_nonblocking(nb), |t| self.sock.set_read_timeout(t))?;
        match self.sock.recv(buf) {
            Ok(n) => Ok(Some(n)),
            Err(e) if is_nothing(&e) => Ok(None),
            // Windows reports an ICMP port unreachable for an earlier send this way.
            Err(e) if e.kind() == ErrorKind::ConnectionReset => Ok(None),
            Err(e) => Err(io_err("UDP receive", e)),
        }
    }
}

impl StreamSocket for StdStream {
    fn send_all(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.mode == Mode::NonBlocking {
            let _ = self.sock.set_nonblocking(false);
            self.mode = Mode::Unset;
        }
        self.sock.write_all(data).map_err(|e| io_err("TCP send", e))
    }

    fn recv(&mut self, buf: &mut [u8], timeout_ms: u64) -> Result<Option<usize>, Error> {
        set_mode(&mut self.mode, timeout_ms, |nb| self.sock.set_nonblocking(nb), |t| self.sock.set_read_timeout(t))?;
        match self.sock.read(buf) {
            Ok(n) => Ok(Some(n)),
            Err(e) if is_nothing(&e) => Ok(None),
            Err(e) => Err(io_err("TCP receive", e)),
        }
    }
}

fn set_mode(
    mode: &mut Mode,
    timeout_ms: u64,
    nonblocking: impl FnOnce(bool) -> std::io::Result<()>,
    read_timeout: impl FnOnce(Option<Duration>) -> std::io::Result<()>,
) -> Result<(), Error> {
    let want = if timeout_ms == 0 { Mode::NonBlocking } else { Mode::Timeout(timeout_ms) };
    if *mode == want {
        return Ok(());
    }
    if want == Mode::NonBlocking {
        nonblocking(true).map_err(|e| io_err("socket mode", e))?;
    } else {
        if *mode == Mode::NonBlocking {
            nonblocking(false).map_err(|e| io_err("socket mode", e))?;
        }
        read_timeout(Some(Duration::from_millis(timeout_ms))).map_err(|e| io_err("socket mode", e))?;
    }
    *mode = want;
    Ok(())
}

/// The standard library's sockets, clock and the system CSPRNG.
#[derive(Debug, Default, Clone, Copy)]
pub struct StdPlatform;

impl Platform for StdPlatform {
    type Datagram = StdDatagram;
    type Stream = StdStream;

    fn now_ns() -> u64 {
        static BASE: OnceLock<Instant> = OnceLock::new();
        BASE.get_or_init(Instant::now).elapsed().as_nanos() as u64
    }

    fn unix_secs() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
    }

    fn fill_random(buf: &mut [u8]) {
        ostp_core::sys::fill_random(buf)
    }

    fn resolve(&mut self, host: &str, port: u16) -> Result<Vec<SocketAddr>, Error> {
        let mut addrs: Vec<SocketAddr> = (host, port)
            .to_socket_addrs()
            .map_err(|e| Error::Net(format!("cannot resolve {host}: {e}")))?
            .collect();
        // IPv4 first: a broken IPv6 route must not block the connection.
        addrs.sort_by_key(|a| !a.is_ipv4());
        Ok(addrs)
    }

    fn udp_connect(&mut self, addr: SocketAddr) -> Result<StdDatagram, Error> {
        let bind: SocketAddr = if addr.is_ipv4() { "0.0.0.0:0".parse().unwrap() } else { "[::]:0".parse().unwrap() };
        let sock = UdpSocket::bind(bind).map_err(|e| io_err("UDP socket", e))?;
        sock.connect(addr).map_err(|e| io_err("UDP connect", e))?;
        Ok(StdDatagram { sock, mode: Mode::Unset })
    }

    fn tcp_connect(&mut self, addr: SocketAddr) -> Result<StdStream, Error> {
        let sock = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT).map_err(|e| io_err(&format!("TCP connect to {addr}"), e))?;
        let _ = sock.set_nodelay(true);
        Ok(StdStream { sock, mode: Mode::Unset })
    }
}
