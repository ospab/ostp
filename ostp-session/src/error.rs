use alloc::string::String;
use core::fmt;

/// What went wrong, in words a user can act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The link or subscription cannot be used (malformed, or a transport this
    /// client does not have).
    Link(String),
    /// A name did not resolve, a socket could not be opened, a send failed.
    Net(String),
    /// The server did not complete the handshake in time.
    HandshakeTimeout,
    /// The session ended: the carrier closed, or the server stopped answering.
    Lost(String),
    /// The protocol state machine refused something.
    Protocol(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Link(m) => write!(f, "{m}"),
            Error::Net(m) => write!(f, "{m}"),
            Error::HandshakeTimeout => write!(
                f,
                "no handshake reply from the server (wrong key, clock more than a few minutes off, or the server is unreachable)"
            ),
            Error::Lost(m) => write!(f, "session lost: {m}"),
            Error::Protocol(m) => write!(f, "protocol error: {m}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
