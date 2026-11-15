//! Stream ids of a v6 session: who may open which, never reused, and how many
//! at once. Pure logic; the machine in `protocol` does not depend on it, the
//! server and the client use it to hand out and to accept ids.
//!
//! The client opens odd ids, the server even ones (as HTTP/2 does), stream 0
//! is the session's own and never a stream a program opened. An id is never
//! reused in a session, so a late frame of a closed stream cannot hit a newer
//! one. At most `MAX_OPEN_STREAMS` are open at once.

use std::collections::{BTreeSet, HashSet};

/// Streams open at the same time in one session.
pub const MAX_OPEN_STREAMS: usize = 1024;
/// How many closed ids of the peer are remembered, to refuse their reuse. The
/// oldest are forgotten first; a frame of one of those streams that is still
/// in flight after that many newer ones is not a case the network produces.
const MAX_REMEMBERED_CLOSED: usize = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Client,
    Server,
}

impl Side {
    pub fn peer(self) -> Side {
        match self {
            Side::Client => Side::Server,
            Side::Server => Side::Client,
        }
    }

    /// The first id this side opens.
    fn first_id(self) -> u32 {
        match self {
            Side::Client => 1,
            Side::Server => 2,
        }
    }
}

/// Whether `id` is one that `side` may open: not 0, odd for the client, even
/// for the server.
pub fn id_belongs_to(id: u32, side: Side) -> bool {
    match side {
        Side::Client => id % 2 == 1,
        Side::Server => id != 0 && id % 2 == 0,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamError {
    /// `MAX_OPEN_STREAMS` are open.
    TooManyOpen,
    /// Every id this side may open is used (2^31 of them).
    IdsExhausted,
    /// The peer used an id of the wrong parity, or 0.
    WrongParity,
    /// The peer opened an id that is open or was closed before.
    Reused,
    /// The stream is not open.
    NotOpen,
}

impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            StreamError::TooManyOpen => "too many open streams",
            StreamError::IdsExhausted => "stream ids exhausted",
            StreamError::WrongParity => "stream id of the wrong parity",
            StreamError::Reused => "stream id reused",
            StreamError::NotOpen => "stream is not open",
        })
    }
}

impl std::error::Error for StreamError {}

/// The streams of one session, from one side.
#[derive(Debug)]
pub struct StreamIds {
    side: Side,
    next_local: Option<u32>,
    open: HashSet<u32>,
    /// Ids of the peer that were opened and closed again.
    closed_remote: BTreeSet<u32>,
}

impl StreamIds {
    pub fn new(side: Side) -> Self {
        Self { side, next_local: Some(side.first_id()), open: HashSet::new(), closed_remote: BTreeSet::new() }
    }

    pub fn open_count(&self) -> usize {
        self.open.len()
    }

    pub fn is_open(&self, id: u32) -> bool {
        self.open.contains(&id)
    }

    /// Opens a stream of our own: the next id of our parity.
    pub fn open_local(&mut self) -> Result<u32, StreamError> {
        if self.open.len() >= MAX_OPEN_STREAMS {
            return Err(StreamError::TooManyOpen);
        }
        let id = self.next_local.ok_or(StreamError::IdsExhausted)?;
        // Steps of two keep the parity; None past u32::MAX.
        self.next_local = id.checked_add(2);
        self.open.insert(id);
        Ok(id)
    }

    /// The peer opens `id`. Streams of different ids may start in any order
    /// (each is ordered on its own), so only parity, reuse and the limit are
    /// checked, not that ids grow.
    pub fn accept_remote(&mut self, id: u32) -> Result<(), StreamError> {
        if !id_belongs_to(id, self.side.peer()) {
            return Err(StreamError::WrongParity);
        }
        if self.open.contains(&id) || self.closed_remote.contains(&id) {
            return Err(StreamError::Reused);
        }
        if self.open.len() >= MAX_OPEN_STREAMS {
            return Err(StreamError::TooManyOpen);
        }
        self.open.insert(id);
        Ok(())
    }

    /// The stream is over on both sides (or reset). Its id is not used again.
    pub fn close(&mut self, id: u32) -> Result<(), StreamError> {
        if !self.open.remove(&id) {
            return Err(StreamError::NotOpen);
        }
        if !id_belongs_to(id, self.side) {
            self.closed_remote.insert(id);
            while self.closed_remote.len() > MAX_REMEMBERED_CLOSED {
                let oldest = *self.closed_remote.iter().next().expect("not empty");
                self.closed_remote.remove(&oldest);
            }
        }
        Ok(())
    }
}

/// The two halves of a stream, for the `Fin` half-close: each side says once
/// that it will write no more, and the stream is over when both have. `Close`
/// (an abort) does not go through this: it ends the stream at once.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct HalfClose {
    local_fin: bool,
    remote_fin: bool,
}

impl HalfClose {
    /// We sent our `Fin`. True when that finished the stream.
    pub fn local_fin(&mut self) -> bool {
        self.local_fin = true;
        self.finished()
    }

    /// The peer's `Fin` arrived. True when that finished the stream.
    pub fn remote_fin(&mut self) -> bool {
        self.remote_fin = true;
        self.finished()
    }

    pub fn local_done(&self) -> bool {
        self.local_fin
    }

    pub fn remote_done(&self) -> bool {
        self.remote_fin
    }

    pub fn finished(&self) -> bool {
        self.local_fin && self.remote_fin
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stream_finishes_only_when_both_sides_sent_fin() {
        let mut h = HalfClose::default();
        assert!(!h.finished());
        assert!(!h.local_fin(), "one side is not enough");
        assert!(h.local_done() && !h.remote_done());
        assert!(!h.local_fin(), "a repeated Fin changes nothing");
        assert!(h.remote_fin(), "the second Fin finishes it");
        assert!(h.finished());

        let mut h = HalfClose::default();
        assert!(!h.remote_fin(), "either order");
        assert!(h.local_fin());
    }

    #[test]
    fn the_client_opens_odd_ids_and_the_server_even_ones() {
        let mut c = StreamIds::new(Side::Client);
        let mut s = StreamIds::new(Side::Server);
        assert_eq!((c.open_local().unwrap(), c.open_local().unwrap(), c.open_local().unwrap()), (1, 3, 5));
        assert_eq!((s.open_local().unwrap(), s.open_local().unwrap()), (2, 4));
        assert!(id_belongs_to(7, Side::Client) && !id_belongs_to(7, Side::Server));
        assert!(id_belongs_to(8, Side::Server) && !id_belongs_to(8, Side::Client));
        assert!(!id_belongs_to(0, Side::Client) && !id_belongs_to(0, Side::Server), "0 is the session's");
    }

    #[test]
    fn an_id_is_never_handed_out_twice() {
        let mut c = StreamIds::new(Side::Client);
        let a = c.open_local().unwrap();
        c.close(a).unwrap();
        let b = c.open_local().unwrap();
        assert_ne!(a, b, "a closed id is not reused");
        assert!(c.close(a).is_err(), "closing twice");
    }

    #[test]
    fn the_peers_ids_must_have_its_parity_and_not_repeat() {
        let mut s = StreamIds::new(Side::Server);
        assert_eq!(s.accept_remote(2), Err(StreamError::WrongParity), "the server's own parity");
        assert_eq!(s.accept_remote(0), Err(StreamError::WrongParity));
        s.accept_remote(5).unwrap();
        s.accept_remote(3).unwrap(); // streams may start out of order
        assert_eq!(s.accept_remote(5), Err(StreamError::Reused), "open");
        s.close(5).unwrap();
        assert_eq!(s.accept_remote(5), Err(StreamError::Reused), "closed");
        assert_eq!(s.open_count(), 1);
        assert!(s.is_open(3) && !s.is_open(5));
    }

    #[test]
    fn at_most_1024_streams_are_open() {
        let mut c = StreamIds::new(Side::Client);
        let ids: Vec<u32> = (0..MAX_OPEN_STREAMS).map(|_| c.open_local().unwrap()).collect();
        assert_eq!(c.open_local(), Err(StreamError::TooManyOpen));
        assert_eq!(c.accept_remote(2), Err(StreamError::TooManyOpen), "the limit covers both directions");
        c.close(ids[10]).unwrap();
        assert!(c.open_local().is_ok(), "a closed stream frees a slot");
        assert_eq!(c.open_count(), MAX_OPEN_STREAMS);
    }

    #[test]
    fn the_ids_run_out_at_the_top_of_the_range() {
        let mut c = StreamIds::new(Side::Client);
        c.next_local = Some(u32::MAX); // the last odd id
        assert_eq!(c.open_local().unwrap(), u32::MAX);
        c.close(u32::MAX).unwrap();
        assert_eq!(c.open_local(), Err(StreamError::IdsExhausted));
        let mut s = StreamIds::new(Side::Server);
        s.next_local = Some(u32::MAX - 1);
        assert_eq!(s.open_local().unwrap(), u32::MAX - 1);
        assert_eq!(s.open_local(), Err(StreamError::IdsExhausted));
    }

    #[test]
    fn remembered_closed_ids_are_bounded() {
        let mut s = StreamIds::new(Side::Server);
        for i in 0..(MAX_REMEMBERED_CLOSED as u32 + 10) {
            let id = 2 * i + 1;
            s.accept_remote(id).unwrap();
            s.close(id).unwrap();
        }
        assert_eq!(s.closed_remote.len(), MAX_REMEMBERED_CLOSED);
        assert_eq!(s.accept_remote(1), Ok(()), "the oldest were forgotten");
        assert_eq!(s.accept_remote(2 * (MAX_REMEMBERED_CLOSED as u32 + 9) + 1), Err(StreamError::Reused));
    }
}
