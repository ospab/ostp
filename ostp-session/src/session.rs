//! One OSTP session: the handshake, a carrier (UDP or UoT), the ARQ timers, keepalive,
//! relay streams and the liveness signal.
//!
//! The session does no waiting of its own after the handshake. The embedder runs a loop:
//! wait until the carrier socket is readable or [`Session::next_wakeup_ms`] passed, call
//! [`Session::pump`], then take [`Event`]s with [`Session::next_event`]. Stream data goes
//! in with [`Session::send`] and is acknowledged with [`Session::consumed`] once the
//! program it was for has taken it.
//!
//! A session that dies is reported ([`Error::Lost`]) and stays dead: connecting again is
//! the user's decision, never this crate's.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::net::SocketAddr;

use ostp_core::bytes::Bytes;
use ostp_core::crypto::{derive_all_secrets, NoiseRole};
use ostp_core::framing::{PaddingStrategy, TrafficProfile};
use ostp_core::protocol::{OstpEvent, OstpState, ProtocolAction, ProtocolConfig, ProtocolMachine};
use ostp_core::relay::{self, RelayMessage};

use crate::link::{Carrier, Server};
use crate::platform::{DatagramSocket, Platform, StreamSocket};
use crate::Error;

/// Stream 0 carries session control: features, ping and pong, keepalive.
const CONTROL_STREAM: u16 = 0;
/// The ARQ timer granularity (the desktop client ticks every 10 ms too).
const TICK_NS: u64 = 10_000_000;
/// Handshake datagram resent this often on UDP until a reply comes.
const HANDSHAKE_RESEND_NS: u64 = 1_000_000_000;
/// Relay payload bytes held back by the congestion window, all streams together.
/// `send` accepts less once this is reached, which is the backpressure for the program.
const OUTQ_LIMIT: usize = 512 * 1024;
/// Largest datagram read from the carrier.
const RECV_BUF: usize = 4096;
/// Frames read per `pump`, so a flood cannot keep the loop from its timers.
const MAX_FRAMES_PER_PUMP: usize = 256;

/// Timing and size settings. The defaults are the desktop client's.
#[derive(Debug, Clone, Copy)]
pub struct SessionConfig {
    /// Datagram budget (the desktop default is 1140).
    pub mtu: usize,
    pub handshake_timeout_ms: u64,
    /// A ping and a keepalive go to the server this often.
    pub keepalive_ms: u64,
    /// After this long without an authenticated datagram, [`Event::Silent`] is reported.
    pub silence_ms: u64,
    /// After this long without one the session is given up. The server keeps a silent
    /// session 10 minutes; this is shorter so a dead path is reported in time.
    pub give_up_ms: u64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        SessionConfig { mtu: 1140, handshake_timeout_ms: 5000, keepalive_ms: 5000, silence_ms: 10_000, give_up_ms: 300_000 }
    }
}

/// What happened on the session since the last call to [`Session::next_event`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The server reached the target of this stream.
    Connected(u16),
    /// Bytes from the target. Call [`Session::consumed`] once they are delivered.
    Data(u16, Vec<u8>),
    /// The target closed the stream (everything before it was delivered).
    Closed(u16),
    /// The server could not reach the target, or lost it.
    Failed(u16, String),
    /// The answer to a ping, with the round-trip time.
    Pong { rtt_us: u64 },
    /// No authenticated datagram for this many seconds (reported once per silence).
    Silent { secs: u64 },
    /// Datagrams arrive again after a silence.
    Resumed,
}

/// Counters for `status`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Stats {
    pub uptime_ms: u64,
    pub idle_ms: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_datagrams: u64,
    pub rx_datagrams: u64,
    pub in_flight: usize,
    pub cwnd: usize,
    pub streams: usize,
    pub queued_bytes: usize,
    pub flow_control: bool,
    pub last_rtt_us: Option<u64>,
    pub handshake_us: u64,
}

enum Wire<P: Platform> {
    Udp(P::Datagram),
    Uot { stream: P::Stream, acc: Vec<u8> },
}

impl<P: Platform> Wire<P> {
    fn send(&mut self, frame: &[u8]) -> Result<(), Error> {
        match self {
            Wire::Udp(s) => s.send(frame),
            Wire::Uot { stream, .. } => {
                if frame.len() > u16::MAX as usize {
                    return Err(Error::Protocol(String::from("datagram larger than 64 KiB")));
                }
                let mut buf = Vec::with_capacity(2 + frame.len());
                buf.extend_from_slice(&(frame.len() as u16).to_be_bytes());
                buf.extend_from_slice(frame);
                stream.send_all(&buf)
            }
        }
    }

    /// Frames that arrived; waits up to `wait_ms` for the first one.
    fn recv_frames(&mut self, wait_ms: u64) -> Result<Vec<Vec<u8>>, Error> {
        let mut out = Vec::new();
        let mut buf = [0u8; RECV_BUF];
        match self {
            Wire::Udp(s) => {
                let mut wait = wait_ms;
                while out.len() < MAX_FRAMES_PER_PUMP {
                    match s.recv(&mut buf, wait)? {
                        Some(n) => out.push(buf[..n].to_vec()),
                        None => break,
                    }
                    wait = 0;
                }
            }
            Wire::Uot { stream, acc } => {
                let mut wait = wait_ms;
                for _ in 0..MAX_FRAMES_PER_PUMP {
                    match stream.recv(&mut buf, wait)? {
                        Some(0) => return Err(Error::Lost(String::from("the server closed the TCP connection"))),
                        Some(n) => acc.extend_from_slice(&buf[..n]),
                        None => break,
                    }
                    wait = 0;
                }
                let mut off = 0;
                while acc.len() - off >= 2 {
                    let len = u16::from_be_bytes([acc[off], acc[off + 1]]) as usize;
                    if acc.len() - off < 2 + len {
                        break;
                    }
                    out.push(acc[off + 2..off + 2 + len].to_vec());
                    off += 2 + len;
                }
                acc.drain(..off);
            }
        }
        Ok(out)
    }
}

struct StreamState {
    /// Bytes this side may still send; `None` until the server's first `Window` (a stream
    /// without flow control).
    send_window: Option<u64>,
    /// Bytes delivered to the program since the last grant.
    consumed: u32,
    connected: bool,
}

/// An established session. `P` supplies the sockets.
pub struct Session<P: Platform> {
    machine: ProtocolMachine,
    wire: Wire<P>,
    server: SocketAddr,
    carrier: Carrier,
    cfg: SessionConfig,
    streams: BTreeMap<u16, StreamState>,
    next_stream: u16,
    /// Relay messages waiting for room in the congestion window, in order.
    outq: VecDeque<(u16, Bytes)>,
    outq_bytes: usize,
    events: VecDeque<Event>,
    flow_control: bool,
    started_ns: u64,
    last_rx_ns: u64,
    last_tick_ns: u64,
    last_keepalive_ns: u64,
    silent: bool,
    lost: Option<String>,
    tx_bytes: u64,
    rx_bytes: u64,
    tx_datagrams: u64,
    rx_datagrams: u64,
    last_rtt_us: Option<u64>,
    handshake_us: u64,
}

fn collect(action: ProtocolAction, sends: &mut Vec<Bytes>, app: &mut Vec<(u16, Bytes)>) {
    match action {
        ProtocolAction::SendDatagram(f) => sends.push(f),
        ProtocolAction::DeliverApp(sid, p) => app.push((sid, p)),
        ProtocolAction::Multiple(list) => {
            for a in list {
                collect(a, sends, app);
            }
        }
        ProtocolAction::HandshakePayload(..) | ProtocolAction::Noop => {}
    }
}

impl<P: Platform> Session<P> {
    /// Resolve the server and run the handshake. Tries up to three of its addresses.
    pub fn connect(platform: &mut P, server: &Server, cfg: SessionConfig) -> Result<Session<P>, Error> {
        let addrs = platform.resolve(&server.host, server.port)?;
        if addrs.is_empty() {
            return Err(Error::Net(format!("{} has no address", server.host)));
        }
        let mut last = Error::HandshakeTimeout;
        for addr in addrs.into_iter().take(3) {
            match Self::handshake(platform, addr, server, cfg) {
                Ok(s) => return Ok(s),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    fn handshake(platform: &mut P, addr: SocketAddr, server: &Server, cfg: SessionConfig) -> Result<Session<P>, Error> {
        let key = server.key.as_bytes();
        let secrets = derive_all_secrets(key);
        let mut sid = [0u8; 4];
        P::fill_random(&mut sid);
        let session_id = u32::from_le_bytes(sid);
        let mut machine = ProtocolMachine::new(ProtocolConfig {
            psk: secrets.psk,
            session_id,
            handshake_payload: ostp_core::build_handshake_payload(key, session_id),
            padding_strategy: PaddingStrategy::Profile(TrafficProfile::JsonRpc),
            obfuscation_key: secrets.obfuscation_key,
            handshake_pad_min: secrets.handshake_pad_min,
            handshake_pad_max: secrets.handshake_pad_max,
            ..ProtocolConfig::with_defaults(NoiseRole::Initiator, cfg.mtu)
        })
        .map_err(|e| Error::Protocol(e.to_string()))?;
        // UoT rides TCP: no timer-driven resends on top of TCP's own.
        machine.set_reliable_carrier(server.carrier == Carrier::Uot);

        let mut wire: Wire<P> = match server.carrier {
            Carrier::Udp => Wire::Udp(platform.udp_connect(addr)?),
            Carrier::Uot => Wire::Uot { stream: platform.tcp_connect(addr)?, acc: Vec::new() },
        };
        let frame = match machine.on_event(OstpEvent::Start).map_err(|e| Error::Protocol(e.to_string()))? {
            ProtocolAction::SendDatagram(f) => f,
            _ => return Err(Error::Protocol(String::from("the protocol produced no handshake datagram"))),
        };

        let start = P::now_ns();
        let deadline = start + cfg.handshake_timeout_ms * 1_000_000;
        let mut next_send = start;
        let mut rx_bytes = 0u64;
        let mut rx_datagrams = 0u64;
        let mut tx_datagrams = 0u64;
        let mut tx_bytes = 0u64;
        loop {
            let now = P::now_ns();
            if now >= next_send {
                wire.send(&frame)?;
                tx_datagrams += 1;
                tx_bytes += frame.len() as u64;
                // TCP delivers the first copy or nothing.
                next_send = if server.carrier == Carrier::Udp { now + HANDSHAKE_RESEND_NS } else { u64::MAX };
            }
            if now >= deadline {
                return Err(Error::HandshakeTimeout);
            }
            let wait_ms = ((deadline - now) / 1_000_000).clamp(1, 50);
            for d in wire.recv_frames(wait_ms)? {
                rx_datagrams += 1;
                rx_bytes += d.len() as u64;
                // A datagram that does not authenticate is dropped, as on any path.
                let action = match machine.on_event(OstpEvent::Inbound(Bytes::from(d))) {
                    Ok(a) => a,
                    Err(_) => continue,
                };
                let mut sends = Vec::new();
                let mut app = Vec::new();
                collect(action, &mut sends, &mut app);
                for f in &sends {
                    wire.send(f)?;
                    tx_datagrams += 1;
                    tx_bytes += f.len() as u64;
                }
                if machine.state() == OstpState::Established {
                    let now = P::now_ns();
                    let mut s = Session {
                        machine,
                        wire,
                        server: addr,
                        carrier: server.carrier,
                        cfg,
                        streams: BTreeMap::new(),
                        next_stream: 1,
                        outq: VecDeque::new(),
                        outq_bytes: 0,
                        events: VecDeque::new(),
                        flow_control: false,
                        started_ns: now,
                        last_rx_ns: now,
                        last_tick_ns: now,
                        last_keepalive_ns: now,
                        silent: false,
                        lost: None,
                        tx_bytes,
                        rx_bytes,
                        tx_datagrams,
                        rx_datagrams,
                        last_rtt_us: None,
                        handshake_us: (now - start) / 1000,
                    };
                    // Offer flow control; a 0.4.5 server drops the message and nothing changes.
                    s.send_now(CONTROL_STREAM, &RelayMessage::Features(relay::FEATURE_FLOW_CONTROL));
                    s.ping();
                    for (sid, p) in app {
                        s.on_relay(sid, &p);
                    }
                    return Ok(s);
                }
            }
        }
    }

    /// The server's address and the carrier.
    pub fn server(&self) -> (SocketAddr, Carrier) {
        (self.server, self.carrier)
    }

    /// The UDP socket, for an embedder that waits on several sockets at once.
    pub fn datagram_socket(&self) -> Option<&P::Datagram> {
        match &self.wire {
            Wire::Udp(s) => Some(s),
            Wire::Uot { .. } => None,
        }
    }

    /// The UoT connection, likewise.
    pub fn stream_socket(&self) -> Option<&P::Stream> {
        match &self.wire {
            Wire::Uot { stream, .. } => Some(stream),
            Wire::Udp(_) => None,
        }
    }

    /// Why the session ended, once it has.
    pub fn lost(&self) -> Option<&str> {
        self.lost.as_deref()
    }

    fn mark_lost(&mut self, why: String) {
        if self.lost.is_none() {
            self.lost = Some(why);
        }
    }

    fn transmit(&mut self, frame: &[u8]) {
        if self.lost.is_some() {
            return;
        }
        match self.wire.send(frame) {
            Ok(()) => {
                self.tx_datagrams += 1;
                self.tx_bytes += frame.len() as u64;
            }
            // UDP: a send error (no route right now) is a lost datagram, the ARQ resends it.
            Err(e) => {
                if self.carrier == Carrier::Uot {
                    self.mark_lost(e.to_string());
                }
            }
        }
    }

    fn act(&mut self, action: ProtocolAction) {
        let mut sends = Vec::new();
        let mut app = Vec::new();
        collect(action, &mut sends, &mut app);
        for f in &sends {
            self.transmit(f);
        }
        for (sid, p) in app {
            self.on_relay(sid, &p);
        }
    }

    /// A control message, past the congestion window (as the desktop client does for
    /// features, pings, keepalives and window grants: they are small and time-critical).
    fn send_now(&mut self, stream: u16, msg: &RelayMessage) {
        match self.machine.on_event(OstpEvent::Outbound(stream, Bytes::from(msg.encode()))) {
            Ok(a) => self.act(a),
            Err(e) => self.mark_lost(format!("cannot send: {e}")),
        }
    }

    fn queue(&mut self, stream: u16, msg: &RelayMessage) {
        let b = Bytes::from(msg.encode());
        self.outq_bytes += b.len();
        self.outq.push_back((stream, b));
    }

    fn on_relay(&mut self, sid: u16, payload: &[u8]) {
        let msg = match RelayMessage::decode(payload) {
            Ok(m) => m,
            Err(_) => return,
        };
        if sid == CONTROL_STREAM {
            match msg {
                RelayMessage::Features(bits) => self.flow_control = bits & relay::FEATURE_FLOW_CONTROL != 0,
                RelayMessage::Pong(ts) => {
                    let rtt = (P::now_ns() / 1000).saturating_sub(ts);
                    self.last_rtt_us = Some(rtt);
                    self.events.push_back(Event::Pong { rtt_us: rtt });
                }
                _ => {}
            }
            return;
        }
        match msg {
            RelayMessage::ConnectOk => {
                if let Some(st) = self.streams.get_mut(&sid) {
                    st.connected = true;
                    self.events.push_back(Event::Connected(sid));
                }
            }
            RelayMessage::Data(d) => {
                if self.streams.contains_key(&sid) {
                    self.events.push_back(Event::Data(sid, d));
                }
            }
            RelayMessage::Close => {
                if self.streams.remove(&sid).is_some() {
                    self.events.push_back(Event::Closed(sid));
                }
            }
            RelayMessage::Error(m) => {
                if self.streams.remove(&sid).is_some() {
                    self.events.push_back(Event::Failed(sid, m));
                }
            }
            RelayMessage::Window(n) => {
                if let Some(st) = self.streams.get_mut(&sid) {
                    st.send_window = Some(st.send_window.unwrap_or(0).saturating_add(n as u64));
                }
            }
            _ => {}
        }
    }

    /// Read what arrived, run the ARQ timer, keepalive and the congestion-limited queue.
    /// Returns the reason once the session is lost.
    pub fn pump(&mut self) -> Result<(), Error> {
        if let Some(why) = &self.lost {
            return Err(Error::Lost(why.clone()));
        }
        let frames = match self.wire.recv_frames(0) {
            Ok(f) => f,
            Err(e) => {
                self.mark_lost(match e {
                    Error::Lost(m) => m,
                    other => other.to_string(),
                });
                Vec::new()
            }
        };
        for d in frames {
            self.rx_datagrams += 1;
            self.rx_bytes += d.len() as u64;
            match self.machine.on_event(OstpEvent::Inbound(Bytes::from(d))) {
                Ok(a) => {
                    self.last_rx_ns = P::now_ns();
                    if self.silent {
                        self.silent = false;
                        self.events.push_back(Event::Resumed);
                    }
                    self.act(a);
                }
                Err(_) => {}
            }
        }

        let now = P::now_ns();
        if now.saturating_sub(self.last_tick_ns) >= TICK_NS {
            self.last_tick_ns = now;
            match self.machine.on_event(OstpEvent::Tick) {
                Ok(a) => self.act(a),
                Err(e) => self.mark_lost(format!("protocol timer: {e}")),
            }
        }
        if now.saturating_sub(self.last_keepalive_ns) >= self.cfg.keepalive_ms * 1_000_000 {
            self.last_keepalive_ns = now;
            self.ping();
            self.send_now(CONTROL_STREAM, &RelayMessage::KeepAlive);
        }
        self.flush();

        let idle = now.saturating_sub(self.last_rx_ns);
        if idle >= self.cfg.give_up_ms * 1_000_000 {
            self.mark_lost(format!("no answer from the server for {} s", idle / 1_000_000_000));
        } else if idle >= self.cfg.silence_ms * 1_000_000 && !self.silent {
            self.silent = true;
            self.events.push_back(Event::Silent { secs: idle / 1_000_000_000 });
        }
        if self.machine.state() == OstpState::Closed {
            self.mark_lost(String::from("the server closed the session"));
        }
        match &self.lost {
            Some(why) => Err(Error::Lost(why.clone())),
            None => Ok(()),
        }
    }

    /// Release queued relay messages while the congestion window and pacing allow.
    fn flush(&mut self) {
        while let Some((_, b)) = self.outq.front() {
            if self.lost.is_some() {
                return;
            }
            if self.machine.in_flight_count() >= self.machine.cwnd_packets() || !self.machine.can_pace_packet() {
                return;
            }
            let len = b.len();
            let (sid, b) = match self.outq.pop_front() {
                Some(x) => x,
                None => return,
            };
            self.outq_bytes -= len;
            match self.machine.on_event(OstpEvent::Outbound(sid, b)) {
                Ok(a) => self.act(a),
                Err(e) => self.mark_lost(format!("cannot send: {e}")),
            }
        }
    }

    /// The next event, if any.
    pub fn next_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// How long the embedder may wait for the carrier before calling [`pump`](Self::pump)
    /// anyway: short while anything is in flight or queued, else until the next keepalive.
    pub fn next_wakeup_ms(&self) -> u64 {
        let now = P::now_ns();
        if !self.outq.is_empty() || self.machine.in_flight_count() > 0 || now.saturating_sub(self.last_rx_ns) < 1_000_000_000 {
            return 10;
        }
        let ka = (self.last_keepalive_ns + self.cfg.keepalive_ms * 1_000_000).saturating_sub(now) / 1_000_000;
        ka.clamp(10, 250)
    }

    /// Ask the server to connect a new stream to `target` (`host:port`). Its result comes
    /// as [`Event::Connected`] or [`Event::Failed`].
    pub fn open_stream(&mut self, target: &str) -> Result<u16, Error> {
        if let Some(why) = &self.lost {
            return Err(Error::Lost(why.clone()));
        }
        if self.streams.len() >= u16::MAX as usize - 1 {
            return Err(Error::Protocol(String::from("too many streams")));
        }
        let mut id = self.next_stream;
        while id == CONTROL_STREAM || self.streams.contains_key(&id) {
            id = id.wrapping_add(1);
        }
        self.next_stream = id.wrapping_add(1);
        self.streams.insert(id, StreamState { send_window: None, consumed: 0, connected: false });
        self.queue(id, &RelayMessage::Connect(target.to_string()));
        self.flush();
        Ok(id)
    }

    /// How many bytes [`send`](Self::send) would take on `stream` now.
    pub fn send_capacity(&self, stream: u16) -> usize {
        let st = match self.streams.get(&stream) {
            Some(s) if s.connected => s,
            _ => return 0,
        };
        let room = OUTQ_LIMIT.saturating_sub(self.outq_bytes);
        match st.send_window {
            Some(w) => room.min(w as usize),
            None => room,
        }
    }

    /// Queue bytes for `stream`; returns how many were taken (see `send_capacity`).
    pub fn send(&mut self, stream: u16, data: &[u8]) -> usize {
        let n = data.len().min(self.send_capacity(stream));
        if n == 0 {
            return 0;
        }
        let max = self.machine.max_payload();
        for chunk in relay::data_chunks(&data[..n], max) {
            self.queue(stream, &RelayMessage::Data(chunk.to_vec()));
        }
        if let Some(st) = self.streams.get_mut(&stream) {
            if let Some(w) = st.send_window.as_mut() {
                *w -= n as u64;
            }
        }
        self.flush();
        n
    }

    /// `n` bytes of [`Event::Data`] on `stream` reached the program: with flow control,
    /// let the server send that much more.
    pub fn consumed(&mut self, stream: u16, n: usize) {
        if !self.flow_control {
            return;
        }
        let grant = match self.streams.get_mut(&stream) {
            Some(st) => {
                st.consumed = st.consumed.saturating_add(n as u32);
                if st.consumed >= relay::WINDOW_UPDATE_STEP {
                    let g = st.consumed;
                    st.consumed = 0;
                    g
                } else {
                    0
                }
            }
            None => 0,
        };
        if grant > 0 {
            self.send_now(stream, &RelayMessage::Window(grant));
        }
    }

    /// Close `stream` after what was queued on it.
    pub fn close_stream(&mut self, stream: u16) {
        if self.streams.remove(&stream).is_some() {
            self.queue(stream, &RelayMessage::Close);
            self.flush();
        }
    }

    /// Send a ping; the answer comes as [`Event::Pong`].
    pub fn ping(&mut self) {
        let ts = P::now_ns() / 1000;
        self.send_now(CONTROL_STREAM, &RelayMessage::Ping(ts));
    }

    pub fn stats(&self) -> Stats {
        let now = P::now_ns();
        Stats {
            uptime_ms: now.saturating_sub(self.started_ns) / 1_000_000,
            idle_ms: now.saturating_sub(self.last_rx_ns) / 1_000_000,
            tx_bytes: self.tx_bytes,
            rx_bytes: self.rx_bytes,
            tx_datagrams: self.tx_datagrams,
            rx_datagrams: self.rx_datagrams,
            in_flight: self.machine.in_flight_count(),
            cwnd: self.machine.cwnd_packets(),
            streams: self.streams.len(),
            queued_bytes: self.outq_bytes,
            flow_control: self.flow_control,
            last_rtt_us: self.last_rtt_us,
            handshake_us: self.handshake_us,
        }
    }

    /// Tell the server the session ends.
    pub fn close(mut self) {
        if self.lost.is_none() {
            if let Ok(a) = self.machine.on_event(OstpEvent::Close) {
                self.act(a);
            }
        }
    }
}
