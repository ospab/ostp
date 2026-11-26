# Protocol v6: the session layer

Status: stage 1 is implemented in `ostp-core` (frame header v2, per-stream delivery, unsequenced datagrams, reset for `lost`, stream id rules). Stage 2 is implemented in the server and the client (see "How stage 2 does it" below): stream ids, release of finished streams, UDP as datagrams, stream resets, the `Fin` half-close and mandatory flow control, in v6 sessions only. Stage 3, the session `Close` with a reason, is implemented in the core, the server, the client and the apps (see "How stage 3 does it" below). It continues [v6-design.md](v6-design.md), which fixes the handshake; this page covers what happens after it: how frames are ordered, how streams and the session end, and what the header looks like. All three stages are in 0.5.0; the wire format is in [specification.md](specification.md), and "Differences from the plan" at the end lists what turned out otherwise than first written. 0.4.x stays on version 5.

## What is wrong in 0.4.x (version 5)

1. **One lost frame stalls everything.** Delivery is gated on a single session-wide sequence (§9.1): a frame missing for stream A holds every later frame of stream B. A page that loads over twenty streams waits for the slowest loss.
2. **A gap is skipped, not repaired.** After a stall the receiver jumps to the lowest buffered nonce (§9.4). For a TCP stream that silently drops a chunk of bytes in the middle, which corrupts the stream instead of ending it.
3. **UDP gets TCP's treatment.** `UdpData` goes through the same retransmission, so a QUIC packet is resent after it is useless, and it waits behind other frames in order.
4. **Streams end badly.** A program's FIN closes the whole stream and the reply is lost. A `u16` stream id is reused, so a late `Close` can kill a newer stream. A `Close` can overtake data that is still being retransmitted.
5. **A refused client learns it late.** The server is silent to an unknown session by design, and an established session that is dropped (revoked key, restart) gets no word either: the client finds out after 10 s of silence.

## Frame header: 12 to 16 bytes

```
version(1) kind(1) random(2) stream_id(4) stream_seq(4) payload_len(2) pad_len(2)
```

- `stream_id` becomes 32 bits and is **never reused in a session**. The client opens odd ids, the server even ones (as HTTP/2 does); a session may have at most 1024 open streams. A stale `Close` cannot hit a newer stream, so no generation number is needed.
- `stream_seq` numbers the `Data` frames of one stream (`Fin` and the stream's `Close` are relay messages inside them). Control frames (`Ack`, `Nack`, `KeepAlive`, the session `Close`) use stream 0 and are not sequenced.
- `payload_len` shrinks to 16 bits: a frame never exceeds the path MTU.
- The usable payload of a datagram is 4 bytes smaller; the MTU defaults do not change. The inner frame version becomes 2, and a session is v5 or v6 as a whole.

Exact layout of the v6 header (implemented, all integers big-endian):

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | `version` = 2 |
| 1 | 1 | `kind` |
| 2 | 2 | `random` (fresh per frame, no meaning) |
| 4 | 4 | `stream_id` |
| 8 | 4 | `stream_seq` |
| 12 | 2 | `payload_len` |
| 14 | 2 | `pad_len` |

Frame kinds: 1 `Handshake`, 2 `Data`, 3 `Close` (the session's), 4 `KeepAlive`, 5 `Nack`, 6 `Ack`, and two new ones that exist only in v6: 7 `Datagram` and 8 `Abandon`. A v5 session treats 7 and 8 as unknown, as 0.4.x does. A frame that carries more payload than `max_payload()` is refused at the sender, not truncated or fragmented. The session is v5 or v6 by `ProtocolConfig.v6`, that is by the handshake; the v5 code paths are untouched. The last `stream_seq` value (2^32 - 1) is never used.

## Ordering and loss

- **Loss recovery stays at the datagram level.** The nonce, `Ack`/`Nack` with SACK, the retransmit timer and the congestion controller work as in §9.1 and §9.5. A datagram that decrypts is acknowledged whatever stream it belongs to.
- **Delivery order moves to the stream.** A receiver keeps `expected_seq` per stream: the frame it expects is delivered at once, a later one waits in that stream's own buffer (bounded by the stream's window), an earlier one is a duplicate. A gap in stream A no longer holds stream B.
- **No silent skipping.** When a sender gives up on a frame (5 minutes, §9.1 as changed in 0.4.7), the stream is reset with the reason `lost`, and only that stream. The receiver does not jump over the gap.
- **`Close` is ordered.** It is the last sequenced frame of its stream, so it is delivered after the data before it; no separate nonce space is needed. As decided, a stream's `Close` (and `Fin`) is a RelayMessage tag inside a sequenced `Data` frame, not a frame kind; the machine only sees `Data` frames, so the stream's order covers it. The frame kind `Close` stays the session's own, on stream 0, and is not sequenced.

### How stage 1 does it

- **Datagram level.** `expected_recv_nonce` and the nonce set (`reorder_buffer`, nonces only in v6) say which datagrams arrived; ACK ranges, duplicate detection and the NACK logic are as in v5. The set is capped by the existing session limit; a frame that does not fit is dropped without being recorded, so it is not acknowledged and the sender resends it.
- **Stream level.** `Data` frames (stream 0 included: it carries `Features`, `Ping`) have a `stream_seq` per stream from 0. The receiver keeps `expected_seq` and a buffer per stream. A frame at `expected_seq` is delivered at once with the buffered run behind it; a later one is held; an earlier one is a duplicate. A held frame needs room in two places: the stream's own bytes (at most the stream window, 8 MiB, `relay::INITIAL_STREAM_WINDOW`) and the frames held by all streams together (at most the session's reorder buffer). With no room the frame is dropped unacknowledged and comes again. A frame that is due is never refused for room, so a full buffer cannot deadlock a stream.
- **State of streams.** A receiver tracks at most 2048 streams; the caller releases one with `OstpEvent::ReleaseStream` when it is over on both sides (stage 2 calls it). The ids of released and reset streams are remembered (the lowest are forgotten past 8192) and late frames of them are acknowledged and dropped. Without the release call the state of a stream stays until the session ends.
- **Datagrams.** `OstpEvent::OutboundDatagram(stream_id, payload)` sends a `Datagram` frame (kind 7, `stream_seq` 0); the receiver delivers it at once as `ProtocolAction::DeliverDatagram` unless its nonce was seen. It is charged to the congestion window and acknowledged like every frame, but never resent: the retransmit timer skips it, a NACK for it does not resend it. A datagram nothing acknowledged within 4 RTOs, or one the peer NACKed, is counted lost: it leaves the window (the controller sees a loss) and the peer is told with `Abandon`. Its hole at the receiver is a datagram-level hole only; no stream waits for it.

### How stage 2 does it

All of this applies to a v6 session only (`ProtocolMachine::is_v6`); a v5 session, including one served by the transitional server, keeps its 16-bit ids, its `Close`, its UDP as stream data and its optional `Features` flow control, byte for byte.

- **Ids.** The server and the client hold their channels and maps by `u32`. The client's bridge opens a stream with the session's `StreamIds::open_local` (one allocator per session, so each mux session has its own id space); the server accepts it with `accept_remote` on the first message (`Connect` or `UdpAssociate`). A refusal (limit, reused or wrong-parity id) is answered with `Error` and the stream is released. At the limit of 1024 open streams the client refuses the new connection at once, with `Connection refused: too many open streams (1024 at most per session)` in the log and a SOCKS failure reply to the program; it never waits. The proxy's own connection ids are `u32` and are not reused while the connection lives; the bridge maps them to the wire ids (and, in v5, allocates the next free 16-bit id of the session, as the proxy did before).
- **Release.** A stream is released (`StreamIds::close`, `OstpEvent::ReleaseStream`) when both sides have sent `Fin`, or at `Close`/`Error`/a reset. Both ends do it on their own: the server in `relay::end_stream`, the client in the bridge's `release_route`. The proxy also tells the bridge when it is done with a connection however it ended (`ProxyEvent::Gone`), so a stream whose connection never finished (a connect that timed out, a UDP association whose control connection closed) is aborted and its slot given back.
- **Half-close.** `RelayMessage::Fin` is tag 13. A program's end of stream (the proxy's read returns 0; for the TUN the same, since the netstack's flow reaches the bridge through the local SOCKS proxy) sends `Fin` and the proxy keeps reading the reply; the peer's `Fin` is `shutdown(Write)` on the program's socket (the server: on the target's, after the bytes still queued). `ConnectOkV6` tells the proxy that the stream is v6, so the end of stream is a half-close and not a `Close`. `Close` is the abort: in v6 it carries a reason byte (`RelayMessage::Abort`, `[4, reason]`).
- **Flow control.** Every v6 stream starts with `INITIAL_STREAM_WINDOW` in each direction and `Window` only adds; no `Features` exchange or first `Window` is needed for flow control (the client sends `Features` in v6 only to ask for server information, bit 2). The server's 32 MiB queued-upload reset does not apply: a v6 stream is aborted only when it has more than twice the window waiting for the target, which means the peer broke the flow control. The client's matching cap on a stalled reader never fires on a v6 stream, since the window keeps its queue under 8 MiB.
- **UDP.** `UdpData` goes through `OutboundDatagram` and arrives as `DeliverDatagram`, in both directions (the server's replies from its UDP socket too). No retransmission, no order. A datagram that does not fit `max_payload` is refused as before.
- **Resets.** `StreamReset` (from `Inbound` and from `Tick`, which callers used to drop) resets the program's connection (the proxy closes with a zero linger time, so the program sees a TCP RST) and the server closes the target. A reset of stream 0 ends the session: the server drops it as it drops an expired one, the client starts its reconnect as it does after a protocol error. The `Abort` of the peer takes the same path.
- **RST in the TUN.** The TUN's TCP flows are the `netstack-smoltcp` crate's `TcpStream`s, and dropping one closes with a FIN, so a reset used to reach the program as a normal end. The tree now carries a copy of the crate (`third_party/netstack-smoltcp`, used through `[patch.crates-io]`; its README lists the change) with `TcpStream::abort`, which makes the stack's smoltcp socket send a RST and discards what is still queued. The TUN bridge (`relay_flow` in `ostp-client/src/tunnel/native_handler.rs`) copies between the flow and the local SOCKS connection; when that connection ends with a connection reset (what the proxy's zero-linger close of a reset stream looks like), it aborts the flow, so the program sees a RST and a truncated transfer fails. A normal end, and an error on the program's side alone, still end the flow as before (a FIN, or nothing). Tests: in the crate, `abort` emits a RST and no FIN and a drop or `shutdown` emits a FIN and no RST, on IPv4 and IPv6 (raw packets through the stack); in the client, the bridge aborts on a reset and only on a reset. Not covered by a test: a whole run through a TUN device (no device in the test environment). A connection that fails before the relay starts (the SOCKS handshake or the connect) still ends the flow with a FIN.

### How stage 3 does it

v6 sessions only. A v5 session never emits or reads a reason: the server stays silent to a v5 client, and `OstpEvent::CloseWith` on a v5 machine sends nothing and leaves the session as it is.

- **The frame.** The existing `Close` frame (kind 3, stream 0). In v6 its payload is `reason(1) text(0..=64, UTF-8)`; an empty payload reads as reason 0. It is a tracked frame, not stream data: it is acted on when it arrives, outside any stream order. A sender cuts a longer text on a character boundary (at most 64 bytes); a receiver reads an unknown reason as 0, cuts a text over 64 bytes and reads a text that is not UTF-8 lossily: the frame is authenticated, so the peer did end the session, and refusing it would leave a hole at its nonce that stalls the session behind it. The core reports it to its caller as `ProtocolAction::PeerClosed(reason, text)`, once, and only on the side that did not close first. A client's normal stop sends `Close` with reason 0 (`OstpEvent::Close`), so the server frees the session at once.
- **Retransmission.** The `Close` is resent until the peer acknowledges it: the core's ordinary retransmit schedule (0.1, 0.2, 0.4, 0.8 s and on) applies, and a machine that sent a `Close` is `Closed` when it is acknowledged or the retries run out. The receiver acknowledges a `Close` at once (not on the delayed-ACK timer), since it is `Closed` and ignores the copies that follow. The server gives a resend at most 5 seconds after it dropped the session (`CLOSE_GRACE`), keeps at most 256 such sessions, and reads only their acknowledgements; a stopping server waits at most 1.5 s for them.
- **Who is told, and why.** Only a session that passed authentication ever gets a `Close`, so a packet of an unknown session still gets nothing. The server sends it from every place that drops a live v6 session for a reason it can name: the key is gone from the config on hot reload (2), the key's traffic limit is used up (3), the per-key cap of 32 sessions drops the oldest (4), the server is stopping (5). Not sent, as decided: idle expiry (the client is gone), a bad or unauthenticated frame, a session the same key replaced by reusing its id (a reconnect), a session the client closed itself.
- **Reason 1 is never sent by the server.** `systemctl stop` and `systemctl restart` both reach the process as SIGTERM, and a restart is a stop followed by a start by the service manager; the server cannot tell them apart. It sends 5 in both cases. Reason 1 is part of the wire format and the client knows its text, but nothing sends it yet.
- **Shutdown.** The signal no longer drops the server loop on the spot: it is told to stop, sends every v6 session a `Close` with reason 5 and accepts no new session, then runs the retransmit tick for at most 1.5 s while the acknowledgements come in, and stops. If the loop has not stopped 3 s after the signal, the process stops anyway.
- **The client.** A `PeerClosed` is not a failure of the path or of the protocol, so it does not go to `begin_reconnect` (a reset of stream 0, which stage 2 sends there, is a different thing and stays as it was). The bridge sends the acknowledgement, stops the tunnel at once (no wait for the 10 s of silence), resets the programs' connections, logs the reason, reports `UiEvent::ServerClosed(message)` and `TunnelStopped`, and idles. It does not reconnect by itself; the user chooses. `run_client_core` ends the run with the message (`RunError::Closed`) and does not restart it as it does after a crashed task. The texts are in `ostp-client/src/app.rs` (`server_close_message`), in plain words with what to do: for example "The server closed the connection: your key was revoked or removed. Ask the server owner for a new key." The optional text of the frame is appended as "Message from the server: ...", without control characters; the server sends none today.
- **The apps.** Desktop: the core's error text goes to the existing banner as it is (no "The connection stopped:" in front of a server message). Android: the JNI metrics carry `stop_reason`, set before `connection_state` turns to 0, and the app shows it in place of "Could not connect to the server" for 12 seconds. There is no "Connect again" button for reason 1: the power button already is one tap, and the text says so. Nothing connects by itself.

## Reset for `lost`: the mechanism

The receiver cannot learn from a frame it never got, so the sender says it. One new unsequenced control frame, `Abandon` (kind 8, stream 0 in the header), carries `stream_id(4) reason(1) count(1)` and `count` ranges of `start(8) end(8)` nonces, in the frame's payload:

- **The sender gives up on a `Data` frame** (retries exhausted and 5 minutes, unchanged). It resets that stream, and only it: every frame of the stream still in flight is dropped from the history, the stream is dead for `Outbound`, and one `Abandon` (several if the ranges do not fit a datagram) goes out with reason 1 (`lost`) and the nonces of all those frames. The caller gets `ProtocolAction::StreamReset(stream_id, Lost)` from the tick.
- **That `Abandon` is retransmitted until acknowledged** (it is a tracked frame with its own nonce). The receiver, on taking it, counts the nonces as received (so the datagram-level holes close), drops the stream's buffers, marks it dead and returns `StreamReset(stream_id, Lost)` to its caller. The stream is dead in both directions; later frames of it are acknowledged and dropped. Other streams are not touched.
- **An `Abandon` with reason 0** only closes nonce holes and is not retransmitted. The sender sends it for lost datagrams and as the answer to a NACK for a nonce it no longer has (and has used): the frame was acknowledged long ago, evicted, or given up on. Without that answer a hole of a lost control frame or datagram would never close. A lost `Abandon` is asked for again by the receiver's own repeated NACK, so no timer is needed. It is rate-limited to one answer per 10 ms.
- **The receiver does not skip in v6.** `recover_stalled_gap` is for v5 only. A stream with a hole waits until the peer resets it.
- The only stream reset reason is 1 `lost` (the session-close reasons below are a separate table); a reason this version does not know reads as `lost`.
- A given-up frame of stream 0 resets stream 0: the caller gets the event and decides (the session control stream is gone, which in practice ends the session).

## Decisions on the questions that were open

1. A stream reset for `lost`: the SOCKS proxy closes the program's connection (RST semantics), the TUN sends a TCP RST on that flow. The event is exposed in stage 1; the wiring is stage 2.
2. No reason is sent for a silently dropped bad frame; only the reasons in the session-close table.
3. The per-stream buffer bound is the stream's flow-control window (8 MiB); the total is capped by the session limit.
4. `Fin` and `Close` are RelayMessage tags inside sequenced `Data` frames, not frame kinds.
5. Not in 0.5.0: a connection id; server sharding and GSO.

## Stream ids (implemented as pure logic)

`ostp_core::streams::StreamIds`: the client opens odd ids and the server even ones, 0 is the session's, an id is never handed out twice, at most 1024 streams are open (`MAX_OPEN_STREAMS`, both directions together). The ids of the peer are accepted by parity and not-reused; they may start in any order, since each stream is ordered on its own (the closed ids of the peer are remembered, the oldest forgotten past 8192). The server and the client use it as of stage 2.

## Streams

- **Half-close.** A new `Fin` message (RelayMessage tag 13) says "I will write no more"; the other direction keeps flowing. The stream is released when both sides have sent `Fin`. `Close` keeps meaning "abort", and now carries a one-byte reason.
- **Flow control is mandatory.** The per-stream credit negotiated in 0.4.7 (§8.1) becomes part of every stream, and the server no longer resets a stream with 32 MiB waiting: the window is what holds the sender.
- **UDP is not a stream.** `UdpData` becomes an unsequenced, unretransmitted frame (a new kind) that ignores the ordering above and counts against the congestion window only. A lost datagram is lost, as on the real path; the application above (QUIC, DNS) recovers it.

## Ending the session

An established session can be told why it ended. The server sends an authenticated `Close` (stream 0) with a one-byte reason and optional text of up to 64 bytes, then forgets the session:

| Reason | Meaning |
|---|---|
| 0 | Normal stop by the peer |
| 1 | The server is restarting |
| 2 | The key was revoked or removed |
| 3 | The traffic limit is used up |
| 4 | Too many sessions for this key |
| 5 | The server is shutting down |
| 6 | The key has expired |

A key whose expiry has passed still completes the handshake; the server then sends `Close` with reason 6 at once, so the reason reaches the client only inside the authenticated session. A v5 client with an expired key is refused like one whose traffic limit is used up. A client that does not know reason 6 reads it as 0.

The client stops, shows the reason and does not retry by itself. This does not weaken the stealth rule: a packet of an unknown session still gets nothing, because only a session that passed authentication is answered, and an observer cannot make one. Reason 1 is the only case where the app may offer one tap to reconnect on the same transport.

## Not built in 0.5.0

- **A connection id for migration.** Today the server finds the session of a datagram from an unfamiliar address by trying keys, behind a token bucket (50 a second, §9.6); roaming works. A QUIC-style rotating connection id would make the lookup cheap but gives an observer a value that is constant along a path. Measure the scan at 1024 sessions in wirelab first; build the id only if it is a real cost.
- **Server throughput** (about 300 Mbit/s, one loop and one syscall per datagram): sharding by session and `sendmmsg`/GSO do not change the wire, so they can ship in a 0.4.x release.

## How it is checked

- Pure logic in unit tests: header encode and decode against fixed vectors, per-stream reordering (in order, gap, duplicate, window overflow), `Close` after data, `Fin` on both sides, id parity and the stream limit.
- Wirelab, v5 against v6 on the same path with loss: two concurrent downloads, one path loss of 1%; the second stream's latency and throughput must not follow the first one's losses. A QUIC-shaped UDP flow over the tunnel must keep its loss instead of having it hidden.
- A 0.4.5 client against a transitional server still works on v5.

## Differences from the plan
- A frame that authenticates but cannot be read (a newer peer's kind, a malformed field) is recorded, acknowledged and ignored in v6. Refusing it was the first idea and it stalls the session: the hole at its nonce is resent into for minutes.
- Timer loss counts as a congestion signal on UDP, and a reliable carrier (TCP, TLS) resends only after 5 s or after a move; the plan treated both carriers alike. See [specification.md](specification.md) §9.1.
- The `KeepAlive` frame kind also carries the path MTU probe, and an `Abandon` with reason 0 closes the hole of a lost probe or datagram (automatic MTU, [specification.md](specification.md) §9.8). Not in the plan.
- A stall detector resends the oldest frame at once when data is in flight and no ACK moves for `max(4×SRTT, 1 s)` (§9.9). Not in the plan.
- `Features` is still sent in v6, only to negotiate server information (bit 2); flow control needs no bit.
- Reason 1 of the session `Close` is never sent by the server (stage 3). Reason 6, key expired, was added after the first table.
- Not built: a connection id, sharding and GSO.

## Open questions

None: the four that were open are decided above.
