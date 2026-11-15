# Protocol v6: the session layer

Status: stage 1 is implemented in `ostp-core` (frame header v2, per-stream delivery, unsequenced datagrams, reset for `lost`, stream id rules); the server and client do not use it yet. Stage 2 is the `Fin` half-close, mandatory flow control and wiring the stream ids and datagrams into the server and client; stage 3 is the session `Close` with a reason. It continues [v6-design.md](v6-design.md), which fixes the handshake; this page covers what happens after it: how frames are ordered, how streams and the session end, and what the header looks like. The wire format in force is version 5 ([specification.md](specification.md)).

## What is wrong today

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
- `stream_seq` numbers the frames of one stream (`Data`, `Fin`, `Close`). Control frames (`Ack`, `Nack`, `KeepAlive`, the session `Close`) use stream 0 and are not sequenced.
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

## Reset for `lost`: the mechanism

The receiver cannot learn from a frame it never got, so the sender says it. One new unsequenced control frame, `Abandon` (kind 8, stream 0 in the header), carries `stream_id(4) reason(1) count(1)` and `count` ranges of `start(8) end(8)` nonces, in the frame's payload:

- **The sender gives up on a `Data` frame** (retries exhausted and 5 minutes, unchanged). It resets that stream, and only it: every frame of the stream still in flight is dropped from the history, the stream is dead for `Outbound`, and one `Abandon` (several if the ranges do not fit a datagram) goes out with reason 1 (`lost`) and the nonces of all those frames. The caller gets `ProtocolAction::StreamReset(stream_id, Lost)` from the tick.
- **That `Abandon` is retransmitted until acknowledged** (it is a tracked frame with its own nonce). The receiver, on taking it, counts the nonces as received (so the datagram-level holes close), drops the stream's buffers, marks it dead and returns `StreamReset(stream_id, Lost)` to its caller. The stream is dead in both directions; later frames of it are acknowledged and dropped. Other streams are not touched.
- **An `Abandon` with reason 0** only closes nonce holes and is not retransmitted. The sender sends it for lost datagrams and as the answer to a NACK for a nonce it no longer has (and has used): the frame was acknowledged long ago, evicted, or given up on. Without that answer a hole of a lost control frame or datagram would never close. A lost `Abandon` is asked for again by the receiver's own repeated NACK, so no timer is needed. It is rate-limited to one answer per 10 ms.
- **The receiver does not skip in v6.** `recover_stalled_gap` is for v5 only. A stream with a hole waits until the peer resets it.
- The only stream reset reason is 1 `lost` (the session-close reasons below are a separate table); an unknown value makes the frame invalid.
- A given-up frame of stream 0 resets stream 0: the caller gets the event and decides (the session control stream is gone, which in practice ends the session).

## Decisions on the questions that were open

1. A stream reset for `lost`: the SOCKS proxy closes the program's connection (RST semantics), the TUN sends a TCP RST on that flow. The event is exposed in stage 1; the wiring is stage 2.
2. No reason is sent for a silently dropped bad frame; only the reasons in the session-close table.
3. The per-stream buffer bound is the stream's flow-control window (8 MiB); the total is capped by the session limit.
4. `Fin` and `Close` are RelayMessage tags inside sequenced `Data` frames, not frame kinds.
5. Not in 0.5.0: a connection id; server sharding and GSO.

## Stream ids (implemented as pure logic)

`ostp_core::streams::StreamIds`: the client opens odd ids and the server even ones, 0 is the session's, an id is never handed out twice, at most 1024 streams are open (`MAX_OPEN_STREAMS`, both directions together). The ids of the peer are accepted by parity and not-reused; they may start in any order, since each stream is ordered on its own (the closed ids of the peer are remembered, the oldest forgotten past 8192). The server and the client start using it in stage 2.

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

The client stops, shows the reason and does not retry by itself. This does not weaken the stealth rule: a packet of an unknown session still gets nothing, because only a session that passed authentication is answered, and an observer cannot make one. Reason 1 is the only case where the app may offer one tap to reconnect on the same transport.

## Left out of the first v6 beta

- **A connection id for migration.** Today the server finds the session of a datagram from an unfamiliar address by trying keys, behind a token bucket (50 a second, §9.6); roaming works. A QUIC-style rotating connection id would make the lookup cheap but gives an observer a value that is constant along a path. Measure the scan at 1024 sessions in wirelab first; build the id only if it is a real cost.
- **Server throughput** (about 300 Mbit/s, one loop and one syscall per datagram): sharding by session and `sendmmsg`/GSO do not change the wire, so they can ship in a 0.4.x release.

## How it is checked

- Pure logic in unit tests: header encode and decode against fixed vectors, per-stream reordering (in order, gap, duplicate, window overflow), `Close` after data, `Fin` on both sides, id parity and the stream limit.
- Wirelab, v5 against v6 on the same path with loss: two concurrent downloads, one path loss of 1%; the second stream's latency and throughput must not follow the first one's losses. A QUIC-shaped UDP flow over the tunnel must keep its loss instead of having it hidden.
- A 0.4.5 client against a transitional server still works on v5.

## Open questions

None: the four that were open are decided above.
