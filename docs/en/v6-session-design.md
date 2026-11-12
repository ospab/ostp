# Protocol v6: the session layer

Status: draft, nothing here is implemented. It continues [v6-design.md](v6-design.md), which fixes the handshake; this page covers what happens after it: how frames are ordered, how streams and the session end, and what the header looks like. The wire format in force is version 5 ([specification.md](specification.md)).

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

## Ordering and loss

- **Loss recovery stays at the datagram level.** The nonce, `Ack`/`Nack` with SACK, the retransmit timer and the congestion controller work as in §9.1 and §9.5. A datagram that decrypts is acknowledged whatever stream it belongs to.
- **Delivery order moves to the stream.** A receiver keeps `expected_seq` per stream: the frame it expects is delivered at once, a later one waits in that stream's own buffer (bounded by the stream's window), an earlier one is a duplicate. A gap in stream A no longer holds stream B.
- **No silent skipping.** When a sender gives up on a frame (5 minutes, §9.1 as changed in 0.4.7), the stream is reset with the reason `lost`, and only that stream. The receiver does not jump over the gap.
- **`Close` is ordered.** It is the last sequenced frame of its stream, so it is delivered after the data before it; no separate nonce space is needed.

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

1. A stream that is reset for `lost` must be visible to the app that owns it (an error in the SOCKS proxy, a reset on the TUN's TCP flow): what exactly does each do?
2. Should the server tell a client a reason also when it silently drops it today for a bad frame? Proposed: no, only for the reasons in the table.
3. The per-stream buffer bound: the stream window (8 MiB) or less, with the total still capped by the session.
4. Whether `Fin` and `Close` need to be separate frame kinds instead of RelayMessage tags.
