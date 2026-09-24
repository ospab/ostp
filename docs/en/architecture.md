# OSTP System Architecture

## Overview
OSTP (Ospab Stealth Transport Protocol) is a high-performance, asynchronous network tunneling framework designed to provide secure, resilient, and indistinguishable data transport over untrusted networks. It is built entirely in Rust to guarantee memory safety, concurrency, and minimal overhead.

---

## Workspace Structure
The Cargo workspace is modularized into the following crates:

1. **ostp-core**: The protocol engine. Contains the `ProtocolMachine` state machine, Noise handshake driving, AEAD framing, header obfuscation, adaptive padding, the `RelayMessage` application-multiplexing layer, and the BBR-inspired congestion controller. Fully `sans-io` — no networking of its own.
2. **ostp-client**: The client daemon. Runs a dual-mode SOCKS5/HTTP inbound proxy and/or a TUN virtual adapter, drives NAT/exclusion logic, and maintains the encrypted session (including reconnection and roaming) to the remote server.
3. **ostp-server**: The high-concurrency dispatcher. Demultiplexes inbound datagrams by session ID, terminates sessions, handles IP roaming, proxies decrypted traffic to the open internet, and hosts the optional Management API, built-in DNS resolver, and TCP fallback listener.
4. **ostp-tun**: Platform TUN-adapter bindings (Windows/Wintun, Linux, macOS) shared by the client and the GUI helper.
5. **ostp-tun-helper**: A small, separately-privileged process the desktop GUI launches to create/own the TUN adapter, so the GUI itself doesn't need to run elevated.
6. **ostp-jni**: Android JNI bindings (`OstpClientSdk` native methods: start/stop client, metrics, logs) that embed the client engine inside the Flutter/Android app via an isolated Tokio runtime.
7. **ostp**: The unified CLI binary — runs the engine in server, client, or relay mode, and hosts the `setup`/`init`/`gk`/`links`/`connect`/`migrate`/`update` subcommands (see [`client.md`](client.md) / [`server.md`](server.md)).

Two further application shells consume these crates but live outside the Cargo workspace: **ostp-gui** (a Tauri desktop app, Windows-focused) and **ostp-flutter** (the cross-platform mobile app, Android via `ostp-jni`). See [`integrations.md`](integrations.md).

---

## Outer Envelope vs. Inner Frame

OSTP has two distinct framing layers (full byte layout in [`specification.md`](specification.md)):

1. **Outer wire envelope** — `[masked session_id : 4][masked nonce : 8][AEAD ciphertext+tag]` for data datagrams, or `[masked session_id : 4][masked noise_len : 2][noise_payload][random padding]` during the handshake. This is what ever touches the network; the first 12 (or 6) bytes are XOR-masked as a unit with an HMAC-SHA256 mask derived from the packet's own payload.
2. **Inner `FrameHeader`** — the plaintext recovered *after* AEAD decryption. Fixed 12 bytes:

| Offset (Bytes) | Data Type | Field Name | Description |
| :--- | :--- | :--- | :--- |
| 0 | `u8` | `version` | Inner frame format version (current: `1`) |
| 1 | `u8` | `kind` | Frame kind (see below) |
| 2–3 | 2×`u8` | *(random)* | Filled with random bytes (not zero) to avoid a known-plaintext pattern inside the encrypted region — there is no `flags` field |
| 4–5 | `u16 BE` | `stream_id` | Reserved for future per-stream framing; `0` on control frames |
| 6–9 | `u32 BE` | `payload_len` | Length of the payload in bytes |
| 10–11 | `u16 BE` | `pad_len` | Length of the appended random padding |

### Frame Kinds (`FrameKind`)
- `1 - Handshake`: reserved; handshake messages actually travel in the outer envelope, not as an inner frame.
- `2 - Data`: carries a `RelayMessage` (see below).
- `3 - Close`: signals session teardown.
- `4 - KeepAlive`: keeps NAT mappings alive.
- `5 - Nack`: explicit negative-ack requesting immediate retransmission.
- `6 - Ack`: cumulative + selective ack.

A complete inner record (`FramedPacket`) is `[12-byte FrameHeader] + [N-byte Payload] + [M-byte Padding]`, and it is this whole record that gets AEAD-encrypted to produce the outer envelope's ciphertext.

---

## Application Multiplexing (`RelayMessage`)

A `Data` frame's payload is a tag-length-value `RelayMessage`: `Connect(addr)`, `Data(bytes)`, `Close`, `ConnectOk`, `Error(msg)`, `Ping`/`Pong(ts)`, `UdpAssociate`, `UdpData(addr, bytes)`, `KeepAlive`. This is the layer that actually multiplexes many proxied TCP connections and UDP flows over one encrypted session — `stream_id` in the inner `FrameHeader` is not yet used to demultiplex; sequencing of a given proxied connection is implicit in the order of its `Connect`/`Data`/`Close` messages.

---

## Reliable ARQ System (Automatic Repeat reQuest)

`ostp-core` implements a custom Selective-Repeat ARQ over the unreliable datagram substrate:

1. **Sequence tracking**: each data frame gets a strictly monotonic 64-bit `nonce`, which is simultaneously the ARQ sequence number and the AEAD nonce.
2. **Transmission history (`sent_history`)**: sent datagrams are cached until acknowledged, capped at `max_sent_history` (server/client default: 32,768) entries.
3. **Fast-path Nack retransmission**: on detecting a sequence gap, the receiver immediately sends a rate-limited `Nack` (at most once per `max(10ms, RTO/2)`) naming the lowest missing nonce; the sender looks it up in `sent_history` and retransmits immediately, bypassing the timeout loop.
4. **Timeout-based retries**: a periodic `OstpEvent::Tick` retransmits any frame past its adaptive RTO (RFC 6298, `[50ms, 16s]`) with exponential backoff up to 64×, budgeted at `max(2, cwnd_packets/4)` (capped 64) retransmits per tick.
5. **Out-of-order delivery (`reorder_buffer`)**: frames received ahead of sequence sit in a `BTreeMap` (capped at `max_reorder_buffer`, default 8,192) until the gap closes, then flush in order.
6. **Zombie eviction & gap recovery**: a frame retried past `max_retries + 2` attempts (default `max_retries` = 8) is dropped from `sent_history` and can never be retransmitted again. If that leaves the receiver's expected-nonce cursor stuck with no forward progress for `clamp(8×RTO, 2s, 10s)`, it deliberately skips the unrecoverable nonce, delivers everything already buffered behind it, and forces an `Ack` — trading one lost chunk for restoring a session that would otherwise freeze permanently.

---

## Congestion Control

A BBR-inspired controller (`ostp-core::congestion`) tracks `cwnd`/RTT per session: exponential slow start from a 32-packet initial window, tolerant of isolated loss (only 3+ losses inside a 500ms window count as sustained congestion and exit slow start), additive-increase/multiplicative-decrease (×0.7) in the probe-bandwidth phase, and RFC 6298 SRTT/RTTVAR-based RTO with Karn's-algorithm RTT sampling (never sampled from a retransmitted frame).

---

## Dynamic Roaming

Session mappings are bound to the cryptographic `session_id`, not the network address. When a client switches networks (e.g., LTE to Wi-Fi) or the current path stops answering:
1. The client opens a new connection over the same transport and moves the same session onto it, with no new handshake.
2. The server accepts the datagram from the new address, checks AEAD, and switches the session's return address only if the packet's nonce is newer than any it has accepted. A replayed old packet does not move it.
3. The client's proxied TCP/UDP flows stay alive; unacknowledged data is retransmitted over the new path.
4. If the server does not answer (session expired or transport blocked), the client says so in the log and does nothing more on its own: the transport is the user's choice.

Details in the [specification, §9.6](specification.md). Looking a session up for an unfamiliar address is gated behind a token bucket (50-token burst, refilled at 50/sec) so an address-spoofing flood can't force unbounded work.

---

## Server-Side Subsystems

Beyond the dispatcher/ARQ core, `ostp-server` hosts several optional subsystems, each independently configurable — see [`server.md`](server.md) for details:

- **Management API** (`api.rs`): REST API for stats, user/key CRUD, traffic limits, audit log, and router rules, authenticated by Bearer token or a password-hash-backed session login.
- **DNS resolver** (`dns.rs`): AdBlock-list filtering and DNS-over-HTTPS forwarding for tunneled clients, with a rate-limited reply path.
- **Fallback listener** (`fallback.rs`): pipes unauthenticated TCP connections (DPI probes, scanners) through to a real backend (e.g. local nginx), so an active probe sees an ordinary website instead of a closed or anomalous port.
- **Outbound chaining** (`outbound.rs`): optional egress through an upstream SOCKS5/HTTP proxy, with per-rule (domain suffix / CIDR / protocol) routing to proxy, direct, or block.
- **Relay-node federation** (`relay_node.rs`): a lightweight relay mode that accepts client connections (UDP or UoT), authenticates them against access keys synced from an upstream server's Management API, and blindly forwards authorized traffic on — letting a chain of relays front one target server without each hop knowing traffic contents.
