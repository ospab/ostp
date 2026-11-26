# Architecture

OSTP (Ospab Stealth Transport Protocol) is an encrypted tunnel written in Rust on Tokio. This page shows how the crates fit together and how a packet is framed.

## Crates

1. **ostp-core**: The protocol engine. Contains the `ProtocolMachine` state machine, Noise handshake driving, AEAD framing, header obfuscation, adaptive padding, the `RelayMessage` application-multiplexing layer, and the congestion controller (slow start, then CUBIC). Fully `sans-io` — no networking of its own.
2. **ostp-client**: The client daemon. Runs a dual-mode SOCKS5/HTTP inbound proxy and/or a TUN virtual adapter, drives NAT/exclusion logic, and maintains the encrypted session to the remote server, moving it to a new socket of the same transport when the network changes (roaming).
3. **ostp-server**: The high-concurrency dispatcher. Demultiplexes inbound datagrams by session ID, terminates sessions, handles IP roaming, proxies decrypted traffic to the open internet, and hosts the optional Management API, built-in DNS resolver, TCP fallback listener and the overnet bridge.
4. **ostp-tun**: Platform TUN-adapter bindings (Windows/Wintun, Linux, macOS) shared by the client and the GUI helper.
5. **ostpd**: A small, separately-privileged process the desktop GUI launches to create/own the TUN adapter, so the GUI itself doesn't need to run elevated.
6. **ostp-jni**: Android JNI bindings (`OstpClientSdk` native methods: start/stop client, metrics, logs, prober, subscriptions, server management) that embed the client engine inside the Flutter/Android app via isolated Tokio runtimes.
7. **ostp-dns**: The filtering DNS resolver the server runs for its clients (block lists, rules, rewrites, cache).
8. **ostp-ssh**: The SSH client both apps use to install OSTP on a server and manage it: password or key sign-in, a pinned host key, commands as root, a local port forward to the web panel, and the saved-servers list with sealed secrets (see [`integrations.md`](integrations.md#your-own-server-from-the-apps)).
9. **ostp**: The unified CLI binary — runs the engine in server, client, or relay mode, and hosts the `setup`/`init`/`key`/`links`/`connect`/`import`/`migrate`/`update`/`cert`/`sub`/`panel`/`dns`/`overnet`/`manage`/`changelog` subcommands (see [`client.md`](client.md) / [`server.md`](server.md)).

10. **ostp-warp**: Cloudflare WARP as an optional exit of the server: a user-space WireGuard client with a TCP/UDP stack, reached through a local SOCKS5 proxy that the server's `outbound` section points at (see [`warp-design.md`](warp-design.md)).

`third_party/netstack-smoltcp` is the vendored user-space TCP/IP stack the client's TUN mode uses (a copy of the crate with `TcpStream::abort`). `ostp-gui/src-tauri` is a separate Cargo workspace, and `ostp-brain`, `ostp-prober` and `ostp-lab` are excluded from the workspace (see the root `Cargo.toml`).

Inside `ostp-core` besides the state machine: the v6 handshake (`crypto/handshake_v6.rs`), v6 frames (`framing/frame.rs`), stream ids (`streams.rs`), path MTU discovery (`pmtu.rs`), stall detection (`stall.rs`), the congestion controller (`congestion.rs`), key expiry and server key helpers (`access_keys.rs`, `server_key.rs`), share links and subscription documents (`share_link.rs`, `subscription.rs`) and log privacy (`logpriv.rs`).

Two further application shells consume these crates but live outside the Cargo workspace: **ostp-gui** (a Tauri desktop app for Windows and Linux) and **ostp-flutter** (the cross-platform mobile app, Android via `ostp-jni`). See [`integrations.md`](integrations.md).

---

## Outer envelope and inner frame

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

## Protocol v6 on the wire (0.5.0)

A profile with the server's public key (`pk`) speaks v6; one without it speaks the v5 described above, which a server keeps answering while `accept_v5` is on. Both are in the code. Full layouts: [`specification.md`](specification.md), design: [`v6-design.md`](v6-design.md), [`v6-session-design.md`](v6-session-design.md).

- **Handshake.** Noise `NKpsk0` (the client knows the server's static key). The datagram is `[nonce:12][tag:4][ChaCha20-masked body]`; the body is `[session_id:4][noise_len:2][Noise message][padding]`. Nothing of the Noise message is visible, and the 4-byte tag lets a server with many keys find the right one with one HMAC per key.
- **Frame header v2**, 16 bytes inside the AEAD: `version(1)=2`, `kind(1)`, 2 random bytes, `stream_id` (u32), `stream_seq` (u32), `payload_len` (u16), `pad_len` (u16). Data headers on the outside stay masked as in v5 (see [`obfuscation.md`](obfuscation.md)).
- **More frame kinds, v6 only:** `7 Datagram` (an unsequenced payload, used for UDP) and `8 Abandon` (the sender says some nonces will never arrive and, with a reason, that a stream is reset). `Close` carries a reason and a short text; reason 6 is an expired key. A frame kind or message a peer does not know, once authenticated, is skipped.
- **Session layer.** The client opens odd stream ids, the server even ones; an id is never reused; at most 1024 streams are open. Order is kept per stream (`stream_seq`), so a lost frame holds back only its own stream. Each stream has its own flow-control window; `Fin` ends one direction and `Close` aborts.
- **Features.** After the handshake the sides exchange a bit set; bit 2 means the server can send its info (`InfoRequest` and `ServerInfo`, only inside the tunnel).
- **Automatic MTU** (RFC 8899 style, v6 over UDP): each side probes what it sends, from 1200 bytes up the ladder 1280, 1350, 1400, 1452.
- **Carriers.** On TCP and TLS nothing is lost, so nothing is resent and the stall detector only logs. The server keeps the queue toward such a client to about 100 ms at its measured drain rate, asks for BBR and `TCP_NOTSENT_LOWAT` on the socket (Linux), and every sender to a client is held to a closed-loop budget (congestion window plus pacing, counting frames still queued).

---

## Multiplexing: `RelayMessage`

A `Data` frame's payload is a tag-length-value `RelayMessage`: `Connect(addr)`, `Data(bytes)`, `Close`, `ConnectOk`, `Error(msg)`, `Ping`/`Pong(ts)`, `UdpAssociate`, `UdpData(addr, bytes)`, `KeepAlive`. This is the layer that actually multiplexes many proxied TCP connections and UDP flows over one encrypted session — in v5 the `stream_id` in the inner `FrameHeader` is not used to demultiplex (v6 does, see above); sequencing of a given proxied connection is implicit in the order of its `Connect`/`Data`/`Close` messages.

---

## ARQ

`ostp-core` implements a custom Selective-Repeat ARQ over the unreliable datagram substrate:

1. **Sequence tracking**: each data frame gets a strictly monotonic 64-bit `nonce`, which is simultaneously the ARQ sequence number and the AEAD nonce.
2. **Transmission history (`sent_history`)**: sent datagrams are cached until acknowledged, capped at `max_sent_history` (server/client default: 32,768) entries.
3. **Fast-path Nack retransmission**: on detecting a sequence gap, the receiver immediately sends a rate-limited `Nack` (at most once per `max(10ms, RTO/2)`) naming the lowest missing nonce; the sender looks it up in `sent_history` and retransmits immediately, bypassing the timeout loop.
4. **Timeout-based retries**: a periodic `OstpEvent::Tick` retransmits any frame past its adaptive RTO (RFC 6298, `[50ms, 16s]`) with exponential backoff up to 64×, budgeted at `max(2, cwnd_packets/4)` (capped 64) retransmits per tick.
5. **Out-of-order delivery (`reorder_buffer`)**: frames received ahead of sequence sit in a `BTreeMap` (capped at `max_reorder_buffer`, default 8,192) until the gap closes, then flush in order.
6. **Zombie eviction & gap recovery**: a frame retried past `max_retries + 2` attempts (default `max_retries` = 8) is dropped from `sent_history` and can never be retransmitted again. If that leaves the receiver's expected-nonce cursor stuck with no forward progress for `clamp(8×RTO, 2s, 10s)`, it deliberately skips the unrecoverable nonce, delivers everything already buffered behind it, and forces an `Ack` — trading one lost chunk for restoring a session that would otherwise freeze permanently.

---

## Congestion control

`ostp-core::congestion` keeps a window and an RTT estimate per session. Slow start begins at 32 packets. A single loss there costs a mild cut and slow start goes on; 3 or more losses inside 500 ms, or a smoothed RTT of twice the minimum, end it. After that the window follows CUBIC (RFC 9438). A smoothed RTT of four times the minimum counts as a standing queue and the window is reduced to drain it. Sending is paced at `cwnd / min_rtt`, and the window is capped at 8,192 packets. RTO follows RFC 6298 (SRTT/RTTVAR) with Karn's rule: a retransmitted frame is never used as an RTT sample.

---

## Data flow

1. A program connects to the local proxy (SOCKS5 or HTTP) or, in TUN mode, its packets reach the TUN adapter and `netstack-smoltcp` rebuilds the TCP and UDP flows. `exclude` rules decide whether a flow goes direct.
2. The client turns each flow into a stream: `Connect` or `UdpAssociate`, then `Data`/`UdpData`, as `RelayMessage`s in `Data` frames (`Datagram` frames for UDP in v6).
3. `ostp-core` frames, pads and encrypts them, applies the ARQ, congestion and flow control, and masks the header. The carrier (UDP, or UoT with optional TLS) sends the bytes. The client never changes the carrier by itself.
4. The server (`dispatcher.rs`) finds the session by `session_id`, decrypts, and `relay` opens the target (directly, through `outbound` or through WARP), subject to `target_policy`. DNS queries to the server's resolver go to `ostp-dns`.
5. Replies go back the same way. The bridge in `ostp-client` watches the session (silence, moves, reconnects, see [`client.md`](client.md)).

---

## Roaming

Session mappings are bound to the cryptographic `session_id`, not the network address. When a client switches networks (e.g., LTE to Wi-Fi) or the current path stops answering:
1. The client opens a new connection over the same transport and moves the same session onto it, with no new handshake.
2. The server accepts the datagram from the new address, checks AEAD, and switches the session's return address only if the packet's nonce is newer than any it has accepted. A replayed old packet does not move it.
3. The client's proxied TCP/UDP flows stay alive; unacknowledged data is retransmitted over the new path.
4. If the server does not answer (session expired or transport blocked), the client says so in the log and does nothing more on its own: the transport is the user's choice.

Details in the [specification, §9.6](specification.md). Looking a session up for an unfamiliar address is gated behind a token bucket (50-token burst, refilled at 50/sec) so an address-spoofing flood can't force unbounded work.

---

## Server subsystems

Beyond the dispatcher/ARQ core, `ostp-server` hosts several optional subsystems, each independently configurable — see [`server.md`](server.md) for details:

- **Management API** (`api.rs`): REST API for stats, user/key CRUD, traffic limits, audit log, and router rules, authenticated by Bearer token or a password-hash-backed session login; it does not start without one of them.
- **Traffic statistics file**: per-user traffic written next to the config every 30 seconds, read by `ostp manage` (what the apps run over SSH).
- **DNS resolver** (`dns.rs`): AdBlock-list filtering and DNS-over-HTTPS forwarding for tunneled clients, with a rate-limited reply path.
- **Fallback listener** (`fallback.rs`): pipes unauthenticated TCP connections (DPI probes, scanners) through to a real backend (e.g. local nginx), so an active probe sees an ordinary website instead of a closed or anomalous port.
- **Outbound proxy** (`outbound.rs`): optional egress through an upstream SOCKS5/HTTP proxy, with per-rule (domain suffix / CIDR / protocol) routing to proxy, direct, or block.
- **Relay node** (`relay_node.rs`): the `relay` mode. It forwards client UDP and UoT traffic to one fixed upstream server and authenticates nothing; the target server does that end to end.
- **overnet bridge**: optional. Sends `.ov` names to a local overnet gateway and can open an exit for overnet users (see [`server.md`](server.md)).
