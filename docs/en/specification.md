# Ospab Stealth Transport Protocol (OSTP) Specification

**Version:** 1.1 (July 2026)
**Wire Protocol Version:** 5 (`PROTOCOL_VERSION`, key-derived, never sent in cleartext — see §6)
**Authors:** Georgiy S., Ospab Foundation
**Status:** Stable, Informational

---

## 1. Introduction

The **Ospab Stealth Transport Protocol (OSTP)** is a high-entropy, multiplexed transport pipeline developed to achieve secure, resilient data replication between distributed nodes across networks characterized by severe stochastic disturbance and hostile packet-level telemetry inspections (Deep Packet Inspection / DPI).

Standard tunneling protocols (e.g., OpenVPN, WireGuard) produce traffic patterns that are reliably identified by stateful DPI systems through static magic bytes, fixed handshake sizes, or predictable sequence patterns. OSTP addresses this threat model by employing key-derived per-packet masking and randomized frame-boundary injection prior to final serialization. The primary design goal is complete convergence toward **Maximum Uniform Entropy**, yielding datagrams statistically identical to pure line noise, with no plaintext version marker or magic byte anywhere on the wire.

OSTP is transport-agnostic at the datagram level: the same masked/encrypted datagram is carried either directly over UDP, or — for networks that block or throttle unrecognized UDP — inside a plain TCP byte stream (**UoT**, "UDP-over-TCP"; see §9). Neither transport adds any protocol-identifying header of its own.

---

## 2. Cryptographic Primitives

OSTP is built strictly upon standardized, modern cryptographic primitives:

| Component | Primitive / Standard | Purpose |
|---|---|---|
| **Handshake** | Noise Protocol Framework (`Noise_NNpsk0`) | Mutual authentication and forward-secret key exchange. |
| **Key Agreement** | X25519 (RFC 7748) | Ephemeral Elliptic Curve Diffie-Hellman. |
| **Symmetric Encryption** | ChaCha20-Poly1305 (RFC 8439) | Authenticated Encryption with Associated Data (AEAD) for all payload data. |
| **Hashing** | BLAKE2s (RFC 7693) | Noise internal state hashing and mixing. |
| **Key Derivation** | HKDF-SHA256 (RFC 5869) | Derives every protocol secret from the shared access key (§6). |
| **Obfuscation Masking** | HMAC-SHA-256 (RFC 2104) | Per-packet header scrambling to eliminate static byte signatures. |

---

## 3. Protocol Architecture

OSTP operates in a client-server paradigm:
* **Client (Initiator):** Establishes connections, generates the Session ID, and drives handshake initiation.
* **Server (Responder):** Accepts connections, validates access keys, and relays application-layer traffic to the open internet.

A single OSTP session (one Noise handshake, one `session_id`, one nonce sequence) carries **all** of a client's traffic. Multiplexing of individual TCP/UDP flows onto that one session is done above the transport layer, by an application-level message protocol (`RelayMessage`, §8) carried inside `Data` frames — not by opening additional cryptographic sessions. An optional `mux` mode can run several independent OSTP sessions in parallel purely to spread load/loss across more than one nonce sequence (§9.3); it is unrelated to per-flow multiplexing.

---

## 4. Outer Wire Envelope

Every OSTP datagram — handshake or data — conforms to a pre-scrambled header envelope followed by ciphered content. All multi-byte fields use network byte order (big-endian). There are two envelope shapes, selected by protocol state.

### 4.1 Data Datagram (Established Session)

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Masked Session Identifier (32 bits)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                     Masked Nonce (64 bits)                    +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
~              AEAD Ciphertext + 16-byte Poly1305 Tag           ~
|                    (Variable Length)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

* **Masked Session Identifier (32 bits):** The Session ID, part of a 12-byte header that is XOR-masked as a unit (see §5).
* **Masked Nonce (64 bits):** A monotonically increasing per-session counter used both as the ARQ sequence number and as the AEAD nonce (zero-padded into a 96-bit ChaCha20-Poly1305 nonce). It is **not** transmitted in cleartext — it is masked together with the Session ID — but it is authenticated: the plaintext 4-byte session ID is passed as AEAD Associated Data, and the nonce value itself is implicit in which AEAD key stream position was used, so any tampering fails Poly1305 verification on decrypt.
* **AEAD Ciphertext + Tag:** ChaCha20-Poly1305 output; the trailing 16 bytes are the Poly1305 authentication tag. The plaintext under this ciphertext is itself a second, inner frame — see §7.

### 4.2 Handshake Datagram

```text
[ session_id : 4 ][ noise_len : 2 ][ noise_payload : N ][ random_padding : var ]
  \_______________ masked as one 6-byte unit _______________/
```

* **session_id** (4 bytes) — a fresh random value chosen by the initiator for this session.
* **noise_len** (2 bytes) — length in bytes of the following Noise handshake message.
* **noise_payload** (N bytes) — one message of the `Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s` exchange (cleartext on the wire, but itself opaque/random-looking: an ephemeral X25519 public key plus an AEAD-encrypted, PSK-authenticated payload).
* **random_padding** — cryptographically random filler. Its length is drawn from a **key-derived range** `[handshake_pad_min, handshake_pad_max]` (§6), so different access keys produce different handshake-packet size distributions and no single size threshold works as a universal DPI filter.

---

## 5. Header Obfuscation

To keep the Session ID and Nonce statistically independent across consecutive packets — and indistinguishable from the AEAD ciphertext that follows them — OSTP masks the entire outer header as a unit, keying the mask off the packet's own payload rather than a counter:

```
Data packet:      mask[0..12] = HMAC-SHA256(obfuscation_key, ciphertext[0..min(32,len)])[0..12]
                   (session_id || nonce) ^= mask

Handshake packet:  mask[0..6]  = HMAC-SHA256(obfuscation_key, noise_payload[0..min(32,len)])[0..6]
                   (session_id || noise_len) ^= mask
```

Because the sampled payload is itself cryptographically random (AEAD ciphertext, or a Noise ephemeral key + encrypted payload), the mask is unique per packet without needing an explicit counter or IV field on the wire. Full derivation of `obfuscation_key` is specified in §6 and in [`obfuscation.md`](obfuscation.md).

---

## 6. Key Derivation and Handshake

### 6.1 Secret Derivation (Kerckhoffs's Principle)

Every protocol secret is derived from the shared `access_key` via HKDF-SHA256 (RFC 5869), with **no hardcoded strings or magic constants** anywhere in the derivation:

```
key_hash = SHA-256(access_key)
salt     = key_hash[0..16]
info_base= key_hash[16..32]
ikm      = access_key || PROTOCOL_VERSION        // version byte 5, never sent on the wire
PRK      = HKDF-Extract(salt, ikm)

obfuscation_key   = HKDF-Expand(PRK, info_base || 0x01, 8 bytes)
psk               = HKDF-Expand(PRK, info_base || 0x02, 32 bytes)
handshake_pad     = HKDF-Expand(PRK, info_base || 0x03, 2 bytes)  -> pad_min, pad_max
junk_marker(window)= HKDF-Expand(PRK, info_base || 0x04 || window_LE, 4 bytes)
```

`PROTOCOL_VERSION` is mixed into the IKM rather than sent as a plaintext byte: peers running an incompatible wire version derive an entirely different `obfuscation_key`/`psk` and simply fail to deobfuscate or decrypt each other's traffic — a hard, deterministic version gate with no observable marker. `junk_marker` additionally rotates every `JUNK_MARKER_WINDOW_SECS` (60s) of wall-clock time (§9.2), so pre-handshake filler traffic carries no static per-user signature either.

### 6.2 Handshake Exchange

OSTP executes a Noise Protocol Framework exchange using the `Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s` pattern (`psk0, e` / `e, ee`):

1. The derived `psk` (32 bytes, §6.1) is bound into the handshake at pattern position zero, authorizing and encrypting the very first datagram.
2. Ephemeral Curve25519 key exchange (`ee`) is evaluated.
3. The two directional transport keys are taken from Noise's `Split()` over the **final chaining key `ck`** — not the handshake hash `h`.

> **Forward secrecy.** `ck` absorbs the ephemeral `ee` Diffie-Hellman result; `h` only ever absorbs public transcript data (ephemeral public keys and on-wire ciphertexts) and never the DH secret. Keys derived from `h` would depend only on the PSK and public data, letting anyone who later learns the access key decrypt any recorded session. Deriving from `ck` binds each session to ephemeral private keys that are discarded once the handshake completes: a later PSK compromise does not expose past traffic. This is a wire-breaking property gated by `PROTOCOL_VERSION` (currently 5); peers on an older version derive different keys and cannot interoperate.

The initial handshake payload includes a Unix timestamp to mitigate replay attacks. The server enforces a ±300-second synchronization window and records accepted handshakes in a bounded anti-replay cache (default capacity 50,000 entries) for that window, rejecting exact retransmissions.

---

## 7. Inner Frame Layout

The plaintext recovered from the AEAD ciphertext (§4.1) is itself a framed record — this is the layer that carries stream multiplexing, control messages, and padding:

```
[ 12-byte FrameHeader ] [ payload : payload_len bytes ] [ padding : pad_len bytes ]
```

| Offset | Type | Field | Description |
|---|---|---|---|
| 0 | `u8` | `version` | Inner frame format version (currently `1`) |
| 1 | `u8` | `kind` | Frame kind (§7.1) |
| 2–3 | 2×`u8` | *(random)* | Filled with random bytes, not zero — avoids a known-plaintext pattern inside the AEAD-encrypted region |
| 4–5 | `u16 BE` | `stream_id` | Reserved for future per-stream framing; `0` for control frames (`Ack`/`Nack`/`Close`) |
| 6–9 | `u32 BE` | `payload_len` | Length of `payload` in bytes |
| 10–11 | `u16 BE` | `pad_len` | Length of the trailing random `padding` |

### 7.1 Frame Kinds

| Value | Kind | Purpose |
|---|---|---|
| 1 | `Handshake` | Unused on the wire today (handshake messages travel in the outer envelope, §4.2); reserved. |
| 2 | `Data` | Application payload — carries a `RelayMessage` (§8). |
| 3 | `Close` | Terminates the session. |
| 4 | `KeepAlive` | Keeps NAT/firewall mappings alive; carries no ARQ-visible payload. |
| 5 | `Nack` | Requests immediate retransmission of a specific missing nonce. |
| 6 | `Ack` | Cumulative + selective acknowledgment (§9.1). |

### 7.2 Adaptive Padding

Padding bytes are cryptographically random and live **inside** the AEAD-encrypted region, so a passive observer cannot distinguish padding from payload or recover the true message length. Three strategies are available: `Fixed(target)`, `Profile` (bucketed to resemble JSON-RPC / HTTPS-burst / video-stream length distributions), and the default `Adaptive` strategy, which buckets the payload to the next 64-byte boundary and adds bounded random jitter on top — smoothing recognizable application bursts into a more constant-bitrate-like stream without ever exceeding the path MTU.

---

## 8. Application Multiplexing Layer (`RelayMessage`)

Everything the client and server exchange after the handshake — proxied TCP connects, UDP associates, keepalives — is a `RelayMessage`, tag-length-value encoded and carried as the payload of `Data` frames:

| Tag | Message | Payload |
|---|---|---|
| 1 | `Connect(addr)` | Target `host:port` to open a TCP connection to |
| 2 | `Data(bytes)` | A chunk of an already-open stream's payload |
| 3 | `KeepAlive` | No payload |
| 4 | `Close` | No payload — closes the associated stream |
| 5 | `ConnectOk` | No payload — acknowledges a successful `Connect` |
| 6 | `Error(msg)` | UTF-8 error string |
| 7 | `Ping(timestamp)` | 8-byte client-chosen timestamp, echoed back for RTT measurement |
| 8 | `Pong(timestamp)` | Echo of the `Ping` timestamp |
| 9 | `UdpAssociate` | No payload — requests a UDP relay association |
| 10 | `UdpData(addr, bytes)` | Length-prefixed target address plus a UDP datagram payload |

This is the layer that lets a single OSTP session carry an arbitrary number of concurrent proxied TCP connections and UDP flows: each is identified by its own sequence of `Connect`/`Data`/`Close` (or `UdpAssociate`/`UdpData`) messages multiplexed over the one encrypted nonce sequence, with the client's local SOCKS5/HTTP proxy or TUN adapter as the demultiplexing point on the client side.

---

## 9. Transport, Reliability, and Session Management

### 9.1 Selective-Repeat ARQ

OSTP provides reliability over an inherently unreliable datagram substrate using a **Selective-Repeat ARQ** mechanism (production defaults shown; all are configurable):

* **Reorder buffer:** out-of-order frames are held in a `BTreeMap` keyed by nonce, capped at 8,192 buffered frames (`max_reorder_buffer`). A frame arriving more than 16,384 nonces (`max_reorder`) ahead of the expected sequence is rejected with an immediate `Nack` rather than buffered.
* **Acknowledgment:** **Cumulative + SACK.** The `Ack` payload always starts with the cumulative range `(0, expected_recv_nonce - 1)`, followed by up to 7 additional selective-ACK ranges describing non-contiguous blocks already sitting in the reorder buffer (8 ranges total).
* **Rate-limited NACK:** on detecting a gap, the receiver emits a `Nack` for the lowest missing nonce, but at most once every `max(10ms, current_RTO / 2)` — this fires *before* the sender's own retransmit timer, prompting a fast retransmit, while still bounding the storm under bursty loss.
* **Retransmission:** unacknowledged data frames are retransmitted after an adaptive RTO (RFC 6298 `SRTT + 4×RTTVAR`, clamped to `[50ms, 16s]`, default base 100ms) with exponential backoff up to 64× the base RTO.
* **Zombie frame eviction:** a frame that has been retried more than `max_retries + 2` times (default `max_retries` = 8, so 10 total attempts) is dropped from the sender's history — it can no longer be retransmitted, which is what makes gap recovery (§9.4) necessary on the receive side.
* **In-flight accounting:** only retransmittable `Data` frames count toward backpressure; control frames (`Ack`/`Nack`) are excluded so acknowledgment traffic can never itself throttle the session.
* **Graceful close:** the `Closing` state keeps processing inbound frames (including trailing ACKs and retransmits) instead of tearing down on the first post-`Close` packet, so in-flight data isn't lost during teardown.

### 9.2 Junk Packets and TCP Fragmentation

Before the handshake, a client may send a configurable number of random-size filler datagrams, each stamped with the time-windowed `junk_marker` from §6.1 rather than a fixed constant. The server derives the same per-key marker while trying candidate keys and silently drops matching junk before it ever reaches "unauthorized probe" logging. Over the UoT transport only, the first TCP segment (the handshake) can additionally be split into small chunks with short inter-write delays, so DPI that inspects only the first TCP segment never observes a complete handshake. See [`obfuscation.md`](obfuscation.md) for full detail; neither mechanism applies to plain UDP transport.

### 9.3 Transport Modes and Session Multiplexing

* **UDP** (default): each OSTP datagram is one UDP datagram.
* **UoT (UDP-over-TCP):** each OSTP datagram is carried inside a plain TCP byte stream, framed with a 2-byte big-endian length prefix (`u16`, sufficient since OSTP datagrams are MTU-bounded and always well under 64 KiB). No protocol mimicry is attempted — the TCP stream carries only length-prefixed opaque blobs, following the project's "no recognizable header at all" stance rather than impersonating TLS/HTTP.
* **Session-level multiplexing (`mux`):** independently of per-flow multiplexing (§8), a client may run more than one full OSTP session (`sessions > 1`) in parallel to the same server, spreading traffic — and loss — across multiple nonce sequences and congestion-control instances.

### 9.4 Gap Recovery

Because delivery is strictly gated on the next expected nonce, a single frame that the sender has given up retransmitting (§9.1, zombie eviction) would otherwise stall the receiver forever, with every later buffered frame withheld — a state indistinguishable from a healthy link `sending ACKs/NACKs into the void`. To break this deadlock, if the expected-nonce sequence makes no forward progress for `clamp(8 × current_RTO, 2s, 10s)`, the receiver skips forward to the lowest nonce it has buffered, delivers everything contiguous from there, and forces an `Ack` so the sender learns the sequence moved on. This trades one lost `RelayMessage` chunk for restoring liveness on an otherwise permanently frozen session.

### 9.5 Congestion Control

A simplified BBR-inspired controller (per-session, independent of TCP-level congestion control on any carrier transport) governs how much data may be in flight:

* **Slow start:** begins at an initial window of 32 MTU-sized packets and grows exponentially per ACKed byte. An isolated loss during slow start (a single dropped frame — Wi-Fi noise, an LTE handover blip) takes a mild window haircut (×0.8) but **stays** in slow start; only 3+ losses within a rolling 500ms window are treated as sustained congestion, which exits slow start and halves the window (`ssthresh = cwnd / 2`).
* **Probe-bandwidth phase:** additive increase (~1 MTU/RTT); loss triggers a multiplicative decrease to 70% of `cwnd` (gentler than TCP Cubic's 50%).
* **RTT/RTO estimation:** RFC 6298 `SRTT`/`RTTVAR`, clamped `RTO ∈ [50ms, 16s]`. RTT samples are taken only from frames that were never retransmitted (Karn's algorithm), so a retransmit never spuriously drags the estimate down.
* **Retransmit budget:** each tick may resend up to `max(2, cwnd_packets / 4)` frames, capped at 64, keeping retransmission bandwidth-aware rather than a flat per-tick constant.

### 9.6 Roaming and Session Migration

The server treats `session_id`, not the source `IP:port`, as the durable session identity. A session moves to a new address with no new handshake, but only on a datagram that (1) passed AEAD authentication and (2) carries a nonce higher than any the session has accepted — the same rule as QUIC (RFC 9000 §9.3). A captured datagram replayed from another address, including a frame still waiting in the reorder buffer, is processed but does not move the session, and replies go to its current address. Looking a session up for an unfamiliar address is gated behind its own token bucket (50-token burst, refilled at 50 tokens/sec); traffic from a session's current address is not subject to it.

For UoT the address is that of the TCP connection, so a new TCP connection is a new address just like a new UDP port.

The client moves the session to a new connection of the same transport:

1. **When:** on a network change (`NetworkChanged`), after 10s without an authenticated datagram from the server, when every UoT TCP connection was closed or reset, and after resume from sleep.
2. **How:** it opens a new connection over the same transport, swaps the socket under the session and resets the path estimates (RTT, congestion window); keys, nonces, streams and the reorder buffer stay. Every unacknowledged frame is retransmitted at once. A packet with a fresh nonce (`Ping`) goes first so the server moves the session's address.
3. **Confirmation:** the move succeeds when an authenticated datagram arrives over the new path within `max(4s, 4×RTT)`. Otherwise the client logs that the server did not answer and does not try another move for 30s.
4. **No automation beyond that:** the transport never changes on its own, and a failed move starts neither a reconnect nor a new handshake. The transport is the user's choice. The server deliberately stays silent to packets of an unknown session (an explicit "unknown session" answer would let any scanner confirm it is talking to an OSTP server), so "session expired" and "transport blocked" look the same to the client.

### 9.7 Session Keepalive and Recovery

* **Client-side:** `Ping`/`Pong` `RelayMessage`s (§8) are exchanged every `keepalive_interval_sec` (default 5s) for RTT measurement. Only a datagram that passed AEAD counts as a sign of life: a duplicate or garbage with a plausible header does not reset the silence timer. After 10s of silence the client moves the session to a new path (§9.6); after 25s it begins a background reconnect attempt; after 180s of total silence it treats the session as permanently lost and stops the tunnel — unless the kill switch is enabled, in which case it retries indefinitely rather than falling open.
* **Server-side:** sessions with no valid inbound datagram for 600 seconds are evicted from the dispatcher's session table.

---

## 10. Security Considerations

* **Nonce Exhaustion:** the nonce field is 64 bits. Implementations MUST terminate and re-key a session before it overflows, to prevent AEAD keystream reuse.
* **Session Exhaustion (DoS):** the server enforces a hard cap on concurrent sessions (default 1024) and silently drops handshake attempts beyond it, bounding memory exhaustion attacks.
* **Handshake-trial CPU DoS:** because there is no cleartext key identifier on the wire (a deliberate stealth property), a datagram from an unrecognized source must be trial-processed against every registered key. The server caches each key's derived secrets and time-windowed junk markers (so a trial is a cheap comparison plus at most one AEAD attempt per key, not a fresh HKDF/HMAC per attempt) and gates the whole trial path behind a global token bucket (100 trials/sec by default). The established-session fast path and the IP-roaming path (§9.6) are not subject to this bucket.
* **Header Authentication:** header obfuscation provides privacy, not integrity on its own — but header tampering is still detected, because the 12-byte outer header (session ID + nonce) is authenticated as AEAD Additional Authenticated Data, so any bit-flip fails Poly1305 verification on decrypt even though the header carries no dedicated MAC of its own.
* **Replay Cache Bound:** the handshake anti-replay cache is capped (default 50,000 entries) and windowed to the ±300s handshake-timestamp tolerance, so it cannot be grown without bound by an attacker replaying old handshakes.
