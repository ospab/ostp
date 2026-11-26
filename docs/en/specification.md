# Ospab Stealth Transport Protocol (OSTP) Specification

**Version:** 1.2 (November 2026)
**Wire protocol versions:** 6 (0.5.0; a profile that carries the server's public key) and 5 (0.4.x; `PROTOCOL_VERSION`). The version is not sent in cleartext; it follows from the key derivation and the handshake shape (see §6). A server in the transitional mode (`accept_v5`) speaks both.
**Authors:** Georgiy S., Ospab Foundation
**Status:** Stable, Informational. The text describes the code of `ostp-core` as of 0.5.0 (`crypto/`, `framing/`, `protocol.rs`, `relay.rs`, `streams.rs`, `congestion.rs`, `pmtu.rs`, `stall.rs`); where v5 and v6 differ it says so.

---

## 1. Introduction

The **Ospab Stealth Transport Protocol (OSTP)** is a multiplexed, encrypted transport for networks with lossy links and deep packet inspection (DPI).

OpenVPN and WireGuard are identified by DPI through static magic bytes, fixed handshake sizes and predictable sequences. OSTP masks each packet with a key derived from the shared secret and randomizes frame boundaries, so datagrams look like random data and the wire carries no plaintext version marker or magic byte.

OSTP is the transport protocol; what lies under it is the *carrier*. OSTP is carrier-agnostic at the datagram level: the same masked/encrypted datagram is carried either directly over UDP, or — for networks that block or throttle unrecognized UDP — inside a plain TCP byte stream (**UoT**, "UDP-over-TCP"; see §9). Neither carrier adds any protocol-identifying header of its own.

---

## 2. Cryptographic Primitives

OSTP is built strictly upon standardized, modern cryptographic primitives:

| Component | Primitive / Standard | Purpose |
|---|---|---|
| **Handshake** | Noise Protocol Framework: `Noise_NKpsk0` (v6), `Noise_NNpsk0` (v5) | Authentication and forward-secret key exchange. In v6 the client also authenticates the server. |
| **Key Agreement** | X25519 (RFC 7748) | Ephemeral Elliptic Curve Diffie-Hellman; in v6 also the server's static key. |
| **Symmetric Encryption** | ChaCha20-Poly1305 (RFC 8439) | Authenticated Encryption with Associated Data (AEAD) for all payload data. |
| **Hashing** | BLAKE2s (RFC 7693) | Noise internal state hashing and mixing. |
| **Key Derivation** | HKDF-SHA256 (RFC 5869) | Derives every protocol secret from the shared access key (§6). |
| **Obfuscation Masking** | HMAC-SHA-256 (RFC 2104) | Per-packet header scrambling (v5 handshake, data datagrams of both versions). |
| **Handshake masking (v6)** | ChaCha20 keystream, HMAC-SHA-256 tag | Hides the whole v6 handshake datagram behind a random nonce (§4.3). |

---

## 3. Protocol Architecture

OSTP operates in a client-server paradigm:
* **Client (Initiator):** Establishes connections, generates the Session ID, and drives handshake initiation.
* **Server (Responder):** Accepts connections, validates access keys, and relays application-layer traffic to the open internet.

A single OSTP session (one Noise handshake, one `session_id`, one nonce sequence) carries **all** of a client's traffic. Multiplexing of individual TCP/UDP flows onto that one session is done above the transport layer, by an application-level message protocol (`RelayMessage`, §8) carried inside `Data` frames — not by opening additional cryptographic sessions. An optional `mux` mode can run several independent OSTP sessions in parallel purely to spread load/loss across more than one nonce sequence (§9.3); it is unrelated to per-flow multiplexing.

---

## 4. Outer Wire Envelope

Every OSTP datagram — handshake or data — conforms to a pre-scrambled header envelope followed by ciphered content. All multi-byte fields use network byte order (big-endian). There are two envelope shapes, selected by protocol state.

### 4.1 Data Datagram (Established Session, v5 and v6)

The data datagram is the same in both versions; only the plaintext inside the AEAD differs (§7).

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

* **Masked Session Identifier (32 bits):** the Session ID, part of a 12-byte header that is XOR-masked as a unit (see §5).
* **Masked Nonce (64 bits):** a per-session counter, one for every datagram the sender builds (data and control alike), starting at 0 and never reused. It is the sequence number of the datagram for acknowledgement and loss recovery, and the AEAD nonce (big-endian, in the low 8 bytes of the 96-bit ChaCha20-Poly1305 nonce, the rest zero). It is not sent in cleartext. It is authenticated implicitly: decryption with a wrong nonce fails the tag. The Associated Data is the 4-byte session ID.
* **AEAD Ciphertext + Tag:** ChaCha20-Poly1305 output; the last 16 bytes are the tag. The plaintext is an inner frame (§7).

Each direction has its own key (the two outputs of Noise's `Split()`, §6.3) and its own nonce counter. A datagram that does not authenticate is dropped without an answer.

### 4.2 Handshake Datagram, v5

```text
[ session_id : 4 ][ noise_len : 2 ][ noise_payload : N ][ random_padding : var ]
  \_______________ masked as one 6-byte unit _______________/
```

* **session_id** (4 bytes): a fresh random value chosen by the initiator.
* **noise_len** (2 bytes): length of the Noise message that follows.
* **noise_payload** (N bytes): one message of the `Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s` exchange, in cleartext on the wire (an ephemeral X25519 key and an AEAD-encrypted, PSK-authenticated payload). The ephemeral key is a curve point with the top bit zero, at a fixed offset.
* **random_padding:** random filler of a length drawn from a key-derived range `[handshake_pad_min, handshake_pad_max]` (§6), so different access keys give different handshake sizes.

The client resends this datagram byte for byte when the reply is late.

### 4.3 Handshake Datagram, v6

```text
[ nonce : 12 ][ tag : 4 ][ ChaCha20(mask key, nonce) XOR body ]
body = [ session_id : 4 ][ noise_len : 2 ][ noise message : N ][ random_padding ]
```

* **nonce:** 12 random bytes, new for every datagram sent.
* **tag:** the first 4 bytes of `HMAC-SHA256(tag_key, direction || nonce)`. `direction` is 0x00 for client to server and 0x01 for server to client, so a datagram sent back to its sender is not taken for the peer's. The tag lets a server with many keys find the right one with one HMAC per key, not one curve operation per key. It proves nothing by itself (a captured datagram carries its tag when replayed); the Noise message behind it authenticates. It is compared in constant time.
* **body:** masked with a ChaCha20 keystream (key: `HMAC-SHA256(mask_key, direction)`, nonce: the datagram's). Nothing of the Noise message is visible, so the ephemeral key leaves no fixed bits. `mask_key` and `tag_key` come from the access key (§6.2).
* **random_padding:** as in v5, a key-derived range. The padding is not authenticated.
* **Resend:** the client does not send the same bytes twice: the Noise message is the same, but it is sealed anew with a new nonce and new padding, so repeated datagrams share nothing on the wire.
* **Server reply:** the same shape with direction 0x01. A server that has already answered a handshake finds it by the session ID and a SHA-256 of the Noise message (not by the whole datagram, because the padding may differ) and sends the same reply again, without creating a second session.

---

## 5. Header Obfuscation

To keep the Session ID and Nonce statistically independent across consecutive data datagrams, and indistinguishable from the ciphertext that follows, OSTP masks the 12-byte outer header as a unit and keys the mask off the packet's own ciphertext:

```
Data datagram (v5 and v6):  mask[0..12] = HMAC-SHA256(obfuscation_key, ciphertext[0..min(32,len)])[0..12]
                            (session_id || nonce) ^= mask

v5 handshake:               mask[0..6]  = HMAC-SHA256(obfuscation_key, noise_payload[0..min(32,len)])[0..6]
                            (session_id || noise_len) ^= mask
```

The sampled bytes are cryptographically random (AEAD ciphertext, or a Noise ephemeral key and encrypted payload), so the mask is different for every packet and no counter or IV is on the wire. The v6 handshake does not use this: it has its own masking (§4.3). Derivation of `obfuscation_key`: §6 and [`obfuscation.md`](obfuscation.md).

---

## 6. Key Derivation and Handshake

### 6.1 Secret Derivation, v5 (Kerckhoffs's Principle)

Every protocol secret is derived from the shared `access_key` via HKDF-SHA256 (RFC 5869). The access key is the only secret input; everything else here, the version byte included, is public (see [Kerckhoffs's principle](obfuscation.md#kerckhoffss-principle-what-is-public-and-what-is-secret)):

```
key_hash = SHA-256(access_key)
salt     = key_hash[0..16]
info_base= key_hash[16..32]
ikm      = access_key || PROTOCOL_VERSION        // version byte 5, never sent on the wire
PRK      = HKDF-Extract(salt, ikm)

obfuscation_key   = HKDF-Expand(PRK, info_base || 0x01, 8 bytes)
psk               = HKDF-Expand(PRK, info_base || 0x02, 32 bytes)
handshake_pad     = HKDF-Expand(PRK, info_base || 0x03, 2 bytes)  -> pad_min = 16 + b0 mod 64, pad_max = pad_min + 48 + b1 mod 128
junk_marker(window)= HKDF-Expand(PRK, info_base || 0x04 || window_LE, 4 bytes)
```

`PROTOCOL_VERSION` is mixed into the IKM rather than sent as a plaintext byte: peers on another wire version derive another `obfuscation_key` and `psk` and cannot read each other. `junk_marker` rotates every `JUNK_MARKER_WINDOW_SECS` (60 s) of wall-clock time (§9.2). The junk marker exists only in the v5 derivation.

### 6.2 Secret Derivation, v6

```
PRK = HKDF-Extract(salt = "ostp v6", ikm = access_key)

obfuscation_key = HKDF-Expand(PRK, "ostp v6 obfuscation", 8 bytes)
psk             = HKDF-Expand(PRK, "ostp v6 psk", 32 bytes)
handshake_pad   = HKDF-Expand(PRK, "ostp v6 handshake padding", 2 bytes)   (same mapping to pad_min, pad_max as v5)
mask_key        = HKDF-Expand(PRK, "ostp v6 handshake mask", 32 bytes)
tag_key         = HKDF-Expand(PRK, "ostp v6 handshake tag", 32 bytes)
```

The labels are public; the access key is the only secret. The version byte is not part of the input: v5 and v6 are told apart by the handshake shape (§4.2, §4.3) and by the keys, so a v6 peer cannot read a v5 peer and the reverse. (`PROTOCOL_VERSION_V6 = 6` is a name for the version; it is not mixed in.)

### 6.3 Handshake Exchange

**v5:** `Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s` (`psk0, e` / `e, ee`). Anyone who holds an access key can answer as the server.

**v6:** `Noise_NKpsk0_25519_ChaChaPoly_BLAKE2s` with the prologue `ostp v6`:

```
<- s                         (known in advance: the server's static public key)
-> psk, e, es                (first message, encrypted to the server's static key)
<- e, ee
```

The client knows the server's static X25519 public key from its profile (`pk=` in an `ostp://` link, `server_pk` in the client config). Only the holder of the private key can read the first message and answer it, so the client authenticates the server; the PSK (§6.2) authorizes the client. The client has no static key. A profile without `pk` is a v5 profile; a profile with it is a v6 profile and never falls back to v5. A client given a key that does not match gets no readable answer and reports that the server did not answer in the expected way.

The transport keys come from Noise's `Split()` over the **final chaining key `ck`**, not the handshake hash `h`. The first Split output is initiator to responder, the second the reverse.

> **Forward secrecy.** `ck` absorbs the ephemeral `ee` Diffie-Hellman result; `h` only absorbs public transcript data. Keys from `h` would depend only on the PSK and public data, so anyone who later learns the access key could decrypt recorded sessions. Keys from `ck` are bound to ephemeral private keys that are discarded after the handshake. This is the change that made version 5.

**Handshake payload.** The client's first message carries `timestamp(8) | session_id(4) | access_key`, big-endian, the timestamp in Unix seconds. The server finds the key that opens the message, requires the access key in the payload and the session ID to match the ones outside it, and enforces a ±300-second window on the timestamp. Accepted payloads go into an anti-replay cache (capacity 50,000; entries past the window are dropped first, then the oldest). A replay is rejected. In v6 a repeated first message (a resend after a lost reply) is answered from the reply cache instead (§4.3).

**Server side of the versions.** A server with a static key tries v6 first for every key (a tag check), then, if `accept_v5` is on, v5. A server without a static key speaks v5 only. `accept_v5` is on in a new install and is switched with `ostp key legacy on|off`.

**Session ID.** Chosen by the client. A new handshake with the ID of a live session of another key is refused; with the ID of a session of the same key it replaces that session (a reconnect).

---

## 7. Inner Frame Layout

The plaintext recovered from the AEAD ciphertext (§4.1) is a frame:

```
[ FrameHeader ] [ payload : payload_len bytes ] [ padding : pad_len bytes ]
```

A session is v5 or v6 as a whole, by its handshake. All integers are big-endian.

**v5 header, 12 bytes:**

| Offset | Type | Field | Description |
|---|---|---|---|
| 0 | `u8` | `version` | `1` |
| 1 | `u8` | `kind` | Frame kind (§7.1) |
| 2–3 | 2×`u8` | *(random)* | Random bytes, not zero, so the encrypted region has no constant bytes |
| 4–5 | `u16` | `stream_id` | `0` for control frames |
| 6–9 | `u32` | `payload_len` | Length of `payload` |
| 10–11 | `u16` | `pad_len` | Length of the random `padding` |

**v6 header, 16 bytes:**

| Offset | Type | Field | Description |
|---|---|---|---|
| 0 | `u8` | `version` | `2` |
| 1 | `u8` | `kind` | Frame kind (§7.1) |
| 2–3 | 2×`u8` | *(random)* | As in v5 |
| 4–7 | `u32` | `stream_id` | Stream of the frame; `0` for control frames (§8.2) |
| 8–11 | `u32` | `stream_seq` | Number of the frame in its stream, from 0, for sequenced frames (`Data`); `0` for every other kind. `2^32-1` is never used |
| 12–13 | `u16` | `payload_len` | Length of `payload`; a frame never exceeds the path MTU |
| 14–15 | `u16` | `pad_len` | Length of the random `padding` |

A datagram carries 40 bytes around its payload and padding in v5 (4 session ID, 8 nonce, 12 header, 16 tag) and 44 in v6. A v6 sender refuses a payload that does not fit the datagram size instead of cutting or fragmenting it.

### 7.1 Frame Kinds

| Value | Kind | Retransmitted | Payload |
|---|---|---|---|
| 1 | `Handshake` | | Unused on the wire (handshake messages travel in the outer envelope, §4.2, §4.3); reserved. |
| 2 | `Data` | yes | A `RelayMessage` (§8). In v6 ordered per stream by `stream_seq`. |
| 3 | `Close` | yes, until acknowledged | v5: empty. v6: `reason(1) text(0..=64, UTF-8)`; an empty payload is reason 0. |
| 4 | `KeepAlive` | no | Empty. A peer acknowledges it and delivers nothing. In v6 it is also the padded path MTU probe (§9.8), counted in flight. |
| 5 | `Nack` | no, not counted in flight | `nonce(8)`: the lowest missing nonce. |
| 6 | `Ack` | no, not counted in flight | `count(1)` followed by `count` ranges of `start(8) end(8)`: the nonces received. See §9.1. |
| 7 | `Datagram` (v6) | no, counted in flight | An unsequenced `RelayMessage` (UDP data). |
| 8 | `Abandon` (v6) | only with a reason | `stream_id(4) reason(1) count(1)` and `count` ranges of `start(8) end(8)`: nonces that will never be sent. See §9.4. |

Every frame, control frames included, takes the next nonce. A v5 session treats kinds 7 and 8 as unknown, as a 0.4.x peer does.

**Unknown frames.** In a v6 session a frame that authenticates but cannot be read (a kind this version does not know, a malformed header or payload) is recorded, acknowledged and ignored: refusing it would leave a hole at its nonce that the sender resends into for minutes. A `Close` whose reason is unknown reads as reason 0, a `Close` text over 64 bytes is cut, and an `Abandon` stream-reset reason it does not know reads as `lost`. In a v5 session an unreadable frame is an error and is not acknowledged.

### 7.2 Adaptive Padding

Padding bytes are random and live inside the AEAD-encrypted region, so a passive observer cannot tell padding from payload or recover the true message length. Three strategies: `Fixed(target)`, `Profile` (bucketed to resemble JSON-RPC, HTTPS-burst or video-stream lengths), and the default `Adaptive`, which rounds the payload up to the next 64-byte boundary and adds random jitter (up to 256 bytes, within the configured maximum). The result never exceeds the datagram size.

---

## 8. Application Multiplexing Layer (`RelayMessage`)

Everything the client and server exchange after the handshake is a `RelayMessage`, carried as the payload of `Data` frames (or `Datagram` frames, in v6, for UDP). A message is a tag byte; most have a 2-byte big-endian length and then that many bytes of payload.

| Tag | Message | Payload |
|---|---|---|
| 1 | `Connect(addr)` | Target `host:port` (UTF-8) to open a TCP connection to |
| 2 | `Data(bytes)` | A chunk of an already-open stream's payload |
| 3 | `KeepAlive` | No payload |
| 4 | `Close` / `Abort(reason)` | v5: the single byte `[4]`, closes the stream. v6: `[4, reason]` is an abort (reason 0 closed abruptly, 1 I/O error, 2 flow control broken); `[4]` alone still reads as `Close` |
| 5 | `ConnectOk` | No payload; acknowledges a successful `Connect` |
| 6 | `Error(msg)` | UTF-8 error string |
| 7 | `Ping(timestamp)` | 8-byte client-chosen timestamp, echoed back for RTT measurement |
| 8 | `Pong(timestamp)` | Echo of the `Ping` timestamp |
| 9 | `UdpAssociate` | No payload; requests a UDP relay association |
| 10 | `UdpData(addr, bytes)` | `addr_len(2) addr data_len(2) data`: a target address and a UDP datagram |
| 11 | `Features(bits)` | 4-byte bit set; stream 0, once per session |
| 12 | `Window(bytes)` | 4-byte byte count; flow-control grant for the stream |
| 13 | `Fin` | No payload (v6): "I will write no more on this stream" |
| 14 | `InfoRequest` | No payload; stream 0, client to server (§8.3) |
| 15 | `ServerInfo(more, bytes)` | 1 flag byte (bit 0: more pieces follow), 2-byte length, a piece of the server-info JSON; stream 0, server to client |

`Features` bits: 1 (`FEATURE_FLOW_CONTROL`) per-stream flow control (v5 only; in v6 it is always on); 2 (`FEATURE_SERVER_INFO`) the server answers `InfoRequest`. A message that cannot be decoded (an unknown tag, a short payload) is dropped; a 0.4.5 peer drops tags it does not know.

### 8.1 Per-stream flow control

Without it, a stream's sender is held back only by the session's congestion window, so a slow destination (a site that takes an upload at 1 MB/s, a program that reads a download slowly) makes the other side buffer what it cannot pass on. Flow control bounds that per stream.

- After the handshake the client sends `Features(1)` (bit 0: flow control) on stream 0. A server that supports it answers `Features(1)` and marks the session; a 0.4.5 server does not know tag 11, drops that message and carries on, so both sides keep the old behaviour.
- For each stream opened after that, the server sends `Window(8 MiB)` right after `ConnectOk`. It is the client's allowance for that stream's upload, and it also tells the client that the stream uses flow control: the client never switches a stream on its own, so both ends agree even if `Features` and the first `Connect` cross.
- On such a stream each direction starts with 8 MiB. The sender stops reading from its source (the program on the client, the target on the server) when the allowance is used up. The receiver sends `Window(n)` each time `n` >= 1 MiB has reached the destination (written to the target, or to the program).
- The server still resets a stream that has more than 32 MiB waiting for its target, which a sender that respects the window never reaches.

One stream's throughput is bounded by 8 MiB per round trip, about 670 Mbit/s at 100 ms.

This is the layer that lets a single OSTP session carry an arbitrary number of concurrent proxied TCP connections and UDP flows: each is identified by its own sequence of `Connect`/`Data`/`Close` (or `UdpAssociate`/`UdpData`) messages multiplexed over the one encrypted nonce sequence, with the client's local SOCKS5/HTTP proxy or TUN adapter as the demultiplexing point on the client side.

### 8.2 Protocol v6

A v6 session (see [v6-session-design.md](v6-session-design.md)) changes the following in this layer; a v5 session and the text above stay as they are.

- **Stream ids** are 32 bits (frame header v2). The client opens odd ids, the server even ones, an id is never reused in a session, and at most 1024 streams are open at a time. A stream is opened by its first message (`Connect` or `UdpAssociate`); the server answers an id it refuses (reused, wrong parity, limit) with `Error`.
- **`Fin` (tag 13, no payload)** says "I will write no more" on the stream; the other direction keeps flowing. It rides in sequenced `Data`, so it arrives after every byte before it. The stream is over, and both sides release its state, when both have sent `Fin`. A program's end of stream (TCP FIN) is a `Fin`; the receiver passes it on as the end of the write side of its socket.
- **`Close` (tag 4)** is the abort. In v6 it carries one reason byte (`[4, reason]`: 0 closed abruptly, 1 I/O error, 2 flow control broken); the receiver resets the connection it feeds (TCP RST) and releases the stream. `Error` ends a stream too. A v5 `Close` stays the single byte `[4]`.
- **A reset stream** (the sender gave up on a frame of it, or the peer said so with `Abandon`) is treated like an abort: the program's connection is reset, the server closes the target. A reset of stream 0 ends the session.
- **The session `Close` (frame kind 3, stream 0)** carries `reason(1) text(0..=64, UTF-8)` in v6 (an empty payload is reason 0; a v5 `Close` has no payload). Reasons: 0 normal stop by the peer, 1 the server is restarting, 2 the key was revoked or removed, 3 the traffic limit is used up, 4 too many sessions for the key, 5 the server is shutting down, 6 the key has expired. A peer that does not know a reason reads it as 0. It is a tracked frame, resent until acknowledged and acted on when it arrives; only a session that passed authentication ever gets one. A client that receives it stops and does not reconnect by itself. See [v6-session-design.md](v6-session-design.md).
- **Flow control is part of every stream.** There is no `Features` exchange for it and no first `Window`: each direction of each stream starts with `INITIAL_STREAM_WINDOW` (8 MiB) and `Window(n)` only adds to it. A sender that goes past the allowance by more than a window (16 MiB waiting at the server) has its stream aborted; the server's 32 MiB reset of v5 does not apply.
- **UDP** is `UdpData` carried in an unsequenced `Datagram` frame (kind 7) on the stream opened by `UdpAssociate`: not ordered, not retransmitted, counted against the congestion window.

### 8.3 Server info (v5 and v6)

A server tells a client that holds a key about itself, only inside the established session; nothing of it is reachable before a session authenticates, so a prober learns nothing more.

- The client sends `Features` on stream 0 after the handshake, in v6 too: bit 1 (`FEATURE_SERVER_INFO`) in v6, bits 0 and 1 in v5. A server that supports it answers with the bits both support, bit 1 included. A server from before it answers without bit 1 (an alpha.6 server answers `Features(0)` in v6; a 0.4.5 server only ever echoes bit 0), and the client then never sends `InfoRequest`.
- The client sends `InfoRequest` once after each setup of its sessions, on the first session whose server set bit 1, and again when the app asks. The server answers at most once per 10 seconds per session; other requests are dropped.
- The answer is a JSON object split into `ServerInfo` pieces that each fit one datagram; stream 0 keeps them in order and the last one has bit 0 of its flag clear. A client keeps at most 32 KiB and drops a document that is larger or not a JSON object:

```
{
  "operator": { "name": "...", "location": "...", "contact": "...", "about": "Markdown..." },
  "server": { "version": "0.5.0-alpha.7", "carriers": ["udp", "tls"], "log_privacy": "normal", "ipv6": true, "dns_filtering": false },
  "key": { "used_bytes": 123, "limit_bytes": 1000, "expires_at": 1767225599, "max_devices": 3 }
}
```

`operator` and each key in it appear only when the operator set them (`server_info` in the server config). `carriers` is what the server offers (`udp`, plus `tls` when TLS is configured); `ipv6` whether the server can reach IPv6 destinations; `dns_filtering` whether its DNS filter is on; `log_privacy` the active log mode. `key` is the asking key's traffic (both directions), traffic limit, expiry (Unix seconds, UTC) and device limit; `null` means none.

---

## 9. Transport, Reliability, and Session Management

### 9.1 Selective-Repeat ARQ

OSTP provides reliability over a datagram substrate with a **Selective-Repeat ARQ** at the level of the nonce (defaults shown; in v6 only the delivery order moves to the stream, see §9.4 and §8.2):

* **Reorder buffer:** out-of-order nonces wait in a set of at most 8,192 entries (`max_reorder_buffer`, never above the congestion window ceiling). A datagram more than 16,384 nonces (`max_reorder`) ahead of the expected one is answered with a `Nack` (after it authenticates) and not kept. A datagram below the expected nonce is a duplicate and is answered with an `Ack`. Both answers are sent at most once per 10 ms, and only for datagrams that authenticate, so a replayed capture cannot make the receiver answer every packet.
* **Acknowledgment:** `Ack` carries `count(1)` and `count` ranges `start(8) end(8)`. The first range is the cumulative one, `(0, expected_recv_nonce - 1)`; the rest are selective ranges of nonces held in the reorder buffer. At most 8 ranges are sent (the cumulative one and the last 7 selective ones). An `Ack` is sent at least 5 ms after the previous one, and at once for a duplicate or a `Close`.
* **Reordering before loss:** a gap is not a loss at once. The receiver waits `SRTT/4` (within 5 to 100 ms; the window is multiplied, up to 16 times, each time a frame it NACKed turns out to be only late, and halves after 10 s without one; RFC 8985) and then sends a `Nack` for the lowest missing nonce, at most once per `max(10 ms, RTO/2)`. A gap that is still open with no new frame to prompt a NACK is NACKed again by the timer, with a growing pause (RTO×2, ×4, … up to 2 s).
* **Retransmission:** an unacknowledged frame is resent when `base_rto × 2^retries` has passed since its last send (`retries` capped at 6). `base_rto` is the larger of the adaptive RTO (RFC 6298, `SRTT + 4×RTTVAR`, clamped to [50 ms, 16 s]) and the configured 100 ms. The wait never exceeds `max(4×SRTT, 1 s)` (never less than `base_rto`, never over 8 s): a v5 session delivers nothing behind a lost frame, and long backoff only prolonged that. A NACK resends the frame at once. Besides the timer there is a stall detector (§9.9).
* **Timer loss is a congestion signal (UDP):** a frame resent because its timer ran out, not because the path changed, is a loss no NACK reported, and the congestion controller hears about it (RFC 5681 §3.1, RFC 9002 §7.8): one loss event per tick at most, and the window shrinks at most once per round trip. On a reliable carrier this does not apply (below).
* **Giving up:** a frame is given up only after more than `max_retries + 2` sends (`max_retries` 8) **and** 300 seconds since it was first sent. The count alone gave up inside an outage the session was about to survive. In v5 the frame is dropped from the history; in v6 the stream of a `Data` frame is reset (§9.4).
* **In-flight accounting:** only retransmittable frames count toward the window; `Ack` and `Nack` never do, so acknowledgment traffic cannot throttle the session.
* **RTT samples:** only from frames that were never retransmitted (Karn). An ACK of a control frame is never a sample.
* **Outage:** an authenticated datagram arriving after 3 s of silence while data is in flight on a datagram carrier is treated as a path change (§9.6): estimates reset, everything unacknowledged is resent at once.
* **Reliable carrier (UoT, TLS):** nothing is lost on the way, and a timer that times the queue in front of the TCP socket only duplicates (TCP over TCP). So the timer resends a frame only after 5 s, or after the session moved to another connection; a NACK still resends. The congestion controller gets no loss from timers and its delay signal (§9.5) is off. Resends are held to the room in the carrier's send queue, like new data.
* **Graceful close:** after sending `Close` a side stays in `Closing` and keeps processing inbound frames. It is `Closed` when the `Close` is acknowledged or its retries run out.

### 9.2 Marked Junk (v5)

Any datagram (UDP) or UoT frame that starts with the time-windowed `junk_marker` of §6.1 for one of the server's keys, in the current or the previous window, is junk: the server drops it silently while trying candidate keys, before "unauthorized probe" logging. Clients send it as TTL-desync decoys over UDP (see [`obfuscation.md`](obfuscation.md)); clients before 0.4.7 could also send it as filler ahead of a UoT handshake, which current clients no longer do. The marker comes from the v5 derivation only. A v6-only server does not know it and drops such datagrams as unknown ones; a transitional server (`accept_v5`) recognises it.

### 9.3 Carriers and Session Multiplexing

* **UDP** (default): each OSTP datagram is one UDP datagram.
* **UoT (UDP-over-TCP) and TLS:** each OSTP datagram is carried in a TCP byte stream (TLS 1.3 when configured, optionally after an HTTP upgrade), framed with a 2-byte big-endian length prefix. No protocol mimicry beyond that. These are the **reliable carriers**; their differences are in §9.1 (timer), §9.5 (no delay signal), §9.8 (no MTU discovery) and §9.9 (stall only logged). On the server, TCP and TLS connections keep little unsent data in the kernel (`TCP_NOTSENT_LOWAT`, Linux) and ask for BBR congestion control when the kernel has it; the sender of a connection fills its queue only to about 100 ms of the rate it drains, so the in-tunnel round trip is not the length of a deep queue.
* **Server send admission:** the server's tasks that read from targets claim frames from a per-session budget that the packet loop sets from the congestion window and the pacing rate, minus the frames still queued toward the loop. Reading from a target stops when the budget is empty, which is what lets flow control (§8.1) hold the target.
* **Session-level multiplexing (`mux`):** a client may run more than one full OSTP session (`sessions > 1`) in parallel to the same server, spreading traffic and loss across several nonce sequences and congestion controllers. Each session has its own stream id space.

### 9.4 Gap Recovery

**v5.** Delivery is gated on the next expected nonce, so a frame the sender gave up on (§9.1) would stall the receiver forever. If the expected nonce makes no progress for `max(sender_gives_up_after, 2 s)` (the sender's own retransmit schedule, at least 300 s), the receiver skips to the lowest nonce it holds, delivers what is contiguous from there and forces an `Ack`. This costs one `RelayMessage` chunk, which for a TCP stream is a hole in the middle of the bytes.

**v6.** The receiver never skips on its own. Loss recovery stays at the nonce level (ACK, NACK, SACK, timer); delivery order is per stream (`stream_seq`), so a hole in stream A does not hold stream B. A hole is closed by the sender, with `Abandon`:

* The sender gives up on a `Data` frame (§9.1): it drops every frame of that stream from its history and sends `Abandon` with reason 1 (`lost`) and the nonces of all of them, resent until acknowledged. The receiver counts those nonces as received, drops the stream's buffers and marks the stream dead; later frames of it are acknowledged and dropped. Both ends tell their program the stream was reset (the connection is reset, not left with a hole). Other streams are untouched. A reset of stream 0 ends the session.
* An `Abandon` with reason 0 only closes holes and is not resent. The sender sends it for lost `Datagram` frames and path MTU probes, and in answer to a NACK for a nonce it no longer has (at most one per 10 ms). A lost one is asked for again by the receiver's repeated NACK. A datagram that nothing acknowledged within 4 RTOs (at most 8 s) is lost: it leaves the window and, on a datagram carrier, counts as a loss. A sender puts at most 32 ranges in one `Abandon`; a receiver takes at most 16,384 nonces from one.
* A `Data` frame ahead of its stream's `expected_seq` waits in the stream's buffer (at most the stream window, 8 MiB, and the session's reorder limit); with no room it is dropped unacknowledged and sent again. A receiver tracks at most 2,048 streams; ids of dead streams are remembered (the lowest forgotten past 8,192).

### 9.5 Congestion Control

A per-session controller, independent of TCP congestion control on any carrier, limits the data in flight:

* **Slow start:** starts at 32 packets (MTU-sized) and grows per ACKed byte. One isolated loss cuts the window by 20% and stays in slow start. Slow start ends on 3 or more losses within a rolling 500 ms, or when the smoothed RTT reaches twice the minimum RTT.
* **Congestion avoidance:** CUBIC (RFC 9438, scaling constant 0.4). A loss while the smoothed RTT is under 1.25 times the path floor (no queue behind it: radio, a lossy hop) cuts the window to 0.85; any other loss to 0.7. Losses within one smoothed RTT are one event.
* **Delay signal (datagram carriers only):** a smoothed RTT of four times the floor (the floor taken as at least 20 ms) is a standing queue and the window is reduced to drain it. It is off on a reliable carrier, where TCP underneath fills a deep buffer anyway and backing off only gave it less to send.
* **Pacing and ceiling:** sending is paced at `cwnd / min_rtt` with a burst allowance of about 10 ms; the window is at least 2 packets and at most 8,192.
* **RTT/RTO estimation:** RFC 6298 `SRTT`/`RTTVAR`, `RTO` clamped to [50 ms, 16 s]; samples as in §9.1.
* **Retransmit budget:** each 10 ms tick may resend up to `max(2, cwnd_packets / 4)` frames, at most 512, and on a reliable carrier no more than the room in the send queue.
* **Path change:** the estimates and the window start over (§9.6); bytes in flight stay accounted.

### 9.6 Roaming and Session Migration

The server treats `session_id`, not the source `IP:port`, as the durable session identity. A session moves to a new address with no new handshake, but only on a datagram that (1) passed AEAD authentication and (2) carries a nonce higher than any the session has accepted — the same rule as QUIC (RFC 9000 §9.3). A captured datagram replayed from another address, including a frame still waiting in the reorder buffer, is processed but does not move the session, and replies go to its current address. Looking a session up for an unfamiliar address is gated behind its own token bucket (50-token burst, refilled at 50 tokens/sec); traffic from a session's current address is not subject to it.

For UoT the address is that of the TCP connection, so a new TCP connection is a new address just like a new UDP port.

The client moves the session to a new connection of the same carrier:

1. **When:** on a network change (`NetworkChanged`), after 10s without an authenticated datagram from the server, when every UoT TCP connection was closed or reset, and after resume from sleep.
2. **How:** it opens a new connection over the same carrier, swaps the socket under the session and resets the path estimates (RTT, congestion window); keys, nonces, streams and the reorder buffer stay. Every unacknowledged frame is retransmitted at once. A packet with a fresh nonce (`Ping`) goes first so the server moves the session's address.
3. **Confirmation:** the move succeeds when an authenticated datagram arrives over the new path within `max(4 s, 4×RTT)`, at most 30 s. Otherwise the client logs that the server did not answer on the new path and starts the recovery of §9.7.
4. **The carrier is the user's choice:** the client never changes it on its own; every move and every reconnect uses the carrier of the profile. The server deliberately stays silent to packets of an unknown session (an explicit "unknown session" answer would let any scanner confirm it is talking to an OSTP server), so "session expired" and "carrier blocked" look the same to the client; a full handshake on the same carrier tells them apart, because it gets through only when the server is reachable.

### 9.7 Session Keepalive and Recovery

* **Client-side:** `Ping`/`Pong` `RelayMessage`s (§8) are exchanged every `keepalive_interval_sec` (default 5s) for RTT measurement. Only a datagram that passed AEAD counts as a sign of life: a duplicate or garbage with a plausible header does not reset the silence timer. After `max(10 s, 2×keepalive interval)` of silence the client moves the session to a new path (§9.6). If the move is not answered, or no socket can be opened, the link is down: the client keeps the session and its application connections and alternates between moving the session and a full handshake, on the same carrier, with pauses of 1, 2, 5, 10, 20 and then 30 s, until the connection is back or the user stops the tunnel. If the old path returns by itself and the kept session answers, the connection is restored with nothing dropped. After 300 s of outage the old session is given up (its application connections are reset) and only full handshakes follow. Without the kill switch the system proxy is released after 45 s of outage, so the machine has its own internet while the tunnel keeps trying; with it the proxy stays.
* **Server-side:** sessions with no valid inbound datagram for 600 seconds are evicted from the dispatcher's session table.
* **Round trips shown to the user:** the apps' "RTT" is the path's own round trip, the congestion controller's smoothed RTT of ACKs of frames that were never retransmitted (the best live session with `mux`); on a reliable carrier it includes the TCP connection's own queue, which is the delay a frame really has there. The in-tunnel `Ping`/`Pong` waits behind every queued data frame, so it is shown separately as the queue delay (in-tunnel RTT minus path RTT, never negative), and only when it is above 200 ms.

### 9.8 Path MTU Discovery (v6)

The datagram size (a UDP payload, the whole OSTP datagram) is set in the client config by `mtu`: `"auto"` (the default; a missing field means it too) or a number of bytes. A number is the size, as in 0.4.x. `auto` is packetization-layer discovery in the spirit of RFC 8899, per session and per direction (each side probes what it sends):

* **Base and ladder:** a session starts at 1200 bytes and tries 1280, 1350, 1400 and 1452, one rung at a time.
* **Probe:** a `KeepAlive` frame (§7) padded to the size under test, counted in flight, acknowledged like any frame and never retransmitted. A peer treats it as a keepalive: nothing is delivered, an ACK follows.
* **Confirmed / ceiling:** an ACKed probe confirms its size and the next rung is tried at once. A rung whose probe is lost 3 times in a row (no ACK within 3 RTOs, 1 to 4 s, or a NACK for its nonce) is the ceiling; the size stays at the rung below. A lost probe is not a congestion loss: it leaves the window alone. The hole it leaves in the nonce space is closed with an `Abandon` (see [`v6-session-design.md`](v6-session-design.md)), so a lost probe stalls no stream.
* **Black hole:** when a frame has been resent 3 times and is still lost, nothing as large was acknowledged since it was first sent, but a clearly smaller frame was, the path no longer carries that size: the size drops to the largest rung below the lost frame, and the log says so. Frames already built at the larger size keep being resent at it (a frame cannot be re-cut) until they are given up.
* **Again:** a ceiling is forgotten after 10 minutes and the rung is probed again; a path change (`on_path_change`) starts over from 1200.
* **Where it does not run:** on a reliable carrier (UoT, TLS) the size does not matter and the configured one is used (1350 on the server, on the client 1350 under `auto`); on a v5 session, because a lost probe would be a hole in the nonce space that a v5 peer cannot close (it would hold up every frame behind it until the NACK for it is answered with a frame that can no longer be re-cut), so the 0.4.x size is kept (1140 under `auto`, a fixed number as given).
* **Chunking follows:** the sender cuts stream data to the size found so far (`ProtocolMachine::max_payload`; the server's readers read it through a shared handle on every read).
* **TUN and local reads:** with `auto` the TUN device keeps its MTU of 1140 (it is set once, and 1140 plus the overhead fits the 1200-byte start), so inner packets stay within it; downloads through the server, and the local proxy's reads, use the full size found.

### 9.9 Stall Detection

A frame lost on a datagram path waits for its retransmit timer, so the cumulative wait for one frame used to reach tens of seconds, during which a v5 session delivers nothing behind it. Each side therefore watches its own sending: **data in flight and no ACK progress for longer than `max(4×SRTT, 1s)` is a stall.**

* **Tail-loss probe:** on a stall the oldest unacknowledged frame is resent at once, without waiting for its backoff timer, and again every such period until an ACK moves. A frame that cannot be resent (a v6 datagram, a path MTU probe) is not probed; with only those in flight there is no stall. The probe does not shrink the congestion window.
* **Backoff cap:** the wait between two sends of one frame stops growing at the same `max(4×SRTT, 1s)` (§9.1).
* **Reliable carrier (UoT, TLS):** nothing is lost on the way and nothing is resent on a timer, so a stall there is counted and logged only: nothing heard from the peer for more than 5s while data waits.
* **Log:** `info`, no address and no destination: the number of the stall, how long it lasted, how many frames were in flight and what was done (`Stall #3: no ACK progress for 1004 ms with 2 frames in flight; resent the oldest frame now`, `Stall #3 over after 1230 ms (1 tail probe(s))`). Only the first stall and then every power of two (1, 2, 4, 8, ...) is written, so a flapping path cannot fill the log.
* **Nothing else:** the detector acts only inside the session. It never reconnects, moves the session or changes the carrier: that is the client's call after its own silence limits (§9.6, §9.7), and the user's choice.

---

## 10. Security Considerations

* **Server authentication (v6):** the first handshake message is encrypted to the server's static key, so a client talks only to the holder of the private key. In v5 anyone with an access key can pose as the server; the apps warn about a profile without a server key, and ask before accepting a changed key on a subscription refresh.
* **Nonce Exhaustion:** the nonce field is 64 bits. An implementation MUST end a session before it overflows (the machine returns an error instead of wrapping), to prevent AEAD keystream reuse.
* **Session Exhaustion (DoS):** the server caps concurrent sessions (1,024; 32 per key, where the oldest session of a key is closed with reason 4 when its 33rd arrives) and silently drops handshakes beyond the cap.
* **Handshake-trial CPU DoS:** there is no cleartext key identifier (a stealth property), so a datagram from an unrecognized source is trial-processed against every key. In v6 a trial is one HMAC (the tag) and one ChaCha20 pass, then at most one Noise read for a key whose tag matched; in v5 a Noise read per key. The server caches each key's derived secrets and gates the whole trial path behind per-source and global token buckets (100 trials/sec globally). The established-session fast path and roaming (§9.6, its own bucket) are not subject to it.
* **Header Authentication:** header obfuscation gives privacy, not integrity. Integrity comes from the AEAD: the session ID is its Associated Data and the nonce is its nonce, so a flipped bit in either fails the Poly1305 check.
* **Replay Cache Bound:** the handshake anti-replay cache is capped (50,000 entries) and windowed to the ±300 s tolerance. The v6 reply cache keeps only the replies to handshakes inside that window.
* **Unauthenticated peers get nothing:** an unknown session or key gets no answer, and a session close reason is sent only inside an authenticated session.
