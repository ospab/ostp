# Protocol v6: design for 0.5.0

Status: implemented in 0.5.0 (the handshake and the session layer; the first release with it is 0.5.0-alpha.1). Releases of 0.4.x stay on wire version 5. The wire format is in [specification.md](specification.md); this page keeps the reasons behind it, and "Differences from the plan" at the end lists what turned out otherwise than written here.

Implemented from section 1 (as built):
- The handshake itself: `Noise NKpsk0`, the masked datagram with a 4-byte tag, the cached reply to a repeated handshake (§1.2 to §1.5); a dispatcher that tries v6 first and v5 behind the switch.
- The server key (§1.1): config section `protocol` (`server_key`, `accept_v5`), created on a new install and, on an existing server, only by `ostp key server new`; `ostp key` shows the public key, `ostp key legacy on|off` is the transitional switch (legacy clients: older than 0.5.0). There is no schema bump: a config without the section means a server with no key, which speaks v5 only, as before. The server reads it at start, so a change restarts the service.
- Key derivation (§1.6): v6 secrets come from HKDF-SHA256 with public labels; v5 derivation is untouched.
- The public key in profiles: `pk=` in `ostp://` links, therefore in subscriptions, the panel/API and `ostp links`; the client config field `server_pk`; a client with it speaks v6 in the bridge, the TTL probe and the prober, and never falls back to v5.
- The error of a v6 client that gets no answer: it names the two causes (a server older than 0.5.0, a replaced key) and says to reissue the link. The server stays silent to unknown handshakes, so this is wording on the client side, not a wire message.
- TTL-desync decoys keep working: their junk marker is the v5 one, a v6-only server drops them as unknown datagrams, a transitional server recognises the marker.
- A damaged `pk` is refused, never read as "no key".
- The apps' own link parsers (the desktop app's JavaScript, the Android app's Dart) carry `pk` too, and the apps warn about a profile without it.

Not done: the wirelab scenarios for v6 (this page does not claim they exist); a minimum client version in subscriptions (see section 3).

## Decisions taken (2026-11-12)

1. **The client checks the server.** The handshake becomes `Noise_NKpsk0_25519_ChaChaPoly_BLAKE2s`: the client knows the server's static public key and the first message is encrypted to it. In v5 (`NNpsk0`) anyone who holds an access key can impersonate the server.
2. **A transitional mode.** A 0.5.0 server accepts v6 and, behind a config switch, v5 as well; the switch goes away in 0.6. Clients never fall back by themselves: which version a client speaks is part of its profile and the user's choice, as with transports.
3. **Plan first.** This page and the page on streams come before code. The old branch `claude/protocol-v6` (based on beta.8) is not rebased; v6 starts from the current alpha and takes over only what has already been checked there: HKDF with public labels (RFC 5869), header protection (RFC 9001 §5.4.4, vector A.5), the Noise prologue `ostp v6`, the RFC 6455 codec.

## 1. Handshake

### 1.1 Server key
- The server has one static X25519 key pair, created at install and kept in its config next to the access keys.
- The public key travels with the profile: a new field in `ostp://` links and in subscriptions. A profile without it is a v5 profile.
- A client whose profile has a key that is not the server's cannot read the server's answer, so it does not connect; it says that the server did not answer as expected (a server older than 0.5.0, or a replaced key) and to reissue the link. Replacing the key is an explicit act on the server (`ostp key server new --yes`) followed by new links. When a subscription refresh brings a different key for a server the app already has, the app keeps the old profile and asks whether to accept the new key (a key that appears where there was none is taken without asking).

### 1.2 Pattern
```
<- s                         (known in advance: the server's public key)
...
-> psk, e, es                (first message, already encrypted to the server)
<- e, ee
```
The PSK is still derived from the access key (§6.2 of the specification), so the access key still authorizes a client and the static key authenticates the server. The client has no static key; this keeps the property that a client leaves nothing that identifies a device. A per-device static key (`IKpsk2`) was weighed for the device limit and rejected for now: it complicates issuing keys and costs anonymity; the limit can be built on sessions.

### 1.3 The handshake must look random
Today the ephemeral X25519 key sits in clear at offset 6, and its top bit is always zero. With the on-curve test that is a fingerprint. In v6 the whole Noise message is XORed with a ChaCha20 stream before it is put on the wire; the stream key comes from the access key (a label of its own, `ostp v6 handshake mask`, with the direction mixed in) and a random 12-byte nonce sent in front. No Elligator is needed because the key never appears unmasked. The padding range stays key-derived.

### 1.3.1 Cheap key lookup
Today the server does one X25519 per access key for every datagram it cannot place. v6 adds a 4-byte keyed tag to the masked header, so a candidate key is checked with a hash, not a curve operation. Cost: 4 bytes in a handshake datagram. Open: whether the tag is enough against an attacker who sends garbage to spend server time (see the questions below).

### 1.4 Retransmitted handshake
A lost server reply makes the client resend, and the server drops the resend as a replay. In v6 the server keeps its reply for the replay window and answers a repeated first message with the same reply, without creating a second session. This is a probing surface (an attacker with a captured first message gets the reply again), but the reply is encrypted to a key the attacker does not have, so it gives nothing.

The reply is found by the Noise message (a hash of it), not by the whole datagram. The padding is not authenticated, so a copy with a damaged padding is accepted; if its reply is lost, the clean copy has to be answered from the same cache entry and not die in the replay check. The lookup costs one HMAC and one ChaCha20 pass (tag check and unmasking), no curve operation, so padding variants of a captured handshake no longer cost the server a Noise read each. The client does not resend identical bytes either: every send is the same Noise message sealed anew, with a new nonce and new padding in the key-derived range, so repeated datagrams share nothing on the wire.

### 1.5 Version
As built, the version is not mixed into the v6 key derivation: `PROTOCOL_VERSION` stays 5 (the v5 derivation), and `PROTOCOL_VERSION_V6 = 6` is only a name. v5 and v6 are told apart by the shape of the handshake datagram and by the keys, which differ because of the salt `ostp v6`. The transitional server tries v6 first and v5 second on a datagram it cannot place.

### 1.6 Key derivation
The v6 secrets come from HKDF-SHA256 (RFC 5869) with public labels, as decision 3 says: `PRK = HKDF-Extract(salt = "ostp v6", IKM = access key)`, and each output is `HKDF-Expand(PRK, label)` with its own label (`ostp v6 psk`, `ostp v6 obfuscation`, `ostp v6 handshake padding`, `ostp v6 handshake mask`, `ostp v6 handshake tag`). The labels carry no secret; the access key is the only secret, as before. The padding range mapping is unchanged. The v5 derivation (salt and info taken from the hash of the access key) is untouched, so a 0.4.x peer derives what it always did. A fixed test vector pins the outputs.

## 2. Session layer
Each item has a problem in 0.4.x and what 0.5.0 does about it; the details are on [v6-session-design.md](v6-session-design.md).

| Problem | Direction | In 0.5.0 |
|---|---|---|
| One lost frame stalls every stream (a single sequence for the whole session). | Per-stream sequence numbers (`stream_seq`); the header grows from 12 to 16 bytes. | Done. |
| A stream is reset when more than 32 MB wait for a slow site. | The per-stream flow control negotiated in 0.4.7 becomes mandatory; no reset. | Done. A v6 stream is aborted only when more than twice the window waits, which means the peer broke the flow control. |
| An application's FIN closes the whole stream, and the reply after it is lost. | TCP half-close as a separate message. | Done: `Fin` (relay tag 13). |
| A reused `u16` stream id can be closed by a stale Close. | A generation number in the stream id; Close, Ack and Nack get their own nonce space so an early Close cannot overtake data. | Done differently: ids are 32 bits and never reused in a session, so no generation is needed; `Close` and `Fin` ride in sequenced `Data`, so no separate nonce space is needed. |
| A client learns that the server dropped it only after about 10 s of silence. | An authenticated session Close with a reason; it also carries errors such as a denied key. | Done, reasons 0 to 6. |
| Migration guesses by the highest nonce and scans sessions. | A connection id, as in QUIC; the session is found by it. | Not done. Migration still moves the session on a datagram that authenticates and carries a higher nonce, behind a token bucket. |
| About 300 Mbit/s per server: one loop, one syscall per datagram. | Sharding by session and GSO/`sendmmsg`; measured in wirelab first. | Not done. |

## 3. Rollout
- 0.5.0: v6 wire. A new install creates a server key and accepts v5 as well (`accept_v5`); an existing server speaks v5 only until `ostp key server new` creates its key. Apps and `ostp` create v6 profiles when the link has `pk`; old profiles keep working.
- A minimum client version in subscriptions was planned and is not built; an old client given a newer link gets no special message.
- The transitional mode (`accept_v5`) is to go in a later release (it was planned for 0.6); today `ostp key legacy off` ends it per server.

## 4. Not in this step
Carriers (WebSocket first, then QUIC/HTTP3, WebRTC, ICMP), the server's DNS policy and the firewall kill switch for Windows have their own pages. They do not change the handshake.

## 5. How it is checked
- Pure logic and RFC vectors in unit tests; no tests that only count calls.
- Handshake and wire tests in `ostp-core` and `ostp/tests/v6_wire.rs` (v6 against v6, v5 and v6 not reading each other, a client refusing a server with another key, a damaged copy not spoiling the clean one, resealed handshakes sharing no bytes). They run on GitHub Actions (see [testing.md](testing.md)).
- Planned for wirelab (this page does not claim it was run): a 0.4.5 client against a transitional server, the TSPU preset, loss and reordering.
- A 0.5.0 client with a v6 profile against a v5 server fails with a message that names the two causes, not with a bare timeout (the server stays silent, so the wording is the client's).

## Differences from the plan
- The version is not mixed into the v6 key derivation (section 1.5); the salt `ostp v6` and the handshake shape separate the versions.
- The handshake mask key comes from its own label, not from the PSK (section 1.3).
- Stream ids are 32 bits, never reused, with parity (client odd, server even); no generation number (section 2).
- The session `Close` is a frame kind with a reason byte and text; the stream-level abort is `[4, reason]` in relay messages; `Fin` is relay tag 13. Two frame kinds were added: 7 `Datagram` and 8 `Abandon`.
- A key that has expired still completes the v6 handshake, and the server then sends `Close` with reason 6, so the reason reaches the client inside the session only.
- Not built: a connection id, sharding and GSO, a minimum client version in subscriptions.

## Open questions, as decided
1. The 4-byte tag stays. The server also gates the whole trial path behind per-source and global token buckets, so a flood of garbage costs it a bounded amount of work. Whether a per-key index would still be worth it was not measured.
2. One server key per server (`protocol.server_key`), not per listener.
3. No grace period: `ostp key server new --yes` replaces the key, and every link and subscription issued before stops working until reissued.
