# Protocol v6: design for 0.5.0

Status: draft, nothing here is implemented. The wire format in force is version 5 ([specification.md](specification.md)); 0.4.x stays on it. This page fixes what 0.5.0 changes and why, so the code is written against a plan.

## Decisions taken (2026-11-12)

1. **The client checks the server.** The handshake becomes `Noise_NKpsk0_25519_ChaChaPoly_BLAKE2s`: the client knows the server's static public key and the first message is encrypted to it. In v5 (`NNpsk0`) anyone who holds an access key can impersonate the server.
2. **A transitional mode.** A 0.5.0 server accepts v6 and, behind a config switch, v5 as well; the switch goes away in 0.6. Clients never fall back by themselves: which version a client speaks is part of its profile and the user's choice, as with transports.
3. **Plan first.** This page and the page on streams come before code. The old branch `claude/protocol-v6` (based on beta.8) is not rebased; v6 starts from the current alpha and takes over only what has already been checked there: HKDF with public labels (RFC 5869), header protection (RFC 9001 §5.4.4, vector A.5), the Noise prologue `ostp v6`, the RFC 6455 codec.

## 1. Handshake

### 1.1 Server key
- The server has one static X25519 key pair, created at install and kept in its config next to the access keys.
- The public key travels with the profile: a new field in `ostp://` links and in subscriptions. A profile without it is a v5 profile.
- A client that gets a different server key than the one in its profile stops and says so; it does not connect and does not ask whether to trust the new key. Replacing the key is an explicit act on the server (`ostp` command) followed by new links.

### 1.2 Pattern
```
<- s                         (known in advance: the server's public key)
...
-> psk, e, es                (first message, already encrypted to the server)
<- e, ee
```
The PSK is still derived from the access key (§6.1 of the specification), so the access key still authorizes a client and the static key authenticates the server. The client has no static key; this keeps the property that a client leaves nothing that identifies a device. A per-device static key (`IKpsk2`) was weighed for the device limit and rejected for now: it complicates issuing keys and costs anonymity; the limit can be built on sessions.

### 1.3 The handshake must look random
Today the ephemeral X25519 key sits in clear at offset 6, and its top bit is always zero. With the on-curve test that is a fingerprint. In v6 the whole Noise message is XORed with a ChaCha20 stream before it is put on the wire; the stream key comes from the PSK and a random 12-byte nonce sent in front. No Elligator is needed because the key never appears unmasked. The padding range stays key-derived.

### 1.3.1 Cheap key lookup
Today the server does one X25519 per access key for every datagram it cannot place. v6 adds a 4-byte keyed tag to the masked header, so a candidate key is checked with a hash, not a curve operation. Cost: 4 bytes in a handshake datagram. Open: whether the tag is enough against an attacker who sends garbage to spend server time (see the questions below).

### 1.4 Retransmitted handshake
A lost server reply makes the client resend, and the server drops the resend as a replay. In v6 the server keeps its reply for the replay window and answers a repeated first message with the same reply, without creating a second session. This is a probing surface (an attacker with a captured first message gets the reply again), but the reply is encrypted to a key the attacker does not have, so it gives nothing.

### 1.5 Version
`PROTOCOL_VERSION` becomes 6 and, as in v5, goes into the IKM, never onto the wire. The transitional server tries v6 first and v5 second on a datagram it cannot place.

## 2. Session layer
Each item has a problem in 0.4.x and a direction; the details go to a second page before code.

| Problem | Direction |
|---|---|
| One lost frame stalls every stream (a single sequence for the whole session). | Per-stream sequence numbers (`stream_seq`); the header grows from 12 to 16 bytes. |
| A stream is reset when more than 32 MB wait for a slow site. | The per-stream flow control negotiated in 0.4.7 becomes mandatory; no reset. |
| An application's FIN closes the whole stream, and the reply after it is lost. | TCP half-close as a separate message. |
| A reused `u16` stream id can be closed by a stale Close. | A generation number in the stream id; Close, Ack and Nack get their own nonce space so an early Close cannot overtake data. |
| A client learns that the server dropped it only after about 10 s of silence. | An authenticated session Close with a reason; it also carries errors such as a denied key. |
| Migration guesses by the highest nonce and scans sessions. | A connection id, as in QUIC; the session is found by it. |
| About 300 Mbit/s per server: one loop, one syscall per datagram. | Sharding by session and GSO/`sendmmsg`; measured in wirelab first. |

## 3. Rollout
- 0.5.0-beta.1: v6 wire, transitional mode on by default. Apps and `ostp` can create v6 profiles; old profiles keep working.
- Subscriptions announce a minimum client version so an app can say "update".
- 0.6: the transitional mode is removed.

## 4. Not in this step
Carriers (WebSocket first, then QUIC/HTTP3, WebRTC, ICMP), the server's DNS policy and the firewall kill switch for Windows have their own pages. They do not change the handshake.

## 5. How it is checked
- Pure logic and RFC vectors in unit tests; no tests that only count calls.
- End to end in wirelab: v6 against v6, a 0.4.5 client against a transitional server, the TSPU preset, loss and reordering.
- A 0.5.0 client against a v5 server must fail with a clear message, not a timeout.

## Open questions
1. Is the 4-byte tag enough, or does cheap lookup need a per-key index of the first bytes of the stream?
2. Where does the server key live for several domains on one server: one key per server (proposed) or per listener?
3. Does a server key rotation need a grace period in which the server answers with both keys?
