# OSTP Traffic Obfuscation

## Goal
OpenVPN and WireGuard have recognizable handshakes or fixed headers. OSTP masks every byte from the first one, so that DPI sees nothing but random-looking data. The limits of that claim are stated below.

---

## Kerckhoffs's principle: what is public and what is secret

OSTP is designed so that it stays secure when everything about it is known: this document, the source code, every constant in it, and the protocol version. The only secrets are per deployment and never appear in the code:

| Secret | Where it lives | What it protects |
|---|---|---|
| The user's access key (128 random bits) | Server config, the user's link | Everything below: the Noise PSK, the header-masking key, padding and junk markers are derived from it (see *Secret derivation*) |
| Noise ephemeral keys | Memory, per session | Forward secrecy of each session's traffic keys |
| The upgrade path (`ws_path`) | Server config, the user's link | Only hides the OSTP endpoint on a web server from scanners; the connection behind it is still authenticated by the access key |
| Panel login, API token, subscription tokens | Server config | Access to management, not to traffic |

Public by design, and published here on purpose:

- **Algorithms:** Noise `NNpsk0_25519_ChaChaPoly_BLAKE2s`, ChaCha20-Poly1305 (RFC 8439), HKDF-SHA256 (RFC 5869), HMAC-SHA256 (RFC 2104), TLS 1.2/1.3 through rustls.
- **Constants:** the protocol version, frame layouts, padding ranges, timers. The string `258EAFA5-E914-47DA-95CA-C5AB0DC85B11` in `ostp-core/src/http_upgrade.rs` is the WebSocket GUID from RFC 6455 §1.3. Every browser and web server has it; the WebSocket handshake through nginx, Apache or Caddy does not work without it. It is not a key and hides nothing.
- **Code paths:** how the server tells OSTP apart from other traffic, how junk packets and fragmentation work, how the prober probes.

What follows for someone who knows all of the above but not an access key:

- They cannot decrypt traffic, forge packets or complete a handshake. The Noise handshake needs the PSK, and the PSK comes only from the access key.
- They cannot unmask headers. The header mask is keyed by a value derived from the access key.
- What they *can* do is statistical: packet sizes, timings, and the fact that there is traffic at all. Padding, junk packets and the TLS carrier make that harder; they do not make it impossible, and this documentation does not claim otherwise.

Obscurity is used only on top of real security, never instead of it: the secret upgrade path and the panel's `webpath` keep scanners away from endpoints that are authenticated anyway.

---

## Secret derivation

Every protocol secret — the obfuscation key, the Noise PSK, the handshake padding range, and the per-key junk marker (see below) — is derived from the shared `access_key` via a single HKDF-SHA256 pass, domain-separated by a trailing info byte per output:

```
PRK              = HKDF-Extract(salt = SHA-256(access_key)[0..16], IKM = access_key || PROTOCOL_VERSION)
obfuscation_key  = HKDF-Expand(PRK, info = SHA-256(access_key)[16..] || 0x01, 8 bytes)
psk              = HKDF-Expand(PRK, info = SHA-256(access_key)[16..] || 0x02, 32 bytes)
handshake_pad    = HKDF-Expand(PRK, info = SHA-256(access_key)[16..] || 0x03, 2 bytes)
junk_marker(w)   = HKDF-Expand(PRK, info = SHA-256(access_key)[16..] || 0x04 || LE(window), 4 bytes)
```

The wire protocol version is mixed into the IKM, not sent as a plaintext byte: peers on a different protocol version derive an entirely different `obfuscation_key`, so they simply cannot deobfuscate each other's packets and are rejected as unauthorized — a hard version gate with no recognizable marker ever appearing on the wire. No secret is ever transmitted; both sides derive the same values independently from the shared access key.

Unlike the other three secrets, `junk_marker` is **not** a fixed per-key value — it is additionally parameterised by `window`, the current wall-clock time divided into 60-second buckets (`JUNK_MARKER_WINDOW_SECS`). The marker therefore rotates every window even though the access key never changes, so a captured junk packet's marker is only valid for about a minute and carries no static per-user fingerprint an observer could log and correlate across sessions. The server checks both the current and the immediately preceding window when matching junk, to absorb clock skew between client and server.

---

## Header masking

OSTP datagrams are masked "in-place" immediately prior to transmission and right after arrival. The mask itself is **derived from the packet's own ciphertext**, not from a fixed keystream or a counter, so it changes with every packet automatically:

```
mask = HMAC-SHA256(key = obfuscation_key, message = ciphertext[0..min(32, len)])
```

### 1. Handshake Phase Mode (`is_handshake = true`)
The wire packet is `[4-byte session_id][2-byte noise_len][Noise payload]`. The mask is computed over the Noise payload (`raw[6..]`), and its first 6 bytes are XORed onto `session_id || noise_len`.

### 2. Data Transmission Mode (`is_handshake = false`)
The wire packet is `[4-byte session_id][8-byte nonce][AEAD ciphertext]`. The mask is computed over the AEAD ciphertext, and its first 12 bytes are XORed onto `session_id || nonce`.

#### Impact of the Scheme
Because the mask is keyed on both the shared secret and the packet's own ciphertext, no two packets — even consecutive ones from the same session — share a keystream, without needing an explicit counter-based scheme. This breaks all packet header correlations and eliminates repeating byte patterns, rendering statistical fingerprinting futile.

---

## Padding

In addition to header obfuscation, OSTP defends against Traffic Length Analysis (TLA). 
The `AdaptivePadder` calculates dynamic dummy byte quantities to append to the packet payload before it enters the cryptographic step:

- **Dynamic Distributions**: The padding algorithms emulate length profiles commonly seen in whitelisted HTTPS or real-time video streams.
- **Encrypted Overheads**: The appended padding resides within the AEAD cipher scope. Consequently, passive observers cannot distinguish padding bytes from useful application payload, hiding the true message boundary lengths.

---

## Junk packets and TCP fragmentation

OSTP does not try to impersonate a known protocol (TLS, HTTP, or otherwise) — a fingerprint-matching filter can always be updated to catch an impersonation attempt. Instead it follows a **zapret-like** approach: no recognizable header at all, plus active manipulation of packet boundaries, so there is nothing distinctive to fingerprint in the first place.

The one opt-in exception is not mimicry either: a server bound to a real domain can carry UoT inside **real TLS** with a real certificate (see [Domains and TLS](tls.md)). That is a genuine HTTPS site, not an imitation of one.

- **Junk packets**: before the handshake, the client sends a configurable number (`junk_pc`) of random-size (`junk_ps`) filler datagrams. Each carries a 4-byte marker **derived from the access key** (the `junk_marker` above) rather than a fixed constant — a fixed marker would itself be a universal signature any observer could filter on across every OSTP deployment. The server derives the same per-key marker while trying candidate keys and drops matching junk silently, before it ever reaches the "unauthorized probe" logging path.
- **TCP fragmentation** (UoT/TCP transport only): the first packet (the handshake) is split into small chunks (`frag_chunk` bytes) with short delays (`frag_sleep` ms) between writes, so DPI that inspects only the first TCP segment never sees a complete handshake to fingerprint.

Both are configurable per-profile; neither is sent over plain UDP transport, where a standalone junk datagram would look exactly like a random one-off probe to the server.