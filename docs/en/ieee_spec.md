# OSTP Technical Specification
## OSI Layer Classification and Protocol Architecture

**Document Type:** Independent Technical Specification  
**Status:** Informational  
**Issuer:** Ospab Project (independent open-source project, not a registered legal entity)  
**Last Updated:** May 2026

---

> [!IMPORTANT]
> This document is an **independent technical specification** authored by the Ospab Project. It is **not** an IEEE standard, an IETF RFC, or a product of any recognized standards body. It is formatted for clarity and references real, published standards (IEEE, IETF, ISO/IEC) to clarify how OSTP relates to existing specifications.

---

## 1. OSI Reference Model Classification

OSTP is classified according to the **ISO/IEC 7498-1:1994** Open Systems Interconnection (OSI) Basic Reference Model:

| OSI Layer | Number | OSTP Role |
|---|---|---|
| Application | 7 | Not in scope (handled by the client application) |
| Presentation | 6 | **Partial** — OSTP performs encryption and data transformation |
| Session | 5 | **Partial** — OSTP manages session state (handshake, teardown, roaming) |
| **Transport** | **4** | **Primary** — OSTP provides reliable, ordered, multiplexed delivery over UDP |
| Network | 3 | Not in scope (uses IP, provided by OS) |
| Data Link | 2 | Not in scope |
| Physical | 1 | Not in scope |

OSTP's primary classification is **Layer 4 (Transport)**, operating above UDP. It is analogous in positioning to QUIC [RFC 9000] and KCP, which are also Transport-layer protocols implemented above UDP.

---

## 2. IETF Protocol Category

The Ospab Project does not hold an RFC number. The following table shows the correct category this protocol *would* fall into under IETF taxonomy (RFC 2026, RFC 7841):

| Attribute | Value |
|---|---|
| Intended category | **Informational** (not Standards Track) |
| Submission type | **Independent Submission** (via Independent Submissions Editor) |
| RFC number | **None assigned** — this is not a published RFC |
| Standards body | None — this is not an IETF, IEEE, or ISO standard |

The distinction matters: a protocol can be well-designed and use only standardized primitives without itself being standardized. OSTP is in this category, alongside many production protocols (e.g., WireGuard was an Informational RFC 8669, VXLAN was an Informational RFC 7348).

---

## 3. Cryptographic Primitive Classification

All cryptographic components used by OSTP are standardized and published by recognized bodies:

| Primitive | Standard | Published By |
|---|---|---|
| Key Agreement | X25519 (ECDH over Curve25519) | RFC 7748 (IETF) |
| AEAD Cipher | ChaCha20-Poly1305 | RFC 8439 (IETF) |
| Hash / HMAC | SHA-256, HMAC-SHA-256 | FIPS PUB 180-4 (NIST), RFC 2104 (IETF) |
| Handshake Framework | Noise Protocol Framework (NNpsk0) | Independent Spec [noiseprotocol.org] |
| Hash (Noise internal) | BLAKE2s | RFC 7693 (IETF) |
| Transport Substrate | UDP | RFC 768 (IETF) |

OSTP does **not** use any proprietary or unreviewed cryptographic algorithms. All primitives listed above are publicly specified and have received significant academic and industry scrutiny.

---

## 4. Frame Format Specification

### 4.1 Wire Format

All multi-byte fields use network byte order (big-endian), consistent with IETF convention (RFC 1700).

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Masked Session Identifier (32 bits)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                    Plaintext Nonce (64 bits)                  +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
~            AEAD Ciphertext + Padding (Variable)               ~
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            16-Octet Poly1305 Authentication Tag               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Header size:** 12 bytes (fixed)  
**Minimum datagram size:** 28 bytes (12 header + 16 auth tag, empty payload)  
**Maximum datagram size:** bounded by UDP MTU (typically ≤ 1472 bytes for standard Ethernet)

### 4.2 Header Obfuscation

The Session ID field is masked per-packet using HMAC-SHA-256, so that no static identifier appears on the wire:

```
K_obf     = SHA-256(access_key || "obfusca")[0..7]
mask[0..3] = HMAC-SHA-256(K_obf, Nonce)[0..3]
Wire_SID  = SID_raw XOR mask
```

Because the Nonce is unique per packet, `mask` is cryptographically independent for every datagram. The Nonce is transmitted in plaintext; its integrity is protected by the AEAD authentication tag which covers the 12-byte header as Additional Authenticated Data (AAD).

---

## 5. ARQ Reliability Classification

OSTP's reliability mechanism is classified as **Selective Repeat ARQ** (SR-ARQ), a well-established technique described in:

- Tanenbaum, A. S., "Computer Networks", 5th ed., Prentice Hall, 2011. (Chapter 3.4)
- Forouzan, B. A., "Data Communications and Networking", 5th ed., McGraw-Hill, 2012.
- ISO/IEC 7498-1 (error recovery at transport layer)

Selective Repeat ARQ allows the receiver to request retransmission of only lost packets, unlike Go-Back-N ARQ which requires retransmitting all packets after a loss. This makes OSTP more efficient on high-loss links.

| Parameter | Default Value | Description |
|---|---|---|
| Sequence number width | 64 bits | Nonce field, monotonically increasing |
| Reorder window | 2^18 (262,144) | Maximum acceptable out-of-order offset |
| Reorder buffer | 8,192 packets | Maximum buffered-out-of-order packets |
| RTO | 100 ms | Retransmission timeout |
| ACK delay | 5 ms | Coalescing delay before sending ACK |
| Max retries | 8 | Per-packet retransmission limit |

---

## 6. Comparison to Related Protocols

| Feature | OSTP | WireGuard | QUIC | OpenVPN (UDP) |
|---|---|---|---|---|
| Transport substrate | UDP | UDP | UDP | UDP |
| OSI Layer | 4 | 3–4 | 4 | 3–4 |
| Handshake framework | Noise NNpsk0 | Noise IKpsk2 | TLS 1.3 | TLS |
| AEAD cipher | ChaCha20-Poly1305 | ChaCha20-Poly1305 | AES-GCM / ChaCha | AES-CBC / AES-GCM |
| Built-in reliability (ARQ) | Yes (Selective Repeat) | No (relies on IP) | Yes (QUIC streams) | No |
| Traffic obfuscation | Yes (HMAC-masked headers, adaptive padding) | No | Partial (QUIC spin bit) | No |
| IP roaming support | Yes | Yes | Yes | No |
| Stream multiplexing | Yes | No (single tunnel) | Yes | No |
| Standardized | No (independent) | RFC 8669 (Informational) | RFC 9000 (Standards Track) | No |

---

## 7. Threat Model Summary

OSTP is designed against the following adversary model:

1. **Passive deep packet inspection (DPI):** Mitigated by per-packet HMAC-masked headers and adaptive payload padding, ensuring no static signatures are present on the wire.
2. **Active probing:** An active prober sends arbitrary data to the server. Mitigated by requiring a valid authenticated Noise handshake — the server produces no response to invalid packets.
3. **Replay attacks:** Mitigated by a 30-second timestamp window in the handshake payload and a short-lived handshake replay cache.
4. **Session flooding (DoS):** Mitigated by a hard cap of 1,024 concurrent sessions on the server; excess handshakes are silently dropped.
5. **IP roaming attacks:** Prevented by the requirement that all peer address updates are gated on successful AEAD authentication of the incoming packet.

---

## 8. Standards Referenced

The following published standards are referenced or used by OSTP:

| Standard | Title | Body |
|---|---|---|
| ISO/IEC 7498-1:1994 | OSI Basic Reference Model | ISO/IEC JTC 1 |
| RFC 768 | User Datagram Protocol | IETF |
| RFC 2104 | HMAC: Keyed-Hashing for Message Authentication | IETF |
| RFC 2119 | Key words for use in RFCs | IETF |
| RFC 7693 | The BLAKE2 Cryptographic Hash and MAC | IETF |
| RFC 7748 | Elliptic Curves for Security (X25519) | IETF |
| RFC 8174 | Ambiguity of Uppercase vs Lowercase in RFC 2119 | IETF |
| RFC 8439 | ChaCha20 and Poly1305 for IETF Protocols | IETF |
| FIPS PUB 180-4 | Secure Hash Standard (SHA-256) | NIST |
| Noise Spec Rev.34 | The Noise Protocol Framework | Trevor Perrin (independent) |
