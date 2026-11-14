# Carriers: OSTP inside other protocols

Status: draft, nothing here is implemented. This page is the look the owner asked for before any code: what a carrier is here, what each candidate costs and what is known about how censors treat it. Statements about censors are marked with a source number from the end of the page; what could not be sourced is marked `(unverified)`. Carriers come after the wire changes of [v6-design.md](v6-design.md) and do not change the handshake.

## Direction

Carry OSTP datagrams inside other protocols, so that when one is blocked another may get through. The client never switches a carrier by itself: a profile has exactly one, the user picks it, as with transports today ([specification.md](specification.md) §9.6).

Two things to keep in mind before the list:

- A carrier hides the outer protocol. It does not hide what runs inside the tunnel. A study of a mid-size ISP's traffic found that the TLS handshakes of the user's own connections, nested inside an obfuscated proxy, can be recognised by the size, direction and timing of the packets, with true positive rates above 70% for proxies in their standard setup [S6]. OSTP carries users' TLS handshakes in the same way, so every carrier below shares this exposure. Padding and multiplexing help only partly [S6]. No carrier fixes it.
- More carriers means more to keep working: each one is code on the client, the server and the Android app, a test in wirelab and a line in the docs. The order below is chosen so that the first steps are cheap and each later one has to earn its place.

## 1. What a carrier is in this code

### 1.1 Today

- **Client** (`ostp-client/src/transport/mod.rs`): `Transport` is an enum with two variants, `Udp(socket)` and `Uot { tx, rx }`. The protocol machine calls `send`, `send_to`, `recv` and `local_addr` on it and sees whole OSTP datagrams as `Bytes`. `connect_uot` opens TCP, then optionally TLS (`tls.rs`) and the HTTP upgrade on `ws_path`, and `spawn_uot_io` frames datagrams with a `u16` length. The choice is `config.transport.mode` (a string) plus the `tls`, `tls_sni`, `tls_insecure` and `ws_path` fields. Only `Udp` supports the TTL decoys.
- **Server** (`ostp-server/src/transport/`): `udp.rs` reads UDP sockets; `sniff.rs` looks at the first byte of every TCP connection (raw UoT, TLS, HTTP) and hands it to `uot.rs`. Every connection registers a sender in `tcp_map`, keyed by the peer's `SocketAddr`, and pushes `(Bytes, SocketAddr)` into the one `udp_tx` channel the dispatcher reads. Replies to a peer go to the UDP socket or to its entry in `tcp_map`. Sessions are found by `session_id`, not by address, so a new connection is just a new address for an existing session ([specification.md](specification.md) §9.6).
- **Link** (`ostp-core/src/share_link.rs`): `LinkTransport` is `Udp` or `Uot`. `type=` accepts `uot`, `tcp`, `http`; any other value falls to UDP. `tls=1` or `path=` forces `Uot`.

So a carrier already is, in practice, "something that moves whole datagrams between a client and the dispatcher". The work is to make that an explicit interface instead of one more `match` arm.

### 1.2 What a carrier has to provide

| Property | Requirement | Why |
|---|---|---|
| Datagram boundaries | A datagram goes in whole and comes out whole. | The protocol machine does not reassemble. A byte stream gets a length prefix (UoT already has one). |
| Maximum datagram size | The carrier reports it; the session's `mtu` (a `ProtocolConfig` field today) is set below it. | QUIC datagrams and ICMP have limits that differ from UDP's. |
| Reliability | Either is accepted. The carrier says which. | OSTP has its own ARQ and CUBIC ([specification.md](specification.md) §9.1, §9.5). Over a reliable carrier it retransmits what the carrier already retransmits; this is how UoT works now. |
| Ordering | Not required. | ARQ reorders. |
| Own flow control | Must not stall the session in a way ARQ cannot see. | A stalled carrier looks like a silent server; the client reports it after the existing 10 s of silence and does nothing else. |
| Liveness | The carrier reports "closed" or "failed" to the bridge. | The bridge uses it for the move to a new connection ([specification.md](specification.md) §9.6). |
| Address | The server gives each carrier connection a `SocketAddr` label (a real one for UDP and TCP, a synthetic one where there is none). | `tcp_map` and the dispatcher are keyed by it. |

Proposed shape, for the code that follows this page: a client trait with `send(&Bytes)`, `recv(&mut [u8])`, `max_datagram() -> usize`, `is_reliable() -> bool`; on the server, an accept loop per carrier that registers connections in the same `tcp_map` and feeds the same `udp_tx`. `Transport` stays as the client's dispatch type; the TTL decoys stay UDP-only.

### 1.3 Naming in `ostp://` links

Existing keys keep their meaning: `sni`, `insecure`, `path`, `tls`, `name`. New `type=` values, and parameters that only they read:

| `type=` | Carrier | Extra parameters |
|---|---|---|
| `udp` | plain UDP (today) | none |
| `uot` | TCP, optionally TLS and an upgrade on `path` (today) | `tls`, `sni`, `path` |
| `ws` | WebSocket over TLS with real RFC 6455 framing | `sni`, `path`, `host` (the `Host`/CDN name when it differs from the address) |
| `quic` | QUIC with ALPN `h3` | `sni`, `qmode=dgram` or `stream` (default `dgram`), `alpn` |
| `poll` | HTTPS long-poll | `sni`, `path` |
| `webrtc` | WebRTC data channel | `sig` (URL of the signalling endpoint on the server) |
| `icmp` | ICMP echo | `id` (echo identifier, optional) |

`type=uot&tls=1&path=...` keeps working and keeps meaning "TCP, TLS, upgrade, then raw UoT frames". `ws` is different: it keeps WebSocket framing after the upgrade, which is what a CDN that inspects frames needs and what [tls.md](tls.md) says the present path does not do.

One trap in the current parser: an unknown `type=` becomes UDP without a word. An old client given `type=ws` would try UDP against a TLS port and fail by timeout. The new parser has to reject an unknown type with a clear error, and subscriptions have to say which minimum client version understands which type (the v6 design already adds that field). The old clients cannot be fixed; they only get a worse message.

## 2. Candidates

### 2.1 WebSocket over TLS

**On the wire.** TCP, TLS 1.3, an HTTP/1.1 `GET` with `Upgrade: websocket`, then masked or unmasked WebSocket binary messages, one OSTP datagram per message. Port 443, a real certificate and a real web server or CDN in front, as in [tls.md](tls.md).

**What a censor sees.** A TLS ClientHello with an SNI and ALPN (`http/1.1`); a handshake fingerprint (JA3 or JA4) that depends on the TLS library; then encrypted records. The client uses rustls, whose ClientHello differs from a browser's; whether a censor keys on that is `(unverified)`. Record sizes and timing follow OSTP's padding, not a browser's. The nested-TLS pattern applies [S6].

**Censors.** In Russia the TSPU is in-path, keeps some state and filters on SNI and IP [S5]. In June 2025 Cloudflare reported that connections from Russian ISPs to its addresses and to some hosting providers were cut after the first 10 to 14 packets, about 16 KB [S3, S4]. The mechanism is ISP-side and reported for several protocols; whether it is still applied in November 2026 and to which networks is `(unverified)`. Mobile operators in Russia moved to allowlists of domains in 2025 and 2026, so a connection to a name or address outside the list may not pass at all, whatever the carrier [S9]; how the list is matched (SNI, address, both) is `(unverified)`. For China the sources I found cover QUIC and fully encrypted traffic, not WebSocket (see below).

**Implementations.** Xray and sing-box offer WebSocket transports, and Xray's XHTTP (see 2.5) has largely replaced it for CDN use [S11]. OSTP already has the TLS, the upgrade and the sniffing server; the WebSocket codec was already written and checked on the old `claude/protocol-v6` branch ([v6-design.md](v6-design.md), decision 3).

**Server.** The same 443 and certificate as today. Behind nginx, apache or caddy it works as the upgrade does now. Behind a CDN it works only if the CDN passes WebSocket frames, which is the reason to have real framing.

**Interaction with OSTP.** Reliable carrier: the same behaviour as UoT today, with the head-of-line blocking and double retransmission that implies. A WebSocket message adds 2 to 14 bytes; the client must mask its frames (RFC 6455), which costs a pass over each datagram.

**Crates.** `tokio-tungstenite` 0.30 (MIT, very widely used), or write the small codec ourselves as before; either way the TLS and upgrade code stays. Size: small.

**wirelab.** The TSPU preset with a web server in front, a cut after 16 KB, a record-size filter.

### 2.2 QUIC and HTTP/3: datagrams

**On the wire.** UDP, a QUIC v1 handshake with TLS 1.3, ALPN `h3`, then DATAGRAM frames (RFC 9221) each carrying one OSTP datagram [S12]. DATAGRAM frames belong to the connection, not to a stream, and are not retransmitted by QUIC; they are still subject to QUIC's congestion control. This is the carrier that behaves like UDP: OSTP's ARQ stays the only reliability layer, and there is no head-of-line blocking from the carrier.

**What a censor sees.** The first packet is a QUIC Initial. Its keys are derived from fields in the packet, so anyone on the path can decrypt it and read the SNI and the ClientHello; a censor does not need the server's key [S1, S2]. After that, short-header packets with random-looking bodies. Observable: the SNI (ECH is not supported by the usual QUIC stacks, and I did not check it for quinn: `(unverified)`), the ClientHello fingerprint, the version, packet sizes (the first datagram of a client must be at least 1200 bytes) and timing.

**Censors.**
- China: since 7 April 2024 the GFW decrypts QUIC Initial packets at scale and blocks by SNI from a blocklist of 58,207 names; about a third of them do not support QUIC. It does not reassemble an Initial split over several UDP datagrams, and heavy load on its decryption lowers its effectiveness [S1]. Splitting the ClientHello and sending a random UDP packet first are published bypasses; Firefox 137 and quic-go 0.52 adopted them [S1, S2]. The paper's title page and the Lantern summary agree; I did not read the full paper.
- Russia: all international QUIC was blocked in March 2022 [S8]; between May 2022 and July 2023 this became SNI-based filtering [S8]. Measurements of March and April 2026 report that the TSPU still decrypts Initial packets and drops the flow for forbidden names, and that it now applies to all UDP ports, not only 443 [S8]. Behaviour differs between ISPs [S7, S8]. For a name that is not blocked, whether QUIC to an unknown VPS address passes today is `(unverified)`; I found no measurement that answers it.
- Hysteria2, which is QUIC with HTTP/3 masquerading, is popular, and its documentation recommends port hopping against per-port UDP throttling; the sources I found on how well it fares against GFW or TSPU are blogs and vendor pages, not measurements [S13] `(unverified)`.

**Implementations.** Hysteria2 (QUIC with a custom congestion control and HTTP/3 masquerade), TUIC, and sing-box's QUIC transports. They show that the approach works where UDP is not throttled and that operators accept it. They do not show resistance to SNI-based QUIC filtering.

**Server.** UDP 443 (or another port) and a certificate for a real name. A web server that serves HTTP/3 on UDP 443 on the same machine conflicts with it; sharing one port means telling QUIC connections apart by SNI or ALPN, which `quinn` does not do for you `(unverified)`. Without a fronting server this is the case with the least friction: OSTP owns UDP 443.

**Interaction with OSTP.** QUIC datagram size is bounded by the path MTU; a client's first flight is 1200 bytes, and the usable DATAGRAM payload is smaller than that by the header and tag. The session `mtu` has to follow what the QUIC library reports. QUIC's congestion control sits under CUBIC: the same two-controllers issue as UoT, but a datagram that does not fit the window is dropped, and ARQ recovers it. QUIC connection migration comes free and matches the session's own roaming; the two must not fight over it.

**Crates.** `quinn` 0.11.12 (MIT or Apache-2.0, ~415 million downloads; supports a `ring` provider through rustls, which matters because the workspace builds rustls with `ring` only, since aws-lc-rs does not build for Android). DATAGRAM support is in `quinn`. For the HTTP/3 shell around it: `h3` 0.0.8 and `h3-datagram` 0.0.2 (MIT, still 0.0.x, last published May 2025). Size: medium for raw QUIC with ALPN `h3` and no HTTP/3 shell; medium to large for a true HTTP/3 masquerade (answering real requests).

**wirelab.** The censor needs a QUIC Initial parser and an SNI list; whether the lab's Go censor has one is `(unverified)`, as I did not read it. Scenarios: pass with a clean SNI, block with a listed SNI, block everything UDP except 443, throttle UDP.

### 2.3 QUIC and HTTP/3: streams

**On the wire.** The same QUIC connection as 2.2, but OSTP datagrams are written to one bidirectional stream with the existing `u16` length framing, or one stream per direction.

**What it changes.** Everything a censor sees is the same as 2.2. The difference is in OSTP: this is a reliable carrier with the double-retransmission and head-of-line blocking of UoT, but with a loss recovery that is better than TCP's. It is useful only if a path passes QUIC streams and drops DATAGRAM frames, or if a CDN or proxy in the middle is meant to see an ordinary HTTP/3 request (MASQUE-style CONNECT, `h3` crate). Both are `(unverified)` as needs.

**Size.** Small once 2.2 exists (the stream mode reuses the UoT framing code). As the first QUIC step it is the wrong choice, because it spends QUIC's advantage.

### 2.4 WebRTC data channel

**On the wire.** ICE over UDP (STUN binding requests and responses), then DTLS 1.2, then SCTP inside DTLS, with the data channel carrying OSTP datagrams as messages [S14]. Needs a signalling exchange (session descriptions) before it starts; with one VPS that is an HTTPS endpoint on the server or a manual copy, and it must itself be reachable. The server has a public address, so it can be an ICE-lite endpoint with one host candidate and needs no TURN or broker. Snowflake, which uses WebRTC to reach Tor through volunteer proxies, needs brokers because it hides the bridge's address; OSTP has no such need.

**What a censor sees.** STUN packets (which have a fixed magic cookie), a DTLS ClientHello with its own fingerprint, DTLS records, SCTP packets inside them. It is one of the most recognisable UDP protocols.

**Censors.** Russia has been blocking Snowflake by its DTLS handshake: reports from 2021 say the filtered implementation was pion's, not browsers' WebRTC; a 2024 report names the offset of the `supported_groups` extension in the DTLS ClientHello; a March and April 2026 report describes new blocking and a response in the form of DTLS randomisation in the Snowflake proxy [S15, S16]. These are forum and mailing list posts; the Lantern summary adds that a connection with another JA3 or JA4 got through, and that is AI-extracted `(unverified)`. In August 2025 Roskomnadzor restricted WhatsApp and Telegram voice and video calls; nothing I found says how, so whether STUN and DTLS traffic in general is now a target is `(unverified)` [S10]. For China: nothing sourced.

**Implementations.** Snowflake (pion, Go) is the reference. For Rust: `webrtc` 0.21.1 (the webrtc-rs port of pion; MIT or Apache-2.0; it is a large dependency tree with its own DTLS and SCTP) and `str0m` 0.25 (sans-io, MIT or Apache-2.0, which suits this codebase's style). Whether the DTLS ClientHello of either differs from pion's and from a browser's, and so from the blocked fingerprint, is `(unverified)`; it would have to be checked by capturing it.

**Interaction with OSTP.** SCTP in a data channel can be set to unordered and no retransmit (`maxRetransmits=0`), so it can behave like a datagram carrier; the SCTP message limit is a few hundred bytes to 16 KB by default but a path MTU applies, so `max_datagram` is again set by the library `(unverified)`. Mismatched configuration silently turns it into a reliable carrier.

**Size.** Large: signalling, ICE-lite, DTLS, SCTP, a client side for Android, and a moving target in the DTLS fingerprint.

**wirelab.** A DTLS ClientHello filter by offset and by JA3 is easy to add to a censor; the real blocking is not reproducible from a lab.

### 2.5 HTTPS long-poll (the extra candidate)

**On the wire.** Plain HTTPS (HTTP/1.1, HTTP/2 or HTTP/3), no upgrade: the client sends each OSTP datagram as a `POST` body, or batches several, and receives downstream datagrams in the body of a long-lived `GET` or in the reply to each `POST`. This is the shape of Xray's XHTTP: its `packet-up` mode sends each upload write as its own `POST` with a streaming `GET` for the download; `stream-up` uses one long `POST`; the modes work over HTTP/1.1, HTTP/2 and HTTP/3 and through CDNs [S11]. The sources I have for the mode defaults disagree with each other; I took the structure only.

**What a censor sees.** Ordinary HTTPS to a name: an SNI, a fingerprint, many short requests or two long ones. Size and timing differ from a browser's. The two-connection split makes some timing analysis harder [S11]; the nested-TLS pattern still applies [S6].

**Censors.** Nothing specific to Russia or China that I could source. The CDN restrictions of 2.1 apply, including the Russian allowlists [S9] and the 16 KB cut [S3].

**Why consider it.** It passes anywhere HTTPS passes, including CDNs and corporate proxies that refuse WebSocket, and it maps onto OSTP's datagram model without a framing layer. Its cost is latency and overhead: each datagram is an HTTP request (HTTP/2 and HTTP/3 make this cheaper), and a downstream with no pending data needs a held request.

**Server.** The same 443 and the same sniffing as 2.1, with a new route.

**Crates.** `hyper` and `hyper-util` (MIT) and `reqwest` already in the workspace. Size: medium.

### 2.6 ICMP echo

**On the wire.** The client sends ICMP echo requests with OSTP datagrams in the payload; the server answers with echo replies carrying its datagrams. Only the client can start an exchange: NAT and firewalls pass replies to requests they saw, so the server cannot send on its own. Downstream is bounded by how many requests the client sends, so the client has to send a steady stream of requests even when it has nothing to say. Classic tools: `hans`, `ptunnel` and `ptunnel-ng`, `icmptunnel`. One vendor measured about 50 kbit/s for classic ptunnel [S17].

**What a censor sees.** ICMP echo with a payload that is not what ping tools produce. Defenders detect tunnels by large echo packets (rules at 256 bytes and up), by request and reply payloads that differ from each other, and by volume [S17]. Encrypted payloads still show these.

**Censors.** I found no source about ICMP blocking by TSPU or the GFW `(unverified)`. Everything above is from security vendors on detection inside enterprise networks. Whether ICMP to foreign hosts is passed on Russian mobile networks under the allowlists is `(unverified)`.

**Server.** The kernel answers echo requests by itself. To receive them with custom payloads, the server has to open a raw ICMP socket (root or `CAP_NET_RAW`) and the host's own reply must be switched off (`net.ipv4.icmp_echo_ignore_all=1`), which is a system setting. `ostp` does not change system settings by itself, so this would be a command the operator runs, with the change shown first. IPv6 needs the same for ICMPv6.

**Client.** Windows has an ICMP API that needs no administrator rights but limits the payload and gives no control over the packet; a raw socket needs administrator. On Linux an unprivileged ICMP datagram socket exists if `ping_group_range` allows it. Android: `(unverified)`. The ICMP identifier and sequence are the only addressing; a synthetic `SocketAddr` is built from the source IP and the identifier on the server.

**Interaction with OSTP.** Datagram, unreliable, ordering not kept; works with ARQ like UDP. Maximum payload around 1400 bytes on a path with MTU 1500, but operators may drop large echo.

**Crates.** `socket2` 0.6 (already in the workspace) for raw sockets; `surge-ping` 0.9 (MIT) for a client; `pnet_transport` 0.35 (last published May 2024). Size: medium, mostly the platform differences and the keep-polling logic.

**Verdict.** Interesting only where ICMP passes and everything else is blocked, which I have no evidence for. It needs a measurement, not a design.

## 3. Comparison

| | WebSocket (`ws`) | QUIC datagrams (`quic`) | QUIC streams | HTTPS poll (`poll`) | WebRTC (`webrtc`) | ICMP (`icmp`) |
|---|---|---|---|---|---|---|
| Underlying | TCP, TLS | UDP, QUIC | UDP, QUIC | TCP, TLS | UDP, DTLS, SCTP | ICMP |
| Reliable under ARQ | yes (double) | no | yes (double) | yes (double) | optional | no |
| Reuses existing code | TLS, upgrade, sniff, UoT framing | UDP path, cert code | UoT framing | TLS, sniff, hyper | little | UDP path logic |
| New dependency | small | `quinn` | `quinn` | none new | `webrtc` or `str0m` | `socket2` (present) |
| Size | small | medium | small after QUIC | medium | large | medium |
| Visible to a censor | TLS fingerprint, SNI | QUIC Initial, SNI | same | TLS fingerprint, SNI | STUN, DTLS fingerprint | echo payload |
| Known blocking | CDN 16 KB cut, allowlists [S3, S9] | SNI-based, RU and CN [S1, S8] | same | same as WebSocket | Snowflake DTLS [S15, S16] | not sourced |
| Works on one cheap VPS | yes | yes | yes | yes | yes, with signalling | needs root and a host setting |
| Through a CDN | yes if the CDN passes frames | no | MASQUE only | yes | no | no |

## 4. Recommended order

Criteria, in this order: how much existing code it reuses; cost; what is known about resistance; deployability for an operator with one VPS and no other server. A carrier that fails the last one is not offered.

1. **The carrier interface, then `ws`.** The interface is the first step, because every other carrier needs it and because it can be tested with the carriers that already exist (UDP and UoT go through it, with no behaviour change). `ws` is small, reuses all the TLS and sniffing work and adds the one thing UoT with an upgrade lacks: frames a CDN can pass. Resistance does not improve over TLS plus upgrade except through the CDN; I am not claiming more.
2. **`quic` with datagrams.** The best candidate for a real difference: no double retransmission, no head-of-line blocking, roaming, and a different shape on the wire. The sources say the Initial packet is read by both censors and filtered by name [S1, S8], so it is worth building only together with a measurement: before the code is finished, run a plain QUIC client and server between a Russian network and a VPS to see whether it passes `(unverified)` today.
3. **`poll`.** Only if a CDN that refuses WebSocket turns out to matter. It is the carrier for "HTTPS passes and nothing else does".
4. **`quic` streams.** Only if 2.2 meets a path that drops DATAGRAM frames.
5. **`icmp`.** A research prototype after a measurement shows ICMP passes where the rest does not. Not before.
6. **`webrtc`.** Last. It is the largest, the most recognisable on the wire, and the closest blocking evidence is against an implementation family we would be using [S15, S16].

## 5. Risks and what I could not verify

- **Current censor behaviour.** All the sources are dated; the TSPU is heterogeneous and changes within months [S5, S8]. What passes in November 2026 on a given ISP has to be measured at that ISP; no table on this page replaces that.
- **Hysteria2 and QUIC proxies against the GFW and TSPU.** Only blogs and vendor pages [S13]; no measurement. `(unverified)`.
- **WebSocket specifically.** No source I found measures its blocking in Russia or China. `(unverified)`.
- **ICMP blocking.** No source. `(unverified)`.
- **ECH and QUIC.** Whether `quinn` and rustls can send ECH, and whether the censors act on it, not checked. `(unverified)`.
- **Android.** ICMP sockets, QUIC (`quinn` with `ring`) and WebRTC builds on Android were not checked. `(unverified)`.
- **The lab.** I did not read wirelab's censor, so I do not know which of the scenarios below it can already do.
- **Secondary sources.** Several summaries (Lantern corpus pages, blogs) are generated or secondary; I used them only for pointers and marked the claims that rest on them. The papers cited in S1, S5, S6 and S8 are primary but I read their abstracts and summaries, not every page.
- **Maintenance.** Each carrier is a surface a censor can learn. A carrier whose fingerprint is blocked leaves the user with a profile that does not connect and a message saying so (the client reports a silent transport, as it does now); it never leaves for another.
- **Licence.** The project is AGPL-3.0; every crate named here is MIT or Apache-2.0, which is compatible.

## 6. How it is checked

- **Interface step:** the existing tests for UDP and UoT run unchanged through the new interface; a carrier with a fake pipe tests the datagram-size handling and the reliable and unreliable paths.
- **Per carrier, in wirelab** (a Docker lab with a Go censor modelled on the TSPU preset): the carrier connects and carries a download and an upload; with a listed SNI it is blocked and the client says so; with a 16 KB cut it fails clearly rather than hanging; a packet-loss and reordering run; roaming across a new connection of the same carrier. For `quic`: Initial parsing with a listed and an unlisted SNI. For `icmp`: a firewall that drops everything except echo.
- **Interop:** `quic` against a plain `quinn` client; `ws` through nginx and through caddy; `poll` through nginx.
- **Performance** against the plain UDP carrier on the same lab: throughput, latency and the added load on the server per client, with a clean path, 1% loss and 5% loss. UoT is the control for every reliable carrier. A carrier that is more than about half the UDP speed on a clean path is not asked to justify itself; one that is slower on a lossy path than UoT is.
- **Live:** one test on a real VPS from a Russian mobile and a Russian home network for each carrier before a beta, with the result written in the release notes as measured on that date.

## 7. Open questions for the owner

1. Is the order in section 4 right, in particular `quic` with datagrams before `poll`, and is a measurement of plain QUIC on real networks allowed to decide whether item 2 is built at all?
2. Should `ws` keep the existing `uot` + `tls` + `path` form as it is and add the new type next to it, or should the old form be treated as `ws` with raw framing? (This page assumes the first.)
3. Should QUIC share UDP 443 with a front web server (needs a demultiplexing step), or only run where OSTP owns the port?
4. Does the owner want port hopping for QUIC (the client uses a range of UDP ports; Hysteria2 does) given that Russian QUIC filtering is reported on all UDP ports [S8]?
5. ICMP: is a prototype wanted at all before there is evidence that ICMP passes where nothing else does?
6. WebRTC: if it is built, is the signalling endpoint allowed to be an HTTPS route on the same 443, or must it need nothing but the UDP path?
7. Should a profile be allowed to list a second carrier for the user to pick by hand (not to switch to by itself)?

## Sources

- S1. https://www.usenix.org/conference/usenixsecurity25/presentation/zohaib: the GFW decrypts QUIC Initial packets and blocks by SNI since April 2024; the blocklist; no reassembly of split Initials; the decryption cost.
- S2. https://corpus.lantern.io/findings/2025-zohaib-quic-sni__gfw-decrypts-quic-initials-at-scale/: summary of S1 (secondary, AI-extracted); used for the bypasses adopted by Firefox and quic-go.
- S3. https://blog.cloudflare.com/russian-internet-users-are-unable-to-access-the-open-internet/: Cloudflare's report of the June 2025 cut after the first packets, over TCP and QUIC, applied by ISPs.
- S4. https://github.com/net4people/bbs/issues/490: community measurements of the roughly 16 KB cut (about 25 packets) and what passes.
- S5. https://par.nsf.gov/servlets/purl/10379650: "TSPU: Russia's Decentralized Censorship System" (IMC 2022): in-path, stateful, SNI, IP and QUIC triggers, deployed per ISP.
- S6. https://www.usenix.org/conference/usenixsecurity24/presentation/xue: encapsulated TLS handshakes are recognisable inside obfuscated proxies; limits of padding and multiplexing.
- S7. https://ntc.party/t/%D0%BE%D0%B3%D1%80%D0%B0%D0%BD%D0%B8%D1%87%D0%B5%D0%BD%D0%B8%D0%B5-http3-quic/1823/29: community reports that HTTP/3 behaviour differs by ISP.
- S8. https://www.petsymposium.org/foci/2026/foci-2026-0010.php: Russia's QUIC filtering, from a blanket block to SNI-based, still in force in 2026 and on all UDP ports.
- S9. https://en.zona.media/article/2026/04/07/russian_internet_censorship_2026: mobile allowlists, VPN restrictions and shutdowns in 2025 and 2026 (also https://www.recordedfuture.com/research/russia-restrictive-info-environment for the number of regions).
- S10. https://en.zona.media/article/2025/08/13/callban: the August 2025 restriction of WhatsApp and Telegram calls; no technical detail.
- S11. https://xray-internals.hidandelion.com/transport/splithttp.html: how XHTTP (SplitHTTP) works, its modes and the HTTP versions it runs on (community documentation).
- S12. https://rfc-editor.org/rfc/rfc9221: QUIC DATAGRAM frames, unreliable, subject to congestion control.
- S13. https://habr.com/en/articles/1008554 and https://botmonster.com/self-hosting/vless-reality-vs-hysteria-2/: Hysteria2 port hopping and masquerade, and claims of its blocking (blogs; not measurements).
- S14. https://www.rfc-editor.org/rfc/rfc8831.html: the WebRTC data channel stack, SCTP over DTLS over ICE.
- S15. https://ntc.party/t/a-new-snowflake-blocking-rule-offset-of-supportedgroups-in-dtls-client-hello/2420: a blocking rule for Snowflake keyed on the DTLS ClientHello layout.
- S16. https://ntc.party/t/drop-in-snowflake-users-from-russia-and-evidence-of-blocking-starting-2024-11/13083 and https://forum.torproject.org/t/snowflake-daily-operations-march-2026-update/21442: reports of Snowflake blocking in Russia in 2024 and 2026.
- S17. https://trisul.org/?p=2861: how ICMP tunnels are detected by payload and size (a vendor; detection in enterprise networks, not censorship).
- Crate data (versions and licences) read from the crates.io API on 2026-11-12: `quinn` 0.11.12, `h3` 0.0.8, `h3-datagram` 0.0.2, `tokio-tungstenite` 0.30.0, `webrtc` 0.21.1, `str0m` 0.25.0, `surge-ping` 0.9.1, `socket2` 0.6.5, `pnet_transport` 0.35.0.
- Also searched and used for context only: https://www.usenix.org/conference/usenixsecurity23/presentation/wu-mingshi (the GFW's detection of fully encrypted traffic; relevant to the plain UDP and UoT carriers, which are fully encrypted by design; its current status was not established).
