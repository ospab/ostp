# OSTP Client Daemon

## Overview
The OSTP Client operates as an autonomous background daemon (or system service) responsible for high-performance interception of local application traffic, encapsulation into the obfuscated secure tunnel, and maintaining robust endpoint connectivity to the remote OSTP server.

---

## Traffic Ingestion Mechanisms

To maximize platform compatibility and application support, the client integrates three primary mechanisms:

### 1. Dual-Protocol Inbound Proxy
The internal proxy server binds to a single TCP port and dynamically distinguishes the protocol based on the initial byte of the incoming stream:
- **SOCKS5 (RFC 1928)**: Activated when the first byte equals `0x05`. Standard stream encapsulation occurs.
- **HTTP Forward Proxy**: Triggered when the first byte differs from `0x05`. The parser supports:
  - The `CONNECT host:port` method for establishing encrypted end-to-end TLS pipelines.
  - Standard `GET http://...` methods for clear-text HTTP proxying.

### 2. Windows System Proxy Integration (Sysproxy)
For zero-configuration deployments on Windows, the client programmatically configures the host's system proxy configuration (WinINet API):
- Proxy server registries are written in the strict format demanded by modern browsers (Edge, Chrome, Firefox):
  `http=127.0.0.1:1088;https=127.0.0.1:1088`
- Upon graceful shutdown, previous registry values are fully restored, ensuring the user is never left without basic internet connectivity.

### 3. Virtual Network Interface (TUN)
On Windows and Linux, the client can instantiate a virtual TUN adapter (Wintun on Windows) that intercepts 100% of machine traffic at OSI Layer 3 (raw IP packets). A userspace TCP/IP stack (the `netstack-smoltcp` crate) reconstructs logical TCP/UDP flows from those raw packets and routes them into the OSTP multiplexer (§`RelayMessage`, see [`specification.md`](specification.md)), enabling system-wide VPN-grade tunneling without per-application configuration. On the desktop GUI, TUN-adapter creation is delegated to a separately-privileged `ostp-tun-helper` process so the GUI itself doesn't need to run elevated (see [`integrations.md`](integrations.md)).

---

## Transport Modes

The client speaks OSTP over one of two carrier transports, selected by `transport.mode` in the config:

- **`udp`** (default): each OSTP datagram is sent as one UDP datagram directly to the server. The client binds a single `UdpSocket` and reuses it for the entire session, so NAT/firewall mapping stays stable for the tunnel's lifetime.
- **`uot`** (UDP-over-TCP): each OSTP datagram is instead carried over a plain TCP connection, framed with a 2-byte length prefix. This is for networks that block or heavily throttle unrecognized UDP; no protocol is mimicked (not a fake TLS/HTTP shell) — the TCP stream is just length-prefixed opaque blobs, consistent with OSTP's "no recognizable header" design.
- **`uot` + `tls`**: the same UoT stream inside real TLS to the server's domain (optionally through nginx/apache/caddy on 443 via `ws_path`), with certificate verification against the bundled Mozilla roots; `tls_insecure` disables it for testing. See [Domains and TLS](tls.md).

Two further obfuscation knobs apply mainly to `uot`, configured under the same `transport` block: `junk_pc`/`junk_ps` (count/size range of random filler datagrams sent before the handshake, each stamped with a key-derived, time-rotating marker) and `tcp_fragmentation`/`frag_chunk`/`frag_sleep` (splits the first TCP segment — the handshake — into small chunks with short delays, so DPI inspecting only the first segment never sees a complete handshake). See [`obfuscation.md`](obfuscation.md) for the cryptographic detail.

There is no STUN/TURN client in the production path — `session_id`-based roaming (§ [`server.md`](server.md)) and, for UDP-blocking networks, the `uot` transport are how OSTP handles restrictive NATs and firewalls instead.

---

## Fault Tolerance & Automated Recovery

The client is engineered to maintain persistence without requiring user intervention:
- **Stall detection and reconnection:** if no valid datagram has been received for 25 seconds, the client starts a background reconnect attempt while keeping the existing session usable in the meantime. If silence continues to 180 seconds (3 minutes) total, the session is declared permanently lost and the tunnel stops — unless the kill switch is enabled, in which case the client keeps retrying indefinitely instead of falling open to unencrypted traffic.
- **Sleep/resume handling:** on OS resume (or a detected network change), the client forces an immediate reconnect rather than waiting out the normal stall timer, since the monotonic clock it uses may not have advanced across a sleep.
- **Log de-noising**: standard, expected TCP interruptions (such as `ConnectionReset`, `BrokenPipe`, or `UnexpectedEof`) are actively suppressed from console output, preserving log clarity for true state transitions (`Idle -> Connecting -> Connected`).

---

## Routing Exclusions (Bypass Mode)

To minimize latency and overhead for trusted resources, the OSTP client incorporates an integrated direct-routing bypass engine. This is configured inside the `"exclude"` block of the `config.json` file:

- **`domains`**: A list of domain suffixes (e.g., `["trusted-site.com", "local.lan"]`). Traffic bound for these domains is instantly channeled via the default local gateway, bypassing encryption entirely.
- **`ips`**: A list of target subnet destinations in CIDR format (e.g., `["192.168.1.0/24", "10.0.0.0/8"]`), ensuring local area networks maintain full wire-speed throughput.
- **`processes`**: A list of OS executable filenames (e.g., `["discord.exe", "steam.exe"]`). Applications specified here will automatically evade the VPN's virtual network driver (Windows only — matched via the owning process of a TCP connection through `GetExtendedTcpTable`).

Exclusions are hot-reloadable: editing `config.json` while the client is running updates the active exclusion set without a reconnect.

---

## Multiplexing

Two independent things are called "multiplexing" in OSTP and should not be confused:

1. **Per-flow multiplexing** (always on): every proxied TCP connection and UDP flow rides the *same* single encrypted session as a sequence of `RelayMessage`s (`Connect`/`Data`/`Close`, `UdpAssociate`/`UdpData`) — this is how one OSTP session already carries an arbitrary number of concurrent browser tabs, downloads, etc.
2. **Session-level multiplexing** (opt-in, the `"mux"` block below): running more than one independent OSTP session to the same server in parallel, to spread traffic and loss across multiple nonce sequences / congestion-control instances.

```json
"mux": {
  "enabled": false,
  "sessions": 1
}
```

Setting `sessions > 1` with `enabled: true` activates session-level multiplexing.
