# OSTP — Ospab Stealth Transport Protocol

[Русский язык](README.ru.md) · [Wiki](https://github.com/ospab/ostp/wiki) · [Contributing](CONTRIBUTING.md) · [Releases](https://github.com/ospab/ostp/releases)

![GitHub Release](https://img.shields.io/github/v/release/ospab/ostp?style=flat-square&color=blue)
![License: BSL 1.1](https://img.shields.io/badge/License-BSL%201.1-orange.svg?style=flat-square)
![Platform: Windows | Linux | macOS | Android](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS%20%7C%20Android-green.svg?style=flat-square)
![Crypto](https://img.shields.io/badge/Crypto-Noise__NNpsk0-blueviolet?style=flat-square)
![Transport](https://img.shields.io/badge/Transport-UDP%20ARQ-informational?style=flat-square)

**OSTP** is a high-performance, censorship-resistant transport protocol designed to tunnel TCP traffic over UDP with full traffic obfuscation. Every byte on the wire — including packet headers — is cryptographically indistinguishable from random noise. Resistant to Deep Packet Inspection (DPI), active probing, and statistical traffic analysis.

---

## Quick Install

### Linux
```bash
bash <(curl -Ls https://raw.githubusercontent.com/ospab/ostp/master/scripts/install.sh)
```

### Windows (PowerShell, run as Administrator)
```powershell
irm https://raw.githubusercontent.com/ospab/ostp/master/scripts/install.ps1 | iex
```

### Manual Download
Download pre-built binaries for your platform from [GitHub Releases](https://github.com/ospab/ostp/releases).

---

## Key Features

| Feature | Description |
|---------|-------------|
| **Full Traffic Obfuscation** | Every packet — including headers — is indistinguishable from random noise. Session IDs and nonces are masked with per-packet HMAC-derived keys. |
| **Noise Protocol Handshake** | `Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s` — PSK-authenticated, forward-secret key exchange with no static identity exposure. |
| **Reliable UDP (ARQ)** | Selective ACK/NACK with rate-limited retransmission, configurable reorder buffer, and exponential backoff. |
| **Multiplexed Streams** | Multiple logical TCP streams over a single encrypted UDP session with per-stream flow control. |
| **Seamless Roaming** | Clients can switch networks (WiFi ↔ LTE) without session interruption — tracked by session-ID, not IP. |
| **Management API** | Built-in REST API for third-party panels (3x-ui, custom dashboards). Per-user stats, traffic limits, key CRUD. |
| **Fallback Server** | TCP fallback proxy to a web server — makes OSTP indistinguishable from nginx during active probing. |
| **Multi-Listener** | Bind to multiple addresses simultaneously (dual-stack IPv4/IPv6, multi-port). |
| **TUN Mode** | Full-system VPN via `tun2socks` integration. All traffic transparently routed through the tunnel. |
| **xHTTP Stealth (UoT)** | UDP-over-TCP tunnel disguised as standard HTTP/1.1 or TLS traffic to bypass Level 1 Deep Packet Inspection (DPI) whitelists. |
| **TURN Relay** | RFC 5766 TURN support for environments where direct UDP is blocked. |
| **Hot-Reload** | Runtime config reload without restart (access keys, exclusions, mux settings). |
| **Structured Logging** | `tracing`-based logging with `RUST_LOG` filtering. JSON/file/syslog output support. |
| **Cross-Platform** | Windows, Linux, macOS, Android, FreeBSD, MIPS, RISC-V. Single binary, no runtime dependencies. |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Client                                                     │
│  ┌──────────┐   ┌──────────┐   ┌────────────────────────┐   │
│  │ Browser  │──▸│ SOCKS5/  │──▸│    Bridge (Mux)        │   │
│  │ / Apps   │   │ HTTP     │   │  ┌─────────────────┐   │   │
│  │          │   │ Proxy    │   │  │ ProtocolMachine │   │   │
│  └──────────┘   └──────────┘   │  │ (Noise + AEAD)  │   │   │
│                                │  └────────┬────────┘   │   │
│  ┌──────────┐                  │           │            │   │
│  │ TUN Mode │──────────────────┤      UDP Socket        │   │
│  │tun2socks │                  │  (32MB buffers,        │   │
│  └──────────┘                  │   obfuscated wire)     │   │
│                                └───────────┬────────────┘   │
└────────────────────────────────────────────┼────────────────┘
                                             │ UDP
┌────────────────────────────────────────────┼────────────────┐
│  Server                                    │                │
│  ┌─────────────────────────────────────────┴───────────┐    │
│  │              Dispatcher                             │    │
│  │  (Session lookup, roaming, replay guard, per-user   │    │
│  │   traffic accounting, limit enforcement)            │    │
│  └──┬──────────────────────┬───────────────────────────┘    │
│     │                      │                                │
│  ┌──▾──────────────────┐ ┌─▾──────────────────────────┐     │
│  │ Relay Loop          │ │ Management API (REST)      │     │
│  │ (per-stream TCP)    │ │ /api/users, /api/stats     │     │
│  │ ──▸ Internet        │ │ Bearer token auth          │     │
│  └─────────────────────┘ └────────────────────────────┘     │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Fallback TCP Proxy ──▸ nginx/caddy (anti-DPI)        │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### 1. Generate config

```bash
# On your VPS (server):
./ostp --init server

# On your machine (client):
./ostp --init client
```

### 2. Edit config

**Server** — set your access keys:
```jsonc
{
  "mode": "server",
  "listen": "0.0.0.0:50000",
  "access_keys": ["YOUR_SECRET_KEY"],
  "api": { "enabled": true, "bind": "127.0.0.1:9090", "token": "admin-token" },
  "fallback": { "enabled": false, "listen": "0.0.0.0:443", "target": "127.0.0.1:8080" }
}
```

**Client** — point to your server:
```jsonc
{
  "mode": "client",
  "server": "YOUR_SERVER_IP:50000",
  "access_key": "YOUR_SECRET_KEY",
  "socks5_bind": "127.0.0.1:1088",
  "transport": { "mode": "udp", "stealth_sni": "vk.com", "stealth_port": 443 },
  "tun": { "enable": false, "dns": "1.1.1.1" }
}
```

### 3. Run

```bash
./ostp                        # Uses config.json in current directory
./ostp --config /path/to.json # Custom config path
./ostp --check                # Validate config without running
./ostp --generate-key         # Generate a new access key
./ostp --links                # Print client share links
```

### 4. Connect via share link (one-liner)
```bash
./ostp "ostp://ACCESS_KEY@server.com:50000?..."
```
> **Note**: Always wrap the `ostp://...` link in quotes (`"`) so your terminal doesn't misinterpret special characters like `&` or `?`.

---

## Management API

Built-in REST API for building panels and dashboards.

```bash
# Server status
curl -H "Authorization: Bearer mytoken" http://127.0.0.1:9090/api/server/status

# List all users with traffic stats  
curl -H "Authorization: Bearer mytoken" http://127.0.0.1:9090/api/users

# Create a user with 10GB traffic limit
curl -X POST -H "Authorization: Bearer mytoken" \
  -H "Content-Type: application/json" \
  -d '{"limit_bytes": 10737418240}' \
  http://127.0.0.1:9090/api/users
```

Full API reference: [Management API](https://github.com/ospab/ostp/wiki/Management-API)

---

## CLI Reference

```
ostp [OPTIONS] [URL]

Options:
  --config <PATH>        Config file path (default: config.json)
  --init <MODE>          Generate template config (server/client)
  --check                Validate configuration and exit
  -g, --generate-key     Generate a secure access key
  -c, --count <N>        Number of keys to generate (default: 1)
  --format <FMT>         Key format: hex, base64 (default: hex)
  --links                Print client share links from server config

Arguments:
  [URL]                  Connect via share link: ostp://KEY@HOST:PORT
```

---

## Protocol Summary

| Layer | Mechanism |
|-------|-----------|
| Key Exchange | Noise NNpsk0 (X25519 + ChaChaPoly + BLAKE2s) |
| Encryption | ChaCha20-Poly1305 AEAD per-packet |
| Header Obfuscation | HMAC-SHA256 derived per-packet mask |
| Reliability | Selective ACK with cumulative + SACK ranges |
| Retransmission | Rate-limited NACK + exponential backoff RTO |
| Keepalive | Ping/Pong with RTT measurement every 5s |

---

## Building from Source

```bash
# Prerequisites: Rust 1.75+
cargo build --release

# Cross-compile for Linux
cross build --release --target x86_64-unknown-linux-gnu

# Run tests
cargo test -p ostp-core -p ostp-server
```

---

## Documentation

- **[Wiki](https://github.com/ospab/ostp/wiki)** — Full documentation
- [Installation](https://github.com/ospab/ostp/wiki/Installation)
- [Configuration Reference](https://github.com/ospab/ostp/wiki/Configuration)
- [Management API](https://github.com/ospab/ostp/wiki/Management-API)
- [Protocol Design](https://github.com/ospab/ostp/wiki/Protocol-Design)
- [Building from Source](https://github.com/ospab/ostp/wiki/Building-from-Source)
- [FAQ](https://github.com/ospab/ostp/wiki/FAQ)

---

## License

Business Source License 1.1. Free for personal and non-commercial use.  
Converts to MIT License on May 14, 2030.

---

## Contact

- **Telegram**: [@ospab0](https://t.me/ospab0)
- **Email**: gvoprgrg@gmail.com
