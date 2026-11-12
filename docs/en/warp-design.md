# Cloudflare WARP as the server's exit: design

Status: draft, nothing here is implemented. Decisions of 2026-11-12 are marked; details that depend on Cloudflare's service are marked "verify" and are checked against the live service before any code is written.

## Why

The operator does not want a site to see the server's address. With WARP the site sees a Cloudflare address instead; Cloudflare sees the server's address and where it connects. This moves trust from the hosting provider to Cloudflare and does not make anyone anonymous towards Cloudflare. WARP addresses are shared and known, so some sites show captchas or refuse them.

The official `warp-cli` in proxy mode did not work for this: in the operator's test all UDP was lost, and the address of the server may have leaked while it was. Both are what this design has to rule out: UDP must work, and there is no way for traffic to leave directly while WARP is meant to carry it.

## Decisions (2026-11-12)

1. **A WireGuard client inside the `ostp` server, with a local SOCKS5 proxy.** The tunnel runs in user space (no root, no kernel module, no changes to the host's routes) and a SOCKS5 server with TCP `CONNECT` and UDP `ASSOCIATE` listens on `127.0.0.1:40000` (configurable). The server's existing outbound proxy (`outbound`, which already speaks SOCKS5 including UDP) is pointed at it.
2. **Two modes, chosen by command.** `ostp warp enable --all` sends everything the server opens outwards through WARP. `ostp warp enable --rules` sends through WARP only what the `outbound` rules say (domain suffixes, subnets, protocol); the rest leaves directly, as the operator wrote it.
3. **Explicit registration, with an optional WARP+ key.** `ostp warp register --accept-terms` creates a free device and stores its keys; `ostp warp license <key>` attaches a WARP+ key. Nothing registers by itself.

## Behaviour

- **No direct fallback.** In `--all` mode, with the tunnel down, a connection fails; it does not go out directly. The TCP and UDP paths of `outbound` already refuse to send directly when a rule asks for the proxy; the resolver's own upstream queries and list downloads get the same rule.
- **DNS.** Names are resolved inside the tunnel (SOCKS5 with a domain, `socks5h` style), never by the server's own resolver. The server's DNS lists and DoH upstreams use the same proxy; today that fails with `unsupported scheme socks5h` because `ostp-dns` is built without reqwest's `socks` feature, which is fixed first.
- **IPv6.** WARP gives the device an IPv6 address too; destinations with only IPv6 go through it. With the tunnel down they fail like IPv4.
- **MTU.** 1280 inside the tunnel; TCP segments are cut to fit by the user-space stack.
- **Keepalive.** 25 s, and a handshake is repeated when the last one is older than the WireGuard limit. A dead tunnel is reported by `ostp warp status` and in the panel, not hidden by retries.

## Commands

```
ostp warp register --accept-terms   # create the device, store keys in warp.json (0600)
ostp warp license <key>             # attach a WARP+ key
ostp warp enable --all | --rules    # write the config, restart the service as other commands do
ostp warp disable
ostp warp status                    # registered, mode, tunnel up, last handshake, address seen from outside
ostp warp test                      # a TCP request and a UDP DNS query through the tunnel; fails loudly
ostp warp reset                     # forget the device (asks first)
```

The "address seen from outside" comes from `https://www.cloudflare.com/cdn-cgi/trace` fetched through the tunnel (`warp=on`).

## Configuration and files

- `config.json` gets a `warp` section (`enabled`, `mode`, `listen`, `endpoint`) and schema version 6 adds it switched off, as with `overnet`. The keys live only in `warp.json` next to the config (0600), never in `config.json`, a backup or a log.
- Enabling writes the `outbound` section (SOCKS5 to `warp.listen`) for `--all`, and leaves the operator's rules in place for `--rules`; disabling puts back what was there before (kept in `warp.json`).
- The web panel gets a WARP page: state, mode, the address seen from outside, register and license.

## Implementation

A new crate `ostp-warp`:

| Part | How |
|---|---|
| Registration | HTTPS to Cloudflare's client API, as `wgcf` does; stores the peer's public key, the endpoint, the device's addresses and its client id (verify). |
| WireGuard | `boringtun` (Cloudflare's Rust implementation). The 3 "reserved" bytes that WARP expects in the packet header are set from the client id before sending (verify). |
| Stack | `smoltcp` over the tunnel's IP packets, as in the client's TUN mode, giving TCP and UDP sockets. |
| SOCKS5 | TCP `CONNECT` and UDP `ASSOCIATE`, loopback only. |

It runs as a task of the server process, so there is one service and one `ostp warp` command. A 32-bit MIPS build is left without it if `boringtun` does not build there.

## Risks

- Cloudflare's registration interface is the one its own apps use, not a documented one for third parties; it may change, be rate-limited or be refused for server addresses. WARP's terms apply, and `--accept-terms` is the operator's acceptance, not ours.
- Throughput is bounded by one user-space WireGuard core; measured in wirelab with a local WireGuard peer standing in for Cloudflare before anything is promised.
- WARP endpoints (UDP 2408 and others) can be blocked by some hosting providers.

## How it is checked

- In wirelab a plain WireGuard peer plays Cloudflare: TCP, UDP (QUIC and DNS) and IPv6 reach a target through it, the target sees the peer's address and not the server's, and with the peer stopped nothing reaches the target.
- Unit tests only for pure logic (SOCKS5 framing, the reserved bytes, config and rule handling).
- A real WARP device on a real server for the first live test.

## Open questions

1. Which ports and addresses to try when `engage.cloudflareclient.com:2408` is blocked.
2. Whether `--rules` should accept a list of rule names on the command line, or only the rules already in `outbound`.
3. What `ostp warp status` shows when WARP+ is attached but the license is rejected.
