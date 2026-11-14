# Cloudflare WARP as the server's exit: design

Status: implemented (crate `ostp-warp`, command `ostp warp`, user documentation in [server.md](server.md#cloudflare-warp-as-the-exit-ostp-warp)); the parts that need a real Cloudflare device are not yet tested live, see "How it is checked". Decisions of 2026-11-12 are marked. Where the code differs from the plan it is said under "Differences from the plan".

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

It runs as a task of the server process, so there is one service and one `ostp warp` command. The MIPS builds are left without it (see "Differences from the plan").

### What the Cloudflare side looks like (as implemented)

Read from the source of other open implementations; nothing here was called live by the implementation (the first live call is the operator's `ostp warp register`).

- Base `https://api.cloudflareclient.com`, version path `v0a5641`, `User-Agent: 1.1.1.1/6.38.9-5641 (Android 16.0.0)`, `CF-Client-Version: a-6.38.9-5641`: `ViRb3/wgcf`, `cloudflare/api.go`.
- `POST /{v}/reg` with `fcm_token`, `install_id`, `key` (base64 public key), `locale`, `model`, `tos` (timestamp), `serial_number`, `os_version`, `key_type: curve25519`, `tunnel_type: wireguard`: the same file. `GET /{v}/reg/{id}` and `PUT /{v}/reg/{id}/account` (`{"license": ...}`), answers with `id`, `token`, `account.account_type`, `config.client_id`, `config.interface.addresses.v4/v6`, `config.peers[].public_key`, `config.peers[].endpoint.host/v4/v6/ports`: `wgcf`'s `openapi-spec.yml`. The spec lists the endpoint ports `[2408, 500, 1701, 4500]` by default; the host entry is `engage.cloudflareclient.com:2408`.
- The "reserved" bytes: the first three bytes of the base64-decoded `client_id` go into bytes 1 to 3 of every WireGuard message sent to the peer, after the message (and its MACs) is built; the same bytes are zeroed on what arrives. Sources: Xray-core `proxy/wireguard/bind.go` (set on send, zeroed on receive), the `warp-wireguard-gen` crate (`parse_client_id`) and `xdqi/warp-ebpf`.
- Not confirmed: the exact format of the `tos` timestamp (the code sends RFC 3339 UTC with milliseconds and `Z`, as `warp-wireguard-gen` does), whether Cloudflare still accepts these client versions, and the URL of the terms (`ostp warp register` prints `https://www.cloudflare.com/application/terms/`, taken from memory).

## Risks

- Cloudflare's registration interface is the one its own apps use, not a documented one for third parties; it may change, be rate-limited or be refused for server addresses. WARP's terms apply, and `--accept-terms` is the operator's acceptance, not ours.
- Throughput is bounded by one user-space WireGuard core; measured in wirelab with a local WireGuard peer standing in for Cloudflare before anything is promised.
- WARP endpoints (UDP 2408 and others) can be blocked by some hosting providers.

## How it is checked

Done, in `cargo test`:

- `ostp-warp` unit tests: SOCKS5 framing (including domain names and IPv6), the reserved bytes, registration JSON against a fixture in the shape of `wgcf`'s spec, `warp.json` (round trip, atomic replace, mode 0600 on Unix, unknown version refused), the config section and what enabling does to `outbound`, DNS queries inside the tunnel, the trace parser.
- `ostp-server` (`warp::tests`): the server's own `connect_target` and `connect_udp_target` (the code that serves clients) against the real SOCKS5 proxy and the real tunnel, whose WireGuard peer is a local stand-in for Cloudflare (`ostp_warp::testpeer`: two `boringtun` tunnels over loopback and a `smoltcp` stack that accepts any address). Covered: TCP by name (resolved by the peer's resolver), by IPv4 and by IPv6 address, UDP by address and by name, the reserved bytes on the wire, `rules` mode (a rule-matching connection enters the tunnel, another one leaves directly), a peer that stops (TCP and UDP fail while the target is reachable directly, and it counts zero accepted connections), a tunnel that never came up (every connection is refused).
- `ostp` (`warp_cmd`): register, license (accepted and refused), reset, enable, disable against a local fake registration service (`ostp_warp::testapi`); nothing registers without `--accept-terms`; keys are not in `config.json`; the previous `outbound` comes back.
- `ostp-dns`: the proxy client (SOCKS5 names as names, a dead proxy is an error).

Not covered, and why: a real Cloudflare device (the rule was never to call Cloudflare from tests; the first live test is the operator's); throughput (not measured); a UDP datagram larger than the tunnel MTU through a real path; rekeying after 2 minutes of a long session; the DNS filter's DoH through the proxy end to end.

Planned for wirelab (not written): one container as the WARP stand-in running plain WireGuard (`wg-quick`, forwarding and NAT on), one running `ostp` with `warp.enabled`, a registration key pair written to `warp.json` by hand with the stand-in's public key and endpoint, a target container. The checks: TCP, UDP (a QUIC and a DNS exchange) and IPv6 reach the target through the peer, the target sees the peer's address and not the server's, and with the peer stopped nothing reaches the target. A plain `wg-quick` peer ignores the reserved bytes' value only if it is built to; the stand-in needs the three bytes zeroed before it decrypts, as Cloudflare's does.

## Differences from the plan

- The tunnel's TCP/UDP stack is `smoltcp` driven directly (one driver task), not the client's TUN code: that code is tied to a TUN device and the client's flow handling. `netstack-smoltcp` (what the client's TUN mode uses) is used only on the other end, in the test peer.
- MIPS: the release matrix builds `mipsel`; the new dependencies were not verified for it, and a router is a poor fit, so `ostp-warp` is excluded there with a `cfg` and `ostp warp` says so. The other targets are built with it (see the changelog and the report of the work for what was checked).
- The DNS filter needed more than the `socks` feature: with a proxy on, its plain UDP, TCP and DoT upstreams also went out directly. They now go through the proxy as DNS over TCP, and a proxy that cannot be used fails queries and list downloads instead of falling back.
- `ostp warp status` also reads `warp.status.json`, which the running server writes every 5 s, because the tunnel lives in another process; `test` and the "address seen outside" go through the proxy as a client, so they exercise the path the server uses without a second WireGuard session on the same keys.
- The registration base URL can be replaced with the environment variable `OSTP_WARP_API_BASE`; it exists for tests with a local fake service and is not documented as a setting.

## Open questions

1. Which ports and addresses to try when `engage.cloudflareclient.com:2408` is blocked. The registration lists the ports 2408, 500, 1701 and 4500; today only the host's port (or `warp.endpoint`) is used, and the operator picks another with `warp.endpoint`. Trying the others automatically is not done.
2. `--rules` takes only the rules already in `outbound`; a list of rules on the command line is not implemented.
3. A rejected WARP+ key: `ostp warp license` fails with the service's answer and stores nothing, so `status` never shows a rejected key. How the service behaves when a key later expires is not known.
4. Whether Cloudflare keeps WireGuard on this registration interface (it has been reported to be moving WARP to MASQUE).
