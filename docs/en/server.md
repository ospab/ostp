# OSTP Server Daemon

## Overview
The OSTP Server functions as a high-performance network gateway, engineered to concurrently serve thousands of anonymous, obfuscated secure tunnels. It handles raw datagram demultiplexing, decrypts encapsulated payloads, and proxies standard stream traffic out to the destination internet endpoints — optionally exposing a management API, a built-in DNS resolver, and a decoy fallback listener alongside the tunnel itself.

---

## Dispatcher Core Architecture

The core scheduler of the server is the centralized `Dispatcher` module. Departing from traditional synchronous, thread-per-socket designs, it enforces a strict separation of network I/O and session state:

1. **Asynchronous Socket Poll**: an independent asynchronous ingestion task continuously reads datagrams from the listening socket(s) — UDP and/or UoT/TCP — and channels them to the dispatcher.
2. **Crypto Session Registry**: the dispatcher maintains a hash map of all active sessions, indexed by `session_id`.
3. **Zero-Copy Routing**: for every incoming payload, the dispatcher performs an `O(1)` lookup by `session_id`. On a match, the ciphertext is handed directly to that session's `ProtocolMachine`.
4. **Handshake-trial path**: a datagram from an unrecognized source carries no cleartext key identifier (by design — see [`obfuscation.md`](obfuscation.md)), so it is trial-processed against every registered access key's cached derived secrets. This path is rate-limited by a global token bucket (default 100 trials/sec) independent of the established-session fast path, bounding the CPU cost of a spoofed-source flood.

---

## Attack Mitigation & Intrusion Resilience

Because public endpoints are exposed to continuous probe traffic and Denial-of-Service (DoS) attempts, the server implements multiple confinement layers:

### 1. Isolated Packet Rejection
Any corrupted frame, AEAD authentication tag failure, or malformed protocol packet instantly terminates in a silent packet drop event:
- Processing faults are localized immediately during the initial extraction block.
- Existing, authenticated sessions **are never terminated or reset** when an invalid packet arrives on their matching ID. This strictly blocks blind packet injection (spoofing) vectors aimed at interrupting existing user tunnels.

### 2. Replay Prevention
To defend against man-in-the-middle adversaries intercepting and later replaying valid handshake datagrams:
- Client handshakes embed a Unix timestamp in their payload.
- The server validates it against a ±300-second synchronization window.
- Accepted handshakes are recorded in a bounded anti-replay cache (default capacity 50,000 entries) to categorically discard exact bitwise retransmissions within that window.

### 3. Session and Trial Caps
- Concurrent sessions are hard-capped (default 1,024); handshakes beyond the cap are silently dropped rather than evicting an existing session.
- Sessions idle for 600 seconds (10 minutes — generous enough to survive typical mobile-NAT rebinding delays) are evicted from the dispatcher.

---

## Zero-Latency Client Roaming

The server treats IP:port coordinates as fluid, tracking sessions by `session_id` instead:
- Upon receiving **any successfully decrypted and authenticated** data frame, the dispatcher reads its source IP and port.
- If this origin deviates from the recorded tracking coordinate for that session, the server executes an atomic in-place update — no handshake restart.
- Subsequent outbound packets for the client are dispatched to the newly updated endpoint.
- The rebind path is gated behind its own token bucket (50-token burst, refilled at 50/sec) so a flood of spoofed-source packets can't force unbounded roaming-scan work; this bucket does not affect already-current, already-authenticated traffic.
- This facilitates millisecond-level handoffs during cellular tower changes or Wi-Fi switches, fully preserving upper TCP sessions.

---

## Management API

An optional REST API (`api.rs`), enabled via the `api` block in `config.json`, exposes server status, per-user traffic statistics, and key management for building panels/dashboards (e.g. 3x-ui-style integrations):

- **Authentication**: either a static Bearer `token` (also used for relay-node federation, below), or a username/password-hash login (`POST /login`) issuing a session token — comparisons are constant-time to avoid timing side-channels. If no token and no username/password-hash are configured, the API is open to whoever can reach the bind address — bind it to `127.0.0.1` and front it with a reverse proxy for anything internet-facing.
- **Endpoints** (mounted under the configured `webpath`): `GET /server/status`, `GET`/`PUT /server/config`, `GET`/`POST /users`, `GET`/`PUT`/`DELETE /users/{key}`, `PUT /users/{key}/limit`, `POST /users/{key}/reset`, `POST /users/bulk`, `GET`/`POST`/`DELETE /audit`, `GET`/`PUT /router/rules`, and `GET /subscribe/{key}` (no Bearer token needed — the access key itself authenticates the request, returning a ready-to-use client config or `ostp://` share link).
- See the [Management API wiki page](https://github.com/ospab/ostp/wiki/Management-API) for the full request/response reference.

### Web panel: `ostp panel`

The panel is built into the binary and runs on the same API. It has its own command:

```
ostp panel status                      # on or off, address, path, sign-in, how to open it
ostp panel enable [--bind 127.0.0.1:9090] [--webpath x7Kq2m] [--user admin]
ostp panel set --webpath x7Kq2m        # change settings without turning it on or off
ostp panel passwd [--user NAME]        # password: asked twice without echo, or read from stdin
ostp panel token [--new | --clear]     # API token for scripts
ostp panel disable
```

`enable` does not turn on a panel without sign-in: it asks for a name and a password when they are missing. The password is never an argument (it would stay in shell history) and needs 8 or more characters. Every command keeps a copy of the config and restarts a running service (`--no-restart` to skip).

Open the panel on the server at `http://127.0.0.1:9090/<webpath>/`, from elsewhere through an SSH tunnel (`ssh -L 9090:127.0.0.1:9090 user@server`) or over HTTPS on the domain when the built-in frontend holds 443 or the web server forwards the panel path (`ostp panel set --vhost`). `ostp panel status` lists every address that works.

---

## Built-in DNS Resolver

An optional embedded DNS server (`dns.rs`), independent of the DNS *tunneling* concept — this resolves DNS *for* already-tunneled clients, it does not carry OSTP traffic itself:

- Listens on a configurable UDP port (default `50053`) that clients point their resolver at.
- Serves custom domain overrides, filters against AdBlock-style hosts lists, and forwards everything else via DNS-over-HTTPS (default upstream `https://cloudflare-dns.com/dns-query`).
- An `intercept_all_port53` mode can additionally catch and resolve any UDP traffic to port 53 through the tunnel even when the full resolver is disabled, to prevent DNS leaks.
- Replies are rate-limited to bound abuse of the resolver as an amplification vector.

---

## Fallback (Decoy) Listener

Every OSTP TCP listener sniffs the first byte of a connection: raw UoT is handled as always, TLS is terminated with the server's certificate when one is configured, and an HTTP request for the secret upgrade path continues as UoT (this is how nginx/apache/caddy on 443 hand clients to OSTP). Everything else is a decoy: a bare 404, or — with `fallback.enabled` — a transparent splice to `fallback.target` (e.g. a local nginx serving an ordinary site), so an active prober sees a normal website. `fallback.listen` adds one more such listener. Domains, certificates and the built-in HTTPS frontend are covered in [Domains and TLS](tls.md).

---

## Outbound Chaining

By default the server proxies decrypted client traffic directly to the internet from its own address. `outbound.rs` optionally routes some or all of that egress through an upstream SOCKS5/HTTP proxy instead, with per-rule matching (`domain_suffix`, `ip_cidr`, `protocol`) selecting `proxy`, `direct`, or `block` — e.g. sending `.onion` traffic to a local Tor SOCKS proxy while everything else goes direct.

---

## Relay-Node Federation

`relay_node.rs` implements a lightweight relay mode (`"mode": "relay"` in config) for chaining: `Client → Relay₁ → Relay₂ → ... → Target Server`. A relay node:

1. Accepts client connections over UDP and/or UoT, same as a full server.
2. Periodically syncs the current access-key set from the **target** server's Management API (`upstream_api_url` + `upstream_api_token`, default interval 30s), so it can authenticate clients without an operator manually mirroring keys.
3. Validates each client purely by HMAC/AEAD against the synced keys, then forwards authorized traffic upstream unchanged — a relay node never decrypts or inspects tunneled payload, only proves a client holds a valid key before relaying its (still end-to-end encrypted) bytes on.

This lets an operator front one target server with disposable relay IPs, without the relays themselves being trusted with traffic content.
