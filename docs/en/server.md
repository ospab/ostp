# Server

The server accepts OSTP sessions over UDP and UoT/TCP, decrypts them and forwards the traffic to its destinations. Next to the tunnel it can run a management API with a web panel, a filtering DNS resolver and a decoy listener.

## Dispatcher

All sockets feed one `Dispatcher`, which keeps network I/O apart from session state:

1. A separate task reads datagrams from the listening sockets (UDP and/or UoT/TCP) and hands them to the dispatcher.
2. The dispatcher keeps a hash map of active sessions by `session_id`.
3. A datagram is looked up by `session_id`; on a match the ciphertext goes straight to that session's `ProtocolMachine`.
4. A datagram from an unknown source carries no cleartext key identifier (see [obfuscation.md](obfuscation.md)), so it is trial-decrypted with the derived secrets of every access key. This path has its own global token bucket (100 trials a second by default), which bounds the CPU cost of a flood with spoofed sources.

---

## Attack mitigation

### 1. Bad packets are dropped silently
A corrupted frame, a failed AEAD tag or a malformed packet is dropped without any answer. An established session is never closed or reset because an invalid packet arrived with its ID, so a spoofed packet cannot cut a user off.

### 2. Replay protection
A handshake carries a Unix timestamp, which the server accepts within ±300 seconds. Accepted handshakes go into a bounded anti-replay cache (50,000 entries), so an exact copy replayed inside that window is discarded.

### 3. Session and trial limits
- At most 1,024 sessions at once; handshakes beyond that are dropped rather than evicting an existing session. One access key holds at most 32 sessions: a new one drops that key's oldest, so a single key cannot take every slot.
- One access key holds at most 4,096 open connections (TCP streams and UDP associations) at a time; more are refused with an error to the client. Without this one key could use up the process's file descriptors.
- Trying every key on an unknown datagram (one X25519 operation per key) is rate-limited per source (an IPv4 address or an IPv6 /64: 5 a second, bursts of 20) and server-wide (100 a second). Sources that completed a handshake in the last 24 hours skip the server-wide limit, so a flood, spoofed or not, cannot keep returning users out; a brand-new client can still be delayed by a flood of more than 100 datagrams a second.
- A session idle for 600 seconds is removed (long enough for mobile NAT rebinding).
- A TCP or TLS connection (UoT) that delivers no complete datagram for 5 minutes is closed. Clients send a keepalive every few seconds, so only dead or abandoned connections reach this; the session itself survives and can continue over a new connection. Behind a web server, the site OSTP writes times out after the same 5 minutes (`proxy_read_timeout 5m` for nginx, `timeout=300` for Apache).

### 4. What clients can reach

A client's connection may go to the internet. On the server itself it reaches only what is meant for clients: the panel's port and DNS (port 53). Private networks (`10/8`, `172.16/12`, `192.168/16`, `100.64/10`, IPv6 `fc00::/7`) and the rest of the server's loopback are closed: they hold the provider's internal network, databases and admin interfaces. Link-local and reserved ranges, including the cloud metadata service at `169.254.169.254` with the instance's credentials, are always closed. The check is made on the address actually dialled, after name resolution, for TCP and UDP.

A server on a home router that should let clients into its LAN, or expose another local service through `10.1.0.1`, opens this with `"local_access": true` at the top level of the config.

---

## Roaming

Sessions are tracked by `session_id`, not by address. When a frame that decrypts and authenticates arrives from a different IP or port, the server updates the session's address in place, without a new handshake, and sends the replies there. A phone changing from Wi-Fi to cellular keeps its TCP connections. The rebind path is rate-limited per source (20 a second, bursts of 50) and server-wide (200 a second, except for sources that authenticated recently); traffic from the current address is not affected.

---

## Configuration reference

The server's `config.json` (`/etc/ostp/config.json` after the install script; `-c PATH` picks another). Fields that are not listed are ignored: `ostp migrate` warns about them. Every `ostp` command that changes the file validates it first and keeps the previous copy as `config.json.bak`. The running server rereads `access_keys` and `server_info` from the file by itself within a few seconds; everything else is read at start.

| Field | Meaning and default |
|---|---|
| `mode` | `"server"`. A relay node has `"relay"` (see [Relay node](#relay-node)) |
| `listen` | Required. One address (`"0.0.0.0:50000"`) or an array. UDP and TCP (UoT) share the address |
| `bind_ip` | Local source address for outgoing connections. Absent: the system chooses |
| `access_keys` | Required, at least one entry (below) |
| `domain` | Public name used in share links and subscriptions, with or without TLS. A bare host name |
| `protocol` | `server_key`: the server's static private key (secret, never printed; made by `ostp key server new`). `accept_v5`: `true` by default; `false` refuses clients older than 0.5.0 and links without `pk`. Ignored while there is no `server_key`. See [Keys](#keys-ostp-key) |
| `server_info` | What the server tells its clients, see [Server info](#server-info) |
| `log` | `{ "privacy": "strict" or "normal" or "debug" }`, default `normal`, see [Privacy of logs](#privacy-of-logs-ostp-log-privacy) |
| `debug` | The old flag. Without `log.privacy`, `true` means `debug` |
| `api` | The management API and panel, see below. Absent: off |
| `fallback` | The decoy listener, see [Fallback listener](#fallback-listener) |
| `outbound` | An upstream proxy for client traffic, see [Outbound proxy](#outbound-proxy) |
| `dns` | The filtering resolver, see [Built-in DNS](#built-in-dns-ostp-dns) |
| `tls` | HTTPS on the domain, see [Domains and TLS](tls.md#server-configuration) |
| `subscription` | Subscription URLs, see [Domains and TLS](tls.md#subscriptions) |
| `overnet` | `.ov` for clients, see [overnet](#overnet-ov-for-clients-and-the-exit) |
| `warp` | Cloudflare WARP as the exit, see [Cloudflare WARP](#cloudflare-warp-as-the-exit-ostp-warp) |
| `local_access` | `false` by default. `true` lets clients reach the server's own services and private networks (see [What clients can reach](#4-what-clients-can-reach)) |
| `config_version` | The schema the file was written for (currently 6); written by `ostp migrate`, never needed by hand |

An `access_keys` entry is a bare key string or an object:

```json
{ "access_key": "...", "name": "alice", "limit_bytes": 107374182400,
  "max_devices": 3, "expires_at": 1767225599, "sub_id": "0123456789abcdef0123456789abcdef" }
```

| Field | Meaning |
|---|---|
| `access_key` | The key itself (8 to 128 characters when you choose it with `--key`) |
| `name` | A label for panels and `ostp links` |
| `limit_bytes` | Traffic limit in bytes; absent: none |
| `max_devices` | Devices that may fetch the subscription, by device ID; absent: none. See [the device limit](tls.md#device-limit) |
| `expires_at` | When the key stops working, Unix seconds UTC; absent: never. See [Key expiry](#key-expiry) |
| `sub_id` | The user's subscription token, 32 lowercase hex characters, unique among users. Absent: the old token, a hash of the key. See [Subscriptions](tls.md#subscriptions) |

`api` fields: `enabled` (`false`), `bind` (`127.0.0.1:9090`), `token` (an empty string counts as none), `webpath` (empty: `panel`), `username` and `password_hash` (the panel sign-in). `ostp panel` writes them; see below.

A wrong value stops the server at start with the field's name, and `ostp check` reports it without starting anything.

### Wire versions

The server speaks protocol v6 (Noise NKpsk0 with the server's static key, the `pk` in links) when `protocol.server_key` is set, and v5 next to it while `protocol.accept_v5` is `true` (the default; the transitional mode is planned to end in 0.6). Without a key it speaks v5 only, as 0.4.x did. A v5 client and a v6 client use the same port and the same access keys. The formats are in [specification.md](specification.md).

### IPv6 on the server

At start the server checks whether it can reach IPv6 destinations at all (an IPv6 UDP socket routed to a public address). If it cannot, it logs that and answers DNS queries for IPv6 addresses (AAAA) that come through the tunnel with an empty answer, so devices that have IPv6 use IPv4 from the start instead of connecting to addresses that reset. Apps with their own encrypted DNS are not covered. The result is part of what the server tells its clients (`server.ipv6`). The check is made once, at start.

---

## Management API

An optional REST API (`api.rs`), enabled via the `api` block in `config.json`, exposes server status, per-user traffic statistics, and key management for building panels/dashboards (e.g. 3x-ui-style integrations):

- **Authentication**: either a static Bearer `token` (also used for relay-node federation, below), or a username/password-hash login (`POST /login`) issuing a session token — comparisons are constant-time to avoid timing side-channels. Without a sign-in (neither a token nor a username with a password hash) the API does not start at all, whatever the bind address: `127.0.0.1` is no protection, because every client reaches the server's loopback through the tunnel as `10.1.0.1`. An empty `"token": ""` counts as no token. `ostp panel enable` sets a sign-in.
- **Endpoints**, all under `/<webpath>/api/` (`webpath` empty means `panel`):
  - server: `GET /server/status`, `GET`/`PUT /server/config`, `GET`/`PUT /server/info`, `GET`/`PUT /router/rules`, `GET`/`POST`/`DELETE /audit`;
  - users: `GET`/`POST /users`, `POST /users/bulk`, `GET`/`PUT`/`DELETE /users/{key}`, `PUT /users/{key}/limit`, `POST /users/{key}/reset`, `GET /users/{key}/share`, `POST /users/{key}/sub-id` (a new subscription link), `GET`/`DELETE /users/{key}/devices`, `DELETE /users/{key}/devices/{hwid}`, `POST /qr`;
  - DNS: `GET /dns/stats`, `GET`/`DELETE /dns/log`, `GET`/`PUT /dns/settings`, `POST /dns/update`, `POST /dns/test`, `GET /dns/meta`;
  - overnet: `GET`/`PUT /overnet`;
  - sign-in: `POST /login`, `POST /logout`;
  - `GET /subscribe/{key}`: no Bearer token needed, the access key itself authenticates the request; returns a ready-to-use client profile (with the server's `pk`) or an `ostp://` link.
  - The panel itself is served at `/<webpath>/`; `/<webpath>` redirects there.
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

`enable` does not turn on a panel without sign-in: it asks for a name and a password when they are missing. The password is never an argument (it would stay in shell history) and needs 8 or more characters. It is stored salted (PBKDF2-HMAC-SHA256, 300,000 rounds); a bare SHA-256 from an older version still signs in, and `ostp panel status` asks to set the password again. Failed sign-ins are limited server-wide to 10 a minute; past that every sign-in is refused for a while, the right password too, while signed-in sessions and the CLI keep working. `enable` picks a random `webpath` when none is set. Every command keeps a copy of the config and restarts a running service (`--no-restart` to skip).

Open the panel on the server at `http://127.0.0.1:9090/<webpath>/`, from elsewhere through an SSH tunnel (`ssh -L 9090:127.0.0.1:9090 user@server`) or over HTTPS on the domain when the built-in frontend holds 443 or the web server forwards the panel path (`ostp panel set --vhost`). The HTTPS site serves the panel only at a secret `webpath`: at the default `/panel/` anyone probing the site would see an OSTP sign-in page. `ostp panel status` lists every address that works. A device connected through this server also reaches it at `http://10.1.0.1:<port>/<webpath>/`. The desktop and Android apps open it through their own SSH connection (*Server management → Management → Open the panel*), no open port needed. The panel's layout adapts to phone screens.

---

## Traffic statistics and `ostp manage`

Every 30 seconds the server writes per-user traffic to `.ostp_stats.json` next to its config (readable by root only; written to a temporary file and renamed). It is also written on a clean stop and read back on start, so traffic, and the traffic limits that depend on it, carry over restarts and updates; users no longer in the config are dropped. The DNS counters and query log are kept the same way in `.ostp_dns_activity.json` (root only, written every minute and on stop; "Clear" in the panel empties it).

`ostp manage` prints the server's state and applies everyday changes. At a terminal it answers in text; without one, as the apps run it over SSH, it prints one JSON object, with `{"error": ...}` and exit code 1 on failure. `--json` asks for JSON at a terminal too. Nothing asks questions, so it runs without a terminal. A user change is one locked edit of the file: a change the panel made in between is not overwritten.

| Command | What it does |
|---|---|
| `ostp manage install [--port N] [--host H] [--user NAME]` | First install: writes a server config with one user, opens the port in ufw or firewalld if one is active, registers and starts the service. On a configured server only makes sure the service runs |
| `ostp manage status` | Version, service state, sessions, users, listen address, TLS domain and certificate, subscriptions, panel, `server_info` (what clients are told, see below), and the system: OS, load, memory, disk |
| `ostp manage users` | Every user with links, subscription URL, traffic, limits and `expires_at` (Unix seconds or `null`) with `expired` |
| `ostp manage user-add NAME [--key K] [--limit-bytes N] [--devices N] [--expires WHEN]`, `user-remove WHO`, `user-rename WHO NAME` | WHO is a number (as in `ostp links`), a name or a key; a key is tried first, then a name, then a number. A new user gets a random key (unless `--key`) and a random `sub_id`. The running server picks up the change from the file; the last user cannot be removed |
| `ostp manage user-set WHO [--name N] [--limit-bytes N] [--devices N] [--expires WHEN] [--new-sub-id]` | Changes a user in one write; an option left out keeps its value, 0 removes a limit, `--expires never` removes the expiry, `--new-sub-id` gives a new subscription link (the old one stops working; see [tls.md](tls.md#subscriptions)) |
| `ostp manage sub-ids [--assign-missing]` | Users whose subscription link is still a hash of the access key; with `--assign-missing` each gets a random `sub_id` and their old links stop working |
| `ostp manage server-info [--name T] [--location T] [--contact T] [--about T \| --about-file PATH]` | Sets what the server tells its clients about itself; an option left out keeps its value, an empty one removes it |
| `ostp manage user-limit WHO --devices N` | Limits the devices that may use the user's subscription (0 removes the limit); see [tls.md](tls.md#device-limit) |
| `ostp manage user-devices WHO` | Devices that fetched the user's subscription, read from `devices.json` |
| `ostp manage dns` | The DNS filter's settings from the config |
| `ostp manage logs [-n N]` | The service log's last lines (200 by default) |
| `ostp manage restart` | Restarts the service, reports whether it stayed up |

`install.sh -y [-b beta] [--port N] [--host H] [--user NAME]` installs without the setup wizard and runs `ostp manage install` on a first install.

### Key expiry

An `access_keys` entry may have `expires_at`: when the key stops working, in Unix seconds (UTC). Absent means never.

```json
"access_keys": [{ "access_key": "...", "name": "alice", "expires_at": 1767225599 }]
```

`--expires` of `user-add` and `user-set` takes `YYYY-MM-DD` (the end of that day, UTC), `<N>d` (N days from now) or `never`. The panel's user form has a date field for it, and the users table marks an expired key. The running server reads the change from the file within a few seconds, like other key changes.

What happens when a key has expired:

- A new v6 session completes its handshake and is closed at once with `Close` reason 6 (*the key has expired*), so the reason reaches the client only inside the tunnel. The app stops and says to ask the server owner to extend the key; it does not reconnect by itself. A v5 client is refused as with a used-up traffic limit.
- A live session is closed with the same reason on the server's periodic check (every few seconds).
- The subscription is still served as before, links included: whether a key works is decided in the tunnel, not by anything reachable without connecting.

### Server info

A server can tell its clients who runs it. The `server_info` section of the config, every field optional:

```json
"server_info": {
  "name": "My VPN",
  "location": "Helsinki",
  "contact": "@owner",
  "about": "Markdown: rules, news, how to pay."
}
```

`name`, `location` and `contact` are one line of up to 128 characters; `about` is Markdown of up to 8 KiB (the apps render a safe subset; the server passes the text as it is). Set it with `ostp manage server-info`, in the panel (*Configuration → Server info*) or in the file; the running server reads changes within a few seconds.

Clients get it only inside an established session, never before or outside a connection: nothing new for a prober to read. With it the server reports its version, what it offers (`udp`, and `tls` when configured), the log privacy mode, whether it reaches IPv6 and whether its DNS filter is on, plus the asking key's traffic, limit, expiry and device limit. The format is in [specification.md](specification.md#83-server-info-v5-and-v6). `ostp manage status` and the panel's `GET /server/info` show the same `operator` and `server` parts.

---

## Keys: `ostp key`

Nothing here happens by itself; a change restarts the running service (`--no-restart` skips that), and the server reads these settings at start.

```
ostp key                              # status: the server's public key, legacy clients, number of access keys
ostp key gen [-n N] [--format hex|base64] [--add]   # print new access keys; --add also puts them into access_keys
ostp key server                       # the public key alone, for scripts
ostp key server new [--yes]           # create the server key, or replace it
ostp key legacy on|off                # accept clients older than 0.5.0 next to current ones
```

- The server has one static key. Its public half is the `pk` of every `ostp://` link and subscription; the private half (`protocol.server_key` in the config) is never printed. A client whose profile has `pk` checks the server against it; a profile without `pk` is a legacy profile.
- A new install creates the key. An existing server has none until `ostp key server new`. Replacing a key needs `--yes`, because every link and subscription made with the old key stops working and has to be reissued.
- `ostp key legacy off` refuses clients older than 0.5.0 and links without `pk` (the transitional mode ends); it is refused while the server has no key. The config field is `protocol.accept_v5`, `true` by default.
- `ostp key gen` only prints the keys and changes nothing. `--add` appends them to `access_keys` of the server config (the previous file is kept as `config.json.bak`); a running server reads access keys again within a few seconds (hot reload), so no restart is needed. `--add` on a config that is not a server one is an error.
- `ostp gk` and `ostp generate-key` still work as hidden aliases of `ostp key gen`. Note: before 0.5.0 `ostp gk` added the keys to the server config by itself; now it does so only with `--add`.

---

## Privacy of logs: `ostp log privacy`

One setting decides what the server's log (the journal, `ostp.log`) may say about destinations and clients. The same key, `log.privacy`, exists in the client config.

```
ostp log                              # show the log (as before)
ostp log privacy                      # the current mode and what it writes
ostp log privacy strict|normal|debug  # set it, restart the running service (--no-restart skips that)
```

```json
"log": { "privacy": "normal" }
```

| | `strict` | `normal` (default) | `debug` |
|---|---|---|---|
| Destinations: hosts and ports of sites, SNI and DNS names, relay targets | never | never | in full |
| A connect that failed | `CONNECT failed for stream [s:n]: timed out` (the kind of error only) | the same | with the target and the error text |
| A client's address | a tag, `peer-` and 8 hex digits: an HMAC of the address with a random salt that changes at 00:00 UTC and is held in memory only; the same client has the same tag all day, and nothing links two days | the network: `203.0.113.0/24` (IPv6: `/48`), no port | in full, with the port |
| DNS query log (the panel's DNS tab, `.ostp_dns_activity.json`) | not kept: no queries, no per-name or per-client tallies; the totals (queries, blocked, cached, failed) stay, and what an earlier run wrote is dropped at start | kept, with the client's network instead of its address | kept in full |
| Per-stream detail (every CONNECT, every payload) | no | no | yes |

- `debug` is only for finding a fault, and only on request. It never turns itself off, and clients are not told. Without `log.privacy`, the old `"debug": true` still means `debug`; with it, `log.privacy` decides and `debug` is ignored.
- Nothing a mode changes touches what billing and limits need: per-user traffic, last seen, devices and the device limit, traffic limits.
- The mode is read at start: a change needs a restart. The panel shows it on the overview page, read-only.
- `RUST_LOG` raises or lowers the level of what is logged, not what it says: the lines that name a destination or a client go through the same rule at every level.
- How long the journal keeps its lines is journald's setting (`SystemMaxUse`, `MaxRetentionSec`), not OSTP's.
- Every line of `ostp.log` has the same shape on the server and the client: time (UTC), level, subsystem, message.

---

## Built-in DNS: `ostp dns`

A filtering resolver for clients connected to the server (the `ostp-dns` crate): ad and tracker blocking by lists, your own rules and names, much like AdGuard Home. It is not a DNS tunnel and does not carry OSTP traffic.

**It is not reachable from outside.** There is no separate port: the resolver only answers queries that arrive through the tunnel. By default it answers only queries sent to the server's own address, `10.1.0.1`: a client gets the filter by using that address as its DNS server (the apps offer it on the first connection), and every other resolver it asks is left alone. The operator can take over all DNS instead (`ostp dns takeover on`); links and subscriptions then carry `dnsall=true`, so apps say so before the first connection. With takeover on, everything a client resolves goes through the resolver:

| How the client looks a name up | What the server does |
|---|---|
| UDP to `10.1.0.1:53` | answers itself |
| UDP to any other address `:53` (TUN mode) | answers itself with takeover on; otherwise passes it through |
| TCP to `10.1.0.1:53` | redirects it to the resolver's local DNS-over-TCP |
| TCP to any other address `:53` | the same with takeover on; otherwise passes it through |
| DNS-over-TLS / DNS-over-QUIC (`:853`, TCP and UDP) | the connection is refused and the app falls back to plain DNS (with takeover and `doh-bypass on`) |
| Encrypted DNS to a public resolver's address (1.1.1.1, 8.8.8.8, Quad9, AdGuard, OpenDNS, Yandex… on `:443`, TCP and QUIC) | refused (with takeover and `doh-bypass on`). Android ("Private DNS: automatic") and Chrome switch to encrypted DNS by themselves when the system DNS is 1.1.1.1 or 8.8.8.8, and nearly everything would pass the filter |
| A browser's DoH | the `use-application-dns.net` canary gets NXDOMAIN and known DoH hosts are blocked (with takeover and `doh-bypass on`) |
| SOCKS/proxy by name (`CONNECT host:port`) | the name is resolved by the same resolver: a blocked name is refused, a rewritten one goes to its address. With the outbound proxy on, the name is passed to it as is, but blocking still applies |

The pipeline for a name: rewrites → other `*.ostp` names get NXDOMAIN → safe search → DoH bypass blocking → blocked services → lists and your rules → cache → upstream → CNAME check (trackers hidden behind a first-party name are caught by the CNAME target).

```bash
ostp dns status                          # what is on, lists, rule count, upstreams
ostp dns enable                          # turn on (the default list is AdGuard DNS filter)
ostp dns disable [--intercept-only]      # turn off; with --intercept-only clients' DNS still goes through the server, unfiltered
ostp dns update                          # download the lists now (otherwise every 24 h)
ostp dns test ads.example.com            # what happens to a name and by which rule (offline, from the downloaded lists)

ostp dns list presets                    # built-in lists: adguard, adaway, stevenblack, oisd-small, hagezi-light
ostp dns list add oisd-small             # by id or URL; --allow for an allow list
ostp dns list show | remove | enable | disable
ostp dns block tracker.example.com       # ||tracker.example.com^
ostp dns allow cdn.example.com           # @@||cdn.example.com^
ostp dns rule add '||ads.*^$important'   # your own rules, adblock or hosts syntax
ostp dns rewrite add panel.ostp 10.1.0.1 # your own names; *.lan for every subdomain
ostp dns service block tiktok            # whole services; ostp dns service list shows them
ostp dns safesearch on                   # Google, YouTube, Bing, DuckDuckGo, Yandex
ostp dns takeover on|off                 # answer every query, not only those sent to 10.1.0.1; clients are told in links
ostp dns doh-bypass on|off               # keep browsers from bypassing the filter with their own DoH/DoT (only with takeover on)
ostp dns mode nxdomain|null_ip|refused   # what a blocked name gets
ostp dns upstream add tls://dns.quad9.net   # https://…/dns-query, tls://, tcp://, udp:// or an IP
ostp dns upstream mode fallback|parallel
```

Every command validates the settings, keeps `config.json.bak`, writes the `"dns"` section and restarts the service if it is running (`--no-restart` to skip). Downloaded lists are kept in `<config dir>/dns/lists/`, so filtering works right after a restart, even offline; a failed download keeps the previous copy. Lists and upstream queries go through the outbound proxy when it is on.

**A name for the panel.** `10.1.0.1` is the server itself as clients see it through the tunnel. After `ostp dns rewrite add panel.ostp 10.1.0.1`, a connected client opens the panel at `http://panel.ostp:9090/<webpath>/` with no SSH tunnel (the port is in `ostp panel status`). Other names in `.ostp` get NXDOMAIN and never leave the server.

**In the panel**, the DNS page shows statistics (queries, blocked, cache, top domains and clients), the query log with Block/Allow buttons, a name test and every setting above. Saving applies at once, without a restart, and writes `config.json` with a backup.

Rule syntax: `||domain^`, `@@||domain^`, `$important`, `*` in names, `/etc/hosts` lines (`0.0.0.0 domain`, `127.0.0.1 domain`; any other address becomes the answer). Regex rules and rules with unknown modifiers are not applied and are counted as unsupported in `ostp dns status`.

---

## Fallback listener

Every OSTP TCP listener sniffs the first byte of a connection: raw UoT is handled as always, TLS is terminated with the server's certificate when one is configured, and an HTTP request for the secret upgrade path continues as UoT (this is how nginx/apache/caddy on 443 hand clients to OSTP). Everything else is a decoy: a bare 404, or — with `fallback.enabled` — a transparent splice to `fallback.target` (e.g. a local nginx serving an ordinary site), so an active prober sees a normal website. `fallback.listen` adds one more such listener. Fields: `enabled` (`false`), `listen` (`0.0.0.0:443`), `target` (`127.0.0.1:8080`). Domains, certificates and the built-in HTTPS frontend are covered in [Domains and TLS](tls.md).

---

## Outbound proxy

By default client traffic leaves from the server's own address. With the `outbound` section, some or all of it goes through an upstream proxy.

```json
"outbound": {
  "enabled": true, "protocol": "socks5", "address": "127.0.0.1", "port": 9050,
  "username": "", "password": "",
  "rules": [{ "domain_suffix": [".onion"], "action": "proxy" }],
  "default_action": "direct"
}
```

- `protocol` is `socks5` or `http`; any other value fails closed (nothing is sent directly). `http` carries TCP only: UDP that the rules send to an `http` proxy is refused, never sent directly. Use `socks5`, or give UDP an explicit `direct` or `block` rule. `username` and `password` are for a proxy that asks for them.
- Rules match on `domain_suffix`, `ip_cidr` and `protocol` (`tcp` or `udp`) and choose `proxy`, `direct` or `block`; `default_action` covers the rest. A missing `action` or `default_action` means `proxy`, so set `default_action` to `direct` when only some traffic should use the proxy.
- A rule can also set `send_from`, a local source address; the server-wide `bind_ip` is the default.

---

## Cloudflare WARP as the exit: `ostp warp`

With WARP the sites a client visits see a Cloudflare address instead of the server's. Cloudflare sees the server's address and where it connects, so this moves trust from the hosting provider to Cloudflare; it does not make anyone anonymous towards Cloudflare. WARP addresses are shared and known, and some sites show captchas or refuse them. WARP is Cloudflare's service under Cloudflare's terms; `--accept-terms` is the operator's acceptance, not ours.

How it works: the `ostp` process runs a WireGuard client in user space (no tun device, no routes, no firewall changes, no root) and a SOCKS5 proxy on `127.0.0.1:40000` (TCP `CONNECT` and UDP `ASSOCIATE`, names and IPv4/IPv6 addresses). The `outbound` section points at that proxy. Names are resolved inside the tunnel, by 1.1.1.1 reached through WARP, never by the server's own resolver. The tunnel's MTU is 1280, the keepalive 25 s, and the handshake is repeated every 5 s while there is none.

```
sudo ostp warp register --accept-terms   # create the device at Cloudflare; keys go to warp.json
sudo ostp warp license <key>             # optional: attach a WARP+ key
sudo ostp warp enable --all              # everything the server opens outwards goes through WARP
sudo ostp warp enable --rules            # only what the outbound rules send to the proxy
sudo ostp warp disable                   # off; the previous outbound section comes back
ostp warp status                         # registration, mode, tunnel, last handshake, address seen outside
ostp warp test                           # a TCP request and a UDP DNS query through the tunnel; exits non-zero on failure
sudo ostp warp reset                     # forget the device (asks first; refused while WARP is enabled)
```

`enable`, `disable` and `license` restart a running service (`--no-restart` to skip), validate the config before writing it and keep the previous one in `config.json.bak`, like the other commands. Nothing registers, enables or restarts by itself.

- **`--all`.** The `outbound` section is written as SOCKS5 to WARP's proxy, no rules, default action `proxy`. Whatever the server opens outwards for clients (TCP, UDP, names), the DNS filter's DoH and list downloads, and plain, DoT and TCP upstream resolvers (carried as DNS over TCP through the proxy) goes through it. There is no direct fallback: with the tunnel down these fail. Connections to the server's own loopback (the panel) stay local, as always.
- **`--rules`.** Your own `outbound` section is kept as written (rules, default action, `send_from`); only its proxy is replaced by WARP's. It needs at least one rule with action `proxy` (or a default action of `proxy`) and refuses otherwise. What the rules send elsewhere is unchanged.
- **What `enable` remembers.** The `outbound` section that was there (with its proxy password) is kept in `warp.json` and put back by `disable`; if you edited the section after enabling, `disable` leaves your edit. Switching between `--all` and `--rules` starts from the remembered section, not from the one WARP wrote.
- **Keys.** The device's private key, access token and WARP+ key live only in `warp.json` next to `config.json` (mode 0600, written atomically). They are never in `config.json`, its backup, the logs or the panel's API. The running server also updates `warp.status.json` there every 5 s (no secrets); `ostp warp status` reads it.
- **The `warp` section** of `config.json`: `enabled`, `mode` (`all` or `rules`), `listen` (a loopback address only: the proxy has no password), `endpoint` (empty = the registered one, or `host:port` / `ip:port` to replace it). `ostp migrate` (schema 6) writes it into older server configs, off. The server starts the tunnel when `enabled`; if it cannot (not registered, port busy), it logs why, and the connections that the `outbound` section sends to WARP fail: nothing is sent directly instead.
- **WARP+.** `ostp warp license` sends the key to Cloudflare; if Cloudflare refuses it, nothing is stored and the command prints what the service answered.
- **Builds.** WARP is not built into the MIPS binary (`ostp warp` says so; the other targets have it).

Things to know before relying on it: the registration interface is the one Cloudflare's own apps use, not a documented one for third parties, and may change, be rate-limited or be refused for server addresses. WARP endpoints (UDP 2408 and others) can be blocked by a hosting provider. Cloudflare has been reported to be moving WARP from WireGuard to MASQUE; this exit only speaks WireGuard. Throughput is bounded by one user-space WireGuard core. A datagram that does not fit the tunnel's MTU (1280) is dropped and counted in `status`.

---

## overnet: `.ov` for clients and the exit

[overnet](https://github.com/ospab/overnet) is an onion network with its own name zone `.ov`. It runs as a separate process next to the server; the server talks to it only through local SOCKS5 ports. The OSTP protocol is unchanged, so this works with any 0.4.x client.

```jsonc
"overnet": {
  "enabled": true,
  "entry": true,                    // clients open .ov sites through this server
  "gateway": "127.0.0.1:9150",      // SOCKS5 port of the local overnet gateway
  "exit": false,                    // let overnet users reach the internet through this server
  "exit_listen": "127.0.0.1:9151"   // where the exit listens; loopback only
}
```

- **Entry.** A connection to `name.ov` goes to the gateway, by name in proxy mode. In TUN mode the server's DNS answers `name.ov` with a fake address from `198.18.0.0/15`, and connections to that address go to the gateway as `name.ov`. `.ov` is answered by the server whatever the `dns` settings say. `.ov` never reaches the DNS upstreams or the internet: with `entry` off, such names get NXDOMAIN and connections are refused. Only TCP; UDP to `.ov` is dropped.
- **Exit.** Off by default: whatever leaves an exit is attributed to its address. The SOCKS5 listener has no authentication and therefore binds to loopback only; the local overnet node sends its users' clearnet connections there. They follow the same route as client traffic (outbound rules, upstream proxy, `bind_ip`, DNS blocklists). Refused: `.ov`, the server itself, its tunnel network and private, link-local and special ranges. Names are resolved and checked before the connection, unless the outbound proxy resolves them.

The section is **off by default**: nothing about overnet runs, and the OSTP installer does not install it. The owner of the server turns it on and installs the overnet gateway themselves (`scripts/install.sh --role gateway` in the overnet repository). With entry on, the server checks every 5 seconds that the gateway accepts connections; while it does not, `.ov` gets NXDOMAIN and connections are refused, exactly as with entry off, and the log says so. A fake 198.18.0.0/15 answer therefore always means the gateway is there, which is what `overnet browser` relies on.

### Turning it on

```bash
sudo ostp overnet install    # overnet's own installer with the gateway role (systemd unit overnet-gateway)
sudo ostp overnet enable     # serve .ov to clients; restarts ostp (--no-restart to skip)
ostp overnet status          # the section, the program, whether the gateway answers, the exit
sudo ostp overnet exit on    # optional: the exit, then `overnet relay --exit socks5://127.0.0.1:9151`
sudo ostp overnet disable    # .ov off (the exit has its own switch: exit off)
```

The same switches are on the **overnet** page of the web panel (applied live, without a restart) and in the desktop and mobile apps under the server's management tab. `ostp check` prints the state of the section. `ostp migrate` writes the section into an older server config, switched off.

Clients need nothing new: in TUN mode and with the system proxy, `http://search.ov/` opens in any browser. While `.ov` is served, encrypted DNS to public resolvers (DoT/DoQ on 853, DoH to a resolver's address on 443) is refused, as with `dns.block_doh_bypass`: Chrome and Edge upgrade to DoH on their own when the system DNS is 1.1.1.1 or 8.8.8.8, Android does with "Private DNS: automatic", and such a resolver answers NXDOMAIN for `.ov`. After the refusal the device asks plain port 53, which the server answers. A browser with DoH set to a fixed provider by hand (Firefox "Max protection", Chrome with a custom provider) keeps failing on `.ov`; turn that off for this connection.

---

## Relay node

`"mode": "relay"` runs a node that forwards everything to one fixed OSTP server (`upstream_tcp` for UoT/TCP, `upstream_udp` for UDP): `Client -> Relay -> Server`. The relay holds no keys and makes no decisions; the target server authenticates every session end to end and drops what fails. Put disposable relay addresses in front of one server without trusting the relays with traffic. A relay keeps at most 4,096 UDP sessions and drops idle ones. Setup: `ostp init relay` or `ostp setup` (Linux, option 4). `upstream_api_url`, `upstream_api_token` and `sync_interval_secs` from older relay configs are ignored; `ostp migrate` removes them.

---

## Update and removal

```
ostp update [-b stable|beta|alpha] [-v VERSION]
ostp uninstall [--yes] [--purge]
```

- `ostp update` (Linux) runs the install script from the repository's `master`, which downloads the release and checks it against the SHA-256 that GitHub publishes for it before installing anything. `-b` picks the channel (`stable` by default); `-v` an exact version such as `0.5.0` or `0.5.0-beta.1` instead of the latest on the channel. `install.sh` takes the same `-b` and `-v`. The configuration is kept. `ostp -V` prints the installed version with its channel; `ostp changelog` shows what changed.
- `ostp uninstall` (Linux) stops and removes the service, deletes `/opt/ostp` and takes the site OSTP added to nginx, apache or caddy back out. The configuration stays in `/etc/ostp`, certificates and user keys with it. `--purge` deletes it too (for a config outside `/etc/ostp`, only the file and its `.bak`). It asks for `yes`; without a terminal it refuses unless `--yes` is given.
