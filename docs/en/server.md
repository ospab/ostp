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

## Management API

An optional REST API (`api.rs`), enabled via the `api` block in `config.json`, exposes server status, per-user traffic statistics, and key management for building panels/dashboards (e.g. 3x-ui-style integrations):

- **Authentication**: either a static Bearer `token` (also used for relay-node federation, below), or a username/password-hash login (`POST /login`) issuing a session token — comparisons are constant-time to avoid timing side-channels. Without a sign-in (neither a token nor a username with a password hash) the API does not start at all, whatever the bind address: `127.0.0.1` is no protection, because every client reaches the server's loopback through the tunnel as `10.1.0.1`. An empty `"token": ""` counts as no token. `ostp panel enable` sets a sign-in.
- **Endpoints** (under the configured `webpath`): `GET /server/status`, `GET`/`PUT /server/config`, `GET`/`POST /users`, `GET`/`PUT`/`DELETE /users/{key}`, `PUT /users/{key}/limit`, `POST /users/{key}/reset`, `POST /users/bulk`, `GET`/`POST`/`DELETE /audit`, `GET`/`PUT /router/rules`, and `GET /subscribe/{key}` (no Bearer token needed — the access key itself authenticates the request, returning a ready-to-use client config or `ostp://` share link).
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

`ostp manage` (hidden from `--help`) prints the server's state and applies everyday changes as one JSON object, with `{"error": ...}` and exit code 1 on failure. Nothing asks questions, so it runs without a terminal: this is what the desktop and Android apps run over SSH.

| Command | What it does |
|---|---|
| `ostp manage install [--port N] [--host H] [--user NAME]` | First install: writes a server config with one user, opens the port in ufw or firewalld if one is active, registers and starts the service. On a configured server only makes sure the service runs |
| `ostp manage status` | Version, service state, sessions, users, listen address, TLS domain and certificate, subscriptions, panel, and the system: OS, load, memory, disk |
| `ostp manage users` | Every user with links, subscription URL and traffic |
| `ostp manage user-add NAME`, `user-remove WHO`, `user-rename WHO NAME` | WHO is a number (as in `ostp links`), a name or a key. The running server picks up the change from the file; the last user cannot be removed |
| `ostp manage logs [-n N]` | The service log's last lines |
| `ostp manage restart` | Restarts the service, reports whether it stayed up |

`install.sh -y [-b beta] [--port N] [--host H] [--user NAME]` installs without the setup wizard and runs `ostp manage install` on a first install.

---

## Built-in DNS: `ostp dns`

A filtering resolver for clients connected to the server (the `ostp-dns` crate): ad and tracker blocking by lists, your own rules and names, much like AdGuard Home. It is not a DNS tunnel and does not carry OSTP traffic.

**It is not reachable from outside.** There is no separate port: the resolver only answers queries that arrive through the tunnel. With filtering on, everything a client resolves goes through it:

| How the client looks a name up | What the server does |
|---|---|
| UDP to any address `:53` (TUN mode) | intercepts and answers itself |
| TCP to any address `:53` | redirects it to the resolver's local DNS-over-TCP |
| DNS-over-TLS / DNS-over-QUIC (`:853`, TCP and UDP) | the connection is refused and the app falls back to plain DNS (with `doh-bypass on`) |
| Encrypted DNS to a public resolver's address (1.1.1.1, 8.8.8.8, Quad9, AdGuard, OpenDNS, Yandex… on `:443`, TCP and QUIC) | refused (with `doh-bypass on`). Android ("Private DNS: automatic") and Chrome switch to encrypted DNS by themselves when the system DNS is 1.1.1.1 or 8.8.8.8, and nearly everything would pass the filter |
| A browser's DoH | the `use-application-dns.net` canary gets NXDOMAIN and known DoH hosts are blocked (with `doh-bypass on`) |
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
ostp dns doh-bypass on|off               # keep browsers from bypassing the filter with their own DoH/DoT
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

Every OSTP TCP listener sniffs the first byte of a connection: raw UoT is handled as always, TLS is terminated with the server's certificate when one is configured, and an HTTP request for the secret upgrade path continues as UoT (this is how nginx/apache/caddy on 443 hand clients to OSTP). Everything else is a decoy: a bare 404, or — with `fallback.enabled` — a transparent splice to `fallback.target` (e.g. a local nginx serving an ordinary site), so an active prober sees a normal website. `fallback.listen` adds one more such listener. Domains, certificates and the built-in HTTPS frontend are covered in [Domains and TLS](tls.md).

---

## Outbound proxy

By default client traffic leaves from the server's own address. With the `outbound` section, some or all of it goes through an upstream SOCKS5 proxy. Rules match on `domain_suffix`, `ip_cidr` and `protocol` and choose `proxy`, `direct` or `block` (`default_action` covers the rest), for example `.onion` to a local Tor and everything else direct. A rule can also set `send_from`, a local source address; the server-wide `bind_ip` is the default.

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
