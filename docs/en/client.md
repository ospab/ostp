# Client

The client takes your applications' traffic, sends it through an encrypted session to the OSTP server and keeps that session alive. It runs as a background process or service (`ostp`, the desktop app, the Android app).

## Config file

The client section of `config.json` (`"mode": "client"`). Fields not listed here are ignored.

| Field | Meaning |
|---|---|
| `server` | `host:port` of the server |
| `access_key` | the user's access key |
| `server_pk` | the server's static public key (base64url, 43 characters), the link's `pk`. With it the profile speaks protocol v6 and the client checks the server; without it, v5 (see [Server key](#server-key-and-protocol-version)) |
| `mtu` | `"auto"` (default) or bytes; see *Packet size* |
| `socks5_bind` | local proxy address, default `127.0.0.1:1088` |
| `tun` | `enable` (TUN instead of proxy mode), `dns` (resolver the TUN mode uses), `kill_switch`. `stack` is read but there is only one stack (`netstack-smoltcp`), so it changes nothing. `wintun_path` and `ipv4_address` are not read; `ostp migrate` deletes them |
| `carrier` (old name `transport`) | what lies under OSTP; see *Carriers* |
| `exclude` | what bypasses the tunnel; see *Exclusions* |
| `mux` | optional extra sessions; see *Multiplexing* |
| `log` | `privacy`: `strict`, `normal` (default) or `debug`; see *Privacy of logs* |
| `debug` | the old switch; `true` means `log.privacy: "debug"` when `log.privacy` is absent |
| `send_hwid` | send a device ID when fetching a subscription; `false` when absent |
| `gui` | kept for the apps, not read by the engine |

With `tun.enable` the client runs in TUN mode, otherwise in proxy mode.

## Server key and protocol version

A profile with `server_pk` speaks protocol v6: the handshake is Noise `NKpsk0`, so only the holder of the server's private key can answer, and the client checks the server by that key. A `server_pk` that is not valid base64url of 32 bytes is an error, never a silent v5 profile. A profile without it speaks v5 (`NNpsk0`), where the server is not verified. The client never switches between the two by itself; if a v6 server does not answer, the error says the server is older than 0.5.0 or its key was replaced. See [specification.md](specification.md).

## Taking traffic

**Local proxy.** One TCP port (`socks5_bind`, default `127.0.0.1:1088`) speaks both protocols and tells them apart by the first byte: `0x05` is SOCKS5 (RFC 1928); anything else is an HTTP proxy (`CONNECT host:port` and plain `GET http://...`).

**System proxy (Windows).** In proxy mode the client writes the system proxy settings (WinINet) in the form browsers expect, `http=127.0.0.1:1088;https=127.0.0.1:1088`, and restores the previous values on a normal stop. On Linux with a desktop session it sets the GNOME or KDE proxy; without a desktop `ostp proxy-env` prints the shell exports instead.

**TUN.** On Windows (Wintun), Linux and macOS the client can create a virtual adapter and take all of the machine's IP traffic. A user-space TCP/IP stack (`netstack-smoltcp`) rebuilds TCP and UDP flows from the packets and feeds them into the session as `RelayMessage`s (see [specification.md](specification.md)). The desktop app creates the adapter in the separate `ostpd` process, so the app itself does not run elevated (see [integrations.md](integrations.md)). `tun.kill_switch` removes the physical default route, so traffic cannot leave outside the tunnel when it drops (Linux and macOS). On Windows it is ignored and the desktop app does not offer it: the blackhole route it used there never took priority over the real default route. A firewall-based kill switch for Windows is planned for 0.5.0.

**Names in TUN mode.** A program in TUN mode connects to an address. The client reads the first bytes of each TCP connection (up to 100 ms, and the whole TLS ClientHello, up to 8 KB) and takes the server name (SNI) from it. The name is used for exclusions and, when the connection goes through the tunnel, it is sent to the server instead of the address, so the server's `outbound` rules by domain apply to it as in proxy mode (see [server.md](server.md)). The server then resolves the name itself and may connect to another address of the same site than the program chose. The address is sent as before when there is no SNI, when the SNI is not a DNS name (an address, a name without a dot), or when the destination is not an internet address (a LAN, 10.1.0.1, 100.64.0.0/10). When the server cannot open the connection by name within 3 seconds (the name does not resolve there, say), the client tries once more by address; when the server's rules refused it (`block`, DNS filtering), it does not. UDP and QUIC are always sent by address; the server matches them by the names it saw for the address. TLS with Encrypted Client Hello (ECH) shows no real name, and plain HTTP and other protocols are sent by address.

**TUN on Windows: what is blocked while connected.** The adapter `ostp_tun` always gets a resolver (`tun.dns`, else `1.1.1.1`) and the lowest interface metric. Windows also asks the resolvers of the other adapters (the router, the provider), often on-link and never routed into the tunnel, so the client adds Windows Firewall rules named `OSTP DNS guard ...`: outbound UDP and TCP to ports 53 and 853 are blocked to every address except the tunnel's resolver, the tunnel subnet `10.1.0.0/24`, loopback and the server. If IPv6 is not carried by the tunnel (the server is reached over IPv6, or the IPv6 routes could not be added), all outbound IPv6 except loopback, link-local, multicast and the server's own address is blocked as well, so it cannot leak. The rules are removed when the tunnel stops and before the next start, so a crashed session leaves them until then (by hand: `netsh advfirewall firewall delete rule name="OSTP DNS guard UDP v4"`, likewise `TCP v4`, `UDP v6`, `TCP v6`, `IPv6 block`). While connected, a lookup of the server's host name (a reconnect) goes through the tunnel's resolver, so with a host name instead of an address a reconnect after a lost path needs the tunnel to be working. Smart multi-homed name resolution is not switched off (it would need a system-wide setting changed and restored); the rules already stop the leak.

## Carriers

OSTP is the transport protocol. What lies under it (UDP, or TCP with optional TLS and an HTTP upgrade) is the *carrier* (see [carriers-design.md](carriers-design.md)). The `carrier` section of the config chooses it, with `mode`:

```json
"carrier": { "mode": "uot", "tls": true, "tls_sni": "vpn.example.com" }
```

New configs (`ostp import`, the setup wizard, the apps) write `carrier`. The old section name `transport` has the same fields and is still read, in old configs and old subscriptions, and nothing rewrites it in your file; if a file has both, `carrier` wins field by field. `ostp://` links keep `type=` as before. (A client older than 0.5.0 ignores `carrier` and falls back to UDP, so a config written by 0.5.0 needs its section renamed back to `transport` to be used by an older client.)

- `udp` (default): one OSTP datagram per UDP datagram, from a single socket kept for the whole session so the NAT mapping stays put.
- `uot`: the same datagrams over one TCP connection, each with a 2-byte length prefix. For networks that block or throttle unknown UDP. Nothing is imitated; the stream is length-prefixed opaque data.
- `uot` with `tls`: UoT inside real TLS to the server's domain, directly on 443 or through nginx/apache/caddy with `ws_path`. The certificate is checked against the Mozilla roots; `tls_insecure` turns that off for testing. See [tls.md](tls.md).

Another option of the `carrier` block: `ttl_desync*` (UDP only, decoy datagrams that expire before the server). `junk_pc`, `junk_ps`, `tcp_fragmentation`, `frag_chunk` and `frag_sleep` were removed in 0.4.7 and are ignored; `ostp migrate` deletes them. Details in [obfuscation.md](obfuscation.md).

There is no STUN/TURN client. Strict NATs are handled by roaming on `session_id` (see [server.md](server.md)) and by the `uot` carrier.

## Silence and recovery

The client does not switch carrier or server on its own; that is the user's choice. Within one carrier it recovers like this:

- When a session has heard nothing authenticated from the server for 10 seconds (or two keepalive intervals, if longer), it moves to a new socket of the same carrier, without a new handshake. With several sessions (`mux`) the quietest one counts.
- If the moved session gets no answer within 4 s or four in-tunnel ping round trips, whichever is longer (at most 30 s), the client checks whether the server answers at all with a full handshake to the same server and carrier. While it does not (the network is down), the session and every open app connection are kept, and the tries alternate between moving the session again and a handshake, after 1, 2, 5, 10, 20 and then every 30 seconds, until one succeeds or the user stops the tunnel. When the network comes back, the kept session is moved and the connections continue; they are reset only if the server no longer knows the session (it keeps an idle one for 10 minutes; the client gives it up after 5).
- After an outage both ends start over on the path (window, round-trip time) and resend what was lost at once, instead of climbing back from the small window the outage left.
- In proxy mode without the kill switch, the system proxy is released after 45 seconds without a connection so the computer keeps internet access, and set again when the tunnel is back. With the kill switch on, it stays set.
- On resume from sleep, or after a network change, recovery starts at once instead of waiting for the timers.
- A first connection that fails (wrong key, address or carrier) is not retried: the tunnel stops and shows the error.

Ordinary TCP errors (`ConnectionReset`, `BrokenPipe`, `UnexpectedEof`) are not written to the log.

Inside a session there is a second, separate check for lost data: if data is in flight and no acknowledgement makes progress for `max(4 x SRTT, 1 s)`, the oldest unacknowledged frame is resent at once. It never reconnects or changes the carrier. On a TCP or TLS carrier nothing is lost on the way and nothing is resent; there a stall is only counted and logged, after 5 s of silence from the server with data queued.

## RTT and queue delay

The apps and `ostp` show two numbers. The RTT is the path's own round trip, measured from acknowledgements by the congestion controller; with several sessions, the lowest. The queue delay is how much longer the in-tunnel ping (`Ping`/`Pong`, which waits behind queued data) takes than that RTT, never below zero. The status line shows `queue=` only when it is above 200 ms. A move leaves the sessions without a sample for a while; the last RTT stays until a new one comes.

## Server information

After each connection, if the server says it supports it, the client asks for the server's information (operator, server, the user's key: usage, limit, expiry, device limit). It travels only inside the tunnel. `ostp_client::app::server_info()` returns the latest JSON and `request_server_info()` asks again; the apps show it in the information window (see [integrations.md](integrations.md#server-info-and-key-expiry)). A key that has expired is closed by the server with reason 6, and the client says so.

## Updates

`ostp update` re-runs the install script for a channel (`--branch stable|beta|alpha`, `--version` for an exact release); `ostp -V` shows the installed version with its channel. The apps check GitHub for a newer stable or beta release (never alpha) and install it only when the user presses the button (see [integrations.md](integrations.md#updates)).

## The app's own requests through the tunnel

The apps make a few requests of their own: refreshing a subscription (to the provider's domain) and the update check and download (to GitHub). Without care they leave from the user's real address, so the provider's network sees the subscription domain and GitHub sees the user. The setting *Use the tunnel for subscriptions and updates* (on by default; Android: *More settings*, *Application*; desktop: *More settings*, *Application*) sends them through the core's local SOCKS5 proxy (`local_proxy.bind_addr` / `socks5_bind`, default `127.0.0.1:1088`; a `0.0.0.0` bind is reached on `127.0.0.1`) while the tunnel is up. The name is sent to the proxy as text (`socks5h`), so it is resolved at the far end of the tunnel, not by the local network.

- Tunnel down: the request goes direct, as before.
- Tunnel up but the request fails (the proxy cannot be reached, or the tunnel cannot reach the host): the app shows the error. It never repeats the request direct, because that would send exactly what the setting hides.
- Setting off: always direct.

`ostp import` and the CLI are not affected; for the library, `ostp_client::subscription::fetch_via` and `ostp_client::updates::check_via` take the proxy.

## Device ID for subscriptions

A server can limit the devices of a subscription (see [tls.md](tls.md), *Device limit*). Sending the device's ID is off by default and has to be turned on: the top-level key `send_hwid` of the client config (`false` when absent), or the switch *Send a device ID to subscriptions* in the apps.

```json
"send_hwid": true
```

Only `ostp import https://…/sub/…` and the apps' subscription fetch use it (`ostp_client::subscription::fetch_with_device`), and only at that moment; the tunnel never sends it. What goes out is the headers `x-hwid`, `x-device-os` (for example `Windows 11`, `Linux`, `macOS`, `Android 14`) and `x-device-model` (the CPU architecture on a computer, `Build.MODEL` on Android; never the computer's name). `x-hwid` is `hex(HMAC-SHA256(key = the system's machine identifier, message = "ostp-hwid:" + the server's host))` cut to 32 characters. The machine identifier is `MachineGuid` on Windows, `IOPlatformUUID` on macOS, `/etc/machine-id` on Linux and `ANDROID_ID` on Android; it is the HMAC key and is never sent or logged. With `send_hwid` off, `ostp import` of a subscription that limits devices stops with a message that says how to turn it on.

## Privacy of logs

`ostp.log` (next to the program; on Android, the app's log screen) follows one setting, `log.privacy` in the client config, the same key as on the server (see [server.md](server.md), *Privacy of logs*):

```json
"log": { "privacy": "normal" }
```

- `normal` (default) and `strict`: no destinations in the log. A line says that a stream opened or a connection bypassed the tunnel, not which site; SNI names, the sites' addresses and the names of excluded domains are not written; the reason a stream failed is its kind (`timed out`, `connection refused`, `name not resolved`...), not the text of the error. The client has no client addresses or DNS query log of its own, so `strict` writes the same as `normal`.
- `debug`: everything, with the destinations. Only when you ask for it (*Log privacy* in the apps, or `"debug": true`, which still means this when `log.privacy` is absent); it does not turn itself off.
- The address of your own server is still written: it is yours.

## Packet size (`mtu`)

`mtu` is `"auto"` or a number of bytes, and a config without it means `"auto"`:

```json
"mtu": "auto"
```

- `"auto"` (default): on a v6 profile over UDP, each side finds by itself how large a datagram the path carries, starting at 1200 bytes and probing 1280, 1350, 1400 and 1452 (see [specification.md](specification.md), *Path MTU discovery*). It also steps down by itself if the path starts to lose large datagrams. Nothing to type in, and nothing to lower when a connection drops over a path with a small MTU. A v5 profile (no `pk`) and a TCP or TLS carrier do not discover anything: they use the size 0.4.x used, 1140 for the client.
- A number (576 to 1500; `1280`): that size, as before, for every profile and carrier.
- The apps: the MTU field is empty for Auto, or holds a number (desktop: Settings, MTU; Android: Settings, MTU (Packet Size)).
- With `auto` the TUN device keeps an MTU of 1140: it is set once, when the tunnel starts.

## Exclusions

The `exclude` block lists what bypasses the tunnel and goes out directly:

- `domains`: domain suffixes such as `["trusted-site.com", "local.lan"]`. Internationalized names work (`пример.рф`); every name is compared in punycode.
- `ips`: networks in CIDR form, such as `["192.168.1.0/24", "10.0.0.0/8"]`.
- `processes`: executable names or parts of them (`["discord", "steam.exe"]`, case-insensitive). All connections of those programs go direct. The client finds the program from the connection's local address in the system socket tables (`GetExtendedTcpTable` / `GetExtendedUdpTable` on Windows, `/proc/net/{tcp,udp}{,6}` on Linux). In TUN mode it uses the packet's source address; in proxy mode, the program's connection to the local proxy, so only programs that use the system proxy are matched. The client's own sockets never match. Not available on Android, which has per-app split tunneling instead.

Changes to `config.json` take effect without a reconnect.

## Multiplexing

Every proxied TCP connection and UDP flow already shares the one encrypted session as `RelayMessage`s (`Connect`, `Data`, `Close`, `UdpAssociate`, `UdpData`), so any number of tabs and downloads fit in it.

The `mux` block is a different, optional thing, available only in the config file: several independent sessions to the same server, each with its own nonce sequence and congestion controller. A stream stays on one session, so a single download gains nothing; in a lab run on a 100 Mbit/s, 80 ms, 0.5% loss path a download took 5.7 Mbit/s without it and 6.9 Mbit/s with 4 sessions, and 40 parallel page objects 4.2 s against 3.3 s. The desktop and Android apps no longer offer it in 0.4.7. Every session also takes a place on the server.

```json
"mux": { "enabled": true, "sessions": 5 }
```

It takes effect only with `enabled: true` and `sessions` above 1.
