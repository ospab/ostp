# Client

The client takes your applications' traffic, sends it through an encrypted session to the OSTP server and keeps that session alive. It runs as a background process or service (`ostp`, the desktop app, the Android app).

## Taking traffic

**Local proxy.** One TCP port (`socks5_bind`, default `127.0.0.1:1088`) speaks both protocols and tells them apart by the first byte: `0x05` is SOCKS5 (RFC 1928); anything else is an HTTP proxy (`CONNECT host:port` and plain `GET http://...`).

**System proxy (Windows).** In proxy mode the client writes the system proxy settings (WinINet) in the form browsers expect, `http=127.0.0.1:1088;https=127.0.0.1:1088`, and restores the previous values on a normal stop. On Linux with a desktop session it sets the GNOME or KDE proxy; without a desktop `ostp proxy-env` prints the shell exports instead.

**TUN.** On Windows (Wintun), Linux and macOS the client can create a virtual adapter and take all of the machine's IP traffic. A user-space TCP/IP stack (`netstack-smoltcp`) rebuilds TCP and UDP flows from the packets and feeds them into the session as `RelayMessage`s (see [specification.md](specification.md)). The desktop app creates the adapter in the separate `ostp-tun-helper` process, so the app itself does not run elevated (see [integrations.md](integrations.md)). `tun.kill_switch` blocks traffic while the tunnel is down.

## Transports

`transport.mode` in the config:

- `udp` (default): one OSTP datagram per UDP datagram, from a single socket kept for the whole session so the NAT mapping stays put.
- `uot`: the same datagrams over one TCP connection, each with a 2-byte length prefix. For networks that block or throttle unknown UDP. Nothing is imitated; the stream is length-prefixed opaque data.
- `uot` with `tls`: UoT inside real TLS to the server's domain, directly on 443 or through nginx/apache/caddy with `ws_path`. The certificate is checked against the Mozilla roots; `tls_insecure` turns that off for testing. See [tls.md](tls.md).

Other options of the `transport` block: `junk_pc` / `junk_ps` (count and size range of random datagrams sent before the handshake), `tcp_fragmentation` / `frag_chunk` / `frag_sleep` (the first TCP segment, which holds the handshake, is split into small pieces with short pauses) and `ttl_desync*` (UDP only, decoy datagrams that expire before the server). Details in [obfuscation.md](obfuscation.md).

There is no STUN/TURN client. Strict NATs are handled by roaming on `session_id` (see [server.md](server.md)) and by `uot`.

## Silence and recovery

The client does not switch transport or server on its own; that is the user's choice. Within one transport it recovers like this:

- After 10 seconds without a valid datagram the session moves to a new socket of the same transport, without a new handshake.
- After 25 seconds a background reconnect starts while the old session stays usable.
- After 180 seconds in total the tunnel stops. With the kill switch on, the client keeps retrying instead of letting traffic out unprotected.
- On resume from sleep, or after a network change, the reconnect starts at once instead of waiting for the timers.

Ordinary TCP errors (`ConnectionReset`, `BrokenPipe`, `UnexpectedEof`) are not written to the log.

## Exclusions

The `exclude` block lists what bypasses the tunnel and goes out directly:

- `domains`: domain suffixes such as `["trusted-site.com", "local.lan"]`. Internationalized names work (`пример.рф`); every name is compared in punycode.
- `ips`: networks in CIDR form, such as `["192.168.1.0/24", "10.0.0.0/8"]`.
- `processes`: executable names or parts of them (`["discord", "steam.exe"]`, case-insensitive). All connections of those programs go direct. The client finds the program from the connection's local address in the system socket tables (`GetExtendedTcpTable` / `GetExtendedUdpTable` on Windows, `/proc/net/{tcp,udp}{,6}` on Linux). In TUN mode it uses the packet's source address; in proxy mode, the program's connection to the local proxy, so only programs that use the system proxy are matched. The client's own sockets never match. Not available on Android, which has per-app split tunneling instead.

Changes to `config.json` take effect without a reconnect.

## Multiplexing

Every proxied TCP connection and UDP flow already shares the one encrypted session as `RelayMessage`s (`Connect`, `Data`, `Close`, `UdpAssociate`, `UdpData`), so any number of tabs and downloads fit in it.

The `mux` block is a different, optional thing: several independent sessions to the same server, to spread traffic and loss over separate nonce sequences and congestion controllers.

```json
"mux": { "enabled": true, "sessions": 5 }
```

It takes effect only with `enabled: true` and `sessions` above 1.
