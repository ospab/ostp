# Client

The client takes your applications' traffic, sends it through an encrypted session to the OSTP server and keeps that session alive. It runs as a background process or service (`ostp`, the desktop app, the Android app).

## Taking traffic

**Local proxy.** One TCP port (`socks5_bind`, default `127.0.0.1:1088`) speaks both protocols and tells them apart by the first byte: `0x05` is SOCKS5 (RFC 1928); anything else is an HTTP proxy (`CONNECT host:port` and plain `GET http://...`).

**System proxy (Windows).** In proxy mode the client writes the system proxy settings (WinINet) in the form browsers expect, `http=127.0.0.1:1088;https=127.0.0.1:1088`, and restores the previous values on a normal stop. On Linux with a desktop session it sets the GNOME or KDE proxy; without a desktop `ostp proxy-env` prints the shell exports instead.

**TUN.** On Windows (Wintun), Linux and macOS the client can create a virtual adapter and take all of the machine's IP traffic. A user-space TCP/IP stack (`netstack-smoltcp`) rebuilds TCP and UDP flows from the packets and feeds them into the session as `RelayMessage`s (see [specification.md](specification.md)). The desktop app creates the adapter in the separate `ostpd` process, so the app itself does not run elevated (see [integrations.md](integrations.md)). `tun.kill_switch` removes the physical default route, so traffic cannot leave outside the tunnel when it drops (Linux and macOS). On Windows it is ignored and the desktop app does not offer it: the blackhole route it used there never took priority over the real default route. A firewall-based kill switch for Windows is planned for 0.5.0.

## Transports

`transport.mode` in the config:

- `udp` (default): one OSTP datagram per UDP datagram, from a single socket kept for the whole session so the NAT mapping stays put.
- `uot`: the same datagrams over one TCP connection, each with a 2-byte length prefix. For networks that block or throttle unknown UDP. Nothing is imitated; the stream is length-prefixed opaque data.
- `uot` with `tls`: UoT inside real TLS to the server's domain, directly on 443 or through nginx/apache/caddy with `ws_path`. The certificate is checked against the Mozilla roots; `tls_insecure` turns that off for testing. See [tls.md](tls.md).

Another option of the `transport` block: `ttl_desync*` (UDP only, decoy datagrams that expire before the server). `junk_pc`, `junk_ps`, `tcp_fragmentation`, `frag_chunk` and `frag_sleep` were removed in 0.4.7 and are ignored; `ostp migrate` deletes them. Details in [obfuscation.md](obfuscation.md).

There is no STUN/TURN client. Strict NATs are handled by roaming on `session_id` (see [server.md](server.md)) and by `uot`.

## Silence and recovery

The client does not switch transport or server on its own; that is the user's choice. Within one transport it recovers like this:

- When a session has heard nothing authenticated from the server for 10 seconds (or two keepalive intervals, if longer), it moves to a new socket of the same transport, without a new handshake.
- If the moved session gets no answer within a few round trips, the client checks whether the server answers at all with a full handshake to the same server and transport. While it does not (the network is down), the session and every open app connection are kept, and the tries alternate between moving the session again and a handshake, after 1, 2, 5, 10, 20 and then every 30 seconds, until one succeeds or the user stops the tunnel. When the network comes back, the kept session is moved and the connections continue; they are reset only if the server no longer knows the session (it keeps an idle one for 10 minutes; the client gives it up after 5).
- After an outage both ends start over on the path (window, round-trip time) and resend what was lost at once, instead of climbing back from the small window the outage left.
- In proxy mode without the kill switch, the system proxy is released after 45 seconds without a connection so the computer keeps internet access, and set again when the tunnel is back. With the kill switch on, it stays set.
- On resume from sleep, or after a network change, recovery starts at once instead of waiting for the timers.
- A first connection that fails (wrong key, address or transport) is not retried: the tunnel stops and shows the error.

Ordinary TCP errors (`ConnectionReset`, `BrokenPipe`, `UnexpectedEof`) are not written to the log.

## Device ID for subscriptions

A server can limit the devices of a subscription (see [tls.md](tls.md), *Device limit*). Sending the device's ID is off by default and has to be turned on: the top-level key `send_hwid` of the client config (`false` when absent), or the switch *Send a device ID to subscriptions* in the apps.

```json
"send_hwid": true
```

Only `ostp import https://…/sub/…` and the apps' subscription fetch use it, and only at that moment; the tunnel never sends it. What goes out is the headers `x-hwid`, `x-device-os` (for example `Windows 11`, `Linux`, `macOS`, `Android 14`) and `x-device-model` (the CPU architecture on a computer, `Build.MODEL` on Android; never the computer's name). `x-hwid` is `hex(HMAC-SHA256(key = the system's machine identifier, message = "ostp-hwid:" + the server's host))` cut to 32 characters. The machine identifier is `MachineGuid` on Windows, `IOPlatformUUID` on macOS, `/etc/machine-id` on Linux and `ANDROID_ID` on Android; it is the HMAC key and is never sent or logged. With `send_hwid` off, `ostp import` of a subscription that limits devices stops with a message that says how to turn it on.

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
