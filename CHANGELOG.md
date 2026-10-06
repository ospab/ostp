# Changelog

What changed in each release, newest first. Russian version: [CHANGELOG.ru.md](CHANGELOG.ru.md).
The same text is built into the binary: `ostp changelog` (or `ostp cl`) shows the installed version's changes, `ostp cl --all` shows everything.

Versions are `X.Y.Z` for stable releases and `X.Y.Z-beta.N` / `X.Y.Z-alpha.N` for pre-releases (see [CONTRIBUTING.md](CONTRIBUTING.md#branch-strategy)).
Older history is on the [Releases](https://github.com/ospab/ostp/releases) page and in `git log`.

## [Unreleased]

### Fixed
- 0.4.7-beta.6 did not build for 32-bit MIPS routers (`AtomicI64`); that release has no mipsel binary.

## [0.4.7-beta.6] - 2026-10-06

### Fixed
Speed: things that slowed transfers down on purpose or by mistake.
- The server stopped sending to a client for the rest of a 10 ms tick whenever its pacing bucket happened to be empty at the moment the tick looked, although the bucket refills in microseconds; on a fast link that was most ticks. Readers now get a budget for the whole tick, refreshed on every ACK as well, and are woken at once instead of polling every 5 ms.
- The window grew like Reno, one packet per round trip, and lost 30% on every gap: with any random loss on the path it stayed around a hundred packets, tens of Mbit/s on a 300 Mbit/s line. It now follows CUBIC (RFC 9438), the algorithm of Linux, Windows and QUIC, which climbs back to its previous size in seconds.
- Several frames lost from one burst each cut the window again; a standing queue halved it on every ACK until the smoothed RTT came down. Each is now one reduction per round trip.
- The window was capped at 1,024 packets (1.4 MB), ~275 Mbit/s at 40 ms and ~180 Mbit/s at 60 ms however fast the line. The cap is 8,192 packets now, 1 Gbit/s at 90 ms.
- The client's upload waited for the next event, up to 10 ms, when the window had room but the pacing bucket was momentarily empty. It now wakes when the next packet is allowed.
- The server read from websites 4 KiB at a time (three full datagrams and a short one per read); it now reads up to 64 KiB, as much as the session may send.
- Up to 64 retransmissions per 10 ms: after a network change a large window took more than a second to resend. Up to 512 now, paced.
- The server formatted a log line and sent two events nobody read for every data packet.

## [0.4.7-beta.5] - 2026-10-06

The tags v0.4.7-beta.3 and v0.4.7-beta.4 were never released (a test failed in CI); their changes are all here.

### Security
- Clients could connect to any service on the server itself (databases, admin interfaces on 127.0.0.1) and to private networks and the cloud metadata service (169.254.169.254, with the instance's credentials). Now the server's loopback is open to clients only for the panel and DNS, private networks are closed, link-local and reserved ranges always. Checked after name resolution, for TCP and UDP. **A server on a home router that let clients into its LAN needs `"local_access": true` in the config.**
- About 100 garbage datagrams a second from anywhere were enough to keep new clients and roaming clients from connecting. The limits are per source now, and addresses that authenticated in the last day skip the server-wide one.
- One access key could hold all 1,024 sessions and every file descriptor. Now at most 32 sessions per key (a new one drops the oldest) and 4,096 open connections.
- Panel: the password is stored salted (PBKDF2-HMAC-SHA256) instead of a bare SHA-256; an old hash still signs in, and `ostp panel status` asks to set the password again. Failed sign-ins are limited to 10 a minute. `ostp panel enable` picks a random path, and the HTTPS site no longer serves the panel at the default `/panel/`, where it gave the server away to anyone probing it. The setup wizard no longer opens the panel to the internet over plain HTTP (`127.0.0.1` now). The API no longer allows requests from any web origin (CORS).
- Desktop apps (Windows, Linux, macOS): IPv6 went past the tunnel with the user's real address on dual-stack networks. It is routed through the tunnel now, as on Android, unless the server itself is reached over IPv6.
- Removed an unused key generator that made predictable keys from the current time.

### Fixed
- Out-of-order packets were treated as lost: the receiver asked for a frame again the moment a later one arrived first, so the sender retransmitted it and shrank its window although nothing was lost. With 1% of packets reordered (common on Wi-Fi, LTE and multipath routes) a download ran at less than half speed. A gap is now asked for only after a quarter of the RTT; when a frame turns out to have been merely late, that wait grows. In a simulated 40 ms path with 1% reordering: 2.2 to 4.9 Mbit/s, retransmissions from 23 to 2. No protocol change.
- Large uploads from the client corrupted the stream or broke the connection. Data read from a local app (up to 64 KiB at a time) went out as one datagram: over UDP a burst of IP fragments, which many networks drop and where one lost fragment loses the whole datagram; past 65,535 bytes the payload was silently cut and, over TCP and TLS, the length prefix overflowed. The server's downloads went out in 4 KiB datagrams, three fragments each. Both sides now split data into datagrams that fit the configured MTU.
- The congestion controller compared every RTT with a 30 ms guess until a real minimum replaced it, which on paths slower than 30 ms took up to 10 seconds; it could read a normal path as a standing queue and leave slow start early. The first measured RTT now sets the minimum.
- Our own ACKs being acknowledged fed the RTT estimate and the window, although they carry no data and wait for whatever the peer sends next; a download-only side could see seconds-long "RTT". Only data frames count now.
- A replayed or forged copy of an old frame got an ACK, and one far ahead got a NACK, per packet and before it was authenticated. Both are now answered only once they authenticate, at most every 10 ms.
- Retransmissions are paced like new data instead of going out in a burst on top of the rate limit, and the in-flight byte count no longer drifts on losses and on frames the sender gave up on.
- Padding left datagrams up to 2 bytes over the MTU (the overhead was counted as 38 bytes instead of 40).
- Server: a client's DNS query that missed the cache stopped every packet of every client until the upstream answered (up to 4 s per resolver), and so did setting up UDP for a client through an outbound SOCKS5 proxy. Both run in the background now.
- After a side sent Close, everything the peer sent was dropped: the ACK for the Close, data still in flight and the peer's own Close. The session waited for the idle timeout instead of ending; it now ends once its Close is acknowledged.
- The reorder buffer kept up to 8,192 frames a session (about 11 MB). It is bounded by two congestion windows (2,048 frames) now, more than any real reordering or loss leaves waiting.

## [0.4.7-beta.2] - 2026-10-04

### Added
- `ostp overnet`: `install` (overnet's own installer with the gateway role), `enable`, `disable`, `exit on|off`, `status`. The section is still off until the owner turns it on; nothing installs by itself.
- overnet in the web panel (an overnet page, applied live without a restart) and in the desktop and mobile apps (the server's management tab: install the gateway, turn `.ov` and the exit on and off). `ostp check` shows the section.
- Config schema v3: `ostp migrate` writes the `overnet` section, switched off, into an older server config. Client configs have nothing to migrate and no longer get the hint.

### Fixed
- `.ov` did not open in Chrome, Edge or on Android even with the gateway running: with the system DNS at 1.1.1.1 or 8.8.8.8 they switch to their own encrypted DNS, which asks the internet about `.ov`. While `.ov` is served, encrypted DNS to public resolvers is refused, so they fall back to port 53, which the server answers.
- 0.4.7-beta.1 did not build for 32-bit MIPS (`AtomicU64`).

## [0.4.7-beta.1] - 2026-10-04

### Added
- Server: an `overnet` section. With `entry`, clients reach the overnet `.ov` zone through the server: `.ov` connections go to the local overnet gateway over SOCKS5, and in TUN mode the server's DNS gives `.ov` names fake addresses from `198.18.0.0/15` that lead there. `.ov` names never go to the DNS upstreams or the internet, even with the section off. With `exit` (off by default), a loopback-only SOCKS5 listener lets the local overnet node send clearnet traffic out through the server's usual route; the server itself and private networks are refused. No protocol change. See `docs/en/server.md`.

### Fixed
- TLS and UDP-over-TCP: downloads went in bursts with 20–30 s pauses. Over a TCP carrier the protocol still resent frames on its 100 ms timer: the timer measured the queue in front of the TCP socket, fired while frames were merely queued, and every duplicate lengthened that queue (TCP over TCP), until the server's per-client queue overflowed and dropped frames. On TCP carriers frames are now resent only when the peer reports a gap, after the session moved to another connection, or after 5 s unacknowledged. A frame dropped from a full queue is logged instead of disappearing silently.
- Repeated NACKs for the same missing frame each cut the sender's window by 0.7, down to the minimum for a single loss; only the first NACK of a gap counts now.
- overnet: with entry on and the gateway not running, the server's DNS still handed out 198.18.0.0/15 addresses for `.ov`, so `overnet browser` assumed `.ov` was served and the sites did not open. The gateway is now checked every 5 s; while it is down, `.ov` is refused as with entry off.

## [0.4.6] - 2026-09-29

The stable 0.4.6: everything from the betas below. In short:
- TLS on port 443, directly or behind nginx, Apache or Caddy, with `ostp cert` for the domain and certificate.
- Subscriptions in the CLI, the desktop app and Android.
- Seamless roaming: a network change no longer drops the session.
- Your own server from the desktop and Android apps: installed and managed over SSH, no Linux knowledge needed.
- A filtering DNS resolver on the server (`ostp dns`) and a new web panel.
- Wire-compatible with 0.4.5: old clients and servers keep working with new ones.

### Fixed
- `install.sh -b beta` (and `-b alpha`), which the apps also run to install or update a server, took the first tag the GitHub API listed instead of the newest version: it installed v0.4.6-beta.9 after beta.10 was out. It now picks the highest version of the channel.

## [0.4.6-beta.10] - 2026-09-28

### Changed
- Server: per-user traffic, the DNS counters and the DNS query log survive restarts and updates. Traffic is read back from `.ostp_stats.json` on start and written on a clean stop too; DNS activity is kept in `.ostp_dns_activity.json` next to the config (root-only; "Clear" in the panel empties it). A restart no longer resets traffic limits.
- Release builds: the desktop and Android packages reuse compiled dependencies (a cache warmed on master; a release tag could never read the old per-tag caches), and the Windows app is compiled once for both the installer and the portable zip.

## [0.4.6-beta.9] - 2026-09-28

### Changed
- Desktop and Android: the settings screen keeps profiles, subscriptions and the connection; exclusions, app options, obfuscation (desktop), logs (Android), server management and updates moved to "More settings".
- First-run screen, desktop and Android: four choices — a link, a QR code, your own server, the project on GitHub. On the desktop the QR code is read from a picture: choose a file, drop it on the window or paste a screenshot with Ctrl+V.
- Web panel: the DNS query log shows the newest 25 entries instead of 150; "Show more" loads 50 more at a time.
- Adding a server that already runs OSTP no longer updates it on its own: the app asks whether to add it as it is or to update it.
- Adding a user to the app from Server management asks how: as a subscription (follows the server's changes) or as fixed profiles. Right after a user is created the app offers the same, with "Not now" for users meant for someone else.

### Fixed
- Web panel and API: a user's "Sessions" counted every connection since the server started (69 for one person) and a user counted as online forever after the first one. It is now the sessions alive right now. The client tells the server when it disconnects, so the server frees the session at once instead of after 10 idle minutes; with an older client the session still closes on that timeout.
- Desktop app: Server management failed with "Command servers_list not allowed by ACL"; the server commands were missing from the app's permissions.
- The same SSH login added twice (a retried install, the first-run screen after "Add server") no longer shows up twice in the servers list; a changed host key is refused instead of being saved over the old one.
- A subscription added for a server whose profiles were already in the app no longer leaves duplicates: the hand-added profiles it covers are replaced by the subscription's.
- The web panel address through the VPN and "Open the panel" missed the path when no webpath was set (`http://10.1.0.1:9090/` instead of `/panel/`). `ostp manage status` now reports the path the panel is served at.

## [0.4.6-beta.8] - 2026-09-27

### Added
- Desktop app: a first-run screen. Add a link or subscription, or install OSTP on your own VPS over SSH (password or private key) with live progress; the new server's connection is added to the app.
- Desktop app: *Settings → Server management*. Per server: status (service, sessions, load, memory, disk; restart, update), users (add, rename, revoke, traffic, add to the app, share as QR), connection (TLS domain and certificate, subscriptions), management (web panel opened through the SSH connection, server log, reboot, uninstall).
- Android: the same first-run screen (link, QR, subscription or your own server over SSH) and *Settings → Server Management*; saved SSH secrets are sealed under a key wrapped by the Android Keystore; the panel opens in an in-app browser tab.
- Both apps show the web panel's address through the VPN (`http://10.1.0.1:<port>/<path>/`), which opens in any browser on a device connected through that server.
- Documentation: what is public and what is secret in OSTP (Kerckhoffs's principle).
- `ostp manage`: server state and user changes as JSON, what the app runs over SSH. `install.sh -y` installs without questions.
- The server writes per-user traffic to `.ostp_stats.json` next to the config every 30 seconds.

### Fixed
- Web panel on phones: no sideways scrolling; users are shown as cards.

## [0.4.6-beta.7] - 2026-09-27

### Changed
- The management API and web panel do not start without a sign-in (a name and password, or an API token). Before, a config without one served an open panel, and loopback was no protection: every client reaches the server's 127.0.0.1 through the tunnel. Set one with `ostp panel on`.
- The desktop app has one dark theme; the light theme and its switch are gone.
- The desktop app no longer has the "auto-connect" button that tried transports and MTUs one after another; pick them in the profile.
- TLS through a web server: nginx and Apache close a connection after 5 minutes of silence instead of a day.

### Fixed
- Security: an empty `api.token` (what `ostp init server` writes) let a request with an empty `Authorization` header use the API.
- Excluded programs work: in proxy mode (they were never checked there), in TUN mode on Linux (only Windows checked them), on Windows for IPv6 connections and for programs the old lookup could not open.
- Excluded domains with non-Latin names (`пример.рф`) match: they are compared in punycode, as DNS, TLS and browsers send them.
- Server: a TCP or TLS connection that sends nothing for 5 minutes is closed. Dead connections used to stay open until the kernel noticed.

## [0.4.6-beta.6] - 2026-09-27

### Added
- `ostp changelog` (`ostp cl`): shows what changed in the installed version; `--all`, `--last N`, `--version X` and `--lang en|ru`.
- This changelog, `SECURITY.md`, issue and pull request templates, and a documentation index in `docs/README.md`.

### Changed
- README (English and Russian) rewritten to match what the code actually does, with the current command list.
- CONTRIBUTING: real project structure, no references to files on a developer's disk.
- The wiki rewritten against the code: false claims removed, the TLS transport, subscriptions, panel, DNS and roaming described, and an honest section on limitations.

### Fixed
- `ostp.wiki` is a proper submodule again (`.gitmodules` was missing).

## [0.4.6-beta.5] - 2026-09-27

### Added
- Seamless roaming: on a network change, after 10 s without an answer, or when the TCP connection is reset, the client moves the session to a new socket of the same transport. No new handshake, and the apps' connections stay open. A move that gets no answer is reported in the log; the transport is never switched on its own.
- `ostp panel status` shows the panel's address through the tunnel.
- `ostp.log` keeps the previous connection's log next to the current one.

### Fixed
- TLS: with an empty `tls_sni`, the server's name from the address is used for SNI and the `Host` header instead of the resolved IP. The IP made the certificate check fail ("certificate not valid for name") and the web server answer with its default site ("HTTP 200 OK, not an OSTP upgrade answer").
- TLS: a dropped connection is now closed. Every failed handshake or reconnect used to leave one TLS connection open; behind nginx this exhausted its worker connections and every request, subscriptions included, got HTTP 500.
- UDP: the server answers from the socket the client reached. With `127.0.0.1` listed first in `listen` (for a web server in front) every UDP handshake was accepted and never answered.
- Server: a session moves to a new client address only on an authenticated packet with a fresh nonce. A replayed or forged packet from another address used to redirect the session's traffic.
- Client: only an authenticated packet counts as a sign of life, so garbage or duplicates no longer hide a dead connection.
- Client: stops after the first failed session and tells a UDP drop apart from a dead server.
- The server's own tunnel address (10.1.0.1) always connects directly.
- DNS: encrypted DNS to public resolvers' addresses is refused, so it cannot bypass the server's DNS filtering.

## [0.4.6-beta.4] - 2026-09-25

### Added
- `ostp-dns`: a filtering DNS resolver on the server with block lists, rules, rewrites and a cache; managed with `ostp dns` and on a new panel page. Connections by name go through it too.
- The panel generates an access key when a user is added.

### Fixed
- The web-server manifest lost the site when it was rewritten.

## [0.4.6-beta.3] - 2026-09-24

### Added
- Update check for the stable and beta channels, on app start (can be turned off in the Android settings).
- Android: share a subscription as a QR code or link.
- `ostp panel`: turn the web panel and API on or off, set its address, path, sign-in and API token.
- Subscription page for people who open a subscription link in a browser; it picks the language and theme on its own.
- Apps group subscription profiles under their subscription and show the SNI.
- Network prober: locates censorship equipment by TTL; checks for foreign-hosting blocks, freezes, QUIC and the path.
- `ostp cert issue` and `ostp sub` restart the running service.

### Fixed
- Windows TUN: looking up the interface by name always failed.
- The nginx site file is named `ostp-<domain>.conf`.

## [0.4.6-beta.2] - 2026-09-24

### Added
- `ostp sub` manages subscriptions separately; `ostp cert issue` no longer turns them on.

### Fixed
- TLS through a web server: a clear diagnosis for 502, rate limiting, fragmentation.
- Debian: the nginx site goes to `sites-available` with a link in `sites-enabled`.

## [0.4.6-beta.1] - 2026-09-24

### Added
- TLS and HTTP-upgrade carrier: OSTP can be reached over real TLS on port 443, directly or through nginx, Apache or Caddy on a secret path.
- `ostp cert issue|status|renew`: a domain and a Let's Encrypt certificate with automatic renewal and web-server integration; a built-in HTTPS frontend when no web server is used.
- Subscriptions: per-user subscription URLs on the server, import in the CLI, desktop and Android apps; `ostp links qr`.
- A new built-in web panel.
- Versioned config schema and a real migrator (`ostp migrate`).
- Share links carry the TLS settings; the apps have TLS profile options.
- The network prober checks TLS profiles.

### Fixed
- The per-IP UoT connection limiter is pruned.
- The relay no longer panics when a new UDP session dies before its first send.

## [0.4.5] - 2026-09-23

### Added
- Network prober (CLI and Android): tries every transport against the server and locates DPI/TSPU by TTL; a generic DPI fingerprint battery.
- Opt-in TTL-desync decoys on the UDP handshake, with automatic hop calibration; switches in the desktop and Android apps.
- Multi-address egress on the server: a global source IP and per-rule `send_from`; the setup wizard offers the server's addresses.
- SOCKS5 username and password for the upstream proxy.
- The config migrator normalizes any config to a clean, canonical form.
- Debug mode shows non-OSTP bytes received, to diagnose DPI interference.

### Fixed
- Android: asks for a battery-optimization exemption so Doze cannot freeze the VPN.
- TUN: IPv4 fragments are reassembled, so large UDP packets (games) are not dropped; routing no longer fails on connect under load.
- More resilient UDP handshake on lossy mobile links.
- Windows: installer and helper-task fixes (permissions, config location).
