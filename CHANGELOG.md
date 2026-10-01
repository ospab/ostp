# Changelog

What changed in each release, newest first. Russian version: [CHANGELOG.ru.md](CHANGELOG.ru.md).
The same text is built into the binary: `ostp changelog` (or `ostp cl`) shows the installed version's changes, `ostp cl --all` shows everything.

Versions are `X.Y.Z` for stable releases and `X.Y.Z-beta.N` / `X.Y.Z-alpha.N` for pre-releases (see [CONTRIBUTING.md](CONTRIBUTING.md#branch-strategy)).
Older history is on the [Releases](https://github.com/ospab/ostp/releases) page and in `git log`.

## [Unreleased]

### Added
- Server: an `overnet` section. With `entry`, clients reach the overnet `.ov` zone through the server: `.ov` connections go to the local overnet gateway over SOCKS5, and in TUN mode the server's DNS gives `.ov` names fake addresses from `198.18.0.0/15` that lead there. `.ov` names never go to the DNS upstreams or the internet, even with the section off. With `exit` (off by default), a loopback-only SOCKS5 listener lets the local overnet node send clearnet traffic out through the server's usual route; the server itself and private networks are refused. No protocol change. See `docs/en/server.md`.

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
