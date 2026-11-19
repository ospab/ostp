# Changelog

What changed in each release, newest first. Russian version: [CHANGELOG.ru.md](CHANGELOG.ru.md).
The same text is built into the binary: `ostp changelog` (or `ostp cl`) shows the installed version's changes, `ostp cl --all` shows everything.

Versions are `X.Y.Z` for stable releases and `X.Y.Z-beta.N` / `X.Y.Z-alpha.N` for pre-releases (see [CONTRIBUTING.md](CONTRIBUTING.md#branch-strategy)).
Older history is on the [Releases](https://github.com/ospab/ostp/releases) page and in `git log`.

## [Unreleased]

### Fixed
- TLS and TCP carriers: the server let the queue toward one client grow to about 15,000 frames (20 MB), and the kernel socket buffer added megabytes more. On a byte stream OSTP sees no loss and its delay signal is off, so nothing held that back: on a link of a few Mbit/s the queue was tens of seconds long, and everything behind it waited that long. The apps' RTT (a ping inside the tunnel) read up to 50 s, and videos froze about a minute in. Now the server measures how fast each TCP/TLS connection drains while frames wait, and lets the queue hold about 100 ms of that rate (at least 64 frames; about 1 MB before the first measurement). On Linux the socket keeps at most 128 KiB unsent in the kernel (`TCP_NOTSENT_LOWAT`). UDP clients are not affected. Tests: the rate counts only time when frames waited, the queue limit follows the rate, a newer connection from the same address keeps its own measurement. Not yet measured on a real slow link.

### Changed
- The RTT the apps and the CLI show is now the network path's own round trip, taken from the congestion controller (the smoothed RTT of ACKs of frames never resent, `ProtocolMachine::path_rtt`; with several sessions, the best live one). It used to be the in-tunnel ping, which waits behind every data frame queued ahead of it and so measured the queue as much as the network. The in-tunnel ping stays as a second number, the queue delay (in-tunnel RTT minus path RTT, never negative): the apps show it next to the RTT when it is above 200 ms (`42 ms · queue 1.8 s`; the CLI status line, the Android home screen, the desktop app). `BridgeMetrics` and `UiEvent::Metrics` carry both (`queue_ms` is new; the Android metrics JSON, the desktop `get_metrics` and the `ostpd` helper messages gained it, an older helper without it reads as 0). On a reliable carrier (TLS, UoT) the path RTT includes the TCP connection's own queue: that is the delay a frame really has there. Tests: the controller's RTT is unknown until a real sample, follows samples and is forgotten with the path; best live session, queue delay never negative, the status line; an end-to-end check that a v6 session publishes a path RTT and a small queue delay when idle.
- `ostp -V`, the setup wizard, the log header, the server status the apps show and the desktop tray say the release with its channel (`0.5.0-alpha.3`, `0.5.0-beta.1`) instead of the bare `0.5.0` shared by every alpha and beta.

## [0.5.0-alpha.3] - 2026-11-17

### Added
- `ostp manage user-set USER [--name N] [--limit-bytes N] [--devices N]` changes a user's name and limits in one write; an option left out keeps its value, 0 removes a limit. `ostp manage user-add` takes `--key`, `--limit-bytes` and `--devices`, so a user is created with everything at once. The apps may run `user-set`.
- Apps, server management, Users: a tap (Android) or click (desktop) on a user opens its settings: name, traffic limit in GB, device limit, the access key, subscription and links to copy, traffic, online state, the devices that fetched the subscription, Add to this app, Share and Revoke. Add opens the same form empty: the name (marked *) is required; the access key may be pasted or left empty for a random one; limits are optional. The field above the list searches users by name. A change is saved with one `ostp manage` call; against a server too old for `user-set` or the new `user-add` options the app says to update OSTP on the server.

### Changed
- `ostp manage` answers a person at a terminal in text, like the other commands (a table of users, `✓ pops: at most 1 device(s) on the subscription`, `[error] ...`), and prints JSON as before when there is no terminal, which is how the apps run it over SSH; `--json` asks for JSON at a terminal too. The command is listed in `ostp --help`.
- `ostp manage` names the users when none matches what was given (`no user matches user1. Users: #1, pops`).

### Fixed
- Desktop app, server DNS: the empty upstream list showed a broken character instead of a dash (`servers.js` had one Windows-1252 byte; the file is UTF-8 again).
- Desktop app: reading a user's devices or the DNS settings no longer counts as a change, so it does not block a change on the same server.

## [0.5.0-alpha.2] - 2026-11-17

### Added
- Protocol v6, session layer, stage 2 follow-up: a real TCP RST on a TUN flow. When the stream to the server is reset or aborted, the program's TUN connection now gets a RST instead of the FIN a normal close sends, so a truncated download fails instead of looking complete. The `netstack-smoltcp` crate cannot abort a flow, so the tree carries a copy of it (`third_party/netstack-smoltcp`, version 0.2.4, MIT OR Apache-2.0, used through `[patch.crates-io]` in the root workspace and in the desktop app's) with a `TcpStream::abort`; its README lists the one change. The TUN bridge aborts the flow only when the local SOCKS connection ends with a connection reset; a normal end, and an error on the program's side alone, behave as before. Tests: in the crate, abort emits a RST and no FIN, a drop or `shutdown` emits a FIN and no RST (IPv4 and IPv6, raw packets through the stack); in the client, the bridge aborts on a reset and only on a reset. A whole run through a real TUN device is not covered. See `docs/en/v6-session-design.md`.

### Fixed
- `ostp init server|client` and `ostp setup` replaced an existing config with a new one holding a single fresh access key, with no question and no copy: every user of the old keys was cut off. Now `init` leaves an existing config alone and says so unless given `--force`; `setup` names the file and how many access keys it holds and asks before going on. When the config is replaced, a copy is kept first as `config.json.<unix time>.bak`, which a later run never overwrites (the single `config.json.bak` was overwritten by the next change). When the setup wizard cannot write the config and falls back to `config.json` in the current folder, it no longer overwrites a file already there. To add keys to a config, use `ostp key gen --add`.
- Builds of 0.5.0-alpha.1 reported themselves as 0.4.8-beta.2 (the mobile app's version line, `ostp update`, the release channel the apps install servers from), because `.release-state.json` was not updated for the release. The release workflow now refuses a tag that this file does not describe.
- `ostp check` printed the listen address as `ColoredString { ... }`.
- Tests: a server in the transitional mode (a server key and `accept_v5`) gives no handshake reply to a v5 or v6 client whose key is not in `access_keys`, and a removed v5 key cannot open a new session.

## [0.5.0-alpha.1] - 2026-11-16

### Added
- Protocol v6, session layer, stage 3 (core, server, client, apps; v6 sessions only, a v5 session and the transitional server's v5 client are unchanged): the session `Close` with a reason. The server sends a session that passed authentication a `Close` (stream 0) with a reason byte and an optional text of up to 64 bytes, then forgets it: 2 the key was removed from the config on hot reload, 3 the traffic limit is used up, 4 too many sessions for the key (the oldest is dropped), 5 the server is stopping. The `Close` is resent until the client acknowledges it (at most 5 s); the stop signal now sends the `Close` frames first and waits up to 1.5 s for the acknowledgements. `systemctl stop` and `restart` are the same to the process (both SIGTERM), so 5 is always sent; reason 1 ("the server is restarting") is in the format but nothing sends it yet. Idle expiry, bad frames and packets of unknown sessions still get nothing. On a `Close` the client stops at once (no 10 s of silence), does not reconnect by itself, does not take the failure path, and says the reason in plain words with what to do ("The server closed the connection: your key was revoked or removed. Ask the server owner for a new key."): the banner in the desktop app, the notice in the Android app (`stop_reason` in the JNI metrics). A client that stops sends `Close` with reason 0, and the server frees the session at once instead of after 10 minutes of idle time. Tests: `Close` with each reason in the core, a lost `Close` is resent, v5 never sends one; server: key, limit, per-key cap, shutdown; end to end in `ostp/tests/v6_wire.rs`: after the key is removed the client stops less than a second after the server dropped the session, names the reason and does not reconnect; a client stop frees the server's session at once. See `docs/en/v6-session-design.md`.
- Protocol v6, session layer, stage 2 (server and client, v6 sessions only; a v5 session, including one served by the transitional server, is unchanged): stream ids are 32-bit and come from `StreamIds` (the client's odd ids, at most 1024 open; at the limit a new connection is refused at once with `too many open streams` in the log and a SOCKS error, never left hanging); a stream that is over on both sides is released, so a session no longer stops taking streams after 2048 (a test runs 3200 in one session); a program's end of stream (TCP FIN) is a half-close, `Fin` (relay tag 13), and the reply still arrives, where the stream used to be closed and the reply lost; `Close` is the abort and carries a reason byte; UDP goes in unsequenced `Datagram` frames in both directions, so a datagram lost on the path is lost, not resent (the test blacks the path out, and the datagram sent in it is never delivered, while stream data sent in it is); a reset stream (`StreamReset`, also from the retransmit tick, which used to be dropped) resets the program's SOCKS connection (a TCP RST) and closes the server's target; a reset of stream 0 ends the session; per-stream flow control is part of every v6 stream without the `Features` exchange, and the server's 32 MiB queued-upload reset does not apply to them. Not done: a TCP RST on a TUN flow (the netstack crate cannot abort a flow); see `docs/en/v6-session-design.md`.
- Protocol v6, session layer, stage 1 (`ostp-core`; the server and client do not use it yet, see `docs/en/v6-session-design.md`): a 16-byte frame header with 32-bit stream ids and a `stream_seq`; delivery order per stream, so a loss in one stream no longer holds the others; an unsequenced, never-resent `Datagram` frame for UDP that still counts against the congestion window; a frame the sender gives up on resets only its stream (`StreamReset`, `lost`, carried by a new `Abandon` frame) instead of the receiver skipping the hole; stream id rules (client odd, server even, never reused, at most 1024 open). v5 sessions are unchanged.
- Protocol v6, first part: the client checks the server. The server has a static key (config section `protocol`: `server_key`, the private key, and `accept_v5`); its public half is the `pk` field of `ostp://` links and subscriptions. A profile with `pk` speaks v6 (`Noise NKpsk0`, a masked handshake); a profile without it speaks v5 exactly as before, and a server without a key serves v5 only. The client never switches between them by itself.
- `ostp key` family (server): `ostp key` shows the server's public key, whether legacy clients (older than 0.5.0) are accepted and how many access keys the config has; `ostp key gen [-n N] [--format hex|base64]` prints new access keys and changes nothing (`--add` also appends them to `access_keys` of the server config); `ostp key server` prints the public key alone, `ostp key server new` creates the key or replaces it (replacing needs `--yes` and makes every link and subscription issued so far stop working); `ostp key legacy on|off` keeps or ends the transitional mode in which a server with a key still accepts clients older than 0.5.0 (config field `protocol.accept_v5`, `true` on new installs). A new install creates a key; an existing server gets one only through `ostp key server new`. There is no schema bump and `ostp migrate` does not touch the `protocol` section: a config without it is a server with no key, which speaks the old handshake only, as before. The private key is never printed; a change restarts the service like the other `ostp` commands (`--no-restart` skips it), and the server reads these settings at start (the hot reload covers access keys only). `ostp gk` and `ostp generate-key` stay as hidden aliases of `ostp key gen`, so existing scripts keep working.
- v6 secrets (the PSK, the obfuscation key, the padding range and the keys of the handshake's outer layer) are derived with HKDF-SHA256 (RFC 5869) and public labels instead of the v5-style salt and info taken from the hash of the access key. The v5 derivation is unchanged, so 0.4.x peers are unaffected; a fixed test vector pins the v6 outputs.
- A v6 profile that gets no answer to its handshake now says why: the server is older than 0.5.0 or its key was replaced, so the link has to be reissued, instead of a bare timeout.
- Log privacy: one setting, `log.privacy`, on the server and the client: `strict`, `normal` (the default) or `debug`. In `normal` no log gets destinations (hosts and ports of sites, SNI and DNS names, relay targets), and on the server a client's address is cut to its /24 network (IPv6: /48). `strict` is the same, and a client's address becomes a tag, an HMAC with a random salt that changes every day (UTC) and is held in memory only (the same client has one tag for a day, and nothing links two days); the DNS query log is not kept at all (only the totals stay). `debug` writes everything, as the old `debug` did, only on explicit request; it never turns itself off and clients are not told. Billing data (per-user traffic, last seen, devices and limits) is untouched. The `Relay error: CONNECT failed` line no longer names the target: it says which stream and what kind of error (`timed out`, `name not resolved`...). `ostp log privacy [strict|normal|debug] [--no-restart]` shows or sets the mode (`ostp log` still shows the log); the desktop and Android apps have a *Log privacy* choice for the client's own log in place of the "Debug" switch; the panel shows the server's mode on the overview, read-only. The old `debug: true` and `log_level` keep working: without `log.privacy`, `debug: true` means `debug`. See docs/en/server.md, *Privacy of logs*.

### Changed
- "Carrier" instead of "transport" for what lies under OSTP (UDP, UoT/TCP with optional TLS and HTTP upgrade; later WebSocket and QUIC): OSTP itself is the transport protocol. The client config section is now `carrier` (same fields: `mode`, `tls`, `tls_sni`, `tls_insecure`, `ws_path`, `ttl_desync*`); new configs (`ostp import`, the setup wizard, the apps) write it. The old `transport` section is still read, in old configs and subscriptions; nothing rewrites your file and there is no schema bump (if both exist, `carrier` wins field by field). `type=` in `ostp://` links is unchanged. A client older than 0.5.0 ignores `carrier` and falls back to UDP, so a config written by 0.5.0 needs its section renamed back to `transport` for an older client. The apps say *Carrier* instead of *Transport*, and so do the log and error texts. Internal names (`Transport` in `ostp-client/src/transport/`, the `transport` field of the runtime config, `transport_mode`, the `transport` field of the prober requests) stay as they are.
- Behaviour change: `ostp key gen` (and its hidden aliases `ostp gk`, `ostp generate-key`) no longer adds the new keys to the server config by itself; it only prints them. `--add` does what it used to do, and keeps the previous file as `config.json.bak`. A running server reads access keys again within a few seconds (hot reload), so no restart is needed. A script that relied on `ostp gk` writing to the config now needs `ostp gk --add`.
- `ostp.log`: every line has one shape on the server and the client, time (UTC), level, subsystem, message; the source line number is no longer written, and the lines the client appends itself (`[core]`, `[ostp]`, the connection mark) no longer start with `[local time]`.
- In `normal` the DNS query log keeps a client's network (/24 or /48) instead of its address; the full address only in `debug`.
- v6 handshake resends: each send of the client's handshake is the same Noise message sealed anew (new nonce, new padding in the key-derived range), so repeated datagrams are no longer byte-identical on the wire. A profile without `pk` resends byte for byte as before.

### Fixed
- Desktop and Android apps dropped the `pk` (the server's key) of a link or subscription, so a v6 profile imported into an app connected as v5 and failed against a v6-only server. The apps now keep `pk` in the profile, pass it to the core (and to the network check), write it back when a profile is shared, and show *Protocol: v6* (or v5) in the profile editor. A malformed `pk` is refused with a message (in a subscription the link is skipped, and if nothing else is usable the error says why) instead of silently making a v5 profile. The Android link parser also reports a link with broken `%` escapes as such instead of failing with an unrelated error.
- v6 handshake: the server found its cached reply by a hash of the whole datagram, but the padding is not authenticated, so a copy with a damaged padding was accepted and, if its reply was lost, the clean resend missed the cache and was dropped as a replay: the client never connected (found in wirelab, `hs-corrupt`). The reply is now found by a hash of the Noise message, after one HMAC and one ChaCha20 pass and before any curve operation.

## [0.4.8-beta.2] - 2026-11-15

### Added
- `ostp manage dns` shows the DNS filter's settings as JSON, and the SSH manager of the apps can turn the filter, the takeover, the encrypted-DNS block and safe search on or off and update the lists (`dns-*` actions).
- Desktop and Android apps: a DNS section in server management (a DNS tab). It shows the server's DNS filter and turns the filter, the takeover, the encrypted-DNS block and safe search on or off and updates the lists; every change asks first, because the service restarts and connected clients drop for a few seconds. The resolvers, lists and the counts of rewrites and own rules are shown read-only.

### Fixed
- Windows client, TUN mode: the adapter could not be set up ("The parameter is incorrect", os error 87, five attempts and then a failed start). The MTU was set for IPv4 and IPv6 alike, and IPv6 refuses anything under 1280 while the default is 1140. IPv4 now gets the configured MTU and IPv6 the same but never under 1280.
- A download could stop for good on a link that loses packets in both directions (found at 30% loss each way: 8 of 13 runs of a 500 KB transfer that got connected): the session stayed up, but no packets moved in either direction. A lost ACK leaves a hole in the sequence that no timer resends, and the receiver can only ask for it with a NACK; if that NACK, or the frame sent in answer, was lost too, nothing asked again, because the sender had already been told that everything behind the hole arrived. A receiver now repeats the NACK for a gap that stays open, with pauses that grow from twice the RTO up to 2 seconds. Nothing on the wire changes, so old servers and clients work with it.
- Windows client: when the TUN adapter could not be created, stopping the failed start ended in a panic ("JoinHandle polled after completion") because a finished task was awaited a second time. The task that ended is no longer awaited again, and the real error (the adapter) is what the app reports.
- Desktop and Android apps: "Open the panel" in server management never finished: the SSH manager held its lock on the table of open panels while it took the same lock again, so the call waited for ever (until the app's time limit). Found by driving the app's own SSH manager against a real server.
- WARP: every UDP flow of the server's clients held a socket with 128 KiB of buffers in the tunnel for as long as its client kept the flow (5 minutes after the last datagram), and the relay allocated 64 KiB per association. On a busy server that was thousands of flows, hundreds of megabytes and the tunnel's flow limit (4095), after which UDP, DNS included, stopped working. A flow in the tunnel is now made on the first datagram, given back after 30 seconds of silence and made again when the client sends, its buffers are 24 KiB, and the relay buffer is 2 KiB.

## [0.4.8-beta.1] - 2026-11-12

### Changed
- Server DNS filter: by default it answers only queries sent to the server's own address (`10.1.0.1`) and no longer takes every client's DNS or refuses encrypted DNS (DoT, DoH) on its own. Taking over all DNS is an explicit option, `ostp dns takeover on` (panel: "Answer every DNS query"), and links and subscriptions then carry `dnsall=true`. `ostp migrate` (schema 5) keeps the takeover on servers whose filter was on, so nothing changes for them until the owner turns it off.

### Added
- Device limit per user for subscriptions: `max_devices` (panel user form, `ostp manage user-limit`), checked by the device ID the app sends when its owner turned that on. A new device over the limit gets HTTP 403 `device_limit`, a request without an ID from a limited user gets 403 `hwid_required`. The record is `devices.json` (0600); the panel lists and removes devices, `ostp manage user-devices` prints them.
- Desktop and Android apps and the CLI: the device ID for subscriptions that limit devices. The switch *Send a device ID to subscriptions* (CLI: `send_hwid` in the client config) is off by default; when on, a subscription fetch sends a per-server hash of the system's machine identifier plus the OS and the model or CPU architecture, never the identifier itself and never the computer's name. After a fetch you started, a server that needs the ID makes the apps ask "Send and retry"; a background refresh only writes the reason on the subscription card, and a reached limit shows the server's message.
- Docs: `v6-design.md` and `v6-session-design.md`, the draft plans for protocol v6 / 0.5.0, and `warp-design.md`, the draft plan for `ostp warp` (nothing in them is implemented).
- Desktop and Android apps: a notice on the first connection to a server that filters DNS (links with `owndns=true` or `dnsall=true`). It says that the operator's resolver filters domain names and sees the names looked up, and asks once per profile: the operator's DNS (10.1.0.1), a public DNS, or keep the app's settings. The buttons wait 5 seconds. The choice is kept with the profile and can be changed in the profile editor (*DNS of this server*).
- Both apps keep and re-export the `dnsall` flag of share and subscription links (Android now also keeps `owndns`).
- Docs: `carriers-design.md`, a draft study of carrying OSTP inside WebSocket, QUIC/HTTP3, WebRTC, ICMP and HTTPS long-poll: costs, what censors are known to do, and a recommended order (nothing in it is implemented).
- Server: Cloudflare WARP as the exit, `ostp warp` (`register --accept-terms`, `license`, `enable --all | --rules`, `disable`, `status`, `test`, `reset`). A WireGuard client in the `ostp` process (user space: no tun device, routes or root) with a local SOCKS5 proxy on `127.0.0.1:40000` (TCP and UDP); the `outbound` section is pointed at it. `--all` sends everything the server opens outwards through WARP with no direct fallback, `--rules` only what the outbound rules send to the proxy. Keys are kept only in `warp.json`. New `warp` config section, schema 6 (`ostp migrate` adds it, off). Not built for MIPS. Details: `docs/en/server.md`, `docs/en/warp-design.md`.

### Fixed
- Server DNS filter: with the outbound proxy on, plain UDP, TCP and DoT upstream resolvers no longer go out directly (they are carried as DNS over TCP through the proxy), DoH through a `socks5h://` proxy works (it failed with "unsupported scheme"), and a proxy that cannot be used fails list downloads and upstream queries instead of silently going direct.

## [0.4.7] - 2026-11-12

Summary of 0.4.7 (the details are in the beta entries below). Wire-compatible with 0.4.5 and 0.4.6 (protocol version 5).

### Added
- Desktop and Android apps: "Update now" downloads the release for the device, checks it against the SHA-256 GitHub published and starts the installer. A Reconnect button appears when the profile changed while connected.
- Per-stream flow control: a large upload to a slow site no longer breaks, and a program that reads slowly cannot stall the others.
- Server: an `overnet` section and `ostp overnet` commands (the `.ov` zone through the server), config schema v4 (`ostp migrate` upgrades older files).
- `ostp start`, `ostp stop`, `ostp restart` and a richer `ostp status` for the Linux service.

### Changed
- Reconnects follow one policy instead of five overlapping ones; a silent server is noticed within about 10 seconds, and long outages keep the session and its connections.
- The congestion controller was reworked: speed on lossy links, on short paths and over TLS and UoT no longer collapses or swings between runs.
- The desktop app's privileged helper `ostp-tun-helper` is now `ostpd`; its Windows task is "OSTP Daemon".

### Removed
- Junk packets and TCP fragmentation of the handshake, and the multiplexing option in the apps (the `mux` block of the config file still works).
- The terminal interface (TUI) of the client.
- The kill switch on Windows, which never blocked anything; Linux and macOS keep theirs. A firewall-based one is planned for 0.5.0.

### Fixed
- Linux builds crashed with "Illegal instruction" on CPUs without BMI2 and AVX2 (QEMU virtual CPUs, older servers) in 0.4.7-beta.15 and beta.16: the CI image moved to Ubuntu 26.04, whose compiler targets newer CPUs. The runners are pinned to Ubuntu 24.04 again. Servers on those betas: `ostp update -v 0.4.7-beta.13` or update to 0.4.7.
- TUN mode recovers by itself after a network change on Windows and Linux; Android with two SIM cards, other-VPN takeover and the "Connected" state were corrected.
- Android and desktop "Update now" installs the update (a missing permission and a dismissed dialog's context broke it).
- Many limits and timeouts so that a hung peer, a huge number or a bad file cannot freeze the client, the server, the panel or the apps.

### Security
- Clients can no longer reach the server's own services by default; a client cannot take over another user's session; at most 32 sessions per key; panel passwords are salted (PBKDF2); IPv6 no longer bypasses the tunnel in the desktop apps.
- Installers and `ostp update` check downloads against the SHA-256 GitHub publishes; `/etc/ostp`, `config.json` and `C:\opt\ostp` are no longer readable or writable by every local user.

## [0.4.7-beta.16] - 2026-11-12

### Fixed
- Android: "Update now" downloaded the APK and then did nothing, with no installer dialog. The button's own dialog was already closed when the download ended, and the code that starts the installer gave up because that dialog's context was gone. It now uses the screen's context. An app that is already installed has this bug itself: update it by hand once.

### Changed
- The desktop app's privileged helper `ostp-tun-helper` is now `ostpd` (the crate, the executable and the sidecar), and its Windows scheduled task is "OSTP Daemon". The installer removes the old task and executable. An update of the portable Windows, Linux or macOS build from 0.4.7-beta.15 or older does not copy `ostpd` (that updater only knows the old file name): copy it from the archive by hand, or install the new version over the old one.
- Desktop app: more room between the Servers button and the exclusions on the More settings screen.

## [0.4.7-beta.15] - 2026-11-12

### Changed
- Desktop and Android apps: the Reconnect notice is now a row with a title, the reason and a button that shows "Reconnecting" with a spinner while it works.

### Removed
- The multiplexing option (several sessions to the server) from the desktop and Android apps. A lab run on a 100 Mbit/s, 80 ms, 0.5% loss path gave 5.7 Mbit/s without it and 6.9 Mbit/s with 4 sessions for a download, and a stream stays on one session anyway; each session also takes a place on the server. The `mux` block of the config file still works.
- Junk packets and TCP fragmentation of the handshake (plain TCP only), with their settings in the desktop and Android apps and the `uot_frag` carrier of the network check. The handshake already looks like random bytes, so random filler in front of it changes nothing a classifier of fully encrypted traffic looks at, and a plain OSTP stream has no server name for splitting the first segment to hide; both only made connecting slower. Config files that still have `junk_pc`, `junk_ps`, `tcp_fragmentation`, `frag_chunk` or `frag_sleep` load as before (the fields are ignored), and `ostp migrate` deletes them (client config schema 4). The server still drops marked junk from older clients, and TTL-desync decoys keep their marker, so nothing changes on the wire.

### Fixed
- Kill switch on Windows did nothing: its blackhole route got the loopback interface's metric of 75 on top of its own 10, so the real default route (45 on a Wi-Fi adapter) always won and traffic left outside the tunnel when it dropped. The route is gone, the setting is ignored on Windows with a warning in the log, and the desktop app no longer shows it there. Linux and macOS are unchanged (they remove the default route). A firewall-based kill switch is planned for 0.5.0.
- Desktop app: Update now failed with "Command install_update not allowed by ACL": the command was missing from the app's permission list. The installed beta.12 to beta.14 builds cannot update themselves, so the next version has to be installed by hand once; from it on, Update now works.

## [0.4.7-beta.14] - 2026-11-06

### Added
- Desktop and Android apps: when the selected profile changes, or the profile in use is edited, while connected, the main screen says that the connection still uses the previous one and shows a Reconnect button. It stops and starts the tunnel with the new profile in one step; open connections are reset, as with Disconnect and Connect. Nothing happens until it is pressed.
- Per-stream flow control: a large upload to a site that takes it slowly no longer breaks (the server used to reset the connection once 32 MB waited for the site), and a program on the client that reads a download slowly no longer makes the server buffer it. Each stream gets an 8 MiB window in each direction; the receiver grants more as data reaches the site or the program. The client offers it after the handshake and both sides use it only if the server answers, so 0.4.5 servers and clients work as before. Checked: a 100 MB upload to a site taking 1 MB/s arrives whole with the server at 25 MB of memory.

### Fixed
- TLS and UDP-over-TCP slowed to a quarter of the path when the network got slower after connecting, or behind a deep buffer: the client's own congestion control backed off on the queue that TCP underneath builds anyway, and left TCP with less to send. On these carriers TCP now does the congestion control alone. A path that gets slower while a session sits idle is also no longer taken for a queue (slow start went on from the initial window). Measured on a 35 ms, 300 Mbit/s path with 0.01% loss: TLS 58 to 191 Mbit/s, UDP 119 to 208 Mbit/s.
- Speed on links with random loss (radio, mobile, a lossy hop) swung between runs, for example 43 to 183 Mbit/s on the same 300 Mbit/s path with 0.01% loss: each loss cut the window to 0.7 as if it were congestion, several times a second. A loss while the round-trip time is at its floor (no queue) now costs a milder cut (0.85); one with a queue built up still costs the full one. The same path now gives a steady ~120 Mbit/s.
- Server: a client on TCP or TLS that drained its connection slower than the server sent had frames dropped from its queue, and they then waited out the long retransmit timer of a reliable carrier: TLS downloads crawled. The server now reads from sites only as fast as that connection drains.
- A frame was given up after 10 retransmits, about 30 seconds on a short path, so an outage that the session would otherwise survive lost data. Frames are now given up only after 5 minutes, and a receiver waits as long for a missing one.
- Outages longer than about 15 seconds reset every app connection (a download broke even though the server still kept the session for 10 minutes). The client now keeps the session and its connections while the server does not answer at all, and moves the session when the network comes back; connections are reset only when the server no longer knows the session. Checked with a 30-second cut in the middle of a 100 MB download, over UDP and UoT: the file arrives intact.
- After an outage the connection crawled for tens of seconds: the window that the lost retransmits had shrunk to 2 packets grew back slowly. Both ends now start over on the path and resend what was lost at once, the server also when a client comes back from a new address.
- Speed on short paths: with a server close by (a LAN, the same city, a nearby data centre) a connection stayed at a few Mbit/s. Every RTT sample includes the receiver's ACK delay and the sender's 10 ms tick, so with a 1 ms ping the smoothed RTT read 10 to 15 times the minimum, which the congestion control took for a standing queue and kept halving the window down to 2 packets. The delay signal now compares with at least 20 ms. Measured on loopback with 0.4.7-beta.13: 4.8 Mbit/s.

## [0.4.7-beta.13] - 2026-10-28

### Fixed
- TUN mode on Windows and Linux did not recover by itself after a network change (another Wi-Fi, a cable, a new gateway after sleep): the route to the server and the sockets of excluded traffic stayed on the network the tunnel started on, so every reconnect attempt went nowhere and only pressing Disconnect and Connect helped. Before each recovery step the client now moves those routes to the current gateway, and excluded connections use the current interface.
- Server: a UoT connection the server had already answered was closed 20 seconds after it opened if the client sent nothing in between.

## [0.4.7-beta.12] - 2026-10-28

## [0.4.7-beta.11] - 2026-10-28

### Added
- Android: "Update now" in the update dialog downloads the APK for the phone's architecture from the GitHub release, checks its size and the SHA-256 GitHub publishes for it, and opens the system installer. If installing apps from this source is not allowed yet, the app opens that setting. Nothing is downloaded until the button is pressed.
- Web panel: "Sign out" now ends the session on the server too. A panel session ends after 12 hours without activity and at most 7 days after sign-in.

### Fixed
- Desktop app: the MTU set in the settings was ignored (always 1350). The CLI, the desktop app and a config reload now turn the config file into the same settings with the same defaults (MTU 1140, I/O timeout 2.5 s, connect timeout 15 s); before, a reload changed the MTU and the timeouts of a running tunnel.
- Client without a GUI (`ostp` as a service): a first connection that failed (wrong key, a name that does not resolve) was retried forever; it now stops with the error, like the apps. When the server name has IPv4 and IPv6 addresses, IPv4 is tried first, so a broken IPv6 route no longer blocks the connection.
- Client: an exclusion like `10.0.0.0/33` crashed the client; prefixes are capped. Routing rules on the server with Cyrillic and other non-Latin domains (`пример.рф`) never matched; they do now.
- `ostp setup` could offer a carrier-grade NAT (100.64.0.0/10) or link-local address as the server's public address for links. The same complete check for private addresses is now used everywhere.
- CLI: every command that changes `config.json` writes it atomically and private (0600); a crash in the middle of a write no longer leaves an empty config without keys. Links printed by the setup wizard percent-encode the key and handle IPv6; `ostp init` uses the configured port instead of 50000.
- TUN on Android: a closed or revoked TUN descriptor made the tunnel spin a CPU core until it was stopped.
- Server: UoT connections that do not complete a handshake within 20 seconds are closed, at most 64 of them per source address. The fallback (decoy) connection closes after 120 seconds of silence and no longer blocks new connections. Unauthenticated queues are bounded; the plain HTTP port times out slow requests. The DNS cache no longer scans itself on every miss.
- Server: subscription links are looked up through an index instead of trying every key, and a source with 30 wrong subscription links in 10 minutes is refused for the rest of that time.
- Android: the app's state no longer depends on the wording of log lines.
- Desktop app: share links keep the `tun`, `dns` and `owndns` options on import and export. Temporary token files are created private instead of being made private after writing.
- Byte sizes are shown in binary units everywhere (KiB, MiB, GiB, TiB); the Android home screen showed a terabyte as "1024 GB".

### Security
- `install.sh`, `install.ps1` and `ostp update` check the downloaded archive against the SHA-256 GitHub publishes for it; without a hash or with a different one nothing is installed. `install.ps1` can install beta and alpha releases (`-Branch`, `-Version`), like `install.sh`.
- `ostp.log` is kept under 10 MB.

## [0.4.7-beta.10] - 2026-10-28

### Added
- Desktop app: "Update now" in the update dialog downloads the new release, checks it against the SHA-256 GitHub publishes for the file, stops the tunnel, installs it and restarts the app. An app installed with the setup program updates through the new setup as an update (one Windows consent prompt, shortcuts and settings kept); the portable Windows app and the Linux and macOS apps replace their files in place. Nothing is downloaded until the button is pressed. If the install fails, the dialog says why and offers the release page.

### Fixed
- Desktop app: the tray menu and the "already running" message were in Russian while the rest of the app is in English; they are in English now.

## [0.4.7-beta.9] - 2026-10-28

### Fixed
- Network prober, DPI test: under an allowlist ("white lists", when only allowlisted addresses are reachable) it showed "10% (clean)". Foreign hosts that refuse even a TCP connection counted as "no result" instead of filtering, and every content test talks to Russian hosts, which an allowlist lets through. The test now recognises an allowlist (Russian hosts answer, Hetzner, OVH, Cloudflare, Google and Quad9 refuse TCP), says so first and scores it 100%; an unreachable foreign hosting counts as filtered. The SNI and HTTP Host tests show "not measured" instead of "clean" when no clean baseline answered.
- Network prober, DPI test, reworked so that it reports only what it measured:
  - The SNI and HTTP Host tests started their clock before connecting, so a reset injected right after the request never looked faster than the server and was not counted as a block; a failed connection, before any name was sent, was counted as one.
  - "RST injection" connected to a closed port that the server silently drops and almost never saw anything; a local firewall made it fire falsely. Forged resets are now taken from the tests that see them: a blocked name reset faster than the server could, or a hop before the server resetting.
  - "UDP throttling" judged the spread of ten DNS round trips, which one slow Wi-Fi answer was enough to trip. It measured nothing about throttling and is gone.
  - A CONNECT refused with 403 by the web server itself counted as a hijack; it is now compared with the same request for a clean name. A `Via` header from the site's own CDN no longer counts as a transparent proxy.
  - No answer from 8.8.8.8 showed "DNS not hijacked"; it is "not measured" now, like the CONNECT and reset tests when they have nothing to compare.
  - The score was a sum of hand-picked weights; it is now the level of the worst finding, with a one-line verdict and advice on which OSTP carrier to use (a relay under an allowlist, UDP or UoT when TLS abroad is filtered, TLS when unknown data is dropped).
  - All messages are in English, like the rest of the prober.
- Linux, TUN mode: the client waited for "yes" typed into the log window and crashed on any other input, while the log already said "TUN tunnel established". The prompt is gone; the log says the tunnel is up only after the TUN interface is created.
- TUN mode no longer turns on the system proxy (on Windows it also reset the proxy exclusion list).
- Client reconnects, rewritten as one policy instead of five overlapping ones. A silent server is noticed within about 10 seconds (each multiplex session is watched on its own, so a live session no longer hides a dead one). The client first moves the session to a new socket; if that fails, it reconnects to the same server and transport with pauses of 1, 2, 5, 10, 20 and then 30 seconds until it succeeds or the user stops it. A network change or waking from sleep starts recovery at once. Old streams are reset on every reconnect. This fixes tunnels on Windows that stayed "connected" while nothing went through, and a stop/start swing caused by a delayed automatic toggle. A first connection that fails (wrong key, address or transport) is not retried: the client stops and shows the error.
- Client, UoT and TLS: on a dead TCP path the send queue filled up and blocked the client's main loop, so recovery did not start until the operating system gave up on the connection. A write that makes no progress for 10 seconds now closes the connection and recovery starts.
- Client: lookups of the server name, migration sockets and the local SOCKS5/HTTP handshake had no time limit; a bad clock jump between ping and pong could stretch a migration without bound. A failed `accept` on the local proxy no longer ends the whole client. Data for a local program that stopped reading is capped at 32 MB per connection, then that connection is reset instead of filling memory. "Protocol decrypt error" is logged at most once in 5 seconds.
- Client and core: an MTU of 0 or below 64 in the config caused a division by zero or a panic; it is raised to the smallest workable value. Keepalive intervals, multiplex sessions (32) and junk packet counts from the config are capped.
- Server: an error sending to one client skipped the rest of the tick for all clients and the cleanup of dropped sessions; an error in one datagram dropped the other payloads in it, which corrupted their streams. Each error is now handled on its own.
- Server: handshakes with an upstream SOCKS5 or HTTP proxy had no timeout, so a proxy that accepted and went silent held a client's slot forever (30 seconds now). Idle UDP relay sessions leaked their socket and task. The handshake timestamp check could be bypassed with an overflowing value.
- Server: the filtering DNS caps parallel upstream queries at 256; DNS over TCP and name lookups for UDP targets have timeouts; per-IP connection windows count IPv6 by /64 and keep at most 100,000 sources. A certificate due for renewal right after issuance no longer makes ACME reissue in a loop. Per-packet warnings ("Protocol error for session", "Reorder buffer still full") moved to debug.
- Proxy mode: after 45 seconds without a connection the system proxy is released so the computer keeps internet access, and turned on again when the connection is back.
- Android with two SIM cards: switching mobile data to the other SIM did not move the tunnel to the new network. The app now follows the default network, sets it as the tunnel's underlying network and reconnects after the switch.
- Android: "Connected" is shown only after the server answered the handshake, and stays "Connecting" while the connection is being restored.
- Android: refusing or dismissing the VPN permission dialog showed "service did not start" after 5 seconds, and a permission granted later started the VPN anyway. The app now waits for the answer and says the permission was not granted.
- Android: when another VPN app took over, the tunnel stayed "running" with nothing behind it; it now stops and the app says so. After the system killed the app, the service was restarted without a tunnel and hung; it now stops. A quick stop and start could kill the new tunnel.
- Android: a second tap while connecting or stopping no longer sends the opposite command; every call to the service has a timeout; switching profiles in Settings while connected says the change applies on the next connect instead of showing the new profile's name over the old tunnel.
- Android: negative or huge numbers in Settings (MTU, junk, fragments), a DNS that is not an IP address or a bad local address broke the whole config; they are now kept in range or replaced by defaults. "Only selected apps" with no app selected sent every app through the tunnel; connecting is refused with a message.
- Android: limits on links (4096 characters), profiles (100), subscriptions (20) and links per subscription (50); duplicate profiles are refused. A QR code could close several screens at once. One broken profile entry no longer wipes the whole list. Closing Settings could overwrite a subscription update that finished meanwhile.
- Android: the log screen keeps at most 2000 lines and no longer opens a new error dialog every second when reading fails; the battery optimisation question is asked once, not on every connect.
- Desktop app: "Disconnected" appeared even when stopping failed; the button could be clicked twice while TUN mode waited for the administrator prompt; an error disappeared after 5 seconds; the beta warning was shown for stable versions too. Tab, B, Q and Escape no longer close the app or switch screens; Escape closes the open dialog.
- Desktop app: no longer loads fonts from Google at start.
- Desktop app: a call to the core that never answered froze the window for good; every call now has a time limit, and network checks, subscription downloads and update checks are stopped after 30 to 120 seconds. A command to the TUN helper waits at most 3 seconds.
- Desktop app: "Exit" in the tray left the elevated TUN helper running with its adapter and kill switch; the tunnel is now stopped first. Exit is refused while a server install or change is running, because half an install leaves the server broken.
- Desktop app: when the TUN helper died without a message, the app showed "Disconnected" with no reason; it now says the helper stopped. A damaged `config.json` gives a clear message instead of a parser error, and the config is written atomically.
- Desktop app: limits on profiles (200), subscriptions (20), links per subscription (50), field lengths, exclusion lists (500) and QR pictures (10 MB, 40 megapixels, checked before unpacking). Numbers in settings are kept in range. A subscription deleted while it was downloading no longer comes back; a slow answer from one server tab no longer redraws another; a dialog opened over another no longer leaves the first one waiting forever.
- Desktop app: uptime and speed are measured by the clock, so they stay right after sleep.
- Web panel: clearer error messages, confirmation before deleting, input checks before saving, keyboard access and screen reader labels; the Overview subtitle showed the overnet text.
- Management API: requests that change `config.json` at the same time could lose each other's changes, and the file was not written atomically, so the 5-second reload could read half of it. Writes are now serialized and atomic, and keep the file's permissions. A user created when the config could not be written no longer lives until the next restart. `POST /users` with an existing key returns 409 instead of replacing the user and its statistics.
- Management API limits: request bodies up to 1 MiB, at most 10,000 users, keys of 8 to 128 characters, names up to 100, traffic limits up to 1 PiB, up to 2000 routing rules; a second `dns/update` while one runs is refused. Parallel sign-in attempts can no longer go past the 10-per-minute limit.
- Web panel: a sign-in in a second tab or by a second admin no longer signs the first one out. Requests time out after 15 seconds; polling no longer piles up while the server restarts and pauses in a hidden tab. Saving warns when the user, config or rules were changed on the server since they were loaded. A form open when the session expired comes back after signing in. The user table shows 200 rows at a time. A negative traffic limit no longer silently means "unlimited".
- Routing rules: the `block` action was read as `proxy`, so traffic meant to be blocked went through the tunnel.
- Windows: one-off commands such as `ostp changelog`, `ostp cert` or `ostp manage` could trim the log of a running client.
- CLI: no ASCII banner at start, no "Enable debug mode?" question on connect, shorter error messages that say what to do. The setup wizard asks about service registration and autostart after it has saved the config.
- Docs: the relay is described as what it is, a transparent forwarder without keys (`upstream_api_*` settings are ignored); congestion control is described as CUBIC, as in the code. The client recovery section matches the new reconnect policy.

### Added
- `ostp start`, `ostp stop`, `ostp restart` for the service on Linux; `ostp status` shows whether ostp is running, since when, whether it starts at boot and the last log lines; `ostp log` shows the log (`-n` lines, `-f` to follow): the service journal on Linux, `ostp.log` on Windows and macOS. A start that fails within 3 seconds prints the journal lines that say why.

### Security
- `install.sh` downloaded the release as root into a fixed file in `/tmp`: a local user could replace it or point the write at another file. It now uses a private temporary directory and HTTPS only.
- `install.sh` left `/etc/ostp` and `config.json` (access keys, panel password hash) readable by every local user. The directory is now 700 and the config 600.
- `install.ps1` left `C:\opt\ostp`, which is on the system PATH, writable by every user, so anyone could replace `ostp.exe`. Only administrators and SYSTEM can write there now.
- Server: a client could put line breaks into a destination name and send its own headers to an HTTP upstream proxy; a name longer than 255 bytes broke a SOCKS5 upstream. Such names are refused.
- Server: a client with a key could make the server compare every unacknowledged frame against hundreds of ACK ranges per packet and stall all users. ACK and NACK lookups are now binary searches.
- Server: a client could take over another user's session by reusing its session ID; this is refused now. Sessions dropped between server ticks (too many per key, key deleted) kept their outgoing connections open.
- Server: users created in bulk got 60-bit access keys; they now get 128 bits like users created one by one. Keys issued that way should be reissued.
- Server: saving routing rules from the panel could overwrite a config that has comments with `null`. A config that cannot be parsed is no longer written.
- DNS: queries to a plain UDP upstream used the client's query ID and accepted any answer with that ID; the server now uses a random ID and checks the question.

### Removed
- The terminal interface (TUI in `ostp-client`), the `test_route` tool, an outdated relay config example and an unused icon.

## [0.4.7-beta.8] - 2026-10-07

### Fixed
- After a connection outage of a few seconds (a lift, a switch between Wi-Fi and mobile data) a TCP connection through the tunnel could lose a piece of data without any error: the receiver gave up on a missing frame after 2 to 10 seconds while the sender was still retransmitting it for about 40. The receiver now waits as long as the sender keeps trying.
- Server: data from a client to a website queued without limit while the site accepted it more slowly, so one fast upload to a slow site (or a client doing it on purpose) could take all of the server's memory. Past 32 MB waiting, that connection is reset with an error.
- Panel: too many sign-in attempts showed an English server message in the Russian interface.

## [0.4.7-beta.7] - 2026-10-06

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
