# Test protocol

The checklist run before a beta and a stable release. It covers the server, the web panel, the desktop GUI, the Android client and the CLI client.

How to use it:

- Every case has a number, steps and an expected result. A case passes only when the result matches in full.
- **P1** is required for both beta and stable. **P2** is required for stable, and for beta when possible.
- When something does not match, open an issue with the case number, version, platform and log. The run report follows the template at the end.
- Certificates are tested against Let's Encrypt staging (`--staging`) first, then the production CA, which has strict limits on failed issuance.

## 0. Automated checks

Builds and tests run on GitHub Actions, not on the developer's machine (`.github/workflows/ci.yml`). CI starts by itself on a push of code (not of docs or changelogs) to `beta` and `master`; `alpha` is checked by hand with `gh workflow run ci.yml --ref alpha` or "Run workflow" in the Actions tab. Commands in the table are what CI runs; run one locally only when it is small.

| # | Check | Expected | Prio |
|---|---|---|---|
| A-01 | CI job *Tests (Linux)*: `cargo test -p ostp-core -p ostp-client -p ostp-server -p ostp -p ostp-ssh -p ostp-jni` (includes the CLI and its nginx/apache/caddy templates, the wire tests in `ostp/tests`, and that every Kotlin `external fun` has a JNI export) | all green | P1 |
| A-02 | CI job *Tests and binary (Windows x64)*: `cargo test -p ostp-core -p ostp-client -p ostp-server -p ostp -p ostp-tun`, the desktop app's backend and its helper `ostpd` compile | all green | P1 |
| A-03 | CI job *Linux binary (x86_64, musl)* builds `ostp` and runs `ostp --version` | green | P1 |
| A-04 | CI job *Apps (checks and tests)*: `node --check` on every `ostp-gui/src/*.js`, `node --test ostp-gui/test/*.test.mjs`, `flutter analyze --no-fatal-infos`, `flutter test` (includes the first-run and server screens on a phone-sized view, the key-pin and server-key tests) | green, no overflow errors | P1 |
| A-05 | `sudo cargo test -p ostp-ssh --test sshd -- --ignored --test-threads=1` on a throwaway machine with sshd (with `OSTP_BIN=target/debug/ostp` for the manager test) | green: key and password sign-in, sudo, host-key change refused, port forward, `ostp manage` over SSH | P2 |
| A-06 | `cargo tree -i aws-lc-sys` at the root and in `ostp-gui/src-tauri` | empty | P1 |
| A-07 | Release build: `scripts/gha.ps1` pushes the tag and `release.yml` builds every platform (never a local build) | every job green, the assets of every platform are attached to the release | P1 |

## 1. Test bed

- **Server:** a VPS with Debian 12 or Ubuntu 24.04, public IPv4 (IPv6 too, if possible). A domain with an A record (and AAAA) pointing at it. Ports 80, 443 and 50000 (TCP+UDP) open.
- **Web servers for section 2.4:** separate clean machines or snapshots with nginx, apache (Debian and the RHEL family) and caddy.
- **Clients:** Windows 10/11 x64 (arm64 if available), Android 8+ on arm64 and armv7, Linux x64 for the CLI.
- **Networks:** a home ISP, a mobile network, if possible an IPv6-only network with NAT64 and a network with noticeable DPI filtering.
- Record the version of every component in the report (`ostp -V`, which also shows the channel; About in the GUI; the APK version).

## 2. Server

### 2.1 Install, update, configuration

| # | Steps | Expected | Prio |
|---|---|---|---|
| S-01 | Fresh install with `install.sh`, then `ostp setup` in Server mode | the `ostp` service is active, `ostp links` prints working links | P1 |
| S-02 | `ostp update --branch beta` on a server running the previous version | new version, service restarted, keys and settings kept | P1 |
| S-03 | `ostp migrate --dry-run` on configs from 0.4.5 and older (modular v0, flat v1) | steps, changes and unknown keys with suggestions are printed; the file is untouched | P1 |
| S-04 | `ostp migrate` on the same configs | `config_version: 6` (the `warp` section added, off), `access_keys` and `api.token` kept, the server starts | P1 |
| S-05 | A config newer than supported (`config_version: 99`) | migrate refuses and leaves the file alone | P2 |
| S-06 | `ostp check` on a valid and a broken config | "Config OK" / a clear error naming the field | P1 |
| S-07 | Add a key to `config.json` of a running server | within ~5 s the new key connects, no restart | P1 |
| S-08 | `ostp links` and `ostp links qr` | TLS/UDP links and SUB (when subscriptions are on) per client; in qr mode one QR on screen: ← → switch SUB / TLS / UDP, ↑ ↓ or Enter switch clients, `q` quits; redirected to a file (`> qr.txt`) every client is printed | P1 |
| S-09 | Scan a QR from `ostp links qr` with a phone | the app imports the profile or the subscription | P1 |
| S-09a | `install.sh -y -b beta` on a clean VPS as root | installs without questions, the last line is JSON with one user and its links, the service is active, the port is open in ufw/firewalld if one is on | P1 |
| S-09b | `ostp manage status`, `users`, `user-add phone`, `user-rename 2 tablet`, `user-remove tablet`, `logs -n 20` | each prints one JSON object; the added user connects within ~5 s without a restart; removing the last user is refused with `{"error": ...}` | P1 |
| S-09c | `.ostp_stats.json` next to the config after a client moved traffic for a minute | exists, mode 600, the user's bytes grow; `ostp manage users` shows them | P2 |
| S-09d | Move traffic and make DNS queries, then `systemctl restart ostp` (and an update) | the panel shows the same traffic per user and the same DNS counters and query log as before; a user over the limit stays over it; "Clear" in the DNS log survives a restart as empty | P1 |

### 2.2 Carriers

| # | Steps | Expected | Prio |
|---|---|---|---|
| S-10 | Client over a UDP link | connects, traffic flows, RTT shown | P1 |
| S-11 | Client over UoT (TCP) on 50000 | same | P1 |
| S-13 | Relay: `ostp init relay`, client goes through the relay | traffic flows, the relay holds no keys | P2 |
| S-14 | Client with a wrong key | no connection, the server stays up, no key in clear in the log | P1 |
| S-15 | A TCP/TLS client that goes silent (kill it with the network, not gracefully) | the server closes its connection within 5 minutes; a normal idle client stays connected | P2 |

### 2.3 Domain and TLS, built-in frontend

No web server on the machine; OSTP listens on 443 and 80 itself.

| # | Steps | Expected | Prio |
|---|---|---|---|
| S-20 | `ostp cert issue --staging`, domain, email, accept the ToS | certificate issued (staging), config saved with a backup, restart offered | P1 |
| S-21 | `ostp cert status` | domain, issuer, validity, certificate source | P1 |
| S-22 | Issue again on the production CA | trusted certificate; a browser opens `https://domain/` without a warning (the answer is a 404) | P1 |
| S-23 | `http://domain/anything` | 301 to https | P2 |
| S-24 | Client over a TLS link (`type=uot&tls=1`) | connects, traffic flows | P1 |
| S-25 | Client with a wrong SNI | a clear certificate verification error | P1 |
| S-26 | Client against the staging certificate without / with "don't verify" | verification error / connects | P2 |
| S-27 | `renew_days_before: 89`, wait for a renewal cycle | certificate replaced on the fly, live sessions survive, no restart | P2 |
| S-28 | `https://domain/<webpath>/` | the panel opens (section 2.7) | P1 |

### 2.4 Domain and TLS through a web server

Repeat for nginx, apache (Debian and RHEL) and caddy.

| # | Steps | Expected | Prio |
|---|---|---|---|
| S-30 | `ostp cert issue` on a machine with a web server | the web server is found; after confirmation a site is added (Debian/Ubuntu: `sites-available/ostp-<domain>.conf` with the symlink `sites-enabled/ostp-<domain>.conf`, otherwise `conf.d/`), the config test passes (`nginx -t` / `configtest` / `caddy validate`), reload done; `ostp cert status` shows every check green | P1 (nginx), P2 (others) |
| S-31 | Client over a TLS link with `path=` | connects through 443 | P1 (nginx) |
| S-32 | Existing sites on that web server | work as before | P1 |
| S-33 | Break the web server config beforehand, run the install | the install rolls back, the web server keeps running on the old config | P2 |
| S-34 | `ostp uninstall` | vhost removed, web server reloaded, other sites untouched | P2 |
| S-35 | Certificate renewal | `reload_command` runs after it, clients see the new certificate | P2 |

### 2.5 Subscriptions

| # | Steps | Expected | Prio |
|---|---|---|---|
| S-40 | After `ostp cert issue`: `ostp sub status`; then `ostp sub enable` (behind nginx with `--vhost`), restart, `ostp sub urls` | subscriptions are off after issuing the certificate; after enable they are on, every key has `https://domain/sub/<token>`, `ostp sub status` has nothing red | P1 |
| S-41 | `curl https://domain/sub/<token>` | 200, one link per line (TLS first, then UDP), headers `Profile-Update-Interval`, `Profile-Title`, `Subscription-Userinfo`, `Cache-Control: no-store` | P1 |
| S-42 | `curl -H 'Accept: application/json' …` or `?format=json` | JSON with `name`, `update_interval_hours`, `links`, `usage` | P1 |
| S-43 | A made-up token; the token of a removed key | the same 404 as any other path | P1 |
| S-44 | `curl http://IP:50000/sub/<token>` from outside (plain HTTP) | not served, the decoy answers | P1 |
| S-45 | The same through nginx/apache/caddy | served | P1 (nginx) |
| S-46 | A key with a limit, its client used traffic | `usage` and `Subscription-Userinfo` show use and limit | P2 |
| S-47 | `include: ["tls"]`, `update_interval_hours: 1`, `path: "/s"` | only the TLS link, interval 1, path `/s/<token>` | P2 |
| S-48 | `subscription.enabled` without TLS, or a path overlapping `ws_path` / the panel | `ostp check` rejects the config with a clear error | P2 |

### 2.6 Probe resistance

| # | Steps | Expected | Prio |
|---|---|---|---|
| S-50 | `head -c 1000 /dev/urandom \| nc IP 50000` | the server stays up, the reply does not reveal OSTP | P1 |
| S-51 | `curl http://IP:50000/` and `curl http://IP:50000/<ws_path>` without Upgrade | 404 (or your fallback site) | P1 |
| S-52 | Slow header (slowloris) on 50000 and 443 | the connection is closed after ~10 s | P2 |
| S-53 | Hundreds of connections from one IP | the limit kicks in, the server keeps working for others | P2 |
| S-54 | TLS with a foreign SNI to the built-in 443 | handshake with the domain's certificate, then 404 | P2 |

### 2.7 Web panel

| # | Steps | Expected | Prio |
|---|---|---|---|
| S-60 | Open `http://127.0.0.1:9090/<webpath>/` (or through an SSH tunnel) | sign-in form | P1 |
| S-61 | Wrong password / right password | error / panel | P1 |
| S-62 | Overview with a connected, busy client | online > 0, total traffic grows, rates and chart match the load, uptime and version right | P1 |
| S-63 | "How clients connect" | address, UDP port, TLS (built-in or through a web server), subscriptions on/off, server DNS match the config | P1 |
| S-64 | Add a user with a name and a limit | shows up in the table, written to `config.json`, the share dialog opens right away | P1 |
| S-65 | Share: Subscription / TLS / UDP tabs | the QR shows and scans in the app, Copy copies the link | P1 |
| S-66 | Rename, change the limit, reset traffic, delete | reflected in the table and `config.json`; a deleted key no longer connects | P1 |
| S-67 | A client uses up its limit | the client is cut off, the limit bar is red | P2 |
| S-68 | Search, the Online and Near limit filters, column sorting | work | P2 |
| S-69 | Bulk create 10 keys | 10 keys in the table and the config | P2 |
| S-70 | Routing: change rules, save | applied at once, written to the config; invalid JSON is rejected | P2 |
| S-71 | Configuration: change and save | file written, restart warning shown; invalid JSON is not saved | P2 |
| S-72 | Activity | every panel action is listed, Clear works | P2 |
| S-73 | Switch language and theme, open on a phone (360–414 px wide) | everything translated, the light theme is readable; no page scrolls sideways, users are cards, the top bar is one row of icons | P2 |
| S-74 | Enable the API in the config without a sign-in (no token, no password), start the server | the panel does not start, the log says how to set a sign-in; with `"token": ""` a request with an empty `Authorization` header is refused | P1 |

### 2.8 Protocol v6, key expiry, server information

| # | Steps | Expected | Prio |
|---|---|---|---|
| S-80 | `ostp key`, `ostp links` on a new install | the server's public key is shown; every link has `pk=`; `legacy` (v5 clients) is on | P1 |
| S-81 | Client with a link that has `pk` | connects, the log says protocol v6 | P1 |
| S-82 | The same link with `pk` changed by one character | does not connect; the client says the server did not answer as expected (a server older than 0.5.0 or a replaced key) and to reissue the link; the server logs nothing about the attempt beyond what it logs for any unknown datagram | P1 |
| S-83 | `ostp key legacy off`, then a link without `pk` (v5); then `ostp key legacy on` | the v5 client is refused after off and connects after on; v6 clients are unaffected | P1 |
| S-84 | An existing server from 0.4.x: `ostp key`, then `ostp key server new` | before: no key, v5 only; after: key created, links get `pk=`; replacing a key later needs `--yes` and stops every older link | P2 |
| S-85 | `ostp manage user-add test --expires 1d`, then `user-set test --expires never` and `--expires 2020-01-01` | the date is shown by `ostp manage users` (a date means the end of that day, UTC; `1d` is 24 hours from now); `never` clears it; a past date is accepted and the key counts as expired at once | P1 |
| S-86 | A v6 client is connected; set `expires_at` of its key in `config.json` to the current Unix time plus a minute | the client stops and says the access key has expired; it does not reconnect; a v5 client with that key is refused as if over its limit | P1 |
| S-87 | Remove a key from `config.json` while its client is connected | within ~5 s the client stops with "your key was revoked or removed" and does not reconnect | P1 |
| S-88 | `systemctl stop ostp` while a client is connected | the client stops at once with "the server is shutting down" (not after 10 s of silence) and does not reconnect | P1 |
| S-89 | `ostp manage server-info --name … --location … --contact … --about-file about.md`, then the same without arguments | the values are saved and shown; a client sees them only while connected: a packet probe (S-50) gets nothing new | P1 |
| S-90 | The "i" of the subscription in the desktop and Android apps while connected | the operator's section (marked as the operator's words; empty fields say "Not given by the operator"), what the server reports (version, carriers, log privacy, IPv6, DNS filtering) and the key's traffic, limit, expiry and device limit; offline it opens with the last copy | P1 |
| S-91 | The same against a server older than 0.5.0-beta.1 | the window says the server does not send information about itself | P2 |
| S-92 | `ostp log privacy` shows the mode; set `strict`, `normal`, `debug` and restart | `normal` is the default; no mode but `debug` logs destinations (sites, SNI, DNS names); addresses are cut to /24 (IPv6 /48) in `normal` and tagged per UTC day in `strict`; `debug` says plainly what it records | P1 |
| S-93 | `ostp -V`, then `ostp uninstall --yes`, then on another install `ostp uninstall --yes --purge` | `-V` shows version and channel; without `--purge` the config stays, with it everything is removed; no question is asked with `--yes` | P2 |
| S-94 | Two `ostp` commands that edit the config at the same moment (for example `user-add` in a loop in two shells) | no lost write and no broken JSON: the config file is locked while it is changed | P2 |

### 2.9 Subscription links

| # | Steps | Expected | Prio |
|---|---|---|---|
| S-95 | A new user: `ostp manage users`, `ostp sub urls` | the subscription id (`sub_id`) is random and is not derived from the access key | P1 |
| S-96 | `ostp manage user-set WHO --new-sub-id`; open the old and the new link | the old one gets the same 404 as any wrong path; the new one works (within ~5 s while the lookup index catches up); the access key is unchanged and the client keeps connecting | P1 |
| S-97 | `ostp manage sub-ids`, then `sub-ids --assign-missing` on a config with users that have no `sub_id` | the first lists, the second gives each a random id and prints the new links | P2 |
| S-98 | `ostp sub enable` on a config with no `subscription.path`; then on one with `/sub` | a random path (`/` and 10 characters) in the first case; `/sub` is kept in the second | P1 |
| S-99 | Behind nginx, apache and caddy: a wrong subscription link, and a wrong path elsewhere | both give the web server's own 404 page (the site's own, if it has one); the two cannot be told apart | P1 (nginx), P2 (others) |

### 2.10 Path, MTU, loss, IPv6

| # | Steps | Expected | Prio |
|---|---|---|---|
| S-100 | A v6 client over UDP with `mtu` missing or `"auto"`; watch the log | `Path MTU: … bytes confirmed by a probe` lines climb to 1452 on a clean path; with `mtu` set to a number no probes run and the number is used | P1 |
| S-101 | Over UDP on a path that drops datagrams above ~1300 bytes (`iptables -m length` on a test machine) | `Path MTU: probes of … bytes are lost; sending … bytes at most`; the tunnel works, no stream stalls | P2 |
| S-102 | Over TLS and UoT | no probes; the size is the configured one (1350) | P2 |
| S-103 | A v6 client over UDP with 1 % and 5 % loss (`tc netem`), a download and an upload | transfers finish; no stream is reset by loss alone; `Stall #n` log lines appear only for the first stall and then every power of two | P1 |
| S-104 | A 0.4.x client (v5 link) under the same loss | works as before | P2 |
| S-105 | Cut the client's network for 30 s, then restore it (UDP, then TLS) | the log says reconnecting; the connection comes back on the same carrier, the profile's, and nothing switches to another carrier; with the old path back, "Connection restored … no connection was dropped" | P1 |
| S-106 | The same cut for more than 5 minutes | "giving up the old session", application connections reset, full handshakes repeat with pauses up to 30 s until the network is back or the user stops the tunnel | P2 |
| S-107 | TLS download at full speed | the RTT shown is the path's, the queue delay is shown only when above 200 ms and stays small (the server keeps the queue to about 100 ms) | P2 |
| S-108 | A server with IPv6 switched off in the kernel, a client device with IPv6 | no app hangs on IPv6 addresses: tunnel DNS answers AAAA with an empty set, the server log says `no IPv6 on this server` where it must | P1 |
| S-109 | A server with IPv6 | IPv6 sites open through the tunnel; server information shows `ipv6: true` | P2 |

## 3. Desktop GUI (Windows, Linux)

| # | Steps | Expected | Prio |
|---|---|---|---|
| G-01 | NSIS install; update over the previous version | starts, profiles and settings kept | P1 |
| G-02 | Import `ostp://` through "Link or subscription" and from the clipboard | the editor opens filled in, TLS fields included | P1 |
| G-03 | Create, edit and delete a profile by hand | works, the active profile stays consistent | P1 |
| G-04 | Share a profile | a QR shows (not an empty dialog), a phone scans it, the link copies | P1 |
| G-05 | Import `https://…/sub/…` | a subscription card (name, usage, "updated just now"); its profiles tagged "sub", the first selected | P1 |
| G-06 | Change the port or path on the server, press Update in the GUI | the subscription's profiles update, the selected one stays selected (same carrier), TTL desync setting kept | P1 |
| G-07 | Subscription with `update_interval_hours: 1`, restart the GUI an hour later | refreshed on its own | P2 |
| G-08 | Wrong URL, `http://…`, a removed key | a clear error on the card and in the toast; a URL that never worked is not kept | P1 |
| G-09 | QR of a subscription card | a phone scans it and imports a subscription | P2 |
| G-10 | Remove a subscription | it and its profiles are gone, manual profiles stay | P1 |
| G-11 | Connect over UDP, UoT, TLS (built-in and through nginx) | connects, traffic flows, speed and RTT shown | P1 |
| G-12 | TUN mode (with and without wintun.dll) | works with the driver, shows the instructions without it | P1 |
| G-13 | Domain/IP exclusions, MTU | work; changes while connected apply by hot reload | P2 |
| G-13a | Exclude a program (e.g. `chrome`) in proxy mode and in TUN mode | that program's traffic goes direct (its IP on a what-is-my-IP site is the home one), others go through the tunnel; with debug on the log shows `BYPASS (process …)` | P1 |
| G-13b | Exclude `госуслуги.рф` | the site goes direct in proxy and TUN mode | P2 |
| G-14 | Network check → Check server on a UDP profile | address × carrier table with RTT, a verdict line | P1 |
| G-15 | The same on a TLS profile | only TLS on the profile's port is probed | P1 |
| G-16 | Path scan (TTL) after the server check | a TTL row with answers marked, and a verdict | P2 |
| G-17 | Network DPI test | list of checks and a verdict, ~10 s | P1 |
| G-18 | Checks while the VPN is connected | run, the tunnel stays up | P2 |
| G-19 | Autostart, auto-connect, tray | work; the top bar has only the prober and settings buttons, there is no theme switch | P2 |
| G-20 | First run (no profiles): *I have a link* with an `ostp://` link and with a subscription | the profile or subscription is added, the main screen opens; *Skip* opens it too and the screen does not come back | P1 |
| G-21 | First run: *I have a server* with a root password on a clean VPS | steps tick off one by one, the server output is visible, the new profile connects | P1 |
| G-22 | The same with a private key (OpenSSH, with a passphrase) and with a non-root sudo user | installs; a wrong password or key gives a clear error and the server is not saved | P1 |
| G-23 | Reinstall the VPS (new host key), open the server in the app | refused with "host key changed", nothing runs | P1 |
| G-24 | *Server management*: Status, Users (add, rename, revoke, add to app, QR), Connection, Management (log) | match `ostp manage` on the server; a revoked key stops connecting | P1 |
| G-25 | Turn on the panel from the app, *Open the panel* | the panel opens in the browser through SSH, with no port open on the server; the VPN address is shown | P1 |
| G-26 | Restart, update or reboot while connected through that server | refused with "Disconnect first"; after disconnecting it works | P2 |
| G-27 | "Remember" off, restart the app, open the server | the password or key is asked for; with it on it is not; `servers.json` holds no secret in clear | P2 |
| G-28 | Add a profile from a link with `owndns=true` (and one with `dnsall=true`), press Connect | before the tunnel starts a notice appears; its buttons are disabled for 5 seconds with a countdown, Escape and a click outside do nothing; the `dnsall` text appears only for the second; after a choice the connection starts and the notice does not come back after a restart | P1 |
| G-29 | Server user with `max_devices: 1`. Import its `https://…/sub/…` in the GUI with *Send a device ID to subscriptions* off | a dialog "This subscription limits devices"; *Cancel*: the card says `Device ID needed: …`, nothing was sent; *Send and retry*: the switch turns on and the subscription is added; the panel lists one device with the OS (`Windows 11`) and the architecture | P1 |
| G-29a | The same user from a second computer, then a background refresh with the switch off on a third | the second: the card and the toast show the server's `device_limit` message; the background refresh opens no dialog and writes `Device ID needed: …` on the card | P1 |
| G-30 | *Server management → DNS* on a server with `ostp manage dns`: turn the filter, the takeover, encrypted-DNS block and safe search on and off, *Update lists* | each press asks first with `The service restarts and connected clients drop for a few seconds.` and a button that names the action; the result is shown like other actions and the tab reloads with the new state; the encrypted-DNS button is disabled with a reason while the takeover is off; lists, resolvers, rewrite and rule counts match `ostp manage dns`; against a server without `manage dns` the tab only says it is too old | P1 |
| G-31 | Import a profile whose link has no `pk` (v5) | the profile is marked with a warning that anyone with the key can pose as that server; connecting is not blocked | P1 |
| G-32 | A subscription whose server changed its key, then Update | the old profile is kept and the card asks whether to accept the new key or keep the old one; a key that appears where there was none is taken without a question | P1 |
| G-33 | Settings with several subscriptions and manual profiles; a long list | profiles are grouped under their subscription (manual ones in their own group), groups fold and remember it, the one with the selected profile is open, a search field appears for a long list | P2 |
| G-34 | *Server management → Users*: add a user with a limit, a device limit and an expiry date; edit; revoke | the values match `ostp manage users`; the expiry date and the new subscription link work as S-85 and S-96 | P1 |

## 4. Android

| # | Steps | Expected | Prio |
|---|---|---|---|
| M-01 | Install the APK (arm64 and armv7); update over the previous one | starts, profiles kept | P1 |
| M-02 | Import `ostp://` by QR, by link and by hand | profile created, TLS fields carried over | P1 |
| M-03 | Import a subscription by QR and by link | a card under Subscriptions (usage, limit bar, "updated"), profiles tagged "subscription" | P1 |
| M-04 | Update a subscription after a server change; remove a subscription | as G-06 and G-10 | P1 |
| M-05 | A subscription past its interval, launch the app | refreshed in the background on launch | P2 |
| M-06 | Subscription errors (404, http, no network) | error text on the card, no crash | P1 |
| M-07 | Connect over UDP, UoT, TLS | works | P1 |
| M-08 | Per-app split tunneling | excluded apps bypass the VPN | P2 |
| M-09 | Switch Wi-Fi ↔ mobile while connected | reconnects without user action | P1 |
| M-10 | Prober: server check | results, no "No implementation found" error | P1 |
| M-11 | Prober: TTL and DPI battery, also while connected | results, the app does not hang | P1 |
| M-12 | Share a profile | QR and link | P2 |
| M-13 | First run: link, QR, subscription, and *I have a server* (password and key) | as G-20 – G-22 | P1 |
| M-14 | *Settings → Server Management*: every tab, as G-24 | works on a 360 dp wide screen, nothing cut off | P1 |
| M-15 | *Open the panel* | opens in an in-app browser tab through SSH; the VPN address opens in Chrome while connected through the server | P1 |
| M-16 | Close and reopen the app with a remembered server; clear the app's data | no password asked / the servers list is empty and nothing crashes | P2 |
| M-17 | As G-28: a link with `owndns=true` / `dnsall=true`, then change *DNS of this server* in the profile editor | the notice before connecting (back button does nothing, buttons wait 5 seconds); the chosen DNS is the one the tunnel uses (operator: 10.1.0.1); the editor value is kept | P1 |
| M-18 | As G-29 on a phone: a user with `max_devices: 1`, *Send a device ID to subscriptions* off, add its subscription, then a second phone | the dialog on the first (*Cancel* leaves a card message, *Send and retry* adds it); the panel shows `Android <version>` and the phone's model; the second phone gets the server's `device_limit` message on the card and in the snackbar; a background refresh on launch opens no dialog | P1 |
| M-19 | As G-30 on a phone: *Settings → Server Management → DNS* | the same texts, confirmations and states as the desktop; the five tabs fit a 360 dp wide screen | P1 |
| M-20 | As G-31 and G-32 on a phone | the same warning, the same question; the buttons fit a 360 dp wide screen | P1 |
| M-21 | As G-33 and the server information window (S-90) on a phone | groups, search and the "i" window work; Markdown links in the "about" text open only after a confirmation | P2 |
| M-22 | As G-34 on a phone | the users editor with limits, devices and expiry works on a 360 dp wide screen | P1 |
| M-23 | Stop the server (`systemctl stop ostp`) and revoke the key while connected | the app shows the server's reason for 12 seconds in place of "Could not connect to the server" and does not connect again by itself | P1 |

## 5. CLI client

| # | Steps | Expected | Prio |
|---|---|---|---|
| C-01 | `ostp connect ostp://…` (UDP, UoT, TLS) | connects, SOCKS5 on `127.0.0.1:1088` works | P1 |
| C-02 | `ostp import ostp://…` | client config written | P1 |
| C-03 | `ostp import https://…/sub/…` | shows the subscription name, usage, the links and asks which one; the chosen link is written | P1 |
| C-03a | `ostp import https://…/sub/…` of a user with `max_devices`, with and without `"send_hwid": true` in the config | without: stops with a message that names `send_hwid`; with: imports, and the panel lists the device | P1 |
| C-04 | `ostp import http://…`, a wrong token | a clear error, config untouched | P1 |
| C-05 | TUN on Linux, `eval $(ostp proxy-env)` | work | P2 |

## 6. Compatibility

| # | Steps | Expected | Prio |
|---|---|---|---|
| X-01 | Clients of the previous stable (GUI, Android, CLI) against the new server over UDP and UoT | connect | P1 |
| X-02 | New clients against a server of the previous stable over UDP and UoT | connect | P1 |
| X-03 | Links from older versions (`type=tcp`, no `type`, bracketed IPv6) | import the same way in every client | P1 |
| X-04 | Server and client configs from older versions, unedited | start; `ostp` points at `migrate` | P1 |
| X-05 | A 0.4.x client (a v5 link) against a 0.5.0 server with `legacy on` (the transitional mode) | connects over UDP and UoT | P1 |
| X-06 | A 0.5.0 client with a v6 link against a 0.4.x server | does not connect and says why (a server older than 0.5.0, or a replaced key), not a bare timeout | P1 |
| X-07 | A 0.5.0 client with a v5 link (no `pk`) against a 0.4.x server | connects as before, with the unverified-server warning in the apps | P1 |

## 7. Release criteria

- **Beta:** CI is green on the branch the beta is cut from (CI is run by hand on `alpha`), the release build is green, and every P1 case passes. Failing P2 cases are listed as known issues in the release notes.
- **Stable:** every case, P2 included, passes on every platform in section 1.
- Any crash, lost profiles or keys, a key leaking into a log, or traffic bypassing the tunnel with the kill switch on blocks the release whatever its priority.

## Report template

```
Version: v0.5.0-beta.N        Date:            Tester:
Server: OS, IP versions, frontend (builtin / nginx / apache / caddy)
Clients: Windows …, Android … (model, ABI), Linux …
Networks: …

Passed: S-01, S-02, …
Failed: S-27 — <what happened>, log: <link>, issue: #…
Not run: G-07 — <why>
Verdict: ship / don't ship
```
