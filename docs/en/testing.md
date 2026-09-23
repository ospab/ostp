# Test protocol

The checklist run before a beta and a stable release. It covers the server, the web panel, the desktop GUI, the Android client and the CLI client.

How to use it:

- Every case has a number, steps and an expected result. A case passes only when the result matches in full.
- **P1** is required for both beta and stable. **P2** is required for stable, and for beta when possible.
- When something does not match, open an issue with the case number, version, platform and log. The run report follows the template at the end.
- Certificates are tested against Let's Encrypt staging (`--staging`) first, then the production CA, which has strict limits on failed issuance.

## 0. Automated checks

Run by CI or by the developer before the manual run.

| # | Check | Expected | Prio |
|---|---|---|---|
| A-01 | `cargo test --workspace --lib` | all green | P1 |
| A-02 | `cargo test -p ostp --bin ostp` (nginx/apache/caddy templates, CLI) | green | P1 |
| A-03 | `cargo test -p ostp-jni` (every Kotlin `external fun` has a JNI export) | green | P1 |
| A-04 | `flutter analyze lib` | no `error` | P1 |
| A-05 | `node --check ostp-gui/src/main.js` | no errors | P1 |
| A-06 | `cargo tree -i aws-lc-sys` at the root and in `ostp-gui/src-tauri` | empty | P1 |
| A-07 | Release build on GHA | every job green, 21 files in the release | P1 |

## 1. Test bed

- **Server:** a VPS with Debian 12 or Ubuntu 24.04, public IPv4 (IPv6 too, if possible). A domain with an A record (and AAAA) pointing at it. Ports 80, 443 and 50000 (TCP+UDP) open.
- **Web servers for section 2.4:** separate clean machines or snapshots with nginx, apache (Debian and the RHEL family) and caddy.
- **Clients:** Windows 10/11 x64 (arm64 if available), Android 8+ on arm64 and armv7, Linux x64 for the CLI.
- **Networks:** a home ISP, a mobile network, if possible an IPv6-only network with NAT64 and a network with noticeable DPI filtering.
- Record the version of every component in the report (`ostp --version`, About in the GUI, the APK version).

## 2. Server

### 2.1 Install, update, configuration

| # | Steps | Expected | Prio |
|---|---|---|---|
| S-01 | Fresh install with `install.sh`, then `ostp setup` in Server mode | the `ostp` service is active, `ostp links` prints working links | P1 |
| S-02 | `ostp update --branch beta` on a server running the previous version | new version, service restarted, keys and settings kept | P1 |
| S-03 | `ostp migrate --dry-run` on configs from 0.4.5 and older (modular v0, flat v1) | steps, changes and unknown keys with suggestions are printed; the file is untouched | P1 |
| S-04 | `ostp migrate` on the same configs | `config_version: 2`, `access_keys` and `api.token` kept, the server starts | P1 |
| S-05 | A config newer than supported (`config_version: 99`) | migrate refuses and leaves the file alone | P2 |
| S-06 | `ostp check` on a valid and a broken config | "Config OK" / a clear error naming the field | P1 |
| S-07 | Add a key to `config.json` of a running server | within ~5 s the new key connects, no restart | P1 |
| S-08 | `ostp links` and `ostp links qr` | TLS/UDP links and SUB (when subscriptions are on) per client; in qr mode one QR on screen: ← → switch SUB / TLS / UDP, ↑ ↓ or Enter switch clients, `q` quits; redirected to a file (`> qr.txt`) every client is printed | P1 |
| S-09 | Scan a QR from `ostp links qr` with a phone | the app imports the profile or the subscription | P1 |

### 2.2 Carriers

| # | Steps | Expected | Prio |
|---|---|---|---|
| S-10 | Client over a UDP link | connects, traffic flows, RTT shown | P1 |
| S-11 | Client over UoT (TCP) on 50000 | same | P1 |
| S-12 | UoT with junk packets and TCP fragmentation | connects | P2 |
| S-13 | Relay: `ostp init relay`, client goes through the relay | traffic flows, the relay holds no keys | P2 |
| S-14 | Client with a wrong key | no connection, the server stays up, no key in clear in the log | P1 |

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
| S-30 | `ostp cert issue` on a machine with a web server | the web server is found; after confirmation a site is added (Debian/Ubuntu: `sites-available/ostp-<domain>` with a symlink in `sites-enabled`, otherwise `conf.d/`), the config test passes (`nginx -t` / `configtest` / `caddy validate`), reload done; `ostp cert status` shows every check green | P1 (nginx), P2 (others) |
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
| S-73 | Switch language and theme, open on a phone | everything translated, the light theme is readable, the narrow layout holds | P2 |

## 3. Desktop GUI (Windows)

| # | Steps | Expected | Prio |
|---|---|---|---|
| G-01 | NSIS install; update over the previous version | starts, profiles and settings kept | P1 |
| G-02 | Import `ostp://` through "Link or subscription" and from the clipboard | the editor opens filled in, TLS fields included | P1 |
| G-03 | Create, edit and delete a profile by hand | works, the active profile stays consistent | P1 |
| G-04 | Share a profile | a QR shows (not an empty dialog), a phone scans it, the link copies | P1 |
| G-05 | Import `https://…/sub/…` | a subscription card (name, usage, "updated just now"); its profiles tagged "sub", the first selected | P1 |
| G-06 | Change the port or path on the server, press Update in the GUI | the subscription's profiles update, the selected one stays selected (same carrier), fragmentation settings kept | P1 |
| G-07 | Subscription with `update_interval_hours: 1`, restart the GUI an hour later | refreshed on its own | P2 |
| G-08 | Wrong URL, `http://…`, a removed key | a clear error on the card and in the toast; a URL that never worked is not kept | P1 |
| G-09 | QR of a subscription card | a phone scans it and imports a subscription | P2 |
| G-10 | Remove a subscription | it and its profiles are gone, manual profiles stay | P1 |
| G-11 | Connect over UDP, UoT, TLS (built-in and through nginx) | connects, traffic flows, speed and RTT shown | P1 |
| G-12 | TUN mode (with and without wintun.dll) | works with the driver, shows the instructions without it | P1 |
| G-13 | Kill switch, domain/IP/process exclusions, MUX, MTU | work; changes while connected apply by hot reload | P2 |
| G-14 | Network check → Check server on a UDP profile | address × carrier table with RTT, a verdict line | P1 |
| G-15 | The same on a TLS profile | only TLS on the profile's port is probed | P1 |
| G-16 | Path scan (TTL) after the server check | a TTL row with answers marked, and a verdict | P2 |
| G-17 | Network DPI test | list of checks and a verdict, ~10 s | P1 |
| G-18 | Checks while the VPN is connected | run, the tunnel stays up | P2 |
| G-19 | Autostart, auto-connect, tray, themes | work | P2 |

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

## 5. CLI client

| # | Steps | Expected | Prio |
|---|---|---|---|
| C-01 | `ostp connect ostp://…` (UDP, UoT, TLS) | connects, SOCKS5 on `127.0.0.1:1088` works | P1 |
| C-02 | `ostp import ostp://…` | client config written | P1 |
| C-03 | `ostp import https://…/sub/…` | shows the subscription name, usage, the links and asks which one; the chosen link is written | P1 |
| C-04 | `ostp import http://…`, a wrong token | a clear error, config untouched | P1 |
| C-05 | TUN on Linux, `eval $(ostp proxy-env)` | work | P2 |

## 6. Compatibility

| # | Steps | Expected | Prio |
|---|---|---|---|
| X-01 | Clients of the previous stable (GUI, Android, CLI) against the new server over UDP and UoT | connect | P1 |
| X-02 | New clients against a server of the previous stable over UDP and UoT | connect | P1 |
| X-03 | Links from older versions (`type=tcp`, no `type`, bracketed IPv6) | import the same way in every client | P1 |
| X-04 | Server and client configs from older versions, unedited | start; `ostp` points at `migrate` | P1 |

## 7. Release criteria

- **Beta:** every case in section 0 and every P1 passes. Failing P2 cases are listed as known issues in the release notes.
- **Stable:** every case, P2 included, passes on every platform in section 1.
- Any crash, lost profiles or keys, a key leaking into a log, or traffic bypassing the tunnel with the kill switch on blocks the release whatever its priority.

## Report template

```
Version: v0.4.6-beta.N        Date:            Tester:
Server: OS, IP versions, frontend (builtin / nginx / apache / caddy)
Clients: Windows …, Android … (model, ABI), Linux …
Networks: …

Passed: S-01, S-02, …
Failed: S-27 — <what happened>, log: <link>, issue: #…
Not run: G-07 — <why>
Verdict: ship / don't ship
```
