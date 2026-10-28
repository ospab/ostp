# Integrations

`ostp-core` does no I/O of its own. Each host application links it and supplies the sockets, the TUN adapter and the interface, as described below.

## Android: Flutter app and JNI
`ostp-flutter` is the mobile app (Flutter; Android only for now). It embeds the Rust client engine on Android through `ostp-jni`, a dedicated crate exporting a small JNI surface (`Java_net_ostp_client_OstpClientSdk_*`) consumed by the app's Kotlin layer (`OstpClientSdk.kt`, `OstpVpnService.kt`, `MainActivity.kt`): start/stop the client, metrics, logs, network changes, the prober, subscriptions, update checks, and `serversCall` for server management (below).

- **Runtime**: `ostp-jni` runs its own multithreaded Tokio runtimes in the app process, and the Kotlin side calls it from background threads, so tunnel I/O does not block the UI thread.
- **Polling**: metrics, logs and the output of server commands are read through plain getter calls; there is no push channel.
- **Split tunneling** is per app (Android's `VpnService` allow/deny lists); process-name exclusions do not exist on Android.

## Desktop GUI
`ostp-gui` is a Tauri v2 desktop application (Windows and Linux) that drives the same client engine in-process for proxy mode and through a helper for TUN mode. It has one dark theme and two buttons in the top bar: the network prober and settings.

### TUN privileges
Creating a TUN adapter needs elevated rights, and the app should not run elevated. TUN setup is therefore done by `ostp-tun-helper`, a small process the app starts and controls over a local command channel (start and stop, with a config and token). Only the helper runs elevated (UAC on Windows, polkit/pkexec on Linux). The actual adapter creation code lives in the shared `ostp-tun` crate, used by both the helper and the CLI's own native TUN path (see [`client.md`](client.md)).

### Updates
The app checks GitHub for a newer stable or beta release when it opens (this can be turned off in settings) and on "Check for updates now". It only tells the user; nothing is downloaded until they press "Update now". Then the app downloads its own build from the release, checks it against the SHA-256 that GitHub publishes for every release file (no hash or a different one: nothing is installed), stops the tunnel and installs it:

- Windows, installed with the setup program: the new setup runs as an update (`/P /R /UPDATE`: a progress bar, no questions, shortcuts and data kept, the app restarts). Windows asks for consent once, because the app is installed for all users.
- Windows portable, Linux and macOS: the files next to the app (`ostp-gui`, `ostp-tun-helper`, `wintun.dll`) are replaced and the app restarts. The old files are renamed to `.old` first, put back if anything fails, and removed on the next start. The folder has to be writable by the user.

If the install fails, the dialog shows why and offers the release page instead.

The Android app does the same with its APK: it downloads the build for the phone's architecture, checks the size and the SHA-256, and opens the system installer, which installs it over the current app because both are signed with the same key. If the app may not install apps yet, it opens that setting first.

## Your own server from the apps

Both apps can install OSTP on a VPS and manage it afterwards, for people who have bought a server and do not want to learn Linux. The SSH work is done by the `ostp-ssh` crate, shared by the desktop app (Tauri commands in `ostp-gui/src-tauri/src/servers.rs`) and Android (`serversCall` in `ostp-jni`).

**First run.** When the app has no profiles or subscriptions it opens on *Let's get started*:
- *I have a link*: an `ostp://` link or a subscription URL (on Android also by QR code).
- *I have a server*: address, SSH port, login, and a password or a private key (OpenSSH, PEM or PuTTY `.ppk`, with its passphrase). The app connects, checks the system (architecture, systemd, root or sudo), downloads the install script for its own release channel (`master`, `beta` or `alpha`) and runs `install.sh -y`, which installs OSTP, writes a config with one user and starts the service. The first user's links become profiles in the app. Every step and the server's output are shown as it runs.

**Server management** (*Settings → Server management*), per server:
- *Status*: service state, version, running time, connected sessions, users, OS, load, memory, disk; restart and update OSTP.
- *Users*: add, rename, revoke; traffic (kept across restarts and updates) and who is online; add a user's links to this app; share as a QR code.
- *Connection*: UDP/TCP port, TLS on 443 with the domain and certificate expiry, getting a certificate (`ostp cert issue`), subscriptions on or off.
- *Management*: the web panel (turn on with a sign-in, open, turn off), the server log, the SSH host key, rename, reboot, uninstall OSTP, forget the server.

Changes that restart the service are refused while this device's VPN goes through the same server, since the answer would never arrive.

**How it talks to the server.** Everything runs over one SSH connection per server, kept open while the app runs. Commands run as root: directly when signed in as root, otherwise through `sudo -S` with the sign-in password on stdin, so it never appears on a command line. State and changes go through `ostp manage` (JSON, see [`server.md`](server.md#traffic-statistics-and-ostp-manage)); longer operations (install, update, certificate) stream their output line by line.

**Opening the web panel.** The app forwards a local port on `127.0.0.1` to the panel's port on the server's loopback through the SSH connection and opens it in the browser (an in-app browser tab on Android, so the app stays in the foreground and the forward alive). No port has to be opened on the server. The app also shows the panel's address through the VPN, `http://10.1.0.1:<port>/<webpath>/`, which works in any browser on a device connected through that server.

**Security.**
- The server's SSH host key is pinned by its SHA-256 fingerprint on the first connection; a different key later is refused ("host key changed"), not silently accepted.
- A password or key is kept only when the user asks. It is sealed with ChaCha20-Poly1305 in `servers.json` under a random 32-byte master key; the master key lives in the system credential store (Windows Credential Manager, Secret Service on Linux, the Android Keystore wraps it on Android). Without a usable store nothing secret is written and the app asks at each connection.
- The app runs only a fixed set of commands on the server (`ostp manage` subcommands, update, restart, reboot, uninstall, panel, certificate, subscriptions); the page cannot send arbitrary shell.

## System interfaces
- **Windows system proxy** (`sysproxy.rs`): writes and restores the WinINet proxy values; excluded domains go into its bypass list in both punycode and readable form.
- **TUN adapters** (`ostp-tun`): Wintun on Windows, native TUN devices on Linux/macOS; a userspace `netstack-smoltcp` stack reconstructs TCP/UDP flows from the raw IP packets the adapter delivers.
- **Process-based exclusion** (`process_lookup.rs`): finds the program behind a local socket through `GetExtendedTcpTable`/`GetExtendedUdpTable` on Windows and `/proc/net` on Linux, in both TUN and proxy mode, so per-process bypass rules (§[`client.md`](client.md)) work without a kernel driver.
