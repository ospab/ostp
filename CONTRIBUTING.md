# Contributing to OSTP

Code, bug reports, tests, documentation and security review are all welcome. By contributing you agree that your contribution is licensed under the project's license (AGPL-3.0).

---

## Development Setup

You will need:

*   **Rust** (current stable): install via [rustup](https://rustup.rs/).
*   **Git**.
*   Only for the desktop GUI: **Node.js 18+** and the [Tauri prerequisites](https://tauri.app/start/prerequisites/).
*   Only for the Android app: **Flutter** and the Android NDK.

### Builds and tests run on GitHub Actions

The project is large, so tests and release builds are not run on a developer's machine. The workflow is
[`.github/workflows/ci.yml`](.github/workflows/ci.yml):

*   It starts by itself on pushes to `beta` and `master` that change code. Changes only to `docs/`, Markdown files and licences start nothing.
*   For `alpha` or any other branch, start it by hand: the Actions tab (*Run workflow*) or `gh workflow run ci.yml --ref alpha`.
*   It runs the tests of the core, client, server, CLI, SSH and JNI crates (the end-to-end v6 and roaming tests included), builds a Linux and a Windows
    binary kept as run artifacts (`gh run download <id> --name ostp-linux-amd64`), and checks the apps (static checks and their tests).
*   Results: `gh run list --workflow ci.yml`, `gh run view <id> --log-failed`.

Release packages (installers, APK, `ostp` for every platform) are built by `.github/workflows/release.yml` from a tag, never by hand.

For a quick check of your own change you can still run `cargo check -p <crate>` or `cargo test -p <crate>` for the crate you touched.
The web panel (`ostp-server/panel/`) is plain HTML/CSS/JS embedded into the server binary: there is no separate build step.

### Releases

Releases are cut by the maintainer with `scripts/gha.ps1`; nothing else tags or promotes. A cycle has one target version (now 0.5.0) that stays in the
manifests through all pre-releases; only the per-channel counter moves, and it lives in the tag (`v0.5.0-alpha.6`, `v0.5.0-beta.1`, then `v0.5.0`).
`.release-state.json` at the repository root remembers the target version, the channel and both counters; `gha.ps1` updates it and the tag push starts
`release.yml`. Promotion to `beta` and `master` is a fast-forward from the branch below. Do not edit `.release-state.json` by hand and do not push `v*` tags.

---

## Project Structure

The Cargo workspace (`Cargo.toml`) has these members:

| Path | What it is |
|---|---|
| [`ostp/`](ostp) | The `ostp` binary: CLI, setup wizard, `cert`/`sub`/`panel`/`dns`/`overnet`/`warp`/`key`/`manage`/`log` commands, runs client or server from the config. |
| [`ostp-core/`](ostp-core) | The protocol: Noise handshake (v5 and v6), header obfuscation, framing and padding, the session layer, ARQ, congestion control, relay messages, share links, log privacy. |
| [`ostp-client/`](ostp-client) | Client: local SOCKS5/HTTP proxy, TUN mode, exclusions, UDP/UoT/TLS carriers, session roaming, path MTU, network prober. |
| [`ostp-server/`](ostp-server) | Server: session dispatcher, relay to the internet, TCP sniffing (UoT, TLS, HTTP upgrade, decoy), certificates, subscriptions, web panel and API. |
| [`ostp-ssh/`](ostp-ssh) | SSH client used by the apps to install and manage a server, and the saved-servers store. |
| [`ostp-dns/`](ostp-dns) | Filtering DNS resolver for the server: block lists, rules, rewrites, cache. |
| [`ostp-tun/`](ostp-tun) | Platform TUN device and routing (Wintun on Windows). |
| [`ostp-warp/`](ostp-warp) | Cloudflare WARP as the server's exit: WireGuard and a SOCKS5 proxy in user space. |
| [`ostpd/`](ostpd) | Privileged helper that runs the tunnel for the desktop GUI on Windows. |
| [`ostp-jni/`](ostp-jni) | JNI bindings used by the Android app. |
| [`third_party/netstack-smoltcp/`](third_party/netstack-smoltcp) | A patched copy of `netstack-smoltcp` (TCP reset support), see its README. |

Outside the workspace:

| Path | What it is |
|---|---|
| [`ostp-gui/`](ostp-gui) | Desktop client (Tauri) for Windows, Linux and macOS; has its own Cargo workspace in `src-tauri`. |
| [`ostp-flutter/`](ostp-flutter) | Android client (Flutter). |
| [`docs/`](docs) | Documentation in English and Russian, see [`docs/README.md`](docs/README.md). |
| [`scripts/`](scripts) | `install.sh`, `install.ps1`, `gha.ps1` (releases), `build.ps1` (local packages). |

---

## Branch Strategy

Three long-lived branches, from least to most stable:

| Branch | Role |
|---|---|
| `alpha` | Active development. All feature work and fixes land here first (0.5.0 work included; protocol v6 is in `alpha`). |
| `beta` | Fast-forwarded from `alpha` once it has had some soak time. Ships as the `{version}-beta.N` release channel. |
| `master` | Fast-forwarded from `beta` when it is proven stable. Stable releases (`vX.Y.Z`) are cut from here. |

`beta` and `master` are **never** committed to directly - they only ever move forward by fast-forwarding from the branch below them. This means promotion is always a plain `git merge` with zero conflicts by construction: don't `git merge`/rebase feature work directly onto `beta` or `master`.

**Contributor PRs target `alpha`**, not `master`.

---

## Development Workflow

1.  **Check for existing issues** or open a new one to discuss proposed changes before starting work.
2.  **Fork the repository** and create a new branch from `alpha`:
    ```bash
    git checkout alpha
    git checkout -b feat/your-feature-name
    ```
3.  **Implement your changes**, ensuring you write appropriate unit or integration tests.
4.  **Format the files you changed** with `rustfmt`. The tree is not fully
    formatted yet, so do not run `cargo fmt --all` in a feature branch: it
    would bury your change in unrelated reformatting.
5.  **Run clippy** and do not add new warnings:
    ```bash
    cargo clippy --workspace --all-targets
    ```
6.  **Run the tests** of the crates you touched (`cargo test -p <crate>`) and push the branch; the full set runs on GitHub Actions (see above).
7.  **Add a line to [`CHANGELOG.md`](CHANGELOG.md) and [`CHANGELOG.ru.md`](CHANGELOG.ru.md)** under *Unreleased* for anything a user would notice. Every change goes into both files.
    Documents under `docs/` exist in English and Russian with the same content: change both.

---

## Commit Message Conventions

```
<type>(<scope>): <short, imperative summary>

<optional body - explain WHY, not what; the diff already shows what changed>
```

- **Type** - one of: `feat` (new capability), `fix` (bug fix), `docs`, `refactor` (no behavior change), `perf`, `test`, `chore` (deps/tooling/version bumps), `ci`, `security`.
- **Scope** (optional) - the crate or area touched: `client`, `server`, `core`, `gui`, `flutter`, `ci`, `docs`, etc. e.g. `fix(client): ...`.
- **Summary** - imperative mood ("add", not "added"/"adds"), no trailing period, ideally under ~70 characters.
- **Body** - only when the *why* isn't obvious from the diff: a prior bug this fixes, a constraint that shaped the approach, a tradeoff you made. Don't restate what the diff already shows. Wrap at ~72 columns.

```
fix(server): drop junk frames by per-key marker instead of a global one

A fixed 4-byte marker on every junk packet is itself a DPI signature any
observer can filter on across every OSTP deployment. Derive the marker
from the access key (HKDF, same scheme as obfuscation_key/psk) so it's
per-user and indistinguishable from the packet's own random payload.
```

Multiple unrelated changes belong in separate commits, not one bundled commit - it keeps `git bisect` and review useful. Squash-merge is fine for a PR with a few "fix typo" / "address review" commits, but don't squash logically distinct changes together.

---

## Coding Guidelines

*   **Safety**: Avoid using `unsafe` blocks unless absolutely necessary for low-level system bindings (e.g., FFI configurations like `setsockopt`). When using `unsafe`, add safety doc comments explaining why it is safe.
*   **Documentation**: Document public modules, structs, and functions. Maintain comment integrity across codebase changes.
*   **Logging**: Use the `tracing` framework for structured logging. Avoid `println!` for production logs.
*   **Interface**: In the GUI and the panel, keep to the existing look. No emoji, gradients or decorative effects; the layout has to work on a phone screen.

---

## Submitting Pull Requests

1.  Push your branch to your GitHub fork:
    ```bash
    git push origin feat/your-feature-name
    ```
2.  Open a Pull Request (PR) targeting the `alpha` branch (see [Branch Strategy](#branch-strategy) - `master` only receives fast-forwards from `beta`, never direct PRs).
3.  In your PR description, explain the rationale behind your changes, what was fixed/added, and how it was tested.
4.  CI does not start by itself on a branch that is not `beta` or `master`: run `ci.yml` on it by hand, or the maintainer will, and check that it passes.

---

## Security Vulnerabilities

If you discover a security vulnerability, please do **not** open a public issue. See [SECURITY.md](SECURITY.md) for how to report it privately.
