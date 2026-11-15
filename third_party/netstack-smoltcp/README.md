# netstack-smoltcp (OSTP copy)

Upstream: <https://github.com/cavivie/netstack-smoltcp>, crate `netstack-smoltcp` 0.2.4 (crates.io),
upstream commit `0ec8fde80c775110492e7498e3f5d31a287dbb89`.
Licence: MIT OR Apache-2.0 (`LICENSE-MIT`, `LICENSE-APACHE`), both compatible with the AGPL-3.0 of OSTP.

The workspace uses this copy through `[patch.crates-io]` in the root `Cargo.toml` and in
`ostp-gui/src-tauri/Cargo.toml`.

## What differs from 0.2.4

- `src/tcp.rs`: new `TcpStream::abort(&self)`. Dropping a `TcpStream` (or `shutdown`) ends the
  connection with a FIN; `abort` ends it with a RST. It sets a new send state `Abort`; the runner turns it
  into `socket.abort()` on the smoltcp socket, discards what is still queued in the stream's buffers,
  wakes the readers and writers (a read returns EOF, a write fails with `BrokenPipe`), and the RST goes out
  with the next interface poll, before the socket is removed. Nothing else changed.
- `tests/tcp_abort.rs`: new; plays the program's side of a TCP connection with raw IP packets and checks
  that `abort` emits a RST and no FIN, and that a drop or `shutdown` emits a FIN and no RST (IPv4 and IPv6).
- `Cargo.toml`: the one from the upstream `Cargo.toml.orig`, without the examples and their
  dev-dependencies (`tun2`, `tun-rs`, `structopt`, `socket2`, `tracing-subscriber`), `publish = false`.
  `examples/`, `scripts/`, `.github/` and the lock file are not copied.

When upstream gets an equivalent, drop this copy and the two `[patch.crates-io]` entries.
