# Coordination between parallel Claude sessions

Several Claude sessions work on this repository at once. They cannot see each
other directly, so they coordinate through git: this file lists who is working
on what. Keep it short and current.

## Protocol

1. Before starting: `git fetch origin`, then read this file on `origin/alpha`
   and on every `origin/claude/*` branch
   (`git show origin/<branch>:.claude/COORDINATION.md`).
2. Claim an area: add a row below, commit it together with your first change,
   push. An area is files or modules, not a feature name.
3. Do not edit files another session has claimed. If you must, keep the change
   minimal and say so in the commit message (`touches <file>, claimed by <session>`).
4. When done (merged into `alpha` or abandoned): remove your row.
5. Rebase onto `origin/alpha` before pushing; never force-push someone
   else's branch.

## Claims

| Session / branch | Area (files) | What | Status |
|---|---|---|---|
| `claude/ostp-cert-validation-gr1dis` | `ostp-server/src/dispatcher.rs` (roaming block in `on_datagram`), `ostp-core/src/protocol.rs` (inbound nonce tracking, `on_path_change`), `ostp-core/src/congestion.rs` (`reset_path`) | Roaming only on authenticated, fresh packets | done, waiting for merge |
| `claude/ostp-cert-validation-gr1dis` | `ostp-client/src/bridge.rs` (reconnect paths, session move, carrier choice), `ostp/tests/roaming.rs` | Seamless session move to a new socket of the same transport (no automatic transport switch or reconnect) | done, waiting for merge |
