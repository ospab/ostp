# OSTP: notes for Claude Code

Read `.claude/HANDOFF.md` first if it exists (local, not in git): branch state, what is left
to do. `.claude/COORDINATION.md` lists files other sessions are working on.

In short:
- Reply to the user in Russian.
- Branches: `alpha → beta → master`, fast-forward only; releases only through
  `scripts/gha.ps1` (it updates `.release-state.json`, the changelogs and the tag), and only
  when the owner says so.
- Do not build or test locally: CI on GitHub Actions does it (`.github/workflows/ci.yml`,
  by hand for alpha or any branch: `gh workflow run ci.yml --ref alpha`; automatic on code
  pushes to beta and master). Prefix `gh` and `git push` with `env -u HTTPS_PROXY`.
- Every change goes into "Unreleased" in both `CHANGELOG.md` and `CHANGELOG.ru.md`; docs exist
  in English and Russian with the same content.
- 0.5.0 speaks protocol v6 (Noise NKpsk0, server key `pk=` in links). A link without `pk` is
  v5, which a server accepts only with `protocol.accept_v5`; 0.4.x clients are v5. Wire
  changes must stay readable by v6 peers from alpha.6 on (they skip unknown frames).
- The client never switches transport (carrier) on its own: the user chooses. Reconnecting
  on the same carrier after a lost path is wanted (stability first; owner, 2026-11-21).
- Server and key information reaches clients only inside an established tunnel, never in
  anything fetchable before connecting (owner, 2026-11-22).
- Commit and push when a piece of work is done.
