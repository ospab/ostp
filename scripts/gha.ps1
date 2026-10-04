<#
.SYNOPSIS
  Cuts a new OSTP release and pushes the tag that triggers the matching
  GitHub Actions build (see .github/workflows/release.yml, which only
  triggers on "v*" tag pushes + workflow_dispatch — a bare branch push
  does NOT start a build).

.DESCRIPTION
  A release cycle has ONE fixed target version (e.g. "0.4.1") that stays in
  Cargo.toml/tauri.conf.json/package.json unchanged through every alpha and
  beta build — only a per-channel ITERATION counter increments, and that
  counter lives ONLY in the git tag, never in the manifests:

    v0.4.1-alpha.1  ->  v0.4.1-alpha.2  ->  ...  ->  v0.4.1-alpha.100
    v0.4.1-beta.1   ->  v0.4.1-beta.2   ->  ...  ->  v0.4.1-beta.100
    v0.4.1                                                <- master: iteration dropped

  This is deliberately NOT "0.4.1.5-alpha" (a 4th dot-separated component
  before the hyphen) — that is not valid semver, and Cargo's version parser
  rejects it outright. "0.4.1-alpha.5" (dot AFTER the hyphen, a semver
  pre-release identifier) is the only form that keeps Cargo.toml itself
  parseable, so that's the only place the iteration number is allowed to
  live: the git tag.

  Promoting to beta/master first fast-forwards that branch to `alpha`
  (--ff-only — this always succeeds cleanly as long as nobody ever commits
  directly to beta/master, per CONTRIBUTING.md's branch strategy), so
  a release always ships alpha's latest, not a stale branch. Switching to a
  channel for the first time in a cycle resets THAT channel's iteration
  counter to 1 (a fresh promotion starts its own count; it doesn't inherit
  wherever alpha's counter happened to be).

  Remembers {target_version, branch, alpha_iteration, beta_iteration} in
  .release-state.json at the repo root. Running with no arguments repeats
  last time's branch, bumping that channel's iteration by one — manifests
  are NOT touched (nothing to bump: the target version hasn't changed).
  -NewVersion starts a new target version line and resets both iteration
  counters to 0 — THIS is the one case that bumps every manifest.

.PARAMETER NewVersion
  Set a new target version (e.g. "0.4.2") instead of continuing the current
  one. Resets both alpha_iteration and beta_iteration to 0. Defaults the
  channel back to alpha unless -Branch is also given this run.

  NOTE: this parameter is deliberately NOT named "Switch" — PowerShell's
  `switch` statement keyword is matched case-insensitively against variable
  names in scope, and a script parameter named exactly $Switch silently
  breaks every `switch (...) { ... }` expression later in the same script
  (it evaluates to nothing, no error). Confirmed by bisection: renaming the
  parameter is the only thing that fixes it. Do not rename this back.

.PARAMETER Branch
  Which branch/channel to release from: master, beta, or alpha.
  Defaults to whatever was used last time (see .release-state.json).

.EXAMPLE
  .\scripts\gha.ps1
  Bumps the current channel's iteration by one and pushes v{target}-{channel}.{N}.

.EXAMPLE
  .\scripts\gha.ps1 -NewVersion 0.4.2
  Starts a fresh 0.4.2 cycle: manifests -> 0.4.2, alpha iteration resets to 1,
  ships v0.4.2-alpha.1.

.EXAMPLE
  .\scripts\gha.ps1 -Branch beta
  Promotes alpha -> beta (beta channel), resets beta_iteration to 1
  (or bumps it if already mid-beta), ships v{target}-beta.{N}.

.EXAMPLE
  .\scripts\gha.ps1 -Branch master
  Promotes to master and ships the bare v{target} stable tag — no iteration.
#>
[CmdletBinding()]
param(
    [string]$NewVersion,
    [ValidateSet('master', 'beta', 'alpha')]
    [string]$Branch
)

$ErrorActionPreference = "Stop"

function Write-Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Fail($msg) { Write-Host "ERROR: $msg" -ForegroundColor Red; exit 1 }

# -- Locate repo root, regardless of where this script was invoked from ------
$RepoRoot = (git rev-parse --show-toplevel 2>$null)
if (-not $RepoRoot) { Fail "Not inside a git repository." }
Set-Location $RepoRoot

$StateFile = Join-Path $RepoRoot ".release-state.json"

# -- Refuse to run on a dirty tree: this script commits, and an autocommit --
# -- silently sweeping up unrelated WIP changes would be a nasty surprise. --
$dirty = git status --porcelain
if ($dirty) {
    Write-Host $dirty
    Fail "Working tree has uncommitted changes. Commit or stash them first."
}

# -- Load remembered state ----------------------------------------------------
$State = $null
if (Test-Path $StateFile) {
    $State = Get-Content $StateFile -Raw | ConvertFrom-Json
}

$PrevBranch = if ($State) { $State.branch } else { $null }
$IsNewTarget = [bool]$NewVersion

$ResolvedBranch = if ($Branch) { $Branch } elseif ($PrevBranch) { $PrevBranch } else { "alpha" }

# -- Resolve the target version + per-channel iteration counters ------------
if ($IsNewTarget) {
    if ($NewVersion -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$') { Fail "-NewVersion must be a bare X.Y.Z version, got '$NewVersion'." }
    $TargetVersion = $NewVersion
    $AlphaIter = 0
    $BetaIter = 0
    # A fresh target version starts a fresh cycle at the bottom of the chain,
    # unless the caller explicitly asked for a different branch this run.
    if (-not $Branch) { $ResolvedBranch = "alpha" }
} else {
    # NOTE: a pre-migration state file (old schema: {version, branch, prefix})
    # has no target_version property at all — PowerShell silently returns
    # $null for a missing property on a PSCustomObject rather than erroring,
    # so this must check for it explicitly or $TargetVersion would end up
    # $null and corrupt every manifest below.
    $TargetVersion = if ($State -and $State.target_version) { $State.target_version } else {
        (Select-String -Path (Join-Path $RepoRoot "Cargo.toml") -Pattern '^version = "([0-9]+\.[0-9]+\.[0-9]+)"').Matches[0].Groups[1].Value
    }
    $AlphaIter = if ($State -and $State.alpha_iteration) { [int]$State.alpha_iteration } else { 0 }
    $BetaIter  = if ($State -and $State.beta_iteration)  { [int]$State.beta_iteration }  else { 0 }

    # Entering a channel that wasn't active last run (a promotion) starts
    # THAT channel's count fresh — it doesn't inherit alpha's iteration number.
    $BranchChanged = ($ResolvedBranch -ne $PrevBranch)
    if ($BranchChanged -and $ResolvedBranch -eq "beta") { $BetaIter = 0 }
    if ($BranchChanged -and $ResolvedBranch -eq "alpha") { $AlphaIter = 0 }
}

$Channel = switch ($ResolvedBranch) { "alpha" { "alpha" }; "beta" { "beta" }; "master" { "stable" } }

if ($Channel -eq "alpha") { $AlphaIter++ }
elseif ($Channel -eq "beta") { $BetaIter++ }
$Iteration = if ($Channel -eq "alpha") { $AlphaIter } else { $BetaIter }

$Tag = if ($Channel -eq "stable") { "v$TargetVersion" } else { "v$TargetVersion-$Channel.$Iteration" }

Write-Step "Releasing $Tag on '$ResolvedBranch'"

# -- Checkout the target branch, promoting it from alpha first --------------
$CurrentBranch = git rev-parse --abbrev-ref HEAD
if ($CurrentBranch -ne $ResolvedBranch) {
    Write-Step "Checking out $ResolvedBranch"
    git checkout $ResolvedBranch 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "Could not check out branch '$ResolvedBranch'." }
}
if ($ResolvedBranch -ne "alpha") {
    Write-Step "Fast-forwarding $ResolvedBranch to alpha (promotion)"
    git merge alpha --ff-only 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        $msg = "'$ResolvedBranch' has diverged from alpha and can't fast-forward. " +
               "Per CONTRIBUTING.md, nothing should ever be committed directly to " +
               "$ResolvedBranch - check what's there before forcing anything."
        Fail $msg
    }
}

# -- Bump manifests ONLY when the target version itself changes. A plain -----
# -- alpha/beta iteration touches nothing but the state file's counter.  -----
if ($IsNewTarget -or -not $State) {
    Write-Step "Bumping target version -> $TargetVersion"

    function Set-VersionLine($Path, $Pattern, $Replacement) {
        $full = Join-Path $RepoRoot $Path
        $text = Get-Content $full -Raw
        $updated = $text -replace $Pattern, $Replacement
        if ($updated -eq $text) { Fail "Version pattern not found in $Path - refusing to proceed with a stale file." }
        [System.IO.File]::WriteAllText($full, $updated)
    }

    $OldVersion = (Select-String -Path (Join-Path $RepoRoot "Cargo.toml") -Pattern '^version = "([0-9]+\.[0-9]+\.[0-9]+)"').Matches[0].Groups[1].Value
    Set-VersionLine "Cargo.toml" '(?m)^version ="[0-9]+\.[0-9]+\.[0-9]+"' "version = `"$TargetVersion`""
    Set-VersionLine "ostp-gui/src-tauri/Cargo.toml" '(?m)^version = "[0-9]+\.[0-9]+\.[0-9]+"' "version = `"$TargetVersion`""
    Set-VersionLine "ostp-gui/src-tauri/tauri.conf.json" '"version": "[0-9]+\.[0-9]+\.[0-9]+"' "`"version`": `"$TargetVersion`""
    Set-VersionLine "ostp-gui/package.json" '"version": "[0-9]+\.[0-9]+\.[0-9]+"' "`"version`": `"$TargetVersion`""

    # Refresh the version of our own packages in both lockfiles (ostp-gui/src-tauri
    # is outside the main workspace and has its own Cargo.lock). Nothing is built
    # here: builds happen on GHA only. Our packages are the [[package]] entries
    # without a `source =` line (path crates); registry and git crates always
    # have one. Only entries still at the old version change, so ostp-jni & co.
    # with their own 0.1.0 stay as they are.
    Write-Step "Refreshing our package versions in Cargo.lock files ($OldVersion -> $TargetVersion)"
    foreach ($lock in @("Cargo.lock", "ostp-gui/src-tauri/Cargo.lock")) {
        $full = Join-Path $RepoRoot $lock
        $text = [System.IO.File]::ReadAllText($full)
        $pattern = '(?m)^(name = "[^"]+"\r?\nversion = )"' + [regex]::Escape($OldVersion) + '"(?=\r?\n(?!source = ))'
        $updated = [regex]::Replace($text, $pattern, "`${1}`"$TargetVersion`"")
        if ($updated -eq $text) { Fail "No package at $OldVersion in $lock - refusing to proceed with a stale lockfile." }
        [System.IO.File]::WriteAllText($full, $updated)
    }
}

# Flutter's build number (Android versionCode) must strictly increase on
# every single build ever shipped — unlike the semantic version, it does NOT
# stay fixed across alpha/beta iterations, so this runs every time, not just
# on a target-version switch.
$pubspecPath = Join-Path $RepoRoot "ostp-flutter/pubspec.yaml"
$pubspecText = Get-Content $pubspecPath -Raw
if ($pubspecText -match 'version: [0-9]+\.[0-9]+\.[0-9]+\+([0-9]+)') {
    $nextBuild = [int]$Matches[1] + 1
    $pubspecText = $pubspecText -replace 'version: [0-9]+\.[0-9]+\.[0-9]+\+[0-9]+', "version: $TargetVersion+$nextBuild"
    [System.IO.File]::WriteAllText($pubspecPath, $pubspecText)
} else {
    Fail "Version pattern not found in ostp-flutter/pubspec.yaml."
}

# -- Changelog: what is under "Unreleased" now belongs to this release. -------
# -- A version heading goes right below the unreleased one, which stays (now  -
# -- empty) for the next round. The unreleased heading is matched as "the    -
# -- first ## [...] that does not start with a digit", so one pattern fits  -
# -- both the English and the Russian heading.                               -
# -- ReadAllText/WriteAllText: Get-Content in Windows PowerShell 5 would read  -
# -- UTF-8 without a BOM as ANSI and mangle the Russian file.                 -
$Released = $Tag.TrimStart('v')
$Today = Get-Date -Format 'yyyy-MM-dd'
$Utf8NoBom = New-Object System.Text.UTF8Encoding $false
foreach ($name in @('CHANGELOG.md', 'CHANGELOG.ru.md')) {
    $path = Join-Path $RepoRoot $name
    if (-not (Test-Path $path)) { continue }
    $text = [System.IO.File]::ReadAllText($path, $Utf8NoBom)
    $unreleased = [regex]::Match($text, '(?m)^## \[[^\]0-9][^\]]*\][^\r\n]*')
    if (-not $unreleased.Success) { Fail "No unreleased section in $name." }
    $insertAt = $unreleased.Index + $unreleased.Length
    $text = $text.Insert($insertAt, "`n`n## [$Released] - $Today")
    [System.IO.File]::WriteAllText($path, $text, $Utf8NoBom)
}

# -- Persist the new state ---------------------------------------------------
[PSCustomObject]@{
    target_version  = $TargetVersion
    branch          = $ResolvedBranch
    alpha_iteration = $AlphaIter
    beta_iteration  = $BetaIter
} | ConvertTo-Json | Set-Content $StateFile

# -- Commit -------------------------------------------------------------------
$commitMsg = "chore: release $Tag on $ResolvedBranch"
Write-Step "Committing: $commitMsg"
git add Cargo.toml Cargo.lock ostp-gui/src-tauri/Cargo.toml ostp-gui/src-tauri/Cargo.lock `
    ostp-gui/src-tauri/tauri.conf.json ostp-gui/package.json ostp-flutter/pubspec.yaml `
    CHANGELOG.md CHANGELOG.ru.md .release-state.json
git commit -m $commitMsg | Out-Null

# -- Push. release.yml triggers ONLY on "v*" tag pushes (no branch trigger), -
# -- so the tag push is what actually starts the build; the branch push is   -
# -- just so the promotion chain (alpha -> beta -> master) itself     -
# -- keeps moving forward for the next --ff-only.                            -
Write-Step "Tagging $Tag and pushing $ResolvedBranch + tag"
git tag $Tag
git push origin $ResolvedBranch
git push origin $Tag

Write-Host ""
Write-Host "Done. Watch the build: https://github.com/ospab/ostp/actions" -ForegroundColor Green
