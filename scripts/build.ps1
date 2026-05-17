# OSTP Build & Release Pipeline
# Usage:
#   .\scripts\build.ps1                Build locally + trigger CI/CD
#   .\scripts\build.ps1 -TriggerOnly   Skip local builds, trigger CI/CD only
#   .\scripts\build.ps1 -Check         Run cargo check only (no build, no release)

param(
    [switch]$Flatten,
    [switch]$TriggerOnly,
    [switch]$Check
)

$ProjectRoot = Split-Path -Parent $PSScriptRoot
Push-Location $ProjectRoot

# --- Sync ---
Write-Output "Synchronizing with origin master..."
& git pull origin master --rebase --autostash | Out-Null

# --- Version bump ---
$CargoToml = Join-Path $ProjectRoot "Cargo.toml"
$Version = "0.2.0"
if (Test-Path $CargoToml) {
    $Content = [System.IO.File]::ReadAllText($CargoToml)
    # Match version only in [workspace.package] section (first occurrence)
    if ($Content -match '\[workspace\.package\][\s\S]*?version\s*=\s*"(\d+)\.(\d+)\.(\d+)"') {
        $Major = [int]$Matches[1]
        $Minor = [int]$Matches[2]
        $Patch = [int]$Matches[3]
        $NewPatch = $Patch + 1
        $Version = "{0}.{1}.{2}" -f $Major, $Minor, $NewPatch
        # Replace only the workspace version line, not dependency versions
        $OldVersionStr = 'version = "{0}.{1}.{2}"' -f $Major, $Minor, $Patch
        $NewVersionStr = 'version = "' + $Version + '"'
        # Use .NET Replace to swap only the first occurrence
        $idx = $Content.IndexOf($OldVersionStr)
        if ($idx -ge 0) {
            $NewContent = $Content.Remove($idx, $OldVersionStr.Length).Insert($idx, $NewVersionStr)
            [System.IO.File]::WriteAllText($CargoToml, $NewContent)
        }
        Write-Output "[ok] Version: v$Version"
    }
}

# --- Pre-flight: cargo check ---
Write-Output ""
Write-Output "Running pre-flight cargo check..."
$checkOutput = & cargo check 2>&1 | Out-String
$checkErrors = $checkOutput | Select-String "^error\[" -CaseSensitive

if ($checkErrors) {
    Write-Output ""
    Write-Output "[error] Compilation check failed. Fix errors before releasing:"
    Write-Output $checkOutput
    # Revert version bump
    [System.IO.File]::WriteAllText($CargoToml, $Content)
    Pop-Location
    exit 1
}

# Show warnings if any
$checkWarnings = $checkOutput | Select-String "^warning:" -CaseSensitive
if ($checkWarnings) {
    Write-Output "[warn] Compiler warnings detected (non-blocking):"
    $checkWarnings | ForEach-Object { Write-Output "  $_" }
} else {
    Write-Output "[ok] No errors or warnings."
}

if ($Check) {
    Write-Output ""
    Write-Output "Check-only mode. Exiting without build or release."
    # Revert version bump
    [System.IO.File]::WriteAllText($CargoToml, $Content)
    Pop-Location
    exit 0
}

Write-Output ""
Write-Output "Starting build pipeline for v$Version"

# Kill existing instances
Stop-Process -Name ostp -ErrorAction SilentlyContinue | Out-Null

$DistDir = Join-Path $ProjectRoot "dist"
$StagingDir = Join-Path $DistDir "staging"

if (Test-Path $DistDir) { Remove-Item -Path $DistDir -Recurse -Force -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Force -Path $DistDir | Out-Null

$ReleaseArchives = @()

# --- Conditional local build ---
if (-not $TriggerOnly) {

    # Phase 1: Windows
    $WindowsTargets = @(
        @{ Target = "x86_64-pc-windows-msvc"; Arch = "x64"; BinaryName = "ostp.exe" }
    )

    Write-Output ""
    Write-Output "--- Phase 1: Windows compilation ---"
    $TempWinTargetDir = Join-Path $env:TEMP "ostp_target_win"

    foreach ($item in $WindowsTargets) {
        $target = $item.Target
        $arch = $item.Arch
        $bin = $item.BinaryName

        Write-Output "  Compiling: Windows $arch ($target)"
        & rustup target add $target 2>&1 | Out-Null

        $env:CARGO_TARGET_DIR = $TempWinTargetDir
        & cargo build --release --target $target --bin ostp

        if ($LASTEXITCODE -eq 0) {
            $compiledBin = Join-Path $TempWinTargetDir "$target\release\$bin"
            if (Test-Path $compiledBin) {
                $archiveName = "ostp-v$Version-windows-$arch.zip"
                $targetStaging = Join-Path $StagingDir "windows-$arch"
                New-Item -ItemType Directory -Force -Path $targetStaging | Out-Null
                Copy-Item -Path $compiledBin -Destination $targetStaging -Force

                $archivePath = Join-Path $DistDir $archiveName
                Compress-Archive -Path "$targetStaging\*" -DestinationPath $archivePath -Force
                $ReleaseArchives += $archivePath
                Write-Output "  [ok] $archiveName"

                if ($Flatten) {
                    $RawReleaseDir = Join-Path $DistDir "release"
                    New-Item -ItemType Directory -Force -Path $RawReleaseDir | Out-Null
                    $FlatName = "ostp-windows-$arch.exe"
                    Copy-Item -Path $compiledBin -Destination (Join-Path $RawReleaseDir $FlatName) -Force
                    Write-Output "  [ok] Flat: dist/release/$FlatName"
                }
            }
        } else {
            Write-Output "  [warn] Failed: Windows $arch ($target)"
        }
    }
    Remove-Item Env:\CARGO_TARGET_DIR -ErrorAction SilentlyContinue | Out-Null

    # Phase 2: Linux via WSL
    Write-Output ""
    Write-Output "--- Phase 2: Linux compilation via WSL ---"

    if (Get-Command wsl -ErrorAction SilentlyContinue) {
        $LinuxBuildDir = Join-Path $ProjectRoot "target_linux"
        New-Item -ItemType Directory -Force -Path $LinuxBuildDir | Out-Null
        $LinuxBuildUnix = $LinuxBuildDir.Replace("\", "/")
        $WslBuildDir = & wsl wslpath -u $LinuxBuildUnix

        $LinuxTargets = @(
            @{ Target = "x86_64-unknown-linux-musl"; Arch = "x64"; BinaryName = "ostp" }
        )

        foreach ($item in $LinuxTargets) {
            $target = $item.Target
            $arch = $item.Arch
            $bin = $item.BinaryName
            $osPrefix = "linux"
            if ($target -match "freebsd") { $osPrefix = "freebsd" }

            Write-Output "  Compiling: $osPrefix $arch ($target)"
            & wsl rustup target add $target 2>&1 | Out-Null
            & wsl env RUSTFLAGS="-C linker=rust-lld" CARGO_TARGET_DIR=$WslBuildDir cargo build --release --target $target --bin ostp

            if ($LASTEXITCODE -eq 0) {
                $compiledBin = Join-Path $LinuxBuildDir "$target\release\$bin"
                if (Test-Path $compiledBin) {
                    $archiveName = "ostp-v$Version-$osPrefix-$arch.tar.gz"
                    $targetStaging = Join-Path $StagingDir "$osPrefix-$arch"
                    New-Item -ItemType Directory -Force -Path $targetStaging | Out-Null
                    Copy-Item -Path $compiledBin -Destination $targetStaging -Force

                    $wslStagingDir = & wsl wslpath -u ($targetStaging.Replace("\", "/"))
                    $wslArchiveFile = & wsl wslpath -u ((Join-Path $DistDir $archiveName).Replace("\", "/"))
                    & wsl tar -czf $wslArchiveFile -C $wslStagingDir $bin

                    $ReleaseArchives += Join-Path $DistDir $archiveName
                    Write-Output "  [ok] $archiveName"

                    if ($Flatten) {
                        $RawReleaseDir = Join-Path $DistDir "release"
                        New-Item -ItemType Directory -Force -Path $RawReleaseDir | Out-Null
                        $FlatName = "ostp-$osPrefix-$arch"
                        Copy-Item -Path $compiledBin -Destination (Join-Path $RawReleaseDir $FlatName) -Force
                        Write-Output "  [ok] Flat: dist/release/$FlatName"
                    }
                }
            } else {
                Write-Output "  [warn] Failed: $osPrefix $arch ($target)"
            }
        }
    } else {
        Write-Output "  [skip] WSL not available."
    }

    # Cleanup staging
    if (Test-Path $StagingDir) { Remove-Item -Path $StagingDir -Recurse -Force -ErrorAction SilentlyContinue }

    Write-Output ""
    Write-Output "--- Build summary ---"
    if ($ReleaseArchives.Count -gt 0) {
        $ReleaseArchives | ForEach-Object { Write-Output "  $_" }
    } else {
        Write-Output "[error] No architectures compiled successfully."
        Pop-Location
        exit 1
    }

} else {
    Write-Output ""
    Write-Output "[info] Trigger-only mode. Skipping local compilation."
}

# --- Phase 3: CI/CD release trigger ---
Write-Output ""
Write-Output "--- Phase 3: CI/CD release ---"

Write-Output "Pushing version metadata..."
& git add Cargo.toml Cargo.lock
& git commit -m "CI/CD: release version v$Version" --allow-empty | Out-Null
& git push origin master | Out-Null

Write-Output "Creating release tag: v$Version"
& git tag -d "v$Version" 2>&1 | Out-Null
& git tag "v$Version"

Write-Output "Pushing tag to GitHub..."
& git push origin "v$Version" --force

if ($LASTEXITCODE -eq 0) {
    Write-Output ""
    Write-Output "[ok] Release v$Version triggered on GitHub Actions."
    Write-Output "     Monitor: https://github.com/ospab/ostp/actions"
} else {
    Write-Output ""
    Write-Output "[error] Failed to push release tag."
}

Pop-Location
