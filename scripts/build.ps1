# OSTP High-Performance Cross-Platform Build & Release Pipeline
param(
    [switch]$Flatten,      # Consolidate raw uncompressed binaries with arch suffixes under dist/release/
    [switch]$TriggerOnly   # Bypasses all local builds to instantly execute global cloud CI/CD tag injection
)

$ProjectRoot = Split-Path -Parent $PSScriptRoot
Push-Location $ProjectRoot

Write-Output "Starting Universal OSTP Build & Release Pipeline in $ProjectRoot"

# Unblock binaries by terminating any existing active instances
Stop-Process -Name ostp -ErrorAction SilentlyContinue | Out-Null

# 1. Read and automatically bump version inside Cargo.toml PRIOR to compilation
$CargoToml = Join-Path $ProjectRoot "Cargo.toml"
$Version = "0.1.0"
if (Test-Path $CargoToml) {
    $Content = [System.IO.File]::ReadAllText($CargoToml)
    if ($Content -match 'version\s*=\s*"(\d+)\.(\d+)\.(\d+)"') {
        $Major = [int]$Matches[1]
        $Minor = [int]$Matches[2]
        $Patch = [int]$Matches[3]
        $NewPatch = $Patch + 1
        $Version = "{0}.{1}.{2}" -f $Major, $Minor, $NewPatch
        $NewVersionStr = 'version = "' + $Version + '"'
        $NewContent = $Content -replace 'version\s*=\s*"\d+\.\d+\.\d+"', $NewVersionStr
        [System.IO.File]::WriteAllText($CargoToml, $NewContent)
        Write-Output "✔ Bounded workspace package to target release version: v$Version"
    }
}

$DistDir = Join-Path $ProjectRoot "dist"
$StagingDir = Join-Path $DistDir "staging"

# Wipe legacy artifacts to prepare a clean clean slate
if (Test-Path $DistDir) { Remove-Item -Path $DistDir -Recurse -Force -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Force -Path $DistDir | Out-Null

# Collection for dynamically mapping successful build archives
$ReleaseArchives = @()

# ---------------------------------------------------------------------
# CONDITIONAL BUILD SUITE execution
# ---------------------------------------------------------------------
if (-not $TriggerOnly) {

# ---------------------------------------------------------------------
# PHASE 1: WINDOWS COMPILATION MATRIX (Native Host)
# ---------------------------------------------------------------------
$WindowsTargets = @(
    @{ Target = "x86_64-pc-windows-msvc"; Arch = "x64"; BinaryName = "ostp.exe" }
)

Write-Output "========================================================="
Write-Output " PHASE 1: Compiling Windows Architectures"
Write-Output "========================================================="
$TempWinTargetDir = Join-Path $env:TEMP "ostp_target_win"

foreach ($item in $WindowsTargets) {
    $target = $item.Target
    $arch = $item.Arch
    $bin = $item.BinaryName
    
    Write-Output "--> Compiling target: Windows $arch [$target]..."
    
    # Attempt setup of the rust toolchain for this architecture
    & rustup target add $target 2>&1 | Out-Null
    
    $env:CARGO_TARGET_DIR = $TempWinTargetDir
    & cargo build --release --target $target --bin ostp
    
    if ($LASTEXITCODE -eq 0) {
        $compiledBin = Join-Path $TempWinTargetDir "$target\release\$bin"
        if (Test-Path $compiledBin) {
            $archiveName = "ostp-v$Version-windows-$arch.zip"
            $targetStaging = Join-Path $StagingDir "windows-$arch"
            New-Item -ItemType Directory -Force -Path $targetStaging | Out-Null
            
            # Stage and package binary natively
            Copy-Item -Path $compiledBin -Destination $targetStaging -Force
            
            $archivePath = Join-Path $DistDir $archiveName
            Compress-Archive -Path "$targetStaging\*" -DestinationPath $archivePath -Force
            
            $ReleaseArchives += $archivePath
            Write-Output "✔ SUCCESSFULLY PACKAGED: $archiveName"
            
            if ($Flatten) {
                $RawReleaseDir = Join-Path $DistDir "release"
                New-Item -ItemType Directory -Force -Path $RawReleaseDir | Out-Null
                $FlatName = "ostp-windows-$arch.exe"
                Copy-Item -Path $compiledBin -Destination (Join-Path $RawReleaseDir $FlatName) -Force
                Write-Output "   -> Flat copied: dist/release/$FlatName"
            }
        }
    } else {
        Write-Output "⚠ FAILED compiling Windows $arch ($target). Missing local platform C++ toolchain components."
    }
}
# Restore environment variables
Remove-Item Env:\CARGO_TARGET_DIR -ErrorAction SilentlyContinue | Out-Null

# ---------------------------------------------------------------------
# PHASE 2: LINUX CROSS-COMPILATION MATRIX (via WSL + rust-lld)
# ---------------------------------------------------------------------
Write-Output "`n========================================================="
Write-Output " PHASE 2: Compiling Linux Architectures via WSL"
Write-Output "========================================================="

if (Get-Command wsl -ErrorAction SilentlyContinue) {
    # Anchor output cache on Windows disk to survive WSL instance cycling
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
        
        Write-Output "--> Compiling target: $osPrefix $arch [$target] via rust-lld..."
        
        & wsl rustup target add $target 2>&1 | Out-Null
        
        # Invoke Cargo cross-compiling via toolless rust-lld LLVM backend for Musl targets!
        & wsl env RUSTFLAGS="-C linker=rust-lld" CARGO_TARGET_DIR=$WslBuildDir cargo build --release --target $target --bin ostp
        
        if ($LASTEXITCODE -eq 0) {
            $compiledBin = Join-Path $LinuxBuildDir "$target\release\$bin"
            if (Test-Path $compiledBin) {
                $archiveName = "ostp-v$Version-$osPrefix-$arch.tar.gz"
                $targetStaging = Join-Path $StagingDir "$osPrefix-$arch"
                New-Item -ItemType Directory -Force -Path $targetStaging | Out-Null
                
                Copy-Item -Path $compiledBin -Destination $targetStaging -Force
                
                # Translate staging paths to Linux formats for WSL tar archiving
                $wslStagingDir = & wsl wslpath -u ($targetStaging.Replace("\", "/"))
                $wslArchiveFile = & wsl wslpath -u ((Join-Path $DistDir $archiveName).Replace("\", "/"))
                
                # Generate clean compressed tarball natively via WSL tar engine
                & wsl tar -czf $wslArchiveFile -C $wslStagingDir $bin
                
                $ReleaseArchives += Join-Path $DistDir $archiveName
                Write-Output "✔ SUCCESSFULLY PACKAGED: $archiveName"
                
                if ($Flatten) {
                    $RawReleaseDir = Join-Path $DistDir "release"
                    New-Item -ItemType Directory -Force -Path $RawReleaseDir | Out-Null
                    $FlatName = "ostp-$osPrefix-$arch"
                    Copy-Item -Path $compiledBin -Destination (Join-Path $RawReleaseDir $FlatName) -Force
                    Write-Output "   -> Flat copied: dist/release/$FlatName"
                }
            }
        } else {
            Write-Output "⚠ FAILED compiling Linux $arch ($target)."
        }
    }
} else {
    Write-Output "⚠ WSL utility not discovered on host. Skipping Linux binary compilations."
}

# Dissolve staging buffer directory
if (Test-Path $StagingDir) { Remove-Item -Path $StagingDir -Recurse -Force -ErrorAction SilentlyContinue }

Write-Output "`n========================================================="
Write-Output " RELEASE ARTIFACTS SUMMARY"
Write-Output "========================================================="
if ($ReleaseArchives.Count -gt 0) {
    $ReleaseArchives | ForEach-Object { Write-Output " [+] $_" }
} else {
    Write-Output "❌ CRITICAL: No architectures compiled successfully."
    Pop-Location
    exit 1
}

} else {
    Write-Output "`n--> [TRIGGER ONLY MODE] Bypassing all local compilations as requested."
}

# ---------------------------------------------------------------------
# PHASE 3: TRIGGER GLOBAL CI/CD RELEASE PIPELINE (Via Git Tag)
# ---------------------------------------------------------------------
Write-Output "`n========================================================="
Write-Output " PHASE 3: Launching Unified Global Cloud Release"
Write-Output "========================================================="

Write-Output "Synchronizing workspace version metadata to origin master..."
# Commit current Cargo.toml bump to establish version lineage
& git add Cargo.toml
& git commit -m "CI/CD: prepare version v$Version [skip ci]" --allow-empty | Out-Null
& git push origin master | Out-Null

Write-Output "Generating release tracking tag: v$Version"
# Purge local tracking tag if pre-existing to guarantee clean sync
& git tag -d "v$Version" 2>&1 | Out-Null
& git tag "v$Version"

Write-Output "Deploying trigger tag to GitHub..."
# Pushing the tag forces GitHub Actions to instantly spin up the cloud builders
& git push origin "v$Version" --force

if ($LASTEXITCODE -eq 0) {
    Write-Output "`n🚀 EXCELLENT! Release trigger successfully synchronized with Cloud runners!"
    Write-Output "✨ GitHub Actions is now compiling all 13 architectures in parallel."
    Write-Output "🔗 Live monitoring link: https://github.com/ospab/ostp/actions"
} else {
    Write-Output "`n❌ Failed to deliver release tag to remote origin."
}

Pop-Location
