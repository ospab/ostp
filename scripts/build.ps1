# OSTP High-Performance Cross-Platform Build & Release Pipeline
param(
    [switch]$Flatten # Consolidate raw uncompressed binaries with arch suffixes under dist/release/
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
# PHASE 1: WINDOWS COMPILATION MATRIX (Native Host)
# ---------------------------------------------------------------------
$WindowsTargets = @(
    @{ Target = "x86_64-pc-windows-msvc"; Arch = "x64"; BinaryName = "ostp.exe" },
    @{ Target = "i686-pc-windows-msvc"; Arch = "x86"; BinaryName = "ostp.exe" }
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
                $FlatName = "ostp-$arch.exe"
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
        @{ Target = "x86_64-unknown-linux-musl"; Arch = "x64"; BinaryName = "ostp" },
        @{ Target = "aarch64-unknown-linux-musl"; Arch = "arm64"; BinaryName = "ostp" },
        @{ Target = "armv7-unknown-linux-musleabihf"; Arch = "armv7"; BinaryName = "ostp" }
    )

    foreach ($item in $LinuxTargets) {
        $target = $item.Target
        $arch = $item.Arch
        $bin = $item.BinaryName
        
        Write-Output "--> Compiling target: Linux $arch [$target] via rust-lld..."
        
        & wsl rustup target add $target 2>&1 | Out-Null
        
        # Invoke Cargo cross-compiling via toolless rust-lld LLVM backend for Musl targets!
        & wsl env RUSTFLAGS="-C linker=rust-lld" CARGO_TARGET_DIR=$WslBuildDir cargo build --release --target $target --bin ostp
        
        if ($LASTEXITCODE -eq 0) {
            $compiledBin = Join-Path $LinuxBuildDir "$target\release\$bin"
            if (Test-Path $compiledBin) {
                $archiveName = "ostp-v$Version-linux-$arch.tar.gz"
                $targetStaging = Join-Path $StagingDir "linux-$arch"
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
                    $FlatName = "ostp-$arch"
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

# ---------------------------------------------------------------------
# PHASE 3: AUTOMATED GITHUB PUBLISHING (Via User configured GH CLI)
# ---------------------------------------------------------------------
Write-Output "`n========================================================="
Write-Output " PHASE 3: Automated GitHub Release Deployment"
Write-Output "========================================================="

if (Get-Command gh -ErrorAction SilentlyContinue) {
    Write-Output "Assessing GitHub authentication credentials..."
    & gh auth status *>&1 | Out-Null
    
    if ($LASTEXITCODE -eq 0) {
        Write-Output "✔ GitHub authenticated. Pushing workspace changes and tagging..."
        
        # Synchronize current Git tree to ensure tag maps to active HEAD
        & git add Cargo.toml; & git commit -m "Release preparation: bump version to v$Version [skip ci]"; & git push
        
        Write-Output "Constructing Release on remote repository..."
        
        # Assemble formatted array of quotes paths for release payloads
        $FilePaths = $ReleaseArchives | ForEach-Object { "`"$_`"" }
        
        # Trigger gh release mechanism with automated changelog generation
        $ReleaseCmd = "gh release create v$Version --title `"Release v$Version`" --notes `"Official cross-platform distribution of Ospab Stealth Transport Protocol (OSTP).`" --generate-notes " + ($FilePaths -join " ")
        
        Invoke-Expression $ReleaseCmd
        
        if ($LASTEXITCODE -eq 0) {
            Write-Output "`n🚀 HOORAY! Universal Release v$Version is officially LIVE on GitHub!"
        } else {
            Write-Output "`n❌ Deployment failed during gh CLI upload."
        }
    } else {
        Write-Output "⚠ gh CLI not logged in. Use 'gh auth login' inside your terminal to authorize auto-deployment."
    }
} else {
    Write-Output "ℹ gh CLI is not present on the PATH. Skipping automatic GitHub publication."
}

Pop-Location
