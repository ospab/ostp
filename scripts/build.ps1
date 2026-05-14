# OSTP Hybrid Build Script (Windows Native + WSL Linux)

$ProjectRoot = Split-Path -Parent $PSScriptRoot
Push-Location $ProjectRoot

Write-Output "Starting OSTP Build Pipeline in $ProjectRoot"

# Stop any currently running instances to release file locks on compiled binaries
Stop-Process -Name ostp -ErrorAction SilentlyContinue | Out-Null

$DistDir = Join-Path $ProjectRoot "dist"
$WinDist = Join-Path $DistDir "windows"
$LinuxDist = Join-Path $DistDir "linux"

New-Item -ItemType Directory -Force -Path $WinDist | Out-Null
New-Item -ItemType Directory -Force -Path $LinuxDist | Out-Null

# Clear old binaries to prevent false positive checks if copy fails
Remove-Item -Path (Join-Path $WinDist "ostp.exe") -ErrorAction SilentlyContinue | Out-Null
Remove-Item -Path (Join-Path $LinuxDist "ostp") -ErrorAction SilentlyContinue | Out-Null

Write-Output "Building Windows Binary natively"
$TempTarget = Join-Path $env:TEMP "ostp_target_build"
$env:CARGO_TARGET_DIR = $TempTarget

& cargo build --release --bin ostp

if ($LASTEXITCODE -ne 0) {
    Write-Output "❌ Windows build failed"
    Pop-Location
    exit 1
}

$WinExe = Join-Path $TempTarget "release\ostp.exe"
if (Test-Path $WinExe) {
    Copy-Item -Path $WinExe -Destination $WinDist -Force
    Write-Output "✔ Windows binary successfully copied to: dist/windows/ostp.exe"
} else {
    Write-Output "❌ Windows binary not found after build"
    Pop-Location
    exit 1
}

# Reset target directory env
Remove-Item Env:\CARGO_TARGET_DIR -ErrorAction SilentlyContinue | Out-Null

Write-Output "Building Linux binary via WSL"
if (Get-Command wsl -ErrorAction SilentlyContinue) {
    & wsl rustup target add x86_64-unknown-linux-musl
    & wsl env CC_x86_64_unknown_linux_musl=gcc CARGO_TARGET_DIR=/tmp/ostp_linux_build cargo build --release --target x86_64-unknown-linux-musl --bin ostp
    
    if ($LASTEXITCODE -ne 0) {
        Write-Output "❌ Linux build failed"
        Pop-Location
        exit 1
    }
    
    # Fix Windows backslashes for WSL path translator passing
    $LinuxDistUnix = $LinuxDist.Replace("\", "/")
    # Determine WSL translation of the destination folder
    $WslLinuxDist = & wsl wslpath -u $LinuxDistUnix
    # Copy from WSL temp directory into the actual host mapped linux dist
    & wsl cp /tmp/ostp_linux_build/x86_64-unknown-linux-musl/release/ostp $WslLinuxDist/ostp
    
    $LinuxBin = Join-Path $LinuxDist "ostp"
    if (Test-Path $LinuxBin) {
        Write-Output "✔ Linux binary successfully copied to dist/linux/ostp"
    } else {
        Write-Output "❌ Linux binary copy failed"
        Pop-Location
        exit 1
    }
} else {
    Write-Output "⚠ WSL not available, skipping Linux server build"
}

Write-Output "Build Completed Successfully"

# Automated metadata version increment
$CargoToml = Join-Path $ProjectRoot "Cargo.toml"
if (Test-Path $CargoToml) {
    $Content = [System.IO.File]::ReadAllText($CargoToml)
    if ($Content -match 'version\s*=\s*"(\d+)\.(\d+)\.(\d+)"') {
        $Major = [int]$Matches[1]
        $Minor = [int]$Matches[2]
        $Patch = [int]$Matches[3]
        $NewPatch = $Patch + 1
        $NewVersionStr = 'version = "{0}.{1}.{2}"' -f $Major, $Minor, $NewPatch
        $NewContent = $Content -replace 'version\s*=\s*"\d+\.\d+\.\d+"', $NewVersionStr
        [System.IO.File]::WriteAllText($CargoToml, $NewContent)
        Write-Output "✔ Successfully bumped workspace version to $Major.$Minor.$NewPatch"
    }
}

Pop-Location
