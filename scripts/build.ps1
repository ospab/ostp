# Local builds of the main targets, the same way CI builds them. Nothing is
# committed, tagged or published: releases go through scripts/gha.ps1.
#
#   .\scripts\build.ps1 <target>[,<target>...] [--arm64 | --armv7]
#
# Targets:
#   win        CLI and server for Windows: ostp.exe + wintun.dll        (zip)
#   win-gui    desktop app for Windows: portable zip + NSIS installer
#   linux      CLI and server for Linux, static (musl), built in WSL     (tar.gz)
#   linux-gui  desktop app for Linux, built in WSL                       (tar.gz)
#   apk        Android app                                               (apk)
#   all        all of the above
#
# Architecture: x86_64 by default, and arm64-v8a (armv8) for the APK.
#   --arm64    aarch64 for every target
#   --armv7    32-bit ARM: linux (armv7 musl) and apk (armeabi-v7a) only
#
# Results go to dist\. Requirements per target are checked first, with the
# command that installs what is missing:
#   win, win-gui  Rust with the MSVC toolchain (Build Tools for Visual Studio,
#                 "Desktop development with C++"); win-gui also Node.js
#   linux*        WSL with Rust; musl-tools; linux-gui also Node.js and
#                 libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev
#   apk           Flutter, Android SDK + NDK, cargo-ndk; the release keystore
#                 in ostp-flutter/android/key.properties (else debug-signed)
# WSL distro: the default one, or $env:OSTP_WSL_DISTRO.

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$Dist = Join-Path $Root 'dist'
$WintunVersion = '0.14.1'

function Show-Usage {
    foreach ($line in Get-Content $PSCommandPath) {
        if ($line -notmatch '^#') { break }
        $line -replace '^# ?', ''
    }
}

function Fail([string]$msg) {
    Write-Host "error: $msg" -ForegroundColor Red
    exit 1
}

# Parsed by hand: PowerShell would read "--arm64" as an unknown parameter.
$targets = @()
$arch = $null
foreach ($a in $args) {
    switch -Regex ($a) {
        '^(-h|--help|-help|/\?)$' { Show-Usage; exit 0 }
        '^--arm64$' { $arch = 'arm64'; break }
        '^--armv7$' { $arch = 'armv7'; break }
        '^-'        { Fail "unknown option $a (see --help)" }
        default     { $targets += ($a -split ',') | Where-Object { $_ } }
    }
}
if (-not $targets) { Show-Usage; exit 1 }
if ($targets -contains 'all') { $targets = @('win', 'win-gui', 'linux', 'linux-gui', 'apk') }
$known = @('win', 'win-gui', 'linux', 'linux-gui', 'apk')
foreach ($t in $targets) { if ($known -notcontains $t) { Fail "unknown target '$t' (one of: $($known -join ', '), all)" } }

# Target triples and package names per architecture.
function Resolve-Target([string]$t) {
    $a = if ($arch) { $arch } elseif ($t -eq 'apk') { 'arm64' } else { 'x86_64' }
    $name = @{ x86_64 = 'amd64'; arm64 = 'arm64'; armv7 = 'armv7' }[$a]
    switch ($t) {
        'win' {
            if ($a -eq 'armv7') { Fail 'win: there is no 32-bit ARM Windows build' }
            $triple = @{ x86_64 = 'x86_64-pc-windows-msvc'; arm64 = 'aarch64-pc-windows-msvc' }[$a]
            return @{ Triple = $triple; Name = $name; Wintun = $name }
        }
        'win-gui' {
            if ($a -eq 'armv7') { Fail 'win-gui: there is no 32-bit ARM Windows build' }
            $triple = @{ x86_64 = 'x86_64-pc-windows-msvc'; arm64 = 'aarch64-pc-windows-msvc' }[$a]
            return @{ Triple = $triple; Name = $name; Wintun = $name }
        }
        'linux' {
            $triple = @{ x86_64 = 'x86_64-unknown-linux-musl'; arm64 = 'aarch64-unknown-linux-musl'; armv7 = 'armv7-unknown-linux-musleabihf' }[$a]
            return @{ Triple = $triple; Name = $name }
        }
        'linux-gui' {
            if ($a -eq 'armv7') { Fail 'linux-gui: there is no 32-bit ARM desktop build' }
            $triple = @{ x86_64 = 'x86_64-unknown-linux-gnu'; arm64 = 'aarch64-unknown-linux-gnu' }[$a]
            return @{ Triple = $triple; Name = $name }
        }
        'apk' {
            if ($a -eq 'x86_64') { Fail 'apk: built for arm64-v8a (default) or armeabi-v7a (--armv7)' }
            $abi = @{ arm64 = 'arm64-v8a'; armv7 = 'armeabi-v7a' }[$a]
            $platform = @{ arm64 = 'android-arm64'; armv7 = 'android-arm' }[$a]
            return @{ Abi = $abi; Platform = $platform; Name = $abi }
        }
    }
}

function Need-Command([string]$cmd, [string]$hint) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) { Fail "$cmd not found. $hint" }
}

function Invoke-Checked([string]$what) {
    if ($LASTEXITCODE -ne 0) { Fail "$what failed (exit code $LASTEXITCODE)" }
}

# A linker named "link" earlier in PATH (Git's coreutils) shadows MSVC's.
function Assert-Msvc {
    $link = Get-Command link.exe -ErrorAction SilentlyContinue
    if (-not $link -or $link.Source -notmatch 'Microsoft Visual Studio|MSVC') {
        $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
        $found = (Test-Path $vswhere) -and (& $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath)
        if (-not $found) {
            Fail ("the MSVC linker is not installed. Install Build Tools for Visual Studio with " +
                  "'Desktop development with C++': winget install Microsoft.VisualStudio.2022.BuildTools " +
                  "--override `"--add Microsoft.VisualStudio.Workload.VCTools --includeRecommended --passive`"")
        }
    }
}

# wintun.dll for the Windows packages, fetched once into target\wintun\.
function Get-Wintun([string]$wintunArch) {
    $dll = Join-Path $Root "target\wintun\$wintunArch\wintun.dll"
    if (Test-Path $dll) { return $dll }
    Write-Host "Downloading wintun $WintunVersion"
    $tmp = Join-Path $Root 'target\wintun\dl'
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null
    $zip = Join-Path $tmp 'wintun.zip'
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri "https://www.wintun.net/builds/wintun-$WintunVersion.zip" -OutFile $zip
    Expand-Archive $zip -DestinationPath $tmp -Force
    $src = Get-ChildItem $tmp -Filter wintun.dll -Recurse | Where-Object { $_.FullName -match "bin[\\/]$wintunArch[\\/]" } | Select-Object -First 1
    if (-not $src) { Fail "wintun.dll for $wintunArch not found in the wintun $WintunVersion archive" }
    New-Item -ItemType Directory -Force -Path (Split-Path $dll) | Out-Null
    Copy-Item $src.FullName $dll -Force
    return $dll
}

# Runs a bash script in WSL from the repository root. The cargo target dir
# stays inside WSL: building on /mnt/... is several times slower.
$WslDistroArgs = if ($env:OSTP_WSL_DISTRO) { @('-d', $env:OSTP_WSL_DISTRO) } else { @() }
function Invoke-Wsl([string]$script) {
    $rootWsl = (& wsl @WslDistroArgs wslpath -u ($Root -replace '\\', '/')).Trim()
    $full = "set -eu; export PATH=`"`$HOME/.cargo/bin:`$PATH`"; export CARGO_TARGET_DIR=`"`$HOME/.cache/ostp-target`"; cd '$rootWsl'; $script"
    & wsl @WslDistroArgs -e bash -c $full
}

function Assert-Wsl([string]$extra) {
    Need-Command wsl 'Install WSL: wsl --install -d Ubuntu'
    $check = 'command -v cargo >/dev/null || [ -x "$HOME/.cargo/bin/cargo" ] || { echo "missing: rust (curl --proto =https -sSf https://sh.rustup.rs | sh)"; exit 3; }; ' + $extra
    Invoke-Wsl $check
    if ($LASTEXITCODE -ne 0) { Fail 'WSL is missing what the build needs (see the line above)' }
}

New-Item -ItemType Directory -Force -Path $Dist | Out-Null
$built = @()

foreach ($t in $targets) {
    $r = Resolve-Target $t
    Write-Host ""
    Write-Host "=== $t ($($r.Name))" -ForegroundColor Cyan
    Push-Location $Root
    try {
        switch ($t) {
            'win' {
                Need-Command cargo 'Install Rust: https://rustup.rs'
                Assert-Msvc
                & rustup target add $r.Triple | Out-Null
                & cargo build --release --target $r.Triple --bin ostp; Invoke-Checked 'cargo build'
                $stage = Join-Path $Dist "stage-win-$($r.Name)"
                Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
                New-Item -ItemType Directory -Force -Path $stage | Out-Null
                Copy-Item (Join-Path $Root "target\$($r.Triple)\release\ostp.exe") $stage
                Copy-Item (Get-Wintun $r.Wintun) $stage
                $out = Join-Path $Dist "ostp-windows-$($r.Name).zip"
                Compress-Archive -Path "$stage\*" -DestinationPath $out -Force
                Remove-Item $stage -Recurse -Force
                $built += $out
            }
            'win-gui' {
                Need-Command cargo 'Install Rust: https://rustup.rs'
                Need-Command npm 'Install Node.js 20: winget install OpenJS.NodeJS.LTS'
                Assert-Msvc
                & rustup target add $r.Triple | Out-Null
                # The helper and wintun where stage-sidecar.cjs looks for them.
                & cargo build -p ostp-tun-helper --release --target $r.Triple; Invoke-Checked 'cargo build ostp-tun-helper'
                Copy-Item (Get-Wintun $r.Wintun) (Join-Path $Root "target\$($r.Triple)\release\wintun.dll") -Force
                Push-Location (Join-Path $Root 'ostp-gui')
                try {
                    & npm install; Invoke-Checked 'npm install'
                    & node stage-sidecar.cjs --release --target $r.Triple; Invoke-Checked 'stage-sidecar'
                    & npx tauri build --bundles nsis --target $r.Triple --config src-tauri/tauri.installer.conf.json; Invoke-Checked 'tauri build'
                } finally { Pop-Location }
                $rel = Join-Path $Root "ostp-gui\src-tauri\target\$($r.Triple)\release"
                $stage = Join-Path $Dist "stage-win-gui-$($r.Name)"
                Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
                New-Item -ItemType Directory -Force -Path $stage | Out-Null
                Copy-Item (Join-Path $rel 'ostp-gui.exe') $stage
                Copy-Item (Join-Path $Root "target\$($r.Triple)\release\ostp-tun-helper.exe") $stage
                Copy-Item (Get-Wintun $r.Wintun) $stage
                $zip = Join-Path $Dist "ostp-windows-gui-$($r.Name).zip"
                Compress-Archive -Path "$stage\*" -DestinationPath $zip -Force
                Remove-Item $stage -Recurse -Force
                $nsis = Get-ChildItem (Join-Path $rel 'bundle\nsis') -Filter *-setup.exe | Select-Object -First 1
                if (-not $nsis) { Fail 'the NSIS installer was not produced' }
                $setup = Join-Path $Dist "ostp-windows-gui-$($r.Name)-setup.exe"
                Copy-Item $nsis.FullName $setup -Force
                $built += $zip, $setup
            }
            'linux' {
                $musl = if ($r.Triple -like 'x86_64*') { 'command -v musl-gcc >/dev/null || { echo "missing: sudo apt-get install -y musl-tools"; exit 3; }' } else { 'true' }
                Assert-Wsl $musl
                $name = "ostp-linux-$($r.Name)"
                $distWsl = (& wsl @WslDistroArgs wslpath -u ($Dist -replace '\\', '/')).Trim()
                Invoke-Wsl ("rustup target add $($r.Triple) >/dev/null; " +
                    "cargo build --release --target $($r.Triple) --bin ostp; " +
                    "tar -czf '$distWsl/$name.tar.gz' -C `"`$CARGO_TARGET_DIR/$($r.Triple)/release`" ostp")
                Invoke-Checked 'linux build'
                $built += Join-Path $Dist "$name.tar.gz"
            }
            'linux-gui' {
                Assert-Wsl ('command -v npm >/dev/null || { echo "missing: node.js (sudo apt-get install -y nodejs npm)"; exit 3; }; ' +
                    'pkg-config --exists webkit2gtk-4.1 || { echo "missing: sudo apt-get install -y libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev patchelf"; exit 3; }')
                $name = "ostp-linux-gui-$($r.Name)"
                $distWsl = (& wsl @WslDistroArgs wslpath -u ($Dist -replace '\\', '/')).Trim()
                # The app is not a workspace member: its own target dir, also inside WSL.
                Invoke-Wsl ("rustup target add $($r.Triple) >/dev/null; " +
                    "cargo build -p ostp-tun-helper --release --target $($r.Triple); " +
                    "cd ostp-gui; npm install; " +
                    "CARGO_TARGET_DIR=`"`$HOME/.cache/ostp-gui-target`" npx tauri build --no-bundle --target $($r.Triple); " +
                    "stage=`$(mktemp -d)/$name; mkdir -p `"`$stage`"; " +
                    "cp `"`$HOME/.cache/ostp-gui-target/$($r.Triple)/release/ostp-gui`" `"`$stage/`"; " +
                    "cp `"`$CARGO_TARGET_DIR/$($r.Triple)/release/ostp-tun-helper`" `"`$stage/`"; " +
                    "tar -czf '$distWsl/$name.tar.gz' -C `"`$(dirname `"`$stage`")`" $name")
                Invoke-Checked 'linux-gui build'
                $built += Join-Path $Dist "$name.tar.gz"
            }
            'apk' {
                Need-Command flutter 'Install Flutter: https://docs.flutter.dev/get-started/install'
                Need-Command cargo 'Install Rust: https://rustup.rs'
                if (-not (Get-Command cargo-ndk -ErrorAction SilentlyContinue)) { Fail 'cargo-ndk not found. Install it: cargo install cargo-ndk' }
                if (-not ($env:ANDROID_NDK_HOME -or $env:ANDROID_NDK_ROOT)) {
                    Write-Host 'warning: ANDROID_NDK_HOME is not set; cargo-ndk will look for the NDK under the Android SDK' -ForegroundColor Yellow
                }
                # cargo-ndk links with the NDK, but build scripts run on this machine.
                Assert-Msvc
                $rustTarget = @{ 'arm64-v8a' = 'aarch64-linux-android'; 'armeabi-v7a' = 'armv7-linux-androideabi' }[$r.Abi]
                & rustup target add $rustTarget | Out-Null
                $jni = Join-Path $Root 'ostp-flutter\android\app\src\main\jniLibs'
                New-Item -ItemType Directory -Force -Path (Join-Path $jni $r.Abi) | Out-Null
                Push-Location (Join-Path $Root 'ostp-jni')
                try {
                    & cargo ndk -t $r.Abi -o $jni build --release; Invoke-Checked 'cargo ndk'
                } finally { Pop-Location }
                $signed = (Test-Path (Join-Path $Root 'ostp-flutter\android\key.properties')) -or $env:OSTP_KEYSTORE_PATH
                if (-not $signed) {
                    Write-Host ('warning: no release keystore (ostp-flutter/android/key.properties). The APK is signed ' +
                        'with the debug key and will not install over a release build.') -ForegroundColor Yellow
                }
                Push-Location (Join-Path $Root 'ostp-flutter')
                try {
                    & flutter build apk --release --target-platform $r.Platform; Invoke-Checked 'flutter build apk'
                } finally { Pop-Location }
                $out = Join-Path $Dist "ostp-android-$($r.Abi).apk"
                Copy-Item (Join-Path $Root 'ostp-flutter\build\app\outputs\flutter-apk\app-release.apk') $out -Force
                $built += $out
            }
        }
    } finally {
        Pop-Location
    }
}

Write-Host ""
Write-Host "Built:" -ForegroundColor Green
foreach ($f in $built) {
    $size = '{0:N1} MB' -f ((Get-Item $f).Length / 1MB)
    Write-Host "  $f ($size)"
}
