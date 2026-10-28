param(
    [Alias("b")][string]$Branch = "stable",
    [Alias("v")][string]$Version = ""
)
$ErrorActionPreference = "Stop"
$repo = "ospab/ostp"

# 1. Install path resolution
$InstallDir = "C:\opt\ostp"

if (Test-Path "config.json") {
    $InstallDir = (Get-Item .).FullName
} elseif (Test-Path "ostp.exe") {
    $InstallDir = (Get-Item .).FullName
} elseif ($cmd = Get-Command "ostp" -ErrorAction SilentlyContinue) {
    $InstallDir = Split-Path $cmd.Path
} else {
    $found = Get-ChildItem -Filter "ostp.exe" -Recurse -File -ErrorAction SilentlyContinue |
             Where-Object { $_.FullName -notlike "*\target\*" -and $_.FullName -notlike "*\.git\*" } |
             Select-Object -First 1
    if ($found) {
        $InstallDir = Split-Path $found.FullName
    } else {
        $parentFound = Get-ChildItem -Path .. -Filter "ostp.exe" -File -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($parentFound) {
            $InstallDir = Split-Path $parentFound.FullName
        }
    }
}

Write-Host "========================================================"
Write-Host " OSTP Installer v3"
Write-Host "========================================================"
Write-Host "Install directory: $InstallDir"

# 2. Access check
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not (Test-Path $InstallDir)) {
    try {
        New-Item -ItemType Directory -Path $InstallDir -ErrorAction Stop | Out-Null
        if ($isAdmin) {
            # A folder made under C:\ inherits "Authenticated Users: Modify". It is
            # then put on the machine PATH and holds binaries that run elevated,
            # so any local user could replace them.
            & icacls $InstallDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" | Out-Null
        }
    } catch {
        Write-Error "Cannot create '$InstallDir'. Run as Administrator."
        exit 1
    }
} else {
    try {
        $testFile = Join-Path $InstallDir "ostp_write_test_$($PID).tmp"
        "test" | Set-Content $testFile -ErrorAction Stop
        Remove-Item $testFile -Force
    } catch {
        Write-Error "Directory '$InstallDir' is read-only. Run as Administrator."
        exit 1
    }
}

# 3. Architecture detection
$arch = "amd64"
if ([System.Environment]::Is64BitOperatingSystem -and ($Env:PROCESSOR_ARCHITECTURE -eq "ARM64" -or $Env:PROCESSOR_ARCHITEW6432 -eq "ARM64")) {
    $arch = "arm64"
}

# 4. Fetch latest release
Write-Host "Fetching latest release..."
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    if ($Version) {
        # Pre-release channels use bare tag names; only stable tags get the "v".
        $tag = $Version
        if ($Branch -eq "stable" -and $tag -notlike "v*") { $tag = "v$tag" }
    } elseif ($Branch -eq "alpha" -or $Branch -eq "beta") {
        # No floating alpha/beta release exists and /releases/latest skips
        # pre-releases: take the highest version among the channel's tags
        # (the API does not order by version).
        $list = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases?per_page=100" -UseBasicParsing
        $tag = $list | Where-Object { $_.tag_name -like "*-$Branch.*" } | Sort-Object {
            $t = $_.tag_name -replace '^v', ''
            $core, $pre = $t -split '-', 2
            [version]"$core.$($pre -replace '.*\.', '')"
        } -Descending | Select-Object -First 1 -ExpandProperty tag_name
        if (-not $tag) { throw "no $Branch release found" }
    } else {
        $api = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest" -UseBasicParsing
        $tag = $api.tag_name
    }
} catch {
    Write-Host "[notice] Could not determine latest release automatically."
    $tag = Read-Host "Enter release tag (e.g. v0.1.60)"
    if (-not $tag) { exit 1 }
}

$archive = "ostp-windows-$arch.zip"
$url = "https://github.com/$repo/releases/download/$tag/$archive"
$zipPath = Join-Path $env:TEMP "ostp_temp_$($PID).zip"
$extractPath = Join-Path $env:TEMP "ostp_extract_$($PID)"

# The SHA-256 GitHub computed for this exact asset, from the API response for this tag.
$expected = $null
try {
    $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/tags/$tag" -UseBasicParsing
    $expected = ($rel.assets | Where-Object { $_.name -eq $archive } | Select-Object -First 1).digest
} catch { }
if (-not $expected -or $expected -notmatch '^sha256:([0-9a-fA-F]{64})$') {
    Write-Error "GitHub published no SHA-256 for $archive in release $tag. Nothing was installed."
    exit 1
}
$expected = $Matches[1].ToLower()

Write-Host "Downloading: $archive ($tag)"
Invoke-WebRequest -Uri $url -OutFile $zipPath -UseBasicParsing

if (-not (Test-Path $zipPath)) {
    Write-Error "Download failed."
    exit 1
}

$actual = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash.ToLower()
if ($actual -ne $expected) {
    Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
    Write-Error "SHA-256 mismatch: expected $expected, got $actual. Nothing was installed."
    exit 1
}
Write-Host "SHA-256 verified: $actual"

if (Test-Path $extractPath) { Remove-Item $extractPath -Recurse -Force }
Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force

$extractedFiles = Get-ChildItem -Path $extractPath -File -Recurse
if ($extractedFiles.Count -gt 0) {
    Write-Host "Stopping active instances..."
    Stop-Process -Name "ostp", "ostp-gui", "ostp-tun-helper" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    foreach ($file in $extractedFiles) {
        $destPath = Join-Path $InstallDir $file.Name
        if (Test-Path $destPath) {
            $oldPath = $destPath + ".old_$PID"
            Rename-Item -Path $destPath -NewName $oldPath -ErrorAction SilentlyContinue
        }
        Copy-Item -Path $file.FullName -Destination $destPath -Force
        (Get-Item $destPath).LastWriteTime = [DateTime]::Now
    }

    Get-ChildItem -Path $InstallDir -Filter "*.old_*" | Remove-Item -Force -ErrorAction SilentlyContinue
    Write-Host "Files deployed to $InstallDir."
} else {
    Write-Error "Archive is empty."
    exit 1
}

Remove-Item $zipPath -Force
Remove-Item $extractPath -Recurse -Force

# 5. PATH registration
Write-Host "--------------------------------------------------------"
Write-Host "Registering in system PATH..."
$targetScope = if ($isAdmin) { [EnvironmentVariableTarget]::Machine } else { [EnvironmentVariableTarget]::User }
$sysPath = [Environment]::GetEnvironmentVariable("Path", $targetScope)
if ($sysPath -notlike "*$InstallDir*") {
    $newPath = "$sysPath;$InstallDir"
    [Environment]::SetEnvironmentVariable("Path", $newPath, $targetScope)
    Write-Host "PATH updated ($($targetScope.ToString()) scope)."
} else {
    Write-Host "$InstallDir already in PATH."
}

# 6. Update detection
$configPath = Join-Path $InstallDir "config.json"
if (Test-Path $configPath) {
    Write-Host "--------------------------------------------------------"
    Write-Host "Existing configuration found. Binary updated to $tag."
    Write-Host "--------------------------------------------------------"
    exit 0
}

# 7. First install: delegate to the built-in setup wizard
Write-Host ""
Write-Host "No configuration found. Launching setup wizard..."
Write-Host ""

Push-Location $InstallDir
& .\ostp.exe setup
Pop-Location
