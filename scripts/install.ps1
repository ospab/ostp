$ErrorActionPreference = "Stop"
$repo = "ospab/ostp"

# 1. Smart Installation Path Resolution
$InstallDir = "C:\opt\ostp" # Standard default fallback

if (Test-Path "config.json") {
    # If current directory already has a configuration, keep it here
    $InstallDir = (Get-Item .).FullName
} elseif (Test-Path "ostp.exe") {
    # If binary already exists in current working directory, use it
    $InstallDir = (Get-Item .).FullName
} elseif ($cmd = Get-Command "ostp" -ErrorAction SilentlyContinue) {
    # If binary is already in the system PATH, find where it lives and update it there
    $InstallDir = Split-Path $cmd.Path
}

Write-Host "========================================================"
Write-Host " Installing Ospab Stealth Transport Protocol (OSTP)"
Write-Host "========================================================"
Write-Host "Target deployment location: $InstallDir"

# 2. Check Write Access & Verify Elevation
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not (Test-Path $InstallDir)) {
    try {
        New-Item -ItemType Directory -Path $InstallDir -ErrorAction Stop | Out-Null
    } catch {
        Write-Error "Access Denied: Cannot create target directory '$InstallDir'. Run as Administrator to proceed."
        exit 1
    }
} else {
    try {
        $testFile = Join-Path $InstallDir "ostp_write_test_$($PID).tmp"
        "test" | Set-Content $testFile -ErrorAction Stop
        Remove-Item $testFile -Force
    } catch {
        Write-Error "Access Denied: Target directory '$InstallDir' is write-protected. Run as Administrator to proceed."
        exit 1
    }
}

# 3. Detect System Architecture
$arch = "amd64"
if ([System.Environment]::Is64BitOperatingSystem -and ($Env:PROCESSOR_ARCHITECTURE -eq "ARM64" -or $Env:PROCESSOR_ARCHITEW6432 -eq "ARM64")) {
    $arch = "arm64"
}

# 4. Fetch Stable Version Asset
Write-Host "Fetching the latest stable version from the repository..."
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $api = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest"
    $tag = $api.tag_name
} catch {
    Write-Host "[Notice] Failed to automatically retrieve latest version tag."
    $tag = Read-Host "Enter release version tag manually (e.g., v0.1.23)"
    if (-not $tag) { exit 1 }
}

$archive = "ostp-windows-$arch.zip"
$url = "https://github.com/$repo/releases/download/$tag/$archive"
$zipPath = Join-Path $env:TEMP "ostp_temp_$($PID).zip"
$extractPath = Join-Path $env:TEMP "ostp_extract_$($PID)"

Write-Host "Downloading asset windows-${arch}: $url ..."
Invoke-WebRequest -Uri $url -OutFile $zipPath

if (-not (Test-Path $zipPath)) {
    Write-Error "Failed to download zip archive."
    exit 1
}

# Overwrite logic with active process suspension
if (Test-Path $extractPath) { Remove-Item $extractPath -Recurse -Force }
Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force

$exeFile = Get-ChildItem -Path $extractPath -Filter "*.exe" -Recurse | Select-Object -First 1
if ($exeFile) {
    Write-Host "Stopping any running instances of ostp to unlock binary..."
    Stop-Process -Name "ostp" -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    
    Copy-Item -Path $exeFile.FullName -Destination (Join-Path $InstallDir "ostp.exe") -Force
    Write-Host "Executable successfully deployed to $(Join-Path $InstallDir 'ostp.exe')."
} else {
    Write-Error "Executable ostp.exe not found in package."
    exit 1
}

# Cleanup temp cache
Remove-Item $zipPath -Force
Remove-Item $extractPath -Recurse -Force

# 5. Zero-Interactive Smart Updater
$configPath = Join-Path $InstallDir "config.json"
if (Test-Path $configPath) {
    Write-Host "--------------------------------------------------------"
    Write-Host "[Update] Existing configuration detected at $configPath."
    Write-Host "[Update] Binary successfully hot-swapped to version $tag."
    Write-Host "--------------------------------------------------------"
    Write-Host "Update completed successfully!"
    exit 0
}

# 6. Interactive Matrix Setup Menu
Write-Host "--------------------------------------------------------"
Write-Host "Select configuration mode:"
Write-Host "1) Configure Server"
Write-Host "2) Configure Client"
Write-Host "--------------------------------------------------------"
$mode = Read-Host "Enter selection choice [1-2]"

Push-Location $InstallDir

if ($mode -eq "1") {
    Write-Host "Initializing server configuration..."
    & .\ostp.exe --init server --config config.json
    
    $config = Get-Content "config.json" -Raw | ConvertFrom-Json
    $listen = Read-Host "Enter IP and port to accept incoming traffic [default: 0.0.0.0:50000]"
    if ($listen) { $config.listen = $listen }
    
    $keyCount = Read-Host "How many access keys to generate? [default: 1]"
    if (-not $keyCount) { $keyCount = 1 }
    
    if ([int]$keyCount -gt 1) {
        Write-Host "Generating additional telemetry keys..."
        $keys = & .\ostp.exe -g -c $keyCount
        $config.access_keys = $keys -split "`r`n" | Where-Object { $_ -ne "" }
    }
    
    $config | ConvertTo-Json -Depth 10 | Set-Content "config.json"
    Write-Host "Server deployment completed. Config file: $(Join-Path $InstallDir 'config.json')"

} elseif ($mode -eq "2") {
    Write-Host "Initializing client configuration..."
    & .\ostp.exe --init client --config config.json
    
    $config = Get-Content "config.json" -Raw | ConvertFrom-Json
    $server = Read-Host "Enter remote server address (IP:PORT)"
    if ($server) { $config.server = $server }
    
    $key = Read-Host "Enter access key (leave blank to generate automatically)"
    if (-not $key) {
        $key = & .\ostp.exe -g
        Write-Host "Automatically generated client access key: $key"
    }
    $config.access_key = $key.Trim()

    $socks = Read-Host "Enter SOCKS5 listening address [default: 127.0.0.1:1088]"
    if ($socks) { $config.socks5_bind = $socks }
    
    $config | ConvertTo-Json -Depth 10 | Set-Content "config.json"
    Write-Host "Client deployment completed. Config file: $(Join-Path $InstallDir 'config.json')"
} else {
    Write-Error "Invalid configuration selection."
    Pop-Location
    exit 1
}

Pop-Location

# 7. Adaptive Environment PATH Injection
Write-Host "--------------------------------------------------------"
Write-Host "Registering binary route in Environment PATH..."
$targetScope = if ($isAdmin) { [EnvironmentVariableTarget]::Machine } else { [EnvironmentVariableTarget]::User }
$sysPath = [Environment]::GetEnvironmentVariable("Path", $targetScope)
if ($sysPath -notlike "*$InstallDir*") {
    $newPath = "$sysPath;$InstallDir"
    [Environment]::SetEnvironmentVariable("Path", $newPath, $targetScope)
    Write-Host "Environment PATH updated successfully ($($targetScope.ToString()) scope)."
} else {
    Write-Host "$InstallDir is already mapped in PATH."
}

Write-Host "--------------------------------------------------------"
Write-Host "Deployment completed successfully!"
Write-Host "OSTP binary can now be run globally by typing: ostp"
Write-Host "Configuration location: $(Join-Path $InstallDir 'config.json')"
Write-Host "--------------------------------------------------------"
