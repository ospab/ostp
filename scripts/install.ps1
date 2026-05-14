$ErrorActionPreference = "Stop"

$repo = "ospab/ostp"
$InstallDir = "C:\opt\ostp"

Write-Host "========================================================"
Write-Host " Installing Ospab Stealth Transport Protocol (OSTP)"
Write-Host "========================================================"

# 1. Verify Administrator Privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be run as Administrator (Run Windows PowerShell as Administrator)."
    exit 1
}

# 2. Setup Target Directory
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir | Out-Null
}

# 3. Detect Operating System Architecture
$arch = "amd64"
if ([System.Environment]::Is64BitOperatingSystem -and ($Env:PROCESSOR_ARCHITECTURE -eq "ARM64" -or $Env:PROCESSOR_ARCHITEW6432 -eq "ARM64")) {
    $arch = "arm64"
}

# 4. Fetch Latest Asset via GitHub API
Write-Host "Fetching the latest stable version from the repository..."
try {
    # We set SecurityProtocol to TLS 1.2 just in case
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $api = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest"
    $tag = $api.tag_name
} catch {
    Write-Host "[Notice] Failed to automatically retrieve the latest release tag."
    $tag = Read-Host "Enter release tag version manually (e.g., v0.1.22)"
    if (-not $tag) { exit 1 }
}

$archive = "ostp-windows-$arch.zip"
$url = "https://github.com/$repo/releases/download/$tag/$archive"
$zipPath = Join-Path $env:TEMP "ostp_temp_$($PID).zip"
$extractPath = Join-Path $env:TEMP "ostp_extract_$($PID)"

Write-Host "Downloading asset windows-${arch}: $url ..."
Invoke-WebRequest -Uri $url -OutFile $zipPath

if (-not (Test-Path $zipPath)) {
    Write-Error "Failed to download zip payload."
    exit 1
}

# Overwrite logic with active process suspension
if (Test-Path $extractPath) { Remove-Item $extractPath -Recurse -Force }
Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force

$exeFile = Get-ChildItem -Path $extractPath -Filter "*.exe" -Recurse | Select-Object -First 1
if ($exeFile) {
    Write-Host "Stopping any running instances of ostp..."
    Stop-Process -Name "ostp" -ErrorAction SilentlyContinue
    
    # Brief pause to let process handle unlock
    Start-Sleep -Seconds 1
    
    Copy-Item -Path $exeFile.FullName -Destination (Join-Path $InstallDir "ostp.exe") -Force
    Write-Host "Executable successfully deployed to $(Join-Path $InstallDir 'ostp.exe')."
} else {
    Write-Error "Executable ostp.exe not found in extracted archive package."
    exit 1
}

# Cleanup cache
Remove-Item $zipPath -Force
Remove-Item $extractPath -Recurse -Force

# 5. Smart Auto-Updater Mode
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
        Write-Host "Generating additional telemetry registration keys..."
        $keys = & .\ostp.exe -g -c $keyCount
        # Split output to string array
        $config.access_keys = $keys -split "`r`n" | Where-Object { $_ -ne "" }
    }
    
    $config | ConvertTo-Json -Depth 10 | Set-Content "config.json"
    Write-Host "Server deployment complete. Config file written to $(Join-Path $InstallDir 'config.json')"

} elseif ($mode -eq "2") {
    Write-Host "Initializing client configuration..."
    & .\ostp.exe --init client --config config.json
    
    $config = Get-Content "config.json" -Raw | ConvertFrom-Json
    $server = Read-Host "Enter remote server collector address (IP:PORT)"
    if ($server) { $config.server = $server }
    
    $key = Read-Host "Enter access key (leave blank to generate automatically)"
    if (-not $key) {
        $key = & .\ostp.exe -g
        Write-Host "Successfully auto-generated client access key: $key"
    }
    $config.access_key = $key.Trim()

    $socks = Read-Host "Enter SOCKS5 listening address [default: 127.0.0.1:1088]"
    if ($socks) { $config.socks5_bind = $socks }
    
    $config | ConvertTo-Json -Depth 10 | Set-Content "config.json"
    Write-Host "Client deployment complete. Config file written to $(Join-Path $InstallDir 'config.json')"
} else {
    Write-Error "Invalid configuration selection."
    Pop-Location
    exit 1
}

Pop-Location

# 7. Inject into System PATH variables
Write-Host "--------------------------------------------------------"
Write-Host "Injecting deployment route into System PATH..."
$sysPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::Machine)
if ($sysPath -notlike "*$InstallDir*") {
    $newPath = "$sysPath;$InstallDir"
    [Environment]::SetEnvironmentVariable("Path", $newPath, [EnvironmentVariableTarget]::Machine)
    Write-Host "System PATH updated successfully."
} else {
    Write-Host "$InstallDir route already present in System PATH."
}

Write-Host "--------------------------------------------------------"
Write-Host "Deployment completed successfully."
Write-Host "Deployment file cataloged at $(Join-Path $InstallDir 'config.json')"
Write-Host "OSTP binary added to global terminal paths. To test, open a new terminal and type: ostp"
Write-Host "To start active routing run: ostp --config $(Join-Path $InstallDir 'config.json')"
Write-Host "--------------------------------------------------------"
