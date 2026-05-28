$ErrorActionPreference = "Stop"

Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "   OSTP Android App Release Build Pipeline    " -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan

# Step 1: Run JNI build script to compile Rust core and download tun2socks
Write-Host ""
Write-Host "[1/3] Compiling Rust JNI Core & Downloading tun2socks..." -ForegroundColor Yellow
$jniScript = Join-Path $PSScriptRoot "build_android_jni.ps1"
if (Test-Path $jniScript) {
    & $jniScript
} else {
    Write-Error "Could not find build_android_jni.ps1 at $jniScript"
    exit 1
}

# Step 2: Build Flutter APK in release mode
Write-Host ""
Write-Host "[2/3] Compiling Flutter Application in Release Mode..." -ForegroundColor Yellow
Push-Location $PSScriptRoot
try {
    & flutter build apk --release --target-platform android-arm,android-arm64
} catch {
    Write-Host "[ERROR] Flutter build failed! Make sure Flutter SDK is installed and configured in your PATH." -ForegroundColor Red
    Pop-Location
    exit 1
}
Pop-Location

# Step 3: Copy and rename the final release APK next to this script
Write-Host ""
Write-Host "[3/3] Copying and packaging release APK..." -ForegroundColor Yellow
$apkPath = Join-Path $PSScriptRoot "build\app\outputs\flutter-apk\app-release.apk"
$destPath = Join-Path $PSScriptRoot "ostp-client-release.apk"

if (Test-Path $apkPath) {
    Copy-Item -Path $apkPath -Destination $destPath -Force
    Write-Host ""
    Write-Host "==============================================" -ForegroundColor Green
    Write-Host "   SUCCESS! Build completed successfully!     " -ForegroundColor Green
    Write-Host "   Release APK copied to:                     " -ForegroundColor Green
    Write-Host "   $destPath" -ForegroundColor White
    Write-Host "==============================================" -ForegroundColor Green
} else {
    Write-Host "[ERROR] Release APK was not found at expected path: $apkPath" -ForegroundColor Red
    exit 1
}
