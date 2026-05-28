$ErrorActionPreference = "Stop"

Write-Host "Building OSTP JNI for Android (arm64-v8a and armeabi-v7a)..."

$jniLibs = "$PSScriptRoot\android\app\src\main\jniLibs"
New-Item -ItemType Directory -Force -Path "$jniLibs\arm64-v8a" | Out-Null
New-Item -ItemType Directory -Force -Path "$jniLibs\armeabi-v7a" | Out-Null

Push-Location "$PSScriptRoot\..\ostp-jni"

Write-Host "Compiling for aarch64-linux-android and armv7-linux-androideabi..."
cargo ndk -t arm64-v8a -t armeabi-v7a -o "$jniLibs" build --release

$tun2socksArm64 = "$jniLibs\arm64-v8a\libtun2socks.so"
$tun2socksArmv7 = "$jniLibs\armeabi-v7a\libtun2socks.so"

if (-not (Test-Path $tun2socksArm64)) {
    Write-Host "Downloading tun2socks for arm64-v8a..."
    Invoke-WebRequest -Uri "https://github.com/xjasonlyu/tun2socks/releases/download/v2.6.0/tun2socks-linux-arm64.zip" -OutFile "$jniLibs\t2s64.zip"
    Expand-Archive "$jniLibs\t2s64.zip" "$jniLibs\t2s64_tmp" -Force
    Copy-Item "$jniLibs\t2s64_tmp\tun2socks-linux-arm64" $tun2socksArm64 -Force
    Remove-Item "$jniLibs\t2s64.zip", "$jniLibs\t2s64_tmp" -Recurse -Force
}

if (-not (Test-Path $tun2socksArmv7)) {
    Write-Host "Downloading tun2socks for armeabi-v7a..."
    Invoke-WebRequest -Uri "https://github.com/xjasonlyu/tun2socks/releases/download/v2.6.0/tun2socks-linux-armv7.zip" -OutFile "$jniLibs\t2s32.zip"
    Expand-Archive "$jniLibs\t2s32.zip" "$jniLibs\t2s32_tmp" -Force
    Copy-Item "$jniLibs\t2s32_tmp\tun2socks-linux-armv7" $tun2socksArmv7 -Force
    Remove-Item "$jniLibs\t2s32.zip", "$jniLibs\t2s32_tmp" -Recurse -Force
}

Pop-Location

Write-Host "Done! The .so files have been copied to $jniLibs"
