#![allow(unused_imports)]
use anyhow::Result;
#[cfg(target_os = "windows")]
use anyhow::anyhow;
use std::path::PathBuf;

#[cfg(target_os = "windows")]
pub fn download_wintun_dll(debug: bool) -> Result<()> {
    let exe = std::env::current_exe()?;
    let dir = exe.parent().ok_or_else(|| anyhow!("failed to get binary directory"))?;
    let dll_path = dir.join("wintun.dll");

    if !dll_path.exists() {
        if debug {
            println!("[ostp-client] wintun.dll not found. Downloading automatically...");
        }
        
        let zip_path = dir.join("wintun.zip").to_string_lossy().replace('\\', "/");
        let temp_path = dir.join("wintun_temp").to_string_lossy().replace('\\', "/");
        let dll_dest = dll_path.to_string_lossy().replace('\\', "/");

        let ps_script = format!(
            "Invoke-WebRequest -Uri 'https://www.wintun.net/builds/wintun-0.14.1.zip' -OutFile '{}' -ErrorAction Stop; \
             Expand-Archive -Path '{}' -DestinationPath '{}' -Force; \
             Get-ChildItem -Path '{}' -Filter 'wintun.dll' -Recurse | Copy-Item -Destination '{}' -Force; \
             Remove-Item '{}', '{}' -Recurse -Force",
            zip_path, zip_path, temp_path, temp_path, dll_dest, zip_path, temp_path
        );

        let output = std::process::Command::new("powershell")
            .args(["-Command", &ps_script])
            .current_dir(dir)
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("Failed to download wintun.dll: {stderr}"));
        }
        if debug {
            println!("[ostp-client] wintun.dll downloaded and installed successfully!");
        }
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn download_wintun_dll(_debug: bool) -> Result<()> {
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn download_tun2socks(debug: bool) -> Result<()> {
    let exe = std::env::current_exe()?;
    let dir = exe.parent().ok_or_else(|| anyhow!("failed to get binary directory"))?;
    let tun2socks_path = dir.join("tun2socks.exe");

    if !tun2socks_path.exists() {
        if debug {
            println!("[ostp-client] tun2socks.exe not found. Downloading automatically...");
        }
        
        let zip_path = dir.join("tun2socks.zip").to_string_lossy().replace('\\', "/");
        let temp_path = dir.join("tun2socks_temp").to_string_lossy().replace('\\', "/");
        let dest_path = tun2socks_path.to_string_lossy().replace('\\', "/");

        let url = "https://github.com/xjasonlyu/tun2socks/releases/download/v2.5.2/tun2socks-windows-amd64.zip";

        let ps_script = format!(
            "Invoke-WebRequest -Uri '{}' -OutFile '{}' -ErrorAction Stop; \
             Expand-Archive -Path '{}' -DestinationPath '{}' -Force; \
             Get-ChildItem -Path '{}' -Filter '*.exe' -Recurse | Copy-Item -Destination '{}' -Force; \
             Remove-Item '{}', '{}' -Recurse -Force",
            url, zip_path, zip_path, temp_path, temp_path, dest_path, zip_path, temp_path
        );

        let output = std::process::Command::new("powershell")
            .args(["-Command", &ps_script])
            .current_dir(dir)
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("Failed to download tun2socks.exe: {stderr}"));
        }
        if debug {
            println!("[ostp-client] tun2socks.exe downloaded and installed successfully!");
        }
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn download_tun2socks(_debug: bool) -> Result<()> {
    Ok(())
}
