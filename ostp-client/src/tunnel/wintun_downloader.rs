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

        // Correctly map compilation target architecture to Wintun zip layout folder structure
        let arch = if cfg!(target_arch = "x86_64") {
            "amd64"
        } else if cfg!(target_arch = "aarch64") {
            "arm64"
        } else if cfg!(target_arch = "arm") {
            "arm"
        } else {
            "x86"
        };
        
        let zip_path = dir.join("wintun.zip").to_string_lossy().replace('\\', "/");
        let temp_path = dir.join("wintun_temp").to_string_lossy().replace('\\', "/");
        let dll_dest = dll_path.to_string_lossy().replace('\\', "/");

        // Explicitly filter via Where-Object to select ONLY the single architecture matching dll.
        // This guarantees we never overwrite the correct x64 dll with x86/ARM formats during Expand-Archive recursions.
        let ps_script = format!(
            "Invoke-WebRequest -Uri 'https://www.wintun.net/builds/wintun-0.14.1.zip' -OutFile '{}' -UseBasicParsing -ErrorAction Stop; \
             Expand-Archive -Path '{}' -DestinationPath '{}' -Force; \
             Get-ChildItem -Path '{}' -Filter 'wintun.dll' -Recurse | Where-Object {{ $_.FullName -match 'bin[\\\\/]{}[\\\\/]' }} | Copy-Item -Destination '{}' -Force; \
             Remove-Item '{}', '{}' -Recurse -Force",
            zip_path, zip_path, temp_path, temp_path, arch, dll_dest, zip_path, temp_path
        );

        let output = std::process::Command::new("powershell")
            .args(["-Command", &ps_script])
            .current_dir(dir)
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("Failed to download and extract wintun.dll for architecture {}: {}", arch, stderr));
        }
        if debug {
            println!("[ostp-client] wintun.dll ({}) successfully downloaded and registered!", arch);
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

        let arch = if cfg!(target_arch = "x86_64") {
            "amd64"
        } else if cfg!(target_arch = "aarch64") {
            "arm64"
        } else if cfg!(target_arch = "arm") {
            "arm"
        } else {
            "386"
        };
        
        let zip_path = dir.join("tun2socks.zip").to_string_lossy().replace('\\', "/");
        let temp_path = dir.join("tun2socks_temp").to_string_lossy().replace('\\', "/");
        let dest_path = tun2socks_path.to_string_lossy().replace('\\', "/");

        let url = format!("https://github.com/xjasonlyu/tun2socks/releases/download/v2.6.0/tun2socks-windows-{}.zip", arch);

        let ps_script = format!(
            "Invoke-WebRequest -Uri '{}' -OutFile '{}' -UseBasicParsing -ErrorAction Stop; \
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
            return Err(anyhow!("Failed to download tun2socks.exe: {}", stderr));
        }
        if debug {
            println!("[ostp-client] tun2socks.exe ({}) downloaded and installed successfully!", arch);
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn download_tun2socks(debug: bool) -> Result<()> {
    let exe = std::env::current_exe()?;
    let dir = exe.parent().ok_or_else(|| anyhow::anyhow!("failed to get binary directory"))?;
    let tun2socks_path = dir.join("tun2socks");

    if !tun2socks_path.exists() {
        if debug {
            println!("[ostp-client] tun2socks not found. Downloading automatically for Linux...");
        }

        let arch = if cfg!(target_arch = "x86_64") {
            "amd64"
        } else if cfg!(target_arch = "aarch64") {
            "arm64"
        } else if cfg!(target_arch = "arm") {
            "arm"
        } else {
            "386"
        };

        let tar_path = dir.join("tun2socks.tar.gz").to_string_lossy().into_owned();
        let dest_path = tun2socks_path.to_string_lossy().into_owned();
        let url = format!("https://github.com/xjasonlyu/tun2socks/releases/download/v2.6.0/tun2socks-linux-{}.tar.gz", arch);

        let sh_script = format!(
            "curl -L -o '{}' '{}' && tar -xzf '{}' -C '{}' --wildcards '*/tun2socks' --strip-components=1 || tar -xzf '{}' -C '{}' tun2socks; \
             chmod +x '{}'; \
             rm -f '{}'",
            tar_path, url, tar_path, dir.to_string_lossy(), tar_path, dir.to_string_lossy(), dest_path, tar_path
        );

        let output = std::process::Command::new("sh")
            .args(["-c", &sh_script])
            .current_dir(dir)
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("Failed to download tun2socks for Linux: {}", stderr));
        }
        if debug {
            println!("[ostp-client] tun2socks ({}) downloaded and installed successfully!", arch);
        }
    }
    Ok(())
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
pub fn download_tun2socks(_debug: bool) -> Result<()> {
    Err(anyhow::anyhow!("Operating system unsupported, text an issue at github."))
}
