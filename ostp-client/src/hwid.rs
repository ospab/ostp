//! Device identity for subscriptions that limit devices.
//!
//! The identifier sent to a server is `hex(HMAC-SHA256(key = platform id,
//! message = "ostp-hwid:" + server host))` cut to 32 hex characters: it is made
//! per server, so two servers cannot match one person, and the platform id itself
//! never leaves the device. Nothing here runs unless the owner turned the
//! "send a device ID" option on.

use anyhow::{anyhow, bail, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// What is sent with a subscription request: the three `x-` headers.
#[derive(Clone, PartialEq, Eq)]
pub struct Device {
    pub hwid: String,
    pub os: String,
    pub model: String,
}

// The identifier is credential-like: show at most its first 8 characters.
impl std::fmt::Debug for Device {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let short: String = self.hwid.chars().take(8).collect();
        f.debug_struct("Device")
            .field("hwid", &format!("{short}..."))
            .field("os", &self.os)
            .field("model", &self.model)
            .finish()
    }
}

/// The identifier for one server, 32 lowercase hex characters.
pub fn derive_hwid(platform_id: &str, server_host: &str) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(platform_id.trim().as_bytes()).expect("HMAC takes any key length");
    mac.update(b"ostp-hwid:");
    mac.update(server_host.trim().to_ascii_lowercase().as_bytes());
    let digest = mac.finalize().into_bytes();
    let mut out = String::with_capacity(32);
    for b in &digest[..16] {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// The device record for `url`'s server, from a platform id the caller got
/// (Android passes `ANDROID_ID`; desktop uses [`local_device`]).
pub fn device_for_url(url: &str, platform_id: &str, os: &str, model: &str) -> Result<Device> {
    if platform_id.trim().is_empty() {
        bail!("the platform did not give a device identifier");
    }
    let u = crate::subscription::parse_url(url)?;
    Ok(Device { hwid: derive_hwid(platform_id, &u.host), os: os.to_string(), model: model.to_string() })
}

/// This computer's record for `url`'s server (Windows, macOS, Linux).
pub fn local_device(url: &str) -> Result<Device> {
    let id = platform_id().ok_or_else(|| anyhow!("this system gives no stable device identifier"))?;
    device_for_url(url, &id, &os_name(), std::env::consts::ARCH)
}

/// The platform's own identifier. Never sent or logged. `None` on Android (the
/// app passes `ANDROID_ID` in) and where the system has none.
pub fn platform_id() -> Option<String> {
    let id = read_platform_id()?;
    let id = id.trim().to_string();
    (!id.is_empty()).then_some(id)
}

#[cfg(windows)]
mod win {
    use std::ptr::null_mut;
    use winapi::um::winreg::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RRF_SUBKEY_WOW6464KEY};

    /// A string value under HKLM, from the 64-bit view. Readable without admin rights.
    pub fn hklm_string(subkey: &str, value: &str) -> Option<String> {
        let wide = |s: &str| s.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
        let (sk, v) = (wide(subkey), wide(value));
        let mut buf = vec![0u16; 256];
        let mut bytes = (buf.len() * 2) as u32;
        // SAFETY: `buf` and `bytes` outlive the call and `bytes` is the buffer's real size.
        let rc = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                sk.as_ptr(),
                v.as_ptr(),
                RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY,
                null_mut(),
                buf.as_mut_ptr().cast(),
                &mut bytes,
            )
        };
        if rc != 0 {
            return None;
        }
        let units = (bytes as usize / 2).min(buf.len());
        let s = String::from_utf16_lossy(&buf[..units]);
        Some(s.trim_end_matches('\0').to_string())
    }
}

#[cfg(windows)]
fn read_platform_id() -> Option<String> {
    win::hklm_string(r"SOFTWARE\Microsoft\Cryptography", "MachineGuid")
}

#[cfg(target_os = "macos")]
fn read_platform_id() -> Option<String> {
    let out = std::process::Command::new("/usr/sbin/ioreg").args(["-rd1", "-c", "IOPlatformExpertDevice"]).output().ok()?;
    parse_ioreg_uuid(&String::from_utf8_lossy(&out.stdout))
}

#[cfg(all(unix, not(target_os = "macos"), not(target_os = "android")))]
fn read_platform_id() -> Option<String> {
    ["/etc/machine-id", "/var/lib/dbus/machine-id"]
        .iter()
        .filter_map(|p| std::fs::read_to_string(p).ok())
        .map(|s| s.trim().to_string())
        .find(|s| !s.is_empty())
}

#[cfg(any(target_os = "android", not(any(windows, unix))))]
fn read_platform_id() -> Option<String> {
    None
}

/// `"IOPlatformUUID" = "XXXXXXXX-..."` out of `ioreg` output.
#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
fn parse_ioreg_uuid(text: &str) -> Option<String> {
    let line = text.lines().find(|l| l.contains("IOPlatformUUID"))?;
    let value = line.split('=').nth(1)?.trim().trim_matches('"').trim();
    (!value.is_empty()).then(|| value.to_string())
}

/// "Windows 11", "macOS", "Linux" for the header `x-device-os`.
#[cfg(windows)]
pub fn os_name() -> String {
    let build = win::hklm_string(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuildNumber")
        .and_then(|b| b.trim().parse::<u32>().ok());
    windows_name(build).to_string()
}

#[cfg(target_os = "macos")]
pub fn os_name() -> String {
    "macOS".to_string()
}

#[cfg(not(any(windows, target_os = "macos")))]
pub fn os_name() -> String {
    match std::env::consts::OS {
        "linux" => "Linux".to_string(),
        other => other.to_string(),
    }
}

/// Windows 11 reports build 22000 and up while still calling itself version 10.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
fn windows_name(build: Option<u32>) -> &'static str {
    match build {
        Some(b) if b >= 22000 => "Windows 11",
        Some(_) => "Windows 10",
        None => "Windows",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_vector() {
        // Computed independently: python hmac.new(key, msg, sha256).hexdigest()[:32]
        let id = "0123456789abcdef-test-platform-id";
        assert_eq!(derive_hwid(id, "vpn.example.com"), "572c291ff9921f090783fd3d22d69228");
        assert_eq!(derive_hwid(id, "other.example.com"), "e4dfb51676e384fd17b0f5386ca7d266");
    }

    #[test]
    fn host_case_does_not_matter_and_servers_differ() {
        let id = "some-platform-id-value";
        assert_eq!(derive_hwid(id, "VPN.Example.com"), derive_hwid(id, "vpn.example.com"));
        assert_ne!(derive_hwid(id, "a.example.com"), derive_hwid(id, "b.example.com"));
        let h = derive_hwid(id, "a.example.com");
        assert_eq!(h.len(), 32);
        assert!(h.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn the_device_uses_the_host_without_the_port() {
        let a = device_for_url("https://Vpn.Example.com:8443/sub/t", "pid-0123456789abcdef", "Android 14", "Pixel 8").unwrap();
        let b = device_for_url("https://vpn.example.com/sub/other", "pid-0123456789abcdef", "Android 14", "Pixel 8").unwrap();
        assert_eq!(a.hwid, b.hwid);
        assert_eq!(a.hwid, derive_hwid("pid-0123456789abcdef", "vpn.example.com"));
        assert!(device_for_url("https://h/sub/t", "  ", "x", "y").is_err());
        assert!(device_for_url("http://h/sub/t", "pid", "x", "y").is_err());
    }

    #[test]
    fn debug_never_shows_the_whole_identifier() {
        let d = Device { hwid: "572c291ff9921f090783fd3d22d69228".into(), os: "Linux".into(), model: "x86_64".into() };
        let s = format!("{d:?}");
        assert!(s.contains("572c291f") && !s.contains("572c291ff"), "{s}");
    }

    #[test]
    fn ioreg_output() {
        let t = "+-o Root  <class IORegistryEntry>\n    {\n      \"IOPlatformUUID\" = \"4C4C4544-0042-4A10-8051-B7C04F4B4E32\"\n      \"IOPlatformSerialNumber\" = \"X\"\n    }\n";
        assert_eq!(parse_ioreg_uuid(t).as_deref(), Some("4C4C4544-0042-4A10-8051-B7C04F4B4E32"));
        assert_eq!(parse_ioreg_uuid("nothing here"), None);
    }

    #[test]
    fn windows_names() {
        assert_eq!(windows_name(Some(26100)), "Windows 11");
        assert_eq!(windows_name(Some(19045)), "Windows 10");
        assert_eq!(windows_name(None), "Windows");
    }

    /// The platform id of the machine running the tests: only its shape and
    /// stability are checked, the value is never printed.
    #[cfg(any(windows, all(unix, not(target_os = "android"))))]
    #[test]
    fn this_machine_has_a_stable_platform_id() {
        if let Some(a) = platform_id() {
            assert!(a.len() >= 16, "suspiciously short platform id");
            assert_eq!(Some(a), platform_id());
        }
        assert!(!os_name().is_empty());
    }
}
