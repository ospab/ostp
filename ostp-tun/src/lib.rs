use anyhow::Result;

pub struct OstpTunOptions {
    pub server_ip: std::net::IpAddr,
    pub bypass_ips: Vec<std::net::IpAddr>,
    pub dns_server: Option<String>,
    pub kill_switch: bool,
    pub mtu: u16,
    pub wintun_path: Option<String>,
}

pub struct OstpTunInterface {
    pub device: tun::AsyncDevice,
    pub guard: Box<dyn std::any::Any + Send + Sync>,
}

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

impl OstpTunInterface {
    pub async fn create(opts: OstpTunOptions) -> Result<Self> {
        #[cfg(target_os = "windows")]
        return windows::create(opts).await;

        #[cfg(target_os = "linux")]
        return linux::create(opts).await;

        #[cfg(target_os = "macos")]
        return macos::create(opts).await;

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        anyhow::bail!("Unsupported OS for ostp-tun");
    }
}
