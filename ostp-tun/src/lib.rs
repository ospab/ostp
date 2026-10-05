use anyhow::Result;

pub struct OstpTunOptions {
    pub server_ip: std::net::IpAddr,
    pub bypass_ips: Vec<std::net::IpAddr>,
    pub dns_server: Option<String>,
    pub kill_switch: bool,
    pub mtu: u16,
    pub wintun_path: Option<String>,
}

/// The tunnel's IPv6 address, the same as on Android: unique-local, so the
/// system still prefers IPv4 where a site has both.
pub const TUN_IPV6: &str = "fd00:1:fd00:1:fd00:1:fd00:1";

/// IPv6 goes into the tunnel too, as two halves that beat any default route.
/// Without them a dual-stack network sent every IPv6 connection past the VPN
/// with the user's real address. Skipped when the server itself is reached
/// over IPv6: its packets would loop into the tunnel.
pub const IPV6_HALVES: [&str; 2] = ["::/1", "8000::/1"];

pub fn capture_ipv6(server_ip: std::net::IpAddr) -> bool {
    if server_ip.is_ipv6() {
        tracing::warn!("The server is reached over IPv6: IPv6 traffic is not captured by the tunnel");
        return false;
    }
    true
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
    #[allow(unused_variables)]
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
