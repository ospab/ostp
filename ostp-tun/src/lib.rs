use anyhow::Result;

pub struct OstpTunOptions {
    pub server_ip: std::net::IpAddr,
    /// Networks (address, prefix length) that bypass the tunnel: excluded IPs, CIDRs
    /// and resolved excluded domains. The server itself is `server_ip`.
    pub bypass_nets: Vec<(std::net::IpAddr, u8)>,
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

/// Network address of `ip`/`prefix` (host bits cleared); the prefix is clamped to the
/// address family's width.
pub fn network_of(ip: std::net::IpAddr, prefix: u8) -> (std::net::IpAddr, u8) {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let p = prefix.min(32);
            let mask = if p == 0 { 0 } else { u32::MAX << (32 - u32::from(p)) };
            (std::net::IpAddr::V4(std::net::Ipv4Addr::from(u32::from(v4) & mask)), p)
        }
        std::net::IpAddr::V6(v6) => {
            let p = prefix.min(128);
            let mask = if p == 0 { 0 } else { u128::MAX << (128 - u32::from(p)) };
            (std::net::IpAddr::V6(std::net::Ipv6Addr::from(u128::from(v6) & mask)), p)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::network_of;

    #[test]
    fn network_clears_host_bits() {
        let (n, p) = network_of("10.20.30.40".parse().unwrap(), 16);
        assert_eq!((n.to_string(), p), ("10.20.0.0".to_string(), 16));
        let (n, p) = network_of("1.2.3.4".parse().unwrap(), 0);
        assert_eq!((n.to_string(), p), ("0.0.0.0".to_string(), 0));
        let (n, p) = network_of("1.2.3.4".parse().unwrap(), 99);
        assert_eq!((n.to_string(), p), ("1.2.3.4".to_string(), 32));
        let (n, p) = network_of("2001:db8::1".parse().unwrap(), 32);
        assert_eq!((n.to_string(), p), ("2001:db8::".to_string(), 32));
    }
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

/// The physical interface that bypass routes and bypass sockets go through. It is
/// set when the TUN is created and moved by `refresh_bypass_routes` when the
/// network changes (another Wi-Fi, a cable, a new gateway after sleep).
static PHYSICAL_IF: std::sync::Mutex<(Option<u32>, Option<String>)> = std::sync::Mutex::new((None, None));

#[allow(dead_code)]
pub(crate) fn set_physical_if(index: Option<u32>, name: Option<String>) {
    if let Ok(mut p) = PHYSICAL_IF.lock() {
        *p = (index, name);
    }
}

/// Index of the physical interface (Windows), as of the last route refresh.
pub fn physical_if_index() -> Option<u32> {
    PHYSICAL_IF.lock().ok().and_then(|p| p.0)
}

/// Name of the physical interface (Linux), as of the last route refresh.
pub fn physical_if_name() -> Option<String> {
    PHYSICAL_IF.lock().ok().and_then(|p| p.1.clone())
}

/// Points the bypass routes (the server and the excluded addresses) at the
/// current physical default gateway if it changed since they were added.
/// Without this, after a network change the route to the server still leads to
/// the old gateway and every reconnect attempt goes nowhere. Returns true when
/// the routes were moved. Blocking: it reads the routing table.
pub fn refresh_bypass_routes() -> bool {
    #[cfg(target_os = "windows")]
    return windows::refresh_bypass_routes();
    #[cfg(target_os = "linux")]
    return linux::refresh_bypass_routes();
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    false
}

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
