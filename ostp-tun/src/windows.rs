use crate::{OstpTunInterface, OstpTunOptions};
use anyhow::{anyhow, Result};
use std::process::Command;
use std::os::windows::process::CommandExt;

pub mod windows_route {
    include!("windows_route.rs");
}

struct WindowsRouteGuard {
    bypass_routes: Vec<(std::net::Ipv4Addr, std::net::Ipv4Addr, u32)>,
    kill_switch: bool,
    /// The TUN interface index when IPv6 routes were added through it.
    ipv6_if: Option<u32>,
}

impl Drop for WindowsRouteGuard {
    fn drop(&mut self) {
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        
        windows_route::sys::remove_bypass_routes(&self.bypass_routes);
        tracing::info!("Removed {} bypass routes.", self.bypass_routes.len());

        let is_kill_switch = self.kill_switch;
        let ipv6_if = self.ipv6_if;
        let _ = std::thread::spawn(move || {
            if let Some(idx) = ipv6_if {
                for prefix in crate::IPV6_HALVES {
                    let _ = Command::new("netsh")
                        .creation_flags(CREATE_NO_WINDOW)
                        .args(["interface", "ipv6", "delete", "route", &format!("prefix={prefix}"), &format!("interface={idx}")])
                        .output();
                }
            }
            let _ = Command::new("netsh")
                .creation_flags(CREATE_NO_WINDOW)
                .args(["advfirewall", "firewall", "delete", "rule", "name=OSTP Tunnel In"])
                .output();
            let _ = Command::new("netsh")
                .creation_flags(CREATE_NO_WINDOW)
                .args(["advfirewall", "firewall", "delete", "rule", "name=OSTP Tunnel Out"])
                .output();
            let _ = Command::new("netsh")
                .creation_flags(CREATE_NO_WINDOW)
                .args(["interface", "ipv4", "set", "dnsservers",
                       "name=ostp_tun", "source=dhcp"])
                .output();
            if is_kill_switch {
                let _ = Command::new("route")
                    .creation_flags(CREATE_NO_WINDOW)
                    .args(["delete", "0.0.0.0", "mask", "0.0.0.0", "127.0.0.1"])
                    .output();
            }
        });
    }
}

pub async fn create(opts: OstpTunOptions) -> Result<OstpTunInterface> {
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    let (phys_gw, phys_if) = windows_route::sys::get_default_ipv4_route()
        .ok_or_else(|| anyhow!("Cannot find physical default IPv4 route"))?;

    let mut bypass_v4: Vec<std::net::Ipv4Addr> = Vec::new();
    if let std::net::IpAddr::V4(v4) = opts.server_ip {
        bypass_v4.push(v4);
    }
    for ip in opts.bypass_ips {
        if let std::net::IpAddr::V4(v4) = ip {
            bypass_v4.push(v4);
        }
    }

    let bypass_routes = windows_route::sys::add_bypass_routes(&bypass_v4, phys_gw, phys_if, 1);
    tracing::info!("Added {} bypass routes via {} (if_index={})", bypass_routes.len(), phys_gw, phys_if);

    let mut tun_cfg = tun::Configuration::default();
    tun_cfg
        .tun_name("ostp_tun")
        .address((10, 1, 0, 2))
        .netmask((255, 255, 255, 0))
        .destination((10, 1, 0, 1))
        .mtu(opts.mtu)
        .up();

    // Setting the address right after the adapter is created can fail with os error 87
    // until the interface is registered in the IP stack; a retry reuses the adapter.
    let dev = {
        let mut attempt = 0;
        loop {
            attempt += 1;
            match tun::create(&tun_cfg) {
                Ok(d) => break d,
                Err(e) if attempt < 5 => {
                    tracing::warn!(
                        "TUN device creation attempt {}/5 failed: {}; retrying in 300 ms",
                        attempt, e
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                }
                Err(e) => return Err(anyhow!("Failed to create TUN device after {} attempts: {}", attempt, e)),
            }
        }
    };
    let dev = tun::AsyncDevice::new(dev).map_err(|e| anyhow!("TUN device async failed: {}", e))?;
    tracing::info!("TUN device 'ostp_tun' created.");

    let current_exe = std::env::current_exe()?.to_string_lossy().into_owned();

    // WinTun does not put the adapter name in FriendlyName, so the index is read from the
    // device itself; the name lookup is only a fallback.
    use tun::AbstractDevice;
    let tun_index = match dev.tun_index() {
        Ok(idx) if idx > 0 => Some(idx as u32),
        Ok(idx) => {
            tracing::error!("WinTun reported a non-positive interface index ({idx})");
            None
        }
        Err(e) => {
            tracing::warn!("cannot read the TUN index from the adapter ({e}); looking it up by name");
            let mut idx = None;
            for _ in 0..75 {
                if let Some(i) = windows_route::sys::get_interface_index("ostp_tun") {
                    idx = Some(i);
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
            idx
        }
    };

    if let Some(idx) = tun_index {
        match windows_route::sys::add_ipv4_route(
            std::net::Ipv4Addr::new(0, 0, 0, 0),
            std::net::Ipv4Addr::new(0, 0, 0, 0),
            std::net::Ipv4Addr::new(10, 1, 0, 1),
            idx,
            5,
        ) {
            Ok(()) => tracing::info!("Default route via TUN (if_index={idx}, metric=5) added."),
            Err(e) => tracing::error!("cannot add the default route via TUN (if_index={idx}): {e}; traffic is not captured"),
        }
    } else {
        tracing::error!("cannot find the ostp_tun interface index after 15 s; traffic is not captured");
    }

    // IPv6 through the tunnel too (see ostp_tun::IPV6_HALVES). The routes are
    // `store=active`: they go away with the adapter even if the guard never runs.
    let ipv6_if = tun_index.filter(|_| crate::capture_ipv6(opts.server_ip));
    if let Some(idx) = ipv6_if {
        let ok = tokio::task::spawn_blocking(move || {
            let run = |args: &[&str]| {
                Command::new("netsh").creation_flags(CREATE_NO_WINDOW).args(args).output().is_ok_and(|o| o.status.success())
            };
            let _ = run(&["interface", "ipv6", "add", "address", &format!("interface={idx}"), &format!("address={}", crate::TUN_IPV6), "store=active"]);
            crate::IPV6_HALVES.iter().all(|prefix| {
                run(&["interface", "ipv6", "add", "route", &format!("prefix={prefix}"), &format!("interface={idx}"), "metric=1", "store=active"])
            })
        })
        .await
        .unwrap_or(false);
        if ok {
            tracing::info!("IPv6 routed through the tunnel (if_index={idx}).");
        } else {
            tracing::error!("Could not route IPv6 through the tunnel: IPv6 connections may bypass the VPN.");
        }
    }

    let exe1 = current_exe.clone();
    let exe2 = current_exe.clone();
    let _ = tokio::task::spawn_blocking(move || {
        let _ = Command::new("netsh")
            .creation_flags(CREATE_NO_WINDOW)
            .args(["advfirewall", "firewall", "add", "rule",
                   "name=OSTP Tunnel In", "dir=in", "action=allow",
                   &format!("program={}", exe1)])
            .output();
        let _ = Command::new("netsh")
            .creation_flags(CREATE_NO_WINDOW)
            .args(["advfirewall", "firewall", "add", "rule",
                   "name=OSTP Tunnel Out", "dir=out", "action=allow",
                   &format!("program={}", exe2)])
            .output();
        let _ = Command::new("netsh")
            .creation_flags(CREATE_NO_WINDOW)
            .args(["interface", "ipv4", "set", "interface", "name=ostp_tun",
                   "routerdiscovery=disabled", "dadtransmits=0",
                   "managedaddress=disabled", "otherstateful=disabled"])
            .output();
    });

    if let Some(ref dns) = opts.dns_server {
        if !dns.is_empty() {
            let dns_clone = dns.clone();
            let _ = tokio::task::spawn_blocking(move || {
                let _ = Command::new("netsh")
                    .creation_flags(CREATE_NO_WINDOW)
                    .args(["interface", "ipv4", "set", "dnsservers",
                           "name=ostp_tun", "static", &dns_clone, "primary"])
                    .output();
            });
        }
    }

    if opts.kill_switch {
        tracing::info!("kill switch: adding a metric 10 blackhole route");
        let _ = tokio::task::spawn_blocking(move || {
            let _ = Command::new("route")
                .creation_flags(CREATE_NO_WINDOW)
                .args(["add", "0.0.0.0", "mask", "0.0.0.0", "127.0.0.1", "metric", "10", "if", "1"])
                .output();
        });
    }

    Ok(OstpTunInterface {
        device: dev,
        guard: Box::new(WindowsRouteGuard {
            bypass_routes,
            kill_switch: opts.kill_switch,
            ipv6_if,
        }),
    })
}
