use crate::{OstpTunInterface, OstpTunOptions};
use anyhow::{anyhow, Result};
use std::process::Command;

struct LinuxRouteGuard {
    server_ip: String,
    bypass_routes: Vec<String>,
    kill_switch: bool,
    ipv6: bool,
}

/// The bypass routes in place, so a network change can move them.
struct BypassRoutes {
    /// "a.b.c.d/32" for the server and every excluded address.
    routes: Vec<String>,
    gw: String,
    dev: String,
    kill_switch: bool,
}

static ROUTES: std::sync::Mutex<Option<BypassRoutes>> = std::sync::Mutex::new(None);

/// (gateway, device) of the physical default route; the TUN's own is skipped.
fn physical_default() -> Option<(String, String)> {
    let out = Command::new("ip").args(["route", "show", "default"]).output().ok()?;
    let text = String::from_utf8(out.stdout).ok()?;
    text.lines().filter(|l| !l.contains("dev ostp_tun")).find_map(|l| {
        let gw = l.split_whitespace().skip_while(|w| *w != "via").nth(1)?;
        let dev = l.split_whitespace().skip_while(|w| *w != "dev").nth(1)?;
        Some((gw.to_string(), dev.to_string()))
    })
}

pub(crate) fn refresh_bypass_routes() -> bool {
    let Some((gw, dev)) = physical_default() else { return false };
    let Ok(mut routes) = ROUTES.lock() else { return false };
    let Some(r) = routes.as_mut() else { return false };
    if r.gw == gw && r.dev == dev {
        return false;
    }
    for route in &r.routes {
        let _ = Command::new("ip").args(["route", "replace", route, "via", &gw, "dev", &dev]).output();
    }
    if r.kill_switch {
        // The new network brought its own default route: drop it as at start.
        let _ = Command::new("ip").args(["route", "del", "default", "via", &gw, "dev", &dev]).output();
    }
    tracing::info!("Network changed: bypass routes moved from {} dev {} to {} dev {}", r.gw, r.dev, gw, dev);
    r.gw = gw;
    r.dev = dev.clone();
    crate::set_physical_if(None, Some(dev));
    true
}

impl Drop for LinuxRouteGuard {
    fn drop(&mut self) {
        let _ = Command::new("ip").args(["route", "del", "default", "dev", "ostp_tun"]).output();
        if self.ipv6 {
            for prefix in crate::IPV6_HALVES {
                let _ = Command::new("ip").args(["-6", "route", "del", prefix, "dev", "ostp_tun"]).output();
            }
        }
        let _ = Command::new("ip").args(["route", "del", &format!("{}/32", self.server_ip)]).output();
        for route in &self.bypass_routes {
            let _ = Command::new("ip").args(["route", "del", route]).output();
        }
        tracing::info!("Removed Linux bypass routes.");

        // The default route to restore is the latest physical one, which a
        // network change may have moved since the tunnel started.
        let latest = ROUTES.lock().ok().and_then(|mut r| r.take());
        crate::set_physical_if(None, None);
        if self.kill_switch {
            if let Some(r) = latest {
                let _ = Command::new("ip").args(["route", "add", "default", "via", &r.gw, "dev", &r.dev]).output();
                tracing::info!("Restored original default route via {} dev {}", r.gw, r.dev);
            }
        }
    }
}

pub async fn create(opts: OstpTunOptions) -> Result<OstpTunInterface> {
    let mut tun_cfg = tun::Configuration::default();
    tun_cfg
        .tun_name("ostp_tun")
        .address((10, 1, 0, 2))
        .netmask((255, 255, 255, 0))
        .destination((10, 1, 0, 1))
        .mtu(opts.mtu)
        .up();

    let dev = tun::create(&tun_cfg).map_err(|e| anyhow!("Failed to create TUN device: {}", e))?;
    let dev = tun::AsyncDevice::new(dev).map_err(|e| anyhow!("TUN device async failed: {}", e))?;
    tracing::info!("TUN device 'ostp_tun' created.");

    let (real_gw, real_dev) = match physical_default() {
        Some((gw, dev)) => (Some(gw), Some(dev)),
        None => (None, None),
    };

    let mut bypass_routes = Vec::new();

    if let (Some(ref gw), Some(ref dev_name)) = (&real_gw, &real_dev) {
        let server_ip_str = opts.server_ip.to_string();
        let _ = Command::new("ip")
            .args(["route", "add", &format!("{}/32", server_ip_str), "via", gw, "dev", dev_name])
            .output();
        tracing::info!("Added bypass route for server {} via {}", server_ip_str, gw);

        for ip in &opts.bypass_ips {
            let route = format!("{}/32", ip);
            let _ = Command::new("ip").args(["route", "add", &route, "via", gw, "dev", dev_name]).output();
            bypass_routes.push(route);
        }

        let _ = Command::new("ip").args(["route", "add", "default", "dev", "ostp_tun"]).output();

        if opts.kill_switch {
            tracing::info!("Kill Switch: deleting original default route to prevent leakage.");
            let _ = Command::new("ip").args(["route", "del", "default", "via", gw, "dev", dev_name]).output();
        }

        let mut routes = vec![format!("{server_ip_str}/32")];
        routes.extend(bypass_routes.iter().cloned());
        if let Ok(mut r) = ROUTES.lock() {
            *r = Some(BypassRoutes { routes, gw: gw.clone(), dev: dev_name.clone(), kill_switch: opts.kill_switch });
        }
        crate::set_physical_if(None, Some(dev_name.clone()));
    } else {
        tracing::warn!("Could not detect physical default gateway. Tunnel routing might not work correctly.");
    }

    // IPv6 through the tunnel too (see ostp_tun::IPV6_HALVES).
    let ipv6 = crate::capture_ipv6(opts.server_ip);
    if ipv6 {
        let _ = Command::new("ip").args(["-6", "addr", "add", &format!("{}/128", crate::TUN_IPV6), "dev", "ostp_tun"]).output();
        let ok = crate::IPV6_HALVES.iter().all(|prefix| {
            Command::new("ip")
                .args(["-6", "route", "replace", prefix, "dev", "ostp_tun", "metric", "1"])
                .output()
                .is_ok_and(|o| o.status.success())
        });
        if ok {
            tracing::info!("IPv6 routed through the tunnel.");
        } else {
            tracing::error!("Could not route IPv6 through the tunnel (IPv6 disabled on ostp_tun?): IPv6 connections may bypass the VPN.");
        }
    }

    if let Some(ref dns) = opts.dns_server {
        if !dns.is_empty() {
            let _ = Command::new("resolvectl").args(["dns", "ostp_tun", dns]).output();
            let _ = Command::new("resolvectl").args(["domain", "ostp_tun", "~."]).output();
            let _ = Command::new("resolvectl").args(["default-route", "ostp_tun", "true"]).output();
            tracing::info!("Configured DNS via resolvectl for ostp_tun: {}", dns);
        }
    }

    Ok(OstpTunInterface {
        device: dev,
        guard: Box::new(LinuxRouteGuard {
            server_ip: opts.server_ip.to_string(),
            bypass_routes,
            kill_switch: opts.kill_switch,
            ipv6,
        }),
    })
}
