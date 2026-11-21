use crate::{OstpTunInterface, OstpTunOptions};
use anyhow::{anyhow, Result};
use std::process::Command;

/// Metric of the default route through the TUN: explicit, so it beats any physical
/// default route whatever metric the DHCP client gave it.
const TUN_DEFAULT_METRIC: &str = "1";

struct LinuxRouteGuard {
    server_ip: String,
    bypass_routes: Vec<String>,
    kill_switch: bool,
    ipv6: bool,
}

/// The bypass routes in place, so a network change can move them.
struct BypassRoutes {
    /// "a.b.c.d/len" for the server and every excluded network.
    routes: Vec<String>,
    /// None for a point-to-point default route (`default dev ppp0`).
    gw: Option<String>,
    dev: String,
    kill_switch: bool,
}

static ROUTES: std::sync::Mutex<Option<BypassRoutes>> = std::sync::Mutex::new(None);

/// Runs `ip` and turns a failure (spawn error or non-zero exit) into an error
/// carrying the command line and its stderr.
fn ip(args: &[&str]) -> Result<()> {
    let out = Command::new("ip").args(args).output().map_err(|e| anyhow!("could not run ip: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(anyhow!("`ip {}` failed: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim()))
    }
}

/// `ip route <verb> <route> [via <gw>] dev <dev>`.
fn route_via(verb: &str, route: &str, gw: &Option<String>, dev: &str) -> Result<()> {
    match gw {
        Some(gw) => ip(&["route", verb, route, "via", gw, "dev", dev]),
        None => ip(&["route", verb, route, "dev", dev]),
    }
}

/// Parses `ip route show default` into (gateway, device) of the first default route
/// that is not the TUN's. The gateway is absent for a device-only route such as
/// `default dev ppp0 scope link` (PPP, some LTE modems and WireGuard-style links).
fn parse_default(text: &str) -> Option<(Option<String>, String)> {
    text.lines().filter(|l| !l.contains("dev ostp_tun")).find_map(|l| {
        let mut words = l.split_whitespace();
        if words.next() != Some("default") {
            return None;
        }
        let dev = l.split_whitespace().skip_while(|w| *w != "dev").nth(1)?.to_string();
        let gw = l.split_whitespace().skip_while(|w| *w != "via").nth(1).map(str::to_string);
        Some((gw, dev))
    })
}

/// (gateway, device) of the physical default route; the TUN's own is skipped.
fn physical_default() -> Option<(Option<String>, String)> {
    let out = Command::new("ip").args(["route", "show", "default"]).output().ok()?;
    parse_default(&String::from_utf8(out.stdout).ok()?)
}

pub(crate) fn refresh_bypass_routes() -> bool {
    let Some((gw, dev)) = physical_default() else { return false };
    let Ok(mut routes) = ROUTES.lock() else { return false };
    let Some(r) = routes.as_mut() else { return false };
    if r.gw == gw && r.dev == dev {
        return false;
    }
    for route in &r.routes {
        if let Err(e) = route_via("replace", route, &gw, &dev) {
            tracing::warn!("could not move the bypass route {route}: {e}");
        }
    }
    if r.kill_switch {
        // The new network brought its own default route: drop it as at start.
        let _ = match &gw {
            Some(g) => ip(&["route", "del", "default", "via", g, "dev", &dev]),
            None => ip(&["route", "del", "default", "dev", &dev]),
        };
    }
    tracing::info!("Network changed: bypass routes moved from {:?} dev {} to {:?} dev {}", r.gw, r.dev, gw, dev);
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
                match route_via("add", "default", &r.gw, &r.dev) {
                    Ok(()) => tracing::info!("Restored original default route via {:?} dev {}", r.gw, r.dev),
                    Err(e) => tracing::error!("could not restore the original default route: {e}"),
                }
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

    let (real_gw, real_dev) = physical_default()
        .ok_or_else(|| anyhow!("Could not detect the physical default route: refusing to start a tunnel that cannot reach its server"))?;

    // From here on every error return drops the guard, which removes what was added.
    let mut guard = LinuxRouteGuard {
        server_ip: opts.server_ip.to_string(),
        bypass_routes: Vec::new(),
        kill_switch: opts.kill_switch,
        ipv6: false,
    };

    // `replace` instead of `add`: a stale route from a crashed session is overwritten
    // instead of failing with EEXIST.
    let server_route = match opts.server_ip {
        std::net::IpAddr::V4(_) => Some(format!("{}/32", opts.server_ip)),
        std::net::IpAddr::V6(_) => None,
    };
    if let Some(route) = &server_route {
        route_via("replace", route, &real_gw, &real_dev)
            .map_err(|e| anyhow!("cannot add the route to the server outside the tunnel: {e}"))?;
        tracing::info!("Added bypass route for server {} via {:?} dev {}", opts.server_ip, real_gw, real_dev);
    }

    for (addr, prefix) in &opts.bypass_nets {
        if addr.is_ipv6() {
            // IPv6 goes through the stack-level matcher; the physical route is IPv4.
            continue;
        }
        let (net, prefix) = crate::network_of(*addr, *prefix);
        let route = format!("{net}/{prefix}");
        match route_via("replace", &route, &real_gw, &real_dev) {
            Ok(()) => guard.bypass_routes.push(route),
            Err(e) => tracing::warn!("bypass route {route} failed: {e}"),
        }
    }

    ip(&["route", "replace", "default", "dev", "ostp_tun", "metric", TUN_DEFAULT_METRIC])
        .map_err(|e| anyhow!("cannot add the default route via the TUN: {e}"))?;

    if opts.kill_switch {
        tracing::info!("Kill Switch: deleting original default route to prevent leakage.");
        let r = match &real_gw {
            Some(gw) => ip(&["route", "del", "default", "via", gw, "dev", &real_dev]),
            None => ip(&["route", "del", "default", "dev", &real_dev]),
        };
        if let Err(e) = r {
            return Err(anyhow!("kill switch: cannot delete the original default route: {e}"));
        }
    }

    let mut routes: Vec<String> = server_route.into_iter().collect();
    routes.extend(guard.bypass_routes.iter().cloned());
    if let Ok(mut r) = ROUTES.lock() {
        *r = Some(BypassRoutes { routes, gw: real_gw.clone(), dev: real_dev.clone(), kill_switch: opts.kill_switch });
    }
    crate::set_physical_if(None, Some(real_dev.clone()));

    // IPv6 through the tunnel too (see ostp_tun::IPV6_HALVES).
    guard.ipv6 = crate::capture_ipv6(opts.server_ip);
    if guard.ipv6 {
        let _ = Command::new("ip").args(["-6", "addr", "add", &format!("{}/128", crate::TUN_IPV6), "dev", "ostp_tun"]).output();
        let ok = crate::IPV6_HALVES.iter().all(|prefix| {
            ip(&["-6", "route", "replace", *prefix, "dev", "ostp_tun", "metric", "1"]).is_ok()
        });
        if ok {
            tracing::info!("IPv6 routed through the tunnel.");
        } else {
            tracing::error!("Could not route IPv6 through the tunnel (IPv6 disabled on ostp_tun?): IPv6 connections may bypass the VPN.");
        }
    }

    if let Some(ref dns) = opts.dns_server {
        if !dns.is_empty() {
            let run = |args: &[&str]| -> bool {
                Command::new("resolvectl").args(args).output().is_ok_and(|o| o.status.success())
            };
            let ok = run(&["dns", "ostp_tun", dns])
                && run(&["domain", "ostp_tun", "~."])
                && run(&["default-route", "ostp_tun", "true"]);
            if ok {
                tracing::info!("Configured DNS via resolvectl for ostp_tun: {}", dns);
            } else {
                tracing::warn!("resolvectl failed (not installed or systemd-resolved not running): DNS {dns} was not set for ostp_tun");
            }
        }
    }

    Ok(OstpTunInterface {
        device: dev,
        guard: Box::new(guard),
    })
}

#[cfg(test)]
mod tests {
    use super::parse_default;

    #[test]
    fn default_with_gateway() {
        let t = "default via 192.168.1.1 dev eth0 proto dhcp metric 100\n";
        assert_eq!(parse_default(t), Some((Some("192.168.1.1".into()), "eth0".into())));
    }

    #[test]
    fn default_device_only() {
        let t = "default dev ppp0 scope link\n";
        assert_eq!(parse_default(t), Some((None, "ppp0".into())));
    }

    #[test]
    fn skips_own_tun_route() {
        let t = "default dev ostp_tun metric 1\ndefault via 10.0.0.1 dev wlan0 metric 600\n";
        assert_eq!(parse_default(t), Some((Some("10.0.0.1".into()), "wlan0".into())));
    }

    #[test]
    fn no_default() {
        assert_eq!(parse_default(""), None);
        assert_eq!(parse_default("default dev ostp_tun metric 1\n"), None);
    }
}
