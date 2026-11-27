use crate::{OstpTunInterface, OstpTunOptions};
use anyhow::{anyhow, Result};
use std::process::Command;
use std::os::windows::process::CommandExt;

pub mod windows_route {
    include!("windows_route.rs");
}

pub mod windows_guard {
    include!("windows_guard.rs");
}

fn netsh(args: &[String]) -> bool {
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    Command::new("netsh").creation_flags(CREATE_NO_WINDOW).args(args).output().is_ok_and(|o| o.status.success())
}

/// Deletes every DNS/IPv6 guard rule (a missing one is not an error). Run before the
/// rules are added, so a crash's leftovers go, and when the tunnel goes down.
fn remove_guard_rules() {
    for name in windows_guard::GUARD_RULE_NAMES {
        netsh(&windows_guard::delete_rule_args(name));
    }
}

/// The bypass routes in place, so a network change can move them.
struct BypassRoutes {
    nets: Vec<(std::net::Ipv4Addr, u8)>,
    gw: std::net::Ipv4Addr,
    if_index: u32,
    added: Vec<(std::net::Ipv4Addr, u8, std::net::Ipv4Addr, u32)>,
}

static ROUTES: std::sync::Mutex<Option<BypassRoutes>> = std::sync::Mutex::new(None);

pub(crate) fn refresh_bypass_routes() -> bool {
    let Some((gw, if_index)) = windows_route::sys::get_default_ipv4_route() else { return false };
    let Ok(mut routes) = ROUTES.lock() else { return false };
    let Some(r) = routes.as_mut() else { return false };
    if r.gw == gw && r.if_index == if_index {
        return false;
    }
    windows_route::sys::remove_bypass_routes(&r.added);
    r.added = windows_route::sys::add_bypass_routes(&r.nets, gw, if_index, 1);
    tracing::info!(
        "Network changed: bypass routes moved from {} (if_index={}) to {} (if_index={})",
        r.gw, r.if_index, gw, if_index
    );
    r.gw = gw;
    r.if_index = if_index;
    crate::set_physical_if(Some(if_index), None);
    true
}

struct WindowsRouteGuard {
    /// The TUN interface index when IPv6 routes were added through it.
    ipv6_if: Option<u32>,
}

impl Drop for WindowsRouteGuard {
    fn drop(&mut self) {
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        
        if let Some(r) = ROUTES.lock().ok().and_then(|mut r| r.take()) {
            windows_route::sys::remove_bypass_routes(&r.added);
            tracing::info!("Removed {} bypass routes.", r.added.len());
        }
        crate::set_physical_if(None, None);

        // Synchronous on purpose: a detached thread could still be running when the
        // tunnel is started again in the same process (GUI restart) and would then
        // delete the firewall rules and routes of the new session.
        if let Some(idx) = self.ipv6_if {
            for prefix in crate::IPV6_HALVES {
                let _ = Command::new("netsh")
                    .creation_flags(CREATE_NO_WINDOW)
                    .args(["interface", "ipv6", "delete", "route", &format!("prefix={prefix}"), &format!("interface={idx}")])
                    .output();
            }
        }
        for rule in ["OSTP Tunnel In", "OSTP Tunnel Out"] {
            let _ = Command::new("netsh")
                .creation_flags(CREATE_NO_WINDOW)
                .args(["advfirewall", "firewall", "delete", "rule", &format!("name={rule}")])
                .output();
        }
        remove_guard_rules();
        let _ = Command::new("netsh")
            .creation_flags(CREATE_NO_WINDOW)
            .args(["interface", "ipv4", "set", "dnsservers", "name=ostp_tun", "source=dhcp"])
            .output();
        let _ = Command::new("netsh")
            .creation_flags(CREATE_NO_WINDOW)
            .args(["interface", "ipv6", "set", "dnsservers", "name=ostp_tun", "source=dhcp"])
            .output();
    }
}

/// The smallest MTU IPv6 allows (RFC 8200 §5); Windows refuses a lower one.
const IPV6_MIN_MTU: u16 = 1280;

/// The MTUs to give the adapter: IPv4 takes the configured one, IPv6 the same
/// but never under its minimum. TCP through the tunnel ends at the local
/// stack, which announces its own MSS, so an IPv6 MTU above the configured one
/// only matters for large IPv6 UDP datagrams.
fn tun_mtus(mtu: u16) -> (u16, u16) {
    (mtu, mtu.max(IPV6_MIN_MTU))
}

/// Sets the adapter's MTU per address family (`store=active`: it goes with the
/// adapter). A failure is logged and the tunnel still starts.
async fn set_tun_mtu(idx: u32, mtu: u16) {
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let (v4, v6) = tun_mtus(mtu);
    let results = tokio::task::spawn_blocking(move || {
        let run = |family: &str, value: u16| {
            Command::new("netsh")
                .creation_flags(CREATE_NO_WINDOW)
                .args(["interface", family, "set", "subinterface", &idx.to_string(), &format!("mtu={value}"), "store=active"])
                .output()
                .is_ok_and(|o| o.status.success())
        };
        (run("ipv4", v4), run("ipv6", v6))
    })
    .await
    .unwrap_or((false, false));
    match results {
        (true, true) => tracing::info!("TUN MTU set: IPv4 {v4}, IPv6 {v6} (if_index={idx})."),
        (true, false) => tracing::warn!("TUN MTU set for IPv4 ({v4}); IPv6 refused {v6} (IPv6 may be off on this machine)."),
        (false, _) => tracing::error!("Could not set the TUN MTU to {v4} (if_index={idx}); large packets may be dropped."),
    }
}

pub async fn create(opts: OstpTunOptions) -> Result<OstpTunInterface> {
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    // Leftovers of a crashed session would block DNS for everything that follows.
    remove_guard_rules();

    let (phys_gw, phys_if) = windows_route::sys::get_default_ipv4_route()
        .ok_or_else(|| anyhow!("Cannot find physical default IPv4 route"))?;

    let mut bypass_v4: Vec<(std::net::Ipv4Addr, u8)> = Vec::new();
    if let std::net::IpAddr::V4(v4) = opts.server_ip {
        bypass_v4.push((v4, 32));
    }
    for (ip, prefix) in &opts.bypass_nets {
        if let std::net::IpAddr::V4(v4) = ip {
            bypass_v4.push((*v4, (*prefix).min(32)));
        }
    }

    let bypass_routes = windows_route::sys::add_bypass_routes(&bypass_v4, phys_gw, phys_if, 1);
    tracing::info!("Added {} bypass routes via {} (if_index={})", bypass_routes.len(), phys_gw, phys_if);
    if let Ok(mut r) = ROUTES.lock() {
        *r = Some(BypassRoutes { nets: bypass_v4, gw: phys_gw, if_index: phys_if, added: bypass_routes });
    }
    crate::set_physical_if(Some(phys_if), None);

    // From here on every error return drops the guard, which removes the routes
    // and rules added so far.
    let mut guard = WindowsRouteGuard { ipv6_if: None };

    let mut tun_cfg = tun::Configuration::default();
    tun_cfg
        .tun_name("ostp_tun")
        .address((10, 1, 0, 2))
        .netmask((255, 255, 255, 0))
        .destination((10, 1, 0, 1))
        .up();
    // No `.mtu()` here: the tun crate sets it for IPv4 and IPv6 alike, and IPv6
    // refuses anything under 1280 with os error 87 (ERROR_INVALID_PARAMETER),
    // so with the default MTU of 1140 the adapter could never be set up. The
    // MTU is set per family below, once the interface index is known.

    // A retry reuses the adapter left by the previous attempt.
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
        set_tun_mtu(idx, opts.mtu).await;
    }

    // Without a default route through the TUN traffic keeps leaving directly while
    // the tunnel looks up: fail instead of running open.
    let Some(idx) = tun_index else {
        return Err(anyhow!("cannot find the ostp_tun interface index: traffic would not be captured"));
    };
    windows_route::sys::add_ipv4_route(
        std::net::Ipv4Addr::new(0, 0, 0, 0),
        std::net::Ipv4Addr::new(0, 0, 0, 0),
        std::net::Ipv4Addr::new(10, 1, 0, 1),
        idx,
        5,
    )
    .map_err(|e| anyhow!("cannot add the default route via TUN (if_index={idx}): {e}"))?;
    tracing::info!("Default route via TUN (if_index={idx}, metric=5) added.");

    // IPv6 through the tunnel too (see ostp_tun::IPV6_HALVES). The routes are
    // `store=active`: they go away with the adapter even if the guard never runs.
    let ipv6_if = Some(idx).filter(|_| crate::capture_ipv6(opts.server_ip));
    guard.ipv6_if = ipv6_if;
    let mut ipv6_captured = false;
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
            ipv6_captured = true;
        } else {
            tracing::error!("Could not route IPv6 through the tunnel: IPv6 is blocked outside it instead.");
        }
    }

    let exe1 = current_exe.clone();
    let exe2 = current_exe.clone();
    let _ = tokio::task::spawn_blocking(move || {
        // Delete first: every start used to add one more rule with the same name.
        for rule in ["OSTP Tunnel In", "OSTP Tunnel Out"] {
            let _ = Command::new("netsh")
                .creation_flags(CREATE_NO_WINDOW)
                .args(["advfirewall", "firewall", "delete", "rule", &format!("name={rule}")])
                .output();
        }
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

    // DNS: the adapter always has a resolver (the configured one, else 1.1.1.1) and the
    // lowest metric, so Windows prefers it; the firewall rules then block DNS to every
    // other address, since Windows also asks the resolvers of the other adapters.
    // The server's host name is resolved before this point; a later lookup of it (a
    // reconnect) goes through the tunnel's resolver.
    let configured: Option<std::net::IpAddr> = opts
        .dns_server
        .as_deref()
        .map(str::trim)
        .filter(|d| !d.is_empty())
        .and_then(|d| d.parse().ok());
    if opts.dns_server.as_deref().is_some_and(|d| !d.trim().is_empty()) && configured.is_none() {
        tracing::warn!("tun.dns is not an IP address; using {}", windows_guard::DEFAULT_TUN_DNS);
    }
    let dns_v4 = match configured {
        Some(std::net::IpAddr::V4(a)) => a,
        _ => windows_guard::DEFAULT_TUN_DNS,
    };
    let dns_v6 = match configured {
        Some(std::net::IpAddr::V6(a)) if ipv6_captured => Some(a),
        _ => None,
    };
    let server_ip = opts.server_ip;
    let (dns4, metric4, blocked, total) = tokio::task::spawn_blocking(move || {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let dns4 = netsh(&s(&["interface", "ipv4", "set", "dnsservers", "name=ostp_tun", "static", &dns_v4.to_string(), "primary", "validate=no"]));
        let metric4 = netsh(&s(&["interface", "ipv4", "set", "interface", "name=ostp_tun", "metric=1"]));
        if ipv6_captured {
            if let Some(d6) = dns_v6 {
                netsh(&s(&["interface", "ipv6", "set", "dnsservers", "name=ostp_tun", "static", &d6.to_string(), "primary", "validate=no"]));
            }
            netsh(&s(&["interface", "ipv6", "set", "interface", "name=ostp_tun", "metric=1"]));
        }
        let mut rules = windows_guard::dns_guard_rules(Some(dns_v4), dns_v6, server_ip, ipv6_captured);
        if !ipv6_captured {
            rules.push(windows_guard::ipv6_block_rule(server_ip));
        }
        let total = rules.len();
        let blocked = rules.iter().filter(|r| netsh(&r.args)).count();
        (dns4, metric4, blocked, total)
    })
    .await
    .unwrap_or((false, false, 0, 1));
    if !dns4 {
        tracing::error!("Could not set the resolver {dns_v4} on ostp_tun.");
    }
    if !metric4 {
        tracing::warn!("Could not lower the metric of ostp_tun; Windows may prefer other adapters' resolvers.");
    }
    if blocked == total {
        tracing::info!(
            "DNS outside the tunnel is blocked (resolver {dns_v4}){}.",
            if ipv6_captured { "" } else { "; IPv6 outside the tunnel is blocked too (it is not carried)" }
        );
    } else {
        tracing::error!("Only {blocked} of {total} firewall rules against DNS/IPv6 leaks were added: queries may leave outside the tunnel.");
    }

    if opts.kill_switch {
        // A blackhole route cannot do this job here: its metric adds to the
        // loopback interface's 75 and never beats the real default route, so
        // traffic would still leave outside the tunnel when it drops.
        tracing::warn!("kill switch is not available on Windows and is ignored");
    }

    Ok(OstpTunInterface {
        device: dev,
        guard: Box::new(guard),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default MTU (1140) is below IPv6's minimum: IPv4 keeps it, IPv6
    /// gets 1280. Asking Windows for 1140 on IPv6 failed with os error 87.
    #[test]
    fn ipv6_never_gets_an_mtu_under_its_minimum() {
        assert_eq!(tun_mtus(1140), (1140, 1280));
        assert_eq!(tun_mtus(1280), (1280, 1280));
        assert_eq!(tun_mtus(1400), (1400, 1400));
    }
}
