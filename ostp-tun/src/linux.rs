use crate::{OstpTunInterface, OstpTunOptions};
use anyhow::{anyhow, Result};
use std::process::Command;

struct LinuxRouteGuard {
    server_ip: String,
    bypass_routes: Vec<String>,
    real_gw: Option<String>,
    real_dev: Option<String>,
    kill_switch: bool,
}

impl Drop for LinuxRouteGuard {
    fn drop(&mut self) {
        let _ = Command::new("ip").args(["route", "del", "default", "dev", "ostp_tun"]).output();
        let _ = Command::new("ip").args(["route", "del", &format!("{}/32", self.server_ip)]).output();
        for route in &self.bypass_routes {
            let _ = Command::new("ip").args(["route", "del", route]).output();
        }
        tracing::info!("Removed Linux bypass routes.");

        if self.kill_switch {
            if let (Some(ref gw), Some(ref dev)) = (&self.real_gw, &self.real_dev) {
                let _ = Command::new("ip").args(["route", "add", "default", "via", gw, "dev", dev]).output();
                tracing::info!("Restored original default route via {} dev {}", gw, dev);
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

    tun_cfg.platform_config(|cfg| {
        cfg.packet_information(false);
    });

    let dev = tun::create(&tun_cfg).map_err(|e| anyhow!("Failed to create TUN device: {}", e))?;
    let dev = tun::AsyncDevice::new(dev).map_err(|e| anyhow!("TUN device async failed: {}", e))?;
    tracing::info!("TUN device 'ostp_tun' created.");

    let gw_out = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok());

    let real_gw = gw_out.as_deref().and_then(|s| {
        s.split_whitespace().skip_while(|w| *w != "via").nth(1).map(|s| s.to_string())
    });
    let real_dev = gw_out.as_deref().and_then(|s| {
        s.split_whitespace().skip_while(|w| *w != "dev").nth(1).map(|s| s.to_string())
    });

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
    } else {
        tracing::warn!("Could not detect physical default gateway. Tunnel routing might not work correctly.");
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
            real_gw,
            real_dev,
            kill_switch: opts.kill_switch,
        }),
    })
}
