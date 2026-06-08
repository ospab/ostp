use crate::{OstpTunInterface, OstpTunOptions};
use anyhow::{anyhow, Result};
use std::process::Command;

struct MacosRouteGuard {
    server_ip: String,
    bypass_routes: Vec<String>,
    real_gw: Option<String>,
    kill_switch: bool,
}

impl Drop for MacosRouteGuard {
    fn drop(&mut self) {
        let _ = Command::new("route").args(["delete", "-net", "default", "-interface", "utun5"]).output();
        let _ = Command::new("route").args(["delete", "-host", &self.server_ip]).output();
        for route in &self.bypass_routes {
            let _ = Command::new("route").args(["delete", "-host", route]).output();
        }
        tracing::info!("Removed macOS bypass routes.");

        if self.kill_switch {
            if let Some(ref gw) = self.real_gw {
                let _ = Command::new("route").args(["add", "default", gw]).output();
                tracing::info!("Restored original default route via {}", gw);
            }
        }
    }
}

pub async fn create(opts: OstpTunOptions) -> Result<OstpTunInterface> {
    let mut tun_cfg = tun::Configuration::default();
    tun_cfg
        .tun_name("utun5")
        .address((10, 1, 0, 2))
        .netmask((255, 255, 255, 0))
        .destination((10, 1, 0, 1))
        .mtu(opts.mtu)
        .up();

    let dev = tun::create(&tun_cfg).map_err(|e| anyhow!("Failed to create TUN device: {}", e))?;
    let dev = tun::AsyncDevice::new(dev).map_err(|e| anyhow!("TUN device async failed: {}", e))?;
    tracing::info!("TUN device 'utun5' created.");

    let gw_out = Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok());

    let real_gw = gw_out.as_deref().and_then(|s| {
        s.lines()
            .find(|l| l.contains("gateway:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .map(|s| s.to_string())
    });

    let mut bypass_routes = Vec::new();

    if let Some(ref gw) = real_gw {
        let server_ip_str = opts.server_ip.to_string();
        let _ = Command::new("route").args(["add", "-host", &server_ip_str, gw]).output();
        tracing::info!("Added bypass route for server {} via {}", server_ip_str, gw);

        for ip in &opts.bypass_ips {
            let route = format!("{}", ip);
            let _ = Command::new("route").args(["add", "-host", &route, gw]).output();
            bypass_routes.push(route);
        }

        let _ = Command::new("route").args(["add", "-net", "default", "-interface", "utun5"]).output();

        if opts.kill_switch {
            tracing::info!("Kill Switch: deleting original default route to prevent leakage.");
            let _ = Command::new("route").args(["delete", "default", gw]).output();
        }
    } else {
        tracing::warn!("Could not detect physical default gateway on macOS.");
    }

    Ok(OstpTunInterface {
        device: dev,
        guard: Box::new(MacosRouteGuard {
            server_ip: opts.server_ip.to_string(),
            bypass_routes,
            real_gw,
            kill_switch: opts.kill_switch,
        }),
    })
}
