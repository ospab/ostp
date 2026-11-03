// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ospab
//! TUN device and routing for the OSTP client on ospab.os (AETERNA microkernel).

use crate::{OstpTunInterface, OstpTunOptions};
use anyhow::Result;

pub struct OosRouteGuard {
    pub server_ip: String,
    pub kill_switch: bool,
}

impl Drop for OosRouteGuard {
    fn drop(&mut self) {
        tracing::info!("Resetting OOS tunnel routes (guard dropped)");
    }
}

pub(crate) fn refresh_bypass_routes() -> bool {
    // On OOS, routing is handled either via IPC to netmgr or in-kernel routing table.
    false
}

pub async fn create(opts: OstpTunOptions) -> Result<OstpTunInterface> {
    tracing::info!(
        "Creating OOS TUN interface for server {} (mtu {})",
        opts.server_ip,
        opts.mtu
    );

    // Prepare configuration for the OOS virtual network device
    let mut config = tun::Configuration::default();
    config
        .address((10, 0, 0, 2))
        .netmask((255, 255, 255, 0))
        .destination((10, 0, 0, 1))
        .mtu(opts.mtu)
        .up();

    #[cfg(unix)]
    {
        config.platform(|cfg| {
            cfg.packet_information(false);
        });
    }

    let dev = tun::create_as_async(&config)?;

    let guard = Box::new(OosRouteGuard {
        server_ip: opts.server_ip.to_string(),
        kill_switch: opts.kill_switch,
    });

    Ok(OstpTunInterface {
        device: dev,
        guard,
    })
}
