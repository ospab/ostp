use std::sync::{Arc, RwLock};
use tokio::net::TcpStream;
use anyhow::Result;
use crate::outbound::{OutboundConfig, connect_target};
use crate::dns::DnsServer;

#[derive(Clone)]
pub struct Router {
    pub outbound_cfg: Arc<RwLock<Option<OutboundConfig>>>,
    pub dns_server: Arc<DnsServer>,
    pub debug: bool,
}

impl Router {
    pub fn new(outbound_cfg: Option<OutboundConfig>, dns_server: Arc<DnsServer>, debug: bool) -> Self {
        Self {
            outbound_cfg: Arc::new(RwLock::new(outbound_cfg)),
            dns_server,
            debug,
        }
    }

    /// TCP Target Routing
    pub async fn route_tcp(&self, target: &str) -> Result<TcpStream> {
        let cfg = {
            let lock = self.outbound_cfg.read().unwrap();
            lock.clone()
        };
        connect_target(target, cfg.as_ref(), self.debug).await
    }

    /// UDP Target Routing
    pub async fn route_udp(&self, target: &str, server_udp: std::sync::Arc<tokio::net::UdpSocket>) -> Result<crate::outbound::UdpProxySocket> {
        let cfg = {
            let lock = self.outbound_cfg.read().unwrap();
            lock.clone()
        };
        crate::outbound::connect_udp_target(target, cfg.as_ref(), self.debug, server_udp).await
    }
    
    /// Establish a UDP session router that can dynamically route packets
    pub async fn route_udp_associate(&self, server_udp: std::sync::Arc<tokio::net::UdpSocket>) -> UdpSessionRouter {
        let cfg = {
            let lock = self.outbound_cfg.read().unwrap();
            lock.clone()
        };
        
        let mut proxy = None;
        if let Some(ref c) = cfg {
            if c.enabled && c.protocol == "socks5" {
                let proxy_addr = format!("{}:{}", c.address, c.port);
                if let Ok(p) = crate::outbound::connect_udp_via_socks5(&proxy_addr, server_udp.clone()).await {
                    proxy = Some(Arc::new(p));
                } else if self.debug {
                    tracing::warn!("Failed to establish SOCKS5 UDP Associate");
                }
            }
        }
        
        UdpSessionRouter {
            direct: server_udp,
            proxy,
            cfg,
            debug: self.debug,
        }
    }
    
    /// Unified DNS Routing and Resolution (AdBlock / Custom Domains / DoH)
    pub async fn route_dns(&self, client_ip: std::net::IpAddr, payload: &[u8]) -> Option<Vec<u8>> {
        self.dns_server.resolve(payload, client_ip).await
    }
}

pub struct UdpSessionRouter {
    direct: Arc<tokio::net::UdpSocket>,
    proxy: Option<Arc<crate::outbound::UdpProxySocket>>,
    cfg: Option<OutboundConfig>,
    debug: bool,
}

impl UdpSessionRouter {
    pub async fn send_to(&self, data: &[u8], target: &str) -> Result<usize> {
        if let Some(cfg) = &self.cfg {
            if cfg.enabled {
                let action = crate::outbound::select_outbound_action(target, "udp", cfg, self.debug).await;
                if action == crate::outbound::OutboundAction::Block {
                    return Err(anyhow::anyhow!("blocked by outbound udp rule: {}", target));
                }
                if action == crate::outbound::OutboundAction::Proxy {
                    if let Some(p) = &self.proxy {
                        return p.send_to(data, target).await;
                    }
                }
            }
        }
        self.direct.send_to(data, target).await.map_err(Into::into)
    }

    pub fn get_proxy_sock(&self) -> Option<Arc<crate::outbound::UdpProxySocket>> {
        self.proxy.clone()
    }
}

