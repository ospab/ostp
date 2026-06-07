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
            lock.clone() // Clone config to avoid holding lock across await point
        };
        connect_target(target, cfg.as_ref(), self.debug).await
    }
    
    /// Unified DNS Routing and Resolution (AdBlock / Custom Domains / DoH)
    pub async fn route_dns(&self, client_ip: std::net::IpAddr, payload: &[u8]) -> Option<Vec<u8>> {
        self.dns_server.resolve(payload, client_ip).await
    }
}
