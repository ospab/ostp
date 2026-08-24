use std::sync::{Arc, RwLock};
use tokio::net::TcpStream;
use anyhow::Result;
use crate::outbound::{OutboundConfig, connect_target};
use crate::dns::DnsServer;

#[derive(Clone)]
pub struct Router {
    pub outbound_cfg: Arc<RwLock<Option<OutboundConfig>>>,
    pub bind_ip: Option<String>,
    pub dns_server: Arc<DnsServer>,
    pub debug: bool,
}

impl Router {
    pub fn new(outbound_cfg: Option<OutboundConfig>, bind_ip: Option<String>, dns_server: Arc<DnsServer>, debug: bool) -> Self {
        Self {
            outbound_cfg: Arc::new(RwLock::new(outbound_cfg)),
            bind_ip,
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
        connect_target(target, cfg.as_ref(), self.bind_ip.as_deref(), self.debug).await
    }

    /// UDP Target Routing
    pub async fn route_udp(&self, target: &str, server_udp: std::sync::Arc<tokio::net::UdpSocket>) -> Result<crate::outbound::UdpProxySocket> {
        let cfg = {
            let lock = self.outbound_cfg.read().unwrap();
            lock.clone()
        };
        crate::outbound::connect_udp_target(target, cfg.as_ref(), self.bind_ip.as_deref(), self.debug, server_udp).await
    }
    
    /// Establish a UDP session router that can dynamically route packets
    pub async fn route_udp_associate(&self, server_udp: std::sync::Arc<tokio::net::UdpSocket>) -> UdpSessionRouter {
        let cfg = {
            let lock = self.outbound_cfg.read().unwrap();
            lock.clone()
        };
        
        let mut proxy = None;
        if let Some(ref c) = cfg {
            if c.enabled {
                if c.protocol == "socks5" {
                    let proxy_addr = format!("{}:{}", c.address, c.port);
                    match crate::outbound::connect_udp_via_socks5(&proxy_addr, server_udp.clone(), self.bind_ip.as_deref(), &c.username, &c.password).await {
                        Ok(p) => proxy = Some(Arc::new(p)),
                        // Warn unconditionally, not only under `debug`. Every UDP
                        // flow the rules want proxied is now dropped instead of
                        // sent, so an operator who cannot see this has a session
                        // where TCP works and UDP silently does not.
                        Err(e) => tracing::warn!(
                            "SOCKS5 UDP ASSOCIATE to {proxy_addr} failed: {e}. UDP that the \
                             outbound rules route through the proxy will be DROPPED (it is not \
                             sent directly, which would expose this server's address)."
                        ),
                    }
                } else {
                    tracing::warn!(
                        "Upstream proxy protocol is '{}', which cannot carry UDP. UDP matching \
                         a Proxy rule will be DROPPED. Use a socks5 upstream for UDP, or add an \
                         explicit udp rule with action \"direct\" or \"block\" to make the \
                         intent explicit.",
                        c.protocol
                    );
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
                let (action, _rule_src) = crate::outbound::select_outbound_action(target, "udp", cfg, self.debug).await;
                if action == crate::outbound::OutboundAction::Block {
                    return Err(anyhow::anyhow!("blocked by outbound udp rule: {}", target));
                }
                if action == crate::outbound::OutboundAction::Proxy {
                    return match &self.proxy {
                        Some(p) => p.send_to(data, target).await,
                        // FAIL CLOSED. This used to fall through to the direct
                        // socket, so whenever the UDP proxy was unavailable —
                        // the SOCKS5 UDP ASSOCIATE failed, or the upstream is an
                        // HTTP proxy, which cannot carry UDP at all — every UDP
                        // datagram silently egressed from the server's own
                        // address while TCP still went through the proxy. The
                        // session then had two different exit IPs, which is what
                        // Google flags and why YouTube (QUIC, i.e. UDP/443)
                        // geolocated to the server instead of the proxy exit.
                        //
                        // A rule that says "proxy" must never be satisfied by
                        // sending in the clear: a dropped datagram is visible and
                        // debuggable, a deanonymising leak is neither.
                        None => Err(anyhow::anyhow!(
                            "outbound rule requires the proxy for UDP to {target}, but no UDP \
                             proxy is available (SOCKS5 UDP ASSOCIATE failed, or the upstream \
                             is an HTTP proxy, which cannot carry UDP) - dropping rather than \
                             leaking the server's own address"
                        )),
                    };
                }
            }
        }
        self.direct.send_to(data, target).await.map_err(Into::into)
    }

    pub fn get_proxy_sock(&self) -> Option<Arc<crate::outbound::UdpProxySocket>> {
        self.proxy.clone()
    }
}

