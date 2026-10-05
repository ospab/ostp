use std::sync::{Arc, RwLock};
use tokio::net::TcpStream;
use anyhow::Result;
use crate::outbound::{OutboundConfig, connect_target};
use crate::dns::DnsServer;
use crate::overnet::{Overnet, OvernetConfig, Route};
use crate::target_policy::TargetPolicy;

#[derive(Clone)]
pub struct Router {
    pub outbound_cfg: Arc<RwLock<Option<OutboundConfig>>>,
    pub bind_ip: Option<String>,
    pub dns_server: Arc<DnsServer>,
    /// Loopback listener answering DNS over TCP with `dns_server`: client
    /// connections to any :53 are sent here instead.
    pub dns_tcp: Arc<std::sync::OnceLock<std::net::SocketAddr>>,
    /// The `.ov` zone and the overnet exit; off unless configured, and even
    /// then `.ov` never goes to the internet.
    pub overnet: Arc<RwLock<Arc<Overnet>>>,
    /// `local_access` and the panel's port: see `target_policy`.
    pub local: Arc<RwLock<(bool, Option<u16>)>>,
    pub debug: bool,
}

impl Router {
    pub fn new(outbound_cfg: Option<OutboundConfig>, bind_ip: Option<String>, dns_server: Arc<DnsServer>, debug: bool) -> Self {
        Self {
            outbound_cfg: Arc::new(RwLock::new(outbound_cfg)),
            bind_ip,
            dns_server,
            dns_tcp: Arc::new(std::sync::OnceLock::new()),
            overnet: Arc::new(RwLock::new(Overnet::new(OvernetConfig::default()))),
            local: Arc::new(RwLock::new((false, None))),
            debug,
        }
    }

    /// `local_access` from the config and the port the panel listens on.
    pub fn set_local_policy(&self, local_access: bool, panel_port: Option<u16>) {
        *self.local.write().unwrap_or_else(|e| e.into_inner()) = (local_access, panel_port);
    }

    /// Where clients may connect: the internet, plus on this machine the
    /// panel and DNS (port 53 and the DNS-over-TCP listener), unless the
    /// owner opened everything with `local_access`.
    pub fn policy(&self) -> TargetPolicy {
        let (local_access, panel_port) = *self.local.read().unwrap_or_else(|e| e.into_inner());
        let mut loopback_ports = vec![53];
        loopback_ports.extend(panel_port);
        loopback_ports.extend(self.dns_tcp.get().map(|a| a.port()));
        TargetPolicy { local_access, loopback_ports }
    }

    pub fn overnet(&self) -> Arc<Overnet> {
        self.overnet.read().unwrap().clone()
    }

    /// TCP Target Routing
    pub async fn route_tcp(&self, target: &str, client: std::net::IpAddr) -> Result<TcpStream> {
        // `.ov` (by name, or by the fake address the DNS gave for it) goes to
        // the overnet gateway on this machine, or nowhere.
        let overnet = self.overnet();
        if let Route::Gateway(ov_target) = overnet.route(target)? {
            let gateway = overnet.config().gateway.clone();
            return crate::outbound::connect_via_socks5(&gateway, &ov_target, None, "", "")
                .await
                .map_err(|e| anyhow::anyhow!("overnet gateway {gateway}: {e}"));
        }
        let cfg = {
            let lock = self.outbound_cfg.read().unwrap();
            lock.clone()
        };
        // A connection by name goes through the server's DNS when filtering is
        // on: blocked names are refused, local names (rewrites) are used, the
        // rest is resolved (and logged) here. With the outbound proxy on, the
        // name is passed to it as is so its domain rules keep working, but a
        // blocked name is still refused.
        let target = match target.rsplit_once(':') {
            Some((host, port)) if host.parse::<std::net::IpAddr>().is_err() && !host.starts_with('[') => {
                let proxied = cfg.as_ref().is_some_and(|c| c.enabled);
                match self.dns_server.resolve_host(host, client).await {
                    Err(reason) => return Err(anyhow::anyhow!("{host}: {reason}")),
                    Ok(Some(ip)) if !proxied || self.dns_server.explain(host).outcome == ostp_dns::Outcome::Rewritten => {
                        // 10.1.0.1 is the server itself as clients see it.
                        let ip = if ip == std::net::IpAddr::from([10, 1, 0, 1]) { std::net::IpAddr::from([127, 0, 0, 1]) } else { ip };
                        std::net::SocketAddr::new(ip, port.parse().unwrap_or(0)).to_string()
                    }
                    Ok(_) => target.to_string(),
                }
            }
            _ => target.to_string(),
        };
        // The server itself (10.1.0.1 as clients see it, i.e. its loopback:
        // the panel, panel.ostp) is always reached directly. The outbound
        // proxy cannot reach this machine's loopback, and a socket bound to
        // bind_ip is not meant for it either.
        if let Ok(addr) = target.parse::<std::net::SocketAddr>() {
            let ip = if addr.ip() == std::net::IpAddr::from([10, 1, 0, 1]) { std::net::IpAddr::from([127, 0, 0, 1]) } else { addr.ip() };
            if ip.is_loopback() {
                let addr = std::net::SocketAddr::new(ip, addr.port());
                self.policy().check(addr)?;
                return match tokio::time::timeout(std::time::Duration::from_secs(10), TcpStream::connect(addr)).await {
                    Ok(r) => Ok(r?),
                    Err(_) => Err(anyhow::anyhow!("connect to {addr} timed out")),
                };
            }
        }
        connect_target(&target, cfg.as_ref(), self.bind_ip.as_deref(), self.debug, Some(&self.policy())).await
    }

    /// Whether a connection to `target` would be made by the upstream proxy
    /// (which then resolves the name on its own machine) rather than from
    /// this server.
    pub async fn resolves_remotely(&self, target: &str) -> bool {
        let cfg = self.outbound_cfg.read().unwrap().clone();
        match cfg {
            Some(c) if c.enabled => {
                crate::outbound::select_outbound_action(target, "tcp", &c, self.debug).await.0
                    == crate::outbound::OutboundAction::Proxy
            }
            _ => false,
        }
    }

    /// A connection for the overnet exit. The target is already checked (see
    /// `overnet::vet_exit_target`): unlike `route_tcp`, nothing here is
    /// special-cased to reach this machine.
    pub async fn route_tcp_exit(&self, target: &str) -> Result<TcpStream> {
        let cfg = self.outbound_cfg.read().unwrap().clone();
        if let Some((host, _)) = target.rsplit_once(':') {
            if host.parse::<std::net::IpAddr>().is_err() {
                // Only names the proxy resolves get here; the blocklists apply.
                let me = std::net::IpAddr::from([127, 0, 0, 1]);
                if let Err(reason) = self.dns_server.resolve_host(host, me).await {
                    return Err(anyhow::anyhow!("{host}: {reason}"));
                }
            }
        }
        // The public internet only, whatever `local_access` says.
        connect_target(target, cfg.as_ref(), self.bind_ip.as_deref(), self.debug, Some(&TargetPolicy::public_only())).await
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
            policy: self.policy(),
            proxy,
            cfg,
            debug: self.debug,
        }
    }
    
    /// Unified DNS Routing and Resolution (AdBlock / Custom Domains / DoH)
    pub async fn route_dns(&self, client_ip: std::net::IpAddr, payload: &[u8]) -> Option<Vec<u8>> {
        self.dns_server.handle(payload, client_ip).await
    }
}

pub struct UdpSessionRouter {
    direct: Arc<tokio::net::UdpSocket>,
    policy: TargetPolicy,
    proxy: Option<Arc<crate::outbound::UdpProxySocket>>,
    cfg: Option<OutboundConfig>,
    debug: bool,
}

impl UdpSessionRouter {
    pub async fn send_to(&self, data: &[u8], target: &str) -> Result<usize> {
        if target.rsplit_once(':').is_some_and(|(h, _)| crate::overnet::is_ov(h)) {
            return Err(anyhow::anyhow!("{target}: overnet carries TCP only"));
        }
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
        // Resolved and checked here rather than by send_to, so a name that
        // points at this machine or a private network is refused too.
        let addr = match target.parse::<std::net::SocketAddr>() {
            Ok(a) => a,
            Err(_) => {
                let mut addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host(target).await?.collect();
                addrs.sort_by_key(|a| a.is_ipv6());
                addrs.into_iter().next().ok_or_else(|| anyhow::anyhow!("no addresses for {target}"))?
            }
        };
        self.policy.check(addr)?;
        self.direct.send_to(data, addr).await.map_err(Into::into)
    }

    pub fn get_proxy_sock(&self) -> Option<Arc<crate::outbound::UdpProxySocket>> {
        self.proxy.clone()
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::OutboundAction;

    /// The panel through the tunnel: with every connection sent to an
    /// outbound proxy (a dead one here) and a bind_ip set, the server's own
    /// services are still reached.
    #[tokio::test]
    async fn the_server_itself_bypasses_outbound_and_bind_ip() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let _ = listener.accept().await;
            }
        });
        let outbound = OutboundConfig {
            enabled: true,
            protocol: "socks5".into(),
            address: "127.0.0.1".into(),
            port: 1,
            username: String::new(),
            password: String::new(),
            rules: Vec::new(),
            default_action: OutboundAction::Proxy,
        };
        let router = Router::new(Some(outbound), Some("192.0.2.1".into()), DnsServer::new(Default::default(), None), false);
        router.set_local_policy(false, Some(port));
        let me: std::net::IpAddr = "203.0.113.5".parse().unwrap();
        assert!(router.route_tcp(&format!("127.0.0.1:{port}"), me).await.is_ok());
        assert!(router.route_tcp(&format!("10.1.0.1:{port}"), me).await.is_ok());
        // Other services on this machine are closed to clients.
        let other = port.wrapping_add(1);
        let e = router.route_tcp(&format!("127.0.0.1:{other}"), me).await.unwrap_err().to_string();
        assert!(e.contains("server itself"), "{e}");
        router.set_local_policy(true, Some(port));
        assert!(!router.route_tcp(&format!("127.0.0.1:{other}"), me).await.is_err_and(|e| e.to_string().contains("server itself")));
        // Anything else still goes where the rules say: the dead proxy.
        assert!(router.route_tcp("198.51.100.7:80", me).await.is_err());
    }
}
