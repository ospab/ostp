//! What the server process runs when `warp.enabled`: the tunnel, the local
//! SOCKS5 proxy and a status file for `ostp warp status`.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::config::WarpConfig;
use crate::store::{self, WarpState};
use crate::tunnel::{reserved_from_client_id, Tunnel, TunnelConfig, TunnelStatus};

pub const STATUS_FILE: &str = "warp.status.json";
/// A status file older than this is the leftover of a process that is gone.
pub const STATUS_FRESH: Duration = Duration::from_secs(30);

pub struct Running {
    pub tunnel: Tunnel,
    pub listen: SocketAddr,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Running {
    pub fn stop(&self) {
        for t in &self.tasks {
            t.abort();
        }
        self.tunnel.shutdown();
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop();
    }
}

/// `host:port` or `ip:port` as the tunnel's UDP peer. The registered IPv4
/// address (port 0 there means "the port of the host entry") is used before
/// the host name, so that starting does not depend on DNS; `override_` (the
/// config's `warp.endpoint`) wins over both.
pub fn endpoint_candidates(override_: &str, st: &WarpState) -> Vec<String> {
    if !override_.is_empty() {
        return vec![override_.to_string()];
    }
    let mut v = Vec::new();
    let host_port = st.endpoint_host.rsplit_once(':').and_then(|(_, p)| p.parse::<u16>().ok()).filter(|p| *p != 0).unwrap_or(2408);
    if let Some(v4) = &st.endpoint_v4 {
        if let Some((ip, port)) = v4.rsplit_once(':') {
            let port = port.parse::<u16>().ok().filter(|p| *p != 0).unwrap_or(host_port);
            v.push(format!("{ip}:{port}"));
        }
    }
    v.push(st.endpoint_host.clone());
    v
}

async fn resolve_endpoint(cands: &[String]) -> Result<SocketAddr> {
    let mut last = anyhow!("no endpoint to use");
    for c in cands {
        match tokio::net::lookup_host(c.as_str()).await {
            Ok(it) => {
                let mut addrs: Vec<SocketAddr> = it.collect();
                addrs.sort_by_key(|a| a.is_ipv6());
                if let Some(a) = addrs.into_iter().next() {
                    return Ok(a);
                }
            }
            Err(e) => last = anyhow!("cannot resolve the WARP endpoint {c}: {e}"),
        }
    }
    Err(last)
}

pub fn tunnel_config(st: &WarpState, endpoint: SocketAddr) -> Result<TunnelConfig> {
    let v4: std::net::Ipv4Addr = st.address_v4.parse().map_err(|_| anyhow!("warp.json: \"{}\" is not an IPv4 address", st.address_v4))?;
    let mut tc = TunnelConfig::new(st.private_key_bytes()?, st.peer_public_bytes()?, endpoint, v4);
    tc.address_v6 = match st.address_v6.as_deref() {
        Some(a) => Some(a.parse().map_err(|_| anyhow!("warp.json: \"{a}\" is not an IPv6 address"))?),
        None => None,
    };
    if let Some(id) = &st.client_id {
        if let Some(r) = reserved_from_client_id(id)? {
            tc.reserved = r;
        }
    }
    Ok(tc)
}

/// Starts the tunnel and the proxy. Errors say what to run.
pub async fn start(cfg: &WarpConfig, config_path: &Path) -> Result<Running> {
    cfg.validate()?;
    let listen = cfg.listen_addr()?;
    let sp = store::path_for(config_path);
    let st = store::load(&sp)?.ok_or_else(|| anyhow!("WARP is not registered ({} does not exist): run `ostp warp register --accept-terms`", sp.display()))?;
    let endpoint = resolve_endpoint(&endpoint_candidates(&cfg.endpoint, &st)).await?;
    let tunnel = Tunnel::start(tunnel_config(&st, endpoint)?).await?;
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("cannot listen on {listen} for the WARP proxy (is something else using the port?)"))?;
    let mut tasks = Vec::new();
    tasks.push(tokio::spawn(crate::socks::serve(listener, tunnel.clone())));
    let status_path = config_path.parent().map(|d| d.join(STATUS_FILE)).unwrap_or_else(|| PathBuf::from(STATUS_FILE));
    {
        let (tunnel, mode, status_path) = (tunnel.clone(), cfg.mode.as_str().to_string(), status_path.clone());
        tasks.push(tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(5));
            loop {
                tick.tick().await;
                let f = StatusFile::now(&tunnel.status(), listen, &mode);
                if let Err(e) = write_status(&status_path, &f) {
                    tracing::debug!("warp: status file: {e}");
                }
            }
        }));
    }
    tracing::info!("warp: proxy on {listen}, peer {endpoint}, mode {}", cfg.mode.as_str());
    Ok(Running { tunnel, listen, tasks })
}

/// What the running process says about itself, for `ostp warp status`.
/// Holds no secrets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusFile {
    pub pid: u32,
    pub updated_unix: u64,
    pub up: bool,
    pub last_handshake_secs: Option<u64>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub endpoint: Option<String>,
    pub listen: String,
    pub mode: String,
    pub tcp_connections: usize,
    pub udp_flows: usize,
    pub udp_too_big: u64,
}

impl StatusFile {
    pub fn now(s: &TunnelStatus, listen: SocketAddr, mode: &str) -> Self {
        Self {
            pid: std::process::id(),
            updated_unix: SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
            up: s.up,
            last_handshake_secs: s.last_handshake_secs,
            tx_bytes: s.tx_bytes,
            rx_bytes: s.rx_bytes,
            endpoint: s.endpoint.map(|e| e.to_string()),
            listen: listen.to_string(),
            mode: mode.to_string(),
            tcp_connections: s.tcp_connections,
            udp_flows: s.udp_flows,
            udp_too_big: s.udp_too_big,
        }
    }

    /// Whether the process that wrote it was alive a moment ago.
    pub fn is_fresh(&self) -> bool {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        now.saturating_sub(self.updated_unix) <= STATUS_FRESH.as_secs()
    }
}

pub fn write_status(path: &Path, f: &StatusFile) -> Result<()> {
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec(f)?)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

pub fn read_status(config_path: &Path) -> Option<StatusFile> {
    let p = config_path.parent().map(|d| d.join(STATUS_FILE))?;
    serde_json::from_slice(&std::fs::read(p).ok()?).ok()
}

/// Whether a TCP port answers (used by `status` to tell "running" from "not").
pub fn port_answers(addr: SocketAddr) -> bool {
    std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::Device;

    fn state(endpoint_v4: Option<&str>, host: &str) -> WarpState {
        let dev: Device = serde_json::from_str(
            r#"{"id":"d","token":"t","config":{"client_id":"AQID","interface":{"addresses":{"v4":"172.16.0.2","v6":"2606:4700:110::2"}},"peers":[{"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","endpoint":{"host":"engage.cloudflareclient.com:2408"}}]}}"#,
        )
        .unwrap();
        let mut s = WarpState::from_device(store::encode_key(&[1u8; 32]), &dev, "t".into()).unwrap();
        s.endpoint_v4 = endpoint_v4.map(String::from);
        s.endpoint_host = host.to_string();
        s
    }

    #[test]
    fn endpoint_prefers_the_override_then_the_registered_ip_then_the_name() {
        let s = state(Some("162.159.192.1:0"), "engage.cloudflareclient.com:2408");
        assert_eq!(endpoint_candidates("1.2.3.4:500", &s), vec!["1.2.3.4:500"]);
        assert_eq!(endpoint_candidates("", &s), vec!["162.159.192.1:2408", "engage.cloudflareclient.com:2408"]);
        let s = state(Some("162.159.192.1:500"), "engage.cloudflareclient.com:2408");
        assert_eq!(endpoint_candidates("", &s)[0], "162.159.192.1:500", "a port the answer gives is kept");
        let s = state(None, "engage.cloudflareclient.com:4500");
        assert_eq!(endpoint_candidates("", &s), vec!["engage.cloudflareclient.com:4500"]);
    }

    #[test]
    fn tunnel_config_takes_addresses_keys_and_reserved_from_the_state() {
        let s = state(None, "h:2408");
        let tc = tunnel_config(&s, "127.0.0.1:2408".parse().unwrap()).unwrap();
        assert_eq!(tc.address_v4.to_string(), "172.16.0.2");
        assert_eq!(tc.address_v6.unwrap().to_string(), "2606:4700:110::2");
        assert_eq!(tc.reserved, [1, 2, 3]);
        assert_eq!(tc.private_key, [1u8; 32]);
        assert_eq!(tc.mtu, 1280);
        assert_eq!(tc.keepalive, Some(25));
        let mut bad = s.clone();
        bad.address_v4 = "not-an-ip".into();
        assert!(tunnel_config(&bad, "127.0.0.1:2408".parse().unwrap()).is_err());
    }

    #[test]
    fn status_file_round_trips_and_goes_stale() {
        let dir = std::env::temp_dir().join(format!("ostp-warp-status-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg_path = dir.join("config.json");
        let f = StatusFile::now(&TunnelStatus { up: true, last_handshake_secs: Some(3), ..Default::default() }, "127.0.0.1:40000".parse().unwrap(), "all");
        write_status(&dir.join(STATUS_FILE), &f).unwrap();
        let back = read_status(&cfg_path).unwrap();
        assert!(back.up && back.is_fresh());
        assert_eq!(back.last_handshake_secs, Some(3));
        let mut old = back;
        old.updated_unix -= 3600;
        assert!(!old.is_fresh());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
