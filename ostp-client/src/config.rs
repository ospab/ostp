use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Client runtime configuration.
/// Constructed by the main binary from the unified `config.json`,
/// then passed into `runner::run_client`. All I/O happens in the
/// binary layer — this crate only owns the plain data structures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub mode: String,
    #[serde(default)]
    pub debug: bool,
    pub ostp: OstpConfig,
    pub local_proxy: LocalProxyConfig,
    pub reality: RealityConfig,
    #[serde(default)]
    pub transport: TransportConfig,
    #[serde(default)]
    pub exclusions: ExclusionConfig,
    #[serde(default)]
    pub multiplex: MultiplexConfig,
    pub dns_server: Option<String>,
    #[serde(default = "default_tun_stack")]
    pub tun_stack: String,
}

fn default_tun_stack() -> String { "system".to_string() }

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExclusionConfig {
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub ips: Vec<String>,
    #[serde(default)]
    pub processes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiplexConfig {
    pub enabled: bool,
    pub sessions: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OstpConfig {
    pub server_addr: String,
    pub local_bind_addr: String,
    #[serde(alias = "auth_token")]
    pub access_key: String,
    pub handshake_timeout_ms: u64,
    pub io_timeout_ms: u64,
    #[serde(default = "default_mtu")]
    pub mtu: usize,
    #[serde(default = "default_keepalive")]
    pub keepalive_interval_sec: u64,
}

fn default_keepalive() -> u64 { 5 }

fn default_mtu() -> usize { 1350 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalProxyConfig {
    pub bind_addr: String,
    pub connect_timeout_ms: u64,
}

/// Transport layer configuration.
/// `mode` = "udp" (default) or "uot" (UDP over TCP with xHTTP stealth).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    /// "udp" or "uot"
    #[serde(default = "default_transport_mode")]
    pub mode: String,
    /// TLS SNI and HTTP Host for stealth routing
    #[serde(default)]
    pub stealth_sni: String,
    /// TCP Port for the stealth connection
    #[serde(default = "default_stealth_port")]
    pub stealth_port: u16,
    /// Enable strict RFC 6455 WebSocket framing
    #[serde(default)]
    pub wss: bool,
}

fn default_transport_mode() -> String { "udp".to_string() }
fn default_stealth_port() -> u16 { 443 }

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            mode: default_transport_mode(),
            stealth_sni: String::new(),
            stealth_port: default_stealth_port(),
            wss: false,
        }
    }
}


#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RealityConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub sni: String,
    #[serde(default)]
    pub fp: String,
    #[serde(default)]
    pub pbk: String,
    #[serde(default)]
    pub sid: String,
    #[serde(default)]
    pub spx: String,
}


impl Default for OstpConfig {
    fn default() -> Self {
        Self {
            server_addr: "127.0.0.1:50000".to_string(),
            local_bind_addr: "0.0.0.0:0".to_string(),
            access_key: String::new(),
            handshake_timeout_ms: 5000,
            io_timeout_ms: 2500,
            mtu: default_mtu(),
            keepalive_interval_sec: default_keepalive(),
        }
    }
}

impl Default for LocalProxyConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:1088".to_string(),
            connect_timeout_ms: 15000,
        }
    }
}


impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            mode: "proxy".to_string(),
            debug: false,
            ostp: OstpConfig::default(),
            local_proxy: LocalProxyConfig::default(),
            reality: RealityConfig::default(),
            transport: TransportConfig::default(),
            exclusions: ExclusionConfig::default(),
            multiplex: MultiplexConfig::default(),
            dns_server: None,
            tun_stack: "system".to_string(),
        }
    }
}

impl Default for MultiplexConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            sessions: 1,
        }
    }
}

/// Unified shape of `config.json` as seen by the client.
/// Used only for hot-reloading (`BridgeCommand::ReloadConfig`).
#[derive(Debug, Deserialize)]
struct RawUnifiedConfig {
    #[allow(dead_code)]
    mode: String,
    debug: Option<bool>,
    server: Option<String>,
    access_key: Option<String>,
    mtu: Option<usize>,
    socks5_bind: Option<String>,
    tun: Option<RawTunSection>,
    exclude: Option<RawExcludeSection>,
    mux: Option<RawMuxSection>,
    reality: Option<RawRealitySection>,
    transport: Option<RawTransportSection>,
}

#[derive(Debug, Deserialize)]
struct RawTransportSection {
    mode: Option<String>,
    stealth_sni: Option<String>,
    stealth_port: Option<u16>,
    wss: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct RawTunSection {
    enable: Option<bool>,
    dns: Option<String>,
    stack: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawExcludeSection {
    domains: Option<Vec<String>>,
    ips: Option<Vec<String>>,
    processes: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct RawMuxSection {
    enabled: Option<bool>,
    sessions: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct RawRealitySection {
    enabled: Option<bool>,
    sni: Option<String>,
    fp: Option<String>,
    pbk: Option<String>,
    sid: Option<String>,
    spx: Option<String>,
}

impl ClientConfig {
    /// Hot-reload from `config.json` placed next to the running binary.
    /// Returns a new `ClientConfig` built from the unified JSON format.
    pub fn reload_from_json_near_binary() -> Result<Self> {
        let exe = std::env::current_exe().context("cannot resolve binary path")?;
        let dir = exe.parent().context("cannot resolve binary directory")?;
        let path = dir.join("config.json");

        let raw = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let mut stripped = json_comments::StripComments::new(raw.as_bytes());
        let raw: RawUnifiedConfig = serde_json::from_reader(&mut stripped)
            .with_context(|| format!("failed to parse {}", path.display()))?;

        let is_tun = raw.tun.as_ref().and_then(|t| t.enable).unwrap_or(false);
        let server = raw.server.unwrap_or_else(|| "127.0.0.1:50000".to_string());
        let key = raw.access_key.unwrap_or_default();
        let mtu = raw.mtu.unwrap_or(default_mtu());
        let socks5 = raw.socks5_bind.unwrap_or_else(|| "127.0.0.1:1088".to_string());
        let exclusions = raw.exclude.unwrap_or(RawExcludeSection {
            domains: None,
            ips: None,
            processes: None,
        });
        let mux = raw.mux.unwrap_or(RawMuxSection {
            enabled: None,
            sessions: None,
        });

        Ok(ClientConfig {
            mode: if is_tun { "tun".to_string() } else { "proxy".to_string() },
            debug: raw.debug.unwrap_or(false),
            ostp: OstpConfig {
                server_addr: server,
                local_bind_addr: "0.0.0.0:0".to_string(),
                access_key: key,
                handshake_timeout_ms: 5000,
                io_timeout_ms: 2500,
                mtu,
                keepalive_interval_sec: default_keepalive(),
            },
            local_proxy: LocalProxyConfig {
                bind_addr: socks5,
                connect_timeout_ms: 15000,
            },
            reality: RealityConfig {
                enabled: raw.reality.as_ref().and_then(|t| t.enabled).unwrap_or(false),
                sni: raw.reality.as_ref().and_then(|t| t.sni.clone()).unwrap_or_default(),
                fp: raw.reality.as_ref().and_then(|t| t.fp.clone()).unwrap_or_default(),
                pbk: raw.reality.as_ref().and_then(|t| t.pbk.clone()).unwrap_or_default(),
                sid: raw.reality.as_ref().and_then(|t| t.sid.clone()).unwrap_or_default(),
                spx: raw.reality.as_ref().and_then(|t| t.spx.clone()).unwrap_or_default(),
            },
            transport: TransportConfig {
                mode: raw.transport.as_ref().and_then(|t| t.mode.clone()).unwrap_or_else(|| "udp".to_string()),
                stealth_sni: raw.transport.as_ref().and_then(|t| t.stealth_sni.clone()).unwrap_or_else(|| "microsoft.com".to_string()),
                stealth_port: raw.transport.as_ref().and_then(|t| t.stealth_port).unwrap_or(443),
                wss: raw.transport.as_ref().and_then(|t| t.wss).unwrap_or(false),
            },
            exclusions: ExclusionConfig {
                domains: exclusions.domains.unwrap_or_default(),
                ips: exclusions.ips.unwrap_or_default(),
                processes: exclusions.processes.unwrap_or_default(),
            },
            multiplex: MultiplexConfig {
                enabled: mux.enabled.unwrap_or(false),
                sessions: mux.sessions.unwrap_or(1),
            },
            dns_server: raw.tun.as_ref().and_then(|t| t.dns.clone()),
            tun_stack: raw.tun.as_ref().and_then(|t| t.stack.clone()).unwrap_or_else(|| "system".to_string()),
        })

    }
}
