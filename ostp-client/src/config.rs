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
    pub turn: TurnConfig,
    #[serde(default)]
    pub exclusions: ExclusionConfig,
    #[serde(default)]
    pub multiplex: MultiplexConfig,
    pub dns_server: Option<String>,
}

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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalProxyConfig {
    pub bind_addr: String,
    pub connect_timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TurnConfig {
    pub enabled: bool,
    pub server_addr: String,
    pub username: String,
    pub access_key: String,
}

impl Default for OstpConfig {
    fn default() -> Self {
        Self {
            server_addr: "127.0.0.1:50000".to_string(),
            local_bind_addr: "0.0.0.0:0".to_string(),
            access_key: String::new(),
            handshake_timeout_ms: 5000,
            io_timeout_ms: 2500,
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

impl Default for TurnConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            server_addr: String::new(),
            username: String::new(),
            access_key: String::new(),
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
            turn: TurnConfig::default(),
            exclusions: ExclusionConfig::default(),
            multiplex: MultiplexConfig::default(),
            dns_server: None,
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
    socks5_bind: Option<String>,
    tun: Option<RawTunSection>,
    exclude: Option<RawExcludeSection>,
    mux: Option<RawMuxSection>,
    turn: Option<RawTurnSection>,
}

#[derive(Debug, Deserialize)]
struct RawTunSection {
    enable: Option<bool>,
    dns: Option<String>,
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
struct RawTurnSection {
    enabled: Option<bool>,
    server_addr: Option<String>,
    username: Option<String>,
    access_key: Option<String>,
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
            },
            local_proxy: LocalProxyConfig {
                bind_addr: socks5,
                connect_timeout_ms: 15000,
            },
            turn: match raw.turn {
                Some(t) => TurnConfig {
                    enabled: t.enabled.unwrap_or(false),
                    server_addr: t.server_addr.unwrap_or_default(),
                    username: t.username.unwrap_or_default(),
                    access_key: t.access_key.unwrap_or_default(),
                },
                None => TurnConfig::default(),
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
        })
    }
}
