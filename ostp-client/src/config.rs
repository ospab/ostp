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
    #[serde(default)]
    pub transport: TransportConfig,
    #[serde(default)]
    pub exclusions: ExclusionConfig,
    #[serde(default)]
    pub multiplex: MultiplexConfig,
    pub dns_server: Option<String>,
    #[serde(default = "default_tun_stack")]
    pub tun_stack: String,
    #[serde(default)]
    pub kill_switch: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gui: Option<serde_json::Value>,
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

fn default_mtu() -> usize { 1140 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalProxyConfig {
    pub bind_addr: String,
    pub connect_timeout_ms: u64,
}

/// Transport layer configuration.
/// `mode` = "udp" (default) or "uot" (UDP over TCP, no protocol mimicry —
/// zapret-like: no recognizable header at all, not a fake TLS/HTTP shell).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    /// "udp" or "uot"
    #[serde(default = "default_transport_mode")]
    pub mode: String,
    /// Split the first UoT/TCP packet (handshake) into tiny TCP segments to
    /// break DPI that inspects the first packet. UoT/TCP only; ignored for UDP.
    pub tcp_fragmentation: bool,
    /// TCP chunk size (bytes)
    #[serde(default = "default_frag_chunk")]
    pub frag_chunk: usize,
    /// TCP sleep duration between chunks (ms)
    #[serde(default = "default_frag_sleep")]
    pub frag_sleep: u64,
    /// [min, max] junk packet count
    #[serde(default = "default_junk_count")]
    pub junk_pc: [usize; 2],
    /// [min, max] junk packet size in bytes
    #[serde(default = "default_junk_size")]
    pub junk_ps: [usize; 2],
    /// TTL-desync (UDP only): before the handshake, send decoy datagrams with a
    /// lowered IP TTL so they reach an on-path DPI box but expire before the
    /// server, poisoning the box's classification of the flow. Off by default —
    /// it needs the TTL calibrated to the network, and the wrong value is inert.
    #[serde(default)]
    pub ttl_desync: bool,
    /// TTL the decoy datagrams are sent with. Set it to one or two hops past the
    /// injector distance the prober reports, so decoys die just beyond the DPI.
    #[serde(default = "default_ttl_desync_ttl")]
    pub ttl_desync_ttl: u8,
    /// How many decoy datagrams to send per handshake.
    #[serde(default = "default_ttl_desync_count")]
    pub ttl_desync_count: u8,
    /// Auto-calibrate the decoy TTL by measuring the hop distance to the server
    /// (see ttl_probe). On by default, so turning desync on "just works"; the
    /// measured value overrides ttl_desync_ttl. Turn off to pin ttl_desync_ttl.
    #[serde(default = "default_true")]
    pub ttl_desync_auto: bool,
}

fn default_true() -> bool { true }

fn default_transport_mode() -> String { "udp".to_string() }
fn default_frag_chunk() -> usize { 2 }
fn default_frag_sleep() -> u64 { 2 }
fn default_junk_count() -> [usize; 2] { [2, 5] }
fn default_junk_size() -> [usize; 2] { [100, 1000] }
fn default_ttl_desync_ttl() -> u8 { 8 }
fn default_ttl_desync_count() -> u8 { 2 }

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            mode: default_transport_mode(),
            tcp_fragmentation: false,
            frag_chunk: default_frag_chunk(),
            frag_sleep: default_frag_sleep(),
            junk_pc: default_junk_count(),
            junk_ps: default_junk_size(),
            ttl_desync: false,
            ttl_desync_ttl: default_ttl_desync_ttl(),
            ttl_desync_count: default_ttl_desync_count(),
            ttl_desync_auto: true,
        }
    }
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
            transport: TransportConfig::default(),
            exclusions: ExclusionConfig::default(),
            multiplex: MultiplexConfig::default(),
            dns_server: None,
            tun_stack: "system".to_string(),
            kill_switch: false,
            gui: None,
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
    transport: Option<RawTransportSection>,
    gui: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct RawTransportSection {
    mode: Option<String>,
    tcp_fragmentation: Option<bool>,
    frag_chunk: Option<usize>,
    frag_sleep: Option<u64>,
    junk_pc: Option<[usize; 2]>,
    junk_ps: Option<[usize; 2]>,
    ttl_desync: Option<bool>,
    ttl_desync_ttl: Option<u8>,
    ttl_desync_count: Option<u8>,
    ttl_desync_auto: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct RawTunSection {
    enable: Option<bool>,
    dns: Option<String>,
    stack: Option<String>,
    kill_switch: Option<bool>,
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
            transport: TransportConfig {
                mode: raw.transport.as_ref().and_then(|t| t.mode.clone()).unwrap_or_else(default_transport_mode),
                tcp_fragmentation: raw.transport.as_ref().and_then(|t| t.tcp_fragmentation).unwrap_or(false),
                frag_chunk: raw.transport.as_ref().and_then(|t| t.frag_chunk).unwrap_or_else(default_frag_chunk),
                frag_sleep: raw.transport.as_ref().and_then(|t| t.frag_sleep).unwrap_or_else(default_frag_sleep),
                junk_pc: raw.transport.as_ref().and_then(|t| t.junk_pc).unwrap_or_else(default_junk_count),
                junk_ps: raw.transport.as_ref().and_then(|t| t.junk_ps).unwrap_or_else(default_junk_size),
                ttl_desync: raw.transport.as_ref().and_then(|t| t.ttl_desync).unwrap_or(false),
                ttl_desync_ttl: raw.transport.as_ref().and_then(|t| t.ttl_desync_ttl).unwrap_or_else(default_ttl_desync_ttl),
                ttl_desync_count: raw.transport.as_ref().and_then(|t| t.ttl_desync_count).unwrap_or_else(default_ttl_desync_count),
                ttl_desync_auto: raw.transport.as_ref().and_then(|t| t.ttl_desync_auto).unwrap_or(true),
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
            kill_switch: raw.tun.as_ref().and_then(|t| t.kill_switch).unwrap_or(false),
            gui: raw.gui,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════
// On-disk config.json shapes — client, server, and relay.
//
// This is the ONE place these are defined. They used to be declared locally
// inside ostp/src/main.rs (the CLI binary) with no other consumer able to
// see them, which is exactly how ostp-client::migrate ended up working
// against loosely-typed serde_json::Value instead of a real schema, and how
// the CLI, the migrator, and this crate's own hot-reload path could each
// silently drift out of sync with what a config.json actually looks like.
// main.rs now imports these instead of re-declaring them (see the `use
// ostp_client::config::{...}` at its top).
//
// These are DELIBERATELY separate from ClientConfig/OstpConfig/etc. above:
// this section is the friendly, minimal shape a user actually edits by
// hand; the types above are what the running engine needs internally
// (handshake/io timeouts, resolved addresses, ...) and are built FROM one
// of these via the mapping in ostp/src/main.rs::run_client_directly. Only
// `ClientConfig` collides by name with the runtime type above, so the
// on-disk one is `ClientFileConfig` — everything else keeps its natural name.
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub enum AppMode {
    Server(ServerConfig),
    Client(ClientFileConfig),
    Relay(RelayServerConfig),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UnifiedConfig {
    #[serde(flatten)]
    pub mode: AppMode,
    pub log_level: Option<String>,
}

impl UnifiedConfig {
    pub fn validate(&self) -> Result<()> {
        match &self.mode {
            AppMode::Server(cfg) => {
                if cfg.access_keys.is_empty() {
                    anyhow::bail!("Server configuration must contain at least one access_key.");
                }
                if let Some(outbound) = &cfg.outbound {
                    if outbound.enabled {
                        let action = outbound.default_action.as_deref().unwrap_or("direct");
                        if action == "direct" && outbound.rules.is_empty() {
                            println!("\n[WARNING] Server outbound proxy is ENABLED, but default_action is 'direct' and there are no rules!");
                            println!("          This means ALL traffic will bypass the proxy and go out directly from the server IP.");
                            println!("          If you want all traffic to be proxied, change 'default_action' to 'proxy'.\n");
                        }
                    }
                }
            }
            AppMode::Client(cfg) => {
                if cfg.access_key.is_empty() {
                    anyhow::bail!("Client configuration must contain an access_key.");
                }
            }
            AppMode::Relay(cfg) => {
                // The relay forwards to a fixed next hop on both carriers, so it
                // needs both upstream addresses. It does NOT need upstream_api_url:
                // that field belonged to the old design where the relay
                // authenticated clients itself, which it no longer does. Requiring
                // it here was the bug that made every generated relay config
                // (wizard and template alike write no api_url) fail to load with
                // "must specify upstream_api_url" — a relay that could never start.
                if cfg.upstream_tcp.is_empty() {
                    anyhow::bail!("Relay configuration must specify upstream_tcp (the next hop's TCP/UoT address).");
                }
                if cfg.upstream_udp.is_empty() {
                    anyhow::bail!("Relay configuration must specify upstream_udp (the next hop's UDP address).");
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(untagged)]
pub enum UserConfig {
    Detailed {
        access_key: String,
        name: Option<String>,
        limit_bytes: Option<u64>,
    },
    KeyOnly(String),
}

impl UserConfig {
    pub fn key(&self) -> String {
        match self {
            UserConfig::KeyOnly(k) => k.clone(),
            UserConfig::Detailed { access_key, .. } => access_key.clone(),
        }
    }
    pub fn name(&self) -> Option<String> {
        match self {
            UserConfig::KeyOnly(_) => None,
            UserConfig::Detailed { name, .. } => name.clone(),
        }
    }
    pub fn limit(&self) -> Option<u64> {
        match self {
            UserConfig::KeyOnly(_) => None,
            UserConfig::Detailed { limit_bytes, .. } => *limit_bytes,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ServerConfig {
    pub listen: ListenConfig,
    pub access_keys: Vec<UserConfig>,
    pub debug: Option<bool>,
    pub outbound: Option<OutboundConfig>,
    pub api: Option<ApiConfig>,
    pub fallback: Option<FallbackCfg>,
    pub transport: Option<TransportConfigRaw>,
    // Left untyped: ostp-client does not (and should not) depend on
    // ostp-server just to name its DnsConfig type. The CLI binary — which
    // already depends on both crates — deserializes this into
    // ostp_server::dns::DnsConfig right before handing it to run_server().
    pub dns: Option<serde_json::Value>,
}

/// Relay-node config.json shape.
#[derive(Debug, Deserialize, Serialize)]
pub struct RelayServerConfig {
    /// Listen address(es) (UDP + TCP UoT)
    pub listen: ListenConfig,
    /// Upstream address for TCP (UoT) traffic
    pub upstream_tcp: String,
    /// Upstream address for UDP traffic
    pub upstream_udp: String,
    // ── Deprecated ──────────────────────────────────────────────────────────
    // The relay used to authenticate clients itself and pulled the access-key
    // list from the target server's management API to do it. It no longer does:
    // sessions are authenticated end-to-end by the target server, and a relay
    // that re-checks credentials only adds a weaker second gate plus a copy of
    // the key list on a machine that does not need one. These are kept solely
    // so existing relay configs still parse; they are ignored.
    #[serde(default)]
    pub upstream_api_url: String,
    #[serde(default)]
    pub upstream_api_token: String,
    #[serde(default)]
    pub sync_interval_secs: u64,
    pub debug: Option<bool>,
}

/// Supports both a single string "0.0.0.0:50000" and an array
/// ["0.0.0.0:50000", "[::]:50000"].
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(untagged)]
pub enum ListenConfig {
    Single(String),
    Multiple(Vec<String>),
}

impl ListenConfig {
    pub fn addresses(&self) -> Vec<String> {
        match self {
            ListenConfig::Single(s) => vec![s.clone()],
            ListenConfig::Multiple(v) => v.clone(),
        }
    }

    pub fn primary(&self) -> String {
        match self {
            ListenConfig::Single(s) => s.clone(),
            ListenConfig::Multiple(v) => v.first().cloned().unwrap_or_default(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ApiConfig {
    pub enabled: Option<bool>,
    pub bind: Option<String>,
    pub token: Option<String>,
    pub webpath: Option<String>,
    pub username: Option<String>,
    pub password_hash: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FallbackCfg {
    pub enabled: Option<bool>,
    pub listen: Option<String>,
    pub target: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ClientFileConfig {
    pub server: String,
    pub access_key: String,
    pub mtu: Option<usize>,
    pub socks5_bind: Option<String>,
    pub tun: Option<TunConfig>,
    pub debug: Option<bool>,
    pub exclude: Option<ExcludeConfig>,
    pub mux: Option<MuxConfig>,
    pub transport: Option<TransportConfigRaw>,
    pub gui: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TransportConfigRaw {
    pub mode: Option<String>,
    pub tcp_fragmentation: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TunConfig {
    pub enable: bool,
    pub wintun_path: Option<String>,
    pub ipv4_address: Option<String>,
    pub dns: Option<String>,
    pub kill_switch: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OutboundConfig {
    pub enabled: bool,
    pub protocol: String,
    pub address: String,
    pub port: u16,
    #[serde(default)]
    pub rules: Vec<OutboundRule>,
    pub default_action: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OutboundRule {
    pub domain_suffix: Option<Vec<String>>,
    pub ip_cidr: Option<Vec<String>>,
    pub protocol: Option<String>,
    pub action: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ExcludeConfig {
    pub domains: Option<Vec<String>>,
    pub ips: Option<Vec<String>>,
    pub processes: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MuxConfig {
    pub enabled: Option<bool>,
    pub sessions: Option<usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Loads a config.json exactly as the daemon does: parse the JSON into the
    /// canonical `UnifiedConfig`, then validate. This is the real drift-catcher —
    /// if the wizard/template and the validator ever disagree on required fields,
    /// this fails instead of a user's relay refusing to start.
    fn load(json: &str) -> Result<UnifiedConfig> {
        let cfg: UnifiedConfig = serde_json::from_str(json)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Regression: the relay used to authenticate clients and so its config
    /// carried `upstream_api_url`. The relay is a transparent pipe now and both
    /// the wizard and the `init` template write NO api_url — yet validation kept
    /// demanding it, so every generated relay config failed to load with
    /// "must specify upstream_api_url". A relay that could never start.
    #[test]
    fn relay_config_without_api_url_loads() {
        // Byte-for-byte the shape the wizard (main.rs) emits.
        let json = r#"{
            "mode": "relay",
            "listen": "0.0.0.0:50000",
            "upstream_tcp": "203.0.113.10:50000",
            "upstream_udp": "203.0.113.10:50000",
            "debug": false
        }"#;
        load(json).expect("a transparent-relay config must load without upstream_api_url");
    }

    /// A relay still needs somewhere to forward to on both carriers, so an
    /// incomplete relay config must fail loudly at load, not connect-to-empty
    /// per session at runtime.
    #[test]
    fn relay_config_missing_upstream_udp_is_rejected() {
        let json = r#"{
            "mode": "relay",
            "listen": "0.0.0.0:50000",
            "upstream_tcp": "203.0.113.10:50000",
            "upstream_udp": "",
            "debug": false
        }"#;
        assert!(load(json).is_err(), "a relay with no UDP upstream must be rejected");
    }

    /// A deprecated api_url left in an OLD config must not break loading — it is
    /// ignored, not required and not forbidden.
    #[test]
    fn relay_config_with_leftover_api_url_still_loads() {
        let json = r#"{
            "mode": "relay",
            "listen": "0.0.0.0:50000",
            "upstream_tcp": "203.0.113.10:50000",
            "upstream_udp": "203.0.113.10:50000",
            "upstream_api_url": "http://old.example:8080",
            "debug": false
        }"#;
        load(json).expect("a stale api_url must be tolerated, not rejected");
    }

    /// The minimal client and server shapes the template emits must also load,
    /// so this test guards all three modes against generator/validator drift.
    #[test]
    fn minimal_client_and_server_configs_load() {
        load(r#"{"mode":"client","server":"127.0.0.1:50000","access_key":"k"}"#)
            .expect("minimal client config must load");
        load(r#"{"mode":"server","listen":"0.0.0.0:50000","access_keys":["k"]}"#)
            .expect("minimal server config must load");
    }
}
