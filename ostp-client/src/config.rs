use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Runtime configuration the engine runs on. The CLI builds it from `config.json`
/// and passes it to `runner::run_client`.
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

/// `mode` is "udp" (default) or "uot" (UDP over TCP). UoT can run inside real TLS to the
/// server's own domain (`tls`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    /// "udp" or "uot"
    #[serde(default = "default_transport_mode")]
    pub mode: String,
    /// Split the first UoT/TCP packet (handshake) into tiny TCP segments to
    /// break DPI that inspects the first packet. UoT/TCP only; ignored for UDP.
    #[serde(default)]
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
    /// lowered IP TTL so they reach an on-path DPI box but expire before the server.
    #[serde(default)]
    pub ttl_desync: bool,
    /// TTL the decoy datagrams are sent with. Set it to one or two hops past the
    /// injector distance the prober reports, so decoys die just beyond the DPI.
    #[serde(default = "default_ttl_desync_ttl")]
    pub ttl_desync_ttl: u8,
    /// How many decoy datagrams to send per handshake.
    #[serde(default = "default_ttl_desync_count")]
    pub ttl_desync_count: u8,
    /// Measure the hop distance to the server (see ttl_probe) and use it instead of
    /// `ttl_desync_ttl`. Turn off to pin the value.
    #[serde(default = "default_true")]
    pub ttl_desync_auto: bool,
    /// Wrap UoT in TLS (UoT only). The certificate is verified against the
    /// public web PKI unless `tls_insecure` is set.
    #[serde(default)]
    pub tls: bool,
    /// TLS server name; defaults to the host part of `server_addr`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_sni: Option<String>,
    /// Accept any server certificate. For testing only: anyone can impersonate the server.
    #[serde(default)]
    pub tls_insecure: bool,
    /// Secret HTTP-upgrade path, needed when a web server (nginx/apache/caddy)
    /// on 443 forwards to OSTP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_path: Option<String>,
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
            tls: false,
            tls_sni: None,
            tls_insecure: false,
            ws_path: None,
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

impl ClientConfig {
    /// Reads `config.json` next to the running binary (hot reload). Goes through the
    /// same `ClientFileConfig::to_runtime` as the CLI and the GUI, so a reload cannot
    /// disagree with a fresh start about any default.
    pub fn reload_from_json_near_binary() -> Result<Self> {
        let exe = std::env::current_exe().context("cannot resolve binary path")?;
        let dir = exe.parent().context("cannot resolve binary directory")?;
        let path = dir.join("config.json");

        let raw = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let mut stripped = json_comments::StripComments::new(raw.as_bytes());
        let unified: UnifiedConfig = serde_json::from_reader(&mut stripped)
            .with_context(|| format!("failed to parse {}", path.display()))?;
        match unified.mode {
            AppMode::Client(client) => Ok(client.to_runtime()),
            _ => anyhow::bail!("{} is not a client config", path.display()),
        }
    }
}

impl ClientFileConfig {
    /// The one place the file's client section becomes the runtime config, and so the
    /// one set of defaults: CLI, GUI and hot reload all call it and override only what
    /// they deliberately set.
    pub fn to_runtime(&self) -> ClientConfig {
        let tun = self.tun.as_ref();
        let ostp = OstpConfig {
            server_addr: self.server.clone(),
            access_key: self.access_key.clone(),
            mtu: self.mtu.unwrap_or_else(default_mtu),
            ..OstpConfig::default()
        };
        let local_proxy = LocalProxyConfig {
            bind_addr: self.socks5_bind.clone().unwrap_or_else(|| LocalProxyConfig::default().bind_addr),
            ..LocalProxyConfig::default()
        };
        ClientConfig {
            mode: if tun.map_or(false, |t| t.enable) { "tun" } else { "proxy" }.to_string(),
            debug: self.debug.unwrap_or(false),
            ostp,
            local_proxy,
            transport: self.transport.clone().unwrap_or_default().to_runtime(),
            exclusions: ExclusionConfig {
                domains: self.exclude.as_ref().and_then(|e| e.domains.clone()).unwrap_or_default(),
                ips: self.exclude.as_ref().and_then(|e| e.ips.clone()).unwrap_or_default(),
                processes: self.exclude.as_ref().and_then(|e| e.processes.clone()).unwrap_or_default(),
            },
            multiplex: MultiplexConfig {
                enabled: self.mux.as_ref().and_then(|m| m.enabled).unwrap_or(false),
                sessions: self.mux.as_ref().and_then(|m| m.sessions).unwrap_or(1),
            },
            dns_server: tun.and_then(|t| t.dns.clone()),
            tun_stack: tun
                .and_then(|t| t.stack.clone())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(default_tun_stack),
            kill_switch: tun.and_then(|t| t.kill_switch).unwrap_or(false),
            gui: self.gui.clone(),
        }
    }
}

// On-disk config.json shapes. `ClientFileConfig` is the file's client section; the
// `ClientConfig` above is what the engine runs on.

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
    /// Schema version the file was written for (see `migrate::CURRENT_VERSION`).
    /// Absent in files from before 0.4.6.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_version: Option<u32>,
}

impl UnifiedConfig {
    pub fn validate(&self) -> Result<()> {
        match &self.mode {
            AppMode::Server(cfg) => {
                if cfg.access_keys.is_empty() {
                    anyhow::bail!("a server config needs at least one access key");
                }
                if let Some(outbound) = &cfg.outbound {
                    if outbound.enabled {
                        let action = outbound.default_action.as_deref().unwrap_or("direct");
                        if action == "direct" && outbound.rules.is_empty() {
                            println!("[warn] outbound proxy is enabled, but default_action is 'direct' and there are no rules: nothing will use the proxy. Set default_action to 'proxy' or add rules.");
                        }
                    }
                }
                if let Some(d) = cfg.domain.as_deref().filter(|d| !d.is_empty()) {
                    validate_domain(d)?;
                }
                if let Some(tls) = &cfg.tls {
                    let webpath = cfg.api.as_ref().and_then(|a| a.webpath.as_deref());
                    tls.validate(cfg.domain.as_deref(), webpath)?;
                }
                if let Some(sub) = &cfg.subscription {
                    let webpath = cfg.api.as_ref().and_then(|a| a.webpath.as_deref());
                    sub.validate(cfg.domain.as_deref(), cfg.tls.as_ref(), webpath)?;
                }
            }
            AppMode::Client(cfg) => {
                if cfg.access_key.is_empty() {
                    anyhow::bail!("a client config needs an access_key");
                }
            }
            AppMode::Relay(cfg) => {
                // The relay forwards to a fixed next hop on both carriers.
                if cfg.upstream_tcp.is_empty() {
                    anyhow::bail!("a relay config needs upstream_tcp (the next hop's TCP/UoT address)");
                }
                if cfg.upstream_udp.is_empty() {
                    anyhow::bail!("a relay config needs upstream_udp (the next hop's UDP address)");
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
    pub bind_ip: Option<String>,
    pub access_keys: Vec<UserConfig>,
    pub debug: Option<bool>,
    pub outbound: Option<OutboundConfig>,
    pub api: Option<ApiConfig>,
    pub fallback: Option<FallbackCfg>,
    pub transport: Option<TransportConfigRaw>,
    // Untyped so ostp-client need not depend on ostp-server; the CLI parses it into
    // `ostp_server::dns::DnsConfig`.
    pub dns: Option<serde_json::Value>,
    /// Public name of the server; used in share links, with or without TLS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsServerCfg>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subscription: Option<SubscriptionCfg>,
    /// overnet: `.ov` for clients and the overnet exit. Untyped for the same
    /// reason as `dns`; the CLI reads it as `ostp_server::OvernetConfig`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overnet: Option<serde_json::Value>,
    /// Clients may reach this server's own services (beyond the panel and
    /// DNS) and private networks, e.g. a home LAN behind a router running
    /// OSTP. Off: only the internet. Cloud metadata stays closed either way.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub local_access: bool,
}

/// Per-user subscription URLs: `https://<domain>[:port]<path>/<token>`
/// returns that user's current links, so clients follow server changes
/// (new port, new path, rotated certificate settings) without a new link.
/// Served only over the TLS carrier: the token must not travel in clear.
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SubscriptionCfg {
    pub enabled: Option<bool>,
    /// URL prefix, "/sub" by default.
    pub path: Option<String>,
    /// Title shown in apps; the domain by default.
    pub name: Option<String>,
    /// How often clients re-fetch, in hours (default 12).
    pub update_interval_hours: Option<u32>,
    /// Which links to hand out, best first: "tls", "udp" (default both).
    pub include: Option<Vec<String>>,
}

impl SubscriptionCfg {
    pub fn is_enabled(&self) -> bool {
        self.enabled.unwrap_or(false)
    }

    pub fn path(&self) -> String {
        let p = self.path.as_deref().unwrap_or("/sub").trim_end_matches('/');
        if p.is_empty() { "/sub".into() } else { p.to_string() }
    }

    pub fn update_interval_hours(&self) -> u32 {
        self.update_interval_hours.unwrap_or(12).clamp(1, 24 * 30)
    }

    pub fn includes(&self, kind: &str) -> bool {
        self.include.as_ref().map_or(true, |v| v.iter().any(|k| k == kind))
    }

    pub fn validate(&self, domain: Option<&str>, tls: Option<&TlsServerCfg>, webpath: Option<&str>) -> Result<()> {
        if !self.is_enabled() {
            return Ok(());
        }
        let tls = tls.filter(|t| t.is_enabled());
        let Some(tls) = tls else {
            anyhow::bail!("subscription needs the HTTPS carrier: enable \"tls\" first (ostp cert issue)");
        };
        if domain.unwrap_or("").is_empty() {
            anyhow::bail!("subscription needs \"domain\" to be set");
        }
        let p = self.path();
        let url_safe = p.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_' | '.' | '~'));
        if !p.starts_with('/') || p.len() < 2 || !url_safe || p.contains("//") {
            anyhow::bail!("subscription.path must look like \"/sub\" (got '{p}')");
        }
        if p.starts_with("/.well-known") {
            anyhow::bail!("subscription.path must not be under /.well-known/");
        }
        let ws = tls.ws_path.as_deref().unwrap_or("");
        let panel = format!("/{}", webpath.filter(|w| !w.is_empty()).unwrap_or("panel").trim_matches('/'));
        for (other, what) in [(ws, "tls.ws_path"), (panel.as_str(), "the panel path")] {
            if !other.is_empty() && (other == p || other.starts_with(&format!("{p}/")) || p.starts_with(&format!("{other}/"))) {
                anyhow::bail!("subscription.path {p} overlaps {what}");
            }
        }
        if let Some(v) = &self.include {
            if let Some(bad) = v.iter().find(|k| !matches!(k.as_str(), "tls" | "udp")) {
                anyhow::bail!("subscription.include accepts \"tls\" and \"udp\" (got '{bad}')");
            }
            if v.is_empty() {
                anyhow::bail!("subscription.include must name at least one link kind");
            }
        }
        Ok(())
    }
}

/// Optional HTTPS carrier: real TLS on a real domain, either terminated by
/// OSTP itself ("builtin", on 443/80) or by a local web server that hands
/// the secret upgrade path to OSTP.
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct TlsServerCfg {
    pub enabled: Option<bool>,
    /// "builtin" | "nginx" | "apache" | "caddy"
    pub frontend: Option<String>,
    /// Secret HTTP-upgrade path, e.g. "/Xk3...".
    pub ws_path: Option<String>,
    /// "acme" | "manual" | "none" (caddy manages its own certificate)
    pub cert: Option<String>,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    pub acme: Option<AcmeCfg>,
    pub https_listen: Option<ListenConfig>,
    pub http_listen: Option<ListenConfig>,
    /// Port put in share links (443 unless the frontend listens elsewhere).
    pub public_port: Option<u16>,
    /// Run after a renewal so a web-server frontend picks up the new files.
    pub reload_command: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct AcmeCfg {
    pub email: Option<String>,
    pub staging: Option<bool>,
    /// Directory URL override (another CA, or a test server).
    pub directory: Option<String>,
    /// Local HTTP-01 responder a web-server frontend proxies challenges to.
    pub responder: Option<String>,
    pub renew_days_before: Option<u32>,
}

impl TlsServerCfg {
    pub fn is_enabled(&self) -> bool {
        self.enabled.unwrap_or(false)
    }

    pub fn frontend(&self) -> &str {
        self.frontend.as_deref().unwrap_or("builtin")
    }

    /// Caddy always manages its own certificate.
    pub fn cert_source(&self) -> &str {
        if self.frontend() == "caddy" {
            "none"
        } else {
            self.cert.as_deref().unwrap_or("acme")
        }
    }

    pub fn validate(&self, domain: Option<&str>, webpath: Option<&str>) -> Result<()> {
        if !self.is_enabled() {
            return Ok(());
        }
        if !matches!(self.frontend(), "builtin" | "nginx" | "apache" | "caddy") {
            anyhow::bail!("tls.frontend must be one of builtin, nginx, apache, caddy (got '{}')", self.frontend());
        }
        let ws = self.ws_path.as_deref().unwrap_or("");
        if !ws.starts_with('/') || ws.len() < 9 || ws.contains(['?', '#', ' ']) {
            anyhow::bail!("tls.ws_path must be a secret path like \"/Xk3pQ9aZ...\" (at least 8 characters after '/')");
        }
        if ws.starts_with("/.well-known/") {
            anyhow::bail!("tls.ws_path must not be under /.well-known/");
        }
        let panel = format!("/{}", webpath.filter(|w| !w.is_empty()).unwrap_or("panel").trim_matches('/'));
        if ws == panel || ws.starts_with(&format!("{panel}/")) {
            anyhow::bail!("tls.ws_path must not be under the panel path {panel}");
        }
        match self.cert_source() {
            "acme" => {
                let d = domain.unwrap_or("");
                if d.is_empty() {
                    anyhow::bail!("tls.cert = \"acme\" needs \"domain\" to be set");
                }
            }
            "manual" => {
                if self.cert_path.as_deref().unwrap_or("").is_empty() || self.key_path.as_deref().unwrap_or("").is_empty() {
                    anyhow::bail!("tls.cert = \"manual\" needs both tls.cert_path and tls.key_path");
                }
            }
            "none" => {}
            other => anyhow::bail!("tls.cert must be acme, manual or none (got '{other}')"),
        }
        Ok(())
    }
}

/// A bare host name: no scheme, port, path or spaces.
pub fn validate_domain(domain: &str) -> Result<()> {
    let ok = !domain.is_empty()
        && domain.len() <= 253
        && domain.contains('.')
        && domain.split('.').all(|l| {
            !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-')
                && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        });
    if !ok {
        anyhow::bail!("\"{domain}\" is not a valid domain name (expected something like vpn.example.com)");
    }
    Ok(())
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
    // Ignored: the target server authenticates sessions. Kept so old relay configs still parse.
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

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct TransportConfigRaw {
    pub mode: Option<String>,
    pub tcp_fragmentation: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frag_chunk: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frag_sleep: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub junk_pc: Option<[usize; 2]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub junk_ps: Option<[usize; 2]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_desync: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_desync_ttl: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_desync_count: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_desync_auto: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_sni: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_insecure: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_path: Option<String>,
}

impl TransportConfigRaw {
    /// The runtime transport settings this file section describes.
    pub fn to_runtime(&self) -> TransportConfig {
        let d = TransportConfig::default();
        TransportConfig {
            mode: self.mode.clone().unwrap_or(d.mode),
            tcp_fragmentation: self.tcp_fragmentation.unwrap_or(d.tcp_fragmentation),
            frag_chunk: self.frag_chunk.unwrap_or(d.frag_chunk),
            frag_sleep: self.frag_sleep.unwrap_or(d.frag_sleep),
            junk_pc: self.junk_pc.unwrap_or(d.junk_pc),
            junk_ps: self.junk_ps.unwrap_or(d.junk_ps),
            ttl_desync: self.ttl_desync.unwrap_or(d.ttl_desync),
            ttl_desync_ttl: self.ttl_desync_ttl.unwrap_or(d.ttl_desync_ttl),
            ttl_desync_count: self.ttl_desync_count.unwrap_or(d.ttl_desync_count),
            ttl_desync_auto: self.ttl_desync_auto.unwrap_or(d.ttl_desync_auto),
            tls: self.tls.unwrap_or(false),
            tls_sni: self.tls_sni.clone().filter(|s| !s.is_empty()),
            tls_insecure: self.tls_insecure.unwrap_or(false),
            ws_path: self.ws_path.clone().filter(|s| !s.is_empty()),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TunConfig {
    pub enable: bool,
    pub wintun_path: Option<String>,
    pub ipv4_address: Option<String>,
    pub dns: Option<String>,
    /// TUN packet stack; "system" when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stack: Option<String>,
    pub kill_switch: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OutboundConfig {
    pub enabled: bool,
    pub protocol: String,
    pub address: String,
    pub port: u16,
    /// SOCKS5 username, for an upstream proxy that requires authentication
    /// (e.g. a residential-proxy service). Empty/absent = no-auth SOCKS5.
    #[serde(default)]
    pub username: String,
    /// SOCKS5 password (paired with `username`).
    #[serde(default)]
    pub password: String,
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
    /// Local source IP to egress from when this rule matches (overrides the
    /// server's global `bind_ip` for this rule). Lets one destination leave via
    /// one address and another via a different one.
    pub send_from: Option<String>,
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

    /// Loads a config.json the way the daemon does: parse, then validate.
    fn load(json: &str) -> Result<UnifiedConfig> {
        let cfg: UnifiedConfig = serde_json::from_str(json)?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn server_with(extra: &str) -> String {
        format!(r#"{{"mode":"server","listen":"0.0.0.0:50000","access_keys":["k"]{extra}}}"#)
    }

    #[test]
    fn server_tls_configs_validate() {
        load(&server_with(
            r#","domain":"vpn.example.com","tls":{"enabled":true,"ws_path":"/Xk3pQ9aZr2","acme":{"email":"a@b.c"}}"#,
        ))
        .expect("builtin + acme with a domain loads");
        load(&server_with(
            r#","tls":{"enabled":true,"frontend":"caddy","ws_path":"/Xk3pQ9aZr2"}"#,
        ))
        .expect("caddy needs no certificate settings");
        load(&server_with(r#","tls":{"enabled":false}"#)).expect("a disabled section is not validated");
    }

    #[test]
    fn server_tls_configs_are_rejected_with_a_reason() {
        for (extra, why) in [
            (r#","tls":{"enabled":true,"ws_path":"/Xk3pQ9aZr2"}"#, "acme without domain"),
            (r#","domain":"vpn.example.com","tls":{"enabled":true}"#, "missing ws_path"),
            (r#","domain":"vpn.example.com","tls":{"enabled":true,"ws_path":"/short"}"#, "short ws_path"),
            (r#","domain":"vpn.example.com","tls":{"enabled":true,"ws_path":"/panel/Xk3pQ9aZr2"}"#, "ws_path under panel"),
            (r#","domain":"vpn.example.com","tls":{"enabled":true,"ws_path":"/Xk3pQ9aZr2","frontend":"iis"}"#, "unknown frontend"),
            (r#","tls":{"enabled":true,"ws_path":"/Xk3pQ9aZr2","cert":"manual"}"#, "manual without paths"),
            (r#","domain":"https://vpn.example.com","tls":{"enabled":false}"#, "domain with scheme"),
        ] {
            assert!(load(&server_with(extra)).is_err(), "{why} must be rejected");
        }
    }

    /// The wizard and `ostp init relay` write no `upstream_api_url`, so it must not be required.
    #[test]
    fn relay_config_without_api_url_loads() {
        let json = r#"{
            "mode": "relay",
            "listen": "0.0.0.0:50000",
            "upstream_tcp": "203.0.113.10:50000",
            "upstream_udp": "203.0.113.10:50000",
            "debug": false
        }"#;
        load(json).expect("a transparent-relay config must load without upstream_api_url");
    }

    /// Both upstreams are required.
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

    /// An `upstream_api_url` left in an old config is ignored.
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

    fn client_file(json: &str) -> ClientFileConfig {
        match serde_json::from_str::<UnifiedConfig>(json).expect("parses").mode {
            AppMode::Client(c) => c,
            _ => panic!("not a client config"),
        }
    }

    /// Every front end gets these defaults from the single conversion.
    #[test]
    fn client_to_runtime_defaults() {
        let rt = client_file(r#"{"mode":"client","server":"example.org:443","access_key":"k"}"#).to_runtime();
        assert_eq!(rt.mode, "proxy");
        assert_eq!(rt.ostp.server_addr, "example.org:443");
        assert_eq!(rt.ostp.mtu, 1140);
        assert_eq!(rt.ostp.io_timeout_ms, 2500);
        assert_eq!(rt.ostp.handshake_timeout_ms, 5000);
        assert_eq!(rt.local_proxy.connect_timeout_ms, 15000);
        assert_eq!(rt.local_proxy.bind_addr, "127.0.0.1:1088");
        assert_eq!(rt.tun_stack, "system");
        assert!(!rt.kill_switch && !rt.multiplex.enabled);
        assert_eq!(rt.multiplex.sessions, 1);
        assert_eq!(rt.transport.mode, "udp");
    }

    /// The file's own values win over the defaults, including `mtu` and `tun.stack`.
    #[test]
    fn client_to_runtime_honours_file_values() {
        let rt = client_file(
            r#"{"mode":"client","server":"s:1","access_key":"k","mtu":1280,"socks5_bind":"127.0.0.1:9",
                "tun":{"enable":true,"dns":"1.1.1.1","stack":"gvisor","kill_switch":true},
                "mux":{"enabled":true,"sessions":3},
                "exclude":{"domains":["a.b"]},
                "transport":{"mode":"uot","tls":true,"tls_sni":""}}"#,
        )
        .to_runtime();
        assert_eq!(rt.mode, "tun");
        assert_eq!(rt.ostp.mtu, 1280);
        assert_eq!(rt.local_proxy.bind_addr, "127.0.0.1:9");
        assert_eq!(rt.tun_stack, "gvisor");
        assert_eq!(rt.dns_server.as_deref(), Some("1.1.1.1"));
        assert!(rt.kill_switch);
        assert!(rt.multiplex.enabled);
        assert_eq!(rt.multiplex.sessions, 3);
        assert_eq!(rt.exclusions.domains, vec!["a.b".to_string()]);
        assert_eq!(rt.transport.mode, "uot");
        assert!(rt.transport.tls);
        assert_eq!(rt.transport.tls_sni, None, "an empty SNI means unset");
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
