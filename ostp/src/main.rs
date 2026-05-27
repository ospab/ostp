use anyhow::{anyhow, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about = "OSTP Core - Ospab Stealth Transport Protocol", long_about = None)]
struct Args {
    /// Path to the JSON configuration file
    #[cfg_attr(unix, arg(long, default_value = "/etc/ostp/config.json"))]
    #[cfg_attr(windows, arg(long, default_value = "config.json"))]
    config: PathBuf,

    /// Optional mode to initialize the config for (client or server)
    #[arg(short, long)]
    init: Option<String>,

    /// Generate a new secure access key and exit
    #[arg(short = 'g', long)]
    generate_key: bool,

    /// Format for generated key (hex, base64)
    #[arg(long, default_value = "hex")]
    format: String,

    /// Number of keys to generate
    #[arg(short = 'c', long, default_value_t = 1)]
    count: usize,

    /// Output ready-to-use client sharing links (ostp://...) from the server configuration
    #[arg(long)]
    links: bool,

    /// Validate configuration file and exit
    #[arg(long)]
    check: bool,

    /// Optional client connection share link (ostp://ACCESS_KEY@HOST:PORT) to run instantly
    url: Option<String>,

    /// Uninstall OSTP: stop service, remove binary and configuration files
    #[arg(long)]
    uninstall: bool,

    /// Update OSTP: re-run the install script to fetch and install the latest version
    #[arg(long)]
    update: bool,
}

fn parse_ostp_link(link: &str) -> Result<ClientConfig> {
    let parsed = url::Url::parse(link)
        .map_err(|e| anyhow!("Failed to parse share link URL: {e}"))?;

    if parsed.scheme() != "ostp" {
        anyhow::bail!("Unsupported URL scheme '{}', expected 'ostp://'", parsed.scheme());
    }

    let access_key = parsed.username().to_string();
    if access_key.is_empty() {
        anyhow::bail!("Missing access key (userinfo segment) in share link");
    }

    let host = parsed.host_str().ok_or_else(|| anyhow!("Missing host in share link"))?;
    let port = parsed.port().ok_or_else(|| anyhow!("Missing port in share link"))?;
    let server = format!("{host}:{port}");
    let mut sni = String::new();
    let mut fp = String::new();
    let mut pbk = String::new();
    let mut sid = String::new();
    let mut spx = String::new();
    let mut transport_mode = String::from("udp");

    for (k, v) in parsed.query_pairs() {
        match k.as_ref() {
            "sni" => sni = v.into_owned(),
            "fp" => fp = v.into_owned(),
            "pbk" => pbk = v.into_owned(),
            "sid" => sid = v.into_owned(),
            "spx" => spx = v.into_owned(),
            "type" => transport_mode = v.into_owned(),
            _ => {}
        }
    }

    Ok(ClientConfig {
        server,
        access_key,
        mtu: None,
        transport: Some(TransportConfigRaw {
            mode: Some(transport_mode),
            stealth_sni: Some(sni.clone()),
            stealth_port: Some(443),
        }),
        socks5_bind: Some("127.0.0.1:1088".to_string()),
        tun: Some(TunConfig {
            enable: false,
            wintun_path: Some("./wintun.dll".to_string()),
            ipv4_address: Some("10.1.0.2/24".to_string()),
            dns: None,
        }),
        reality: Some(RealityConfigRaw {
            sni,
            fp,
            pbk,
            sid,
            spx,
        }),
        debug: Some(false),
        exclude: None,
        mux: None,
    })
}

fn generate_secure_key(format_type: &str) -> String {
    use rand::RngCore;
    let mut key = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut key);
    match format_type.to_lowercase().as_str() {
        "base64" => {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(key)
        }
        _ => key.iter().map(|b| format!("{:02x}", b)).collect(),
    }
}

fn generate_reality_keys() -> (String, String, String) {
    use rand::RngCore;
    use base64::Engine;
    
    let builder = snow::Builder::new("Noise_NN_25519_ChaChaPoly_BLAKE2s".parse().unwrap());
    let keypair = builder.generate_keypair().expect("failed to generate reality keys");
    let priv_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&keypair.private);
    let pub_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&keypair.public);
    
    let mut sid_bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut sid_bytes);
    let sid_hex = sid_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>();
    
    (priv_b64, pub_b64, sid_hex)
}

fn parse_outbound_action(value: Option<String>) -> ostp_server::OutboundAction {
    match value.as_deref() {
        Some("direct") => ostp_server::OutboundAction::Direct,
        _ => ostp_server::OutboundAction::Proxy,
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
enum AppMode {
    Server(ServerConfig),
    Client(ClientConfig),
    Relay(RelayServerConfig),
}

#[derive(Debug, Deserialize, Serialize)]
struct UnifiedConfig {
    #[serde(flatten)]
    mode: AppMode,
    log_level: Option<String>,
}

impl UnifiedConfig {
    fn validate(&self) -> Result<()> {
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
                if cfg.upstream_tcp.is_empty() {
                    anyhow::bail!("Relay configuration must specify upstream_tcp address.");
                }
                if cfg.upstream_api_url.is_empty() {
                    anyhow::bail!("Relay configuration must specify upstream_api_url.");
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
            UserConfig::Detailed { limit_bytes, .. } => limit_bytes.clone(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct ServerConfig {
    listen: ListenConfig,
    access_keys: Vec<UserConfig>,
    reality: Option<RealityServerConfigRaw>,
    debug: Option<bool>,
    outbound: Option<OutboundConfig>,
    api: Option<ApiConfig>,
    fallback: Option<FallbackCfg>,
    transport: Option<TransportConfigRaw>,
    dns: Option<ostp_server::dns::DnsConfig>,
}

/// Конфигурация Relay-узла в config.json
#[derive(Debug, Deserialize, Serialize)]
struct RelayServerConfig {
    /// Адрес(а) прослушивания (UDP + TCP UoT)
    listen: ListenConfig,
    /// Адрес upstream для TCP (UoT) трафика
    upstream_tcp: String,
    /// Адрес upstream для UDP трафика
    upstream_udp: String,
    /// URL API целевого сервера для синхронизации ключей
    upstream_api_url: String,
    /// Bearer-токен для API целевого сервера
    #[serde(default)]
    upstream_api_token: String,
    /// Интервал синхронизации ключей в секундах (по умолчанию 30)
    #[serde(default = "default_sync_interval")]
    sync_interval_secs: u64,
    debug: Option<bool>,
}

fn default_sync_interval() -> u64 { 30 }

/// Supports both single string "0.0.0.0:50000" and array ["0.0.0.0:50000", "[::]:50000"]
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(untagged)]
enum ListenConfig {
    Single(String),
    Multiple(Vec<String>),
}

impl ListenConfig {
    fn addresses(&self) -> Vec<String> {
        match self {
            ListenConfig::Single(s) => vec![s.clone()],
            ListenConfig::Multiple(v) => v.clone(),
        }
    }

    fn primary(&self) -> String {
        match self {
            ListenConfig::Single(s) => s.clone(),
            ListenConfig::Multiple(v) => v.first().cloned().unwrap_or_default(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct ApiConfig {
    enabled: Option<bool>,
    bind: Option<String>,
    webpath: Option<String>,
    username: Option<String>,
    password_hash: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct FallbackCfg {
    enabled: Option<bool>,
    listen: Option<String>,
    target: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ClientConfig {
    server: String,
    access_key: String,
    mtu: Option<usize>,
    socks5_bind: Option<String>,
    tun: Option<TunConfig>,
    reality: Option<RealityConfigRaw>,
    debug: Option<bool>,
    exclude: Option<ExcludeConfig>,
    mux: Option<MuxConfig>,
    transport: Option<TransportConfigRaw>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct TransportConfigRaw {
    mode: Option<String>,
    stealth_sni: Option<String>,
    stealth_port: Option<u16>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct TunConfig {
    enable: bool,
    wintun_path: Option<String>,
    ipv4_address: Option<String>,
    dns: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct RealityConfigRaw {
    sni: String,
    fp: String,
    pbk: String,
    sid: String,
    spx: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct RealityServerConfigRaw {
    #[serde(default)]
    enabled: bool,
    dest: String,
    private_key: String,
    pbk: String,
    sid: String,
    sni_list: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct OutboundConfig {
    enabled: bool,
    protocol: String,
    address: String,
    port: u16,
    #[serde(default)]
    rules: Vec<OutboundRule>,
    default_action: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct OutboundRule {
    domain_suffix: Option<Vec<String>>,
    ip_cidr: Option<Vec<String>>,
    action: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ExcludeConfig {
    domains: Option<Vec<String>>,
    ips: Option<Vec<String>>,
    processes: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Serialize)]
struct MuxConfig {
    enabled: Option<bool>,
    sessions: Option<usize>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize structured logging via tracing
    // Default: info level; override with RUST_LOG env var (e.g. RUST_LOG=ostp_server=debug)
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
        )
        .with_target(false)
        .compact()
        .init();

    let res = run_app().await;
    if let Err(e) = res {
        eprintln!();
        eprintln!("[ostp] Fatal error: {}", e);
        eprintln!();
        
        #[cfg(target_os = "windows")]
        {
            println!("\nPress ENTER key to close this window...");
            let mut dummy = String::new();
            let _ = std::io::stdin().read_line(&mut dummy);
        }
        std::process::exit(1);
    }
    Ok(())
}

#[allow(dead_code)]
fn is_private_ip(ip: &str) -> bool {
    ip.starts_with("10.") 
    || ip.starts_with("192.168.") 
    || ip.starts_with("127.")
    || (ip.starts_with("172.") && {
        let parts: Vec<&str> = ip.split('.').collect();
        if parts.len() >= 2 {
            if let Ok(second) = parts[1].parse::<u8>() {
                (16..=31).contains(&second)
            } else { false }
        } else { false }
    })
}

fn detect_local_public_ip() -> Option<String> {
    #[cfg(not(target_os = "windows"))]
    {
        let out = std::process::Command::new("ip")
            .args(["-4", "addr", "show", "scope", "global"])
            .output()
            .ok()?;
        
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            if let Some(idx) = line.find("inet ") {
                let substr = &line[idx + 5..];
                let ip = substr.split(|c: char| c == '/' || c.is_whitespace()).next().unwrap_or("");
                if !ip.is_empty() && !is_private_ip(ip) {
                    return Some(ip.to_string());
                }
            }
        }
    }
    None
}

fn get_or_ask_public_ip(config_path: &std::path::Path) -> String {
    let config_dir = config_path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let cache_path = config_dir.join(".ostp_public_ip");

    if cache_path.exists() {
        if let Ok(cached) = std::fs::read_to_string(&cache_path) {
            let ip = cached.trim().to_string();
            if !ip.is_empty() {
                return ip;
            }
        }
    }

    if let Some(detected) = detect_local_public_ip() {
        println!("[ostp] Detected public IP: {}", detected);
        let _ = std::fs::write(&cache_path, &detected);
        return detected;
    }

    print!("\n[ostp] Could not detect the server public IP automatically.\n");
    print!("  Enter your public IP or domain: ");
    use std::io::Write;
    let _ = std::io::stdout().flush();

    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_ok() {
        let ip = input.trim().to_string();
        if !ip.is_empty() {
            let _ = std::fs::write(&cache_path, &ip);
            return ip;
        }
    }

    "<YOUR_SERVER_PUBLIC_IP>".to_string()
}

async fn run_app() -> Result<()> {
    let args = Args::parse();

    if args.uninstall {
        return cmd_uninstall();
    }

    if args.update {
        return cmd_update();
    }

    if args.generate_key {
        let mut new_keys = Vec::new();
        for _ in 0..args.count {
            let key = generate_secure_key(&args.format);
            println!("{}", key);
            new_keys.push(key);
        }

        // Автоматическое добавление ключа в config.json если это сервер
        if args.config.exists() {
            if let Ok(content) = fs::read_to_string(&args.config) {
                let mut stripped = json_comments::StripComments::new(content.as_bytes());
                let mut content_str = String::new();
                use std::io::Read;
                if stripped.read_to_string(&mut content_str).is_ok() {
                    if let Ok(mut json_val) = serde_json::from_str::<serde_json::Value>(&content_str) {
                        if let Some(mode) = json_val.get("mode").and_then(|m| m.as_str()) {
                            if mode == "server" {
                                if let Some(access_keys) = json_val.get_mut("access_keys").and_then(|a| a.as_array_mut()) {
                                    for key in new_keys {
                                        access_keys.push(serde_json::Value::String(key));
                                    }
                                    if let Ok(new_content) = serde_json::to_string_pretty(&json_val) {
                                        let _ = fs::write(&args.config, new_content);
                                        println!("[ostp] Key(s) automatically added to {:?}", args.config);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        return Ok(());
    }

    if let Some(url) = args.url {
        println!("[ostp] Connecting via share link...");
        let client_cfg = parse_ostp_link(&url)
            .map_err(|e| anyhow!("Share Link Error: {e}"))?;
        return run_client_directly(client_cfg).await;
    }

    // Handle --check: validate config and exit
    if args.check {
        if !args.config.exists() {
            anyhow::bail!("Configuration file {:?} not found.", args.config);
        }
        let content = fs::read_to_string(&args.config)?;
        let mut stripped = json_comments::StripComments::new(content.as_bytes());
        match serde_json::from_reader::<_, UnifiedConfig>(&mut stripped) {
            Ok(config) => {
                config.validate()?;
                match &config.mode {
                    AppMode::Server(s) => {
                        println!("[ostp] Config OK: server mode");
                        println!("  Listen: {:?}", s.listen.primary());
                        println!("  Access keys: {}", s.access_keys.len());
                        if let Some(api) = &s.api {
                            println!("  API: {} (bind: {})",
                                if api.enabled.unwrap_or(false) { "enabled" } else { "disabled" },
                                api.bind.as_deref().unwrap_or("127.0.0.1:9090"));
                        }
                        if let Some(outbound) = &s.outbound {
                            println!("  Outbound proxy: {} ({})",
                                if outbound.enabled { "enabled" } else { "disabled" },
                                outbound.protocol);
                        }
                        if let Some(fb) = &s.fallback {
                            println!("  Fallback: {} ({} -> {})",
                                if fb.enabled.unwrap_or(false) { "enabled" } else { "disabled" },
                                fb.listen.as_deref().unwrap_or("0.0.0.0:443"),
                                fb.target.as_deref().unwrap_or("127.0.0.1:8080"));
                        }
                    }
                    AppMode::Client(c) => {
                        println!("[ostp] Config OK: client mode");
                        println!("  Server: {}", c.server);
                        println!("  Key: {}...", &c.access_key[..8.min(c.access_key.len())]);
                    }
                    AppMode::Relay(r) => {
                        println!("[ostp] Config OK: relay mode");
                        println!("  Listen: {:?}", r.listen.primary());
                        println!("  Upstream TCP: {}", r.upstream_tcp);
                        println!("  Upstream UDP: {}", r.upstream_udp);
                        println!("  API sync: {}", r.upstream_api_url);
                    }
                }
            }
            Err(e) => {
                anyhow::bail!("Config parse error: {}", e);
            }
        }
        return Ok(());
    }

    // Handle explicit configuration initialization
    if let Some(ref mode_str) = args.init {
        let is_server = mode_str == "server";
        let key = generate_secure_key("hex");
        let content = if is_server {
            let (priv_key, pub_key, sid) = generate_reality_keys();
            format!(r#"{{
  // OSTP Server Configuration
  "mode": "server",
  "log_level": "info",
  
  // The address and port the server listens on for incoming OSTP connections.
  "listen": "0.0.0.0:50000",
  
  // List of valid keys. Clients must use one of these to connect.
  "access_keys": [
    "{}"
  ],
  
  // Optional proxy for outbound traffic.
  "outbound": {{
    "enabled": false,
    "protocol": "socks5",
    "address": "127.0.0.1",
    "port": 9050,
    // default_action: 'proxy' (all through proxy) or 'direct' (bypass proxy by default).
    "default_action": "proxy",
    "rules": [
      {{
        "domain_suffix": [".onion"],
        "action": "proxy"
      }}
    ]
  }},
  
  // Web control panel
  "api": {{
    "enabled": false,
    "bind": "0.0.0.0:9090",
    // Secret URL path to hide panel from scanners (e.g. "mySecret123")
    "webpath": "",
    // Login credentials for web panel (password stored as SHA256 hash)
    "username": "",
    "password_hash": ""
  }},
  
  // Fallback TCP proxy: unrecognized connections are proxied to a web server (anti-DPI).
  "fallback": {{
    "enabled": false,
    "listen": "0.0.0.0:443",
    // Target web server (e.g., local nginx or caddy)
    "target": "127.0.0.1:8080"
  }},

  // Reality (XTLS) / UoT Masquerade parameters
  "reality": {{
    "enabled": false,
    "dest": "www.microsoft.com:443",
    "private_key": "{}",
    "pbk": "{}",
    "sid": "{}",
    "sni_list": ["www.microsoft.com"]
  }},
  "debug": false
}}"#, key, priv_key, pub_key, sid)
        } else if mode_str == "relay" {
            r#"{
  // OSTP Relay Node Configuration
  "mode": "relay",
  "listen": "0.0.0.0:50000",
  "upstream_tcp": "TARGET_SERVER_IP:50000",
  "upstream_udp": "TARGET_SERVER_IP:50000",
  "upstream_api_url": "http://TARGET_SERVER_IP:9090",
  "upstream_api_token": "YOUR_API_TOKEN_HERE",
  "sync_interval_secs": 30,
  "debug": false
}"#.to_string()
        } else {
            format!(r#"{{
  // OSTP Client Configuration
  "mode": "client",
  "log_level": "info",
  
  // Address of the remote OSTP server
  "server": "127.0.0.1:50000",
  
  // Must match one of the access_keys on the server
  "access_key": "{}",
  
  // The local port for HTTP/SOCKS5 proxying
  "socks5_bind": "127.0.0.1:1088",
  
  // Virtual network adapter settings
  "tun": {{
    "enable": false,
    "wintun_path": "./wintun.dll",
    "ipv4_address": "10.1.0.2/24",
    "dns": "1.1.1.1"
  }},
  
  // Bypass tunnel for these domains/IPs
  "exclude": {{
    "domains": ["localhost", "127.0.0.1"],
    "ips": [],
    "processes": []
  }},
  
  // Reality (XTLS) / WebRTC Masquerade parameters
  "reality": {{
    "dest": "www.microsoft.com:443",
    "private_key": "",
    "pbk": "",
    "sid": "",
    "sni_list": ["www.microsoft.com"]
  }},
  
  // Transport Mode: "udp" (default WebRTC masquerade) or "uot" (TCP XTLS-Reality)
  "transport": {{
    "mode": "udp",
    "stealth_sni": "www.microsoft.com",
    "stealth_port": 443
  }},
  
  "mux": {{
    "enabled": false,
    "sessions": 1
  }},
  "debug": false
}}"#, key)
        };
        if let Some(parent) = args.config.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        fs::write(&args.config, &content)?;
        println!("[ostp] Configuration written to {:?}", args.config);
        
        if is_server {
            let mut stripped = json_comments::StripComments::new(content.as_bytes());
            if let Ok(config) = serde_json::from_reader::<_, UnifiedConfig>(&mut stripped) {
                if let AppMode::Server(s) = &config.mode {
                    let key = &s.access_keys[0];
                    let host = get_or_ask_public_ip(&args.config);
                    let mut link = format!("ostp://{}@{}:50000", key.key(), host);
                    let mut query_params = Vec::new();
                    
                    if let Some(r) = &s.reality {
                        if r.enabled {
                            query_params.push("security=reality".to_string());
                            query_params.push(format!("sni={}", r.sni_list.first().unwrap_or(&String::new())));
                            query_params.push(format!("pbk={}", r.pbk));
                            if !r.sid.is_empty() {
                                query_params.push(format!("sid={}", r.sid));
                            }
                        }
                    }
                    
                    if let Some(t) = &s.transport {
                        if let Some(mode) = &t.mode {
                            if mode == "uot" {
                                query_params.push("type=tcp".to_string());
                            } else {
                                query_params.push("type=udp".to_string());
                            }
                        }
                        if let Some(sni) = &t.stealth_sni {
                            // If reality is not enabled, add stealth_sni to link so client configures it
                            let reality_enabled = s.reality.as_ref().map(|r| r.enabled).unwrap_or(false);
                            if !reality_enabled && !sni.is_empty() {
                                query_params.push(format!("sni={}", sni));
                            }
                        }
                    } else {
                        query_params.push("type=udp".to_string());
                    }

                    if !query_params.is_empty() {
                        link.push('?');
                        link.push_str(&query_params.join("&"));
                    }
                    println!("\n  Share link for client distribution:");
                    println!("  {}", link);
                }
            }
        }
        return Ok(());
    }

    // Validate config file existence
    if !args.config.exists() {
        anyhow::bail!(
            "Configuration file {:?} not found.\n\n\
             To generate a default configuration template, run:\n\
             \t./ostp --init server\n\
             \tor\n\
             \t./ostp --init client\n\n\
             Or specify a custom configuration file path using:\n\
             \t./ostp --config /path/to/your_config.json",
            args.config
        );
    }

    let config_content = fs::read_to_string(&args.config)?;
    let mut stripped = json_comments::StripComments::new(config_content.as_bytes());
    let config: UnifiedConfig = serde_json::from_reader(&mut stripped)
        .map_err(|e| anyhow!("Failed to parse config: {}", e))?;

    config.validate()?;

    if args.links {
        match config.mode {
            AppMode::Server(server_cfg) => {
                let listen = server_cfg.listen.primary();
                let parts: Vec<&str> = listen.split(':').collect();
                let port = parts.get(1).unwrap_or(&"50000");
                let host = if parts[0] == "0.0.0.0" { 
                    get_or_ask_public_ip(&args.config) 
                } else { 
                    parts[0].to_string() 
                };
                
                println!("\n  Client share links from {:?}:", args.config);
                for (idx, key) in server_cfg.access_keys.iter().enumerate() {
                    let mut link = format!("ostp://{}@{}:{}", key.key(), host, port);
                    if let Some(r) = &server_cfg.reality {
                        link = format!("{}?security=reality&sni={}&pbk={}&sid={}&type=udp", link, r.sni_list.first().unwrap_or(&String::new()), r.pbk, r.sid);
                    }
                    println!("  [{}] {}", idx + 1, link);
                }
                return Ok(());
            }
            AppMode::Client(_) => {
                anyhow::bail!("The configuration file is in Client mode. The --links flag can only extract keys from a Server configuration.");
            }
            AppMode::Relay(_) => {
                anyhow::bail!("The configuration file is in Relay mode. The --links flag only works with Server configuration.");
            }
        }
    }

    match config.mode {
        AppMode::Server(server_cfg) => {
            let listen_addrs = server_cfg.listen.addresses();
            println!("[ostp] Starting server on {:?}", listen_addrs);
            if let Some(ref reality) = server_cfg.reality {
                if reality.enabled {
                    println!("[ostp] Reality mode enabled (dest: {})", reality.dest);
                }
            }
            let debug = server_cfg.debug.unwrap_or(false);
            let outbound = server_cfg.outbound.map(|o| ostp_server::OutboundConfig {
                enabled: o.enabled,
                protocol: o.protocol,
                address: o.address,
                port: o.port,
                rules: o
                    .rules
                    .into_iter()
                    .map(|r| ostp_server::OutboundRule {
                        domain_suffix: r.domain_suffix.unwrap_or_default(),
                        ip_cidr: r.ip_cidr.unwrap_or_default(),
                        action: parse_outbound_action(r.action),
                    })
                    .collect(),
                default_action: parse_outbound_action(o.default_action),
            });
            let api_config = server_cfg.api.map(|a| ostp_server::ApiConfig {
                enabled: a.enabled.unwrap_or(false),
                bind: a.bind.unwrap_or_else(|| "127.0.0.1:9090".to_string()),
                webpath: a.webpath.unwrap_or_default(),
                username: a.username.unwrap_or_default(),
                password_hash: a.password_hash.unwrap_or_default(),
            });
            let fallback_config = server_cfg.fallback.map(|f| ostp_server::FallbackConfig {
                enabled: f.enabled.unwrap_or(false),
                listen: f.listen.unwrap_or_else(|| "0.0.0.0:443".to_string()),
                target: f.target.unwrap_or_else(|| "127.0.0.1:8080".to_string()),
            });
            let mut rq = None;
            let mut rc = None;
            if let Some(r) = server_cfg.reality {
                if r.enabled {
                    rq = Some(format!("?security=reality&sni={}&pbk={}&sid={}&type=udp", r.sni_list.first().unwrap_or(&String::new()), r.pbk, r.sid));
                    rc = Some(ostp_server::RealityServerConfig {
                        sni_list: r.sni_list.clone(),
                        dest: r.dest,
                        private_key: r.private_key,
                        pbk: r.pbk,
                        sid: r.sid,
                    });
                }
            }
            let access_keys_meta = server_cfg.access_keys.into_iter().map(|uc| {
                (uc.key(), ostp_server::api::UserMeta {
                    name: uc.name(),
                    limit_bytes: uc.limit(),
                })
            }).collect::<Vec<_>>();
            let host = get_or_ask_public_ip(&args.config);
            // Build DNS config and set owndns flag in subscribe links if DNS enabled
            let dns_cfg = server_cfg.dns;
            // Pass all listen addresses for multi-listener support
            ostp_server::run_server(listen_addrs, Some(host), access_keys_meta, outbound, api_config, fallback_config, debug, rq, rc, dns_cfg, Some(args.config)).await?;
        }
        AppMode::Client(client_cfg) => {
            run_client_directly(client_cfg).await?;
        }
        AppMode::Relay(relay_cfg) => {
            let listen_addrs = relay_cfg.listen.addresses();
            println!("[ostp] Starting relay node on {:?}", listen_addrs);
            println!("[ostp] Upstream TCP: {}", relay_cfg.upstream_tcp);
            println!("[ostp] Upstream UDP: {}", relay_cfg.upstream_udp);
            println!("[ostp] Key sync API: {}", relay_cfg.upstream_api_url);
            let relay_config = ostp_server::RelayConfig {
                listen_addrs,
                upstream_tcp: relay_cfg.upstream_tcp,
                upstream_udp: relay_cfg.upstream_udp,
                upstream_api_url: relay_cfg.upstream_api_url,
                upstream_api_token: relay_cfg.upstream_api_token,
                sync_interval_secs: relay_cfg.sync_interval_secs,
            };
            ostp_server::relay_node::run_relay_node(relay_config).await?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Uninstall command
// ---------------------------------------------------------------------------
#[cfg(unix)]
fn cmd_uninstall() -> Result<()> {
    use std::process::Command;

    println!("[ostp] Uninstalling OSTP...");

    // 1. Stop and disable systemd service (best-effort)
    for action in &["stop", "disable"] {
        let _ = Command::new("systemctl")
            .args([action, "ostp"])
            .status();
    }

    // 2. Remove the systemd unit file
    let unit_path = std::path::Path::new("/etc/systemd/system/ostp.service");
    if unit_path.exists() {
        fs::remove_file(unit_path)?;
        println!("[ostp] Removed {}", unit_path.display());
        let _ = Command::new("systemctl")
            .args(["daemon-reload"])
            .status();
    }

    // 3. Remove binary
    let bin_path = std::path::Path::new("/opt/ostp/ostp");
    if bin_path.exists() {
        fs::remove_file(bin_path)?;
        println!("[ostp] Removed {}", bin_path.display());
    }

    // 4. Remove install directory
    let install_dir = std::path::Path::new("/opt/ostp");
    if install_dir.exists() {
        fs::remove_dir_all(install_dir)?;
        println!("[ostp] Removed {}", install_dir.display());
    }

    // 5. Remove configuration directory
    let config_dir = std::path::Path::new("/etc/ostp");
    if config_dir.exists() {
        fs::remove_dir_all(config_dir)?;
        println!("[ostp] Removed {}", config_dir.display());
    }

    println!("[ostp] Uninstall complete.");
    Ok(())
}

#[cfg(not(unix))]
fn cmd_uninstall() -> Result<()> {
    anyhow::bail!("The 'uninstall' command is only supported on Linux/Unix systems.");
}

// ---------------------------------------------------------------------------
// Update command
// ---------------------------------------------------------------------------
#[cfg(unix)]
fn cmd_update() -> Result<()> {
    use std::process::Command;

    println!("[ostp] Updating OSTP...");
    let status = Command::new("bash")
        .args(["-c", "bash <(curl -Ls https://raw.githubusercontent.com/ospab/ostp/master/scripts/install.sh)"])
        .status()
        .map_err(|e| anyhow!("Failed to run update: {e}"))?;

    if !status.success() {
        anyhow::bail!("Update script exited with status: {}", status);
    }
    Ok(())
}

#[cfg(not(unix))]
fn cmd_update() -> Result<()> {
    anyhow::bail!("The 'update' command is only supported on Linux/Unix systems.");
}

async fn run_client_directly(client_cfg: ClientConfig) -> Result<()> {
    let is_tun_enabled = client_cfg.tun.as_ref().map(|t| t.enable).unwrap_or(false);
    let mode_str = if is_tun_enabled { "tun" } else { "proxy" };
    println!("[ostp] Starting client (mode={}, server={})", mode_str, client_cfg.server);
    let reality_cfg = client_cfg.reality.as_ref();
    let client_conf = ostp_client::config::ClientConfig {
        mode: if is_tun_enabled { "tun".to_string() } else { "proxy".to_string() },
        tun_stack: "native".to_string(),
        debug: client_cfg.debug.unwrap_or(false),
        ostp: ostp_client::config::OstpConfig {
            server_addr: client_cfg.server.clone(),
            local_bind_addr: "0.0.0.0:0".to_string(),
            access_key: client_cfg.access_key.clone(),
            handshake_timeout_ms: 5000,
            io_timeout_ms: 2500,
            mtu: client_cfg.mtu.unwrap_or(1350),
            keepalive_interval_sec: 5,
        },
        local_proxy: ostp_client::config::LocalProxyConfig {
            bind_addr: client_cfg.socks5_bind.clone().unwrap_or_else(|| "127.0.0.1:1088".to_string()),
            connect_timeout_ms: 5000,
        },
        reality: ostp_client::config::RealityConfig {
            sni: reality_cfg.map(|t| t.sni.clone()).unwrap_or_default(),
            fp: reality_cfg.map(|t| t.fp.clone()).unwrap_or_default(),
            pbk: reality_cfg.map(|t| t.pbk.clone()).unwrap_or_default(),
            sid: reality_cfg.map(|t| t.sid.clone()).unwrap_or_default(),
            spx: reality_cfg.map(|t| t.spx.clone()).unwrap_or_default(),
        },
        exclusions: ostp_client::config::ExclusionConfig {
            domains: client_cfg.exclude.as_ref().and_then(|e| e.domains.clone()).unwrap_or_default(),
            ips: client_cfg.exclude.as_ref().and_then(|e| e.ips.clone()).unwrap_or_default(),
            processes: client_cfg.exclude.as_ref().and_then(|e| e.processes.clone()).unwrap_or_default(),
        },
        multiplex: ostp_client::config::MultiplexConfig {
            enabled: client_cfg.mux.as_ref().and_then(|m| m.enabled).unwrap_or(false),
            sessions: client_cfg.mux.as_ref().and_then(|m| m.sessions).unwrap_or(1),
        },
        transport: ostp_client::config::TransportConfig {
            mode: client_cfg.transport.as_ref().and_then(|t| t.mode.clone()).unwrap_or_else(|| "udp".to_string()),
            stealth_sni: client_cfg.transport.as_ref().and_then(|t| t.stealth_sni.clone()).unwrap_or_else(|| "microsoft.com".to_string()),
            stealth_port: client_cfg.transport.as_ref().and_then(|t| t.stealth_port).unwrap_or(443),
        },
        dns_server: client_cfg.tun.as_ref().and_then(|t| t.dns.clone()),
    };

    // Run the client implementation
    ostp_client::runner::run_client(client_conf).await?;
    Ok(())
}
