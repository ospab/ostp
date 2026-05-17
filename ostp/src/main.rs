use anyhow::{anyhow, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about = "OSTP Core - Ospab Stealth Transport Protocol", long_about = None)]
struct Args {
    /// Path to the JSON configuration file
    #[arg(long, default_value = "config.json")]
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

    Ok(ClientConfig {
        server,
        access_key,
        socks5_bind: Some("127.0.0.1:1088".to_string()), // Fallback to standard SOCKS5 port
        tun: Some(TunConfig {
            enable: false, // Default to proxy, configurable via settings GUI
            wintun_path: Some("./wintun.dll".to_string()),
            ipv4_address: Some("10.1.0.2/24".to_string()),
            dns: None,
        }),
        turn: None,
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
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct ServerConfig {
    listen: ListenConfig,
    access_keys: Vec<String>,
    turn_server: Option<String>,
    debug: Option<bool>,
    outbound: Option<OutboundConfig>,
    api: Option<ApiConfig>,
    fallback: Option<FallbackCfg>,
}

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
    token: Option<String>,
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
    socks5_bind: Option<String>,
    tun: Option<TunConfig>,
    turn: Option<TurnConfigRaw>,
    debug: Option<bool>,
    exclude: Option<ExcludeConfig>,
    mux: Option<MuxConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct TunConfig {
    enable: bool,
    wintun_path: Option<String>,
    ipv4_address: Option<String>,
    dns: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct TurnConfigRaw {
    enabled: bool,
    server_addr: String,
    username: Option<String>,
    access_key: Option<String>,
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
    
    if args.generate_key {
        for _ in 0..args.count {
            println!("{}", generate_secure_key(&args.format));
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
  
  // Management REST API for third-party panels.
  "api": {{
    "enabled": false,
    "bind": "127.0.0.1:9090",
    // Set a strong token for authentication. Leave empty to disable auth.
    "token": ""
  }},
  
  // Fallback TCP proxy: unrecognized connections are proxied to a web server (anti-DPI).
  "fallback": {{
    "enabled": false,
    "listen": "0.0.0.0:443",
    // Target web server (e.g., local nginx or caddy)
    "target": "127.0.0.1:8080"
  }},
  "debug": false
}}"#, key)
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
  
  // STUN/TURN server settings to bypass UDP blocks by mimicking WebRTC call traffic
  "turn": {{
    "enabled": false,
    "server_addr": "127.0.0.1:3478",
    "username": "ostpuser",
    "access_key": "ostppassword"
  }},
  
  "mux": {{
    "enabled": false,
    "sessions": 1
  }},
  "debug": false
}}"#, key)
        };
        fs::write(&args.config, &content)?;
        println!("[ostp] Configuration written to {:?}", args.config);
        
        if is_server {
            let mut stripped = json_comments::StripComments::new(content.as_bytes());
            if let Ok(config) = serde_json::from_reader::<_, UnifiedConfig>(&mut stripped) {
                if let AppMode::Server(s) = config.mode {
                    let key = &s.access_keys[0];
                    let host = get_or_ask_public_ip(&args.config);
                    println!("\n  Share link for client distribution:");
                    println!("  ostp://{}@{}:50000", key, host);
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
                    println!("  [{}] ostp://{}@{}:{}", idx + 1, key, host, port);
                }
                return Ok(());
            }
            AppMode::Client(_) => {
                anyhow::bail!("The configuration file is in Client mode. The --links flag can only extract keys from a Server configuration.");
            }
        }
    }

    match config.mode {
        AppMode::Server(server_cfg) => {
            let listen_addrs = server_cfg.listen.addresses();
            println!("[ostp] Starting server on {:?}", listen_addrs);
            if let Some(turn) = server_cfg.turn_server {
                println!("[ostp] TURN relay enabled: {}", turn);
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
                token: a.token.unwrap_or_default(),
            });
            let fallback_config = server_cfg.fallback.map(|f| ostp_server::FallbackConfig {
                enabled: f.enabled.unwrap_or(false),
                listen: f.listen.unwrap_or_else(|| "0.0.0.0:443".to_string()),
                target: f.target.unwrap_or_else(|| "127.0.0.1:8080".to_string()),
            });
            // Pass all listen addresses for multi-listener support
            ostp_server::run_server(listen_addrs, server_cfg.access_keys, outbound, api_config, fallback_config, debug).await?;
        }
        AppMode::Client(client_cfg) => {
            run_client_directly(client_cfg).await?;
        }

    }

    Ok(())
}

async fn run_client_directly(client_cfg: ClientConfig) -> Result<()> {
    let is_tun_enabled = client_cfg.tun.as_ref().map(|t| t.enable).unwrap_or(false);
    let mode_str = if is_tun_enabled { "tun" } else { "proxy" };
    println!("[ostp] Starting client (mode={}, server={})", mode_str, client_cfg.server);
    let turn_cfg = client_cfg.turn.as_ref();
    let client_conf = ostp_client::config::ClientConfig {
        mode: if is_tun_enabled { "tun".to_string() } else { "proxy".to_string() },
        debug: client_cfg.debug.unwrap_or(false),
        ostp: ostp_client::config::OstpConfig {
            server_addr: client_cfg.server.clone(),
            local_bind_addr: "0.0.0.0:0".to_string(),
            access_key: client_cfg.access_key.clone(),
            handshake_timeout_ms: 5000,
            io_timeout_ms: 5000,
        },
        local_proxy: ostp_client::config::LocalProxyConfig {
            bind_addr: client_cfg.socks5_bind.clone().unwrap_or_else(|| "127.0.0.1:1088".to_string()),
            connect_timeout_ms: 5000,
        },
        turn: ostp_client::config::TurnConfig {
            enabled: turn_cfg.map(|t| t.enabled).unwrap_or(false),
            server_addr: turn_cfg.map(|t| t.server_addr.clone()).unwrap_or_default(),
            username: turn_cfg.and_then(|t| t.username.clone()).unwrap_or_default(),
            access_key: turn_cfg.and_then(|t| t.access_key.clone()).unwrap_or_default(),
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
        dns_server: client_cfg.tun.as_ref().and_then(|t| t.dns.clone()),
    };
    // Run the client implementation
    ostp_client::runner::run_client(client_conf).await?;
    Ok(())
}
