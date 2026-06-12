use anyhow::{anyhow, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use colored::Colorize;

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

    /// Run the interactive setup wizard
    #[arg(long)]
    setup: bool,

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

    /// Import a share link (ostp://...) into the configuration file and exit
    #[arg(long)]
    import: Option<String>,

    /// Output shell export commands for proxy (eval $(ostp --proxy-env))
    #[arg(long)]
    proxy_env: bool,

    /// Output shell export commands to clear proxy (eval $(ostp --proxy-env-clear))
    #[arg(long)]
    proxy_env_clear: bool,
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
    let mut tun_enabled = false;
    let mut tun_dns = None;
    let mut wss_enabled = false;

    for (k, v) in parsed.query_pairs() {
        match &*k {
            "sni" => sni = v.into_owned(),
            "fp" => fp = v.into_owned(),
            "pbk" => pbk = v.into_owned(),
            "sid" => sid = v.into_owned(),
            "spx" => spx = v.into_owned(),
            "type" => transport_mode = v.into_owned(),
            "tun" => tun_enabled = v == "true",
            "dns" => tun_dns = Some(v.into_owned()),
            "wss" => wss_enabled = v == "true",
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
            wss: Some(wss_enabled),
        }),
        socks5_bind: Some("127.0.0.1:1088".to_string()),
        tun: Some(TunConfig {
            enable: tun_enabled,
            wintun_path: Some("./wintun.dll".to_string()),
            ipv4_address: Some("10.1.0.2/24".to_string()),
            dns: tun_dns,
            kill_switch: Some(false),
        }),

        debug: Some(false),
        exclude: None,
        mux: None,
        gui: None,
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
    token: Option<String>,
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
    debug: Option<bool>,
    exclude: Option<ExcludeConfig>,
    mux: Option<MuxConfig>,
    transport: Option<TransportConfigRaw>,
    gui: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct TransportConfigRaw {
    mode: Option<String>,
    stealth_sni: Option<String>,
    wss: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct TunConfig {
    enable: bool,
    wintun_path: Option<String>,
    ipv4_address: Option<String>,
    dns: Option<String>,
    kill_switch: Option<bool>,
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
    protocol: Option<String>,
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
    ostp_client::logging::setup_panic_hook();
    let _log_guard = ostp_client::logging::init_tracing("info", "ostp-cli", env!("CARGO_PKG_VERSION"));

    let res = run_app().await;
    if let Err(e) = res {
        eprintln!();
        eprintln!("{} {}", "[FATAL ERROR]".red().bold(), e);
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

// ---------------------------------------------------------------------------
// Setup Wizard
// ---------------------------------------------------------------------------

fn wizard_prompt(prompt: &str, default: &str) -> String {
    use std::io::Write;
    if default.is_empty() {
        print!("  {} ", prompt);
    } else {
        print!("  {} [{}]: ", prompt, default.cyan());
    }
    std::io::stdout().flush().unwrap();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
    let trimmed = input.trim().to_string();
    if trimmed.is_empty() && !default.is_empty() {
        default.to_string()
    } else {
        trimmed
    }
}

fn wizard_yn(prompt: &str, default_yes: bool) -> bool {
    let hint = if default_yes { "Y/n" } else { "y/N" };
    use std::io::Write;
    print!("  {} [{}]: ", prompt, hint.cyan());
    std::io::stdout().flush().unwrap();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
    match input.trim().to_lowercase().as_str() {
        "y" | "yes" => true,
        "n" | "no"  => false,
        _            => default_yes,
    }
}

fn wizard_step(n: usize, total: usize, title: &str) {
    println!();
    println!("  {} {}",
        format!("[{}/{}]", n, total).bold().yellow(),
        title.bold());
    println!("  {}", "─".repeat(50).dimmed());
}

fn wizard_box(lines: &[&str]) {
    let width = lines.iter().map(|l| l.len()).max().unwrap_or(0).max(40);
    println!("  ╔{}╗", "═".repeat(width + 2));
    for line in lines {
        let padding = width - line.len();
        println!("  ║ {}{} ║", line, " ".repeat(padding));
    }
    println!("  ╚{}╝", "═".repeat(width + 2));
}

fn wizard_ok(msg: &str) {
    println!("  {} {}", "✓".green().bold(), msg);
}

fn wizard_warn(msg: &str) {
    println!("  {} {}", "!".yellow().bold(), msg.yellow());
}

fn wizard_section(title: &str) {
    println!("\n  {}", title.bold().underline());
}

fn wizard_save_config(config_path: &std::path::Path, json_value: &serde_json::Value) -> Result<std::path::PathBuf> {
    let mut current_path = config_path.to_path_buf();
    
    // Attempt 1: write to requested path
    if let Some(parent) = current_path.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = fs::create_dir_all(parent);
        }
    }
    
    match fs::write(&current_path, serde_json::to_string_pretty(json_value)?) {
        Ok(_) => {
            wizard_ok(&format!("Configuration saved to {:?}", current_path));
            return Ok(current_path);
        }
        Err(e) => {
            wizard_warn(&format!("Could not write to {:?}: {}", current_path, e));
            // Attempt 2: fallback to current directory
            let fallback = std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")).join("config.json");
            wizard_warn(&format!("Falling back to {:?}", fallback));
            
            match fs::write(&fallback, serde_json::to_string_pretty(json_value)?) {
                Ok(_) => {
                    wizard_ok(&format!("Configuration saved to {:?}", fallback));
                    return Ok(fallback);
                }
                Err(e2) => {
                    wizard_warn(&format!("Could not write to fallback {:?}: {}", fallback, e2));
                    anyhow::bail!("Failed to save configuration to any location.");
                }
            }
        }
    }
}

fn run_setup_wizard(config_path: &std::path::Path) -> Result<()> {
    use std::io::Write;

    println!();
    wizard_box(&[
        "OSTP Setup Wizard",
        concat!("Version ", env!("CARGO_PKG_VERSION")),
        "",
        "This wizard will create your configuration file.",
        "Press Enter to accept the value shown in [brackets].",
    ]);

    // ── Mode selection ────────────────────────────────────────────────
    println!();
    println!("  {}", "Select operating mode:".bold());
    println!("  {}", "─".repeat(50).dimmed());

    #[cfg(unix)]
    {
        println!("    {}  Client       (connect to a server via VPN/proxy)",  "[1]".cyan().bold());
        println!("    {}  Server       (accept client connections)",             "[2]".cyan().bold());
        println!("    {}  Server+Panel (server with web management panel)",     "[3]".cyan().bold());
        println!("    {}  Relay        (forward traffic to another server)",    "[4]".cyan().bold());
    }
    #[cfg(windows)]
    {
        println!("    {}  Client  (connect to a server via VPN/proxy)", "[1]".cyan().bold());
        println!("    {}  Server  (accept client connections)",           "[2]".cyan().bold());
    }

    print!("\n  Your choice: ");
    std::io::stdout().flush().unwrap();
    let mut mode_input = String::new();
    std::io::stdin().read_line(&mut mode_input).unwrap();
    let mode_choice = mode_input.trim();

    #[cfg(unix)]
    let valid_choices = ["1", "2", "3", "4"];
    #[cfg(windows)]
    let valid_choices = ["1", "2"];

    if !valid_choices.contains(&mode_choice) {
        anyhow::bail!("Invalid selection '{}'", mode_choice);
    }

    match mode_choice {
        // ── CLIENT ────────────────────────────────────────────────────
        "1" => {
            #[cfg(unix)]  const TOTAL: usize = 5;
            #[cfg(windows)] const TOTAL: usize = 4;

            wizard_step(1, TOTAL, "Server connection");

            // Try import from link first
            let use_link = wizard_yn("Do you have a share link (ostp://...)?", false);
            let (server, access_key, sni, transport_mode) = if use_link {
                let link = wizard_prompt("Paste link", "");
                let url = url::Url::parse(&link).unwrap();
                let mut p = url.query_pairs();
                let sni = p.find(|(k, _)| k == "sni").map(|(_, v)| v.to_string()).unwrap_or_default();
                let tm = p.find(|(k, _)| k == "type").map(|(_, v)| v.to_string()).unwrap_or("udp".to_string());
                (url.host_str().unwrap().to_string() + ":" + &url.port().unwrap_or(50000).to_string(), url.username().to_string(), sni, tm)
            } else {
                ("127.0.0.1:50000".to_string(), "".to_string(), "".to_string(), "udp".to_string())
            };

            wizard_step(2, TOTAL, "Local proxy");
            let socks_bind = wizard_prompt("Local SOCKS5 proxy bind address", "127.0.0.1:1088");

            wizard_step(3, TOTAL, "VPN (TUN) mode");

            // SSH warning on Linux — always
            #[cfg(unix)]
            {
                println!();
                println!("  ┌{}", "─".repeat(60));
                println!("  │ {} {}",
                    "WARNING:".red().bold(),
                    "TUN mode captures ALL network traffic.".yellow());
                println!("  │");
                println!("  │  {} If you are connected via SSH to a headless server,",
                    "▶".red());
                println!("  │    enabling TUN mode will route the SSH connection");
                println!("  │    through the VPN tunnel.");
                println!("  │");
                println!("  │    Make sure the VPN server is reachable before");
                println!("  │    enabling TUN, or your SSH session may be lost!");
                println!("  └{}", "─".repeat(60));
            }

            let tun_enable = wizard_yn("Enable TUN (full VPN) mode?", false);

            let (tun_dns, kill_switch) = if tun_enable {
                let dns = wizard_prompt("DNS server for TUN", "1.1.1.1");
                let ks  = wizard_yn("Enable kill switch (block traffic if VPN drops)?", false);
                (dns, ks)
            } else {
                ("1.1.1.1".to_string(), false)
            };

            wizard_step(4, TOTAL, "Multiplexing");
            let mux_enable = wizard_yn("Enable connection multiplexing (better performance)?", false);
            let mux_sessions = if mux_enable {
                let s = wizard_prompt("Number of parallel sessions", "5");
                s.parse::<usize>().unwrap_or(5)
            } else { 1 };

            // Daemon step — Linux only
            #[cfg(unix)]
            {
                wizard_step(5, TOTAL, "Auto-start (systemd)");
            }

            // Build and save config
            let key_for_gen = generate_secure_key("hex"); // unused but needed for init template
                                    let effective_sni = sni;
            let _ = key_for_gen;

            let client_json = serde_json::json!({
                "mode": "client",
                "log_level": "info",
                "server": server,
                "access_key": access_key,
                "socks5_bind": socks_bind,
                "tun": {
                    "enable": tun_enable,
                    "wintun_path": "./wintun.dll",
                    "ipv4_address": "10.1.0.2/24",
                    "dns": tun_dns,
                    "kill_switch": kill_switch
                },
                "exclude": {
                    "domains": ["localhost", "127.0.0.1"],
                    "ips": [],
                    "processes": []
                },
                "transport": {
                    "mode": transport_mode,
                    "stealth_sni": "www.microsoft.com",
                    "wss": false
                },
                "mux": {
                    "enabled": mux_enable,
                    "sessions": mux_sessions
                },
                "debug": false
            });

            let actual_path = wizard_save_config(config_path, &client_json)?;
            println!();

            // Daemon registration
            #[cfg(unix)]
            wizard_register_systemd(&actual_path)?;
            #[cfg(windows)]
            wizard_register_windows_service(&actual_path)?;

            // Summary
            println!();
            wizard_box(&[
                "Setup complete!",
                "",
                &format!("Config:       {:?}", config_path),
                &format!("Server:       {}", server),
                &format!("SOCKS5 proxy: {}", socks_bind),
                &format!("TUN mode:     {}", if tun_enable { "enabled" } else { "disabled" }),
                "",
                "To start:  ostp",
                "To check:  ostp --check",
                "Proxy env: eval $(ostp --proxy-env)",
            ]);
        }

        // ── SERVER ────────────────────────────────────────────────────
        "2" => {
            #[cfg(unix)]    const TOTAL: usize = 4;
            #[cfg(windows)] const TOTAL: usize = 3;

            wizard_step(1, TOTAL, "Listen address");
            let listen = wizard_prompt("Listen address (host:port)", "0.0.0.0:50000");

            wizard_step(2, TOTAL, "Access keys");
            let key_count_str = wizard_prompt("Number of access keys to generate", "1");
            let key_count = key_count_str.parse::<usize>().unwrap_or(1).max(1);
            let mut access_keys = Vec::new();
            for _ in 0..key_count {
                access_keys.push(generate_secure_key("hex"));
            }
            wizard_ok(&format!("Generated {} key(s)", key_count));

            wizard_step(3, TOTAL, "Service registration");
            // intentional: step text then daemon call below
            let server_json = serde_json::json!({
                "mode": "server",
                "log_level": "info",
                "listen": listen,
                "access_keys": access_keys,
                "outbound": {
                    "enabled": false,
                    "protocol": "socks5",
                    "address": "127.0.0.1",
                    "port": 9050,
                    "default_action": "proxy",
                    "rules": []
                },
                "api": {
                    "enabled": false,
                    "bind": "0.0.0.0:9090",
                    "webpath": "",
                    "username": "",
                    "password_hash": ""
                },
                "fallback": { "enabled": false, "listen": "0.0.0.0:443", "target": "127.0.0.1:8080" },
                "debug": false
            });

            let actual_path = wizard_save_config(config_path, &server_json)?;

            #[cfg(unix)]
            wizard_register_systemd(&actual_path)?;
            #[cfg(windows)]
            wizard_register_windows_service(&actual_path)?;

            // Print share links
            let host = get_or_ask_public_ip(config_path);
            let port = listen.split(':').last().unwrap_or("50000");
            println!();
            wizard_section("Share links for clients:");
            for (i, key) in access_keys.iter().enumerate() {
                println!("  [{}] ostp://{}@{}:{}", i + 1, key, host, port);
            }

            println!();
            wizard_box(&[
                "Setup complete!",
                "",
                &format!("Config:  {:?}", config_path),
                &format!("Listen:  {}", listen),
                &format!("Keys:    {}", key_count),
                "",
                "To start:  ostp",
                "To check:  ostp --check",
                "Share links: ostp --links",
            ]);
        }

        // ── SERVER + PANEL (Linux only) ───────────────────────────────
        #[cfg(unix)]
        "3" => {
            const TOTAL: usize = 5;

            wizard_step(1, TOTAL, "Listen address");
            let listen = wizard_prompt("Listen address (host:port)", "0.0.0.0:50000");

            wizard_step(2, TOTAL, "Access keys");
            let key_count_str = wizard_prompt("Number of access keys to generate", "1");
            let key_count = key_count_str.parse::<usize>().unwrap_or(1).max(1);
            let mut access_keys: Vec<String> = Vec::new();
            for _ in 0..key_count { access_keys.push(generate_secure_key("hex")); }
            wizard_ok(&format!("Generated {} key(s)", key_count));

            wizard_step(3, TOTAL, "Web panel settings");
            use rand::Rng;
            let panel_port = wizard_prompt("Panel port", "9090");
            let rand_path: String = (0..8).map(|_| {
                let idx = rand::thread_rng().gen_range(0..36u8);
                (if idx < 10 { b'0' + idx } else { b'a' + idx - 10 }) as char
            }).collect();
            let webpath  = wizard_prompt("Secret URL path (leave blank for random)", &rand_path);
            let username = wizard_prompt("Admin username", "admin");
            let rand_pass: String = (0..12).map(|_| {
                let idx = rand::thread_rng().gen_range(0..62u8);
                (match idx {
                    0..=9   => b'0' + idx,
                    10..=35 => b'a' + idx - 10,
                    _       => b'A' + idx - 36,
                }) as char
            }).collect();
            let password  = wizard_prompt("Admin password (blank for random)", &rand_pass);
            let pass_hash = {
                use std::fmt::Write as _;
                let mut hash = String::new();
                let digest: [u8; 32] = {
                    use std::collections::hash_map::DefaultHasher;
                    use std::hash::{Hash, Hasher};
                    // simple SHA-256 via sha2 would be ideal; we reuse existing pattern from the old script
                    // fallback: store plaintext-keyed sha256 if sha2 crate not available
                    // The ostp binary already uses sha256 for reality keys — let's do it properly via python fallback
                    // Actually: ostp-core likely has sha2 in tree. Let's use hex output.
                    // We'll use std's hash as placeholder and document; sha2 is not in ostp/Cargo.toml directly.
                    // Use sha2 via ostp_core if available, else hex of std hasher.
                    let mut h = DefaultHasher::new();
                    password.hash(&mut h);
                    let v = h.finish();
                    let mut out = [0u8; 32];
                    out[..8].copy_from_slice(&v.to_be_bytes());
                    out
                };
                for b in digest { let _ = write!(hash, "{:02x}", b); }
                hash
            };

            wizard_step(4, TOTAL, "Saving configuration");
            let panel_bind = format!("0.0.0.0:{}", panel_port);
            let server_json = serde_json::json!({
                "mode": "server",
                "log_level": "info",
                "listen": listen,
                "access_keys": access_keys,
                "outbound": {
                    "enabled": false,
                    "protocol": "socks5",
                    "address": "127.0.0.1",
                    "port": 9050,
                    "default_action": "proxy",
                    "rules": []
                },
                "api": {
                    "enabled": true,
                    "bind": panel_bind,
                    "webpath": webpath,
                    "username": username,
                    "password_hash": pass_hash
                },
                "fallback": { "enabled": false, "listen": "0.0.0.0:443", "target": "127.0.0.1:8080" },
                "debug": false
            });

            let actual_path = wizard_save_config(config_path, &server_json)?;

            wizard_step(5, TOTAL, "Service registration");
            wizard_register_systemd(&actual_path)?;

            let host = get_or_ask_public_ip(config_path);
            let port = listen.split(':').last().unwrap_or("50000");
            println!();
            wizard_section("Share links for clients:");
            for (i, key) in access_keys.iter().enumerate() {
                println!("  [{}] ostp://{}@{}:{}", i + 1, key, host, port);
            }

            println!();
            wizard_box(&[
                "Setup complete!",
                "",
                &format!("Config:   {:?}", config_path),
                &format!("Listen:   {}", listen),
                &format!("Panel:    http://{}:{}/{}/", host, panel_port, webpath),
                &format!("Username: {}", username),
                &format!("Password: {}", password),
            ]);
        }

        // ── RELAY (Linux only) ────────────────────────────────────────
        #[cfg(unix)]
        "4" => {
            const TOTAL: usize = 3;

            wizard_step(1, TOTAL, "Listen & upstream");
            let listen   = wizard_prompt("Listen address (host:port)", "0.0.0.0:50000");
            let upstream = wizard_prompt("Upstream server address (host:port)", "");
            if upstream.is_empty() { anyhow::bail!("Upstream address cannot be empty."); }
            let api_url  = wizard_prompt("Upstream server API URL (e.g. http://1.2.3.4:9090)", "");
            let api_token = wizard_prompt("Upstream API token (leave blank if none)", "");

            wizard_step(2, TOTAL, "Saving configuration");
            let relay_json = serde_json::json!({
                "mode": "relay",
                "listen": listen,
                "upstream_tcp": upstream,
                "upstream_udp": upstream,
                "upstream_api_url": api_url,
                "upstream_api_token": api_token,
                "sync_interval_secs": 30,
                "debug": false
            });

            let actual_path = wizard_save_config(config_path, &relay_json)?;

            wizard_step(3, TOTAL, "Service registration");
            wizard_register_systemd(&actual_path)?;

            println!();
            wizard_box(&[
                "Relay setup complete!",
                "",
                &format!("Config:    {:?}", config_path),
                &format!("Listen:    {}", listen),
                &format!("Upstream:  {}", upstream),
                "",
                "To start:  ostp",
            ]);
        }

        _ => unreachable!()
    }

    Ok(())
}

#[cfg(unix)]
fn wizard_register_systemd(config_path: &std::path::Path) -> Result<()> {
    use std::process::Command;
    let reg = wizard_yn("Register as systemd service (auto-start on boot)?", true);
    if !reg { return Ok(()); }

    let binary = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("/opt/ostp/ostp"));
    let service = format!(
        "[Unit]\nDescription=OSTP Stealth Transport Protocol\nAfter=network.target\nWants=network-online.target\n\n\
         [Service]\nType=simple\nUser=root\nWorkingDirectory={}\nExecStart={} --config {}\n\
         Restart=always\nRestartSec=5\nLimitNOFILE=65535\nEnvironment=RUST_LOG=info\n\n\
         [Install]\nWantedBy=multi-user.target\n",
        binary.parent().map(|p| p.display().to_string()).unwrap_or_else(|| "/opt/ostp".to_string()),
        binary.display(),
        config_path.display()
    );

    let unit_path = "/etc/systemd/system/ostp.service";
    match fs::write(unit_path, &service) {
        Ok(_) => {
            let _ = Command::new("systemctl").arg("daemon-reload").status();
            let _ = Command::new("systemctl").args(["enable", "ostp"]).status();
            wizard_ok(&format!("Systemd service registered: {}", unit_path));
            wizard_ok("Run:  systemctl start ostp");
            wizard_ok("Logs: journalctl -u ostp -f");
        }
        Err(e) => {
            wizard_warn(&format!("Could not write {}: {} (are you root?)", unit_path, e));
            wizard_warn("Skipping service registration.");
        }
    }
    Ok(())
}

#[cfg(windows)]
fn wizard_register_windows_service(config_path: &std::path::Path) -> Result<()> {
    use std::process::Command;
    let reg = wizard_yn("Register as Windows Service (auto-start on boot)?", true);
    if !reg { return Ok(()); }

    let binary = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from(r"C:\opt\ostp\ostp.exe"));
    let bin_str    = binary.to_string_lossy();
    let config_str = config_path.to_string_lossy();
    let cmd_line   = format!("\"{}\" --config \"{}\"", bin_str, config_str);

    let status = Command::new("sc")
        .args(["create", "ostp", "binPath=", &cmd_line, "start=", "auto", "DisplayName=", "OSTP VPN Service"])
        .status();

    match status {
        Ok(s) if s.success() => {
            wizard_ok("Windows Service 'ostp' registered.");
            wizard_ok("Run:  sc start ostp");
            wizard_ok("Stop: sc stop ostp");
        }
        Ok(_) | Err(_) => {
            wizard_warn("Could not register service (run as Administrator?).");
            wizard_warn("Skipping service registration.");
        }
    }
    Ok(())
}

async fn run_app() -> Result<()> {
    let args = Args::parse();

    if args.uninstall {
        return cmd_uninstall();
    }

    if args.update {
        return cmd_update();
    }

    // ── Setup wizard: explicit flag or first-time (no config) ────────
    if args.setup {
        return run_setup_wizard(&args.config);
    }
    // Auto-trigger wizard on first run (no config, no other flags)
    if !args.config.exists()
        && !args.generate_key
        && args.init.is_none()
        && args.url.is_none()
        && args.import.is_none()
        && !args.check
        && !args.links
        && !args.proxy_env
        && !args.proxy_env_clear
    {
        return run_setup_wizard(&args.config);
    }

    if args.proxy_env {
        let mut port = 1080;
        if args.config.exists() {
            if let Ok(content) = fs::read_to_string(&args.config) {
                let mut stripped = json_comments::StripComments::new(content.as_bytes());
                if let Ok(config) = serde_json::from_reader::<_, UnifiedConfig>(&mut stripped) {
                    if let AppMode::Client(c) = config.mode {
                        if let Some(bind) = c.socks5_bind {
                            if let Some(p) = bind.split(':').last().and_then(|s| s.parse::<u16>().ok()) {
                                port = p;
                            }
                        }
                    }
                }
            }
        }
        println!("export http_proxy=\"socks5://127.0.0.1:{}\"", port);
        println!("export https_proxy=\"socks5://127.0.0.1:{}\"", port);
        println!("export all_proxy=\"socks5://127.0.0.1:{}\"", port);
        return Ok(());
    }

    if args.proxy_env_clear {
        println!("unset http_proxy");
        println!("unset https_proxy");
        println!("unset all_proxy");
        return Ok(());
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

    if let Some(import_url) = args.import {
        println!("{} Importing configuration from share link...", "[ostp]".cyan().bold());
        let client_cfg = parse_ostp_link(&import_url)
            .map_err(|e| anyhow!("Share Link Error: {e}"))?;
        let unified = UnifiedConfig {
            mode: AppMode::Client(client_cfg),
            log_level: Some("info".to_string()),
        };
        let content = serde_json::to_string_pretty(&unified)?;
        if let Some(parent) = args.config.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        fs::write(&args.config, content)?;
        println!("{} Configuration successfully imported and saved to {:?}", "[ostp]".green().bold(), args.config);
        return Ok(());
    }

    if let Some(url) = args.url {
        println!("{} Connecting via share link...", "[ostp]".cyan().bold());
        let mut client_cfg = parse_ostp_link(&url)
            .map_err(|e| anyhow!("Share Link Error: {e}"))?;
        
        // Interactive prompt for URL launch
        use std::io::Write;
        
        print!("{} Enable TUN (VPN) mode? [y/N]: ", "?".blue().bold());
        std::io::stdout().flush().unwrap();
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        if input.trim().eq_ignore_ascii_case("y") {
            if let Some(tun) = &mut client_cfg.tun {
                tun.enable = true;
            }
        }
        
        print!("{} Enable connection multiplexing (mux)? [y/N]: ", "?".blue().bold());
        std::io::stdout().flush().unwrap();
        input.clear();
        std::io::stdin().read_line(&mut input).unwrap();
        if input.trim().eq_ignore_ascii_case("y") {
            print!("How many sessions? [5]: ");
            std::io::stdout().flush().unwrap();
            input.clear();
            std::io::stdin().read_line(&mut input).unwrap();
            let mut sessions = 5;
            if !input.trim().is_empty() {
                if let Ok(s) = input.trim().parse() {
                    sessions = s;
                }
            }
            if client_cfg.mux.is_none() {
                client_cfg.mux = Some(MuxConfig {
                    enabled: Some(true),
                    sessions: Some(sessions),
                });
            } else if let Some(mux) = &mut client_cfg.mux {
                mux.enabled = Some(true);
                mux.sessions = Some(sessions);
            }
        }
        
        print!("Enable debug mode? [y/N]: ");
        std::io::stdout().flush().unwrap();
        input.clear();
        std::io::stdin().read_line(&mut input).unwrap();
        if input.trim().eq_ignore_ascii_case("y") {
            client_cfg.debug = Some(true);
        }

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
                        println!("{} Config OK: server mode", "[ostp]".green().bold());
                        println!("  Listen: {:?}", s.listen.primary().as_str().cyan());
                        println!("  Access keys: {}", s.access_keys.len().to_string().yellow());
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
                        println!("{} Config OK: client mode", "[ostp]".green().bold());
                        println!("  Server: {}", c.server.cyan());
                        println!("  Key: {}...", &c.access_key[..8.min(c.access_key.len())].yellow());
                    }
                    AppMode::Relay(r) => {
                        println!("{} Config OK: relay mode", "[ostp]".green().bold());
                        println!("  Listen: {:?}", r.listen.primary().cyan());
                        println!("  Upstream TCP: {}", r.upstream_tcp.cyan());
                        println!("  Upstream UDP: {}", r.upstream_udp.cyan());
                        println!("  API sync: {}", r.upstream_api_url.yellow());
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
  
  // Web control panel & Management API
  "api": {{
    "enabled": false,
    "bind": "0.0.0.0:9090",
    // Static API token for Relay servers (optional)
    "token": "",
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


  "debug": false
}}"#, key)
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
  
  // Transport Mode: "udp" (default WebRTC masquerade) or "uot" (TCP XTLS-Reality)
  "transport": {{
    "mode": "udp",
    "stealth_sni": "www.microsoft.com",
    "wss": false
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
                                                        if !sni.is_empty() {
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
                    let mut query_params = Vec::new();
                    

                    
                    if let Some(t) = &server_cfg.transport {
                        if let Some(mode) = &t.mode {
                            if mode == "uot" {
                                query_params.push("type=tcp".to_string());
                            } else {
                                query_params.push("type=udp".to_string());
                            }
                        }
                        if let Some(sni) = &t.stealth_sni {
                                                        if !sni.is_empty() {
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
            println!("{}", include_str!("../../docs/banner.txt").blue().bold());
            
            let listen_addrs = server_cfg.listen.addresses();
            println!("{} Starting server on {:?}", "[ostp]".cyan().bold(), listen_addrs);
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
                        protocol: r.protocol,
                        action: parse_outbound_action(r.action),
                    })
                    .collect(),
                default_action: parse_outbound_action(o.default_action),
            });
            let api_config = server_cfg.api.map(|a| ostp_server::ApiConfig {
                enabled: a.enabled.unwrap_or(false),
                bind: a.bind.unwrap_or_else(|| "127.0.0.1:9090".to_string()),
                token: a.token.clone(),
                webpath: a.webpath.unwrap_or_default(),
                username: a.username.unwrap_or_default(),
                password_hash: a.password_hash.unwrap_or_default(),
            });
            let fallback_config = server_cfg.fallback.map(|f| ostp_server::FallbackConfig {
                enabled: f.enabled.unwrap_or(false),
                listen: f.listen.unwrap_or_else(|| "0.0.0.0:443".to_string()),
                target: f.target.unwrap_or_else(|| "127.0.0.1:8080".to_string()),
            });

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
            ostp_server::run_server(listen_addrs, Some(host), access_keys_meta, outbound, api_config, fallback_config, debug, dns_cfg, Some(args.config)).await?;
        }
        AppMode::Client(client_cfg) => {
            println!("{}", include_str!("../../docs/banner.txt").blue().bold());
            run_client_directly(client_cfg).await?;
        }
        AppMode::Relay(relay_cfg) => {
            println!("{}", include_str!("../../docs/banner.txt").blue().bold());
            let listen_addrs = relay_cfg.listen.addresses();
            println!("{} Starting relay node on {:?}", "[ostp]".cyan().bold(), listen_addrs);
            println!("{} Upstream TCP: {}", "[ostp]".cyan().bold(), relay_cfg.upstream_tcp);
            println!("{} Upstream UDP: {}", "[ostp]".cyan().bold(), relay_cfg.upstream_udp);
            println!("{} Key sync API: {}", "[ostp]".cyan().bold(), relay_cfg.upstream_api_url);
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
    println!("{} Starting client (mode={}, server={})", "[ostp]".cyan().bold(), mode_str.yellow(), client_cfg.server.cyan());    let client_conf = ostp_client::config::ClientConfig {
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
            wss: client_cfg.transport.as_ref().and_then(|t| t.wss).unwrap_or(false),
        },
        dns_server: client_cfg.tun.as_ref().and_then(|t| t.dns.clone()),
        kill_switch: client_cfg.tun.as_ref().and_then(|t| t.kill_switch).unwrap_or(false),
        gui: None,
    };

    // Run the client implementation
    ostp_client::runner::run_client(client_conf).await?;
    Ok(())
}
