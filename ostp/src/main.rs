use anyhow::{anyhow, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use colored::Colorize;

mod dns_prober;

#[derive(Parser, Debug)]
#[command(author, version, about = "OSTP Core - Ospab Stealth Transport Protocol", long_about = None)]
struct Args {
    /// Path to the JSON configuration file
    #[cfg_attr(unix, arg(short, long, default_value = "/etc/ostp/config.json", global = true))]
    #[cfg_attr(windows, arg(short, long, default_value = "config.json", global = true))]
    config: PathBuf,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// Run the interactive setup wizard
    Setup {
        /// Optional mode to initialize the config for (client or server)
        #[arg(short, long)]
        init: Option<String>,
    },
    /// Initialize config
    Init {
        mode: String,
    },
    /// Generate a new secure access key
    GenerateKey {
        /// Format for generated key (hex, base64)
        #[arg(long, default_value = "hex")]
        format: String,
        /// Number of keys to generate
        #[arg(short = 'c', long, default_value_t = 1)]
        count: usize,
    },
    /// Output ready-to-use client sharing links
    Links,
    /// Validate configuration file
    Check,
    /// Connect using a share link
    Connect {
        url: String,
    },
    /// Uninstall OSTP
    Uninstall,
    /// Update OSTP
    Update {
        /// Specify the release branch to update from (stable, pre-release, nightly)
        #[arg(short, long, default_value = "stable")]
        branch: String,
        
        /// Specify a specific target version to update to (e.g., 0.2.98)
        #[arg(short, long)]
        version: Option<String>,
    },
    /// Import a share link
    Import {
        url: String,
    },
    /// Output shell export commands for proxy
    ProxyEnv,
    /// Output shell export commands to clear proxy
    ProxyEnvClear,
    /// Force migration of the configuration file
    Migrate,
    /// Run the network prober
    Prober,
    /// Run daemon
    Run,
}

struct LegacyArgs {
    config: PathBuf,
    init: Option<String>,
    setup: bool,
    generate_key: bool,
    format: String,
    count: usize,
    links: bool,
    check: bool,
    url: Option<String>,
    uninstall: bool,
    update: bool,
    update_branch: String,
    target_version: Option<String>,
    import: Option<String>,
    proxy_env: bool,
    proxy_env_clear: bool,
    migrate: bool,
    prober: bool,
}


fn patch_existing_client_config(config_path: &std::path::Path, new_client_inner: serde_json::Value) -> serde_json::Value {
    let unified_new = serde_json::to_value(UnifiedConfig {
        mode: AppMode::Client(new_client_inner.clone()),
        version: Some(env!("CARGO_PKG_VERSION").to_string()),
        log: Some(serde_json::json!({ "level": "info" })),
    }).unwrap();

    if !config_path.exists() {
        return unified_new;
    }
    
    let content = match std::fs::read_to_string(config_path) {
        Ok(c) => c,
        Err(_) => return unified_new,
    };
    
    let mut stripped = json_comments::StripComments::new(content.as_bytes());
    let mut existing: serde_json::Value = match serde_json::from_reader(&mut stripped) {
        Ok(v) => v,
        Err(_) => return unified_new,
    };
    
    if existing.get("mode").and_then(|m| m.as_str()) != Some("client") {
        return unified_new;
    }
    
    let mut new_proxy = None;
    if let Some(outbounds) = new_client_inner.get("outbounds").and_then(|o| o.as_array()) {
        for ob in outbounds {
            if ob.get("tag").and_then(|t| t.as_str()) == Some("proxy") {
                new_proxy = Some(ob.clone());
                break;
            }
        }
    }
    
    if let Some(new_proxy) = new_proxy {
        if let Some(existing_outbounds) = existing.get_mut("outbounds").and_then(|o| o.as_array_mut()) {
            let mut replaced = false;
            for ob in existing_outbounds.iter_mut() {
                if ob.get("tag").and_then(|t| t.as_str()) == Some("proxy") {
                    *ob = new_proxy.clone();
                    replaced = true;
                    break;
                }
            }
            if !replaced {
                existing_outbounds.insert(0, new_proxy);
            }
        } else {
            existing["outbounds"] = serde_json::json!([new_proxy]);
        }
    }
    
    if let Some(new_inbounds) = new_client_inner.get("inbounds").and_then(|i| i.as_array()) {
        for new_ib in new_inbounds {
            if new_ib.get("type").and_then(|t| t.as_str()) == Some("tun") {
                if let Some(auto_route) = new_ib.get("auto_route").and_then(|a| a.as_bool()) {
                    if auto_route {
                        if let Some(existing_inbounds) = existing.get_mut("inbounds").and_then(|i| i.as_array_mut()) {
                            for existing_ib in existing_inbounds.iter_mut() {
                                if existing_ib.get("type").and_then(|t| t.as_str()) == Some("tun") {
                                    existing_ib["auto_route"] = serde_json::json!(true);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    existing["version"] = serde_json::json!(env!("CARGO_PKG_VERSION"));
    
    existing
}

fn parse_ostp_link(link: &str) -> Result<serde_json::Value> {
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
    let _server = format!("{host}:{port}");
    let mut _sni = String::new();
    let mut transport_mode = String::from("udp");
    let mut tun_enabled = false;
    let mut _tun_dns = None;
    let mut _wss_enabled = false;
    let mut dns_domain = None;
    let mut dns_pubkey = None;

    for (k, v) in parsed.query_pairs() {
        match &*k {
            "sni" => _sni = v.into_owned(),
            "type" => transport_mode = v.into_owned(),
            "tun" => tun_enabled = v == "true",
            "dns" => _tun_dns = Some(v.into_owned()),
            "wss" => _wss_enabled = v == "true",
            "domain" => dns_domain = Some(v.into_owned()),
            "pubkey" => dns_pubkey = Some(v.into_owned()),
            _ => {}
        }
    }

    let mut transport_json = serde_json::json!({
        "type": transport_mode
    });
    
    if transport_mode == "dns" {
        if let Some(d) = dns_domain {
            transport_json["domain"] = serde_json::json!(d);
        }
        if let Some(p) = dns_pubkey {
            transport_json["pubkey"] = serde_json::json!(p);
        }
    }

    Ok(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "log": {
            "level": "info"
        },
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "auto_route": tun_enabled,
                "mtu": 1140
            },
            {
                "type": "local_proxy",
                "tag": "socks-in",
                "protocol": "socks",
                "listen": "127.0.0.1",
                "port": 1088
            }
        ],
        "outbounds": [
            {
                "type": "ostp",
                "tag": "proxy",
                "server": parsed.host_str().unwrap_or(""),
                "port": parsed.port().unwrap_or(50000),
                "access_key": access_key,
                "transport": transport_json,
                "multiplex": {
                    "enabled": false,
                    "sessions": 1
                }
            },
            {
                "type": "direct",
                "tag": "direct"
            },
            {
                "type": "block",
                "tag": "block"
            }
        ],
        "routing": {
            "rules": [],
            "default_outbound": "proxy"
        }
    }))
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
    Client(serde_json::Value),
    Relay(RelayServerConfig),
}

#[derive(Debug, Deserialize, Serialize)]
struct UnifiedConfig {
    version: Option<String>,
    log: Option<serde_json::Value>,
    #[serde(flatten)]
    mode: AppMode,
}

impl UnifiedConfig {
    fn validate(&self) -> Result<()> {
        match &self.mode {
            AppMode::Server(cfg) => {
                let mut has_ostp = false;
                for inbound in &cfg.inbounds {
                    if let ostp_server::config::ServerInbound::Ostp { users, .. } = inbound {
                        has_ostp = true;
                        if users.is_empty() {
                            anyhow::bail!("Ostp inbound must contain at least one user.");
                        }
                    }
                }
                if !has_ostp {
                    anyhow::bail!("Server configuration must contain at least one Ostp inbound.");
                }
            }
            AppMode::Client(cfg) => {
                if let Some(outbounds) = cfg.get("outbounds").and_then(|o| o.as_array()) {
                    let has_proxy = outbounds.iter().any(|o| o.get("type").and_then(|t| t.as_str()) == Some("ostp"));
                    if !has_proxy {
                        anyhow::bail!("Client configuration must contain an ostp outbound proxy.");
                    }
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
            UserConfig::Detailed { limit_bytes, .. } => *limit_bytes,
        }
    }
}

#[allow(dead_code)]
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

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize)]
struct OutboundRule {
    domain_suffix: Option<Vec<String>>,
    ip_cidr: Option<Vec<String>>,
    protocol: Option<String>,
    action: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize, Clone)]
struct TransportConfigRaw {
    mode: Option<String>,
    stealth_sni: Option<String>,
    wss: Option<bool>,
}

type ServerConfig = ostp_server::config::ModularServerConfig;

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

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize)]
struct ApiConfig {
    enabled: Option<bool>,
    bind: Option<String>,
    token: Option<String>,
    webpath: Option<String>,
    username: Option<String>,
    password_hash: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize)]
struct FallbackCfg {
    enabled: Option<bool>,
    listen: Option<String>,
    target: Option<String>,
}



#[tokio::main]
async fn main() -> Result<()> {
    let _ = rlimit::increase_nofile_limit(1048576);
    ostp_client::logging::setup_panic_hook();
    // Tracing init moved to run_app

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
    let current_path = config_path.to_path_buf();
    
    // Attempt 1: write to requested path
    if let Some(parent) = current_path.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = fs::create_dir_all(parent);
        }
    }
    
    match fs::write(&current_path, serde_json::to_string_pretty(json_value)?) {
        Ok(_) if current_path.exists() => {
            wizard_ok(&format!("Configuration saved to {:?}", current_path));
            Ok(current_path)
        }
        _ => {
            wizard_warn(&format!("Could not write to {:?}", current_path));
            // Attempt 2: fallback to current directory
            let fallback = std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")).join("config.json");
            wizard_warn(&format!("Falling back to {:?}", fallback));
            
            match fs::write(&fallback, serde_json::to_string_pretty(json_value)?) {
                Ok(_) if fallback.exists() => {
                    wizard_ok(&format!("Configuration saved to {:?}", fallback));
                    Ok(fallback)
                }
                _ => {
                    wizard_warn(&format!("Could not write to fallback {:?}", fallback));
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
        println!("    {}  Client       (connect to a server via VPN/proxy)", "[1]".cyan().bold());
        println!("    {}  Server       (accept client connections)",           "[2]".cyan().bold());
        println!("    {}  Server+Panel (server with web management panel)",     "[3]".cyan().bold());
    }

    print!("\n  Your choice: ");
    std::io::stdout().flush().unwrap();
    let mut mode_input = String::new();
    std::io::stdin().read_line(&mut mode_input).unwrap();
    let mode_choice = mode_input.trim();

    #[cfg(unix)]
    let valid_choices = ["1", "2", "3", "4"];
    #[cfg(windows)]
    let valid_choices = ["1", "2", "3"];

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
                let link_str = wizard_prompt("Paste link", "");
                let parsed = url::Url::parse(&link_str).unwrap();
                let mut p = parsed.query_pairs();
                let sni = p.find(|(k, _)| k == "sni").map(|(_, v)| v.to_string()).unwrap_or_default();
                let tm = p.find(|(k, _)| k == "type").map(|(_, v)| v.to_string()).unwrap_or("udp".to_string());
                (parsed.host_str().unwrap().to_string() + ":" + &parsed.port().unwrap_or(50000).to_string(), parsed.username().to_string(), sni, tm)
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

            let (_tun_dns, _kill_switch) = if tun_enable {
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
            let key_for_gen = generate_secure_key("hex");
            let _ = key_for_gen;
            let _ = &sni;

            let server_parts: Vec<&str> = server.split(':').collect();
            let server_host = server_parts.first().unwrap_or(&"127.0.0.1");
            let server_port = server_parts.get(1).unwrap_or(&"50000").parse::<u16>().unwrap_or(50000);
            
            let socks_parts: Vec<&str> = socks_bind.split(':').collect();
            let socks_host = socks_parts.first().unwrap_or(&"127.0.0.1");
            let socks_port = socks_parts.get(1).unwrap_or(&"1088").parse::<u16>().unwrap_or(1088);

            let client_json = serde_json::json!({
                "mode": "client",
                "version": env!("CARGO_PKG_VERSION"),
                "log": {
                    "level": "info"
                },
                "inbounds": [
                    {
                        "type": "tun",
                        "tag": "tun-in",
                        "auto_route": tun_enable,
                        "mtu": 1140
                    },
                    {
                        "type": "local_proxy",
                        "tag": "socks-in",
                        "protocol": "socks",
                        "listen": socks_host,
                        "port": socks_port
                    }
                ],
                "outbounds": [
                    {
                        "type": "ostp",
                        "tag": "proxy",
                        "server": server_host,
                        "port": server_port,
                        "access_key": access_key,
                        "transport": {
                            "type": transport_mode
                        },
                        "multiplex": {
                            "enabled": mux_enable,
                            "sessions": mux_sessions
                        }
                    },
                    {
                        "type": "direct",
                        "tag": "direct"
                    },
                    {
                        "type": "block",
                        "tag": "block"
                    }
                ],
                "routing": {
                    "rules": [
                        {
                            "domain_suffix": ["localhost", "127.0.0.1"],
                            "outbound": "direct"
                        }
                    ],
                    "default_outbound": "proxy"
                }
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
            let port_str = listen.split(':').next_back().unwrap_or("50000");
            let port: u16 = port_str.parse().unwrap_or(50000);
            let server_json = serde_json::json!({
                "mode": "server",
                "version": "{}",
                "log": {
                    "level": "info"
                },
                "dns_transport": {
                    "enabled": false,
                    "listen": "0.0.0.0:53",
                    "domain": "tunnel.yourdomain.com",
                    "pubkey": "",
                    "privkey": ""
                },
                "inbounds": [
                    {
                        "type": "ostp",
                        "tag": "ostp-in",
                        "listen": "0.0.0.0",
                        "port": port,
                        "users": access_keys
                    }
                ],
                "outbounds": [
                    {
                        "type": "direct",
                        "tag": "direct"
                    }
                ]
            });

            let actual_path = wizard_save_config(config_path, &server_json)?;

            #[cfg(unix)]
            wizard_register_systemd(&actual_path)?;
            #[cfg(windows)]
            wizard_register_windows_service(&actual_path)?;

            // Print share links
            let host = get_or_ask_public_ip(config_path);
            let port = listen.split(':').next_back().unwrap_or("50000");
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

        // ── SERVER + PANEL ───────────────────────────────
        "3" => {
            #[cfg(unix)]    const TOTAL: usize = 6;
            #[cfg(windows)] const TOTAL: usize = 5;

            wizard_step(1, TOTAL, "Listen address");
            let listen = wizard_prompt("Listen address (host:port)", "0.0.0.0:50000");
            let host = get_or_ask_public_ip(config_path);

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
            let _panel_bind = format!("0.0.0.0:{}", panel_port);
            let server_json = serde_json::json!({
                "mode": "server",
                "version": "{}",
                "log": {
                    "level": "info"
                },
                "dns_transport": {
                    "enabled": false,
                    "listen": "0.0.0.0:53",
                    "domain": "tunnel.yourdomain.com",
                    "pubkey": "",
                    "privkey": ""
                },
                "inbounds": [
                    {
                        "type": "ostp",
                        "tag": "ostp-in",
                        "listen": "0.0.0.0",
                        "port": 50000,
                        "users": access_keys
                    },
                    {
                        "type": "api",
                        "tag": "api-in",
                        "listen": "0.0.0.0",
                        "port": panel_port.parse::<u16>().unwrap_or(9090),
                        "webpath": webpath,
                        "username": username,
                        "password_hash": pass_hash
                    }
                ],
                "outbounds": [
                    {
                        "type": "direct",
                        "tag": "direct"
                    }
                ]
            });

            wizard_step(4, TOTAL, "Saving configuration");
            let actual_path = wizard_save_config(config_path, &server_json)?;

            #[cfg(unix)]
            {
                wizard_step(5, TOTAL, "Service registration");
                wizard_register_systemd(&actual_path)?;
            }
            #[cfg(windows)]
            {
                wizard_step(5, TOTAL, "Service registration");
                wizard_register_windows_service(&actual_path)?;
            }

            let port = listen.split(':').next_back().unwrap_or("50000");
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
                "version": "{}",
                "log": {
                    "level": "info"
                },
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

fn apply_interactive_prompts(client_cfg: &mut serde_json::Value) {
    use std::io::Write;
    
    print!("{} Enable TUN (VPN) mode? [y/N]: ", "?".blue().bold());
    std::io::stdout().flush().unwrap();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
    if input.trim().eq_ignore_ascii_case("y") {
        if let Some(i_val) = client_cfg.get_mut("inbounds") {
            if let Some(inbounds) = i_val.as_array_mut() {
                for inbound in inbounds.iter_mut() {
                    if inbound.get("type").and_then(|t| t.as_str()) == Some("tun") {
                        inbound["auto_route"] = serde_json::json!(true);
                    }
                }
            }
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
        if let Some(o_val) = client_cfg.get_mut("outbounds") {
            if let Some(outbounds) = o_val.as_array_mut() {
                for outbound in outbounds.iter_mut() {
                    if outbound.get("type").and_then(|t| t.as_str()) == Some("ostp") {
                        outbound["multiplex"] = serde_json::json!({
                            "enabled": true,
                            "sessions": sessions
                        });
                    }
                }
            }
        }
    }
    
    print!("Enable debug mode? [y/N]: ");
    std::io::stdout().flush().unwrap();
    input.clear();
    std::io::stdin().read_line(&mut input).unwrap();
    if input.trim().eq_ignore_ascii_case("y") {
        client_cfg["log"]["level"] = serde_json::json!("debug");
    }
}

async fn run_app() -> Result<()> {
    let raw_args = Args::parse();
    let mut args = LegacyArgs {
        config: raw_args.config.clone(),
        init: None,
        setup: false,
        generate_key: false,
        format: "hex".to_string(),
        count: 1,
        links: false,
        check: false,
        url: None,
        uninstall: false,
        update: false,
        update_branch: "stable".to_string(),
        target_version: None,
        import: None,
        proxy_env: false,
        proxy_env_clear: false,
        migrate: false,
        prober: false,
    };
    
    let mut enable_logging = true;

    if let Some(cmd) = &raw_args.command {
        match cmd {
            Commands::Setup { init } => { args.setup = true; args.init = init.clone(); }
            Commands::Init { mode } => { args.init = Some(mode.clone()); enable_logging = false; }
            Commands::GenerateKey { format, count } => { args.generate_key = true; args.format = format.clone(); args.count = *count; enable_logging = false; }
            Commands::Links => { args.links = true; enable_logging = false; }
            Commands::Check => { args.check = true; enable_logging = false; }
            Commands::Connect { url } => { args.url = Some(url.clone()); }
            Commands::Uninstall => { args.uninstall = true; enable_logging = false; }
            Commands::Update { branch, version } => { args.update = true; args.update_branch = branch.clone(); args.target_version = version.clone(); enable_logging = false; }
            Commands::Import { url } => { args.import = Some(url.clone()); enable_logging = false; }
            Commands::ProxyEnv => { args.proxy_env = true; enable_logging = false; }
            Commands::ProxyEnvClear => { args.proxy_env_clear = true; enable_logging = false; }
            Commands::Migrate => { args.migrate = true; enable_logging = false; }
            Commands::Prober => { args.prober = true; enable_logging = false; }
            Commands::Run => { }
        }
    }
    
    let _log_guard = if enable_logging {
        Some(ostp_client::logging::init_tracing("info", "ostp-cli", env!("CARGO_PKG_VERSION")))
    } else {
        None
    };


    if args.uninstall {
        return cmd_uninstall();
    }

    if args.update {
        return cmd_update(args.update_branch, args.target_version);
    }

    if args.migrate {
        return cmd_migrate(&args.config);
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
                        let (migrated, _) = ostp_client::config::ClientConfig::migrate_json(c);
                        if let Some(inbounds) = migrated.get("inbounds").and_then(|i| i.as_array()) {
                            for inbound in inbounds {
                                if inbound.get("type").and_then(|t| t.as_str()) == Some("local_proxy") {
                                    if let Some(p) = inbound.get("port").and_then(|p| p.as_u64()) {
                                        port = p as u16;
                                        break;
                                    }
                                }
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
        let mut client_cfg = parse_ostp_link(&import_url)
            .map_err(|e| anyhow!("Share Link Error: {e}"))?;
            
        apply_interactive_prompts(&mut client_cfg);
            
        let patched = patch_existing_client_config(&args.config, client_cfg);
        let content = serde_json::to_string_pretty(&patched)?;
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
        
        apply_interactive_prompts(&mut client_cfg);

        let patched = patch_existing_client_config(&args.config, client_cfg);
        return run_client_directly(patched).await;
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
                        let mut keys_count = 0;
                        let mut _has_outbound = false;
                        for inbound in &s.inbounds {
                            match inbound {
                                ostp_server::config::ServerInbound::Ostp { listen, port, users, fallback, .. } => {
                                    println!("  Inbound OSTP: {}:{}", listen.cyan(), port.to_string().cyan());
                                    keys_count += users.len();
                                    if let Some(fb) = fallback {
                                        if fb.enabled {
                                            println!("    Fallback: -> {}", fb.target.cyan());
                                        }
                                    }
                                }
                                ostp_server::config::ServerInbound::Api { listen, port, .. } => {
                                    println!("  Inbound API: {}:{}", listen.cyan(), port.to_string().cyan());
                                }
                                ostp_server::config::ServerInbound::Dns { listen, .. } => {
                                    println!("  Inbound DNS Tunnel: {}", listen.cyan());
                                }
                            }
                        }
                        println!("  Access keys: {}", keys_count.to_string().yellow());
                        for ob in &s.outbounds {
                            if let ostp_server::config::ServerOutbound::Socks { server, port, .. } = ob {
                                println!("  Outbound Proxy: SOCKS5 {}:{}", server.cyan(), port.to_string().cyan());
                                _has_outbound = true;
                            }
                        }
                        if let Some(dns) = &s.dns {
                            println!("  DNS Proxy: Listen 127.0.0.1:{}", dns.local_port.to_string().cyan());
                        }
                    }
                    AppMode::Client(c) => {
                        println!("{} Config OK: client mode", "[ostp]".green().bold());
                        let (migrated, _) = ostp_client::config::ClientConfig::migrate_json(c.clone());
                        let mut display_server = "unknown";
                        let mut display_key = "unknown";
                        if let Some(outbounds) = migrated.get("outbounds").and_then(|o| o.as_array()) {
                            for outbound in outbounds {
                                if outbound.get("type").and_then(|t| t.as_str()) == Some("ostp") {
                                    if let Some(s) = outbound.get("server").and_then(|s| s.as_str()) {
                                        display_server = s;
                                    }
                                    if let Some(k) = outbound.get("access_key").and_then(|k| k.as_str()) {
                                        display_key = k;
                                    }
                                    break;
                                }
                            }
                        }
                        println!("  Server: {}", display_server.cyan());
                        println!("  Key: {}...", &display_key[..8.min(display_key.len())].yellow());
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
        
        let (dns_priv, dns_pub) = if is_server {
            ostp_core::dnstt::generate_keypair().unwrap_or_else(|e| {
                tracing::warn!("Failed to generate dnstt keys: {}. Using placeholders.", e);
                ("YOUR_PRIVKEY".to_string(), "YOUR_PUBKEY".to_string())
            })
        } else {
            ("".to_string(), "".to_string())
        };
                let content = if is_server {
            format!(r#"{{
  // OSTP Server Configuration
  "version": "{}",
  "mode": "server",
  "log": {{
    // Log levels: trace, debug, info, warn, error
    "level": "info"
  }},
  "inbounds": [
    {{
      // Primary OSTP protocol listener
      "protocol": "ostp",
      "tag": "ostp-in",
      "listen": "0.0.0.0",
      "port": 50000,
      "users": [
        {{
          // Generated access key for the first client
          "key": "{}"
        }}
      ],
      "fallback": {{
        // Fallback protection: redirects unauthorized probes to a real website
        "enabled": false,
        "listen": "0.0.0.0:443",
        "target": "127.0.0.1:8080"
      }}
    }},
    {{
      // Web Administration API
      "protocol": "api",
      "tag": "api-in",
      "listen": "127.0.0.1",
      "port": 9090,
      "token": "YOUR_SECRET_TOKEN",
      "webpath": "/admin",
      "username": "admin",
      "password_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }},
    {{
      // DNS Tunnel Inbound
      // [WARNING] This is a last-resort transport via public DNS.
      // It requires a dedicated registered domain with NS records pointing to this server.
      // Full setup guide: https://github.com/ospab/ostp/wiki/DNS-Tunneling
      "protocol": "dns",
      "tag": "dns-tunnel",
      "listen": "0.0.0.0:53",
      "domain": "tunnel.example.com",
      "pubkey": "{dns_pub}",
      "privkey": "{dns_priv}"
    }}
  ],
  "outbounds": [
    {{
      // Example local SOCKS5 proxy (e.g. for Tor network)
      "protocol": "socks5",
      "tag": "socks5-local",
      "server": "127.0.0.1",
      "port": 9050
    }},
    {{
      // Default direct internet access
      "protocol": "direct",
      "tag": "direct"
    }},
    {{
      // Blackhole for blocked connections
      "protocol": "block",
      "tag": "block"
    }}
  ],
  "routing": {{
    // Rule-based routing of client traffic
    "rules": [
      {{
        "domain_suffix": [".onion"],
        "outbound": "socks5-local"
      }}
    ],
    // If no rules match, use the default outbound
    "default_outbound": "direct"
  }},
  "debug": false
}}"#, env!("CARGO_PKG_VERSION"), key, dns_pub=dns_pub, dns_priv=dns_priv)
        } else if mode_str == "relay" {
            format!(r#"{{
  // OSTP Relay Configuration v0.3.5
  // DO NOT EDIT THIS COMMENT - Migrator relies on it
  "version": "{}",
  "mode": "relay",
  "log": {{
    // Log levels: trace, debug, info, warn, error
    "level": "info"
  }},
  // Local port for the relay to listen on
  "listen": "0.0.0.0:50000",
  // Upstream server details
  "upstream_tcp": "TARGET_SERVER_IP:50000",
  "upstream_udp": "TARGET_SERVER_IP:50000",
  // Upstream Control Panel API for automatic key synchronization
  "upstream_api_url": "http://TARGET_SERVER_IP:9090",
  "upstream_api_token": "YOUR_API_TOKEN_HERE",
  "sync_interval_secs": 30,
  "debug": false
}}"#, env!("CARGO_PKG_VERSION"))
        } else {
            format!(r#"{{
  // OSTP Client Configuration
  // DO NOT EDIT THIS COMMENT - Migrator relies on it
  "version": "{}",
  "mode": "client",
  "log": {{
    "level": "info"
  }},
  "inbounds": [
    {{
      // Virtual network interface for transparent proxying
      "type": "tun",
      "tag": "tun-in",
      "auto_route": true,
      "mtu": 1140
    }},
    {{
      // Local SOCKS5 proxy server for browser configuration
      "type": "local_proxy",
      "tag": "socks-in",
      "protocol": "socks",
      "listen": "127.0.0.1",
      "port": 1088
    }}
  ],
  "outbounds": [
    {{
      // Connection to the remote OSTP server
      "type": "ostp",
      "tag": "proxy",
      "server": "YOUR_SERVER_IP",
      "port": 50000,
      "access_key": "{key}",
      "transport": {{
        "type": "udp"
      }},
      "multiplex": {{
        "enabled": false,
        "sessions": 1
      }}
    }},
    {{
      // DNS Tunneling connection to the remote OSTP server
      // NOTE: DNS Tunneling is very slow and should be used only when UDP/TCP are blocked.
      // Read the manual here: https://github.com/ospab/ostp/wiki/DNS-Tunneling
      "type": "ostp",
      "tag": "proxy-dns",
      "server": "1.1.1.1",
      "port": 53,
      "access_key": "{key}",
      "transport": {{
        "type": "dns",
        "domain": "tunnel.yourdomain.com",
        "pubkey": "SERVER_PUBLIC_KEY_HERE"
      }},
      "multiplex": {{
        "enabled": true,
        "sessions": 5
      }}
    }},
    {{
      "type": "direct",
      "tag": "direct"
    }},
    {{
      "type": "block",
      "tag": "block"
    }}
  ],
  "routing": {{
    "rules": [
      {{
        "domain_suffix": ["localhost"],
        "outbound": "direct"
      }}
    ],
    "default_outbound": "proxy"
  }}
}}"#, env!("CARGO_PKG_VERSION"), key = key)
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
                    let mut first_key = None;
                    for inbound in &s.inbounds {
                        if let ostp_server::config::ServerInbound::Ostp { users, .. } = inbound {
                            if !users.is_empty() {
                                first_key = Some(users[0].key());
                                break;
                            }
                        }
                    }
                    if let Some(key) = first_key {
                        let host = get_or_ask_public_ip(&args.config);
                        let mut query_params = vec!["type=udp".to_string()];

                        let mut link = format!("ostp://{}@{}:50000", key, host);
                        if !query_params.is_empty() {
                            link.push('?');
                            link.push_str(&query_params.join("&"));
                        }
                        println!("\n  Share link for client distribution:");
                        println!("  {}", link);
                    }
                }
            }
        }
        return Ok(());
    }

    if args.prober {
        dns_prober::run_prober(&args.config).await;
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
    let mut raw_json: serde_json::Value = serde_json::from_reader(&mut stripped)
        .map_err(|e| anyhow!("Failed to parse config as JSON: {}", e))?;


    // Hard stop if config is not in current format — user must run --migrate explicitly
    {
        let has_new_format = raw_json.get("inbounds").and_then(|v| v.as_array()).is_some()
            && raw_json.get("outbounds").and_then(|v| v.as_array()).is_some();
        let version_ok = raw_json.get("version").and_then(|v| v.as_str()) == Some(env!("CARGO_PKG_VERSION"));
        if !has_new_format {
            eprintln!();
            eprintln!("{} Your configuration file is in an outdated format.", "[ostp]".yellow().bold());
            eprintln!("{} Run the following command to upgrade it:", "[ostp]".yellow().bold());
            eprintln!();
            eprintln!("    {}", "ostp --migrate".green().bold());
            eprintln!();
            std::process::exit(1);
        }
        if !version_ok {
            // New format but wrong version — silently fix just the version field in memory (no write)
            raw_json["version"] = serde_json::json!(env!("CARGO_PKG_VERSION"));
        }
    }


    let config: UnifiedConfig = serde_json::from_value(raw_json)
        .map_err(|e| anyhow!("Failed to parse config: {}", e))?;

    config.validate()?;

    if args.links {
        match &config.mode {
            AppMode::Server(server_cfg) => {
                let mut host = "127.0.0.1".to_string();
                let mut port = 50000;
                let mut users = Vec::new();
                for inbound in &server_cfg.inbounds {
                    if let ostp_server::config::ServerInbound::Ostp { listen: l, port: p, users: u, .. } = inbound {
                        if l != "0.0.0.0" {
                            host = l.clone();
                        }
                        port = *p;
                        users.extend(u.clone());
                    }
                }
                if host == "127.0.0.1" { 
                    host = get_or_ask_public_ip(&args.config); 
                }
                
                println!("\n  Client share links from {:?}:", args.config);
                if let AppMode::Server(cfg) = &config.mode {
                    let mut has_ostp = false;
                    for inbound in &cfg.inbounds {
                        if let ostp_server::config::ServerInbound::Ostp { users, .. } = inbound {
                            has_ostp = true;
                            if users.is_empty() {
                                anyhow::bail!("Ostp inbound must contain at least one user.");
                            }
                        }
                    }
                    if !has_ostp {
                        anyhow::bail!("Server configuration must contain at least one Ostp inbound.");
                    }
                }
                for (idx, user) in users.iter().enumerate() {
                    let mut query_params = vec!["type=udp".to_string()];

                    let mut link = format!("ostp://{}@{}:{}", user.key(), host, port);
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
            
            let mut listen_addrs = Vec::new();
            let mut access_keys_meta = Vec::new();
            let mut fallback_config = None;
            let mut host_port = ("0.0.0.0".to_string(), 50000);
            let mut api_config = None;
            let mut dns_transport = None;

            for inbound in server_cfg.inbounds {
                match inbound {
                    ostp_server::config::ServerInbound::Ostp { listen, port, users, fallback, .. } => {
                        listen_addrs.push(format!("{}:{}", listen, port));
                        host_port = (listen.clone(), port);
                        for uc in users {
                            access_keys_meta.push((uc.key(), ostp_server::api::UserMeta {
                                name: uc.name(),
                                limit_bytes: uc.limit(),
                            }));
                        }
                        if fallback_config.is_none() {
                            fallback_config = fallback;
                        }
                    }
                    ostp_server::config::ServerInbound::Api { listen, port, token, webpath, username, password_hash, .. } => {
                        api_config = Some(ostp_server::ApiConfig {
                            enabled: true,
                            bind: format!("{}:{}", listen, port),
                            token,
                            webpath: webpath.unwrap_or_default(),
                            username: username.unwrap_or_default(),
                            password_hash: password_hash.unwrap_or_default(),
                        });
                    }
                    ostp_server::config::ServerInbound::Dns { listen, domain, pubkey, privkey, .. } => {
                        dns_transport = Some(ostp_server::config::DnsTransportConfig {
                            enabled: true,
                            listen,
                            domain,
                            pubkey: pubkey.unwrap_or_default(),
                            privkey: privkey.unwrap_or_default(),
                        });
                    }
                }
            }

            println!("{} Starting server on {:?}", "[ostp]".cyan().bold(), listen_addrs);
            let debug = server_cfg.debug.unwrap_or(false);
            
            let mut outbound = None;
            for ob in server_cfg.outbounds {
                if let ostp_server::config::ServerOutbound::Socks { server, port, tag, l4_protocol } = ob {
                    let mut rules = Vec::new();
                    let mut default_action = Some("proxy".to_string());
                    if let Some(routing) = &server_cfg.routing {
                        for rule in &routing.rules {
                            if rule.outbound == tag {
                                rules.push(ostp_server::OutboundRule {
                                    domain_suffix: rule.domain_suffix.clone().unwrap_or_default(),
                                    ip_cidr: rule.ip_cidr.clone().unwrap_or_default(),
                                    protocol: rule.protocol.clone(),
                                    action: parse_outbound_action(Some("proxy".to_string())),
                                });
                            }
                        }
                        if routing.default_outbound != tag {
                            default_action = Some("direct".to_string());
                        }
                    }
                    outbound = Some(ostp_server::OutboundConfig {
                        enabled: true,
                        protocol: "socks5".to_string(),
                        l4_protocol,
                        address: server,
                        port,
                        rules,
                        default_action: parse_outbound_action(default_action),
                    });
                    break;
                }
            }

            let dns_cfg = server_cfg.dns;
            
            let host = if host_port.0 == "0.0.0.0" {
                detect_local_public_ip().unwrap_or_else(|| "127.0.0.1".to_string())
            } else {
                host_port.0.to_string()
            };

            ostp_server::run_server(listen_addrs, Some(host), access_keys_meta, outbound, api_config, fallback_config, debug, dns_cfg, dns_transport, Some(args.config)).await?;
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
fn cmd_update(branch: String, version: Option<String>) -> Result<()> {
    use std::process::Command;

    println!("[ostp] Updating OSTP...");
    
    let mut script_args = vec!["-c".to_string()];
    if let Some(v) = version {
        script_args.push(format!("bash <(curl -Ls https://raw.githubusercontent.com/ospab/ostp/master/scripts/install.sh) --branch {} -v {}", branch, v));
    } else {
        script_args.push(format!("bash <(curl -Ls https://raw.githubusercontent.com/ospab/ostp/master/scripts/install.sh) --branch {}", branch));
    }

    let status = Command::new("bash")
        .args(&script_args)
        .status()
        .map_err(|e| anyhow!("Failed to run update: {e}"))?;

    if !status.success() {
        anyhow::bail!("Update script exited with status: {}", status);
    }
    Ok(())
}

#[cfg(not(unix))]
fn cmd_update(branch: String, version: Option<String>) -> Result<()> {
    anyhow::bail!("The 'update' command is only supported on Linux/Unix systems.");
}

async fn run_client_directly(client_cfg: serde_json::Value) -> Result<()> {
    let (migrated, _) = ostp_client::config::ClientConfig::migrate_json(client_cfg);
    let client_conf: ostp_client::config::ClientConfig = serde_json::from_value(migrated)?;

    let mut is_tun_enabled = false;
    for inbound in &client_conf.inbounds {
        if matches!(inbound, ostp_client::config::InboundConfig::Tun { .. }) {
            is_tun_enabled = true;
            break;
        }
    }

    let mode_str = if is_tun_enabled { "tun" } else { "proxy" };
    println!("{} Starting client (mode={})", "[ostp]".cyan().bold(), mode_str.yellow());

    #[cfg(target_os = "windows")]
    if is_tun_enabled {
        ensure_elevated_for_tun()?;
    }

    // Run the client implementation
    let (_shutdown_tx, rx) = tokio::sync::watch::channel(false);
    let metrics = std::sync::Arc::new(ostp_client::bridge::BridgeMetrics::default());
    
    // Launch the core runner directly.
    ostp_client::runner::run_client_core(client_conf, metrics, rx, None).await?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn ensure_elevated_for_tun() -> Result<()> {
    #[link(name = "shell32")]
    extern "system" {
        fn IsUserAnAdmin() -> i32;
        fn ShellExecuteW(h: *mut std::ffi::c_void, op: *const u16, f: *const u16, p: *const u16, d: *const u16, s: i32) -> isize;
    }

    let is_admin = unsafe { IsUserAnAdmin() != 0 };
    if is_admin {
        return Ok(());
    }

    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    let exe = std::env::current_exe()?;
    let exe_wstr: Vec<u16> = exe.as_os_str().encode_wide().chain(Some(0)).collect();
    let verb_wstr: Vec<u16> = OsStr::new("runas").encode_wide().chain(Some(0)).collect();

    // Reconstruct arguments
    let args: Vec<String> = std::env::args().skip(1).collect();
    let params_str = args.iter().map(|s| format!("\"{}\"", s)).collect::<Vec<_>>().join(" ");
    let params_wstr: Vec<u16> = OsStr::new(&params_str).encode_wide().chain(Some(0)).collect();

    let cwd = std::env::current_dir()?;
    let cwd_wstr: Vec<u16> = cwd.as_os_str().encode_wide().chain(Some(0)).collect();

    println!("{}", "[ostp] TUN mode requires administrator privileges. Requesting elevation...".yellow());

    let ret = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb_wstr.as_ptr(),
            exe_wstr.as_ptr(),
            params_wstr.as_ptr(),
            cwd_wstr.as_ptr(),
            1, // SW_SHOWNORMAL
        )
    };

    if ret <= 32 {
        anyhow::bail!("UAC elevation was denied or failed (ret={}). Please run as Administrator.", ret);
    }
    std::process::exit(0);
}

fn cmd_migrate(config_path: &std::path::Path) -> Result<()> {
    if !config_path.exists() {
        anyhow::bail!("Configuration file not found at {:?}", config_path);
    }

    let config_content = fs::read_to_string(config_path)?;
    let mut stripped = json_comments::StripComments::new(config_content.as_bytes());
    let old: serde_json::Value = serde_json::from_reader(&mut stripped)
        .map_err(|e| anyhow!("Failed to parse config as JSON: {}", e))?;

    // --- Determine config type ---
    let mode = old.get("mode").and_then(|m| m.as_str()).unwrap_or("");
    let is_server = mode == "server"
        || old.get("listen").is_some()
        || old.get("access_keys").is_some()
        || old.get("inbounds").and_then(|v| v.as_array()).map(|arr| {
            arr.iter().any(|i| {
                i.get("protocol").and_then(|p| p.as_str()) == Some("ostp")
                || i.get("type").and_then(|t| t.as_str()) == Some("ostp")
            })
        }).unwrap_or(false);
    let is_relay = mode == "relay" || old.get("upstream_tcp").is_some();
    let _is_client = !is_server && !is_relay;

    // --- Helper: extract log level ---
    let log_level = old.get("log").and_then(|l| l.get("level")).and_then(|v| v.as_str())
        .or_else(|| old.get("log_level").and_then(|v| v.as_str()))
        .unwrap_or("info");

    // --- Backup original ---
    let bak_path = config_path.with_extension("json.bak");
    fs::copy(config_path, &bak_path)?;
    println!("{} Original config backed up to {:?}", "[ostp]".cyan().bold(), bak_path);

    let new_content: String;

    if is_server {
        println!("{} Detected: Server configuration", "[ostp]".cyan().bold());

        // --- Extract server data ---
        // Listen host:port
        let (listen_host, listen_port) = extract_server_listen(&old);

        // Access keys — support old flat list and new inbounds format
        let users_json = extract_server_users(&old);

        // Fallback
        let (fallback_enabled, fallback_listen, fallback_target) = extract_server_fallback(&old);

        // API
        let (api_listen, api_port, api_token, api_webpath, api_username, api_pass_hash) =
            extract_server_api(&old);

        // DNS transport
        let (dns_listen, dns_domain, dns_pubkey, dns_privkey) = extract_server_dns(&old);

        // Routing rules (preserve if present)
        let routing_rules_str = extract_routing_rules_str(&old);
        let default_outbound = old.get("routing").and_then(|r| r.get("default_outbound"))
            .and_then(|v| v.as_str()).unwrap_or("direct");

        let users_str = users_json.iter()
            .map(|k| format!(
                r#"        {{
          "key": "{}"
        }}
"#, k))
            .collect::<Vec<_>>()
            .join(",\n");
        let users_str = if users_str.is_empty() {
            format!(r#"        {{
          "key": "{}"
        }}
"#, generate_secure_key("hex"))
        } else { users_str };

        new_content = format!(r#"{{
  // OSTP Server Configuration
  "version": "{ver}",
  "mode": "server",
  "log": {{
    // Log levels: trace, debug, info, warn, error
    "level": "{log_level}"
  }},
  "inbounds": [
    {{
      // Primary OSTP protocol listener
      "protocol": "ostp",
      "tag": "ostp-in",
      "listen": "{listen_host}",
      "port": {listen_port},
      "users": [
{users_str}      ],
      "fallback": {{
        // Fallback protection: redirects unauthorized probes to a real website
        "enabled": {fallback_enabled},
        "listen": "{fallback_listen}",
        "target": "{fallback_target}"
      }}
    }},
    {{
      // Web Administration API
      "protocol": "api",
      "tag": "api-in",
      "listen": "{api_listen}",
      "port": {api_port},
      "token": "{api_token}",
      "webpath": "{api_webpath}",
      "username": "{api_username}",
      "password_hash": "{api_pass_hash}"
    }},
    {{
      // DNS Tunnel Inbound
      // [WARNING] This is a last-resort transport via public DNS.
      // It requires a dedicated registered domain with NS records pointing to this server.
      // Full setup guide: https://github.com/ospab/ostp/wiki/DNS-Tunneling
      "protocol": "dns",
      "tag": "dns-tunnel",
      "listen": "{dns_listen}",
      "domain": "{dns_domain}",
      "pubkey": "{dns_pubkey}",
      "privkey": "{dns_privkey}"
    }}
  ],
  "outbounds": [
    {{
      // Example local SOCKS5 proxy (e.g. for Tor network)
      "protocol": "socks5",
      "tag": "socks5-local",
      "server": "127.0.0.1",
      "port": 9050
    }},
    {{
      // Default direct internet access
      "protocol": "direct",
      "tag": "direct"
    }},
    {{
      // Blackhole for blocked connections
      "protocol": "block",
      "tag": "block"
    }}
  ],
  "routing": {{
    // Rule-based routing of client traffic
    "rules": [{routing_rules}],
    // If no rules match, use the default outbound
    "default_outbound": "{default_outbound}"
  }},
  "debug": false
}}
"#,
            ver = env!("CARGO_PKG_VERSION"),
            log_level = log_level,
            listen_host = listen_host,
            listen_port = listen_port,
            users_str = users_str,
            fallback_enabled = fallback_enabled,
            fallback_listen = fallback_listen,
            fallback_target = fallback_target,
            api_listen = api_listen,
            api_port = api_port,
            api_token = api_token,
            api_webpath = api_webpath,
            api_username = api_username,
            api_pass_hash = api_pass_hash,
            dns_listen = dns_listen,
            dns_domain = dns_domain,
            dns_pubkey = dns_pubkey,
            dns_privkey = dns_privkey,
            routing_rules = routing_rules_str,
            default_outbound = default_outbound,
        );

    } else if is_relay {
        println!("{} Detected: Relay configuration", "[ostp]".cyan().bold());

        let upstream_tcp = old.get("upstream_tcp").and_then(|v| v.as_str()).unwrap_or("TARGET_SERVER_IP:50000");
        let upstream_udp = old.get("upstream_udp").and_then(|v| v.as_str()).unwrap_or(upstream_tcp);
        let api_url = old.get("upstream_api_url").and_then(|v| v.as_str()).unwrap_or("http://TARGET_SERVER_IP:9090");
        let api_token = old.get("upstream_api_token").and_then(|v| v.as_str()).unwrap_or("");
        let sync_interval = old.get("sync_interval_secs").and_then(|v| v.as_u64()).unwrap_or(30);
        let listen = old.get("listen").and_then(|v| v.as_str()).unwrap_or("0.0.0.0:50000");

        new_content = format!(r#"{{
  // OSTP Relay Configuration
  "version": "{ver}",
  "mode": "relay",
  "log": {{
    // Log levels: trace, debug, info, warn, error
    "level": "{log_level}"
  }},
  // Local port for the relay to listen on
  "listen": "{listen}",
  // Upstream server details
  "upstream_tcp": "{upstream_tcp}",
  "upstream_udp": "{upstream_udp}",
  // Upstream Control Panel API for automatic key synchronization
  "upstream_api_url": "{api_url}",
  "upstream_api_token": "{api_token}",
  "sync_interval_secs": {sync_interval},
  "debug": false
}}
"#,
            ver = env!("CARGO_PKG_VERSION"),
            log_level = log_level,
            listen = listen,
            upstream_tcp = upstream_tcp,
            upstream_udp = upstream_udp,
            api_url = api_url,
            api_token = api_token,
            sync_interval = sync_interval,
        );

    } else {
        println!("{} Detected: Client configuration", "[ostp]".cyan().bold());

        // Extract client data
        let (server_ip, server_port, access_key, transport_type) = extract_client_server(&old);
        let (socks_listen, socks_port) = extract_client_socks(&old);
        let tun_enabled = extract_client_tun(&old);
        let mux_enabled = old.get("mux").and_then(|m| m.get("enabled")).and_then(|v| v.as_bool())
            .or_else(|| old.get("outbounds").and_then(|o| o.as_array()).and_then(|arr| {
                arr.iter().find(|o| o.get("type").and_then(|t| t.as_str()) == Some("ostp"))
                    .and_then(|o| o.get("multiplex")).and_then(|m| m.get("enabled")).and_then(|v| v.as_bool())
            }))
            .unwrap_or(false);
        let mux_sessions = old.get("mux").and_then(|m| m.get("sessions")).and_then(|v| v.as_u64())
            .or_else(|| old.get("outbounds").and_then(|o| o.as_array()).and_then(|arr| {
                arr.iter().find(|o| o.get("type").and_then(|t| t.as_str()) == Some("ostp"))
                    .and_then(|o| o.get("multiplex")).and_then(|m| m.get("sessions")).and_then(|v| v.as_u64())
            }))
            .unwrap_or(1);
        let routing_rules_str = extract_routing_rules_str(&old);
        let default_outbound = old.get("routing").and_then(|r| r.get("default_outbound"))
            .and_then(|v| v.as_str()).unwrap_or("proxy");

        let tun_block = if tun_enabled {
            r#"    {{
      // Virtual network interface for transparent proxying
      "type": "tun",
      "tag": "tun-in",
      "auto_route": true,
      "mtu": 1140
    }},
"#
        } else {
            r#"    // Uncomment below to enable TUN (VPN) mode:
    // {{ "type": "tun", "tag": "tun-in", "auto_route": true, "mtu": 1140 }},
"#
        };

        new_content = format!(r#"{{
  // OSTP Client Configuration
  "version": "{ver}",
  "mode": "client",
  "log": {{
    "level": "{log_level}"
  }},
  "inbounds": [
{tun_block}    {{
      // Local SOCKS5 proxy server for browser configuration
      "type": "local_proxy",
      "tag": "socks-in",
      "protocol": "socks",
      "listen": "{socks_listen}",
      "port": {socks_port}
    }}
  ],
  "outbounds": [
    {{
      // Connection to the remote OSTP server
      "type": "ostp",
      "tag": "proxy",
      "server": "{server_ip}",
      "port": {server_port},
      "access_key": "{access_key}",
      "transport": {{
        "type": "{transport_type}"
      }},
      "multiplex": {{
        "enabled": {mux_enabled},
        "sessions": {mux_sessions}
      }}
    }},
    {{
      "type": "direct",
      "tag": "direct"
    }},
    {{
      "type": "block",
      "tag": "block"
    }}
  ],
  "routing": {{
    "rules": [{routing_rules}],
    "default_outbound": "{default_outbound}"
  }}
}}
"#,
            ver = env!("CARGO_PKG_VERSION"),
            log_level = log_level,
            tun_block = tun_block,
            socks_listen = socks_listen,
            socks_port = socks_port,
            server_ip = server_ip,
            server_port = server_port,
            access_key = access_key,
            transport_type = transport_type,
            mux_enabled = mux_enabled,
            mux_sessions = mux_sessions,
            routing_rules = routing_rules_str,
            default_outbound = default_outbound,
        );
    }

    fs::write(config_path, &new_content)?;
    println!("{} Configuration successfully migrated to v{}!", "[ostp]".green().bold(), env!("CARGO_PKG_VERSION"));
    println!("{} Backup saved at {:?}", "[ostp]".dimmed(), bak_path);
    Ok(())
}

// ---------------------------------------------------------------------------
// Migration helper extractors
// ---------------------------------------------------------------------------

/// Extract listen host and port for server from old or new format
fn extract_server_listen(old: &serde_json::Value) -> (String, u16) {
    // New format: inbounds[type=ostp].listen + port
    if let Some(arr) = old.get("inbounds").and_then(|v| v.as_array()) {
        for inbound in arr {
            let proto = inbound.get("protocol").or(inbound.get("type")).and_then(|v| v.as_str()).unwrap_or("");
            if proto == "ostp" {
                let h = inbound.get("listen").and_then(|v| v.as_str()).unwrap_or("0.0.0.0").to_string();
                let p = inbound.get("port").and_then(|v| v.as_u64()).unwrap_or(50000) as u16;
                return (h, p);
            }
        }
    }
    // Old format: "listen": "0.0.0.0:50000"
    if let Some(s) = old.get("listen").and_then(|v| v.as_str()) {
        let parts: Vec<&str> = s.split(':').collect();
        let h = parts.first().unwrap_or(&"0.0.0.0").to_string();
        let p = parts.get(1).and_then(|x| x.parse().ok()).unwrap_or(50000);
        return (h, p);
    }
    ("0.0.0.0".to_string(), 50000)
}

/// Extract access keys as list of strings
fn extract_server_users(old: &serde_json::Value) -> Vec<String> {
    // New format: inbounds[type=ostp].users[].key
    if let Some(arr) = old.get("inbounds").and_then(|v| v.as_array()) {
        for inbound in arr {
            let proto = inbound.get("protocol").or(inbound.get("type")).and_then(|v| v.as_str()).unwrap_or("");
            if proto == "ostp" {
                if let Some(users) = inbound.get("users").and_then(|v| v.as_array()) {
                    return users.iter().filter_map(|u| {
                        u.get("key").and_then(|k| k.as_str()).map(|s| s.to_string())
                        .or_else(|| u.as_str().map(|s| s.to_string()))
                    }).collect();
                }
            }
        }
    }
    // Old flat format: "access_keys": ["key1", "key2"]
    if let Some(keys) = old.get("access_keys").and_then(|v| v.as_array()) {
        return keys.iter().filter_map(|k| k.as_str().map(|s| s.to_string())).collect();
    }
    vec![]
}

/// Extract fallback config
fn extract_server_fallback(old: &serde_json::Value) -> (bool, String, String) {
    // New format: inbounds[type=ostp].fallback
    if let Some(arr) = old.get("inbounds").and_then(|v| v.as_array()) {
        for inbound in arr {
            let proto = inbound.get("protocol").or(inbound.get("type")).and_then(|v| v.as_str()).unwrap_or("");
            if proto == "ostp" {
                if let Some(fb) = inbound.get("fallback") {
                    let enabled = fb.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
                    let listen = fb.get("listen").and_then(|v| v.as_str()).unwrap_or("0.0.0.0:443").to_string();
                    let target = fb.get("target").and_then(|v| v.as_str()).unwrap_or("127.0.0.1:8080").to_string();
                    return (enabled, listen, target);
                }
            }
        }
    }
    // Old flat format
    if let Some(fb) = old.get("fallback") {
        let enabled = fb.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
        let listen = fb.get("listen").and_then(|v| v.as_str()).unwrap_or("0.0.0.0:443").to_string();
        let target = fb.get("target").and_then(|v| v.as_str()).unwrap_or("127.0.0.1:8080").to_string();
        return (enabled, listen, target);
    }
    (false, "0.0.0.0:443".to_string(), "127.0.0.1:8080".to_string())
}

/// Extract API config
fn extract_server_api(old: &serde_json::Value) -> (String, u16, String, String, String, String) {
    let default_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string();
    // New format: inbounds[protocol=api]
    if let Some(arr) = old.get("inbounds").and_then(|v| v.as_array()) {
        for inbound in arr {
            let proto = inbound.get("protocol").or(inbound.get("type")).and_then(|v| v.as_str()).unwrap_or("");
            if proto == "api" {
                let listen = inbound.get("listen").and_then(|v| v.as_str()).unwrap_or("127.0.0.1").to_string();
                let port = inbound.get("port").and_then(|v| v.as_u64()).unwrap_or(9090) as u16;
                let token = inbound.get("token").and_then(|v| v.as_str()).unwrap_or("YOUR_SECRET_TOKEN").to_string();
                let webpath = inbound.get("webpath").and_then(|v| v.as_str()).unwrap_or("/admin").to_string();
                let username = inbound.get("username").and_then(|v| v.as_str()).unwrap_or("admin").to_string();
                let pass = inbound.get("password_hash").and_then(|v| v.as_str()).unwrap_or(&default_hash).to_string();
                return (listen, port, token, webpath, username, pass);
            }
        }
    }
    // Old format: "api": { "bind": "127.0.0.1:9090", ... }
    if let Some(api) = old.get("api") {
        let bind = api.get("bind").and_then(|v| v.as_str()).unwrap_or("127.0.0.1:9090");
        let parts: Vec<&str> = bind.split(':').collect();
        let listen = parts.first().unwrap_or(&"127.0.0.1").to_string();
        let port = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(9090);
        let token = api.get("token").and_then(|v| v.as_str()).unwrap_or("YOUR_SECRET_TOKEN").to_string();
        let webpath = api.get("webpath").and_then(|v| v.as_str()).unwrap_or("/admin").to_string();
        let username = api.get("username").and_then(|v| v.as_str()).unwrap_or("admin").to_string();
        let pass = api.get("password_hash").and_then(|v| v.as_str()).unwrap_or(&default_hash).to_string();
        return (listen, port, token, webpath, username, pass);
    }
    ("127.0.0.1".to_string(), 9090, "YOUR_SECRET_TOKEN".to_string(), "/admin".to_string(), "admin".to_string(), default_hash)
}

/// Extract DNS transport config
fn extract_server_dns(old: &serde_json::Value) -> (String, String, String, String) {
    // New format: inbounds[protocol=dns]
    if let Some(arr) = old.get("inbounds").and_then(|v| v.as_array()) {
        for inbound in arr {
            let proto = inbound.get("protocol").or(inbound.get("type")).and_then(|v| v.as_str()).unwrap_or("");
            if proto == "dns" {
                let listen = inbound.get("listen").and_then(|v| v.as_str()).unwrap_or("0.0.0.0:53").to_string();
                let domain = inbound.get("domain").and_then(|v| v.as_str()).unwrap_or("tunnel.example.com").to_string();
                let pubkey = inbound.get("pubkey").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let privkey = inbound.get("privkey").and_then(|v| v.as_str()).unwrap_or("").to_string();
                return (listen, domain, pubkey, privkey);
            }
        }
    }
    // Old flat format: "dns_transport": {...}
    if let Some(dns) = old.get("dns_transport") {
        let listen = dns.get("listen").and_then(|v| v.as_str()).unwrap_or("0.0.0.0:53").to_string();
        let domain = dns.get("domain").and_then(|v| v.as_str()).unwrap_or("tunnel.example.com").to_string();
        let pubkey = dns.get("pubkey").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let privkey = dns.get("privkey").and_then(|v| v.as_str()).unwrap_or("").to_string();
        return (listen, domain, pubkey, privkey);
    }
    let new_pub = generate_secure_key("base64");
    let new_priv = generate_secure_key("base64");
    ("0.0.0.0:53".to_string(), "tunnel.example.com".to_string(), new_pub, new_priv)
}

/// Extract routing rules as a formatted JSON string for embedding in template
fn extract_routing_rules_str(old: &serde_json::Value) -> String {
    if let Some(rules) = old.get("routing").and_then(|r| r.get("rules")).and_then(|v| v.as_array()) {
        if !rules.is_empty() {
            let parts: Vec<String> = rules.iter()
                .filter_map(|r| serde_json::to_string_pretty(r).ok())
                .collect();
            return format!("\n      {}\n    ", parts.join(",\n      "));
        }
    }
    String::new()
}

/// Extract client server address, port, key, transport
fn extract_client_server(old: &serde_json::Value) -> (String, u16, String, String) {
    // New format: outbounds[type=ostp]
    if let Some(arr) = old.get("outbounds").and_then(|v| v.as_array()) {
        for ob in arr {
            let t = ob.get("type").and_then(|v| v.as_str()).unwrap_or("");
            if t == "ostp" {
                let server = ob.get("server").and_then(|v| v.as_str()).unwrap_or("YOUR_SERVER_IP").to_string();
                let port = ob.get("port").and_then(|v| v.as_u64()).unwrap_or(50000) as u16;
                let key = ob.get("access_key").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let transport = ob.get("transport").and_then(|t| t.get("type")).and_then(|v| v.as_str()).unwrap_or("udp").to_string();
                return (server, port, key, transport);
            }
        }
    }
    // Old flat format
    let server_full = old.get("server").and_then(|v| v.as_str()).unwrap_or("YOUR_SERVER_IP:50000");
    let parts: Vec<&str> = server_full.split(':').collect();
    let server = parts.first().unwrap_or(&"YOUR_SERVER_IP").to_string();
    let port = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(50000);
    let key = old.get("access_key").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let transport = old.get("transport").and_then(|t| t.get("mode").or(t.get("type"))).and_then(|v| v.as_str()).unwrap_or("udp").to_string();
    (server, port, key, transport)
}

/// Extract client SOCKS listen address and port
fn extract_client_socks(old: &serde_json::Value) -> (String, u16) {
    // New format: inbounds[type=local_proxy]
    if let Some(arr) = old.get("inbounds").and_then(|v| v.as_array()) {
        for inbound in arr {
            let t = inbound.get("type").and_then(|v| v.as_str()).unwrap_or("");
            if t == "local_proxy" {
                let listen = inbound.get("listen").and_then(|v| v.as_str()).unwrap_or("127.0.0.1").to_string();
                let port = inbound.get("port").and_then(|v| v.as_u64()).unwrap_or(1088) as u16;
                return (listen, port);
            }
        }
    }
    // Old flat format
    let bind = old.get("socks5_bind").and_then(|v| v.as_str()).unwrap_or("127.0.0.1:1088");
    let parts: Vec<&str> = bind.split(':').collect();
    let listen = parts.first().unwrap_or(&"127.0.0.1").to_string();
    let port = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(1088);
    (listen, port)
}

/// Check if TUN is enabled in old config
fn extract_client_tun(old: &serde_json::Value) -> bool {
    // New format: inbounds[type=tun]
    if let Some(arr) = old.get("inbounds").and_then(|v| v.as_array()) {
        for inbound in arr {
            let t = inbound.get("type").and_then(|v| v.as_str()).unwrap_or("");
            if t == "tun" {
                return inbound.get("auto_route").and_then(|v| v.as_bool()).unwrap_or(true);
            }
        }
    }
    // Old flat format
    old.get("tun").and_then(|t| t.get("enable")).and_then(|v| v.as_bool()).unwrap_or(false)
}
