use anyhow::{anyhow, Context, Result};
use clap::Parser;
use std::fs;
use std::path::{Path, PathBuf};
use colored::Colorize;

mod cert_cmd;
mod webserver;

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
    /// Initialize config for client, server, or relay mode
    Init {
        mode: String,
    },
    /// Hash a password for the web panel's `api.password_hash` config field
    #[command(name = "hash-password", alias = "hp")]
    HashPassword {
        /// The password to hash. Omit to be prompted (keeps it out of shell history).
        password: Option<String>,
    },
    /// Generate a new secure access key
    #[command(name = "gk", alias = "generate-key")]
    GenerateKey {
        /// Format for generated key (hex, base64)
        #[arg(long, default_value = "hex")]
        format: String,
        /// Number of keys to generate
        // NOT short='c' - `--config` is a global arg (propagated into every
        // subcommand's scope), so a local '-c' here would collide with it.
        // Clap validates the whole command tree on the first parse() and
        // panics on a duplicate short flag, breaking the ENTIRE CLI.
        #[arg(short = 'n', long, default_value_t = 1)]
        count: usize,
    },
    /// Output ready-to-use client sharing links (ostp://...) from the server configuration.
    /// `ostp links qr` shows a QR code per client, one client at a time.
    Links {
        #[arg(value_parser = ["qr"])]
        view: Option<String>,
        /// With qr: a code for every link, not just the best one
        #[arg(long)]
        all: bool,
    },
    /// Validate configuration file
    Check,
    /// Connect using a share link (ostp://ACCESS_KEY@HOST:PORT)
    Connect {
        url: String,
    },
    /// Uninstall OSTP: stop service, remove binary and configuration files
    Uninstall,
    /// Update OSTP: re-run the install script to fetch and install the latest version
    Update {
        /// Release branch to update from (stable, beta, alpha)
        #[arg(short = 'b', long, default_value = "stable")]
        branch: String,
        /// Exact release version to update to (e.g. 0.4.1 or 0.4.1-beta.3),
        /// overriding the latest release on the selected branch
        #[arg(short = 'v', long, value_name = "VERSION")]
        version: Option<String>,
    },
    /// Import a share link (ostp://...) or a subscription URL (https://...) into the configuration file
    Import {
        url: String,
    },
    /// Output shell export commands for proxy (eval $(ostp proxy-env))
    ProxyEnv,
    /// Output shell export commands to clear proxy (eval $(ostp proxy-env-clear))
    ProxyEnvClear,
    /// Domain, HTTPS and Let's Encrypt certificate (server only)
    Cert {
        #[command(subcommand)]
        action: cert_cmd::CertAction,
    },
    /// Upgrade the configuration file to the current schema. This is the
    /// ONLY place config migration ever runs - never automatically at
    /// startup or during install/update, so a config never changes shape
    /// without you asking it to.
    Migrate {
        /// Show what would change without writing anything
        #[arg(long)]
        dry_run: bool,
    },
}

/// Bridges the new subcommand-based CLI onto the original flat-flag dispatch
/// below, so the ~500 lines of existing command logic don't need to change -
/// only how they get populated does.
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
    migrate_dry_run: bool,
}

/// Asks the same TUN/mux/debug questions regardless of how a share link
/// reached this config - connecting directly (`ostp connect <url>`) or
/// importing it to disk (`ostp import <url>`). Previously only the connect
/// path asked; `import` just wrote flat defaults with no way to turn any of
/// this on short of hand-editing the resulting config.json.
fn prompt_client_options(client_cfg: &mut ClientConfig) {
    use std::io::Write;
    let mut input = String::new();

    print!("{} Enable TUN (VPN) mode? [y/N]: ", "?".blue().bold());
    std::io::stdout().flush().unwrap();
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
}

fn parse_ostp_link(link: &str) -> Result<ClientConfig> {
    let l = ostp_core::share_link::ShareLink::parse(link)?;
    Ok(ClientConfig {
        server: l.server(),
        access_key: l.key.clone(),
        mtu: None,
        transport: Some(link_transport(&l)),
        socks5_bind: Some("127.0.0.1:1088".to_string()),
        tun: Some(TunConfig {
            enable: l.tun,
            wintun_path: Some("./wintun.dll".to_string()),
            ipv4_address: Some("10.1.0.2/24".to_string()),
            dns: l.dns.clone(),
            kill_switch: Some(false),
        }),

        debug: Some(false),
        exclude: None,
        mux: None,
        gui: None,
    })
}

/// Links for one key: over TLS on the domain when that is set up, and UDP.
fn share_links_for(
    server_cfg: &ostp_client::config::ServerConfig,
    key: &str,
    config_path: &std::path::Path,
) -> Vec<(&'static str, ostp_core::share_link::ShareLink)> {
    use ostp_core::share_link::{LinkTransport, ShareLink};
    let listen = server_cfg.listen.primary();
    let (listen_host, port) = match listen.rsplit_once(':') {
        Some((h, p)) => (h.trim_matches(['[', ']']).to_string(), p.parse().unwrap_or(50000)),
        None => (listen.clone(), 50000),
    };
    let domain = server_cfg.domain.clone().filter(|d| !d.is_empty());
    let host = domain.clone().unwrap_or_else(|| {
        if listen_host == "0.0.0.0" || listen_host == "::" {
            get_or_ask_public_ip(config_path)
        } else {
            listen_host
        }
    });

    let mut links = Vec::new();
    if let (Some(tls), Some(domain)) = (server_cfg.tls.as_ref().filter(|t| t.is_enabled()), &domain) {
        let mut l = ShareLink::new(key, domain, tls.public_port.unwrap_or(443));
        l.transport = LinkTransport::Uot;
        l.tls = true;
        if tls.frontend() != "builtin" {
            l.path = tls.ws_path.clone();
        }
        links.push(("TLS", l));
    }
    links.push(("UDP", ShareLink::new(key, &host, port)));
    links
}

/// The `transport` section a share link describes.
/// `https://<domain>[:port]<path>/<token>` when subscriptions are on.
fn subscription_url_for(server_cfg: &ostp_client::config::ServerConfig, key: &str) -> Option<String> {
    let sub = server_cfg.subscription.as_ref().filter(|s| s.is_enabled())?;
    let tls = server_cfg.tls.as_ref().filter(|t| t.is_enabled())?;
    let domain = server_cfg.domain.as_deref().filter(|d| !d.is_empty())?;
    let port = match tls.public_port.unwrap_or(443) {
        443 => String::new(),
        p => format!(":{p}"),
    };
    Some(format!("https://{domain}{port}{}/{}", sub.path(), ostp_core::subscription::token_for_key(key)))
}

/// Terminal QR code; light modules drawn as blocks so it scans on the usual
/// dark terminal background.
fn qr_text(data: &str) -> Result<String> {
    use qrcode::render::unicode::Dense1x2;
    let code = qrcode::QrCode::with_error_correction_level(data.as_bytes(), qrcode::EcLevel::L)
        .map_err(|e| anyhow!("cannot encode a QR code: {e}"))?;
    Ok(code
        .render::<Dense1x2>()
        .dark_color(Dense1x2::Light)
        .light_color(Dense1x2::Dark)
        .quiet_zone(true)
        .build())
}

fn cmd_links_qr(config_path: &Path, all: bool) -> Result<()> {
    let content = fs::read_to_string(config_path).with_context(|| format!("cannot read {}", config_path.display()))?;
    let stripped = json_comments::StripComments::new(content.as_bytes());
    let config: UnifiedConfig = serde_json::from_reader(stripped)?;
    let AppMode::Server(server_cfg) = config.mode else {
        anyhow::bail!("`ostp links qr` needs a server configuration");
    };
    let interactive = std::io::IsTerminal::is_terminal(&std::io::stdin());
    let total = server_cfg.access_keys.len();
    for (idx, user) in server_cfg.access_keys.iter().enumerate() {
        let key = user.key();
        // Best first: the subscription carries every link and follows changes.
        let mut entries: Vec<(String, String)> = Vec::new();
        if let Some(url) = subscription_url_for(&server_cfg, &key) {
            entries.push(("SUB".into(), url));
        }
        for (label, link) in share_links_for(&server_cfg, &key, config_path) {
            entries.push((label.to_string(), link.to_uri()));
        }
        let who = user.name().filter(|n| !n.is_empty()).unwrap_or_else(|| format!("key {}", idx + 1));
        println!("
  {} {}/{total}: {}", "Client".bold(), idx + 1, who.cyan().bold());
        for (n, (label, text)) in entries.iter().enumerate() {
            if n == 0 || all {
                println!("
  {label}");
                println!("{}", qr_text(text)?);
            }
            println!("  {label:<3}  {text}");
        }
        if interactive && idx + 1 < total {
            let answer = wizard_prompt("Enter for the next client, q to stop", "");
            if answer.trim().eq_ignore_ascii_case("q") {
                break;
            }
        }
    }
    Ok(())
}

fn format_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 { format!("{n} B") } else { format!("{v:.1} {}", UNITS[i]) }
}

fn link_transport(l: &ostp_core::share_link::ShareLink) -> TransportConfigRaw {
    TransportConfigRaw {
        mode: Some(l.transport.as_str().to_string()),
        tls: l.tls.then_some(true),
        tls_sni: l.sni.clone(),
        tls_insecure: l.insecure.then_some(true),
        ws_path: l.path.clone(),
        ..Default::default()
    }
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

/// Directory holding the config file; certificates and ACME state live under it.
fn config_dir_of(config_path: &std::path::Path) -> std::path::PathBuf {
    config_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."))
}

/// Fills in the defaults of an (already validated) `tls` section.
fn resolve_tls_settings(
    t: &ostp_client::config::TlsServerCfg,
    domain: Option<String>,
    config_path: &std::path::Path,
) -> ostp_server::tls::TlsSettings {
    use ostp_server::tls::{default_cert_paths, AcmeSettings, CertSource, Frontend, TlsSettings};
    let config_dir = config_dir_of(config_path);
    let frontend = Frontend::parse(t.frontend()).unwrap_or(Frontend::Builtin);
    let cert = CertSource::parse(t.cert_source()).unwrap_or(CertSource::Acme);
    let (default_cert, default_key) = default_cert_paths(&config_dir, domain.as_deref().unwrap_or("default"));
    let acme = t.acme.clone().unwrap_or_default();
    TlsSettings {
        frontend,
        ws_path: t.ws_path.clone().unwrap_or_default(),
        cert,
        cert_path: t.cert_path.clone().map(Into::into).unwrap_or(default_cert),
        key_path: t.key_path.clone().map(Into::into).unwrap_or(default_key),
        acme: AcmeSettings {
            email: acme.email.filter(|e| !e.is_empty()),
            staging: acme.staging.unwrap_or(false),
            directory: acme.directory.filter(|d| !d.is_empty()),
            responder: acme.responder.unwrap_or_else(|| ostp_server::tls::DEFAULT_ACME_RESPONDER.to_string()),
            renew_days_before: acme.renew_days_before,
        },
        https_listen: t.https_listen.as_ref().map(|l| l.addresses()).unwrap_or_else(|| vec!["0.0.0.0:443".into()]),
        http_listen: t.http_listen.as_ref().map(|l| l.addresses()).unwrap_or_else(|| vec!["0.0.0.0:80".into()]),
        public_port: t.public_port.unwrap_or(443),
        reload_command: t.reload_command.clone().filter(|c| !c.is_empty()),
        domain,
        config_dir,
    }
}

// The on-disk config.json shapes (client/server/relay + all nested types)
// live in ostp_client::config now - this used to be ~220 lines of struct
// definitions duplicated here with no other consumer able to see them,
// which is exactly why ostp_client::migrate had to work against loosely
// typed JSON instead of a real schema. `ClientFileConfig` is aliased back to
// the bare `ClientConfig` name used throughout the rest of this file, so it
// doesn't collide with `ostp_client::config::ClientConfig` (the RUNTIME
// shape the engine actually uses - a different thing on purpose; see the
// doc comment on that struct).
use ostp_client::config::{
    AppMode, ClientFileConfig as ClientConfig, MuxConfig, TransportConfigRaw, TunConfig,
    UnifiedConfig,
};

#[tokio::main]
async fn main() -> Result<()> {
    // Raise the open-file-descriptor limit to avoid EMFILE under many concurrent
    // connections (ported from 0.3.x fix 922cf0b). No-op / best-effort on platforms
    // where it does not apply.
    let _ = rlimit::increase_nofile_limit(1048576);
    ostp_client::logging::setup_panic_hook();
    // Clear the shared log at startup only when THIS invocation is the daemon —
    // a one-shot command (`ostp gk`, `ostp check`, ...) must not wipe a running
    // daemon's log. (Truncation itself is additionally Windows-only.)
    let is_daemon = ostp_client::logging::invocation_is_daemon(std::env::args());
    let _log_guard = ostp_client::logging::init_tracing("info", "ostp-cli", env!("CARGO_PKG_VERSION"), is_daemon);

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

/// All global (non-private) IPv4 addresses the machine holds. A VPS with a
/// second address — bought to escape a burned IP — shows up here as more than
/// one entry, which is what the multi-address egress feature (bind_ip /
/// send_from) routes over.
fn detect_all_public_ipv4() -> Vec<String> {
    let mut ips = Vec::new();
    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(out) = std::process::Command::new("ip")
            .args(["-4", "addr", "show", "scope", "global"])
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                if let Some(idx) = line.find("inet ") {
                    let substr = &line[idx + 5..];
                    let ip = substr
                        .split(|c: char| c == '/' || c.is_whitespace())
                        .next()
                        .unwrap_or("");
                    if !ip.is_empty() && !is_private_ip(ip) && !ips.contains(&ip.to_string()) {
                        ips.push(ip.to_string());
                    }
                }
            }
        }
    }
    ips
}

/// Detect the machine's public IPv4 address(es), record them one per line in
/// `.ostp_public_ip`, and — when there is more than one — offer to set up
/// multi-address egress. Called from the server setup wizard.
///
/// Returns `Some(primary_ip)` to be used as the config's global `bind_ip` when
/// the operator opts into multi-address egress; `None` when there is a single
/// address or they decline (leave egress on the OS default). The file is always
/// written regardless, so the addresses are on hand for editing send_from later.
fn setup_public_ips(config_dir: &std::path::Path) -> Option<String> {
    let cache_path = config_dir.join(".ostp_public_ip");
    let detected = detect_all_public_ipv4();
    if detected.is_empty() {
        return None;
    }

    // Record every detected address, one per line, so it is available later for
    // configuring bind_ip / send_from. The first line stays the primary.
    let _ = std::fs::write(&cache_path, detected.join("\n") + "\n");

    if detected.len() == 1 {
        println!("  {} Detected public IP: {}", "[ostp]".green().bold(), detected[0].cyan());
        return None;
    }

    println!("  {} Detected {} public IPs (saved to {}):", "[ostp]".green().bold(), detected.len(), cache_path.display());
    for ip in &detected {
        println!("      • {}", ip.cyan());
    }
    let multi = wizard_yn(
        "Set up multi-address egress (route different destinations out of different IPs)?",
        true,
    );
    if !multi {
        return None;
    }
    println!(
        "      Global source set to {}. Per-destination sources go in outbound rules, e.g.\n      \
         {{ \"domain_suffix\": [\"youtube.com\"], \"action\": \"direct\", \"send_from\": \"{}\" }}",
        detected[0].cyan(),
        detected.last().unwrap()
    );
    detected.into_iter().next()
}

fn get_or_ask_public_ip(config_path: &std::path::Path) -> String {
    let config_dir = config_path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let cache_path = config_dir.join(".ostp_public_ip");

    if cache_path.exists() {
        if let Ok(cached) = std::fs::read_to_string(&cache_path) {
            // The file may hold several addresses (one per line); the first
            // non-empty line is the primary that links advertise.
            if let Some(ip) = cached.lines().map(|l| l.trim()).find(|l| !l.is_empty()) {
                return ip.to_string();
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
    println!("  {}", "-".repeat(50).dimmed());
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

/// Returns the saved config's path when the user asked to set up HTTPS,
/// which needs async work the caller runs afterwards.
fn run_setup_wizard(config_path: &std::path::Path) -> Result<Option<PathBuf>> {
    let mut https_for: Option<PathBuf> = None;
    use std::io::Write;

    println!();
    wizard_box(&[
        "OSTP Setup Wizard",
        concat!("Version ", env!("CARGO_PKG_VERSION")),
        "",
        "This wizard will create your configuration file.",
        "Press Enter to accept the value shown in [brackets].",
    ]);

    // -- Mode selection ------------------------------------------------
    println!();
    println!("  {}", "Select operating mode:".bold());
    println!("  {}", "-".repeat(50).dimmed());

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
        // -- CLIENT ----------------------------------------------------
        "1" => {
            #[cfg(unix)]  const TOTAL: usize = 5;
            #[cfg(windows)] const TOTAL: usize = 4;

            wizard_step(1, TOTAL, "Server connection");

            // Try import from link first
            let use_link = wizard_yn("Do you have a share link (ostp://...)?", false);
            let (server, access_key, transport) = if use_link {
                loop {
                    let link_str = wizard_prompt("Paste link", "");
                    match ostp_core::share_link::ShareLink::parse(&link_str) {
                        Ok(l) => break (l.server(), l.key.clone(), link_transport(&l)),
                        Err(e) => wizard_warn(&format!("Not a valid ostp:// link: {e}")),
                    }
                }
            } else {
                ("127.0.0.1:50000".to_string(), "".to_string(), TransportConfigRaw { mode: Some("udp".into()), ..Default::default() })
            };

            wizard_step(2, TOTAL, "Local proxy");
            let socks_bind = wizard_prompt("Local SOCKS5 proxy bind address", "127.0.0.1:1088");

            wizard_step(3, TOTAL, "VPN (TUN) mode");

            // SSH warning on Linux - always
            #[cfg(unix)]
            {
                println!();
                println!("  ┌{}", "-".repeat(60));
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
                println!("  └{}", "-".repeat(60));
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

            // Daemon step - Linux only
            #[cfg(unix)]
            {
                wizard_step(5, TOTAL, "Auto-start (systemd)");
            }

            // Build and save config
            let key_for_gen = generate_secure_key("hex");
            let _ = key_for_gen;

            let client_json = serde_json::json!({
                "mode": "client",
                "config_version": ostp_client::migrate::CURRENT_VERSION,
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
                "transport": transport,
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
                "To check:  ostp check",
                "Proxy env: eval $(ostp proxy-env)",
            ]);
        }

        // -- SERVER ----------------------------------------------------
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

            // Auto-detect the machine's public IPs and, when there is more than
            // one, offer multi-address egress (records them in .ostp_public_ip).
            let config_dir = config_path.parent().unwrap_or_else(|| std::path::Path::new("."));
            let bind_ip = setup_public_ips(config_dir);

            wizard_step(3, TOTAL, "Service registration");
            // intentional: step text then daemon call below
            let mut server_json = serde_json::json!({
                "mode": "server",
                "config_version": ostp_client::migrate::CURRENT_VERSION,
                "log_level": "info",
                "listen": listen,
                "access_keys": access_keys,
                "outbound": {
                    "enabled": false,
                    "protocol": "socks5",
                    "address": "127.0.0.1",
                    "port": 9050,
                    "username": "",
                    "password": "",
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
            if let Some(ip) = &bind_ip {
                server_json["bind_ip"] = serde_json::json!(ip);
            }

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
                "To check:  ostp check",
                "Share links: ostp links",
            ]);
            println!();
            if wizard_yn("Bind a domain name and serve OSTP over HTTPS on 443 (Let's Encrypt)?", false) {
                https_for = Some(actual_path.clone());
            }
        }

        // -- SERVER + PANEL (Linux only) -------------------------------
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
            // Must match api.rs's handle_login exactly (format!("{:x}", Sha256::digest(..))) -
            // this used to be a DefaultHasher (SipHash) placeholder that produced a
            // differently-shaped digest, so a password set up through this wizard could
            // never actually log into the panel it just configured.
            // Trait-qualified so this compiles whether or not `sha2::Digest` happens
            // to be in scope: `digest` is a trait method, and relying on the import
            // alone broke the CI build once (v0.4.2-beta.3) while resolving fine
            // locally.
            let pass_hash = format!(
                "{:x}",
                <sha2::Sha256 as sha2::Digest>::digest(password.as_bytes())
            );

            // Auto-detect public IPs and offer multi-address egress.
            let config_dir = config_path.parent().unwrap_or_else(|| std::path::Path::new("."));
            let bind_ip = setup_public_ips(config_dir);

            wizard_step(4, TOTAL, "Saving configuration");
            let panel_bind = format!("0.0.0.0:{}", panel_port);
            let mut server_json = serde_json::json!({
                "mode": "server",
                "config_version": ostp_client::migrate::CURRENT_VERSION,
                "log_level": "info",
                "listen": listen,
                "access_keys": access_keys,
                "outbound": {
                    "enabled": false,
                    "protocol": "socks5",
                    "address": "127.0.0.1",
                    "port": 9050,
                    "username": "",
                    "password": "",
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
            if let Some(ip) = &bind_ip {
                server_json["bind_ip"] = serde_json::json!(ip);
            }

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
            println!();
            if wizard_yn("Bind a domain name: HTTPS on 443 for clients and the panel (Let's Encrypt)?", false) {
                https_for = Some(actual_path.clone());
            }
        }

        // -- RELAY (Linux only) ----------------------------------------
        #[cfg(unix)]
        "4" => {
            const TOTAL: usize = 3;

            wizard_step(1, TOTAL, "Listen & upstream");
            let listen   = wizard_prompt("Listen address (host:port)", "0.0.0.0:50000");
            let upstream = wizard_prompt("Upstream server address (host:port)", "");
            if upstream.is_empty() { anyhow::bail!("Upstream address cannot be empty."); }

            wizard_step(2, TOTAL, "Saving configuration");
            // No credentials are collected: the relay forwards transparently and
            // authenticates nothing, so it needs neither the target's API nor a
            // copy of the access keys.
            let relay_json = serde_json::json!({
                "mode": "relay",
                "config_version": ostp_client::migrate::CURRENT_VERSION,
                "listen": listen,
                "upstream_tcp": upstream,
                "upstream_udp": upstream,
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

    Ok(https_for)
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
        migrate_dry_run: false,
    };

    if let Some(cmd) = raw_args.command {
        match cmd {
            Commands::Setup { init } => { args.setup = true; args.init = init; }
            Commands::Init { mode } => { args.init = Some(mode); }
            Commands::HashPassword { password } => {
                // The panel stores only a hash, and until now nothing in the CLI
                // could produce one: `ostp init server` writes password_hash: ""
                // and the only generator lived inside the Unix-only Server+Panel
                // wizard branch, leaving no supported way to set up API auth on a
                // plain server.
                let password = match password {
                    Some(p) => p,
                    None => {
                        print!("Password: ");
                        use std::io::Write as _;
                        std::io::stdout().flush().ok();
                        let mut buf = String::new();
                        std::io::stdin().read_line(&mut buf)?;
                        buf.trim_end_matches(['\r', '\n']).to_string()
                    }
                };
                if password.is_empty() {
                    anyhow::bail!("password must not be empty");
                }
                // Must match api.rs's handle_login byte for byte.
                let hash = format!(
                    "{:x}",
                    <sha2::Sha256 as sha2::Digest>::digest(password.as_bytes())
                );
                println!();
                println!("Add this to the \"api\" section of your config:");
                println!();
                println!("  \"password_hash\": \"{hash}\"");
                println!();
                return Ok(());
            }
            Commands::GenerateKey { format, count } => { args.generate_key = true; args.format = format; args.count = count; }
            Commands::Links { view: Some(_), all } => return cmd_links_qr(&args.config, all),
            Commands::Links { view: None, .. } => { args.links = true; }
            Commands::Check => { args.check = true; }
            Commands::Connect { url } => { args.url = Some(url); }
            Commands::Uninstall => { args.uninstall = true; }
            Commands::Update { branch, version } => { args.update = true; args.update_branch = branch; args.target_version = version; }
            Commands::Import { url } => { args.import = Some(url); }
            Commands::ProxyEnv => { args.proxy_env = true; }
            Commands::ProxyEnvClear => { args.proxy_env_clear = true; }
            Commands::Migrate { dry_run } => { args.migrate = true; args.migrate_dry_run = dry_run; }
            Commands::Cert { action } => return cert_cmd::run(action, &args.config).await,
        }
    }

    if args.uninstall {
        return cmd_uninstall();
    }

    if args.update {
        return cmd_update(args.update_branch, args.target_version);
    }

    if args.migrate {
        return cmd_migrate(&args.config, args.migrate_dry_run);
    }

    // -- Setup wizard: explicit flag or first-time (no config) --------
    if args.setup {
        if let Some(path) = run_setup_wizard(&args.config)? {
            cert_cmd::issue_interactive(&path, cert_cmd::IssueArgs::default()).await?;
        }
        return Ok(());
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
        if let Some(path) = run_setup_wizard(&args.config)? {
            cert_cmd::issue_interactive(&path, cert_cmd::IssueArgs::default()).await?;
        }
        return Ok(());
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
        let import_url = if import_url.trim().to_ascii_lowercase().starts_with("https://") {
            println!("{} Fetching subscription...", "[ostp]".cyan().bold());
            let doc = ostp_client::subscription::fetch(&import_url)
                .await
                .map_err(|e| anyhow!("Subscription Error: {e}"))?;
            let links = doc.valid_links();
            println!("  {} — {} link(s), refresh every {} h", doc.name.bold(), links.len(), doc.update_interval_hours);
            if let Some(u) = &doc.usage {
                let limit = u.limit_bytes.map(format_bytes).unwrap_or_else(|| "unlimited".into());
                println!("  Traffic: {} of {limit}", format_bytes(u.used_bytes));
            }
            for (i, l) in links.iter().enumerate() {
                println!("  [{}] {}", i + 1, l.name.clone().unwrap_or_else(|| l.server()));
            }
            let pick = if links.len() > 1 && std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                wizard_prompt("Which one", "1").trim().parse::<usize>().unwrap_or(1).clamp(1, links.len())
            } else {
                1
            };
            println!("  Run `ostp import <url>` again to pick up server changes.");
            links[pick - 1].to_uri()
        } else {
            import_url
        };
        println!("{} Importing configuration from share link...", "[ostp]".cyan().bold());
        let mut client_cfg = parse_ostp_link(&import_url)
            .map_err(|e| anyhow!("Share Link Error: {e}"))?;
        prompt_client_options(&mut client_cfg);
        let unified = UnifiedConfig {
            mode: AppMode::Client(client_cfg),
            log_level: Some("info".to_string()),
            config_version: Some(ostp_client::migrate::CURRENT_VERSION),
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
        prompt_client_options(&mut client_cfg);

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
                        if let Some(d) = s.domain.as_deref().filter(|d| !d.is_empty()) {
                            println!("  Domain: {}", d.cyan());
                        }
                        match s.tls.as_ref().filter(|t| t.is_enabled()) {
                            Some(t) => println!("  HTTPS: enabled ({} frontend, certificate: {}) - details: ostp cert status",
                                t.frontend(), t.cert_source()),
                            None => println!("  HTTPS: disabled (set up with: ostp cert issue)"),
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
                        if !r.upstream_api_url.is_empty() {
                            println!("  {}", "upstream_api_url is set but no longer used - safe to remove".yellow());
                        }
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
  "config_version": 2,
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

  // Domain & HTTPS - easiest via `ostp cert issue`. The domain goes into share
  // links. With tls enabled OSTP accepts TLS on its own port too; the builtin
  // frontend also serves 443 (and 80 for Let's Encrypt) itself, while nginx /
  // apache / caddy forward the secret ws_path to it.
  "domain": "",
  "tls": {{
    "enabled": false,
    "frontend": "builtin",
    "ws_path": "{ws}",
    "cert": "acme",
    "public_port": 443,
    "acme": {{ "email": "", "staging": false }}
  }},

  // Subscriptions (needs tls + domain): every key gets
  // https://<domain>/sub/<token>, which apps re-fetch to pick up changes.
  // `ostp links` prints the URLs.
  "subscription": {{
    "enabled": false,
    "path": "/sub",
    "update_interval_hours": 12,
    "include": ["tls", "udp"]
  }},

  "debug": false
}}"#, key, ws = cert_cmd::random_path())
        } else if mode_str == "relay" {
            r#"{
  // OSTP Relay Node Configuration
  "mode": "relay",
  "config_version": 2,
  "listen": "0.0.0.0:50000",
  "upstream_tcp": "TARGET_SERVER_IP:50000",
  "upstream_udp": "TARGET_SERVER_IP:50000",
  // The relay forwards transparently and holds no keys: sessions are
  // authenticated end-to-end by the target server, which drops anything that
  // fails. Nothing else needs configuring here.
  "debug": false
}"#.to_string()
        } else {
            format!(r#"{{
  // OSTP Client Configuration
  "mode": "client",
  "config_version": 2,
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
  
  // Transport Mode: "udp" (default) or "uot" (UDP over TCP, no mimicry)
  "transport": {{
    "mode": "udp"
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
                    let mut query_params = Vec::<String>::new();
                    query_params.push("type=udp".to_string());

                    let mut link = format!("ostp://{}@{}:50000", key.key(), host);
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
             \t./ostp init server\n\
             \tor\n\
             \t./ostp init client\n\n\
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
    let current = ostp_client::migrate::CURRENT_VERSION;
    match config.config_version {
        Some(v) if v > current => println!(
            "{} {:?} was written by a newer ostp (schema v{v}, this one knows v{current}); settings it doesn't know are ignored.",
            "[warn]".yellow().bold(), args.config
        ),
        Some(v) if v == current => {}
        _ => println!(
            "{} {:?} predates config schema v{current}; `ostp migrate --dry-run` shows what would change.",
            "[note]".cyan().bold(), args.config
        ),
    }

    if args.links {
        match config.mode {
            AppMode::Server(server_cfg) => {
                println!("\n  Client share links from {:?}:", args.config);
                for (idx, key) in server_cfg.access_keys.iter().enumerate() {
                    for (label, link) in share_links_for(&server_cfg, &key.key(), &args.config) {
                        println!("  [{}] {label:<3}  {}", idx + 1, link.to_uri());
                    }
                    if let Some(url) = subscription_url_for(&server_cfg, &key.key()) {
                        println!("  [{}] SUB  {url}", idx + 1);
                    }
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
                username: o.username,
                password: o.password,
                rules: o
                    .rules
                    .into_iter()
                    .map(|r| ostp_server::OutboundRule {
                        domain_suffix: r.domain_suffix.unwrap_or_default(),
                        ip_cidr: r.ip_cidr.unwrap_or_default(),
                        protocol: r.protocol,
                        action: parse_outbound_action(r.action),
                        send_from: r.send_from,
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
            let domain = server_cfg.domain.clone().filter(|d| !d.is_empty());
            // With a domain there is nothing to ask: never prompt from a service.
            let host = domain.clone().unwrap_or_else(|| get_or_ask_public_ip(&args.config));
            let tls = server_cfg
                .tls
                .as_ref()
                .filter(|t| t.is_enabled())
                .map(|t| resolve_tls_settings(t, domain.clone(), &args.config));
            let subscription = server_cfg.subscription.as_ref().filter(|s| s.is_enabled()).map(|s| {
                ostp_server::SubscriptionSettings {
                    prefix: s.path(),
                    name: s.name.clone().filter(|n| !n.is_empty()).or_else(|| domain.clone()).unwrap_or_else(|| "OSTP".into()),
                    update_interval_hours: s.update_interval_hours(),
                    include_tls: s.includes("tls"),
                    include_udp: s.includes("udp"),
                }
            });
            // Build DNS config and set owndns flag in subscribe links if DNS enabled.
            // Kept untyped (serde_json::Value) in the shared ServerConfig so
            // ostp-client doesn't need a dependency on ostp-server just to
            // name this type - deserialize it here instead, where both
            // crates are already in scope.
            let dns_cfg: Option<ostp_server::dns::DnsConfig> = server_cfg
                .dns
                .map(serde_json::from_value)
                .transpose()
                .map_err(|e| anyhow!("Invalid 'dns' section in server config: {e}"))?;
            ostp_server::run_server(ostp_server::ServerParams {
                bind_addrs: listen_addrs,
                server_public_ip: Some(host),
                bind_ip: server_cfg.bind_ip,
                access_keys: access_keys_meta,
                outbound,
                api_config,
                fallback_config,
                debug,
                dns_config: dns_cfg,
                config_path: Some(args.config),
                tls,
                subscription,
            })
            .await?;
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
            if !relay_cfg.upstream_api_url.is_empty() {
                println!(
                    "{} Note: upstream_api_url is no longer used and can be removed. The relay \
                     forwards transparently; sessions are authenticated end-to-end by the target \
                     server.",
                    "[ostp]".yellow().bold()
                );
            }
            let relay_config = ostp_server::RelayConfig {
                listen_addrs,
                upstream_tcp: relay_cfg.upstream_tcp,
                upstream_udp: relay_cfg.upstream_udp,
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

    // 5. Take the OSTP site back out of nginx/apache/caddy, if one was added
    webserver::uninstall(std::path::Path::new("/etc/ostp"));

    // 6. Remove configuration directory (certificates included)
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

    println!("[ostp] Updating OSTP (branch={branch})...");

    let mut script_args = vec!["-c".to_string()];
    if let Some(v) = version {
        script_args.push(format!(
            "bash <(curl -Ls https://raw.githubusercontent.com/ospab/ostp/master/scripts/install.sh) --branch {} -v {}",
            branch, v
        ));
    } else {
        script_args.push(format!(
            "bash <(curl -Ls https://raw.githubusercontent.com/ospab/ostp/master/scripts/install.sh) --branch {}",
            branch
        ));
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
fn cmd_update(_branch: String, _version: Option<String>) -> Result<()> {
    anyhow::bail!("The 'update' command is only supported on Linux/Unix systems.");
}

/// The ONLY place config migration ever runs - see ostp_client::migrate for
/// why (and for the actual field-by-field mapping). Never called
/// automatically; only this explicit command touches an existing config's
/// shape.
fn cmd_migrate(config_path: &std::path::Path, dry_run: bool) -> Result<()> {
    use ostp_client::migrate::{self, Change};
    if !config_path.exists() {
        anyhow::bail!("Configuration file not found at {:?}", config_path);
    }

    let raw = fs::read_to_string(config_path)?;
    let mut stripped = json_comments::StripComments::new(raw.as_bytes());
    let mut content = String::new();
    {
        use std::io::Read;
        stripped.read_to_string(&mut content)?;
    }
    let had_comments = content != raw;
    let parsed: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| anyhow!("Failed to parse {:?} as JSON: {}", config_path, e))?;

    let m = migrate::migrate(parsed)?;
    let tag = "[ostp]".cyan().bold();

    for u in &m.unknown_keys {
        let hint = u.suggestion.as_ref().map(|s| format!(" - did you mean \"{s}\"?")).unwrap_or_default();
        println!("{} unknown setting \"{}\" is ignored by ostp{hint}", "[warn]".yellow().bold(), u.path);
    }

    if m.is_up_to_date() {
        println!("{tag} {:?} is a current {} config (schema version {}), nothing to migrate.",
            config_path, m.kind.as_str(), migrate::CURRENT_VERSION);
        return Ok(());
    }

    println!("{tag} {} config, schema version {} -> {}",
        m.kind.as_str(), m.from_version, migrate::CURRENT_VERSION);
    for step in &m.steps {
        println!("  {} (from v{})", step.title.bold(), step.from);
        for note in &step.notes {
            println!("    - {note}");
        }
    }
    println!("  Changes:");
    for c in &m.changes {
        let line = c.to_string();
        let line = match c {
            Change::Added { .. } => line.green(),
            Change::Removed { .. } => line.red(),
            Change::Changed { .. } => line.yellow(),
        };
        println!("    {line}");
    }
    if had_comments {
        println!("{} comments are not kept in the rewritten file; the original stays in the backup.", "[note]".cyan().bold());
    }

    if dry_run {
        println!("\n{tag} Dry run: nothing written. Run without --dry-run to apply.");
        return Ok(());
    }

    let backup_path = config_path.with_extension("json.bak");
    fs::copy(config_path, &backup_path)?;
    let mut out = serde_json::to_string_pretty(&m.output)?;
    out.push('\n');
    fs::write(config_path, out)?;
    println!("\n{tag} Migrated {:?}; the original is in {:?}.", config_path, backup_path);
    println!("{tag} Run 'ostp check' to validate it.");
    Ok(())
}

#[cfg(target_os = "windows")]
fn ensure_elevated_for_tun() -> Result<()> {
    #[link(name = "shell32")]
    extern "system" {
        fn IsUserAnAdmin() -> i32;
        fn ShellExecuteW(h: *mut std::ffi::c_void, op: *const u16, f: *const u16, p: *const u16, d: *const u16, s: i32) -> isize;
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetLastError() -> u32;
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

    // Reconstruct arguments so the elevated relaunch runs the same command.
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

    // ShellExecuteW's return is a pseudo-HINSTANCE: > 32 means the call itself
    // "succeeded" - but that range INCLUDES ERROR_CANCELLED (1223), which is
    // exactly what Windows returns when the user clicks "No" on the UAC
    // prompt. The old check (`ret <= 32` only) treated a user-denied prompt
    // as success and silently exited without ever starting the tunnel.
    if ret == 1223 {
        anyhow::bail!("UAC elevation was denied. TUN mode requires administrator privileges.");
    }
    if ret <= 32 {
        let win_err = unsafe { GetLastError() };
        anyhow::bail!(
            "Failed to request UAC elevation (ShellExecuteW ret={}, GetLastError={}). \
             If this keeps happening, an unsigned binary can be silently blocked by \
             SmartScreen/antivirus during elevation - try running this as Administrator manually.",
            ret, win_err
        );
    }
    std::process::exit(0);
}

async fn run_client_directly(client_cfg: ClientConfig) -> Result<()> {
    let is_tun_enabled = client_cfg.tun.as_ref().map(|t| t.enable).unwrap_or(false);
    let mode_str = if is_tun_enabled { "tun" } else { "proxy" };
    println!("{} Starting client (mode={}, server={})", "[ostp]".cyan().bold(), mode_str.yellow(), client_cfg.server.cyan());

    // TUN mode needs admin rights to create the WinTun adapter. This was
    // missing entirely before - the CLI would just try to create the
    // adapter unelevated and fail at the driver level with no UAC prompt
    // ever shown, which is what "UAC denied regardless of GUI or TUI"
    // actually was for this code path: TUI never asked for elevation at all.
    #[cfg(target_os = "windows")]
    if is_tun_enabled {
        ensure_elevated_for_tun()?;
    }

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
        exclusions: ostp_client::config::ExclusionConfig {
            domains: client_cfg.exclude.as_ref().and_then(|e| e.domains.clone()).unwrap_or_default(),
            ips: client_cfg.exclude.as_ref().and_then(|e| e.ips.clone()).unwrap_or_default(),
            processes: client_cfg.exclude.as_ref().and_then(|e| e.processes.clone()).unwrap_or_default(),
        },
        multiplex: ostp_client::config::MultiplexConfig {
            enabled: client_cfg.mux.as_ref().and_then(|m| m.enabled).unwrap_or(false),
            sessions: client_cfg.mux.as_ref().and_then(|m| m.sessions).unwrap_or(1),
        },
        transport: client_cfg.transport.clone().unwrap_or_default().to_runtime(),
        dns_server: client_cfg.tun.as_ref().and_then(|t| t.dns.clone()),
        kill_switch: client_cfg.tun.as_ref().and_then(|t| t.kill_switch).unwrap_or(false),
        gui: None,
    };

    // Run the client implementation
    ostp_client::runner::run_client(client_conf).await?;
    Ok(())
}
