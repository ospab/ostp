//! `ostp panel`: the web panel and management API, managed on their own.
//!
//! Like `ostp sub`: each subcommand changes exactly what it names, backs up
//! the config, restarts a running service to apply it (`--no-restart` to
//! skip) and rewrites the web-server site only with `--vhost`. Passwords are
//! never taken as arguments (they would land in shell history): they are
//! read from the terminal without echo, or from stdin when piped.

use anyhow::{anyhow, bail, Context, Result};
use colored::Colorize;
use std::io::{IsTerminal, Write};
use std::path::Path;

use crate::cert_cmd::{listen_port, panel_route, read_json, restart_service, subscription_prefix, tls_settings};
use crate::sub_cmd::{vhost_forwards, web_kind};
use crate::webserver::{self, Kind, VhostParams};
use ostp_client::config::UnifiedConfig;
use ostp_server::tls::Frontend;

const DEFAULT_BIND: &str = "127.0.0.1:9090";

#[derive(clap::Subcommand, Debug)]
pub enum PanelAction {
    /// Show whether the panel is on, where it listens, how to open it and whether sign-in is set up
    Status,
    /// Turn the panel on (asks for a login and a password when none is set)
    Enable(PanelOpts),
    /// Turn the panel off (settings are kept)
    Disable {
        /// Do not restart the running ostp service
        #[arg(long)]
        no_restart: bool,
    },
    /// Change panel settings without turning it on or off
    Set(PanelOpts),
    /// Set the sign-in password (asked twice, not echoed; or read from stdin)
    Passwd {
        /// Also change the sign-in name
        #[arg(long)]
        user: Option<String>,
        /// Do not restart the running ostp service
        #[arg(long)]
        no_restart: bool,
    },
    /// API token for scripts: show it, make a new one, or remove it
    Token {
        /// Replace the token with a new random one
        #[arg(long, conflicts_with = "clear")]
        new: bool,
        /// Remove the token (the API then accepts only panel sign-ins)
        #[arg(long)]
        clear: bool,
        /// Do not restart the running ostp service
        #[arg(long)]
        no_restart: bool,
    },
}

#[derive(clap::Args, Debug, Default, Clone)]
pub struct PanelOpts {
    /// Address the panel and API listen on, e.g. 127.0.0.1:9090
    #[arg(long)]
    pub bind: Option<String>,
    /// URL path of the panel: it is served at /<webpath>/
    #[arg(long)]
    pub webpath: Option<String>,
    /// Sign-in name
    #[arg(long)]
    pub user: Option<String>,
    /// Also rewrite the OSTP-managed web-server site so it forwards the panel path
    #[arg(long)]
    pub vhost: bool,
    /// Do not restart the running ostp service
    #[arg(long)]
    pub no_restart: bool,
}

pub fn run(action: PanelAction, config_path: &Path) -> Result<()> {
    match action {
        PanelAction::Status => status(config_path),
        PanelAction::Enable(o) => {
            let mut v = read_json(config_path)?;
            let mut api = api_obj(&v);
            api["enabled"] = true.into();
            apply_opts(&mut api, &o)?;
            if str_of(&api, "bind").is_empty() {
                api["bind"] = DEFAULT_BIND.into();
            }
            if str_of(&api, "username").is_empty() {
                let name = if std::io::stdin().is_terminal() { prompt_line("Sign-in name [admin]: ")? } else { String::new() };
                api["username"] = if name.is_empty() { "admin".into() } else { name.into() };
            }
            if str_of(&api, "password_hash").is_empty() {
                println!("  The panel needs a password (it controls the server).");
                api["password_hash"] = hash(&read_new_password()?).into();
            }
            v["api"] = api;
            save(config_path, &v)?;
            after_change(config_path, &v, o.vhost, o.no_restart)
        }
        PanelAction::Disable { no_restart } => {
            let mut v = read_json(config_path)?;
            let mut api = api_obj(&v);
            api["enabled"] = false.into();
            v["api"] = api;
            save(config_path, &v)?;
            after_change(config_path, &v, false, no_restart)
        }
        PanelAction::Set(o) => {
            if o.bind.is_none() && o.webpath.is_none() && o.user.is_none() && !o.vhost {
                bail!("nothing to change: pass --bind, --webpath, --user or --vhost");
            }
            let mut v = read_json(config_path)?;
            let mut api = api_obj(&v);
            apply_opts(&mut api, &o)?;
            v["api"] = api;
            save(config_path, &v)?;
            after_change(config_path, &v, o.vhost, o.no_restart)
        }
        PanelAction::Passwd { user, no_restart } => {
            let mut v = read_json(config_path)?;
            let mut api = api_obj(&v);
            if let Some(u) = user {
                api["username"] = u.trim().into();
            }
            if str_of(&api, "username").is_empty() {
                bail!("no sign-in name yet: ostp panel passwd --user NAME");
            }
            api["password_hash"] = hash(&read_new_password()?).into();
            v["api"] = api;
            save(config_path, &v)?;
            println!("  {} Password set for \"{}\"; signed-in sessions end on restart", "✓".green(), str_of(&v["api"], "username"));
            restart_service(no_restart);
            Ok(())
        }
        PanelAction::Token { new, clear, no_restart } => {
            let mut v = read_json(config_path)?;
            let mut api = api_obj(&v);
            if !new && !clear {
                match api.get("token").and_then(|t| t.as_str()).filter(|t| !t.is_empty()) {
                    Some(t) => println!("  API token: {t}\n  Send it as: Authorization: Bearer <token>"),
                    None => println!("  No API token. Make one: ostp panel token --new"),
                }
                return Ok(());
            }
            if clear {
                api.as_object_mut().map(|o| o.remove("token"));
            } else {
                let token: String = (0..32).map(|_| format!("{:x}", rand::random::<u8>() & 0xf)).collect();
                api["token"] = token.clone().into();
                println!("  New API token: {token}");
            }
            v["api"] = api;
            save(config_path, &v)?;
            restart_service(no_restart);
            Ok(())
        }
    }
}

fn api_obj(v: &serde_json::Value) -> serde_json::Value {
    v.get("api").cloned().filter(|a| a.is_object()).unwrap_or_else(|| serde_json::json!({}))
}

fn str_of(api: &serde_json::Value, key: &str) -> String {
    api.get(key).and_then(|x| x.as_str()).unwrap_or("").to_string()
}

fn apply_opts(api: &mut serde_json::Value, o: &PanelOpts) -> Result<()> {
    if let Some(b) = &o.bind {
        let b = b.trim();
        b.parse::<std::net::SocketAddr>().map_err(|_| anyhow!("--bind must be an address with a port, e.g. 127.0.0.1:9090"))?;
        api["bind"] = b.into();
    }
    if let Some(w) = &o.webpath {
        let w = w.trim().trim_matches('/');
        if w.is_empty() || !w.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~')) {
            bail!("--webpath must be one path segment of letters, digits, - _ . ~ (e.g. panel or x7Kq2m)");
        }
        api["webpath"] = w.into();
    }
    if let Some(u) = &o.user {
        let u = u.trim();
        if u.is_empty() {
            bail!("--user must not be empty");
        }
        api["username"] = u.into();
    }
    Ok(())
}

/// Validates the whole config, then writes it with a backup.
fn save(config_path: &Path, v: &serde_json::Value) -> Result<()> {
    let parsed: UnifiedConfig = serde_json::from_value(v.clone()).context("the resulting config does not parse")?;
    parsed.validate()?;
    let backup = config_path.with_extension("json.bak");
    std::fs::copy(config_path, &backup).with_context(|| format!("cannot back up {}", config_path.display()))?;
    std::fs::write(config_path, serde_json::to_string_pretty(v)?)
        .with_context(|| format!("cannot write {}", config_path.display()))?;
    println!("  {} Saved {} (previous: {})", "✓".green(), config_path.display(), backup.display());
    Ok(())
}

fn after_change(config_path: &Path, v: &serde_json::Value, vhost: bool, no_restart: bool) -> Result<()> {
    print_settings(v);
    if let (Some(t), Some((webpath, api_addr))) = (tls_settings(config_path).ok(), panel_route(v)) {
        if let Some(kind) = web_kind(t.frontend) {
            if vhost {
                let domain = t.domain.clone().ok_or_else(|| anyhow!("no domain in the config"))?;
                let params = VhostParams {
                    domain,
                    ws_path: t.ws_path.clone(),
                    ostp_port: listen_port(v),
                    panel: panel_route(v),
                    subscription: subscription_prefix(v),
                    responder: t.acme.responder.clone(),
                    cert_path: t.cert_path.clone(),
                    key_path: t.key_path.clone(),
                };
                webserver::install(kind, &params, &crate::config_dir_of(config_path))?;
                println!("  {} {} site rewritten and reloaded", "✓".green(), kind.as_str());
            } else if !vhost_forwards(config_path, &format!("/{webpath}")) {
                println!(
                    "\n  {} {} does not forward /{webpath}/ to the panel. Run `ostp panel set --vhost` to rewrite the\n    OSTP-managed site, or add this to your {} config yourself:\n\n{}\n",
                    "!".yellow(),
                    kind.as_str(),
                    kind.as_str(),
                    snippet(kind, &webpath, &api_addr)
                );
            }
        }
    }
    restart_service(no_restart);
    Ok(())
}

fn snippet(kind: Kind, webpath: &str, api: &str) -> String {
    match kind {
        Kind::Nginx => format!(
            "    location ^~ /{webpath}/ {{\n        proxy_pass http://{api};\n        proxy_set_header Host $host;\n        proxy_set_header X-Real-IP $remote_addr;\n        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n    }}"
        ),
        Kind::Apache => format!("    ProxyPass /{webpath}/ http://{api}/{webpath}/\n    ProxyPassReverse /{webpath}/ http://{api}/{webpath}/"),
        Kind::Caddy => format!("    handle /{webpath}/* {{\n        reverse_proxy {api}\n    }}"),
    }
}

fn print_settings(v: &serde_json::Value) {
    let api = api_obj(v);
    let on = api.get("enabled").and_then(|e| e.as_bool()).unwrap_or(false);
    let bind = Some(str_of(&api, "bind")).filter(|b| !b.is_empty()).unwrap_or_else(|| DEFAULT_BIND.into());
    let webpath = Some(str_of(&api, "webpath").trim_matches('/').to_string()).filter(|w| !w.is_empty()).unwrap_or_else(|| "panel".into());
    let user = str_of(&api, "username");
    let has_pass = !str_of(&api, "password_hash").is_empty();
    let has_token = !str_of(&api, "token").is_empty();
    println!("    Panel:     {}", if on { "on".green().bold() } else { "off".yellow().bold() });
    println!("    Listens:   {bind}");
    println!("    Path:      /{webpath}/");
    println!("    Sign-in:   {}", match (user.is_empty(), has_pass) {
        (false, true) => format!("{user} (password set)"),
        (false, false) => format!("{user} (no password: ostp panel passwd)").red().to_string(),
        (true, _) => "not set up: ostp panel passwd --user NAME".red().to_string(),
    });
    println!("    API token: {}", if has_token { "set (ostp panel token)" } else { "none" });
    if on && user.is_empty() && !has_pass && !has_token {
        println!("    {} Without sign-in anyone who reaches {bind} controls the server.", "!".red());
    }
    if on && (bind.starts_with("0.0.0.0") || bind.starts_with("[::]")) {
        println!("    {} {bind} is reachable from the internet over plain HTTP: passwords travel unencrypted. Prefer 127.0.0.1 and HTTPS through the domain or an SSH tunnel.", "!".yellow());
    }
}

fn status(config_path: &Path) -> Result<()> {
    let v = read_json(config_path)?;
    println!("\n  {}", "Web panel".bold());
    print_settings(&v);
    let api = api_obj(&v);
    if !api.get("enabled").and_then(|e| e.as_bool()).unwrap_or(false) {
        println!("\n  Turn on: ostp panel enable");
        return Ok(());
    }
    let bind = Some(str_of(&api, "bind")).filter(|b| !b.is_empty()).unwrap_or_else(|| DEFAULT_BIND.into());
    let (webpath, _) = panel_route(&v).unwrap_or(("panel".into(), String::new()));
    let port = bind.rsplit_once(':').map(|(_, p)| p.to_string()).unwrap_or_else(|| "9090".into());
    println!("\n  Open it:");
    println!("    on the server:   http://127.0.0.1:{port}/{webpath}/");
    println!("    over SSH:        ssh -L {port}:127.0.0.1:{port} <user>@<server>, then http://127.0.0.1:{port}/{webpath}/");
    if let Ok(t) = tls_settings(config_path) {
        if let Some(domain) = &t.domain {
            let reachable = match t.frontend {
                Frontend::Builtin => true,
                _ => vhost_forwards(config_path, &format!("/{webpath}")),
            };
            if reachable {
                let port = if t.public_port == 443 { String::new() } else { format!(":{}", t.public_port) };
                println!("    over HTTPS:      https://{domain}{port}/{webpath}/");
            } else {
                println!("    over HTTPS:      not forwarded by {} (ostp panel set --vhost)", t.frontend.as_str());
            }
        }
    }
    Ok(())
}

fn hash(password: &str) -> String {
    // Must match api.rs's handle_login byte for byte.
    format!("{:x}", <sha2::Sha256 as sha2::Digest>::digest(password.as_bytes()))
}

fn prompt_line(prompt: &str) -> Result<String> {
    print!("  {prompt}");
    std::io::stdout().flush().ok();
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    Ok(buf.trim_end_matches(['\r', '\n']).trim().to_string())
}

/// A line from the terminal with echo off (stty), or from stdin when piped.
fn read_secret(prompt: &str) -> Result<String> {
    let tty = std::io::stdin().is_terminal();
    print!("  {prompt}");
    std::io::stdout().flush().ok();
    let saved = if tty && cfg!(unix) {
        let out = std::process::Command::new("stty").arg("-g").stdin(std::process::Stdio::inherit()).output().ok();
        let saved = out.filter(|o| o.status.success()).map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
        if saved.is_some() {
            let _ = std::process::Command::new("stty").arg("-echo").stdin(std::process::Stdio::inherit()).status();
        }
        saved
    } else {
        None
    };
    let mut buf = String::new();
    let read = std::io::stdin().read_line(&mut buf);
    if let Some(s) = saved {
        let _ = std::process::Command::new("stty").arg(&s).stdin(std::process::Stdio::inherit()).status();
        println!();
    }
    read?;
    Ok(buf.trim_end_matches(['\r', '\n']).to_string())
}

fn read_new_password() -> Result<String> {
    let first = read_secret("New password: ")?;
    if first.chars().count() < 8 {
        bail!("the password must be at least 8 characters");
    }
    if std::io::stdin().is_terminal() {
        let again = read_secret("Repeat it: ")?;
        if again != first {
            bail!("the passwords do not match; nothing was changed");
        }
    }
    Ok(first)
}
