//! `ostp overnet`: the `overnet` section of the server config.
//!
//! overnet is a separate program (github.com/ospab/overnet); this server only
//! talks to it through local SOCKS5 ports. Nothing here is on by default and
//! nothing is installed unless asked: `ostp overnet install` runs overnet's
//! own installer, `enable` and `exit on` change the config. Every change is
//! validated, backed up, and applied by restarting a running service
//! (`--no-restart` to skip; the panel applies the same settings live).

use anyhow::{Context, Result};
use colored::Colorize;
use std::path::Path;

use crate::cert_cmd::{read_json, restart_service};
use ostp_server::OvernetConfig;

#[cfg(unix)]
const INSTALLER: &str = "https://raw.githubusercontent.com/ospab/overnet/master/scripts/install.sh";

#[derive(clap::Subcommand, Debug)]
pub enum OvernetAction {
    /// Show the overnet section, whether the gateway answers and the exit
    Status,
    /// Install overnet and run its SOCKS5 gateway (systemd unit overnet-gateway)
    Install,
    /// Serve .ov to this server's clients through the overnet gateway
    Enable {
        /// SOCKS5 address of the overnet gateway (default 127.0.0.1:9150)
        #[arg(long)]
        gateway: Option<String>,
        #[arg(long)]
        no_restart: bool,
    },
    /// Stop serving .ov (the exit, if open, stays: `exit off`)
    Disable {
        #[arg(long)]
        no_restart: bool,
    },
    /// Let the local overnet node send its users' clearnet traffic out through this server: on or off
    Exit {
        #[arg(value_parser = ["on", "off"])]
        state: String,
        /// Loopback address of the exit SOCKS5 listener (default 127.0.0.1:9151)
        #[arg(long)]
        listen: Option<String>,
        #[arg(long)]
        no_restart: bool,
    },
}

fn load(config_path: &Path) -> Result<(serde_json::Value, OvernetConfig)> {
    let v = read_json(config_path)?;
    let cfg = match v.get("overnet") {
        Some(o) if !o.is_null() => serde_json::from_value(o.clone()).context("the overnet section does not parse")?,
        _ => OvernetConfig::default(),
    };
    Ok((v, cfg))
}

fn save(config_path: &Path, mut v: serde_json::Value, cfg: &OvernetConfig, no_restart: bool) -> Result<()> {
    cfg.validate()?;
    v["overnet"] = serde_json::to_value(cfg)?;
    let backup = config_path.with_extension("json.bak");
    std::fs::copy(config_path, &backup).with_context(|| format!("cannot back up {}", config_path.display()))?;
    std::fs::write(config_path, serde_json::to_string_pretty(&v)?).with_context(|| format!("cannot write {}", config_path.display()))?;
    println!("  {} Saved {} (previous: {})", "✓".green(), config_path.display(), backup.display());
    restart_service(no_restart);
    Ok(())
}

fn gateway_answers(addr: &str) -> bool {
    use std::net::{SocketAddr, TcpStream};
    addr.parse::<SocketAddr>()
        .is_ok_and(|a| TcpStream::connect_timeout(&a, std::time::Duration::from_secs(2)).is_ok())
}

fn overnet_installed() -> Option<String> {
    let out = std::process::Command::new("overnet").arg("--version").output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    Some(if text.is_empty() { "installed".into() } else { text })
}

fn unit_state(unit: &str) -> Option<String> {
    let out = std::process::Command::new("systemctl").args(["is-active", unit]).output().ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!s.is_empty()).then_some(s)
}

fn status(config_path: &Path) -> Result<()> {
    let (_, cfg) = load(config_path)?;
    let onoff = |b: bool| if b { "on".green() } else { "off".yellow() };
    println!("  overnet section: {}", onoff(cfg.enabled));
    println!("  .ov for clients: {}  (gateway {})", onoff(cfg.enabled && cfg.entry), cfg.gateway);
    println!("  exit:            {}  (listens on {})", onoff(cfg.enabled && cfg.exit), cfg.exit_listen);
    match overnet_installed() {
        Some(v) => println!("  overnet program: {v}"),
        None => println!("  overnet program: {} (ostp overnet install)", "not installed".yellow()),
    }
    if let Some(s) = unit_state("overnet-gateway") {
        println!("  overnet-gateway service: {s}");
    }
    let up = gateway_answers(&cfg.gateway);
    println!("  gateway {}: {}", cfg.gateway, if up { "answers".green() } else { "does not answer".red() });
    if cfg.enabled && cfg.entry && !up {
        println!("  {}", "Clients get NXDOMAIN for .ov until the gateway runs.".yellow());
    }
    if !cfg.enabled {
        println!("\n  Turn on with: {}", "ostp overnet enable".bold());
    }
    Ok(())
}

#[cfg(unix)]
fn install() -> Result<()> {
    println!("  Running overnet's installer with the gateway role:\n  {INSTALLER}\n");
    let st = std::process::Command::new("bash")
        .args(["-c", &format!("curl -fsSL {INSTALLER} | bash -s -- --role gateway -y")])
        .status()
        .context("cannot run bash")?;
    if !st.success() {
        anyhow::bail!("the overnet installer failed (run it as root: sudo ostp overnet install)");
    }
    println!("\n  {} overnet gateway installed. This server does not use it yet: {}", "✓".green(), "ostp overnet enable".bold());
    Ok(())
}

#[cfg(not(unix))]
fn install() -> Result<()> {
    anyhow::bail!("ostp overnet install is for Linux servers; on this machine install overnet from https://github.com/ospab/overnet and run `overnet gateway`")
}

pub fn run(action: OvernetAction, config_path: &Path) -> Result<()> {
    match action {
        OvernetAction::Status => status(config_path),
        OvernetAction::Install => install(),
        OvernetAction::Enable { gateway, no_restart } => {
            let (v, mut cfg) = load(config_path)?;
            if !cfg.enabled {
                cfg.exit = false;
            }
            cfg.enabled = true;
            cfg.entry = true;
            if let Some(g) = gateway {
                cfg.gateway = g;
            }
            if !gateway_answers(&cfg.gateway) {
                println!(
                    "  {} nothing answers at {} yet: clients get NXDOMAIN for .ov until the gateway runs ({}).",
                    "!".yellow(),
                    cfg.gateway,
                    "ostp overnet install".bold()
                );
            }
            save(config_path, v, &cfg, no_restart)?;
            println!("  Clients of this server open .ov sites in any browser once they reconnect (TUN mode or the system proxy).");
            Ok(())
        }
        OvernetAction::Disable { no_restart } => {
            let (v, mut cfg) = load(config_path)?;
            cfg.entry = false;
            cfg.enabled = cfg.exit;
            save(config_path, v, &cfg, no_restart)
        }
        OvernetAction::Exit { state, listen, no_restart } => {
            let (v, mut cfg) = load(config_path)?;
            // Each switch on its own: `enable` never reopens an exit that was
            // closed, `exit on` never starts serving .ov.
            if !cfg.enabled {
                cfg.entry = false;
                cfg.exit = false;
            }
            cfg.exit = state == "on";
            if let Some(l) = listen {
                cfg.exit_listen = l;
            }
            cfg.enabled = cfg.entry || cfg.exit;
            if cfg.exit {
                println!("  An exit answers for what leaves it: overnet users' clearnet traffic goes out from this server's IP.");
            }
            let listen = cfg.exit_listen.clone();
            let exit = cfg.exit;
            save(config_path, v, &cfg, no_restart)?;
            if exit {
                println!("  Point the local overnet relay at it: {}", format!("overnet relay --exit socks5://{listen}").bold());
            }
            Ok(())
        }
    }
}
