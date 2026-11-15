//! `ostp v6`: the server key of protocol v6 and the transitional mode.
//!
//! Nothing here runs by itself. An existing server gets a key only through
//! `ostp v6 key new`; a fresh install creates one in `new_section`. The
//! private key is never printed: `ostp v6 key` shows the public half, which is
//! what links carry as `pk`.

use anyhow::{bail, Context, Result};
use colored::Colorize;
use ostp_client::config::ProtocolCfg;
use ostp_core::crypto::noise::{generate_server_key, server_public_key};
use ostp_core::server_key::{decode_key, encode_key};
use std::path::Path;

use crate::cert_cmd::{read_json, save_json};
use crate::service_cmd::restart_service;

#[derive(clap::Subcommand, Debug)]
pub enum V6Action {
    /// The server key: show the public key (the `pk` of links), or make a new one
    Key {
        #[command(subcommand)]
        action: Option<KeyAction>,
    },
    /// Keep accepting v5 clients (0.4.x apps, links without pk) next to v6: on or off
    V5 {
        #[arg(value_parser = ["on", "off"])]
        state: String,
        #[arg(long)]
        no_restart: bool,
    },
}

#[derive(clap::Subcommand, Debug)]
pub enum KeyAction {
    /// Create the server key, or replace it. Every v6 link and subscription made
    /// with the old key stops working and has to be reissued
    New {
        /// Confirm replacing an existing key
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        no_restart: bool,
    },
}

/// A new `protocol` section with a fresh key and v5 still accepted: what a
/// fresh install writes.
pub fn new_section() -> serde_json::Value {
    let (private, _) = generate_server_key();
    serde_json::json!({ "server_key": encode_key(&private), "accept_v5": true })
}

/// The public key of a server's config value, for the links printed at install.
pub fn public_key_of(section: &serde_json::Value) -> Option<[u8; 32]> {
    let private = decode_key(section.get("server_key")?.as_str()?).ok()?;
    Some(server_public_key(&private))
}

fn load(config_path: &Path) -> Result<(serde_json::Value, ProtocolCfg)> {
    let v = read_json(config_path)?;
    let p: ProtocolCfg = match v.get("protocol") {
        Some(p) if !p.is_null() => serde_json::from_value(p.clone()).context("the protocol section does not parse")?,
        _ => ProtocolCfg::default(),
    };
    p.private_key()?;
    Ok((v, p))
}

fn save(config_path: &Path, mut v: serde_json::Value, p: &ProtocolCfg, no_restart: bool) -> Result<()> {
    p.private_key()?;
    v["protocol"] = serde_json::to_value(p)?;
    save_json(config_path, &v)?;
    println!("  {} Saved {} (previous: config.json.bak)", "✓".green(), config_path.display());
    restart_service(no_restart);
    Ok(())
}

pub fn run(action: V6Action, config_path: &Path) -> Result<()> {
    let (v, mut p) = load(config_path)?;
    match action {
        V6Action::Key { action: None } => {
            match p.private_key()? {
                Some(private) => {
                    println!("  Protocol v6 is on. Server public key (the pk of every link):");
                    println!("  {}", encode_key(&server_public_key(&private)));
                    println!(
                        "  v5 clients are {}. `ostp links` prints links that carry the key.",
                        if p.accept_v5 { "still accepted (transitional mode, `ostp v6 v5 off` ends it)" } else { "refused" }
                    );
                }
                None => {
                    println!("  No server key: this server speaks protocol v5 only, as 0.4.x does.");
                    println!("  `ostp v6 key new` creates the key that turns protocol v6 on.");
                }
            }
            Ok(())
        }
        V6Action::Key { action: Some(KeyAction::New { yes, no_restart }) } => {
            let replacing = p.server_key.is_some();
            if replacing && !yes {
                bail!(
                    "this server already has a key. A new one makes every v6 link and subscription issued so far stop working: \
                     each user needs a new link. Run `ostp v6 key new --yes` if that is what you want"
                );
            }
            let (private, public) = generate_server_key();
            p.server_key = Some(encode_key(&private));
            save(config_path, v, &p, no_restart)?;
            println!("  {} Server key {}. Public key: {}", "✓".green(), if replacing { "replaced" } else { "created" }, encode_key(&public));
            if replacing {
                println!("  Every v6 link made with the old key must be reissued (`ostp links`, or the panel).");
            } else {
                println!("  Links printed from now on carry it (pk=...) and are v6 profiles; links without it still work while v5 is accepted.");
            }
            Ok(())
        }
        V6Action::V5 { state, no_restart } => {
            let on = state == "on";
            if !on && p.server_key.is_none() {
                bail!("there is no server key, so v5 is the only version this server can speak; `ostp v6 key new` first");
            }
            p.accept_v5 = on;
            save(config_path, v, &p, no_restart)?;
            if on {
                println!("  v5 clients are accepted next to v6.");
            } else {
                println!("  v5 clients are refused now: 0.4.x apps and links without pk stop connecting until they get a v6 link.");
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_section_has_a_usable_key_and_keeps_v5() {
        let s = new_section();
        assert_eq!(s["accept_v5"], true);
        let p: ProtocolCfg = serde_json::from_value(s.clone()).unwrap();
        let private = p.private_key().unwrap().expect("a key");
        assert_eq!(public_key_of(&s), Some(server_public_key(&private)));
        assert_ne!(new_section()["server_key"], s["server_key"], "every install gets its own key");
    }

    /// The private key does not appear when a config is debug-printed.
    #[test]
    fn the_private_key_stays_out_of_debug_output() {
        let s = new_section();
        let p: ProtocolCfg = serde_json::from_value(s.clone()).unwrap();
        let text = format!("{p:?}");
        assert!(!text.contains(s["server_key"].as_str().unwrap()), "{text}");
    }

    #[test]
    fn a_damaged_key_is_refused_without_echoing_it() {
        let p: ProtocolCfg = serde_json::from_value(serde_json::json!({ "server_key": "not-a-key!!", "accept_v5": true })).unwrap();
        let e = p.private_key().unwrap_err().to_string();
        assert!(!e.contains("not-a-key"), "{e}");
    }
}
