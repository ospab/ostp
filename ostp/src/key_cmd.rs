//! `ostp key`: access keys, the server's own key and the old-clients mode.
//!
//! Nothing here runs by itself. An existing server gets a server key only
//! through `ostp key server new`; a fresh install creates one in
//! `new_section`. The private key is never printed: `ostp key` and
//! `ostp key server` show the public half, which is what links carry as `pk`.

use anyhow::{bail, Context, Result};
use colored::Colorize;
use ostp_client::config::ProtocolCfg;
use ostp_core::crypto::noise::{generate_server_key, server_public_key};
use ostp_core::server_key::{decode_key, encode_key};
use std::path::Path;

use crate::cert_cmd::{read_json, save_json};
use crate::service_cmd::restart_service;

#[derive(clap::Subcommand, Debug)]
pub enum KeyAction {
    /// Print new access keys; on a server config they are also added to access_keys
    Gen {
        /// Format of the keys
        #[arg(long, default_value = "hex", value_parser = ["hex", "base64"])]
        format: String,
        /// Number of keys to generate
        // No short `-c`: the global `--config` already owns it and clap panics on a duplicate.
        #[arg(short = 'n', long, default_value_t = 1)]
        count: usize,
    },
    /// The server's key: print the public key alone, or make a new one
    Server {
        #[command(subcommand)]
        action: Option<ServerKeyAction>,
    },
    /// Legacy clients (older than 0.5.0): keep accepting them next to current ones, on or off
    Legacy {
        #[arg(value_parser = ["on", "off"])]
        state: String,
        /// Do not restart the running ostp service
        #[arg(long)]
        no_restart: bool,
    },
}

#[derive(clap::Subcommand, Debug)]
pub enum ServerKeyAction {
    /// Create the server key, or replace it. Every link and subscription made
    /// with the old key stops working and has to be reissued
    New {
        /// Confirm replacing an existing key
        #[arg(long)]
        yes: bool,
        /// Do not restart the running ostp service
        #[arg(long)]
        no_restart: bool,
    },
}

/// A new `protocol` section with a fresh key and old clients still accepted:
/// what a fresh install writes.
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

/// The lines of `ostp key`. They never contain the private key.
fn status_lines(p: &ProtocolCfg, access_keys: usize) -> Result<Vec<String>> {
    let mut lines = Vec::new();
    match p.private_key()? {
        Some(private) => {
            lines.push("  Server public key (the pk of every link):".to_string());
            lines.push(format!("  {}", encode_key(&server_public_key(&private))));
            lines.push(if p.accept_v5 {
                "  Legacy clients (older than 0.5.0): accepted (`ostp key legacy off` ends it)".to_string()
            } else {
                "  Legacy clients (older than 0.5.0): refused".to_string()
            });
        }
        None => {
            lines.push("  Server public key: none. This server accepts only the handshake of 0.4.x; links carry no pk.".to_string());
            lines.push("  `ostp key server new` creates the key that turns the 0.5.0 handshake on.".to_string());
            lines.push("  Legacy clients (older than 0.5.0): accepted (the only kind this server can serve)".to_string());
        }
    }
    lines.push(format!("  Access keys in the config: {access_keys}"));
    Ok(lines)
}

/// Adds keys to `access_keys` of a server config. Returns whether the config
/// was changed; a missing, unreadable or non-server config is left alone, as
/// `ostp gk` always did.
fn add_to_config(config_path: &Path, new_keys: Vec<String>) -> bool {
    if !config_path.exists() {
        return false;
    }
    let Ok(content) = std::fs::read_to_string(config_path) else { return false };
    let mut stripped = json_comments::StripComments::new(content.as_bytes());
    let mut content_str = String::new();
    use std::io::Read;
    if stripped.read_to_string(&mut content_str).is_err() {
        return false;
    }
    let Ok(mut json_val) = serde_json::from_str::<serde_json::Value>(&content_str) else { return false };
    if json_val.get("mode").and_then(|m| m.as_str()) != Some("server") {
        return false;
    }
    let Some(access_keys) = json_val.get_mut("access_keys").and_then(|a| a.as_array_mut()) else { return false };
    for key in new_keys {
        access_keys.push(serde_json::Value::String(key));
    }
    let Ok(new_content) = serde_json::to_string_pretty(&json_val) else { return false };
    ostp_server::config_io::save_config(config_path, &new_content, false).is_ok()
}

/// `ostp key gen` (and the hidden `ostp gk`, `ostp generate-key`).
pub fn gen(config_path: &Path, format: &str, count: usize) -> Result<()> {
    let mut new_keys = Vec::new();
    for _ in 0..count {
        let key = match format.to_lowercase().as_str() {
            "base64" => ostp_core::keys::access_key_base64(),
            _ => ostp_core::keys::access_key_hex(),
        };
        println!("{}", key);
        new_keys.push(key);
    }
    // On a server config the new keys are appended to access_keys.
    if add_to_config(config_path, new_keys) {
        println!("[ostp] Added to access_keys in {:?}", config_path);
    }
    Ok(())
}

pub fn run(action: Option<KeyAction>, config_path: &Path) -> Result<()> {
    let action = match action {
        Some(KeyAction::Gen { format, count }) => return gen(config_path, &format, count),
        Some(a) => a,
        None => {
            let (v, p) = load(config_path)?;
            let count = v.get("access_keys").and_then(|a| a.as_array()).map_or(0, |a| a.len());
            for line in status_lines(&p, count)? {
                println!("{line}");
            }
            return Ok(());
        }
    };
    let (v, mut p) = load(config_path)?;
    match action {
        KeyAction::Gen { .. } => unreachable!("handled above"),
        KeyAction::Server { action: None } => match p.private_key()? {
            Some(private) => {
                println!("{}", encode_key(&server_public_key(&private)));
                Ok(())
            }
            None => bail!("this server has no key; `ostp key server new` creates one"),
        },
        KeyAction::Server { action: Some(ServerKeyAction::New { yes, no_restart }) } => {
            let replacing = p.server_key.is_some();
            if replacing && !yes {
                bail!(
                    "this server already has a key. A new one makes every link and subscription issued so far stop working: \
                     each user needs a new link. Run `ostp key server new --yes` if that is what you want"
                );
            }
            let (private, public) = generate_server_key();
            p.server_key = Some(encode_key(&private));
            save(config_path, v, &p, no_restart)?;
            println!("  {} Server key {}. Public key: {}", "✓".green(), if replacing { "replaced" } else { "created" }, encode_key(&public));
            if replacing {
                println!("  Every link made with the old key must be reissued (`ostp links`, or the panel).");
            } else {
                println!("  Links printed from now on carry it (pk=...); links without it still work while legacy clients are accepted.");
            }
            Ok(())
        }
        KeyAction::Legacy { state, no_restart } => {
            let on = state == "on";
            if !on && p.server_key.is_none() {
                bail!("there is no server key, so the handshake of 0.4.x is the only one this server can speak; `ostp key server new` first");
            }
            p.accept_v5 = on;
            save(config_path, v, &p, no_restart)?;
            if on {
                println!("  Legacy clients (older than 0.5.0) are accepted next to current ones.");
            } else {
                println!("  Legacy clients (older than 0.5.0) are refused now: 0.4.x apps and links without pk stop connecting until they get a new link.");
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_section_has_a_usable_key_and_keeps_old_clients() {
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

    /// The status shows the public key, the mode and the key count, and never
    /// the private key.
    #[test]
    fn the_status_shows_the_public_key_and_never_the_private_one() {
        let s = new_section();
        let private = s["server_key"].as_str().unwrap().to_string();
        let p: ProtocolCfg = serde_json::from_value(s.clone()).unwrap();
        let public = encode_key(&public_key_of(&s).unwrap());
        let text = status_lines(&p, 3).unwrap().join("\n");
        assert!(text.contains(&public), "{text}");
        assert!(!text.contains(&private), "{text}");
        assert!(text.contains("Legacy clients (older than 0.5.0): accepted"), "{text}");
        assert!(text.contains("Access keys in the config: 3"), "{text}");

        let off: ProtocolCfg = serde_json::from_value(serde_json::json!({ "server_key": private, "accept_v5": false })).unwrap();
        assert!(status_lines(&off, 0).unwrap().join("\n").contains("Legacy clients (older than 0.5.0): refused"));

        let none = status_lines(&ProtocolCfg::default(), 1).unwrap().join("\n");
        assert!(none.contains("none") && none.contains("ostp key server new"), "{none}");
    }

    fn temp_config(name: &str, body: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("ostp-key-cmd-{}-{name}.json", std::process::id()));
        std::fs::write(&path, body).unwrap();
        path
    }

    /// `gen` keeps what `gk` did: a server config gets the keys in access_keys,
    /// any other config is left untouched.
    #[test]
    fn new_keys_are_added_to_a_server_config_only() {
        let server = temp_config("server", r#"{"mode":"server","access_keys":["old"]}"#);
        assert!(add_to_config(&server, vec!["new1".into(), "new2".into()]));
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&server).unwrap()).unwrap();
        assert_eq!(v["access_keys"], serde_json::json!(["old", "new1", "new2"]));

        let client = temp_config("client", r#"{"mode":"client"}"#);
        assert!(!add_to_config(&client, vec!["x".into()]));
        assert_eq!(std::fs::read_to_string(&client).unwrap(), r#"{"mode":"client"}"#);

        assert!(!add_to_config(&std::env::temp_dir().join("ostp-key-cmd-missing.json"), vec!["x".into()]));
        let _ = std::fs::remove_file(server);
        let _ = std::fs::remove_file(client);
    }
}
