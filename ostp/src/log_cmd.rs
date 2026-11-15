//! `ostp log privacy`: what the server's log may say about clients and
//! destinations (`log.privacy` in the config; see `ostp_core::logpriv`).
//!
//! Setting it edits the config, keeps a backup, and restarts a running service
//! (`--no-restart` to skip), like the other server settings. `ostp log` alone
//! still shows the log.

use anyhow::Result;
use colored::Colorize;
use ostp_core::logpriv::Privacy;
use std::path::Path;

use crate::cert_cmd::{read_json, save_json};
use crate::service_cmd::restart_service;

#[derive(clap::Subcommand, Debug)]
pub enum LogAction {
    /// Show, or set, what the log says about clients and destinations
    Privacy {
        /// strict, normal or debug; without it the current mode is shown
        #[arg(value_parser = ["strict", "normal", "debug"])]
        mode: Option<String>,
        /// Save the change but do not restart a running service
        #[arg(long)]
        no_restart: bool,
    },
}

/// What a mode writes, one line each, for the status view.
fn describe(mode: Privacy) -> [&'static str; 3] {
    match mode {
        Privacy::Strict => [
            "no destinations (sites, SNI and DNS names, relay targets) in any log",
            "client addresses as a tag that changes every UTC day (nothing links two days)",
            "the DNS query log is not kept",
        ],
        Privacy::Normal => [
            "no destinations (sites, SNI and DNS names, relay targets) in any log",
            "client addresses cut to the /24 network (IPv6: /48)",
            "the DNS query log is kept, with the same truncated addresses",
        ],
        Privacy::Debug => [
            "destinations, full client addresses and per-stream detail",
            "meant for finding a fault, on request only; it does not turn itself off",
            "clients are not told",
        ],
    }
}

/// The mode a server config asks for, and whether it comes from the old `debug` flag.
fn current(v: &serde_json::Value) -> Result<(Privacy, bool)> {
    let explicit = match v.pointer("/log/privacy").and_then(|p| p.as_str()) {
        Some(s) => Some(Privacy::parse(s).ok_or_else(|| anyhow::anyhow!("log.privacy in the config is \"{s}\"; it must be strict, normal or debug"))?),
        None => None,
    };
    let legacy_debug = v.get("debug").and_then(|d| d.as_bool()).unwrap_or(false);
    Ok((Privacy::resolve(explicit, legacy_debug), explicit.is_none() && legacy_debug))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_mode_of_a_config() {
        assert_eq!(current(&json!({})).unwrap(), (Privacy::Normal, false));
        assert_eq!(current(&json!({ "debug": true })).unwrap(), (Privacy::Debug, true));
        // An explicit setting beats the old flag.
        assert_eq!(current(&json!({ "debug": true, "log": { "privacy": "strict" } })).unwrap(), (Privacy::Strict, false));
        assert!(current(&json!({ "log": { "privacy": "loud" } })).is_err());
    }
}

pub fn run(action: LogAction, config_path: &Path) -> Result<()> {
    let LogAction::Privacy { mode, no_restart } = action;
    let mut v = read_json(config_path)?;
    let (now, from_debug_flag) = current(&v)?;
    let Some(mode) = mode else {
        println!("  Log privacy: {}{}", now.as_str().bold(), if from_debug_flag { " (from \"debug\": true)" } else { "" });
        for line in describe(now) {
            println!("    {line}");
        }
        println!("\n  Change it: ostp log privacy strict|normal|debug");
        return Ok(());
    };
    let new = Privacy::parse(&mode).expect("the value parser admits three words");
    if new == now && !from_debug_flag {
        println!("  Log privacy is already {}.", new.as_str());
        return Ok(());
    }
    if !v.get("log").is_some_and(|l| l.is_object()) {
        v["log"] = serde_json::json!({});
    }
    v["log"]["privacy"] = serde_json::json!(new.as_str());
    save_json(config_path, &v)?;
    println!("  Log privacy: {} -> {}", now.as_str(), new.as_str().bold());
    for line in describe(new) {
        println!("    {line}");
    }
    if new != Privacy::Debug && v.get("debug").and_then(|d| d.as_bool()) == Some(true) {
        println!("\n  \"debug\": true is still in the config; log.privacy takes precedence over it.");
    }
    if new == Privacy::Debug {
        println!("\n  Debug writes destinations and full client addresses to the log. Set it back with: ostp log privacy normal");
    }
    restart_service(no_restart);
    Ok(())
}
