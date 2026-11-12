//! `ostp warp`: Cloudflare WARP as this server's exit (crate ostp-warp).
//!
//! Nothing here happens by itself: `register` creates a device at Cloudflare
//! only with `--accept-terms`, `enable` changes the `warp` and `outbound`
//! sections of the config, and every change is validated, backed up
//! (`config.json.bak`) and applied by restarting a running service
//! (`--no-restart` to skip). The device's keys live in `warp.json` next to the
//! config, never in `config.json`.

#[derive(clap::Subcommand, Debug)]
pub enum WarpAction {
    /// Create a free WARP device at Cloudflare and store its keys in warp.json
    Register {
        /// You accept Cloudflare's WARP terms of service; nothing registers without it
        #[arg(long)]
        accept_terms: bool,
    },
    /// Attach a WARP+ key to the registered device
    License {
        key: String,
        #[arg(long)]
        no_restart: bool,
    },
    /// Send the server's outgoing connections through WARP: --all or --rules
    Enable {
        /// Everything the server opens outwards, with no direct fallback
        #[arg(long, conflicts_with = "rules", required_unless_present = "rules")]
        all: bool,
        /// Only what the `outbound` rules send to the proxy; the rest as written
        #[arg(long)]
        rules: bool,
        #[arg(long)]
        no_restart: bool,
    },
    /// Stop using WARP and put the previous `outbound` section back
    Disable {
        #[arg(long)]
        no_restart: bool,
    },
    /// Registration, mode, tunnel state and the address a site sees
    Status,
    /// A TCP request and a UDP DNS query through the running tunnel; exits non-zero on failure
    Test,
    /// Forget the registered device (asks first)
    Reset {
        /// Do not ask
        #[arg(long)]
        yes: bool,
    },
}

#[cfg(not(any(target_arch = "mips", target_arch = "mips64")))]
mod imp;

#[cfg(not(any(target_arch = "mips", target_arch = "mips64")))]
pub use imp::{print_check_line, run};

#[cfg(any(target_arch = "mips", target_arch = "mips64"))]
pub async fn run(_action: WarpAction, _config_path: &std::path::Path) -> anyhow::Result<()> {
    anyhow::bail!("this build of ostp has no WARP (it is not built for MIPS)")
}

#[cfg(any(target_arch = "mips", target_arch = "mips64"))]
pub fn print_check_line(warp: Option<serde_json::Value>) -> anyhow::Result<()> {
    if warp.and_then(|w| w.get("enabled").and_then(|e| e.as_bool())).unwrap_or(false) {
        println!("  warp: enabled in the config, but this build has no WARP (not built for MIPS)");
    }
    Ok(())
}
