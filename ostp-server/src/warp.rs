//! Cloudflare WARP as the server's exit (`ostp-warp`): a task of this
//! process that runs the WireGuard client and the local SOCKS5 proxy the
//! `outbound` section points at.
//!
//! The crate is not built for MIPS (not verified to build there, and a poor
//! fit for a router); on those targets the section parses and a server that
//! has it enabled says so at start.

#[cfg(not(any(target_arch = "mips", target_arch = "mips64")))]
pub use ostp_warp::WarpConfig;

#[cfg(any(target_arch = "mips", target_arch = "mips64"))]
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct WarpConfig {
    pub enabled: bool,
    #[serde(flatten)]
    pub rest: serde_json::Map<String, serde_json::Value>,
}

/// Whether this binary has WARP in it.
pub const BUILT_IN: bool = cfg!(not(any(target_arch = "mips", target_arch = "mips64")));

/// What `run_server` keeps alive for as long as the server runs.
#[cfg(not(any(target_arch = "mips", target_arch = "mips64")))]
pub type Handle = ostp_warp::Running;
#[cfg(any(target_arch = "mips", target_arch = "mips64"))]
pub type Handle = ();

/// Starts WARP when its section is enabled. A failure is logged and leaves
/// WARP off; with the `outbound` section pointing at the proxy that then does
/// not exist, connections fail: nothing goes out directly.
#[cfg(not(any(target_arch = "mips", target_arch = "mips64")))]
pub async fn start(cfg: Option<WarpConfig>, config_path: Option<&std::path::Path>) -> Option<Handle> {
    let cfg = cfg.filter(|c| c.enabled)?;
    let Some(path) = config_path else {
        tracing::error!("warp: enabled, but the server has no config file to find warp.json next to");
        return None;
    };
    match ostp_warp::start(&cfg, path).await {
        Ok(h) => Some(h),
        Err(e) => {
            tracing::error!(
                "warp: not started: {e:#}. Whatever the outbound rules send to WARP's proxy ({}) fails until it runs; nothing is sent directly instead.",
                cfg.listen
            );
            None
        }
    }
}

#[cfg(any(target_arch = "mips", target_arch = "mips64"))]
pub async fn start(cfg: Option<WarpConfig>, _config_path: Option<&std::path::Path>) -> Option<Handle> {
    if cfg.is_some_and(|c| c.enabled) {
        tracing::error!("warp: enabled in the config, but this build of ostp has no WARP (not built for MIPS)");
    }
    None
}

#[cfg(all(test, not(any(target_arch = "mips", target_arch = "mips64"))))]
mod tests;
