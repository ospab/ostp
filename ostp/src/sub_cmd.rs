//! `ostp sub`: the subscription server, managed on its own.
//!
//! Nothing here happens implicitly: each subcommand changes exactly what it
//! says, keeps a backup of the config, restarts a running service to apply it
//! (`--no-restart` to skip) and only rewrites the web-server site when asked
//! to (`--vhost`).

use anyhow::{anyhow, bail, Context, Result};
use colored::Colorize;
use std::path::Path;

use crate::cert_cmd::{listen_port, panel_route, read_json, subscription_prefix, tls_settings};
use crate::webserver::{self, Kind, VhostParams};
use ostp_client::config::{SubscriptionCfg, UnifiedConfig};
use ostp_server::tls::Frontend;

#[derive(clap::Subcommand, Debug)]
pub enum SubAction {
    /// Show whether subscriptions are served, with what settings, and what is missing
    Status,
    /// Start serving subscriptions (needs HTTPS on a domain: `ostp cert issue`)
    Enable(SubOpts),
    /// Stop serving subscriptions (settings are kept)
    Disable {
        /// Do not restart the running ostp service
        #[arg(long)]
        no_restart: bool,
    },
    /// Change subscription settings without turning them on or off
    Set(SubOpts),
    /// Print subscription URLs: every user, or one by number, name or key
    Urls {
        /// User number (as in `ostp links`), name or access key
        user: Option<String>,
    },
}

#[derive(clap::Args, Debug, Default, Clone)]
pub struct SubOpts {
    /// URL prefix, e.g. /sub
    #[arg(long)]
    pub path: Option<String>,
    /// Title shown in apps (default: the domain)
    #[arg(long)]
    pub name: Option<String>,
    /// How often apps refresh, in hours
    #[arg(long, value_name = "HOURS")]
    pub interval: Option<u32>,
    /// Links to hand out, best first, comma-separated: tls,udp
    #[arg(long, value_delimiter = ',')]
    pub include: Option<Vec<String>>,
    /// Also rewrite the OSTP-managed web-server site so it forwards the subscription path
    #[arg(long)]
    pub vhost: bool,
    /// Do not restart the running ostp service
    #[arg(long)]
    pub no_restart: bool,
}

pub fn run(action: SubAction, config_path: &Path) -> Result<()> {
    match action {
        SubAction::Status => status(config_path),
        SubAction::Enable(o) => change(config_path, Some(true), o),
        SubAction::Disable { no_restart } => change(config_path, Some(false), SubOpts { no_restart, ..Default::default() }),
        SubAction::Set(o) => {
            if o.path.is_none() && o.name.is_none() && o.interval.is_none() && o.include.is_none() && !o.vhost {
                bail!("nothing to change: pass --path, --name, --interval, --include or --vhost");
            }
            change(config_path, None, o)
        }
        SubAction::Urls { user } => urls(config_path, user.as_deref()),
    }
}

fn current(v: &serde_json::Value) -> SubscriptionCfg {
    v.get("subscription").cloned().and_then(|s| serde_json::from_value(s).ok()).unwrap_or_default()
}

fn change(config_path: &Path, enabled: Option<bool>, o: SubOpts) -> Result<()> {
    let mut v = read_json(config_path)?;
    let before = current(&v);

    let mut sub = v.get("subscription").cloned().filter(|s| s.is_object()).unwrap_or_else(|| serde_json::json!({}));
    if let Some(e) = enabled {
        sub["enabled"] = e.into();
    }
    if let Some(p) = &o.path {
        let p = format!("/{}", p.trim().trim_matches('/'));
        sub["path"] = p.into();
    }
    if let Some(n) = &o.name {
        sub["name"] = n.trim().into();
    }
    if let Some(h) = o.interval {
        sub["update_interval_hours"] = h.into();
    }
    if let Some(inc) = &o.include {
        let inc: Vec<String> = inc.iter().map(|s| s.trim().to_ascii_lowercase()).filter(|s| !s.is_empty()).collect();
        sub["include"] = inc.into();
    }
    v["subscription"] = sub;

    // Validate the whole config before anything is written.
    let parsed: UnifiedConfig = serde_json::from_value(v.clone()).context("the resulting config does not parse")?;
    parsed.validate()?;

    let after = current(&v);
    let backup = config_path.with_extension("json.bak");
    std::fs::copy(config_path, &backup).with_context(|| format!("cannot back up {}", config_path.display()))?;
    std::fs::write(config_path, serde_json::to_string_pretty(&v)?)
        .with_context(|| format!("cannot write {}", config_path.display()))?;
    println!("  {} Saved {} (previous: {})", "✓".green(), config_path.display(), backup.display());
    print_settings(&after);

    // A web server in front must forward the prefix to OSTP.
    let t = tls_settings(config_path).ok();
    if let Some(kind) = t.as_ref().and_then(|t| web_kind(t.frontend)) {
        let prefix_changed = before.path() != after.path();
        let needs_route = after.is_enabled() && (enabled == Some(true) || prefix_changed || o.vhost);
        if o.vhost {
            let t = t.as_ref().unwrap();
            let domain = t.domain.clone().ok_or_else(|| anyhow!("no domain in the config"))?;
            let params = VhostParams {
                domain,
                ws_path: t.ws_path.clone(),
                ostp_port: listen_port(&v),
                panel: panel_route(&v),
                subscription: subscription_prefix(&v),
                responder: t.acme.responder.clone(),
                cert_path: t.cert_path.clone(),
                key_path: t.key_path.clone(),
            };
            webserver::install(kind, &params, &crate::config_dir_of(config_path))?;
            println!("  {} {} site rewritten and reloaded", "✓".green(), kind.as_str());
        } else if needs_route && !vhost_forwards(config_path, &after.path()) {
            println!(
                "\n  {} {} serves 443 and does not forward {}/ to OSTP yet. Either run\n      ostp sub set --vhost\n    to rewrite the OSTP-managed site, or add this to your {} config yourself:\n",
                "!".yellow(),
                kind.as_str(),
                after.path(),
                kind.as_str()
            );
            println!("{}", snippet(kind, &after.path(), listen_port(&v)));
        }
    }

    crate::cert_cmd::restart_service(o.no_restart);
    Ok(())
}

fn web_kind(f: Frontend) -> Option<Kind> {
    match f {
        Frontend::Builtin => None,
        Frontend::Nginx => Some(Kind::Nginx),
        Frontend::Apache => Some(Kind::Apache),
        Frontend::Caddy => Some(Kind::Caddy),
    }
}

fn snippet(kind: Kind, prefix: &str, port: u16) -> String {
    match kind {
        Kind::Nginx => format!(
            "    location ^~ {prefix}/ {{\n        proxy_pass http://127.0.0.1:{port};\n        proxy_set_header Host $host;\n        proxy_set_header X-Real-IP $remote_addr;\n    }}"
        ),
        Kind::Apache => format!("    ProxyPass {prefix}/ http://127.0.0.1:{port}{prefix}/"),
        Kind::Caddy => format!("    handle {prefix}/* {{\n        reverse_proxy 127.0.0.1:{port}\n    }}"),
    }
}

/// Whether the site OSTP wrote for the web server already forwards `prefix`.
fn vhost_forwards(config_path: &Path, prefix: &str) -> bool {
    let manifest = webserver::manifest_path(&crate::config_dir_of(config_path));
    let Ok(raw) = std::fs::read_to_string(manifest) else { return false };
    let Ok(m) = serde_json::from_str::<webserver::Manifest>(&raw) else { return false };
    m.files_created
        .iter()
        .filter_map(|f| std::fs::read_to_string(f).ok())
        .any(|site| site.contains(&format!("{prefix}/")))
}

fn print_settings(s: &SubscriptionCfg) {
    let state = if s.is_enabled() { "on".green().bold() } else { "off".yellow().bold() };
    println!("    Subscriptions: {state}");
    println!("    Path:          {}/<token>", s.path());
    println!("    Title:         {}", s.name.clone().filter(|n| !n.is_empty()).unwrap_or_else(|| "(the domain)".into()));
    println!("    Refresh:       every {} h", s.update_interval_hours());
    let inc: Vec<&str> = ["tls", "udp"].into_iter().filter(|k| s.includes(k)).collect();
    println!("    Links:         {}", inc.join(", "));
}

fn status(config_path: &Path) -> Result<()> {
    let v = read_json(config_path)?;
    let s = current(&v);
    println!("\n  {}", "Subscription server".bold());
    print_settings(&s);

    let domain = v.get("domain").and_then(|d| d.as_str()).filter(|d| !d.is_empty());
    let tls_on = v.pointer("/tls/enabled").and_then(|x| x.as_bool()) == Some(true);
    println!("\n  Requirements:");
    let ok = |b: bool| if b { "✓".green() } else { "✗".red() };
    println!("    {} domain       {}", ok(domain.is_some()), domain.unwrap_or("not set"));
    println!("    {} HTTPS (tls)  {}", ok(tls_on), if tls_on { "enabled" } else { "not set up: ostp cert issue" });
    if let Some(kind) = tls_settings(config_path).ok().and_then(|t| web_kind(t.frontend)) {
        let fwd = vhost_forwards(config_path, &s.path());
        println!(
            "    {} {} forwards {}/  {}",
            ok(fwd),
            kind.as_str(),
            s.path(),
            if fwd { "" } else { "(ostp sub set --vhost, or add it by hand)" }
        );
    }
    if s.is_enabled() {
        println!("\n  URLs: ostp sub urls");
    } else {
        println!("\n  Turn on: ostp sub enable");
    }
    Ok(())
}

fn urls(config_path: &Path, who: Option<&str>) -> Result<()> {
    let v = read_json(config_path)?;
    let cfg: UnifiedConfig = serde_json::from_value(v)?;
    let ostp_client::config::AppMode::Server(server) = cfg.mode else { bail!("not a server config") };
    if !server.subscription.as_ref().is_some_and(|s| s.is_enabled()) {
        bail!("subscriptions are off (ostp sub enable)");
    }
    let mut shown = 0;
    for (i, user) in server.access_keys.iter().enumerate() {
        let key = user.key();
        let name = user.name().unwrap_or_default();
        let hit = match who {
            None => true,
            Some(w) => w == (i + 1).to_string() || (!name.is_empty() && w.eq_ignore_ascii_case(&name)) || w == key,
        };
        if !hit {
            continue;
        }
        if let Some(url) = crate::subscription_url_for(&server, &key) {
            let label = if name.is_empty() { format!("key {}", i + 1) } else { name };
            println!("  [{}] {label:<16} {url}", i + 1);
            shown += 1;
        }
    }
    if shown == 0 {
        bail!("no user matches {}", who.unwrap_or("(any)"));
    }
    Ok(())
}
