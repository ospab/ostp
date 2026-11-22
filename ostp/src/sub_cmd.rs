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
    // One command, one edit of the file.
    let _lock = (!matches!(action, SubAction::Status)).then(|| ostp_server::config_io::lock_config(config_path));
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
    } else if let Some(p) = prefix_on_enable(&sub, before.is_enabled(), enabled == Some(true)) {
        println!("  {} Subscription path: {p} (random; `ostp sub set --path <p>` changes it)", "✓".green());
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
    crate::cert_cmd::save_json(config_path, &v)?;
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

    crate::service_cmd::restart_service(o.no_restart);
    Ok(())
}

/// The prefix to write when subscriptions are turned on: a random one when
/// they were off and the config names no path, so the URL does not tell a
/// scanner where to look. A config that has a path (even "/sub") keeps it, and
/// one already serving keeps its default "/sub": URLs in use never change.
fn prefix_on_enable(sub: &serde_json::Value, was_enabled: bool, enabling: bool) -> Option<String> {
    let has_path = sub.get("path").and_then(|p| p.as_str()).is_some_and(|p| !p.trim_matches('/').is_empty());
    (enabling && !was_enabled && !has_path).then(ostp_core::subscription::random_prefix)
}

pub(crate) fn web_kind(f: Frontend) -> Option<Kind> {
    match f {
        Frontend::Builtin => None,
        Frontend::Nginx => Some(Kind::Nginx),
        Frontend::Apache => Some(Kind::Apache),
        Frontend::Caddy => Some(Kind::Caddy),
    }
}

/// The route to paste into a site the operator keeps by hand: the same one the
/// OSTP-managed site gets, which replaces OSTP's bare 404 for an unknown token
/// with the web server's own error page.
fn snippet(kind: Kind, prefix: &str, port: u16) -> String {
    let route = webserver::sub_route(kind, prefix, port, true);
    let route = route.trim_end();
    match kind {
        Kind::Nginx => format!(
            "{route}\n    # If this server has its own `error_page 404`, point the location's error_page there instead."
        ),
        Kind::Apache => format!("{route}\n    # Apache older than 2.4.47: write `ProxyErrorOverride On` without the code."),
        Kind::Caddy => route.to_string(),
    }
}

/// Whether the site's route for the prefix makes the web server answer an
/// unknown token with its own 404 (sites written before 0.5.0 do not).
fn vhost_hides_unknown_tokens(config_path: &Path) -> bool {
    let manifest = webserver::manifest_path(&crate::config_dir_of(config_path));
    let Ok(raw) = std::fs::read_to_string(manifest) else { return false };
    let Ok(m) = serde_json::from_str::<webserver::Manifest>(&raw) else { return false };
    m.files_created
        .iter()
        .filter_map(|f| std::fs::read_to_string(f).ok())
        .any(|site| ["proxy_intercept_errors on", "ProxyErrorOverride On", "@ostp_not_found status 404"].iter().any(|d| site.contains(d)))
}

/// Whether the site OSTP wrote for the web server already forwards `prefix`.
pub(crate) fn vhost_forwards(config_path: &Path, prefix: &str) -> bool {
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
        if fwd && !vhost_hides_unknown_tokens(config_path) {
            println!(
                "    {} {} shows OSTP's own 404 for an unknown token, unlike its 404 for other paths\n      \
                 (ostp sub set --vhost rewrites the OSTP-managed site; a site kept by hand: see `ostp sub enable` output or docs)",
                "!".yellow(),
                kind.as_str()
            );
        }
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
        if let Some(url) = crate::subscription_url_for(&server, &user.sub_token()) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn enabling_writes_a_random_prefix_only_when_none_is_configured() {
        let p = prefix_on_enable(&json!({}), false, true).expect("off and no path: a random one");
        assert_eq!(p.len(), 11);
        assert!(p.starts_with('/') && p[1..].bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()), "{p}");
        assert_eq!(prefix_on_enable(&json!({ "path": "/sub" }), false, true), None, "an explicit /sub is kept");
        assert_eq!(prefix_on_enable(&json!({ "path": "/mine" }), false, true), None);
        assert_eq!(prefix_on_enable(&json!({}), true, true), None, "already serving on the default /sub: unchanged");
        assert_eq!(prefix_on_enable(&json!({}), false, false), None, "only when turning it on");
    }

    #[test]
    fn printed_snippets_make_the_web_server_answer_unknown_tokens_itself() {
        let n = snippet(Kind::Nginx, "/abc", 50000);
        assert!(n.contains("location ^~ /abc/ {"));
        assert!(n.contains("proxy_intercept_errors on;"));
        assert!(n.contains("error_page 404 = @ostp_not_found;"));
        assert!(n.contains("location @ostp_not_found {\n"));
        assert!(n.contains("recursive_error_pages on;\n        return 404;"));
        let a = snippet(Kind::Apache, "/abc", 50000);
        assert!(a.contains("ProxyPass /abc/ http://127.0.0.1:50000/abc/"));
        assert!(a.contains("<Location \"/abc/\">") && a.contains("ProxyErrorOverride On 404"));
        let c = snippet(Kind::Caddy, "/abc", 50000);
        assert!(c.contains("reverse_proxy 127.0.0.1:50000 {"));
        assert!(c.contains("@ostp_not_found status 404"));
        assert!(c.contains("handle_response @ostp_not_found {\n                error 404"));
    }
}
