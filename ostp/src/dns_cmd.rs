//! `ostp dns`: the server's filtering DNS resolver (crate ostp-dns).
//!
//! Every change is made to the `dns` section of the config, validated,
//! backed up, and applied by restarting a running service (`--no-restart`
//! to skip). Clients connected to this server resolve through it; it is
//! never reachable from the internet.

use anyhow::{bail, Context, Result};
use colored::Colorize;
use std::path::Path;

use crate::cert_cmd::{read_json, restart_service};
use ostp_dns::{BlockingMode, DnsSettings, FilterList, Rewrite, UpstreamMode, PRESET_LISTS};

#[derive(clap::Subcommand, Debug)]
pub enum DnsAction {
    /// Show whether filtering is on and with what upstreams, lists and rules
    Status,
    /// Turn filtering on (the default block list is AdGuard DNS filter)
    Enable {
        #[arg(long)]
        no_restart: bool,
    },
    /// Turn filtering off (clients' DNS is still answered here with --intercept-only)
    Disable {
        /// Keep answering clients' port-53 queries, forwarded without filtering
        #[arg(long)]
        intercept_only: bool,
        #[arg(long)]
        no_restart: bool,
    },
    /// Upstream resolvers: https://…/dns-query, tls://host, tcp://ip, udp://ip, or an IP
    Upstream {
        #[command(subcommand)]
        action: UpstreamAction,
    },
    /// Block lists and allow lists
    List {
        #[command(subcommand)]
        action: ListAction,
    },
    /// Block a domain and its subdomains (adds ||domain^)
    Block {
        domain: String,
        #[arg(long)]
        no_restart: bool,
    },
    /// Never block a domain and its subdomains (adds @@||domain^)
    Allow {
        domain: String,
        #[arg(long)]
        no_restart: bool,
    },
    /// Your own rules, in adblock or hosts syntax
    Rule {
        #[command(subcommand)]
        action: RuleAction,
    },
    /// Local names answered by the server, e.g. panel.ostp -> 10.1.0.1
    Rewrite {
        #[command(subcommand)]
        action: RewriteAction,
    },
    /// Block whole services (TikTok, Facebook, ...)
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
    /// Safe search on Google, YouTube, Bing, DuckDuckGo and Yandex: on or off
    Safesearch {
        #[arg(value_parser = ["on", "off"])]
        state: String,
        #[arg(long)]
        no_restart: bool,
    },
    /// Stop browsers from using their own DNS over HTTPS/TLS: on or off
    DohBypass {
        #[arg(value_parser = ["on", "off"])]
        state: String,
        #[arg(long)]
        no_restart: bool,
    },
    /// What a blocked name gets: nxdomain, null_ip (0.0.0.0/::) or refused
    Mode {
        #[arg(value_parser = ["nxdomain", "null_ip", "refused"])]
        mode: String,
        #[arg(long)]
        no_restart: bool,
    },
    /// Download the lists now
    Update {
        #[arg(long)]
        no_restart: bool,
    },
    /// Explain what the resolver does with a name (offline, from the downloaded lists)
    Test { domain: String },
}

#[derive(clap::Subcommand, Debug)]
pub enum UpstreamAction {
    List,
    Add {
        upstream: String,
        #[arg(long)]
        no_restart: bool,
    },
    Remove {
        upstream: String,
        #[arg(long)]
        no_restart: bool,
    },
    /// fallback (in order) or parallel (first answer wins)
    Mode {
        #[arg(value_parser = ["fallback", "parallel"])]
        mode: String,
        #[arg(long)]
        no_restart: bool,
    },
}

#[derive(clap::Subcommand, Debug)]
pub enum ListAction {
    /// Lists in the config
    Show,
    /// Built-in lists to add by id
    Presets,
    /// Add a list by preset id or URL
    Add {
        list: String,
        #[arg(long)]
        name: Option<String>,
        /// An allow list: its domains are never blocked
        #[arg(long)]
        allow: bool,
        #[arg(long)]
        no_restart: bool,
    },
    /// Remove a list by number (as in `show`), name or URL
    Remove {
        list: String,
        #[arg(long)]
        no_restart: bool,
    },
    Enable {
        list: String,
        #[arg(long)]
        no_restart: bool,
    },
    Disable {
        list: String,
        #[arg(long)]
        no_restart: bool,
    },
}

#[derive(clap::Subcommand, Debug)]
pub enum RuleAction {
    List,
    Add {
        rule: String,
        #[arg(long)]
        no_restart: bool,
    },
    Remove {
        rule: String,
        #[arg(long)]
        no_restart: bool,
    },
}

#[derive(clap::Subcommand, Debug)]
pub enum RewriteAction {
    List,
    /// domain ("*.lan" for subdomains) and answer (IPv4, IPv6 or a name)
    Add {
        domain: String,
        answer: String,
        #[arg(long)]
        no_restart: bool,
    },
    Remove {
        domain: String,
        #[arg(long)]
        no_restart: bool,
    },
}

#[derive(clap::Subcommand, Debug)]
pub enum ServiceAction {
    List,
    Block {
        id: String,
        #[arg(long)]
        no_restart: bool,
    },
    Unblock {
        id: String,
        #[arg(long)]
        no_restart: bool,
    },
}

fn load(config_path: &Path) -> Result<(serde_json::Value, DnsSettings)> {
    let v = read_json(config_path)?;
    let s: DnsSettings = match v.get("dns") {
        Some(d) if !d.is_null() => serde_json::from_value(d.clone()).context("the dns section does not parse")?,
        _ => DnsSettings::default(),
    };
    Ok((v, s.normalized()))
}

/// Validates, backs up, writes, restarts.
fn save(config_path: &Path, mut v: serde_json::Value, s: &DnsSettings, no_restart: bool) -> Result<()> {
    s.validate()?;
    v["dns"] = serde_json::to_value(s)?;
    let backup = config_path.with_extension("json.bak");
    std::fs::copy(config_path, &backup).with_context(|| format!("cannot back up {}", config_path.display()))?;
    std::fs::write(config_path, serde_json::to_string_pretty(&v)?).with_context(|| format!("cannot write {}", config_path.display()))?;
    println!("  {} Saved {} (previous: {})", "✓".green(), config_path.display(), backup.display());
    restart_service(no_restart);
    Ok(())
}

fn find_list(lists: &[FilterList], key: &str) -> Option<usize> {
    if let Ok(n) = key.parse::<usize>() {
        return (n >= 1 && n <= lists.len()).then(|| n - 1);
    }
    lists.iter().position(|l| l.url == key || l.name.eq_ignore_ascii_case(key))
}

fn domain_arg(d: &str) -> Result<String> {
    let d = d.trim().trim_end_matches('.').to_ascii_lowercase();
    if d.is_empty() || !d.contains('.') || d.contains(['/', ' ', ':']) {
        bail!("\"{d}\" is not a domain name");
    }
    Ok(d)
}

pub async fn run(action: DnsAction, config_path: &Path) -> Result<()> {
    let data_dir = crate::config_dir_of(config_path);
    match action {
        DnsAction::Status => status(config_path, &data_dir),
        DnsAction::Enable { no_restart } => {
            let (v, mut s) = load(config_path)?;
            s.enabled = true;
            println!("  Filtering DNS on. Block lists: {}", s.lists.iter().filter(|l| l.enabled).map(|l| l.name.as_str()).collect::<Vec<_>>().join(", "));
            save(config_path, v, &s, no_restart)?;
            println!("  Clients resolve through this server once they reconnect. Try: ostp dns test ads.example.com");
            Ok(())
        }
        DnsAction::Disable { intercept_only, no_restart } => {
            let (v, mut s) = load(config_path)?;
            s.enabled = false;
            s.intercept_all_port53 = intercept_only;
            save(config_path, v, &s, no_restart)
        }
        DnsAction::Upstream { action } => {
            let (v, mut s) = load(config_path)?;
            match action {
                UpstreamAction::List => {
                    for (i, u) in s.upstreams.iter().enumerate() {
                        println!("  [{}] {u}", i + 1);
                    }
                    println!("  mode: {:?}", s.upstream_mode);
                    Ok(())
                }
                UpstreamAction::Add { upstream, no_restart } => {
                    ostp_dns::upstream::Upstream::parse(&upstream)?;
                    if !s.upstreams.contains(&upstream) {
                        s.upstreams.push(upstream);
                    }
                    save(config_path, v, &s, no_restart)
                }
                UpstreamAction::Remove { upstream, no_restart } => {
                    let before = s.upstreams.len();
                    s.upstreams.retain(|u| u != &upstream);
                    if s.upstreams.len() == before {
                        bail!("no upstream \"{upstream}\" (ostp dns upstream list)");
                    }
                    save(config_path, v, &s, no_restart)
                }
                UpstreamAction::Mode { mode, no_restart } => {
                    s.upstream_mode = if mode == "parallel" { UpstreamMode::Parallel } else { UpstreamMode::Fallback };
                    save(config_path, v, &s, no_restart)
                }
            }
        }
        DnsAction::List { action } => {
            let (v, mut s) = load(config_path)?;
            match action {
                ListAction::Show => {
                    for (kind, lists) in [("block", &s.lists), ("allow", &s.allowlists)] {
                        for (i, l) in lists.iter().enumerate() {
                            let age = ostp_dns::lists::age(&data_dir, &l.url)
                                .map(|a| format!("downloaded {} h ago", a.as_secs() / 3600))
                                .unwrap_or_else(|| "not downloaded yet".into());
                            println!(
                                "  [{}] {:<5} {} {}  {}\n        {}",
                                i + 1,
                                kind,
                                if l.enabled { "on ".green() } else { "off".yellow() },
                                l.name,
                                age.dimmed(),
                                l.url.dimmed()
                            );
                        }
                    }
                    Ok(())
                }
                ListAction::Presets => {
                    for (id, name, url) in PRESET_LISTS {
                        let added = s.lists.iter().any(|l| l.url == *url);
                        println!("  {id:<14} {name}{}\n                 {}", if added { "  (added)".green().to_string() } else { String::new() }, url.dimmed());
                    }
                    Ok(())
                }
                ListAction::Add { list, name, allow, no_restart } => {
                    let (url, default_name) = match PRESET_LISTS.iter().find(|(id, _, _)| *id == list) {
                        Some((_, n, u)) => (u.to_string(), n.to_string()),
                        None if list.starts_with("https://") || list.starts_with("http://") => (list.clone(), list.clone()),
                        None => bail!("\"{list}\" is neither a preset id (ostp dns list presets) nor a URL"),
                    };
                    let target = if allow { &mut s.allowlists } else { &mut s.lists };
                    if target.iter().any(|l| l.url == url) {
                        bail!("that list is already added");
                    }
                    target.push(FilterList { name: name.unwrap_or(default_name), url, enabled: true });
                    println!("  The service downloads it on start; to fetch it now: ostp dns update");
                    save(config_path, v, &s, no_restart)
                }
                ListAction::Remove { list, no_restart } => change_list(config_path, v, s, &list, ListChange::Remove, no_restart),
                ListAction::Enable { list, no_restart } => change_list(config_path, v, s, &list, ListChange::Enable, no_restart),
                ListAction::Disable { list, no_restart } => change_list(config_path, v, s, &list, ListChange::Disable, no_restart),
            }
        }
        DnsAction::Block { domain, no_restart } => {
            let (v, mut s) = load(config_path)?;
            let d = domain_arg(&domain)?;
            s.user_rules.retain(|r| r != &format!("@@||{d}^"));
            let rule = format!("||{d}^");
            if !s.user_rules.contains(&rule) {
                s.user_rules.push(rule);
            }
            save(config_path, v, &s, no_restart)
        }
        DnsAction::Allow { domain, no_restart } => {
            let (v, mut s) = load(config_path)?;
            let d = domain_arg(&domain)?;
            s.user_rules.retain(|r| r != &format!("||{d}^"));
            let rule = format!("@@||{d}^");
            if !s.user_rules.contains(&rule) {
                s.user_rules.push(rule);
            }
            save(config_path, v, &s, no_restart)
        }
        DnsAction::Rule { action } => {
            let (v, mut s) = load(config_path)?;
            match action {
                RuleAction::List => {
                    if s.user_rules.is_empty() {
                        println!("  No rules of your own. Add one: ostp dns rule add \"||ads.example.com^\"");
                    }
                    for r in &s.user_rules {
                        println!("  {r}");
                    }
                    Ok(())
                }
                RuleAction::Add { rule, no_restart } => {
                    let mut f = ostp_dns::filter::Filter::new();
                    f.add_source("check", &rule, false);
                    if f.sources[0].rules == 0 {
                        bail!("\"{rule}\" is not a rule this resolver applies (adblock ||domain^, @@||domain^, $important, * wildcards, or hosts lines)");
                    }
                    if !s.user_rules.contains(&rule) {
                        s.user_rules.push(rule);
                    }
                    save(config_path, v, &s, no_restart)
                }
                RuleAction::Remove { rule, no_restart } => {
                    let before = s.user_rules.len();
                    s.user_rules.retain(|r| r != &rule);
                    if s.user_rules.len() == before {
                        bail!("no rule \"{rule}\" (ostp dns rule list)");
                    }
                    save(config_path, v, &s, no_restart)
                }
            }
        }
        DnsAction::Rewrite { action } => {
            let (v, mut s) = load(config_path)?;
            match action {
                RewriteAction::List => {
                    if s.rewrites.is_empty() {
                        println!("  None. For the panel through the tunnel: ostp dns rewrite add panel.ostp 10.1.0.1");
                    }
                    for r in &s.rewrites {
                        println!("  {:<30} {}", r.domain, r.answer);
                    }
                    Ok(())
                }
                RewriteAction::Add { domain, answer, no_restart } => {
                    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
                    s.rewrites.retain(|r| !(r.domain == domain && r.answer == answer));
                    s.rewrites.push(Rewrite { domain: domain.clone(), answer: answer.clone() });
                    if answer == "10.1.0.1" {
                        println!("  10.1.0.1 is the server itself as clients see it through the tunnel.");
                    }
                    save(config_path, v, &s, no_restart)
                }
                RewriteAction::Remove { domain, no_restart } => {
                    let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
                    let before = s.rewrites.len();
                    s.rewrites.retain(|r| r.domain != d);
                    if s.rewrites.len() == before {
                        bail!("no rewrite for \"{d}\" (ostp dns rewrite list)");
                    }
                    save(config_path, v, &s, no_restart)
                }
            }
        }
        DnsAction::Service { action } => {
            let (v, mut s) = load(config_path)?;
            match action {
                ServiceAction::List => {
                    for (id, name, _) in ostp_dns::services::SERVICES {
                        let on = s.blocked_services.iter().any(|b| b == id);
                        println!("  {id:<10} {name}{}", if on { "  blocked".red().to_string() } else { String::new() });
                    }
                    Ok(())
                }
                ServiceAction::Block { id, no_restart } => {
                    if !s.blocked_services.contains(&id) {
                        s.blocked_services.push(id);
                    }
                    save(config_path, v, &s, no_restart)
                }
                ServiceAction::Unblock { id, no_restart } => {
                    s.blocked_services.retain(|b| b != &id);
                    save(config_path, v, &s, no_restart)
                }
            }
        }
        DnsAction::Safesearch { state, no_restart } => {
            let (v, mut s) = load(config_path)?;
            s.safe_search = state == "on";
            save(config_path, v, &s, no_restart)
        }
        DnsAction::DohBypass { state, no_restart } => {
            let (v, mut s) = load(config_path)?;
            s.block_doh_bypass = state == "on";
            save(config_path, v, &s, no_restart)
        }
        DnsAction::Mode { mode, no_restart } => {
            let (v, mut s) = load(config_path)?;
            s.blocking_mode = match mode.as_str() {
                "null_ip" => BlockingMode::NullIp,
                "refused" => BlockingMode::Refused,
                _ => BlockingMode::Nxdomain,
            };
            save(config_path, v, &s, no_restart)
        }
        DnsAction::Update { no_restart } => {
            let (_, s) = load(config_path)?;
            println!("  Downloading {} lists…", s.lists.iter().chain(s.allowlists.iter()).filter(|l| l.enabled).count());
            let results = ostp_dns::lists::update_all(&s, &data_dir, None).await;
            let mut ok = true;
            for r in &results {
                println!("  {} {}  {}", if r.ok { "✓".green() } else { "✗".red() }, r.name, r.detail.dimmed());
                ok &= r.ok;
            }
            let f = ostp_dns::lists::build_filter(&s, Some(&data_dir));
            println!("  {} rules in total", f.rule_count());
            restart_service(no_restart);
            if !ok {
                println!("  Failed lists keep their previous copy.");
            }
            Ok(())
        }
        DnsAction::Test { domain } => {
            let (_, s) = load(config_path)?;
            let dns = ostp_dns::Dns::new(s, Some(data_dir));
            let e = dns.explain(&domain);
            let outcome = format!("{:?}", e.outcome);
            let colored = match e.outcome {
                ostp_dns::Outcome::Blocked | ostp_dns::Outcome::BlockedService => outcome.red(),
                ostp_dns::Outcome::Allowed => outcome.green(),
                _ => outcome.cyan(),
            };
            println!("  {}  {colored}  {}", e.name.bold(), e.detail);
            if let Some(r) = e.rule {
                println!("  rule:   {r}");
            }
            if let Some(src) = e.source {
                println!("  from:   {src}");
            }
            Ok(())
        }
    }
}

enum ListChange {
    Remove,
    Enable,
    Disable,
}

fn change_list(config_path: &Path, v: serde_json::Value, mut s: DnsSettings, key: &str, change: ListChange, no_restart: bool) -> Result<()> {
    let (lists, i) = if let Some(i) = find_list(&s.lists, key) {
        (&mut s.lists, i)
    } else if let Some(i) = find_list(&s.allowlists, key) {
        (&mut s.allowlists, i)
    } else {
        bail!("no list \"{key}\" (ostp dns list show)");
    };
    match change {
        ListChange::Remove => {
            lists.remove(i);
        }
        ListChange::Enable => lists[i].enabled = true,
        ListChange::Disable => lists[i].enabled = false,
    }
    save(config_path, v, &s, no_restart)
}

fn status(config_path: &Path, data_dir: &Path) -> Result<()> {
    let (_, s) = load(config_path)?;
    println!("\n  {}", "DNS".bold());
    println!(
        "    Filtering:     {}{}",
        if s.enabled { "on".green().bold() } else { "off".yellow().bold() },
        if !s.enabled && s.intercept_all_port53 { " (clients' queries still answered here, unfiltered)" } else { "" }
    );
    println!("    Upstreams:     {} ({:?})", s.upstreams.join(", "), s.upstream_mode);
    println!("    Blocked names: {:?}, TTL {} s", s.blocking_mode, s.blocked_ttl);
    let f = ostp_dns::lists::build_filter(&s, Some(data_dir));
    for src in &f.sources {
        println!("    {:<28} {} rules{}", src.name, src.rules, if src.unsupported > 0 { format!(", {} unsupported", src.unsupported) } else { String::new() });
    }
    println!("    Rewrites:      {}", if s.rewrites.is_empty() { "none".into() } else { s.rewrites.iter().map(|r| format!("{} → {}", r.domain, r.answer)).collect::<Vec<_>>().join(", ") });
    println!("    Services:      {}", if s.blocked_services.is_empty() { "none blocked".into() } else { s.blocked_services.join(", ") });
    println!("    Safe search:   {}", if s.safe_search { "on" } else { "off" });
    println!("    DoH/DoT bypass blocked: {}", if s.block_doh_bypass { "yes" } else { "no" });
    if s.enabled && ostp_dns::lists::update_due(&s, data_dir) {
        println!("\n  {} Some lists are missing or out of date: ostp dns update", "!".yellow());
    }
    if !s.enabled {
        println!("\n  Turn on: ostp dns enable");
    }
    Ok(())
}
