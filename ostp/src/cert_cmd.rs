//! `ostp cert issue|status|renew`: bind the server to a domain, put it behind
//! the local web server (or OSTP's own 443/80), and get a Let's Encrypt
//! certificate that the service then renews by itself.

use anyhow::{anyhow, bail, Context, Result};
use colored::Colorize;
use std::path::Path;

use ostp_server::tls::{acme, Frontend, TlsSettings};

use crate::webserver::{self, Kind};

#[derive(clap::Subcommand, Debug)]
pub enum CertAction {
    /// Bind a domain, set up HTTPS and issue a Let's Encrypt certificate
    Issue(IssueArgs),
    /// Show the domain, HTTPS setup and certificate state
    Status,
    /// Renew the certificate now (the service also renews on its own)
    Renew {
        /// Renew even if the certificate is not due yet
        #[arg(long)]
        force: bool,
    },
}

#[derive(clap::Args, Debug, Default, Clone)]
pub struct IssueArgs {
    /// Domain name pointing at this server (A/AAAA record)
    #[arg(long)]
    pub domain: Option<String>,
    /// Contact email for Let's Encrypt (optional)
    #[arg(long)]
    pub email: Option<String>,
    /// Use the Let's Encrypt staging CA (untrusted test certificates)
    #[arg(long)]
    pub staging: bool,
    /// Agree to the Let's Encrypt Subscriber Agreement without asking
    #[arg(long)]
    pub agree_tos: bool,
    /// Who serves 443: auto, builtin, nginx, apache, caddy
    #[arg(long)]
    pub frontend: Option<String>,
    /// Use your own certificate instead of Let's Encrypt
    #[arg(long, requires = "key_path")]
    pub cert_path: Option<String>,
    #[arg(long, requires = "cert_path")]
    pub key_path: Option<String>,
    /// Answer yes to every confirmation
    #[arg(short = 'y', long)]
    pub yes: bool,
    /// Do not restart the running ostp service afterwards
    #[arg(long)]
    pub no_restart: bool,
}

pub async fn run(action: CertAction, config_path: &Path) -> Result<()> {
    match action {
        CertAction::Issue(a) => issue_interactive(config_path, a).await,
        CertAction::Status => status(config_path).await,
        CertAction::Renew { force } => renew(config_path, force).await,
    }
}

// ── Config access ────────────────────────────────────────────────────────────

pub(crate) fn read_json(config_path: &Path) -> Result<serde_json::Value> {
    let raw = std::fs::read_to_string(config_path).with_context(|| format!("cannot read {}", config_path.display()))?;
    let mut stripped = json_comments::StripComments::new(raw.as_bytes());
    let v: serde_json::Value = serde_json::from_reader(&mut stripped)
        .with_context(|| format!("cannot parse {}", config_path.display()))?;
    if v.get("mode").and_then(|m| m.as_str()) != Some("server") {
        bail!("{} is not a server config", config_path.display());
    }
    Ok(v)
}

fn server_cfg(config_path: &Path) -> Result<ostp_client::config::ServerConfig> {
    let v = read_json(config_path)?;
    let cfg: ostp_client::config::UnifiedConfig = serde_json::from_value(v)?;
    cfg.validate()?;
    match cfg.mode {
        ostp_client::config::AppMode::Server(s) => Ok(s),
        _ => bail!("{} is not a server config", config_path.display()),
    }
}

pub(crate) fn tls_settings(config_path: &Path) -> Result<TlsSettings> {
    let cfg = server_cfg(config_path)?;
    let tls = cfg
        .tls
        .as_ref()
        .filter(|t| t.is_enabled())
        .ok_or_else(|| anyhow!("HTTPS is not set up in {} (run `ostp cert issue`)", config_path.display()))?;
    Ok(crate::resolve_tls_settings(tls, cfg.domain.clone().filter(|d| !d.is_empty()), config_path))
}

pub(crate) fn random_path() -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let s: String = (0..24).map(|_| A[rand::random::<usize>() % A.len()] as char).collect();
    format!("/{s}")
}

pub(crate) fn listen_port(v: &serde_json::Value) -> u16 {
    let first = match &v["listen"] {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(a) => a.first().and_then(|x| x.as_str()).unwrap_or_default().to_string(),
        _ => String::new(),
    };
    first.rsplit_once(':').and_then(|(_, p)| p.parse().ok()).unwrap_or(50000)
}

/// (webpath, loopback API address) when the panel is enabled.
pub(crate) fn panel_route(v: &serde_json::Value) -> Option<(String, String)> {
    let api = v.get("api")?;
    if !api.get("enabled").and_then(|e| e.as_bool()).unwrap_or(false) {
        return None;
    }
    let webpath = api.get("webpath").and_then(|w| w.as_str()).unwrap_or("").trim_matches('/').to_string();
    let webpath = if webpath.is_empty() { "panel".to_string() } else { webpath };
    let bind = api.get("bind").and_then(|b| b.as_str()).unwrap_or("127.0.0.1:9090");
    let port = bind.rsplit_once(':').map(|(_, p)| p).unwrap_or("9090");
    Some((webpath, format!("127.0.0.1:{port}")))
}

pub(crate) fn subscription_prefix(v: &serde_json::Value) -> Option<String> {
    let cfg: ostp_client::config::SubscriptionCfg = serde_json::from_value(v.get("subscription")?.clone()).ok()?;
    cfg.is_enabled().then(|| cfg.path())
}

// ── issue ────────────────────────────────────────────────────────────────────

pub async fn issue_interactive(config_path: &Path, a: IssueArgs) -> Result<()> {
    let mut v = read_json(config_path)?;
    let config_dir = crate::config_dir_of(config_path);
    crate::wizard_section("Domain & HTTPS");

    let existing = v.get("domain").and_then(|d| d.as_str()).unwrap_or("").to_string();
    let domain = match a.domain.clone() {
        Some(d) => d,
        None => crate::wizard_prompt("Domain name (its A/AAAA record must point to this server)", &existing),
    }
    .trim()
    .to_lowercase();
    ostp_client::config::validate_domain(&domain)?;
    check_dns(&domain, a.yes).await?;

    let frontend = choose_frontend(a.frontend.as_deref(), a.yes)?;
    let cert = if frontend == Some(Kind::Caddy) {
        "none"
    } else if a.cert_path.is_some() {
        "manual"
    } else {
        "acme"
    };

    let mut acme_cfg = serde_json::json!({});
    if cert == "acme" {
        let email = match a.email.clone() {
            Some(e) => e,
            None if a.yes => String::new(),
            None => crate::wizard_prompt("Contact email for Let's Encrypt (optional, Enter to skip)", ""),
        };
        println!("\n  Let's Encrypt Subscriber Agreement: https://letsencrypt.org/repository/");
        if !a.agree_tos && !a.yes && !crate::wizard_yn("Do you agree to the Let's Encrypt Subscriber Agreement?", false) {
            bail!("the Subscriber Agreement must be accepted to get a certificate");
        }
        let staging = a.staging
            || (!a.yes && crate::wizard_yn("Use the staging CA first (untrusted test certificate)?", false));
        acme_cfg = serde_json::json!({ "email": email, "staging": staging });
    }

    let ws_path = v
        .pointer("/tls/ws_path")
        .and_then(|p| p.as_str())
        .filter(|p| p.len() >= 9)
        .map(str::to_string)
        .unwrap_or_else(random_path);
    let mut tls = serde_json::json!({
        "enabled": true,
        "frontend": frontend.map(Kind::as_str).unwrap_or("builtin"),
        "ws_path": ws_path,
        "cert": cert,
        "public_port": 443,
    });
    if cert == "acme" {
        tls["acme"] = acme_cfg;
    }
    if let (Some(c), Some(k)) = (&a.cert_path, &a.key_path) {
        tls["cert_path"] = c.clone().into();
        tls["key_path"] = k.clone().into();
    }
    if let Some(kind) = frontend {
        tls["reload_command"] = webserver::reload_command(kind).into();
    }
    v["domain"] = domain.clone().into();
    v["tls"] = tls;

    // Validate before touching anything on disk.
    let parsed: ostp_client::config::UnifiedConfig = serde_json::from_value(v.clone())?;
    parsed.validate()?;
    let backup = config_path.with_extension("json.bak");
    let _ = std::fs::copy(config_path, &backup);
    crate::wizard_save_config(config_path, &v)?;
    crate::wizard_ok(&format!("Saved domain and HTTPS settings to {} (previous: {})", config_path.display(), backup.display()));

    let t = tls_settings(config_path)?;

    if let Some(kind) = frontend {
        if t.cert != ostp_server::tls::CertSource::None && (!t.cert_path.exists() || !t.key_path.exists()) {
            // The vhost must pass the web server's config test before the real
            // certificate exists.
            ostp_server::tls::write_placeholder(&domain, &t.cert_path, &t.key_path)?;
        }
        let params = webserver::VhostParams {
            domain: domain.clone(),
            ws_path: t.ws_path.clone(),
            ostp_port: listen_port(&v),
            panel: panel_route(&v),
            subscription: subscription_prefix(&v),
            responder: t.acme.responder.clone(),
            cert_path: t.cert_path.clone(),
            key_path: t.key_path.clone(),
        };
        webserver::install(kind, &params, &config_dir)?;
        crate::wizard_ok(&format!("{} now serves {domain} and forwards OSTP to port {}", kind.as_str(), params.ostp_port));
    } else {
        check_ports_free();
    }

    if t.cert == ostp_server::tls::CertSource::Acme {
        let info = issue_now(&t).await?;
        crate::wizard_ok(&format!(
            "Certificate for {domain} issued by {}, valid for {} days{}",
            info.issuer,
            info.days_left(acme::unix_now()),
            if info.is_staging() { " (STAGING: not trusted by clients unless they skip verification)" } else { "" }
        ));
    }

    print_links(config_path)?;
    restart_service(a.no_restart);
    Ok(())
}

async fn check_dns(domain: &str, yes: bool) -> Result<()> {
    let resolved: Vec<std::net::IpAddr> = match tokio::net::lookup_host((domain, 80)).await {
        Ok(addrs) => addrs.map(|a| a.ip()).collect(),
        Err(e) => {
            crate::wizard_warn(&format!("{domain} does not resolve yet: {e}"));
            Vec::new()
        }
    };
    let mine = crate::detect_all_public_ipv4();
    let matches = resolved.iter().any(|ip| mine.contains(&ip.to_string()));
    if !mine.is_empty() && !matches {
        crate::wizard_warn(&format!(
            "{domain} points to {:?}, but this server's public addresses are {:?}. Let's Encrypt will fail until DNS is fixed.",
            resolved, mine
        ));
        if !yes && !crate::wizard_yn("Continue anyway?", false) {
            bail!("aborted");
        }
    }
    Ok(())
}

fn choose_frontend(flag: Option<&str>, yes: bool) -> Result<Option<Kind>> {
    match flag {
        Some("builtin") => return Ok(None),
        Some(f) if f != "auto" => {
            return Kind::parse(f).map(Some).ok_or_else(|| anyhow!("unknown --frontend {f} (auto, builtin, nginx, apache, caddy)"));
        }
        _ => {}
    }
    let found = webserver::detect();
    match found.as_slice() {
        [] => {
            println!("  No nginx, apache or caddy found: OSTP will serve HTTPS on 443 (and 80 for Let's Encrypt) itself.");
            Ok(None)
        }
        [kind] => {
            let q = format!(
                "{} is installed. Add an OSTP site for this domain to it (backed up, config-tested, rolled back on error)?",
                kind.as_str()
            );
            if yes || crate::wizard_yn(&q, true) {
                Ok(Some(*kind))
            } else {
                bail!("nothing changed; with {} on 443 OSTP cannot take the port itself", kind.as_str())
            }
        }
        many => {
            let names: Vec<&str> = many.iter().map(|k| k.as_str()).collect();
            let pick = crate::wizard_prompt(&format!("Several web servers found ({}). Which one serves 443?", names.join(", ")), names[0]);
            Kind::parse(pick.trim()).map(Some).ok_or_else(|| anyhow!("unknown web server {pick}"))
        }
    }
}

fn check_ports_free() {
    for port in [80u16, 443] {
        if std::net::TcpListener::bind(("0.0.0.0", port)).is_err() {
            crate::wizard_warn(&format!(
                "port {port} is in use (another web server, or OSTP already running with HTTPS); OSTP needs it for the built-in HTTPS frontend"
            ));
        }
    }
}

/// Runs one issuance from the CLI. The challenge is served in-process when
/// its port is free, otherwise by the running service through the shared
/// challenge directory.
async fn issue_now(t: &TlsSettings) -> Result<acme::CertInfo> {
    let domain = t.domain.clone().ok_or_else(|| anyhow!("no domain configured"))?;
    let state = acme::state_dir(&t.config_dir);
    let _lock = acme::acquire_lock(&state)?;
    let store = acme::ChallengeStore::new(&state);
    let bind = if t.frontend == Frontend::Builtin {
        t.http_listen.first().cloned().unwrap_or_else(|| "0.0.0.0:80".into())
    } else {
        t.acme.responder.clone()
    };
    let server = match tokio::net::TcpListener::bind(&bind).await {
        Ok(listener) => Some(tokio::spawn(ostp_server::tls::http_frontend::serve(
            listener,
            acme::challenge_router(store.clone(), None),
        ))),
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            println!("  {bind} is in use; assuming the running OSTP service answers the challenge.");
            None
        }
        Err(e) => bail!("cannot listen on {bind} for the ACME challenge: {e}"),
    };

    println!("  Requesting a certificate for {domain} from Let's Encrypt{}...", if t.acme.staging { " (staging)" } else { "" });
    let result = acme::issue(acme::IssueRequest {
        domain: &domain,
        email: t.acme.email.as_deref(),
        directory_url: acme::directory_url(t.acme.staging, t.acme.directory.as_deref()),
        state_dir: &state,
        store: &store,
        cert_path: &t.cert_path,
        key_path: &t.key_path,
    })
    .await;
    if let Some(s) = server {
        s.abort();
    }
    let info = result?;
    if let Some(cmd) = &t.reload_command {
        acme::run_reload_command(cmd).await;
    }
    Ok(info)
}

fn print_links(config_path: &Path) -> Result<()> {
    let cfg = server_cfg(config_path)?;
    if let Some(key) = cfg.access_keys.first() {
        println!("\n  {}", "Share links for the first key:".bold());
        for (label, link) in crate::share_links_for(&cfg, &key.key(), config_path) {
            println!("    {label:<3}  {}", link.to_uri().green());
        }
        if let Some(url) = crate::subscription_url_for(&cfg, &key.key()) {
            println!("    SUB  {}", url.green());
        }
        println!("  All keys: ostp links");
    }
    if let Some((webpath, _)) = panel_route(&read_json(config_path)?) {
        if let Some(d) = cfg.domain.as_deref() {
            println!("  Panel: https://{d}/{webpath}/");
        }
    }
    Ok(())
}

/// Applies a config change to the running service: restarts it if it is
/// running (a stopped service stays stopped), then checks it came back.
pub(crate) fn restart_service(skip: bool) {
    let has_unit = Path::new("/etc/systemd/system/ostp.service").exists() || Path::new("/lib/systemd/system/ostp.service").exists();
    if skip || !has_unit {
        println!("\n  Restart OSTP to apply this: {}", "sudo systemctl restart ostp".bold());
        return;
    }
    let active = |unit: &str| {
        std::process::Command::new("systemctl").args(["is-active", "--quiet", unit]).status().is_ok_and(|s| s.success())
    };
    if !active("ostp") {
        println!("\n  The ostp service is not running; the change applies when it starts.");
        return;
    }
    match std::process::Command::new("systemctl").args(["restart", "ostp"]).status() {
        Ok(s) if s.success() => {
            std::thread::sleep(std::time::Duration::from_secs(2));
            if active("ostp") {
                crate::wizard_ok("ostp restarted with the new settings");
            } else {
                crate::wizard_warn("ostp did not stay up after the restart; last log lines:");
                let _ = std::process::Command::new("journalctl").args(["-u", "ostp", "-n", "15", "--no-pager"]).status();
            }
        }
        _ => crate::wizard_warn("could not restart ostp; run: sudo systemctl restart ostp"),
    }
}

// ── status / renew ───────────────────────────────────────────────────────────

async fn status(config_path: &Path) -> Result<()> {
    let t = tls_settings(config_path)?;
    let now = acme::unix_now();
    println!();
    println!("  Domain:      {}", t.domain.as_deref().unwrap_or("-"));
    println!("  Frontend:    {}", t.frontend.as_str());
    println!("  Upgrade:     {}", t.ws_path);
    match t.cert {
        ostp_server::tls::CertSource::None => println!("  Certificate: managed by {}", t.frontend.as_str()),
        _ => match acme::cert_info(&t.cert_path) {
            Ok(i) => {
                let kind = if i.self_signed {
                    "self-signed placeholder (not issued yet)".to_string()
                } else if i.is_staging() {
                    format!("{} (STAGING)", i.issuer)
                } else {
                    i.issuer.clone()
                };
                println!("  Certificate: {}", t.cert_path.display());
                println!("  Issuer:      {kind}");
                println!("  Names:       {}", i.sans.join(", "));
                println!("  Expires in:  {} days", i.days_left(now));
                if t.cert == ostp_server::tls::CertSource::Acme {
                    if let Some(d) = &t.domain {
                        let at = acme::renew_at(Some(&i), d, t.acme.staging, t.acme.renew_days_before);
                        if at <= now {
                            println!("  Renewal:     due now (the service retries on its own; or `ostp cert renew`)");
                        } else {
                            println!("  Renewal:     in {} days", (at - now) / 86_400);
                        }
                    }
                }
            }
            Err(e) => println!("  Certificate: {e:#}"),
        },
    }
    if webserver::manifest_path(&t.config_dir).exists() {
        println!("  Web server:  site installed by ostp ({})", webserver::manifest_path(&t.config_dir).display());
    }
    self_test(config_path, &t).await;
    Ok(())
}

/// Walks the path a client takes, from the inside out, so a failure names
/// the link that is broken instead of a bare 502 on the phone.
async fn self_test(config_path: &Path, t: &TlsSettings) {
    use ostp_client::transport::tls::{http_upgrade, wrap_tls};
    use ostp_client::transport::TlsClientOptions;
    use std::time::Duration;
    const WAIT: Duration = Duration::from_secs(4);

    let Ok(v) = read_json(config_path) else { return };
    let domain = t.domain.clone().unwrap_or_else(|| "localhost".into());
    let port = listen_port(&v);
    let listen: Vec<String> = match &v["listen"] {
        serde_json::Value::String(s) => vec![s.clone()],
        serde_json::Value::Array(a) => a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect(),
        _ => Vec::new(),
    };
    let on_loopback = listen.iter().any(|a| {
        let host = a.rsplit_once(':').map(|(h, _)| h.trim_matches(['[', ']'])).unwrap_or("");
        matches!(host, "0.0.0.0" | "::" | "127.0.0.1" | "::1" | "localhost")
    });

    println!("\n  Checks:");
    let report = |ok: bool, what: &str, detail: String| {
        if ok {
            println!("    {} {what}", "✓".green());
        } else {
            println!("    {} {what}\n        {detail}", "✗".red());
        }
    };

    // 1. OSTP itself, where the web server forwards to.
    let direct = async {
        let mut s = tokio::time::timeout(WAIT, tokio::net::TcpStream::connect(("127.0.0.1", port)))
            .await
            .map_err(|_| anyhow!("connect timed out"))??;
        http_upgrade(&mut s, &t.ws_path, &domain, WAIT).await
    }
    .await;
    let mut detail = match &direct {
        Ok(_) => String::new(),
        Err(e) => format!("{e:#}. Is the service running (systemctl status ostp)?"),
    };
    if !on_loopback {
        detail.push_str(&format!(
            " OSTP listens on {} only, not on 127.0.0.1, which is where the web server forwards: add \"127.0.0.1:{port}\" (or use 0.0.0.0:{port}) in \"listen\".",
            listen.join(", ")
        ));
    }
    report(direct.is_ok(), &format!("OSTP answers the upgrade on 127.0.0.1:{port}"), detail);

    // 2. The public side: TLS on 443 and the secret path, as a client does it.
    let tls_opts = TlsClientOptions { sni: domain.clone(), insecure: true };
    let front = async {
        let s = tokio::time::timeout(WAIT, tokio::net::TcpStream::connect(("127.0.0.1", t.public_port)))
            .await
            .map_err(|_| anyhow!("connect timed out"))??;
        let mut s = wrap_tls(s, &tls_opts, WAIT).await?;
        http_upgrade(&mut s, &t.ws_path, &domain, WAIT).await
    }
    .await;
    let via = if t.frontend == ostp_server::tls::Frontend::Builtin { "OSTP" } else { t.frontend.as_str() };
    report(
        front.is_ok(),
        &format!("TLS on :{} ({via}) forwards {} to OSTP", t.public_port, t.ws_path),
        front.as_ref().err().map(|e| format!("{e:#}")).unwrap_or_default(),
    );

    // 3. Subscriptions, when they are on.
    let sub = subscription_prefix(&v);
    let first_key = v["access_keys"].as_array().and_then(|a| a.first()).and_then(|k| {
        k.as_str().map(str::to_string).or_else(|| k.get("access_key").and_then(|x| x.as_str()).map(str::to_string))
    });
    if let (Some(prefix), Some(key)) = (sub, first_key) {
        let token = ostp_core::subscription::token_for_key(&key);
        let got = async {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let s = tokio::time::timeout(WAIT, tokio::net::TcpStream::connect(("127.0.0.1", t.public_port)))
                .await
                .map_err(|_| anyhow!("connect timed out"))??;
            let mut s = wrap_tls(s, &tls_opts, WAIT).await?;
            s.write_all(format!("GET {prefix}/{token} HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n").as_bytes()).await?;
            let mut buf = vec![0u8; 256];
            let n = tokio::time::timeout(WAIT, s.read(&mut buf)).await.map_err(|_| anyhow!("no answer"))??;
            let line = String::from_utf8_lossy(&buf[..n]).lines().next().unwrap_or("").to_string();
            if line.contains(" 200 ") { Ok(()) } else { Err(anyhow!("answered \"{line}\" (ostp sub status shows what is missing)")) }
        }
        .await;
        report(
            got.is_ok(),
            &format!("subscription {prefix}/<token> is served over TLS"),
            got.err().map(|e| format!("{e:#}")).unwrap_or_default(),
        );
    }
}

async fn renew(config_path: &Path, force: bool) -> Result<()> {
    let t = tls_settings(config_path)?;
    if t.cert != ostp_server::tls::CertSource::Acme {
        bail!("the certificate is not issued by ostp (tls.cert = manual or none)");
    }
    let domain = t.domain.clone().ok_or_else(|| anyhow!("no domain configured"))?;
    let info = acme::cert_info(&t.cert_path).ok();
    let at = acme::renew_at(info.as_ref(), &domain, t.acme.staging, t.acme.renew_days_before);
    let now = acme::unix_now();
    if !force && at > now {
        println!("  Not due for {} more days (use --force to renew anyway).", (at - now) / 86_400);
        return Ok(());
    }
    let info = issue_now(&t).await?;
    crate::wizard_ok(&format!("Renewed: valid for {} days. The running service picks it up within a minute.", info.days_left(acme::unix_now())));
    Ok(())
}
