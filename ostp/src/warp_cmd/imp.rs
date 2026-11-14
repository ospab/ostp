use anyhow::{anyhow, bail, Context, Result};
use colored::Colorize;
use serde_json::Value;
use std::net::SocketAddr;
use std::path::Path;

use super::WarpAction;
use crate::cert_cmd::{read_json, save_json};
use crate::service_cmd::restart_service;
use ostp_warp::api::{self, ApiClient};
use ostp_warp::config::{outbound_for_all, outbound_for_rules, outbound_points_at, WarpConfig, WarpMode};
use ostp_warp::store::{self, SavedOutbound, WarpState};

const TERMS_URL: &str = "https://www.cloudflare.com/application/terms/";

pub async fn run(action: WarpAction, config_path: &Path) -> Result<()> {
    match action {
        WarpAction::Register { accept_terms } => register(config_path, accept_terms, &api::api_base()).await,
        WarpAction::License { key, no_restart } => license(config_path, &key, &api::api_base(), no_restart).await,
        WarpAction::Enable { all, rules, no_restart } => {
            let mode = if all && !rules { WarpMode::All } else { WarpMode::Rules };
            enable(config_path, mode)?;
            restart_service(no_restart);
            Ok(())
        }
        WarpAction::Disable { no_restart } => {
            disable(config_path)?;
            restart_service(no_restart);
            Ok(())
        }
        WarpAction::Status => status(config_path).await,
        WarpAction::Test => test(config_path).await,
        WarpAction::Reset { yes } => reset(config_path, yes),
    }
}

fn load_cfg(v: &Value) -> Result<WarpConfig> {
    match v.get("warp") {
        Some(w) if !w.is_null() => serde_json::from_value(w.clone()).context("the warp section does not parse"),
        _ => Ok(WarpConfig::default()),
    }
}

/// The whole config as the server will read it, before anything is written.
fn validate_whole(v: &Value) -> Result<()> {
    let cfg: ostp_client::config::UnifiedConfig = serde_json::from_value(v.clone()).context("the config does not parse after the change")?;
    cfg.validate()?;
    Ok(())
}

fn load_state(config_path: &Path) -> Result<Option<WarpState>> {
    store::load(&store::path_for(config_path))
}

fn registered(config_path: &Path) -> Result<WarpState> {
    load_state(config_path)?.ok_or_else(|| {
        anyhow!("WARP is not registered on this server ({} does not exist): run `ostp warp register --accept-terms`", store::path_for(config_path).display())
    })
}

// ── register, license, reset ────────────────────────────────────────────────

pub(super) async fn register(config_path: &Path, accept_terms: bool, api_base: &str) -> Result<()> {
    read_json(config_path)?;
    if !accept_terms {
        println!("  `ostp warp register` creates a device at Cloudflare for this server:");
        println!("    - a new WireGuard key pair is made here; its public half is sent to {api_base}");
        println!("    - Cloudflare sees this server's IP address, as it does for any connection");
        println!("    - Cloudflare's WARP terms apply: {TERMS_URL}");
        bail!("nothing was registered. If you accept those terms: ostp warp register --accept-terms");
    }
    let sp = store::path_for(config_path);
    if store::load(&sp)?.is_some() {
        bail!("this server is already registered ({}). To start over: ostp warp reset, then register again", sp.display());
    }
    let client = ApiClient::new(api_base)?;
    let st = api::register_new(&client).await?;
    store::save(&sp, &st)?;
    println!("  {} Registered a WARP device ({}, {}).", "✓".green(), short_id(&st.device_id), st.account_type.as_deref().unwrap_or("account type not stated"));
    println!("  Keys are in {} (readable by its owner only); they are never written to config.json.", sp.display());
    println!("  Nothing uses WARP yet: {} or {}", "ostp warp enable --all".bold(), "ostp warp enable --rules".bold());
    Ok(())
}

pub(super) async fn license(config_path: &Path, key: &str, api_base: &str, no_restart: bool) -> Result<()> {
    let v = read_json(config_path)?;
    let mut st = registered(config_path)?;
    let key = key.trim();
    if key.is_empty() {
        bail!("the license key is empty");
    }
    let client = ApiClient::new(api_base)?;
    api::attach_license(&client, &mut st, key).await?;
    store::save(&store::path_for(config_path), &st)?;
    println!("  {} WARP+ key attached; the account type is now {}.", "✓".green(), st.account_type.as_deref().unwrap_or("not stated"));
    if load_cfg(&v)?.enabled {
        restart_service(no_restart);
    }
    Ok(())
}

fn reset(config_path: &Path, yes: bool) -> Result<()> {
    let v = read_json(config_path)?;
    let sp = store::path_for(config_path);
    if store::load(&sp)?.is_none() {
        println!("  Nothing to forget: {} does not exist.", sp.display());
        return Ok(());
    }
    if load_cfg(&v)?.enabled {
        bail!("WARP is enabled: run `ostp warp disable` first (that also puts the previous outbound section back)");
    }
    if !yes {
        use std::io::{IsTerminal, Write};
        if !std::io::stdin().is_terminal() {
            bail!("this deletes the device's keys from {}; run it in a terminal, or add --yes", sp.display());
        }
        print!("  Forget the registered device and delete {}? The device stays at Cloudflare; a new one needs `register`. [y/N]: ", sp.display());
        std::io::stdout().flush()?;
        let mut a = String::new();
        std::io::stdin().read_line(&mut a)?;
        if !a.trim().eq_ignore_ascii_case("y") {
            println!("  Left as it was.");
            return Ok(());
        }
    }
    store::remove(&sp)?;
    println!("  {} {} deleted.", "✓".green(), sp.display());
    Ok(())
}

fn short_id(id: &str) -> String {
    id.chars().take(8).collect()
}

// ── enable, disable ─────────────────────────────────────────────────────────

/// Writes the `warp` section (on) and the `outbound` section it needs, after
/// remembering what the operator had (in `warp.json`, once).
pub(super) fn enable(config_path: &Path, mode: WarpMode) -> Result<()> {
    let mut v = read_json(config_path)?;
    let sp = store::path_for(config_path);
    let mut st = registered(config_path)?;
    let mut cfg = load_cfg(&v)?;
    cfg.enabled = true;
    cfg.mode = mode;
    cfg.validate()?;
    let listen = cfg.listen_addr()?;

    let current = v.get("outbound").filter(|o| !o.is_null()).cloned();
    let current_is_warp = current.as_ref().is_some_and(|o| outbound_points_at(o, listen));
    // What the operator had comes from the first enable; a later one (a mode
    // change) starts from that, not from the section WARP wrote.
    let base: Option<Value> = match &st.saved_outbound {
        Some(saved) => saved.section.clone(),
        None => current.clone(),
    };
    let new_outbound = match mode {
        WarpMode::All => outbound_for_all(listen),
        WarpMode::Rules => outbound_for_rules(base.as_ref(), listen)?,
    };
    if st.saved_outbound.is_none() && !current_is_warp {
        st.saved_outbound = Some(SavedOutbound { section: current.clone() });
    }
    v["warp"] = serde_json::to_value(&cfg)?;
    v["outbound"] = new_outbound;
    validate_whole(&v)?;
    // The record of what to put back is on disk before the config changes.
    store::save(&sp, &st)?;
    save_json(config_path, &v)?;
    println!("  {} Saved {} (previous: {})", "✓".green(), config_path.display(), config_path.with_extension("json.bak").display());
    match mode {
        WarpMode::All => println!("  Mode all: every connection and UDP flow this server opens goes through WARP; with the tunnel down they fail, none goes out directly."),
        WarpMode::Rules => println!("  Mode rules: only what your outbound rules send to the proxy goes through WARP; the rest leaves as you wrote it."),
    }
    if let Some(Some(old)) = st.saved_outbound.as_ref().map(|s| s.section.as_ref()) {
        let host = old.get("address").and_then(Value::as_str).unwrap_or("?");
        println!("  Your previous outbound section (proxy {host}) is kept in warp.json and comes back with `ostp warp disable`.");
    }
    Ok(())
}

pub(super) fn disable(config_path: &Path) -> Result<()> {
    let mut v = read_json(config_path)?;
    let sp = store::path_for(config_path);
    let mut st = store::load(&sp)?;
    let mut cfg = load_cfg(&v)?;
    cfg.enabled = false;
    let listen = cfg.listen_addr().ok();
    let points = match (v.get("outbound"), listen) {
        (Some(o), Some(l)) => outbound_points_at(o, l),
        _ => false,
    };
    let mut note = None;
    match st.as_ref().and_then(|s| s.saved_outbound.clone()) {
        Some(saved) if points => match saved.section {
            Some(sec) => v["outbound"] = sec,
            None => {
                if let Some(o) = v.as_object_mut() {
                    o.remove("outbound");
                }
            }
        },
        Some(_) => note = Some("the outbound section no longer points at WARP's proxy (you changed it); it is left as it is"),
        None if points => {
            // WARP's own section with no record of what was before it.
            if let Some(o) = v.as_object_mut() {
                o.remove("outbound");
            }
            note = Some("there was no record of an earlier outbound section; the one pointing at WARP was removed");
        }
        None => {}
    }
    v["warp"] = serde_json::to_value(&cfg)?;
    validate_whole(&v)?;
    save_json(config_path, &v)?;
    if let Some(s) = st.as_mut() {
        if s.saved_outbound.take().is_some() {
            store::save(&sp, s)?;
        }
    }
    println!("  {} WARP is off; the server's connections go out as your outbound section says (or directly, when there is none).", "✓".green());
    if let Some(n) = note {
        println!("  {} {n}", "!".yellow());
    }
    Ok(())
}

// ── status, test ────────────────────────────────────────────────────────────

fn proxy_addr(cfg: &WarpConfig) -> Result<SocketAddr> {
    cfg.listen_addr()
}

async fn status(config_path: &Path) -> Result<()> {
    let v = read_json(config_path)?;
    let cfg = load_cfg(&v)?;
    let st = load_state(config_path)?;
    let onoff = |b: bool| if b { "yes".green() } else { "no".yellow() };
    match &st {
        None => println!("  registered:   {} (ostp warp register --accept-terms)", "no".yellow()),
        Some(s) => {
            println!("  registered:   {} (device {}, account {})", "yes".green(), short_id(&s.device_id), s.account_type.as_deref().unwrap_or("not stated"));
            println!("  WARP+ key:    {}", if s.license.is_some() { "attached" } else { "none" });
            println!("  endpoint:     {}", if cfg.endpoint.is_empty() { s.endpoint_host.clone() } else { cfg.endpoint.clone() });
        }
    }
    println!("  enabled:      {}  (mode {}, proxy {})", onoff(cfg.enabled), cfg.mode.as_str(), cfg.listen);
    let listen = proxy_addr(&cfg);
    let points = match (v.get("outbound"), &listen) {
        (Some(o), Ok(l)) => outbound_points_at(o, *l),
        _ => false,
    };
    if cfg.enabled && !points {
        println!("  {} the outbound section does not point at {}: traffic does not go through WARP. Run `ostp warp enable --all` or `--rules`.", "!".yellow(), cfg.listen);
    }
    if !cfg.enabled && points {
        println!("  {} the outbound section points at {} but WARP is off: connections that use it fail. Run `ostp warp disable`.", "!".yellow(), cfg.listen);
    }
    let Some(file) = ostp_warp::run::read_status(config_path).filter(|f| f.is_fresh()) else {
        if cfg.enabled {
            println!("  tunnel:       {} (the server is not running, or has not started WARP: see its log)", "unknown".yellow());
        }
        return Ok(());
    };
    let hs = file.last_handshake_secs.map(|s| format!("{s} s ago")).unwrap_or_else(|| "never".into());
    println!("  tunnel:       {}  (last handshake {hs}, {} sent, {} received)", if file.up { "up".green() } else { "DOWN".red().bold() }, human(file.tx_bytes), human(file.rx_bytes));
    println!("  connections:  {} TCP, {} UDP flows", file.tcp_connections, file.udp_flows);
    if file.udp_too_big > 0 {
        println!("  {} {} UDP datagrams were dropped for not fitting the tunnel's MTU (1280)", "!".yellow(), file.udp_too_big);
    }
    if let Ok(l) = listen {
        match ostp_warp::probe::trace_via(l).await {
            Ok(t) => println!("  seen outside: {} (warp={}, {})", t.ip.as_deref().unwrap_or("?"), t.warp.as_deref().unwrap_or("?"), t.loc.as_deref().unwrap_or("?")),
            Err(e) => println!("  seen outside: {} ({e:#})", "could not be read".red()),
        }
    }
    Ok(())
}

fn human(n: u64) -> String {
    match n {
        0..=1023 => format!("{n} B"),
        1024..=1_048_575 => format!("{:.1} KiB", n as f64 / 1024.0),
        _ => format!("{:.1} MiB", n as f64 / 1_048_576.0),
    }
}

async fn test(config_path: &Path) -> Result<()> {
    let v = read_json(config_path)?;
    let cfg = load_cfg(&v)?;
    registered(config_path)?;
    if !cfg.enabled {
        bail!("WARP is not enabled: ostp warp enable --all (or --rules), and keep the server running");
    }
    let l = proxy_addr(&cfg)?;
    println!("  Testing through the running server's proxy at {l} ...");
    let mut failed = false;
    match ostp_warp::probe::trace_via(l).await {
        Ok(t) if t.is_warp() => println!("  {} TCP: https://www.cloudflare.com/cdn-cgi/trace says warp={}, ip={}", "✓".green(), t.warp.as_deref().unwrap_or("?"), t.ip.as_deref().unwrap_or("?")),
        Ok(t) => {
            failed = true;
            println!("  {} TCP: reached Cloudflare but warp={}: the traffic is not leaving through WARP", "✗".red(), t.warp.as_deref().unwrap_or("absent"));
        }
        Err(e) => {
            failed = true;
            println!("  {} TCP: {e:#}", "✗".red());
        }
    }
    match ostp_warp::probe::dns_via(l, "1.1.1.1:53".parse()?, "cloudflare.com").await {
        Ok(ips) if !ips.is_empty() => println!("  {} UDP: a DNS query to 1.1.1.1 through the tunnel answered with {} address(es)", "✓".green(), ips.len()),
        Ok(_) => {
            failed = true;
            println!("  {} UDP: the query was answered with no addresses", "✗".red());
        }
        Err(e) => {
            failed = true;
            println!("  {} UDP: {e:#}", "✗".red());
        }
    }
    if failed {
        bail!("the WARP test failed");
    }
    Ok(())
}

/// The line `ostp check` prints for the `warp` section of a server config.
pub fn print_check_line(warp: Option<Value>) -> Result<()> {
    let cfg: WarpConfig = match warp {
        Some(w) if !w.is_null() => serde_json::from_value(w).map_err(|e| anyhow!("Invalid 'warp' section in server config: {e}"))?,
        _ => WarpConfig::default(),
    };
    if !cfg.enabled {
        println!("  warp: disabled (Cloudflare WARP as this server's exit: ostp warp register --accept-terms, then ostp warp enable)");
        return Ok(());
    }
    cfg.validate()?;
    println!("  warp: enabled, mode {}, proxy {}", cfg.mode.as_str(), cfg.listen);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use ostp_warp::testapi::{FakeApi, FakeApiConfig};
    use serde_json::json;

    fn dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("ostp-warp-cmd-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn write_config(d: &Path, extra: Value) -> std::path::PathBuf {
        let mut v = json!({
            "mode": "server", "config_version": 6, "listen": "0.0.0.0:50000", "access_keys": ["k"],
            "warp": { "enabled": false, "mode": "rules", "listen": "127.0.0.1:40000", "endpoint": "" }
        });
        for (k, x) in extra.as_object().unwrap() {
            v[k] = x.clone();
        }
        let p = d.join("config.json");
        std::fs::write(&p, serde_json::to_string_pretty(&v).unwrap()).unwrap();
        p
    }

    async fn fake() -> FakeApi {
        let b64 = base64::engine::general_purpose::STANDARD;
        FakeApi::start(FakeApiConfig {
            peer_public_b64: b64.encode([5u8; 32]),
            endpoint_host: "engage.invalid:2408".into(),
            client_id: b64.encode([1u8, 2, 3]),
            refuse_license: Some("bad-key".into()),
        })
        .await
        .unwrap()
    }

    fn config(p: &Path) -> Value {
        read_json(p).unwrap()
    }

    #[tokio::test]
    async fn nothing_registers_without_accept_terms() {
        let d = dir("terms");
        let p = write_config(&d, json!({}));
        let api = fake().await;
        let e = register(&p, false, &api.base).await.unwrap_err().to_string();
        assert!(e.contains("--accept-terms"), "{e}");
        assert!(api.requests.lock().unwrap().is_empty(), "no request was made");
        assert!(!store::path_for(&p).exists());
    }

    #[tokio::test]
    async fn register_license_and_reset_against_the_fake_service() {
        let d = dir("reg");
        let p = write_config(&d, json!({}));
        let api = fake().await;
        register(&p, true, &api.base).await.unwrap();
        let st = store::load(&store::path_for(&p)).unwrap().unwrap();
        assert_eq!(st.device_id, "dev-fake-1");
        assert_eq!(st.access_token, "tok-from-the-fake");
        assert_eq!(st.address_v4, "172.16.0.2");
        // The request carried the public half of the key stored here, and the
        // terms stamp; the private half never left.
        {
            let reqs = api.requests.lock().unwrap();
            let r = &reqs[0];
            assert_eq!((r.method.as_str(), r.path.as_str()), ("POST", "/v0a5641/reg"));
            let body: Value = serde_json::from_str(&r.body).unwrap();
            let private = st.private_key_bytes().unwrap();
            let public = ostp_warp::store::encode_key(boringtun_public(&private).as_bytes());
            assert_eq!(body["key"], public);
            assert_eq!(body["tunnel_type"], "wireguard");
            assert!(body["tos"].as_str().unwrap().ends_with('Z'));
            assert!(!r.body.contains(&st.private_key));
        }
        // The keys are not in config.json or its backup.
        assert!(!std::fs::read_to_string(&p).unwrap().contains(&st.private_key));
        // A second registration is refused.
        assert!(register(&p, true, &api.base).await.is_err());
        assert_eq!(api.requests.lock().unwrap().len(), 1);

        // A refused license is not stored; an accepted one is, and the account is re-read.
        assert!(license(&p, "bad-key", &api.base, true).await.is_err());
        assert!(store::load(&store::path_for(&p)).unwrap().unwrap().license.is_none());
        license(&p, "good-key", &api.base, true).await.unwrap();
        let st = store::load(&store::path_for(&p)).unwrap().unwrap();
        assert_eq!(st.license.as_deref(), Some("good-key"));
        assert_eq!(st.account_type.as_deref(), Some("limited"));
        {
            let reqs = api.requests.lock().unwrap();
            let put = reqs.iter().find(|r| r.method == "PUT").unwrap();
            assert_eq!(put.path, "/v0a5641/reg/dev-fake-1/account");
            assert_eq!(put.authorization.as_deref(), Some("Bearer tok-from-the-fake"));
        }

        reset(&p, true).unwrap();
        assert!(!store::path_for(&p).exists());
    }

    fn boringtun_public(private: &[u8; 32]) -> boringtun::x25519::PublicKey {
        boringtun::x25519::PublicKey::from(&boringtun::x25519::StaticSecret::from(*private))
    }

    async fn registered_dir(tag: &str, extra: Value) -> (std::path::PathBuf, FakeApi) {
        let d = dir(tag);
        let p = write_config(&d, extra);
        let api = fake().await;
        register(&p, true, &api.base).await.unwrap();
        (p, api)
    }

    #[tokio::test]
    async fn enable_all_replaces_outbound_and_disable_puts_the_old_one_back() {
        let mine = json!({"enabled": true, "protocol": "socks5", "address": "203.0.113.5", "port": 1080,
            "username": "u", "password": "secret-proxy-pass", "rules": [], "default_action": "direct"});
        let (p, _api) = registered_dir("all", json!({ "outbound": mine })).await;
        enable(&p, WarpMode::All).unwrap();
        let c = config(&p);
        assert_eq!(c["warp"]["enabled"], true);
        assert_eq!(c["warp"]["mode"], "all");
        assert_eq!(c["outbound"]["address"], "127.0.0.1");
        assert_eq!(c["outbound"]["port"], 40000);
        assert_eq!(c["outbound"]["default_action"], "proxy");
        assert_eq!(c["outbound"]["rules"], json!([]));
        assert!(!serde_json::to_string(&c).unwrap().contains("secret-proxy-pass"), "the old proxy's password moved to warp.json");
        let st = store::load(&store::path_for(&p)).unwrap().unwrap();
        assert_eq!(st.saved_outbound.unwrap().section.unwrap(), mine);
        // The backup the config writer made holds the config before this change.
        let bak = std::fs::read_to_string(p.with_extension("json.bak")).unwrap();
        assert!(!bak.contains(&st.private_key));

        // Enabling again keeps the first record, not WARP's own section.
        enable(&p, WarpMode::All).unwrap();
        assert_eq!(store::load(&store::path_for(&p)).unwrap().unwrap().saved_outbound.unwrap().section.unwrap(), mine);

        disable(&p).unwrap();
        let c = config(&p);
        assert_eq!(c["warp"]["enabled"], false);
        assert_eq!(c["outbound"], mine);
        assert!(store::load(&store::path_for(&p)).unwrap().unwrap().saved_outbound.is_none());
    }

    #[tokio::test]
    async fn disable_with_no_earlier_outbound_removes_the_section() {
        let (p, _api) = registered_dir("noold", json!({})).await;
        enable(&p, WarpMode::All).unwrap();
        assert!(config(&p).get("outbound").is_some());
        disable(&p).unwrap();
        assert!(config(&p).get("outbound").is_none());
    }

    #[tokio::test]
    async fn disable_leaves_an_outbound_section_the_operator_changed_since() {
        let (p, _api) = registered_dir("edited", json!({})).await;
        enable(&p, WarpMode::All).unwrap();
        let mut c = config(&p);
        c["outbound"]["address"] = json!("198.51.100.1");
        std::fs::write(&p, serde_json::to_string(&c).unwrap()).unwrap();
        disable(&p).unwrap();
        assert_eq!(config(&p)["outbound"]["address"], "198.51.100.1");
    }

    #[tokio::test]
    async fn enable_rules_keeps_the_rules_and_refuses_when_there_are_none() {
        let (p, _api) = registered_dir("rules-none", json!({})).await;
        let e = enable(&p, WarpMode::Rules).unwrap_err().to_string();
        assert!(e.contains("outbound"), "{e}");
        assert_eq!(config(&p)["warp"]["enabled"], false, "nothing was written");

        let mine = json!({"enabled": false, "protocol": "http", "address": "203.0.113.5", "port": 3128, "username": "", "password": "",
            "rules": [{"domain_suffix": ["example.com"], "action": "proxy"}], "default_action": "direct"});
        let (p, _api) = registered_dir("rules", json!({ "outbound": mine })).await;
        enable(&p, WarpMode::Rules).unwrap();
        let c = config(&p);
        assert_eq!(c["outbound"]["rules"], mine["rules"]);
        assert_eq!(c["outbound"]["default_action"], "direct");
        assert_eq!(c["outbound"]["protocol"], "socks5");
        assert_eq!(c["outbound"]["port"], 40000);
        // all, then rules again: the rules come from what the operator had, not from the all section.
        enable(&p, WarpMode::All).unwrap();
        enable(&p, WarpMode::Rules).unwrap();
        assert_eq!(config(&p)["outbound"]["rules"], mine["rules"]);
        disable(&p).unwrap();
        assert_eq!(config(&p)["outbound"], mine);
    }

    #[tokio::test]
    async fn enable_needs_a_registration_and_reset_needs_disable() {
        let d = dir("needreg");
        let p = write_config(&d, json!({}));
        let e = enable(&p, WarpMode::All).unwrap_err().to_string();
        assert!(e.contains("register"), "{e}");
        let (p, _api) = registered_dir("resetfirst", json!({})).await;
        enable(&p, WarpMode::All).unwrap();
        assert!(reset(&p, true).unwrap_err().to_string().contains("disable"));
        assert!(store::path_for(&p).exists());
    }

    #[test]
    fn warp_json_is_not_world_readable() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let d = dir("perm");
            let p = d.join("warp.json");
            let st = WarpState::from_device(
                store::encode_key(&[1u8; 32]),
                &serde_json::from_str(r#"{"id":"d","token":"t","config":{"interface":{"addresses":{"v4":"1.2.3.4"}},"peers":[{"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","endpoint":{}}]}}"#).unwrap(),
                "t".into(),
            )
            .unwrap();
            store::save(&p, &st).unwrap();
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }
}
