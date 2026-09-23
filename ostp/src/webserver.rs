//! Puts OSTP behind an existing nginx / apache / caddy on 443: a vhost for
//! the OSTP domain whose secret path is upgraded and proxied to OSTP, whose
//! /{webpath}/ reaches the panel, and whose /.well-known/acme-challenge/ is
//! answered by OSTP's ACME responder. Every change is backed up, checked with
//! the server's own config test, reloaded, and rolled back if either fails.

use anyhow::{anyhow, bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

const HEADER: &str = "# Managed by ostp (ostp cert issue). Removed by `ostp uninstall`.";
const CADDY_BEGIN: &str = "# BEGIN ostp (managed by ostp, removed by `ostp uninstall`)";
const CADDY_END: &str = "# END ostp";
const CADDY_DIR: &str = "/etc/caddy/ostp.d";
const CADDYFILE: &str = "/etc/caddy/Caddyfile";

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Nginx,
    Apache,
    Caddy,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Nginx => "nginx",
            Kind::Apache => "apache",
            Kind::Caddy => "caddy",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "nginx" => Some(Kind::Nginx),
            "apache" | "apache2" | "httpd" => Some(Kind::Apache),
            "caddy" => Some(Kind::Caddy),
            _ => None,
        }
    }
}

/// What the vhost routes where.
pub struct VhostParams {
    pub domain: String,
    pub ws_path: String,
    /// OSTP's own TCP port, reached over loopback.
    pub ostp_port: u16,
    /// (webpath without slashes, API address) when the panel is enabled.
    pub panel: Option<(String, String)>,
    /// OSTP's local ACME responder (nginx/apache only).
    pub responder: String,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

/// What was changed, so `ostp uninstall` can take it back out.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct Manifest {
    pub kind: Option<Kind>,
    pub files_created: Vec<PathBuf>,
    /// Apache site enabled with a2ensite.
    pub site: Option<String>,
    /// The Caddyfile got an import block.
    pub caddy_import: bool,
}

pub fn manifest_path(config_dir: &Path) -> PathBuf {
    config_dir.join("webserver.json")
}

fn run(cmd: &str, args: &[&str]) -> Result<std::process::Output> {
    Command::new(cmd).args(args).output().with_context(|| format!("cannot run {cmd}"))
}

fn run_ok(cmd: &str, args: &[&str]) -> Result<()> {
    let out = run(cmd, args)?;
    if out.status.success() {
        return Ok(());
    }
    bail!(
        "`{cmd} {}` failed:\n{}{}",
        args.join(" "),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn have(cmd: &str, arg: &str) -> bool {
    Command::new(cmd).arg(arg).output().map(|o| o.status.success()).unwrap_or(false)
}

fn apache_ctl() -> Option<&'static str> {
    ["apache2ctl", "apachectl", "httpd"].into_iter().find(|c| have(c, "-v"))
}

/// Web servers installed on this machine.
pub fn detect() -> Vec<Kind> {
    if !cfg!(unix) {
        return Vec::new();
    }
    let mut found = Vec::new();
    if have("nginx", "-v") {
        found.push(Kind::Nginx);
    }
    if apache_ctl().is_some() {
        found.push(Kind::Apache);
    }
    if have("caddy", "version") {
        found.push(Kind::Caddy);
    }
    found
}

pub fn reload_command(kind: Kind) -> String {
    match kind {
        Kind::Nginx => "systemctl reload nginx || nginx -s reload".into(),
        Kind::Apache => {
            if Path::new("/etc/apache2").exists() {
                "systemctl reload apache2 || apache2ctl graceful".into()
            } else {
                "systemctl reload httpd || apachectl graceful".into()
            }
        }
        Kind::Caddy => format!("systemctl reload caddy || caddy reload --config {CADDYFILE} --adapter caddyfile"),
    }
}

fn reload(kind: Kind) -> Result<()> {
    run_ok("sh", &["-c", &reload_command(kind)])
}

fn config_test(kind: Kind) -> Result<()> {
    match kind {
        Kind::Nginx => run_ok("nginx", &["-t"]),
        Kind::Apache => run_ok(apache_ctl().ok_or_else(|| anyhow!("apachectl not found"))?, &["configtest"]),
        Kind::Caddy => run_ok("caddy", &["validate", "--config", CADDYFILE, "--adapter", "caddyfile"]),
    }
}

fn has_ipv6() -> bool {
    Path::new("/proc/net/if_inet6").exists()
}

pub fn nginx_vhost(p: &VhostParams, ipv6: bool) -> String {
    let v6 = |port: &str, extra: &str| if ipv6 { format!("    listen [::]:{port}{extra};\n") } else { String::new() };
    let panel = p
        .panel
        .as_ref()
        .map(|(webpath, api)| {
            format!(
                "    location ^~ /{webpath}/ {{\n        proxy_pass http://{api};\n        proxy_set_header Host $host;\n        \
                 proxy_set_header X-Real-IP $remote_addr;\n        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n    }}\n"
            )
        })
        .unwrap_or_default();
    format!(
        "{HEADER}\n\
server {{\n    listen 80;\n{v6_80}    server_name {domain};\n\n    \
location ^~ /.well-known/acme-challenge/ {{\n        proxy_pass http://{responder};\n        proxy_set_header Host $host;\n    }}\n    \
location / {{\n        return 301 https://$host$request_uri;\n    }}\n}}\n\n\
server {{\n    listen 443 ssl;\n{v6_443}    server_name {domain};\n\n    \
ssl_certificate {cert};\n    ssl_certificate_key {key};\n    ssl_protocols TLSv1.2 TLSv1.3;\n\n    \
location = {ws_path} {{\n        proxy_pass http://127.0.0.1:{port};\n        proxy_http_version 1.1;\n        \
proxy_set_header Upgrade $http_upgrade;\n        proxy_set_header Connection \"upgrade\";\n        proxy_set_header Host $host;\n        \
proxy_set_header X-Real-IP $remote_addr;\n        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n        \
proxy_buffering off;\n        proxy_read_timeout 1d;\n        proxy_send_timeout 1d;\n    }}\n\
{panel}    location / {{\n        return 404;\n    }}\n}}\n",
        v6_80 = v6("80", ""),
        v6_443 = v6("443", " ssl"),
        domain = p.domain,
        responder = p.responder,
        cert = p.cert_path.display(),
        key = p.key_path.display(),
        ws_path = p.ws_path,
        port = p.ostp_port,
    )
}

/// `upgrade=websocket` on ProxyPass needs Apache 2.4.47+; older ones tunnel
/// through mod_proxy_wstunnel with a ws:// target instead.
pub fn apache_vhost(p: &VhostParams, modern: bool) -> String {
    let ws = if modern {
        format!("    ProxyPass {0} http://127.0.0.1:{1}{0} upgrade=websocket timeout=86400\n", p.ws_path, p.ostp_port)
    } else {
        format!("    ProxyPass {0} ws://127.0.0.1:{1}{0} timeout=86400\n", p.ws_path, p.ostp_port)
    };
    let panel = p
        .panel
        .as_ref()
        .map(|(webpath, api)| {
            format!("    ProxyPass /{webpath}/ http://{api}/{webpath}/\n    ProxyPassReverse /{webpath}/ http://{api}/{webpath}/\n")
        })
        .unwrap_or_default();
    format!(
        "{HEADER}\n\
<VirtualHost *:80>\n    ServerName {domain}\n    \
ProxyPass /.well-known/acme-challenge/ http://{responder}/.well-known/acme-challenge/\n    \
RedirectMatch 301 ^/(?!\\.well-known/acme-challenge/)(.*)$ https://{domain}/$1\n</VirtualHost>\n\n\
<VirtualHost *:443>\n    ServerName {domain}\n    SSLEngine on\n    SSLCertificateFile {cert}\n    SSLCertificateKeyFile {key}\n    \
ProxyPreserveHost On\n{ws}{panel}</VirtualHost>\n",
        domain = p.domain,
        responder = p.responder,
        cert = p.cert_path.display(),
        key = p.key_path.display(),
    )
}

/// Caddy manages the certificate and the http->https redirect itself.
pub fn caddy_site(p: &VhostParams) -> String {
    let panel = p
        .panel
        .as_ref()
        .map(|(webpath, api)| format!("    handle /{webpath}/* {{\n        reverse_proxy {api}\n    }}\n"))
        .unwrap_or_default();
    format!(
        "{HEADER}\n{domain} {{\n    handle {ws_path} {{\n        reverse_proxy 127.0.0.1:{port}\n    }}\n{panel}    handle {{\n        respond 404\n    }}\n}}\n",
        domain = p.domain,
        ws_path = p.ws_path,
        port = p.ostp_port,
    )
}

fn apache_is_modern(ctl: &str) -> bool {
    let Ok(out) = run(ctl, &["-v"]) else { return true };
    let text = String::from_utf8_lossy(&out.stdout);
    let Some(ver) = text.split("Apache/").nth(1).and_then(|v| v.split_whitespace().next()) else { return true };
    let n: Vec<u32> = ver.split('.').filter_map(|x| x.parse().ok()).collect();
    matches!(n.as_slice(), [2, 4, patch, ..] if *patch >= 47) || n.first().is_some_and(|m| *m > 2)
}

/// Undo record for one install attempt.
#[derive(Default)]
struct Changes {
    created: Vec<PathBuf>,
    /// (path, original contents) of files that were modified.
    modified: Vec<(PathBuf, Vec<u8>)>,
    site: Option<String>,
}

impl Changes {
    fn write(&mut self, path: &Path, contents: &str) -> Result<()> {
        match std::fs::read(path) {
            Ok(old) => {
                let backup = path.with_extension(format!(
                    "{}.ostp-bak",
                    path.extension().and_then(|e| e.to_str()).unwrap_or("conf")
                ));
                std::fs::write(&backup, &old).with_context(|| format!("cannot back up {}", path.display()))?;
                self.modified.push((path.to_path_buf(), old));
            }
            Err(_) => self.created.push(path.to_path_buf()),
        }
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(path, contents).with_context(|| format!("cannot write {}", path.display()))
    }

    fn rollback(&self) {
        if let Some(site) = &self.site {
            let _ = run("a2dissite", &[site]);
        }
        for p in &self.created {
            let _ = std::fs::remove_file(p);
        }
        for (p, old) in &self.modified {
            let _ = std::fs::write(p, old);
        }
    }
}

/// Installs the vhost and returns the command that reloads the web server.
pub fn install(kind: Kind, p: &VhostParams, config_dir: &Path) -> Result<String> {
    if !cfg!(unix) {
        bail!("web-server integration is only supported on Linux");
    }
    let mut ch = Changes::default();
    let mut manifest = Manifest { kind: Some(kind), ..Default::default() };

    let result = (|| -> Result<()> {
        match kind {
            Kind::Nginx => {
                let dir = Path::new("/etc/nginx/conf.d");
                if !dir.is_dir() {
                    bail!("/etc/nginx/conf.d not found; add this to your nginx config by hand:\n\n{}", nginx_vhost(p, has_ipv6()));
                }
                ch.write(&dir.join(format!("ostp-{}.conf", p.domain)), &nginx_vhost(p, has_ipv6()))?;
            }
            Kind::Apache => {
                let ctl = apache_ctl().ok_or_else(|| anyhow!("apachectl not found"))?;
                let text = apache_vhost(p, apache_is_modern(ctl));
                if Path::new("/etc/apache2/sites-available").is_dir() {
                    let _ = run_ok("a2enmod", &["-q", "ssl", "proxy", "proxy_http", "proxy_wstunnel"]);
                    let site = format!("ostp-{}", p.domain);
                    ch.write(&PathBuf::from(format!("/etc/apache2/sites-available/{site}.conf")), &text)?;
                    run_ok("a2ensite", &["-q", &site])?;
                    ch.site = Some(site);
                } else if Path::new("/etc/httpd/conf.d").is_dir() {
                    ch.write(&PathBuf::from(format!("/etc/httpd/conf.d/ostp-{}.conf", p.domain)), &text)?;
                } else {
                    bail!("unknown Apache layout; add this to your Apache config by hand:\n\n{text}");
                }
            }
            Kind::Caddy => {
                let caddyfile = std::fs::read_to_string(CADDYFILE)
                    .with_context(|| format!("{CADDYFILE} not found (caddy run from JSON/API is not supported); add this by hand:\n\n{}", caddy_site(p)))?;
                ch.write(&Path::new(CADDY_DIR).join(format!("{}.caddy", p.domain)), &caddy_site(p))?;
                if !caddyfile.contains(CADDY_BEGIN) {
                    let block = format!("\n{CADDY_BEGIN}\nimport {CADDY_DIR}/*.caddy\n{CADDY_END}\n");
                    ch.write(Path::new(CADDYFILE), &format!("{}{block}", caddyfile.trim_end()))?;
                    manifest.caddy_import = true;
                }
            }
        }
        config_test(kind)?;
        reload(kind)?;
        Ok(())
    })();

    if let Err(e) = result {
        ch.rollback();
        let _ = reload(kind);
        return Err(e.context(format!("{} was left as it was", kind.as_str())));
    }

    manifest.files_created = ch.created.clone();
    manifest.site = ch.site.clone();
    let path = manifest_path(config_dir);
    std::fs::write(&path, serde_json::to_vec_pretty(&manifest)?)
        .with_context(|| format!("cannot write {}", path.display()))?;
    Ok(reload_command(kind))
}

/// Best-effort removal of whatever `install` added; never fails the caller.
#[cfg_attr(not(unix), allow(dead_code))]
pub fn uninstall(config_dir: &Path) {
    let path = manifest_path(config_dir);
    let Ok(data) = std::fs::read(&path) else { return };
    let Ok(m) = serde_json::from_slice::<Manifest>(&data) else { return };
    if let Some(site) = &m.site {
        let _ = run("a2dissite", &["-q", site]);
    }
    for f in &m.files_created {
        let _ = std::fs::remove_file(f);
    }
    if m.caddy_import {
        if let Ok(text) = std::fs::read_to_string(CADDYFILE) {
            if let (Some(a), Some(b)) = (text.find(CADDY_BEGIN), text.find(CADDY_END)) {
                if a < b {
                    let cleaned = format!("{}{}", &text[..a], &text[b + CADDY_END.len()..]);
                    let _ = std::fs::write(CADDYFILE, cleaned.trim_end().to_string() + "\n");
                }
            }
        }
    }
    if let Some(kind) = m.kind {
        if config_test(kind).is_ok() {
            let _ = reload(kind);
        }
        println!("  Removed the OSTP site from {}.", kind.as_str());
    }
    let _ = std::fs::remove_file(path);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(panel: bool) -> VhostParams {
        VhostParams {
            domain: "vpn.example.com".into(),
            ws_path: "/Xk3pQ9aZr2".into(),
            ostp_port: 50000,
            panel: panel.then(|| ("wp".to_string(), "127.0.0.1:9090".to_string())),
            responder: "127.0.0.1:50080".into(),
            cert_path: "/etc/ostp/certs/vpn.example.com/fullchain.pem".into(),
            key_path: "/etc/ostp/certs/vpn.example.com/privkey.pem".into(),
        }
    }

    #[test]
    fn nginx_routes_upgrade_panel_and_challenges() {
        let v = nginx_vhost(&params(true), true);
        assert!(v.contains("location = /Xk3pQ9aZr2 {"));
        assert!(v.contains("proxy_pass http://127.0.0.1:50000;"));
        assert!(v.contains("proxy_set_header Connection \"upgrade\";"));
        assert!(v.contains("location ^~ /wp/ {"));
        assert!(v.contains("proxy_pass http://127.0.0.1:50080;"));
        assert!(v.contains("listen [::]:443 ssl;"));
        assert!(v.contains("ssl_certificate /etc/ostp/certs/vpn.example.com/fullchain.pem;"));
        assert!(!nginx_vhost(&params(false), false).contains("[::]"));
        assert!(!nginx_vhost(&params(false), false).contains("/wp/"));
    }

    #[test]
    fn apache_uses_upgrade_or_wstunnel_by_version() {
        let modern = apache_vhost(&params(true), true);
        assert!(modern.contains("ProxyPass /Xk3pQ9aZr2 http://127.0.0.1:50000/Xk3pQ9aZr2 upgrade=websocket"));
        assert!(modern.contains("ProxyPass /wp/ http://127.0.0.1:9090/wp/"));
        assert!(modern.contains("ProxyPass /.well-known/acme-challenge/ http://127.0.0.1:50080/.well-known/acme-challenge/"));
        let old = apache_vhost(&params(false), false);
        assert!(old.contains("ProxyPass /Xk3pQ9aZr2 ws://127.0.0.1:50000/Xk3pQ9aZr2"));
    }

    #[test]
    fn caddy_uses_exclusive_handle_blocks() {
        let c = caddy_site(&params(true));
        assert!(c.contains("vpn.example.com {"));
        assert!(c.contains("handle /Xk3pQ9aZr2 {\n        reverse_proxy 127.0.0.1:50000"));
        assert!(c.contains("handle /wp/* {"));
        assert!(c.contains("handle {\n        respond 404"));
    }
}
