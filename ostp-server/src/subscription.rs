//! `GET <prefix>/<token>`: one user's current links, so clients follow
//! server-side changes without being handed a new link.
//!
//! Served by the sniffing listener, only over TLS or from a local web server
//! that terminated TLS: the token is a credential and must not travel in
//! clear. Unknown tokens get the same decoy as any other path.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use ostp_core::share_link::{LinkTransport, ShareLink};
use ostp_core::subscription::{token_for_key, SubscriptionDoc, SubscriptionUsage};
use subtle::ConstantTimeEq;

use crate::api::{TlsLink, UserMeta};
use crate::dispatcher::UserStats;

/// Resolved `subscription` section.
#[derive(Debug, Clone)]
pub struct SubscriptionSettings {
    /// e.g. "/sub"
    pub prefix: String,
    pub name: String,
    pub update_interval_hours: u32,
    pub include_tls: bool,
    pub include_udp: bool,
}

pub struct SubscriptionService {
    pub settings: SubscriptionSettings,
    pub tls: Option<TlsLink>,
    /// Host and port of the plain UDP link.
    pub udp: (String, u16),
    pub dns: Arc<crate::dns::DnsServer>,
    pub keys: Arc<RwLock<HashMap<String, UserMeta>>>,
    pub stats: Arc<RwLock<HashMap<String, Arc<UserStats>>>>,
}

/// What the request asked for.
struct Request {
    token: String,
    json: bool,
    /// A browser (Accept: text/html): a person opened the link, not an app.
    html: bool,
    /// Accept-Language prefers Russian.
    ru: bool,
    head_only: bool,
}

impl SubscriptionService {
    /// Whether the request path is under our prefix at all (cheap check
    /// before a full parse).
    pub fn wants(&self, path: &str) -> bool {
        path.strip_prefix(self.settings.prefix.as_str()).is_some_and(|r| r.starts_with('/'))
    }

    fn parse(&self, head: &[u8]) -> Option<Request> {
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut req = httparse::Request::new(&mut headers);
        if !matches!(req.parse(head), Ok(httparse::Status::Complete(_))) {
            return None;
        }
        let head_only = match req.method? {
            "GET" => false,
            "HEAD" => true,
            _ => return None,
        };
        let (path, query) = req.path?.split_once('?').unwrap_or((req.path?, ""));
        let token = path.strip_prefix(self.settings.prefix.as_str())?.strip_prefix('/')?;
        if token.len() != 32 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let header = |name: &str| {
            req.headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case(name))
                .and_then(|h| std::str::from_utf8(h.value).ok())
                .unwrap_or("")
                .to_ascii_lowercase()
        };
        let accept = header("accept");
        let json = accept.contains("application/json") || query.split('&').any(|kv| kv == "format=json");
        let html = !json && accept.contains("text/html");
        let ru = prefers_russian(&header("accept-language"));
        Some(Request { token: token.to_ascii_lowercase(), json, html, ru, head_only })
    }

    /// The access key a token belongs to. Every key is checked so the time
    /// taken does not depend on where (or whether) the match is.
    fn key_for(&self, token: &str) -> Option<String> {
        let keys = self.keys.read().unwrap_or_else(|e| e.into_inner());
        let mut found = None;
        for key in keys.keys() {
            if bool::from(token_for_key(key).as_bytes().ct_eq(token.as_bytes())) {
                found = Some(key.clone());
            }
        }
        found
    }

    pub async fn document(&self, key: &str) -> SubscriptionDoc {
        let owndns = self.dns.enabled();
        let user = self
            .keys
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(key)
            .and_then(|m| m.name.clone())
            .filter(|n| !n.is_empty());
        let title = |kind: &str| match &user {
            Some(u) => format!("{} · {u} · {kind}", self.settings.name),
            None => format!("{} · {kind}", self.settings.name),
        };

        let mut links = Vec::new();
        if let (true, Some(t)) = (self.settings.include_tls, &self.tls) {
            let mut l = ShareLink::new(key, &t.host, t.port);
            l.transport = LinkTransport::Uot;
            l.tls = true;
            l.path = t.path.clone();
            l.owndns = owndns;
            l.name = Some(title("TLS"));
            links.push(l.to_uri());
        }
        if self.settings.include_udp {
            let mut l = ShareLink::new(key, &self.udp.0, self.udp.1);
            l.owndns = owndns;
            l.name = Some(title("UDP"));
            links.push(l.to_uri());
        }

        let usage = self.stats.read().unwrap_or_else(|e| e.into_inner()).get(key).map(|s| SubscriptionUsage {
            used_bytes: s.bytes_up.load(std::sync::atomic::Ordering::Relaxed)
                + s.bytes_down.load(std::sync::atomic::Ordering::Relaxed),
            limit_bytes: s.limit_bytes,
        });
        SubscriptionDoc {
            name: self.settings.name.clone(),
            update_interval_hours: self.settings.update_interval_hours,
            links,
            usage,
        }
    }

    /// A complete HTTP response, or `None` when the request is not a valid
    /// subscription fetch (the caller then serves the decoy).
    pub async fn respond(&self, head: &[u8]) -> Option<Vec<u8>> {
        let req = self.parse(head)?;
        let key = self.key_for(&req.token)?;
        let doc = self.document(&key).await;

        let (content_type, body) = if req.json {
            ("application/json", serde_json::to_string(&doc).ok()?)
        } else if req.html {
            ("text/html; charset=utf-8", self.page(&doc, &req.token, req.ru))
        } else {
            ("text/plain; charset=utf-8", doc.links.join("\n") + "\n")
        };
        let mut out = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\n\
             Profile-Update-Interval: {}\r\nProfile-Title: {}\r\n",
            body.len(),
            doc.update_interval_hours,
            header_text(&doc.name),
        );
        if req.html {
            out.push_str(
                "X-Robots-Tag: noindex, nofollow\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\n\
                 X-Frame-Options: DENY\r\nContent-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; \
                 script-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\n",
            );
        }
        if let Some(u) = &doc.usage {
            out.push_str(&format!(
                "Subscription-Userinfo: upload=0; download={}; total={}; expire=0\r\n",
                u.used_bytes,
                u.limit_bytes.unwrap_or(0)
            ));
        }
        out.push_str("Connection: close\r\n\r\n");
        let mut out = out.into_bytes();
        if !req.head_only {
            out.extend_from_slice(body.as_bytes());
        }
        Some(out)
    }
}

impl SubscriptionService {
    /// The subscription's own address, as a person would paste it.
    fn url(&self, token: &str) -> String {
        match &self.tls {
            Some(t) => {
                let port = if t.port == 443 { String::new() } else { format!(":{}", t.port) };
                format!("https://{}{port}{}/{token}", t.host, self.settings.prefix)
            }
            None => format!("{}/{token}", self.settings.prefix),
        }
    }

    /// The page a person sees when they open the subscription in a browser:
    /// what it is, how to connect, the QR code, both languages.
    fn page(&self, doc: &SubscriptionDoc, token: &str, ru: bool) -> String {
        let url = self.url(token);
        let qr = qrcode::QrCode::new(url.as_bytes())
            .map(|c| {
                c.render::<qrcode::render::svg::Color>()
                    .min_dimensions(176, 176)
                    .dark_color(qrcode::render::svg::Color("#000000"))
                    .light_color(qrcode::render::svg::Color("#ffffff"))
                    .build()
            })
            .unwrap_or_default();
        // Drop the XML prolog: the SVG is inlined into HTML.
        let qr = match qr.find("<svg") {
            Some(i) => qr[i..].to_string(),
            None => qr,
        };

        let usage = match &doc.usage {
            Some(u) => {
                let (limit_en, limit_ru, bar) = match u.limit_bytes.filter(|l| *l > 0) {
                    Some(l) => {
                        let pct = (u.used_bytes as f64 / l as f64 * 100.0).min(100.0);
                        (
                            format!("of {}", fmt_bytes(l)),
                            format!("из {}", fmt_bytes(l)),
                            format!("<div class=\"bar\"><div style=\"width:{pct:.1}%\"></div></div>"),
                        )
                    }
                    None => ("no limit".into(), "без лимита".into(), String::new()),
                };
                format!(
                    "<section class=\"card\"><h2><span lang=\"ru\">Трафик</span><span lang=\"en\">Traffic</span></h2>\
                     <div class=\"usage-row\"><span><span lang=\"ru\">Использовано</span><span lang=\"en\">Used</span>: <b>{used}</b></span>\
                     <span class=\"muted\"><span lang=\"ru\">{limit_ru}</span><span lang=\"en\">{limit_en}</span></span></div>{bar}</section>",
                    used = fmt_bytes(u.used_bytes),
                )
            }
            None => String::new(),
        };

        let links: String = doc
            .links
            .iter()
            .enumerate()
            .map(|(i, l)| {
                let kind = match ShareLink::parse(l) {
                    Ok(s) if s.tls => "TLS",
                    Ok(s) if s.transport == LinkTransport::Uot => "TCP",
                    _ => "UDP",
                };
                format!(
                    "<div class=\"link-row\"><div class=\"muted\">{kind}</div><div class=\"copy\">\
                     <input id=\"link-{i}\" readonly value=\"{v}\" aria-label=\"{kind}\">\
                     <button class=\"btn\" type=\"button\" data-copy=\"link-{i}\"><span lang=\"ru\">Копировать</span><span lang=\"en\">Copy</span></button></div></div>",
                    v = html_escape(l)
                )
            })
            .collect();

        let name = if doc.name.is_empty() { "OSTP".to_string() } else { doc.name.clone() };
        include_str!("subscription_page.html")
            .replace("{{LANG}}", if ru { "ru" } else { "en" })
            .replace("{{RU_PRESSED}}", if ru { "true" } else { "false" })
            .replace("{{EN_PRESSED}}", if ru { "false" } else { "true" })
            .replace("{{NAME}}", &html_escape(&name))
            .replace("{{INTERVAL}}", &doc.update_interval_hours.to_string())
            .replace("{{USAGE}}", &usage)
            .replace("{{LINKS}}", &links)
            .replace("{{QR}}", &qr)
            .replace("{{SUB_URL}}", &html_escape(&url))
    }
}

/// Whether Accept-Language ranks Russian above English (by q, then order).
/// Neither listed: English.
fn prefers_russian(accept_language: &str) -> bool {
    let mut best: Option<(f32, usize, bool)> = None;
    for (i, part) in accept_language.split(',').enumerate() {
        let mut it = part.split(';');
        let tag = it.next().unwrap_or("").trim().to_ascii_lowercase();
        let q = it
            .find_map(|p| p.trim().strip_prefix("q=").and_then(|v| v.trim().parse::<f32>().ok()))
            .unwrap_or(1.0);
        let is_ru = tag == "ru" || tag.starts_with("ru-");
        if !(is_ru || tag == "en" || tag.starts_with("en-")) || q <= 0.0 {
            continue;
        }
        let better = match best {
            None => true,
            Some((bq, bi, _)) => q > bq || (q == bq && i < bi),
        };
        if better {
            best = Some((q, i, is_ru));
        }
    }
    best.is_some_and(|(_, _, ru)| ru)
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}

fn fmt_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 { format!("{n} B") } else { format!("{v:.1} {}", UNITS[i]) }
}

/// Header-safe title: plain ASCII as is, anything else as `base64:...`,
/// the form subscription clients already understand.
fn header_text(s: &str) -> String {
    if s.bytes().all(|b| (0x20..0x7f).contains(&b)) {
        s.to_string()
    } else {
        use base64::Engine;
        format!("base64:{}", base64::engine::general_purpose::STANDARD.encode(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service() -> SubscriptionService {
        let mut keys = HashMap::new();
        keys.insert("key-a".to_string(), UserMeta { name: Some("alice".into()), limit_bytes: Some(1000) });
        keys.insert("key-b".to_string(), UserMeta { name: None, limit_bytes: None });
        let stats = HashMap::from([("key-a".to_string(), Arc::new(UserStats::new(Some(1000))))]);
        stats["key-a"].bytes_up.store(10, std::sync::atomic::Ordering::Relaxed);
        stats["key-a"].bytes_down.store(32, std::sync::atomic::Ordering::Relaxed);
        SubscriptionService {
            settings: SubscriptionSettings {
                prefix: "/sub".into(),
                name: "vpn.example.com".into(),
                update_interval_hours: 6,
                include_tls: true,
                include_udp: true,
            },
            tls: Some(TlsLink { host: "vpn.example.com".into(), port: 443, path: Some("/s3cr3tpath".into()) }),
            udp: ("vpn.example.com".into(), 50000),
            dns: crate::dns::DnsServer::new(Default::default(), None),
            keys: Arc::new(RwLock::new(keys)),
            stats: Arc::new(RwLock::new(stats)),
        }
    }

    fn get(path: &str, accept: &str) -> Vec<u8> {
        format!("GET {path} HTTP/1.1\r\nHost: vpn.example.com\r\nAccept: {accept}\r\n\r\n").into_bytes()
    }

    #[tokio::test]
    async fn serves_links_for_a_known_token() {
        let svc = service();
        let resp = svc.respond(&get(&format!("/sub/{}", token_for_key("key-a")), "*/*")).await.unwrap();
        let resp = String::from_utf8(resp).unwrap();
        assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"), "{resp}");
        assert!(resp.contains("Profile-Update-Interval: 6\r\n"));
        assert!(resp.contains("Subscription-Userinfo: upload=0; download=42; total=1000; expire=0\r\n"));
        let body = resp.splitn(2, "\r\n\r\n").nth(1).unwrap();
        let doc = SubscriptionDoc::parse(body).unwrap();
        let links = doc.valid_links();
        assert_eq!(links.len(), 2);
        assert!(links[0].tls && links[0].port == 443 && links[0].path.as_deref() == Some("/s3cr3tpath"));
        assert_eq!(links[0].key, "key-a");
        assert!(links[0].name.as_deref().unwrap().contains("alice"));
        assert!(!links[1].tls && links[1].port == 50000);
    }

    #[tokio::test]
    async fn json_form_carries_usage() {
        let svc = service();
        let path = format!("/sub/{}?format=json", token_for_key("key-a"));
        let resp = String::from_utf8(svc.respond(&get(&path, "*/*")).await.unwrap()).unwrap();
        assert!(resp.contains("Content-Type: application/json"));
        let doc = SubscriptionDoc::parse(resp.splitn(2, "\r\n\r\n").nth(1).unwrap()).unwrap();
        assert_eq!(doc.usage, Some(SubscriptionUsage { used_bytes: 42, limit_bytes: Some(1000) }));
        assert_eq!(doc.update_interval_hours, 6);
    }

    #[tokio::test]
    async fn unknown_tokens_and_other_requests_are_refused() {
        let svc = service();
        assert!(svc.respond(&get(&format!("/sub/{}", token_for_key("nope")), "*/*")).await.is_none());
        assert!(svc.respond(&get("/sub/key-a", "*/*")).await.is_none());
        assert!(svc.respond(&get(&format!("/other/{}", token_for_key("key-a")), "*/*")).await.is_none());
        let post = format!("POST /sub/{} HTTP/1.1\r\n\r\n", token_for_key("key-a"));
        assert!(svc.respond(post.as_bytes()).await.is_none());
    }

    #[tokio::test]
    async fn include_filters_link_kinds() {
        let mut svc = service();
        svc.settings.include_udp = false;
        let doc = svc.document("key-b").await;
        assert_eq!(doc.links.len(), 1);
        assert!(doc.links[0].contains("tls=1"));
        assert_eq!(doc.usage, None);
    }

    #[tokio::test]
    async fn a_browser_gets_the_page_and_apps_do_not() {
        let svc = service();
        let path = format!("/sub/{}", token_for_key("key-a"));
        let browser = format!(
            "GET {path} HTTP/1.1\r\nHost: vpn.example.com\r\nAccept: text/html,application/xhtml+xml,*/*;q=0.8\r\nAccept-Language: ru-RU,ru;q=0.9\r\n\r\n"
        );
        let resp = String::from_utf8(svc.respond(browser.as_bytes()).await.unwrap()).unwrap();
        assert!(resp.contains("Content-Type: text/html"));
        assert!(resp.contains("Content-Security-Policy: default-src 'none'"));
        assert!(resp.contains("X-Robots-Tag: noindex"));
        let body = resp.splitn(2, "\r\n\r\n").nth(1).unwrap();
        assert!(body.contains("<html lang=\"ru\">"));
        let want = format!("value=\"https://vpn.example.com/sub/{}\"", token_for_key("key-a"));
        assert!(body.contains(&want), "{want} not in: {}", body.lines().find(|l| l.contains("sub-url")).unwrap_or("<no sub-url line>"));
        assert!(body.contains("<svg"));
        assert!(body.contains("github.com/ospab/ostp"));
        assert!(body.contains("из 1000 B") || body.contains("из 1000"));
        assert!(!body.contains("{{"), "every placeholder is filled");

        // Apps and subscription managers keep getting links.
        let app = format!("GET {path} HTTP/1.1\r\nAccept: */*\r\n\r\n");
        let resp = String::from_utf8(svc.respond(app.as_bytes()).await.unwrap()).unwrap();
        assert!(resp.contains("Content-Type: text/plain"));
        let json = format!("GET {path} HTTP/1.1\r\nAccept: application/json, text/html\r\n\r\n");
        let resp = String::from_utf8(svc.respond(json.as_bytes()).await.unwrap()).unwrap();
        assert!(resp.contains("Content-Type: application/json"));
    }

    #[test]
    fn language_follows_accept_language_priorities() {
        assert!(prefers_russian("ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7"));
        assert!(!prefers_russian("en-US,en;q=0.9,ru;q=0.8"));
        assert!(prefers_russian("uk-UA,uk;q=0.9,ru;q=0.8,en;q=0.7"));
        assert!(prefers_russian("en;q=0.5, ru;q=0.9"));
        assert!(!prefers_russian("de-DE,de;q=0.9"));
        assert!(!prefers_russian(""));
        assert!(!prefers_russian("ru;q=0, en"));
    }

    #[test]
    fn page_escapes_the_title() {
        assert_eq!(html_escape("<b>\"x\"</b>"), "&lt;b&gt;&quot;x&quot;&lt;/b&gt;");
    }

    #[test]
    fn header_text_is_ascii_safe() {
        assert_eq!(header_text("vpn"), "vpn");
        assert!(header_text("впн").starts_with("base64:"));
    }
}
