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
        let accept_json = req
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("accept"))
            .and_then(|h| std::str::from_utf8(h.value).ok())
            .is_some_and(|v| v.contains("application/json"));
        let json = accept_json || query.split('&').any(|kv| kv == "format=json");
        Some(Request { token: token.to_ascii_lowercase(), json, head_only })
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
        let owndns = self.dns.config.read().await.enabled;
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
            dns: crate::dns::DnsServer::new(Default::default()),
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
        let body = resp.split("\r\n\r\n").nth(1).unwrap();
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
        let doc = SubscriptionDoc::parse(resp.split("\r\n\r\n").nth(1).unwrap()).unwrap();
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

    #[test]
    fn header_text_is_ascii_safe() {
        assert_eq!(header_text("vpn"), "vpn");
        assert!(header_text("впн").starts_with("base64:"));
    }
}
