//! Subscription documents: what `https://<domain><path>/<token>` returns, and
//! the token that addresses one access key without putting the key itself in
//! URLs (and so in web-server access logs).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::share_link::ShareLink;

/// The URL token for an access key: 32 hex characters, stable, one-way.
pub fn token_for_key(access_key: &str) -> String {
    let digest = Sha256::digest(format!("ostp-subscription:{access_key}").as_bytes());
    digest[..16].iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionUsage {
    /// Traffic used so far (both directions).
    pub used_bytes: u64,
    pub limit_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionDoc {
    /// Title shown in apps (the server's name or domain).
    #[serde(default)]
    pub name: String,
    /// How often clients should fetch the document again.
    #[serde(default = "default_interval")]
    pub update_interval_hours: u32,
    /// `ostp://` links, best first.
    #[serde(default)]
    pub links: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<SubscriptionUsage>,
}

fn default_interval() -> u32 {
    12
}

impl SubscriptionDoc {
    /// Accepts the JSON form, or a plain list of links (one per line,
    /// optionally base64-encoded as a whole, as other subscription formats do).
    pub fn parse(body: &str) -> anyhow::Result<Self> {
        let body = body.trim_start_matches('\u{feff}').trim();
        if body.starts_with('{') {
            let doc: SubscriptionDoc = serde_json::from_str(body)?;
            return Ok(doc);
        }
        let text = if body.contains("ostp://") {
            body.to_string()
        } else {
            use base64::Engine;
            let compact: String = body.split_whitespace().collect();
            let raw = base64::engine::general_purpose::STANDARD
                .decode(&compact)
                .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(compact.trim_end_matches('=')))
                .map_err(|_| anyhow::anyhow!("not a subscription: no ostp:// links in the response"))?;
            String::from_utf8(raw).map_err(|_| anyhow::anyhow!("not a subscription: the response is not text"))?
        };
        let links: Vec<String> = text.lines().map(str::trim).filter(|l| l.starts_with("ostp://")).map(str::to_string).collect();
        if links.is_empty() {
            anyhow::bail!("not a subscription: no ostp:// links in the response");
        }
        Ok(SubscriptionDoc { name: String::new(), update_interval_hours: default_interval(), links, usage: None })
    }

    /// The links that parse, in order; malformed ones are skipped.
    pub fn valid_links(&self) -> Vec<ShareLink> {
        self.links.iter().filter_map(|l| ShareLink::parse(l).ok()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_stable_hex_and_hides_the_key() {
        let t = token_for_key("0123456789abcdef");
        assert_eq!(t.len(), 32);
        assert!(t.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(t, token_for_key("0123456789abcdef"));
        assert_ne!(t, token_for_key("0123456789abcdeg"));
        assert!(!t.contains("0123456789abcdef"));
    }

    #[test]
    fn parses_json_plain_and_base64_forms() {
        let doc = SubscriptionDoc {
            name: "vpn".into(),
            update_interval_hours: 6,
            links: vec!["ostp://k@vpn.example.com:443?type=uot&tls=1".into(), "ostp://k@vpn.example.com:50000?type=udp".into()],
            usage: Some(SubscriptionUsage { used_bytes: 10, limit_bytes: Some(100) }),
        };
        let json = serde_json::to_string(&doc).unwrap();
        assert_eq!(SubscriptionDoc::parse(&json).unwrap(), doc);

        let plain = doc.links.join("\n");
        assert_eq!(SubscriptionDoc::parse(&plain).unwrap().links, doc.links);

        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(plain.as_bytes());
        assert_eq!(SubscriptionDoc::parse(&b64).unwrap().links, doc.links);

        assert!(SubscriptionDoc::parse("<html>404</html>").is_err());
        assert_eq!(doc.valid_links().len(), 2);
    }
}
