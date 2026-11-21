//! Subscription documents: what `https://<domain><path>/<token>` returns, and
//! the token that addresses one access key without putting the key itself in
//! URLs (and so in web-server access logs).
//!
//! The token is a user's `sub_id` when the config gives one: random, so it
//! says nothing about the key, and replaceable without touching the key.
//! A user without `sub_id` keeps the older token, a hash of the access key
//! ([`token_for_key`]), so links handed out before `sub_id` existed still work.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::share_link::ShareLink;

/// The legacy URL token for an access key: 32 hex characters, stable, one-way.
/// Also the stable per-key id the server's device record is keyed by.
pub fn token_for_key(access_key: &str) -> String {
    let digest = Sha256::digest(format!("ostp-subscription:{access_key}").as_bytes());
    digest[..16].iter().map(|b| format!("{b:02x}")).collect()
}

/// A new subscription id: 32 lowercase hex characters (128 bits) from
/// `rand`'s thread RNG (a CSPRNG seeded from the operating system).
pub fn new_sub_id() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Whether `s` has the shape of a subscription id: 32 lowercase hex characters.
pub fn is_valid_sub_id(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The URL token of a user: its `sub_id` when it has one, otherwise the
/// legacy hash of the key. A `sub_id` of the wrong shape counts as none
/// (config validation refuses such a file, so this is only a safety net).
pub fn token_for(access_key: &str, sub_id: Option<&str>) -> String {
    match sub_id.filter(|s| is_valid_sub_id(s)) {
        Some(id) => id.to_string(),
        None => token_for_key(access_key),
    }
}

/// A random URL prefix for a newly enabled subscription: `/` and 10
/// characters of `[a-z0-9]`, so the path does not tell a scanner where to look.
pub fn random_prefix() -> String {
    use rand::Rng;
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    let tail: String = (0..10).map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char).collect();
    format!("/{tail}")
}

/// `https://<host>[:port]<prefix>/<token>`; the port is left out on 443.
pub fn subscription_url(host: &str, port: u16, prefix: &str, token: &str) -> String {
    let port = if port == 443 { String::new() } else { format!(":{port}") };
    format!("https://{host}{port}{prefix}/{token}")
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
    fn url_leaves_out_port_443() {
        assert_eq!(subscription_url("vpn.example.com", 443, "/sub", "tok"), "https://vpn.example.com/sub/tok");
        assert_eq!(subscription_url("vpn.example.com", 8443, "/sub", "tok"), "https://vpn.example.com:8443/sub/tok");
    }

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
    fn sub_ids_are_random_hex_and_replace_the_hash() {
        let a = new_sub_id();
        let b = new_sub_id();
        assert!(is_valid_sub_id(&a) && is_valid_sub_id(&b));
        assert_ne!(a, b);
        assert!(!is_valid_sub_id("0123456789ABCDEF0123456789abcdef"), "lowercase only");
        assert!(!is_valid_sub_id("0123456789abcdef"));
        assert!(!is_valid_sub_id("0123456789abcdef0123456789abcdeg"));
        assert_eq!(token_for("k", Some(&a)), a);
        assert_eq!(token_for("k", None), token_for_key("k"));
        assert_eq!(token_for("k", Some("bad")), token_for_key("k"));
    }

    #[test]
    fn random_prefix_shape() {
        for _ in 0..50 {
            let p = random_prefix();
            assert_eq!(p.len(), 11);
            assert!(p.starts_with('/'));
            assert!(p[1..].bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()), "{p}");
        }
        assert_ne!(random_prefix(), random_prefix());
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
