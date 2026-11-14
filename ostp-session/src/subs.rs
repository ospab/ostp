//! A client's subscriptions, kept as JSON: the URL and the links it returned last time.
//! Fetching is the embedder's job (it needs HTTPS); this module decides what is stored.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use ostp_core::subscription::SubscriptionDoc;
use serde::{Deserialize, Serialize};

use crate::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subscription {
    /// What the user or the server called it.
    pub name: String,
    /// The subscription URL. It is a credential: never print it whole.
    pub url: String,
    /// `ostp://` links from the last update, best first.
    #[serde(default)]
    pub links: Vec<String>,
    /// When the links were fetched (Unix seconds, 0 = unknown clock).
    #[serde(default)]
    pub updated_unix: u64,
    /// How often the server asks clients to refresh.
    #[serde(default)]
    pub update_interval_hours: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Store {
    #[serde(default)]
    pub subscriptions: Vec<Subscription>,
}

/// Subscription URLs must be https: the URL is a credential (the desktop client refuses
/// plain HTTP for the same reason).
pub fn check_url(url: &str) -> Result<(), Error> {
    let u = url.trim();
    match u.split_once("://") {
        Some((scheme, rest)) if scheme.eq_ignore_ascii_case("https") && !rest.is_empty() => Ok(()),
        Some((scheme, _)) => Err(Error::Link(format!(
            "subscription URLs must use https (got {scheme}://): the link is a credential"
        ))),
        None => Err(Error::Link(String::from("not a subscription URL: expected https://..."))),
    }
}

/// The URL with its secret part hidden: scheme, host and the first characters of the path.
pub fn redact_url(url: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap_or(("", url));
    let (host, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let shown: String = path.chars().take(5).collect();
    let more = if path.chars().count() > 5 { "..." } else { "" };
    if scheme.is_empty() {
        format!("{host}{shown}{more}")
    } else {
        format!("{scheme}://{host}{shown}{more}")
    }
}

impl Store {
    pub fn parse(json: &str) -> Result<Store, Error> {
        if json.trim().is_empty() {
            return Ok(Store::default());
        }
        serde_json::from_str(json).map_err(|e| Error::Link(format!("the subscription list is damaged: {e}")))
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| String::from("{}"))
    }

    /// By number as `list` shows it (1, 2, ...) or by name.
    pub fn find(&self, which: &str) -> Option<usize> {
        if let Ok(n) = which.parse::<usize>() {
            if n >= 1 && n <= self.subscriptions.len() {
                return Some(n - 1);
            }
        }
        self.subscriptions.iter().position(|s| s.name.eq_ignore_ascii_case(which))
    }

    /// Store a freshly fetched subscription. The same URL again replaces the old entry.
    /// Returns its index.
    pub fn add(&mut self, name: Option<&str>, url: &str, doc: &SubscriptionDoc, now_unix: u64) -> Result<usize, Error> {
        check_url(url)?;
        let name = match name {
            Some(n) if !n.trim().is_empty() => n.trim().to_string(),
            _ if !doc.name.is_empty() => doc.name.clone(),
            _ => format!("subscription {}", self.subscriptions.len() + 1),
        };
        let entry = Subscription {
            name,
            url: url.trim().to_string(),
            links: doc.links.clone(),
            updated_unix: now_unix,
            update_interval_hours: doc.update_interval_hours,
        };
        if let Some(i) = self.subscriptions.iter().position(|s| s.url == entry.url) {
            self.subscriptions[i] = entry;
            return Ok(i);
        }
        self.subscriptions.push(entry);
        Ok(self.subscriptions.len() - 1)
    }

    /// New links for entry `i`; its name stays.
    pub fn update(&mut self, i: usize, doc: &SubscriptionDoc, now_unix: u64) {
        if let Some(s) = self.subscriptions.get_mut(i) {
            s.links = doc.links.clone();
            s.updated_unix = now_unix;
            s.update_interval_hours = doc.update_interval_hours;
        }
    }

    pub fn remove(&mut self, i: usize) -> Option<Subscription> {
        if i < self.subscriptions.len() {
            Some(self.subscriptions.remove(i))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(name: &str, links: &[&str]) -> SubscriptionDoc {
        SubscriptionDoc { name: name.into(), update_interval_hours: 6, links: links.iter().map(|s| s.to_string()).collect(), usage: None }
    }

    #[test]
    fn add_find_update_roundtrip() {
        let mut st = Store::default();
        let i = st.add(None, "https://vpn.example.com/sub/abcdef", &doc("vpn", &["ostp://k@a:1?type=udp"]), 100).unwrap();
        assert_eq!(i, 0);
        assert_eq!(st.find("1"), Some(0));
        assert_eq!(st.find("VPN"), Some(0));
        assert_eq!(st.add(Some("mine"), "https://vpn.example.com/sub/abcdef", &doc("vpn", &[]), 200).unwrap(), 0);
        assert_eq!(st.subscriptions[0].name, "mine");
        st.update(0, &doc("x", &["ostp://k@b:2?type=uot"]), 300);
        assert_eq!(st.subscriptions[0].name, "mine");
        assert_eq!(st.subscriptions[0].links.len(), 1);
        let back = Store::parse(&st.to_json()).unwrap();
        assert_eq!(back, st);
    }

    #[test]
    fn plain_http_is_refused_and_urls_are_redacted() {
        assert!(check_url("http://vpn.example.com/sub/x").is_err());
        assert!(check_url("https://vpn.example.com/sub/x").is_ok());
        assert_eq!(redact_url("https://vpn.example.com/sub/0123456789"), "https://vpn.example.com/sub/...");
    }
}
