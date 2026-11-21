//! What a server tells its clients about itself, inside the tunnel only (the
//! `ServerInfo` relay message): the operator's own words (`server_info` in
//! config.json), what the server offers, and the asking key's usage and
//! expiry. Nothing of it is reachable before a session is authenticated: a
//! prober learns nothing more from the server than before.

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::sync::RwLock;

/// Longest name, location and contact, in characters.
pub const SHORT_FIELD_MAX: usize = 128;
/// Longest `about` (Markdown), in bytes.
pub const ABOUT_MAX: usize = 8 << 10;

/// The `server_info` section of config.json. Every field is optional.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contact: Option<String>,
    /// Markdown written by the operator. Apps render a safe subset of it;
    /// the server passes the text as it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub about: Option<String>,
}

/// `s` cut to at most `max` bytes on a character boundary.
fn cut_bytes(s: &str, max: usize) -> &str {
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// A one-line field: trimmed, without control characters, at most
/// `SHORT_FIELD_MAX` characters; empty means not set.
fn short_field(v: Option<String>) -> Option<String> {
    let v: String = v?.chars().filter(|c| !c.is_control()).collect();
    let v: String = v.trim().chars().take(SHORT_FIELD_MAX).collect();
    let v = v.trim().to_string();
    (!v.is_empty()).then_some(v)
}

impl OperatorInfo {
    /// The info as it is kept and sent: one-line fields cleaned and cut,
    /// `about` cut to `ABOUT_MAX` bytes with its line breaks kept (other
    /// control characters dropped), empty fields left out.
    pub fn sanitized(self) -> Self {
        let about = self.about.and_then(|a| {
            let a: String = a.replace("\r\n", "\n").chars().filter(|&c| c == '\n' || c == '\t' || !c.is_control()).collect();
            let a = cut_bytes(a.trim(), ABOUT_MAX).trim_end().to_string();
            (!a.is_empty()).then_some(a)
        });
        Self { name: short_field(self.name), location: short_field(self.location), contact: short_field(self.contact), about }
    }

    pub fn is_empty(&self) -> bool {
        self.name.is_none() && self.location.is_none() && self.contact.is_none() && self.about.is_none()
    }

    /// Reads the `server_info` section of a config already parsed as JSON;
    /// absent or malformed gives the empty info.
    pub fn from_config(config: &Value) -> Self {
        config
            .get("server_info")
            .cloned()
            .and_then(|v| serde_json::from_value::<OperatorInfo>(v).ok())
            .unwrap_or_default()
            .sanitized()
    }
}

/// What the server reports about itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServerFacts {
    pub version: String,
    /// What the server offers: "udp", plus "tls" when TLS is configured.
    pub carriers: Vec<String>,
    pub log_privacy: String,
    pub ipv6: bool,
    pub dns_filtering: bool,
}

/// `{ "operator": {...}, "server": {...} }`; `operator` is left out when empty.
pub fn info_value(operator: &OperatorInfo, facts: &ServerFacts) -> Value {
    let mut out = Map::new();
    if !operator.is_empty() {
        out.insert("operator".into(), serde_json::to_value(operator).unwrap_or(Value::Null));
    }
    out.insert("server".into(), serde_json::to_value(facts).unwrap_or(Value::Null));
    Value::Object(out)
}

/// The asking key's part of the document.
pub fn key_value(used_bytes: u64, limit_bytes: Option<u64>, expires_at: Option<u64>, max_devices: Option<u32>) -> Value {
    json!({ "used_bytes": used_bytes, "limit_bytes": limit_bytes, "expires_at": expires_at, "max_devices": max_devices })
}

/// The live state: the operator's info (hot-reloaded from config.json) and
/// the carriers the server was started with.
#[derive(Debug, Default)]
pub struct ServerInfoState {
    operator: RwLock<OperatorInfo>,
    carriers: RwLock<Vec<String>>,
}

impl ServerInfoState {
    pub fn set_operator(&self, info: OperatorInfo) {
        *self.operator.write().unwrap_or_else(|e| e.into_inner()) = info.sanitized();
    }

    pub fn operator(&self) -> OperatorInfo {
        self.operator.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn set_carriers(&self, carriers: Vec<String>) {
        *self.carriers.write().unwrap_or_else(|e| e.into_inner()) = carriers;
    }

    pub fn carriers(&self) -> Vec<String> {
        self.carriers.read().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

/// The carriers a server with or without TLS offers.
pub fn carriers(tls: bool) -> Vec<String> {
    let mut c = vec!["udp".to_string()];
    if tls {
        c.push("tls".to_string());
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_are_cleaned_and_cut() {
        let info = OperatorInfo {
            name: Some("  My\u{7} VPN  ".into()),
            location: Some("".into()),
            contact: Some("x".repeat(300)),
            about: Some(format!("# Hi\r\nline two\u{1b}\n{}", "é".repeat(ABOUT_MAX))),
        }
        .sanitized();
        assert_eq!(info.name.as_deref(), Some("My VPN"));
        assert_eq!(info.location, None);
        assert_eq!(info.contact.as_ref().unwrap().chars().count(), SHORT_FIELD_MAX);
        let about = info.about.unwrap();
        assert!(about.starts_with("# Hi\nline two\n"));
        assert!(about.len() <= ABOUT_MAX);
        assert!(!about.contains('\u{1b}') && !about.contains('\r'));
    }

    #[test]
    fn the_document_has_the_contract_shape() {
        let facts = ServerFacts {
            version: "0.5.0-alpha.7".into(),
            carriers: carriers(true),
            log_privacy: "normal".into(),
            ipv6: false,
            dns_filtering: true,
        };
        let empty = info_value(&OperatorInfo::default(), &facts);
        assert!(empty.get("operator").is_none(), "an empty operator object is left out");
        assert_eq!(empty["server"]["carriers"], json!(["udp", "tls"]));
        assert_eq!(empty["server"]["version"], "0.5.0-alpha.7");
        assert_eq!(empty["server"]["ipv6"], false);
        assert_eq!(empty["server"]["dns_filtering"], true);
        assert_eq!(empty["server"]["log_privacy"], "normal");
        let op = OperatorInfo { name: Some("n".into()), ..Default::default() };
        let v = info_value(&op, &facts);
        assert_eq!(v["operator"], json!({ "name": "n" }), "unset keys are left out");
        let k = key_value(5, None, Some(10), Some(3));
        assert_eq!(k, json!({ "used_bytes": 5, "limit_bytes": null, "expires_at": 10, "max_devices": 3 }));
    }

    #[test]
    fn read_from_config() {
        let cfg = json!({ "mode": "server", "server_info": { "name": " a ", "about": "b" } });
        assert_eq!(OperatorInfo::from_config(&cfg), OperatorInfo { name: Some("a".into()), about: Some("b".into()), ..Default::default() });
        assert!(OperatorInfo::from_config(&json!({ "mode": "server" })).is_empty());
        assert!(OperatorInfo::from_config(&json!({ "server_info": 5 })).is_empty());
    }
}
