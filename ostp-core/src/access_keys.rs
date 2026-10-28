//! `access_keys` entries in a server config come in two forms: a bare key
//! string, or an object `{ "access_key", "name", "limit_bytes" }`.

use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum AccessKeyEntry {
    Detailed { access_key: String, name: Option<String>, limit_bytes: Option<u64> },
    KeyOnly(String),
}

impl AccessKeyEntry {
    /// `(key, name, limit_bytes)`.
    pub fn into_parts(self) -> (String, Option<String>, Option<u64>) {
        match self {
            AccessKeyEntry::Detailed { access_key, name, limit_bytes } => (access_key, name, limit_bytes),
            AccessKeyEntry::KeyOnly(k) => (k, None, None),
        }
    }
}

/// The key of an entry parsed as untyped JSON; `None` when it has none.
pub fn key_of(entry: &Value) -> Option<String> {
    match entry {
        Value::String(k) => Some(k.clone()),
        _ => entry.get("access_key").and_then(Value::as_str).map(str::to_string),
    }
}

/// `(key, name)` of an entry parsed as untyped JSON; missing parts are empty.
pub fn key_and_name(entry: &Value) -> (String, String) {
    let name = match entry {
        Value::String(_) => String::new(),
        _ => entry["name"].as_str().unwrap_or_default().to_string(),
    };
    (key_of(entry).unwrap_or_default(), name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn both_forms() {
        assert_eq!(key_and_name(&json!("k1")), ("k1".into(), String::new()));
        assert_eq!(key_and_name(&json!({"access_key": "k2", "name": "bob"})), ("k2".into(), "bob".into()));
        assert_eq!(key_and_name(&json!({"name": "x"})), (String::new(), "x".into()));
        assert_eq!(key_of(&json!({"name": "x"})), None);
        let e: AccessKeyEntry = serde_json::from_value(json!({"access_key": "k", "limit_bytes": 5})).unwrap();
        assert_eq!(e.into_parts(), ("k".into(), None, Some(5)));
        let e: AccessKeyEntry = serde_json::from_value(json!("k")).unwrap();
        assert_eq!(e.into_parts(), ("k".into(), None, None));
    }
}
