//! `access_keys` entries in a server config come in two forms: a bare key
//! string, or an object `{ "access_key", "name", "limit_bytes", "max_devices",
//! "expires_at", "sub_id" }`.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum AccessKeyEntry {
    Detailed {
        access_key: String,
        name: Option<String>,
        limit_bytes: Option<u64>,
        /// Devices a subscription may serve at once (by HWID); absent = no limit.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_devices: Option<u32>,
        /// When the key stops working, Unix seconds (UTC); absent = never.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expires_at: Option<u64>,
        /// The subscription URL token (32 lowercase hex, random). Absent: the
        /// legacy token, a hash of the key, keeps working.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sub_id: Option<String>,
    },
    KeyOnly(String),
}

impl AccessKeyEntry {
    pub fn key(&self) -> String {
        match self {
            AccessKeyEntry::KeyOnly(k) => k.clone(),
            AccessKeyEntry::Detailed { access_key, .. } => access_key.clone(),
        }
    }

    pub fn name(&self) -> Option<String> {
        match self {
            AccessKeyEntry::KeyOnly(_) => None,
            AccessKeyEntry::Detailed { name, .. } => name.clone(),
        }
    }

    pub fn limit(&self) -> Option<u64> {
        match self {
            AccessKeyEntry::KeyOnly(_) => None,
            AccessKeyEntry::Detailed { limit_bytes, .. } => *limit_bytes,
        }
    }

    pub fn max_devices(&self) -> Option<u32> {
        match self {
            AccessKeyEntry::KeyOnly(_) => None,
            AccessKeyEntry::Detailed { max_devices, .. } => *max_devices,
        }
    }

    pub fn expires_at(&self) -> Option<u64> {
        match self {
            AccessKeyEntry::KeyOnly(_) => None,
            AccessKeyEntry::Detailed { expires_at, .. } => *expires_at,
        }
    }

    /// The subscription id as written in the config (shape not checked here;
    /// config validation does that).
    pub fn sub_id(&self) -> Option<String> {
        match self {
            AccessKeyEntry::KeyOnly(_) => None,
            AccessKeyEntry::Detailed { sub_id, .. } => sub_id.clone().filter(|s| !s.is_empty()),
        }
    }

    /// The URL token of this user's subscription: `sub_id`, or the legacy hash.
    pub fn sub_token(&self) -> String {
        crate::subscription::token_for(&self.key(), self.sub_id().as_deref())
    }

    /// `(key, name, limit_bytes)`.
    pub fn into_parts(self) -> (String, Option<String>, Option<u64>) {
        match self {
            AccessKeyEntry::Detailed { access_key, name, limit_bytes, .. } => (access_key, name, limit_bytes),
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

/// The `sub_id` of an entry parsed as untyped JSON; `None` for a bare key or
/// an object without one.
pub fn sub_id_of(entry: &Value) -> Option<String> {
    entry.get("sub_id").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string)
}

/// The subscription URL token of an entry parsed as untyped JSON: its
/// `sub_id`, or the legacy hash of its key.
pub fn sub_token_of(entry: &Value) -> Option<String> {
    let key = key_of(entry)?;
    Some(crate::subscription::token_for(&key, sub_id_of(entry).as_deref()))
}

/// Whether a key with this expiry has expired at `now` (Unix seconds). The
/// moment itself already counts as expired.
pub fn is_expired(expires_at: Option<u64>, now: u64) -> bool {
    expires_at.is_some_and(|t| now >= t)
}

/// Seconds since the Unix epoch, 0 when the clock is before it.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant's algorithm).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let m = i64::from(m);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `(year, month, day)` of a day count since 1970-01-01.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// `YYYY-MM-DD` (UTC) of a Unix time.
pub fn format_date(unix: u64) -> String {
    let (y, m, d) = civil_from_days((unix / 86_400) as i64);
    format!("{y:04}-{m:02}-{d:02}")
}

/// `YYYY-MM-DD HH:MM UTC` of a Unix time.
pub fn format_datetime(unix: u64) -> String {
    let secs = unix % 86_400;
    format!("{} {:02}:{:02} UTC", format_date(unix), secs / 3600, secs % 3600 / 60)
}

/// The latest expiry accepted: 9999-12-31 23:59:59 UTC.
pub const MAX_EXPIRES_AT: u64 = 253_402_300_799;

/// Reads an expiry as people write it: `YYYY-MM-DD` (the end of that day,
/// UTC), `<N>d` (N days from `now`), or `never` (no expiry, `None`).
pub fn parse_expiry(value: &str, now: u64) -> Result<Option<u64>, String> {
    let v = value.trim();
    if v.eq_ignore_ascii_case("never") || v.eq_ignore_ascii_case("none") {
        return Ok(None);
    }
    if let Some(n) = v.strip_suffix('d').or_else(|| v.strip_suffix('D')) {
        let days: u64 = n.parse().map_err(|_| format!("`{value}`: expected YYYY-MM-DD, <N>d or never"))?;
        if days == 0 || days > 36_500 {
            return Err(format!("`{value}`: the number of days must be 1 to 36500"));
        }
        return Ok(Some(now + days * 86_400));
    }
    let parts: Vec<&str> = v.split('-').collect();
    let bad = || format!("`{value}`: expected YYYY-MM-DD, <N>d or never");
    let [y, m, d] = parts.as_slice() else { return Err(bad()) };
    if y.len() != 4 || m.len() != 2 || d.len() != 2 {
        return Err(bad());
    }
    let (y, m, d): (i64, u32, u32) = (y.parse().map_err(|_| bad())?, m.parse().map_err(|_| bad())?, d.parse().map_err(|_| bad())?);
    if !(1970..=9999).contains(&y) || !(1..=12).contains(&m) || d == 0 {
        return Err(bad());
    }
    let days = days_from_civil(y, m, d);
    // 31 February and the like: the day must come back as written.
    if civil_from_days(days) != (y, m, d) {
        return Err(format!("`{value}`: no such date"));
    }
    Ok(Some(days as u64 * 86_400 + 86_399))
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
        assert_eq!(e.expires_at(), None);
        assert_eq!(e.into_parts(), ("k".into(), None, None));
        let e: AccessKeyEntry = serde_json::from_value(json!({"access_key": "k", "expires_at": 1767225599u64})).unwrap();
        assert_eq!(e.expires_at(), Some(1_767_225_599));
        let id = "0123456789abcdef0123456789abcdef";
        let e: AccessKeyEntry = serde_json::from_value(json!({"access_key": "k", "sub_id": id})).unwrap();
        assert_eq!(e.sub_id().as_deref(), Some(id));
        assert_eq!(e.sub_token(), id);
        assert_eq!(sub_token_of(&json!({"access_key": "k", "sub_id": id})).as_deref(), Some(id));
        let legacy = crate::subscription::token_for_key("k");
        assert_eq!(sub_token_of(&json!("k")), Some(legacy.clone()));
        assert_eq!(serde_json::from_value::<AccessKeyEntry>(json!("k")).unwrap().sub_token(), legacy);
        assert!(!serde_json::to_string(&serde_json::from_value::<AccessKeyEntry>(json!({"access_key": "k"})).unwrap()).unwrap().contains("sub_id"));
        // Written back only when set.
        assert!(!serde_json::to_string(&serde_json::from_value::<AccessKeyEntry>(json!({"access_key": "k"})).unwrap()).unwrap().contains("expires_at"));
    }

    #[test]
    fn expiry_values() {
        let now = 1_700_000_000;
        assert_eq!(parse_expiry("never", now), Ok(None));
        assert_eq!(parse_expiry("30d", now), Ok(Some(now + 30 * 86_400)));
        // The end of the day, UTC.
        assert_eq!(parse_expiry("2025-12-31", now), Ok(Some(1_767_225_599)));
        assert_eq!(parse_expiry("2024-02-29", now), Ok(Some(1_709_251_199)));
        assert!(parse_expiry("2023-02-29", now).is_err());
        assert!(parse_expiry("2025-13-01", now).is_err());
        assert!(parse_expiry("2025-1-01", now).is_err());
        assert!(parse_expiry("0d", now).is_err());
        assert!(parse_expiry("tomorrow", now).is_err());
        assert_eq!(format_date(1_767_225_599), "2025-12-31");
        assert_eq!(format_date(0), "1970-01-01");
        assert_eq!(format_datetime(1_767_225_599), "2025-12-31 23:59 UTC");
        assert!(is_expired(Some(now), now));
        assert!(!is_expired(Some(now + 1), now));
        assert!(!is_expired(None, now));
        assert_eq!(format_date(MAX_EXPIRES_AT), "9999-12-31");
    }
}
