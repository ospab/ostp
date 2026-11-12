//! Devices that fetched a user's subscription, by HWID.
//!
//! A user may have `max_devices`. The limit is checked when a subscription is
//! fetched: a device the server has seen before always passes, a new one takes
//! a free slot, and with none free the fetch is refused. A user with a limit
//! whose app sends no HWID is refused too (`hwid_required`), because a limit
//! that anonymous requests can walk around is not a limit.
//!
//! The record is kept in `devices.json` next to the config (mode 0600), keyed
//! by the subscription token of the access key, never by the key itself.
//! It is the operator's own file on the operator's own server; the app sends an
//! HWID only when its owner turned that on.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use serde::{Deserialize, Serialize};

/// Devices remembered per user, whatever the limit says: a bound on the file.
const MAX_STORED_PER_USER: usize = 1000;
/// How often a device that keeps fetching has its `last_seen` rewritten to disk.
const TOUCH_EVERY_SECS: u64 = 3600;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Device {
    pub hwid: String,
    pub os: String,
    pub model: String,
    pub first_seen: u64,
    pub last_seen: u64,
}

/// A validated device identity from the request headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hwid {
    pub hwid: String,
    pub os: String,
    pub model: String,
}

impl Hwid {
    /// `hwid` is 16 to 64 characters of `[0-9a-zA-Z_-]` (the apps send 32 hex
    /// digits); `os` and `model` are free text of the device, cut to 64 printable
    /// ASCII characters so they cannot carry markup or control characters.
    pub fn parse(hwid: &str, os: &str, model: &str) -> Option<Hwid> {
        let hwid = hwid.trim();
        if !(16..=64).contains(&hwid.len()) || !hwid.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') {
            return None;
        }
        Some(Hwid { hwid: hwid.to_ascii_lowercase(), os: clean(os), model: clean(model) })
    }
}

fn clean(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_graphic() || *c == ' ').take(64).collect::<String>().trim().to_string()
}

/// Why a subscription fetch is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The user has a device limit and the request carried no HWID.
    HwidRequired,
    /// Every slot of the limit is taken by other devices.
    DeviceLimit { max: u32 },
}

pub struct DeviceStore {
    path: Option<PathBuf>,
    inner: Mutex<HashMap<String, Vec<Device>>>,
}

static SHARED: OnceLock<Mutex<HashMap<PathBuf, Arc<DeviceStore>>>> = OnceLock::new();

impl DeviceStore {
    /// One store per file, shared by the subscription service and the API so
    /// they never write over each other. `None` keeps everything in memory.
    pub fn shared(path: Option<PathBuf>) -> Arc<DeviceStore> {
        let Some(path) = path else { return Arc::new(DeviceStore::in_memory()) };
        let registry = SHARED.get_or_init(Default::default);
        let mut map = registry.lock().unwrap_or_else(|e| e.into_inner());
        map.entry(path.clone()).or_insert_with(|| Arc::new(DeviceStore::open(path))).clone()
    }

    pub fn in_memory() -> DeviceStore {
        DeviceStore { path: None, inner: Mutex::new(HashMap::new()) }
    }

    /// Loads the file when there is one. A file that cannot be read as the
    /// record is moved aside (`.corrupt`) rather than overwritten, and the
    /// store starts empty: losing the list of devices is the lesser harm.
    pub fn open(path: PathBuf) -> DeviceStore {
        let map = match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<HashMap<String, Vec<Device>>>(&bytes) {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!("{} is not a device record ({e}); moved to .corrupt, starting empty", path.display());
                    let _ = std::fs::rename(&path, path.with_extension("json.corrupt"));
                    HashMap::new()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(e) => {
                tracing::warn!("cannot read {}: {e}; starting with no devices", path.display());
                HashMap::new()
            }
        };
        DeviceStore { path: Some(path), inner: Mutex::new(map) }
    }

    /// The check at a subscription fetch. `user` is the subscription token of
    /// the access key. `max` of `None` or 0 means no limit; the device is still
    /// recorded when it sent an HWID, so the operator can see it.
    pub fn check(&self, user: &str, max: Option<u32>, hwid: Option<&Hwid>, now: u64) -> Result<(), Refusal> {
        let max = max.filter(|m| *m > 0);
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let list = map.entry(user.to_string()).or_default();
        let result;
        let mut dirty = false;
        match (max, hwid) {
            (Some(_), None) => result = Err(Refusal::HwidRequired),
            (_, None) => result = Ok(()),
            (limit, Some(h)) => {
                if let Some(d) = list.iter_mut().find(|d| d.hwid == h.hwid) {
                    if now.saturating_sub(d.last_seen) >= TOUCH_EVERY_SECS || d.os != h.os || d.model != h.model {
                        d.last_seen = now;
                        d.os = h.os.clone();
                        d.model = h.model.clone();
                        dirty = true;
                    }
                    result = Ok(());
                } else if limit.is_some_and(|m| list.len() >= m as usize) {
                    result = Err(Refusal::DeviceLimit { max: limit.unwrap_or(0) });
                } else if list.len() >= MAX_STORED_PER_USER {
                    // Unlimited user with a full record: the oldest entry makes room.
                    if let Some(i) = list.iter().enumerate().min_by_key(|(_, d)| d.last_seen).map(|(i, _)| i) {
                        list.remove(i);
                    }
                    list.push(Device { hwid: h.hwid.clone(), os: h.os.clone(), model: h.model.clone(), first_seen: now, last_seen: now });
                    dirty = true;
                    result = Ok(());
                } else {
                    list.push(Device { hwid: h.hwid.clone(), os: h.os.clone(), model: h.model.clone(), first_seen: now, last_seen: now });
                    dirty = true;
                    result = Ok(());
                }
            }
        }
        if list.is_empty() {
            map.remove(user);
        }
        if dirty {
            self.save(&map);
        }
        result
    }

    /// The devices of `user` as recorded in the file, read without touching it
    /// (the CLI's view; a running server's newest `last_seen` may lag by an hour).
    pub fn read_list(path: &Path, user: &str) -> Vec<Device> {
        let Ok(bytes) = std::fs::read(path) else { return Vec::new() };
        let mut v = serde_json::from_slice::<HashMap<String, Vec<Device>>>(&bytes).ok().and_then(|mut m| m.remove(user)).unwrap_or_default();
        v.sort_by_key(|d| std::cmp::Reverse(d.last_seen));
        v
    }

    pub fn list(&self, user: &str) -> Vec<Device> {
        let map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut v = map.get(user).cloned().unwrap_or_default();
        v.sort_by_key(|d| std::cmp::Reverse(d.last_seen));
        v
    }

    /// Frees one slot. `true` when the device was in the record.
    pub fn remove(&self, user: &str, hwid: &str) -> bool {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(list) = map.get_mut(user) else { return false };
        let before = list.len();
        list.retain(|d| d.hwid != hwid.to_ascii_lowercase());
        let removed = list.len() != before;
        if list.is_empty() {
            map.remove(user);
        }
        if removed {
            self.save(&map);
        }
        removed
    }

    /// Forgets every device of a user; how many there were.
    pub fn clear(&self, user: &str) -> usize {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let n = map.remove(user).map(|l| l.len()).unwrap_or(0);
        if n > 0 {
            self.save(&map);
        }
        n
    }

    fn save(&self, map: &HashMap<String, Vec<Device>>) {
        let Some(path) = &self.path else { return };
        if let Err(e) = write_private(path, &serde_json::to_vec_pretty(map).unwrap_or_default()) {
            tracing::warn!("cannot write {}: {e}; the device record is kept in memory only until the next write", path.display());
        }
    }
}

/// Written to a temporary file and renamed, readable by the owner only.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("json.tmp");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(id: &str) -> Hwid {
        Hwid::parse(&format!("{id:0>32}"), "Windows 11", "PC").unwrap()
    }

    #[test]
    fn a_limit_counts_distinct_devices_and_refuses_the_next() {
        let s = DeviceStore::in_memory();
        assert_eq!(s.check("u", Some(2), Some(&h("a")), 100), Ok(()));
        assert_eq!(s.check("u", Some(2), Some(&h("b")), 101), Ok(()));
        // The same device again takes no new slot.
        assert_eq!(s.check("u", Some(2), Some(&h("a")), 102), Ok(()));
        assert_eq!(s.check("u", Some(2), Some(&h("c")), 103), Err(Refusal::DeviceLimit { max: 2 }));
        assert_eq!(s.list("u").len(), 2);
    }

    #[test]
    fn a_limit_without_an_hwid_is_refused_and_no_limit_is_not() {
        let s = DeviceStore::in_memory();
        assert_eq!(s.check("u", Some(1), None, 100), Err(Refusal::HwidRequired));
        assert_eq!(s.check("u", None, None, 100), Ok(()));
        assert_eq!(s.check("u", Some(0), None, 100), Ok(()), "0 means no limit");
    }

    #[test]
    fn an_unlimited_user_still_has_the_devices_that_identified_themselves() {
        let s = DeviceStore::in_memory();
        assert_eq!(s.check("u", None, Some(&h("a")), 100), Ok(()));
        assert_eq!(s.list("u").len(), 1);
    }

    #[test]
    fn removing_a_device_frees_its_slot() {
        let s = DeviceStore::in_memory();
        s.check("u", Some(1), Some(&h("a")), 100).unwrap();
        assert!(s.check("u", Some(1), Some(&h("b")), 101).is_err());
        assert!(s.remove("u", &h("a").hwid));
        assert!(!s.remove("u", &h("a").hwid), "already gone");
        assert_eq!(s.check("u", Some(1), Some(&h("b")), 102), Ok(()));
        assert_eq!(s.clear("u"), 1);
        assert!(s.list("u").is_empty());
    }

    #[test]
    fn users_do_not_share_slots() {
        let s = DeviceStore::in_memory();
        s.check("u1", Some(1), Some(&h("a")), 100).unwrap();
        assert_eq!(s.check("u2", Some(1), Some(&h("a")), 100), Ok(()));
    }

    #[test]
    fn identity_is_validated_and_cleaned() {
        assert!(Hwid::parse("short", "x", "y").is_none());
        assert!(Hwid::parse(&"g".repeat(65), "x", "y").is_none());
        assert!(Hwid::parse("0123456789abcdef<script>", "x", "y").is_none());
        let id = Hwid::parse("0123456789ABCDEF0123456789ABCDEF", "Android 14\r\n<b>", &"m".repeat(100)).unwrap();
        assert_eq!(id.hwid, "0123456789abcdef0123456789abcdef", "lower-cased so one device has one identity");
        assert!(!id.os.contains('\r') && !id.os.contains('\n'));
        assert_eq!(id.model.len(), 64);
    }

    #[test]
    fn the_record_survives_a_restart_and_a_corrupt_file_is_set_aside() {
        let dir = std::env::temp_dir().join(format!("ostp-devices-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("devices.json");
        {
            let s = DeviceStore::open(path.clone());
            s.check("u", Some(2), Some(&h("a")), 100).unwrap();
        }
        let s = DeviceStore::open(path.clone());
        assert_eq!(s.list("u").len(), 1);
        assert_eq!(s.check("u", Some(1), Some(&h("b")), 200), Err(Refusal::DeviceLimit { max: 1 }));
        std::fs::write(&path, b"not json").unwrap();
        let s = DeviceStore::open(path.clone());
        assert!(s.list("u").is_empty());
        assert!(path.with_extension("json.corrupt").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn the_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("ostp-devices-perm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("devices.json");
        let s = DeviceStore::open(path.clone());
        s.check("u", None, Some(&h("a")), 100).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
