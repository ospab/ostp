//! `warp.json`: the device's keys and what enabling changed, next to
//! `config.json`. Mode 0600, written atomically. Nothing from it goes into
//! `config.json`, a backup, a log or the panel's API.

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::api::{Device, DeviceConfig};

pub const FILE_NAME: &str = "warp.json";
pub const DEFAULT_ENDPOINT_HOST: &str = "engage.cloudflareclient.com:2408";

/// What `enable --all` found in the config's `outbound` section, so that
/// `disable` can put it back. `section: None` means there was no section.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SavedOutbound {
    pub section: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarpState {
    pub version: u32,
    /// WireGuard private key, base64. Secret.
    pub private_key: String,
    pub device_id: String,
    /// Bearer token of the device. Secret.
    pub access_token: String,
    /// WARP+ key, if attached. Secret.
    #[serde(default)]
    pub license: Option<String>,
    #[serde(default)]
    pub account_type: Option<String>,
    /// The peer's public key, base64.
    pub peer_public_key: String,
    pub address_v4: String,
    #[serde(default)]
    pub address_v6: Option<String>,
    /// `host:port` of the peer.
    pub endpoint_host: String,
    /// The peer's IPv4 address as `ip:port`, when given (port 0 there means
    /// "the port from `endpoint_host`").
    #[serde(default)]
    pub endpoint_v4: Option<String>,
    #[serde(default)]
    pub endpoint_v6: Option<String>,
    /// `config.client_id` of the device; its first 3 bytes are the WireGuard
    /// "reserved" bytes.
    #[serde(default)]
    pub client_id: Option<String>,
    pub registered_at: String,
    #[serde(default)]
    pub saved_outbound: Option<SavedOutbound>,
}

pub fn path_for(config_path: &Path) -> PathBuf {
    config_path.parent().map(|d| d.join(FILE_NAME)).unwrap_or_else(|| PathBuf::from(FILE_NAME))
}

fn strip_cidr(a: &str) -> &str {
    a.split('/').next().unwrap_or(a)
}

impl WarpState {
    /// Builds the state from a registration (or a later read of the device).
    pub fn from_device(private_key_b64: String, dev: &Device, now: String) -> Result<Self> {
        let token = dev.token.clone().ok_or_else(|| anyhow!("the registration answer has no access token"))?;
        let mut st = WarpState {
            version: 1,
            private_key: private_key_b64,
            device_id: dev.id.clone(),
            access_token: token,
            license: None,
            account_type: None,
            peer_public_key: String::new(),
            address_v4: String::new(),
            address_v6: None,
            endpoint_host: DEFAULT_ENDPOINT_HOST.to_string(),
            endpoint_v4: None,
            endpoint_v6: None,
            client_id: None,
            registered_at: now,
            saved_outbound: None,
        };
        st.apply_device(dev)?;
        Ok(st)
    }

    /// Takes the config and the account from a device answer.
    pub fn apply_device(&mut self, dev: &Device) -> Result<()> {
        let cfg: &DeviceConfig = dev.config.as_ref().ok_or_else(|| anyhow!("the answer has no config"))?;
        let peer = cfg.peers.first().ok_or_else(|| anyhow!("the answer lists no WireGuard peer"))?;
        let v4 = cfg
            .interface
            .addresses
            .v4
            .as_deref()
            .filter(|a| !a.is_empty())
            .ok_or_else(|| anyhow!("the answer gives no IPv4 address for the device"))?;
        self.address_v4 = strip_cidr(v4).to_string();
        self.address_v6 = cfg.interface.addresses.v6.as_deref().filter(|a| !a.is_empty()).map(|a| strip_cidr(a).to_string());
        self.peer_public_key = peer.public_key.clone();
        if let Some(h) = peer.endpoint.host.as_deref().filter(|h| !h.is_empty()) {
            self.endpoint_host = h.to_string();
        }
        self.endpoint_v4 = peer.endpoint.v4.clone().filter(|a| !a.is_empty());
        self.endpoint_v6 = peer.endpoint.v6.clone().filter(|a| !a.is_empty());
        if let Some(id) = cfg.client_id.as_deref().filter(|c| !c.is_empty()) {
            self.client_id = Some(id.to_string());
        }
        if let Some(acc) = &dev.account {
            if let Some(t) = &acc.account_type {
                self.account_type = Some(t.clone());
            }
            // `account.license` is the account's own key, not a WARP+ key the
            // operator attached: it is not kept.
        }
        Ok(())
    }

    pub fn private_key_bytes(&self) -> Result<[u8; 32]> {
        decode_key(&self.private_key, "private key")
    }

    pub fn peer_public_bytes(&self) -> Result<[u8; 32]> {
        decode_key(&self.peer_public_key, "peer public key")
    }
}

pub fn decode_key(b64: &str, what: &str) -> Result<[u8; 32]> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| anyhow!("{what} is not base64: {e}"))?;
    <[u8; 32]>::try_from(raw.as_slice()).map_err(|_| anyhow!("{what} is {} bytes, not 32", raw.len()))
}

pub fn encode_key(k: &[u8; 32]) -> String {
    base64::engine::general_purpose::STANDARD.encode(k)
}

pub fn load(path: &Path) -> Result<Option<WarpState>> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
    };
    let st: WarpState = serde_json::from_str(&text).with_context(|| format!("{} does not parse", path.display()))?;
    if st.version != 1 {
        bail!("{} is version {}, which this ostp does not know", path.display(), st.version);
    }
    Ok(Some(st))
}

/// Writes through a temporary file next to the target (created 0600 on Unix,
/// flushed to disk) and renames it over the target, so a crash leaves either
/// the old file or the new one.
pub fn save(path: &Path, st: &WarpState) -> Result<()> {
    use std::io::Write;
    let json = serde_json::to_vec_pretty(st)?;
    let tmp = path.with_extension("json.tmp");
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp).with_context(|| format!("cannot write {}", tmp.display()))?;
        #[cfg(unix)]
        {
            // A leftover temporary file keeps the mode it was created with.
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        f.write_all(&json)?;
        f.write_all(b"\n")?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path).with_context(|| format!("cannot replace {}", path.display()))?;
    Ok(())
}

pub fn remove(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("cannot remove {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> WarpState {
        let dev: Device = serde_json::from_str(
            r#"{"id":"dev-1","token":"tok","account":{"account_type":"free","license":"acc-lic"},
                "config":{"client_id":"AQID","interface":{"addresses":{"v4":"172.16.0.2/32","v6":"2606:4700:110::2"}},
                "peers":[{"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","endpoint":{"host":"engage.cloudflareclient.com:2408","v4":"162.159.192.1:0","v6":"[2606:4700:d0::a29f:c001]:0"}}]}}"#,
        )
        .unwrap();
        WarpState::from_device(encode_key(&[7u8; 32]), &dev, "2026-11-12T00:00:00.000Z".into()).unwrap()
    }

    #[test]
    fn state_takes_what_the_registration_gave() {
        let s = sample();
        assert_eq!(s.address_v4, "172.16.0.2", "the prefix length is dropped");
        assert_eq!(s.address_v6.as_deref(), Some("2606:4700:110::2"));
        assert_eq!(s.account_type.as_deref(), Some("free"));
        assert_eq!(s.client_id.as_deref(), Some("AQID"));
        assert_eq!(s.private_key_bytes().unwrap(), [7u8; 32]);
        assert_eq!(s.peer_public_bytes().unwrap(), [0u8; 32]);
        assert!(s.license.is_none(), "the account's own key is not a WARP+ key");
    }

    #[test]
    fn a_registration_without_token_or_peer_is_refused() {
        let no_token: Device = serde_json::from_str(r#"{"id":"x","config":{"interface":{"addresses":{"v4":"1.1.1.1"}},"peers":[]}}"#).unwrap();
        assert!(WarpState::from_device("k".into(), &no_token, "t".into()).is_err());
        let no_peer: Device = serde_json::from_str(r#"{"id":"x","token":"t","config":{"interface":{"addresses":{"v4":"1.1.1.1"}},"peers":[]}}"#).unwrap();
        assert!(WarpState::from_device("k".into(), &no_peer, "t".into()).is_err());
    }

    #[test]
    fn keys_of_the_wrong_size_are_refused() {
        assert!(decode_key("AAAA", "k").is_err());
        assert!(decode_key("not base64!", "k").is_err());
    }

    #[test]
    fn save_and_load_round_trip_and_leave_no_temp_file() {
        let dir = std::env::temp_dir().join(format!("ostp-warp-store-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join(FILE_NAME);
        assert!(load(&p).unwrap().is_none());
        let mut s = sample();
        s.saved_outbound = Some(SavedOutbound { section: Some(serde_json::json!({"enabled": false})) });
        save(&p, &s).unwrap();
        let back = load(&p).unwrap().unwrap();
        assert_eq!(back.device_id, "dev-1");
        assert_eq!(back.saved_outbound, s.saved_outbound);
        // A second save replaces the first.
        s.device_id = "dev-2".into();
        save(&p, &s).unwrap();
        assert_eq!(load(&p).unwrap().unwrap().device_id, "dev-2");
        assert!(!p.with_extension("json.tmp").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
            // A temp file left by a crash with loose permissions is tightened.
            std::fs::write(p.with_extension("json.tmp"), b"x").unwrap();
            std::fs::set_permissions(p.with_extension("json.tmp"), std::fs::Permissions::from_mode(0o644)).unwrap();
            save(&p, &s).unwrap();
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        }
        remove(&p).unwrap();
        remove(&p).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_file_of_an_unknown_version_is_refused() {
        let dir = std::env::temp_dir().join(format!("ostp-warp-store-v-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join(FILE_NAME);
        let mut v = serde_json::to_value(sample()).unwrap();
        v["version"] = serde_json::json!(9);
        std::fs::write(&p, v.to_string()).unwrap();
        assert!(load(&p).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
