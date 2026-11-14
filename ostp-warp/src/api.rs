//! Registration with Cloudflare's client API, the interface the WARP apps
//! use (it is not a documented API for third parties).
//!
//! What this follows, and where it comes from (nothing here was called live
//! while writing it; the first live call is the operator's):
//! - base `https://api.cloudflareclient.com`, version path `v0a5641`, the
//!   `User-Agent` and `CF-Client-Version` of the 1.1.1.1 Android app, and the
//!   registration body: `ViRb3/wgcf`, `cloudflare/api.go`;
//! - the paths `POST /{v}/reg`, `GET /{v}/reg/{id}`, `PUT /{v}/reg/{id}/account`
//!   and the response fields: `ViRb3/wgcf`, `openapi-spec.yml`;
//! - `config.client_id` (base64) whose first 3 bytes are the WireGuard
//!   "reserved" bytes: the `warp-wireguard-gen` crate, `src/api.rs`, and
//!   sing-box's `reserved` option (see `wg::reserved_from_client_id`).

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const DEFAULT_API_BASE: &str = "https://api.cloudflareclient.com";
/// Environment variable that replaces the API base URL. For tests with a
/// local stand-in for Cloudflare; it is not a setting for operators.
pub const API_BASE_ENV: &str = "OSTP_WARP_API_BASE";
pub const API_VERSION: &str = "v0a5641";
const USER_AGENT: &str = "1.1.1.1/6.38.9-5641 (Android 16.0.0)";
const CLIENT_VERSION: &str = "a-6.38.9-5641";

/// The base URL to use: `OSTP_WARP_API_BASE` when set, else Cloudflare's.
pub fn api_base() -> String {
    match std::env::var(API_BASE_ENV) {
        Ok(v) if !v.trim().is_empty() => v.trim().trim_end_matches('/').to_string(),
        _ => DEFAULT_API_BASE.to_string(),
    }
}

#[derive(Debug, Serialize)]
pub struct RegisterRequest<'a> {
    pub fcm_token: &'a str,
    pub install_id: &'a str,
    pub key: &'a str,
    pub locale: &'a str,
    pub model: &'a str,
    pub tos: String,
    pub serial_number: &'a str,
    pub os_version: &'a str,
    pub key_type: &'a str,
    pub tunnel_type: &'a str,
}

#[derive(Debug, Deserialize)]
pub struct Device {
    pub id: String,
    /// Only the registration answer carries it.
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub account: Option<Account>,
    #[serde(default)]
    pub config: Option<DeviceConfig>,
}

#[derive(Debug, Deserialize, Default)]
pub struct Account {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub license: Option<String>,
    #[serde(default)]
    pub account_type: Option<String>,
    #[serde(default)]
    pub warp_plus: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct DeviceConfig {
    #[serde(default)]
    pub client_id: Option<String>,
    pub interface: Interface,
    #[serde(default)]
    pub peers: Vec<Peer>,
}

#[derive(Debug, Deserialize)]
pub struct Interface {
    pub addresses: Addresses,
}

#[derive(Debug, Deserialize)]
pub struct Addresses {
    #[serde(default)]
    pub v4: Option<String>,
    #[serde(default)]
    pub v6: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Peer {
    pub public_key: String,
    pub endpoint: Endpoint,
}

#[derive(Debug, Deserialize)]
pub struct Endpoint {
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub v4: Option<String>,
    #[serde(default)]
    pub v6: Option<String>,
    #[serde(default)]
    pub ports: Vec<u16>,
}

pub struct ApiClient {
    base: String,
    http: reqwest::Client,
}

impl ApiClient {
    pub fn new(base: &str) -> Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(Duration::from_secs(30))
            .http1_only()
            .build()
            .context("cannot build the HTTP client")?;
        Ok(Self { base: base.trim_end_matches('/').to_string(), http })
    }

    fn url(&self, path: &str) -> String {
        format!("{}/{}/{}", self.base, API_VERSION, path)
    }

    /// Creates a device for the public key (base64). The terms of service are
    /// accepted by the caller before this is reached.
    pub async fn register(&self, public_key_b64: &str) -> Result<Device> {
        let body = RegisterRequest {
            fcm_token: "",
            install_id: "",
            key: public_key_b64,
            locale: "en_US",
            model: "PC",
            tos: rfc3339_now(),
            serial_number: "",
            os_version: "16.0.0",
            key_type: "curve25519",
            tunnel_type: "wireguard",
        };
        let resp = self
            .http
            .post(self.url("reg"))
            .header("CF-Client-Version", CLIENT_VERSION)
            .json(&body)
            .send()
            .await
            .context("cannot reach the WARP registration service")?;
        read_json(resp, "registration").await
    }

    /// Reads the device back: its config (addresses, peer, client id) and account.
    pub async fn device(&self, id: &str, token: &str) -> Result<Device> {
        let resp = self
            .http
            .get(self.url(&format!("reg/{id}")))
            .header("CF-Client-Version", CLIENT_VERSION)
            .bearer_auth(token)
            .send()
            .await
            .context("cannot reach the WARP registration service")?;
        read_json(resp, "reading the device").await
    }

    /// Attaches a WARP+ key to the device's account.
    pub async fn set_license(&self, id: &str, token: &str, license: &str) -> Result<()> {
        let resp = self
            .http
            .put(self.url(&format!("reg/{id}/account")))
            .header("CF-Client-Version", CLIENT_VERSION)
            .bearer_auth(token)
            .json(&serde_json::json!({ "license": license }))
            .send()
            .await
            .context("cannot reach the WARP registration service")?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            bail!("the license was refused: HTTP {status}: {}", short(&text));
        }
        Ok(())
    }
}

/// A fresh WireGuard key pair: (private, public), 32 bytes each.
pub fn new_keypair() -> ([u8; 32], [u8; 32]) {
    use boringtun::x25519::{PublicKey, StaticSecret};
    let private = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let public = PublicKey::from(&private);
    (private.to_bytes(), *public.as_bytes())
}

/// Registers a new device and returns what `warp.json` keeps. This is the one
/// call that creates something at Cloudflare; callers reach it only through
/// `ostp warp register --accept-terms`.
pub async fn register_new(api: &ApiClient) -> Result<crate::store::WarpState> {
    let (private, public) = new_keypair();
    let dev = api.register(&crate::store::encode_key(&public)).await?;
    crate::store::WarpState::from_device(crate::store::encode_key(&private), &dev, rfc3339_now())
}

/// Attaches a WARP+ key, then reads the device back so that the account type
/// and config in `st` are what the service now says. The key is kept in `st`
/// only after the service accepted it.
pub async fn attach_license(api: &ApiClient, st: &mut crate::store::WarpState, license: &str) -> Result<()> {
    api.set_license(&st.device_id, &st.access_token, license).await?;
    st.license = Some(license.to_string());
    let dev = api.device(&st.device_id, &st.access_token).await?;
    st.apply_device(&dev)?;
    Ok(())
}

async fn read_json(resp: reqwest::Response, what: &str) -> Result<Device> {
    let status = resp.status();
    let text = resp.text().await.context("the answer was cut off")?;
    if !status.is_success() {
        bail!("{what} failed: HTTP {status}: {}", short(&text));
    }
    serde_json::from_str(&text).map_err(|e| anyhow!("{what}: the answer is not what was expected ({e}): {}", short(&text)))
}

fn short(s: &str) -> String {
    let s = s.trim();
    // Never echo more than a line: the body can hold tokens.
    let line: String = s.chars().take(200).collect();
    line.replace(['\n', '\r'], " ")
}

/// `2006-01-02T15:04:05.000Z`, the shape of the terms-of-service stamp.
/// (wgcf's exact format string was not retrievable; `warp-wireguard-gen`
/// sends RFC 3339 UTC with a `Z`, which this is.)
pub fn rfc3339_now() -> String {
    let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    rfc3339(d.as_secs(), d.subsec_millis())
}

pub fn rfc3339(secs: u64, millis: u32) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Civil date from days since 1970-01-01 (H. Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_is_rfc3339_utc() {
        assert_eq!(rfc3339(0, 0), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339(1_700_000_000, 5), "2023-11-14T22:13:20.005Z");
        // A leap day.
        assert_eq!(rfc3339(1_709_164_800, 0), "2024-02-29T00:00:00.000Z");
    }

    /// The shape of the registration answer as `wgcf`'s OpenAPI spec lists it
    /// (field names and nesting; the values are made up).
    const FIXTURE: &str = r#"{
        "id": "11111111-2222-3333-4444-555555555555",
        "type": "Android",
        "key": "AAAA",
        "token": "tok-secret",
        "warp_enabled": true,
        "account": { "id": "acc", "account_type": "free", "license": "lic-free-1", "warp_plus": false },
        "config": {
            "client_id": "AQID",
            "peers": [ {
                "public_key": "UEVFUi1QVUItS0VZ",
                "endpoint": { "v4": "162.159.192.1:0", "v6": "[2606:4700:d0::a29f:c001]:0", "host": "engage.cloudflareclient.com:2408" }
            } ],
            "interface": { "addresses": { "v4": "172.16.0.2", "v6": "2606:4700:110:8000::2" } },
            "services": { "http_proxy": "172.16.0.1:2480" }
        }
    }"#;

    #[test]
    fn registration_answer_parses() {
        let d: Device = serde_json::from_str(FIXTURE).unwrap();
        assert_eq!(d.id, "11111111-2222-3333-4444-555555555555");
        assert_eq!(d.token.as_deref(), Some("tok-secret"));
        let acc = d.account.unwrap();
        assert_eq!(acc.account_type.as_deref(), Some("free"));
        assert_eq!(acc.license.as_deref(), Some("lic-free-1"));
        let c = d.config.unwrap();
        assert_eq!(c.client_id.as_deref(), Some("AQID"));
        assert_eq!(c.interface.addresses.v4.as_deref(), Some("172.16.0.2"));
        assert_eq!(c.peers[0].endpoint.host.as_deref(), Some("engage.cloudflareclient.com:2408"));
        assert_eq!(c.peers[0].endpoint.v4.as_deref(), Some("162.159.192.1:0"));
    }

    #[test]
    fn answers_without_optional_parts_still_parse() {
        let d: Device = serde_json::from_str(r#"{"id":"x","config":{"interface":{"addresses":{"v4":"1.2.3.4"}},"peers":[]}}"#).unwrap();
        assert!(d.token.is_none());
        assert!(d.config.unwrap().peers.is_empty());
    }

    #[test]
    fn errors_do_not_echo_bodies_at_length() {
        let long = "x".repeat(1000);
        assert_eq!(short(&long).len(), 200);
        assert!(!short("a\nb").contains('\n'));
    }
}
