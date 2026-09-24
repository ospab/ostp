//! Block and allow lists: downloaded, cached on disk (so a restart filters
//! at once, even offline), and compiled into one `Filter`.

use anyhow::{bail, Result};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::filter::Filter;
use crate::settings::DnsSettings;

const MAX_LIST_BYTES: usize = 64 * 1024 * 1024;

fn fnv(s: &str) -> u64 {
    s.bytes().fold(0xcbf29ce484222325u64, |h, b| (h ^ b as u64).wrapping_mul(0x100000001b3))
}

pub fn lists_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("dns").join("lists")
}

pub fn cache_path(data_dir: &Path, url: &str) -> PathBuf {
    lists_dir(data_dir).join(format!("{:016x}.txt", fnv(url)))
}

/// How long ago the list was downloaded, if it ever was.
pub fn age(data_dir: &Path, url: &str) -> Option<Duration> {
    let m = std::fs::metadata(cache_path(data_dir, url)).ok()?.modified().ok()?;
    SystemTime::now().duration_since(m).ok()
}

async fn download(client: &reqwest::Client, url: &str) -> Result<String> {
    let resp = client.get(url).send().await?;
    if !resp.status().is_success() {
        bail!("HTTP {}", resp.status());
    }
    if resp.content_length().is_some_and(|l| l as usize > MAX_LIST_BYTES) {
        bail!("larger than {} MB", MAX_LIST_BYTES >> 20);
    }
    let bytes = resp.bytes().await?;
    if bytes.len() > MAX_LIST_BYTES {
        bail!("larger than {} MB", MAX_LIST_BYTES >> 20);
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[derive(Debug, Clone, Serialize)]
pub struct UpdateResult {
    pub name: String,
    pub url: String,
    pub ok: bool,
    pub detail: String,
}

/// Downloads every enabled list; a failed download keeps the cached copy.
pub async fn update_all(settings: &DnsSettings, data_dir: &Path, proxy: Option<&str>) -> Vec<UpdateResult> {
    let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(180)).user_agent(concat!("ostp-dns/", env!("CARGO_PKG_VERSION")));
    if let Some(p) = proxy {
        if let Ok(px) = reqwest::Proxy::all(p) {
            builder = builder.proxy(px);
        }
    }
    let client = match builder.build() {
        Ok(c) => c,
        Err(e) => return vec![UpdateResult { name: "-".into(), url: "-".into(), ok: false, detail: e.to_string() }],
    };
    let _ = std::fs::create_dir_all(lists_dir(data_dir));
    let mut out = Vec::new();
    for l in settings.lists.iter().chain(settings.allowlists.iter()).filter(|l| l.enabled) {
        let r = match download(&client, &l.url).await {
            Ok(text) => {
                let path = cache_path(data_dir, &l.url);
                let tmp = path.with_extension("tmp");
                match std::fs::write(&tmp, &text).and_then(|_| std::fs::rename(&tmp, &path)) {
                    Ok(()) => UpdateResult { name: l.name.clone(), url: l.url.clone(), ok: true, detail: format!("{} KB", text.len() / 1024) },
                    Err(e) => UpdateResult { name: l.name.clone(), url: l.url.clone(), ok: false, detail: format!("cannot save: {e}") },
                }
            }
            Err(e) => UpdateResult { name: l.name.clone(), url: l.url.clone(), ok: false, detail: format!("{e:#}") },
        };
        if !r.ok {
            tracing::warn!("DNS list {} ({}): {}", r.name, r.url, r.detail);
        }
        out.push(r);
    }
    out
}

/// Whether any enabled list is missing or older than the update interval.
pub fn update_due(settings: &DnsSettings, data_dir: &Path) -> bool {
    let max = Duration::from_secs(settings.update_interval_hours.max(1) as u64 * 3600);
    settings
        .lists
        .iter()
        .chain(settings.allowlists.iter())
        .filter(|l| l.enabled)
        .any(|l| age(data_dir, &l.url).map_or(true, |a| a >= max))
}

/// The filter from cached lists and the user's own rules.
pub fn build_filter(settings: &DnsSettings, data_dir: Option<&Path>) -> Filter {
    let mut f = Filter::new();
    if let Some(dir) = data_dir {
        for l in settings.lists.iter().filter(|l| l.enabled) {
            let text = std::fs::read_to_string(cache_path(dir, &l.url)).unwrap_or_default();
            f.add_source(&l.name, &text, false);
        }
        for l in settings.allowlists.iter().filter(|l| l.enabled) {
            let text = std::fs::read_to_string(cache_path(dir, &l.url)).unwrap_or_default();
            f.add_source(&l.name, &text, true);
        }
    }
    f.add_source("user rules", &settings.user_rules.join("\n"), false);
    f
}
