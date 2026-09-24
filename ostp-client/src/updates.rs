//! Update check: which release this build is, and whether a newer stable or
//! beta release exists on GitHub.
//!
//! The build's own release comes from `.release-state.json`, which
//! `scripts/gha.ps1` commits with every release (version, channel,
//! iteration): the app version alone is "0.4.6" for every alpha, beta and
//! the stable release, so it cannot tell them apart.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

const RELEASES_API: &str = "https://api.github.com/repos/ospab/ostp/releases?per_page=15";
const RELEASE_STATE: &str = include_str!("../../.release-state.json");

#[derive(Deserialize)]
struct ReleaseState {
    target_version: String,
    branch: String,
    #[serde(default)]
    alpha_iteration: u32,
    #[serde(default)]
    beta_iteration: u32,
}

/// The release tag this build was cut from, e.g. "v0.4.6-beta.2".
pub fn build_tag() -> String {
    match serde_json::from_str::<ReleaseState>(RELEASE_STATE) {
        Ok(s) => match s.branch.as_str() {
            "alpha" => format!("v{}-alpha.{}", s.target_version, s.alpha_iteration),
            "beta" => format!("v{}-beta.{}", s.target_version, s.beta_iteration),
            _ => format!("v{}", s.target_version),
        },
        Err(_) => format!("v{}", env!("CARGO_PKG_VERSION")),
    }
}

/// A parsed tag: numbers, then the pre-release channel (none = stable).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    /// (channel rank: alpha 0, beta 1; iteration); None for a stable release.
    pub pre: Option<(u8, u32)>,
}

impl Version {
    pub fn parse(tag: &str) -> Option<Self> {
        let t = tag.trim().trim_start_matches('v');
        let (core, pre) = match t.split_once('-') {
            Some((c, p)) => (c, Some(p)),
            None => (t, None),
        };
        let mut n = core.split('.').map(|x| x.parse::<u32>().ok());
        let (major, minor, patch) = (n.next()??, n.next()??, n.next().flatten().unwrap_or(0));
        let pre = match pre {
            None => None,
            Some(p) => {
                let (ch, it) = p.split_once('.').unwrap_or((p, "0"));
                let rank = match ch {
                    "alpha" => 0,
                    "beta" => 1,
                    "rc" => 2,
                    _ => return None,
                };
                Some((rank, it.parse().ok()?))
            }
        };
        Some(Version { major, minor, patch, pre })
    }

    pub fn channel(&self) -> &'static str {
        match self.pre {
            None => "stable",
            Some((0, _)) => "alpha",
            Some((1, _)) => "beta",
            Some(_) => "rc",
        }
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| match (&self.pre, &other.pre) {
                // A release is newer than any of its own pre-releases.
                (None, None) => Ordering::Equal,
                (None, Some(_)) => Ordering::Greater,
                (Some(_), None) => Ordering::Less,
                (Some(a), Some(b)) => a.cmp(b),
            })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Release {
    pub tag: String,
    pub channel: &'static str,
    pub url: String,
    pub published_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UpdateCheck {
    pub current: String,
    pub current_channel: &'static str,
    /// Newest stable release newer than this build.
    pub stable: Option<Release>,
    /// Newest beta newer than this build and than `stable`.
    pub beta: Option<Release>,
}

#[derive(Deserialize)]
struct GhRelease {
    tag_name: String,
    html_url: String,
    #[serde(default)]
    draft: bool,
    published_at: Option<String>,
}

/// Picks the updates to offer from a list of release tags (alpha releases
/// are never offered).
fn pick(current: &Version, releases: &[(Version, Release)]) -> (Option<Release>, Option<Release>) {
    let newest = |channel: &str| {
        releases
            .iter()
            .filter(|(v, _)| v.channel() == channel && v > current)
            .max_by(|a, b| a.0.cmp(&b.0))
    };
    let stable = newest("stable");
    let beta = newest("beta").filter(|(bv, _)| stable.map_or(true, |(sv, _)| bv > sv));
    (stable.map(|s| s.1.clone()), beta.map(|b| b.1.clone()))
}

pub async fn check() -> Result<UpdateCheck> {
    let current_tag = build_tag();
    let Some(current) = Version::parse(&current_tag) else { bail!("cannot read this build's version ({current_tag})") };
    let (code, body) = crate::subscription::https_get(RELEASES_API, "application/vnd.github+json").await?;
    match code {
        200 => {}
        403 | 429 => bail!("GitHub is rate-limiting update checks from this address; try again later"),
        _ => bail!("GitHub answered HTTP {code}"),
    }
    let list: Vec<GhRelease> = serde_json::from_slice(&body)?;
    let releases: Vec<(Version, Release)> = list
        .into_iter()
        .filter(|r| !r.draft)
        .filter_map(|r| {
            let v = Version::parse(&r.tag_name)?;
            let channel = v.channel();
            Some((v, Release { tag: r.tag_name, channel, url: r.html_url, published_at: r.published_at }))
        })
        .collect();
    let (stable, beta) = pick(&current, &releases);
    Ok(UpdateCheck { current: current_tag, current_channel: current.channel(), stable, beta })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    #[test]
    fn ordering() {
        assert!(v("v0.4.6") > v("v0.4.6-beta.9"));
        assert!(v("v0.4.6-beta.2") > v("v0.4.6-beta.1"));
        assert!(v("v0.4.6-beta.1") > v("v0.4.6-alpha.9"));
        assert!(v("v0.4.7-alpha.1") > v("v0.4.6"));
        assert!(v("v0.5.0") > v("v0.4.10"));
        assert_eq!(v("v0.4.6").channel(), "stable");
        assert_eq!(v("0.4.6-beta.3").channel(), "beta");
        assert!(Version::parse("nightly").is_none());
    }

    #[test]
    fn offers_newer_stable_and_a_beta_only_above_it() {
        let rel = |t: &str| (v(t), Release { tag: t.into(), channel: v(t).channel(), url: String::new(), published_at: None });
        let list = vec![rel("v0.4.5"), rel("v0.4.6-alpha.4"), rel("v0.4.6-beta.2"), rel("v0.4.6-beta.3"), rel("v0.4.6")];
        // On beta.2: stable 0.4.6 is newer; beta.3 is older than that stable.
        let (s, b) = pick(&v("v0.4.6-beta.2"), &list);
        assert_eq!(s.unwrap().tag, "v0.4.6");
        assert!(b.is_none());
        // On 0.4.5: 0.4.6 stable, no beta above it.
        let (s, b) = pick(&v("v0.4.5"), &list[..4]);
        assert!(s.is_none());
        assert_eq!(b.unwrap().tag, "v0.4.6-beta.3");
        // Alphas are never offered; nothing newer than the newest.
        let (s, b) = pick(&v("v0.4.6"), &list);
        assert!(s.is_none() && b.is_none());
    }

    #[test]
    fn this_build_has_a_tag() {
        assert!(Version::parse(&build_tag()).is_some(), "{}", build_tag());
    }
}
