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
    #[serde(default)]
    assets: Vec<GhAsset>,
}

#[derive(Deserialize)]
struct GhAsset {
    name: String,
    size: u64,
    /// "sha256:<hex>", computed by GitHub when the file was uploaded.
    #[serde(default)]
    digest: Option<String>,
    browser_download_url: String,
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

// Installing an update of the desktop app. Nothing here runs unless the user
// pressed "Update now": the check above only tells them a release exists.

/// Files of the desktop app that an update may replace. Anything else in a
/// downloaded archive is ignored.
const APP_FILES: &[&str] = &["ostp-gui", "ostp-gui.exe", "ostp-tun-helper", "ostp-tun-helper.exe", "wintun.dll"];
/// Larger than any build of the app; a bigger answer is not ours.
const MAX_DOWNLOAD: u64 = 300 * 1024 * 1024;
const READ_STALL: std::time::Duration = std::time::Duration::from_secs(30);

/// A verified download, ready to be installed.
#[derive(Debug)]
pub struct Downloaded {
    pub path: std::path::PathBuf,
    /// The Windows installer (run it) rather than an archive (unpack it next to the app).
    pub installer: bool,
}

fn app_dir() -> Result<std::path::PathBuf> {
    let exe = std::env::current_exe()?;
    Ok(exe.parent().ok_or_else(|| anyhow::anyhow!("cannot tell where the app is"))?.to_path_buf())
}

/// True when the app runs from the Windows installer's folder (it leaves an
/// uninstaller there); the portable zip has none.
pub fn installed_by_setup() -> bool {
    cfg!(windows) && app_dir().map(|d| d.join("uninstall.exe").exists()).unwrap_or(false)
}

/// The release file of the desktop app for this system.
fn app_asset_name(installer: bool) -> Option<String> {
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        _ => return None,
    };
    match std::env::consts::OS {
        "windows" if installer => Some(format!("ostp-windows-gui-{arch}-setup.exe")),
        "windows" => Some(format!("ostp-windows-gui-{arch}.zip")),
        "linux" => Some(format!("ostp-linux-gui-{arch}.tar.gz")),
        "macos" => Some(format!("ostp-macos-gui-{arch}.tar.gz")),
        _ => None,
    }
}

/// Downloads this system's build of release `tag` and checks it against the
/// SHA-256 GitHub published for it. `progress` gets (bytes so far, total).
pub async fn download_app_update(tag: &str, mut progress: impl FnMut(u64, u64)) -> Result<Downloaded> {
    let current = Version::parse(&build_tag()).ok_or_else(|| anyhow::anyhow!("cannot read this build's version"))?;
    let wanted = Version::parse(tag).ok_or_else(|| anyhow::anyhow!("not a release tag: {tag}"))?;
    if !tag.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-') {
        bail!("not a release tag: {tag}");
    }
    if wanted <= current {
        bail!("{tag} is not newer than this build ({})", build_tag());
    }

    let installer = installed_by_setup();
    let name = app_asset_name(installer).ok_or_else(|| anyhow::anyhow!("there is no desktop build for this system"))?;
    let url = format!("https://api.github.com/repos/ospab/ostp/releases/tags/{tag}");
    let (code, body) = crate::subscription::https_get(&url, "application/vnd.github+json").await?;
    match code {
        200 => {}
        404 => bail!("GitHub has no release {tag}"),
        403 | 429 => bail!("GitHub is rate-limiting requests from this address; try again later"),
        _ => bail!("GitHub answered HTTP {code}"),
    }
    let release: GhRelease = serde_json::from_slice(&body)?;
    let asset = release
        .assets
        .into_iter()
        .find(|a| a.name == name)
        .ok_or_else(|| anyhow::anyhow!("release {tag} has no {name}"))?;
    // Without the published hash nothing proves the file is the one CI built.
    let sha = asset
        .digest
        .as_deref()
        .and_then(|d| d.strip_prefix("sha256:"))
        .filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| anyhow::anyhow!("GitHub gives no SHA-256 for {name}; not installing it"))?
        .to_ascii_lowercase();
    if asset.size == 0 || asset.size > MAX_DOWNLOAD {
        bail!("{name} has an unexpected size ({} bytes)", asset.size);
    }

    let dir = std::env::temp_dir().join(format!("ostp-update-{tag}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(&name);
    download_verified(&asset.browser_download_url, &path, asset.size, &sha, &mut progress).await?;
    Ok(Downloaded { path, installer })
}

async fn download_verified(
    url: &str,
    dest: &std::path::Path,
    size: u64,
    sha: &str,
    progress: &mut impl FnMut(u64, u64),
) -> Result<()> {
    use sha2::{Digest, Sha256};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut url = url.to_string();
    for _ in 0..5 {
        let u = crate::subscription::parse_url(&url)?;
        // GitHub sends release files from its own CDN. The hash is what makes
        // the file trustworthy; the host check only keeps the request on GitHub.
        if u.host != "github.com" && !u.host.ends_with(".githubusercontent.com") {
            bail!("the download was redirected to {}, which is not GitHub", u.host);
        }
        let tcp = tokio::time::timeout(READ_STALL, tokio::net::TcpStream::connect((u.host.as_str(), u.port)))
            .await
            .map_err(|_| anyhow::anyhow!("{} did not answer", u.host))??;
        let opts = crate::transport::tls::TlsClientOptions { sni: u.host.clone(), insecure: false };
        let mut s = crate::transport::tls::wrap_tls(tcp, &opts, READ_STALL).await?;
        let req = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nAccept: application/octet-stream\r\nUser-Agent: ostp/{}\r\nConnection: close\r\n\r\n",
            u.target,
            u.host,
            env!("CARGO_PKG_VERSION")
        );
        s.write_all(req.as_bytes()).await?;
        s.flush().await?;

        let mut buf = Vec::with_capacity(16 * 1024);
        let mut chunk = vec![0u8; 64 * 1024];
        let head_len = loop {
            let n = tokio::time::timeout(READ_STALL, s.read(&mut chunk))
                .await
                .map_err(|_| anyhow::anyhow!("{} stopped answering", u.host))??;
            if n == 0 {
                bail!("{} closed the connection before answering", u.host);
            }
            buf.extend_from_slice(&chunk[..n]);
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
            if buf.len() > 64 * 1024 {
                bail!("the answer from {} has no end of headers", u.host);
            }
        };
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut resp = httparse::Response::new(&mut headers);
        resp.parse(&buf[..head_len]).map_err(|e| anyhow::anyhow!("not an HTTP response: {e}"))?;
        let code = resp.code.unwrap_or(0);
        let header = |name: &str| {
            resp.headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case(name))
                .and_then(|h| std::str::from_utf8(h.value).ok())
                .map(|v| v.trim().to_string())
        };
        if matches!(code, 301 | 302 | 303 | 307 | 308) {
            let loc = header("location").ok_or_else(|| anyhow::anyhow!("a redirect without a location"))?;
            url = if loc.starts_with('/') { format!("https://{}{loc}", u.host) } else { loc };
            continue;
        }
        if code != 200 {
            bail!("{} answered HTTP {code}", u.host);
        }
        let chunked = header("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));

        // A plain file: the caller runs this on its own thread, and writes are local.
        let mut file = std::fs::File::create(dest)?;
        let mut hasher = Sha256::new();
        let mut got: u64 = 0;
        let mut pending = buf.split_off(head_len);
        let mut dechunk = Dechunk::default();
        loop {
            let data = if chunked { dechunk.feed(&pending)? } else { std::mem::take(&mut pending) };
            pending.clear();
            if !data.is_empty() {
                got += data.len() as u64;
                if got > size {
                    bail!("the download is larger than GitHub said ({size} bytes)");
                }
                hasher.update(&data);
                std::io::Write::write_all(&mut file, &data)?;
                progress(got, size);
            }
            if got == size || (chunked && dechunk.done) {
                break;
            }
            let n = tokio::time::timeout(READ_STALL, s.read(&mut chunk))
                .await
                .map_err(|_| anyhow::anyhow!("the download stalled for {} seconds", READ_STALL.as_secs()))?;
            match n {
                Ok(0) => break,
                Ok(n) => pending.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e.into()),
            }
        }
        file.sync_all()?;
        drop(file);
        if got != size {
            let _ = std::fs::remove_file(dest);
            bail!("the download was cut short ({got} of {size} bytes)");
        }
        let hex: String = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();
        if hex != sha {
            let _ = std::fs::remove_file(dest);
            bail!("the downloaded file does not match the SHA-256 GitHub published; not installing it");
        }
        return Ok(());
    }
    bail!("too many redirects")
}

/// Incremental decoder for `Transfer-Encoding: chunked`.
#[derive(Default)]
struct Dechunk {
    buf: Vec<u8>,
    /// Bytes left in the current chunk, then its trailing CRLF.
    left: usize,
    in_chunk: bool,
    done: bool,
}

impl Dechunk {
    fn feed(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        self.buf.extend_from_slice(input);
        let mut out = Vec::new();
        loop {
            if self.done {
                return Ok(out);
            }
            if self.in_chunk {
                let take = self.left.min(self.buf.len());
                out.extend(self.buf.drain(..take));
                self.left -= take;
                if self.left > 0 || self.buf.len() < 2 {
                    return Ok(out);
                }
                self.buf.drain(..2);
                self.in_chunk = false;
            }
            let Some(end) = self.buf.windows(2).position(|w| w == b"\r\n") else {
                if self.buf.len() > 1024 {
                    bail!("bad chunked encoding");
                }
                return Ok(out);
            };
            let line = std::str::from_utf8(&self.buf[..end]).map_err(|_| anyhow::anyhow!("bad chunk size"))?;
            let size = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16)
                .map_err(|_| anyhow::anyhow!("bad chunk size"))?;
            self.buf.drain(..end + 2);
            if size == 0 {
                self.done = true;
            } else {
                self.left = size;
                self.in_chunk = true;
            }
        }
    }
}

/// Unpacks a downloaded archive and puts its app files next to the running
/// app. The running files are renamed to `.old` first (Windows does not let a
/// running program be overwritten, but does let it be renamed) and put back if
/// a later step fails. Returns the path of the new app to start.
pub fn apply_app_archive(archive: &std::path::Path) -> Result<std::path::PathBuf> {
    use anyhow::Context;
    let dir = app_dir()?;
    let probe = dir.join(".ostp-update-probe");
    std::fs::write(&probe, b"").with_context(|| {
        format!("cannot write to {}; update it by hand or give this account write access there", dir.display())
    })?;
    let _ = std::fs::remove_file(&probe);

    let unpacked = archive.with_extension("unpacked");
    let _ = std::fs::remove_dir_all(&unpacked);
    std::fs::create_dir_all(&unpacked)?;
    // The system tar reads both .zip (Windows 10 and later) and .tar.gz. The
    // full path on Windows keeps a tar.exe in the current folder from being picked.
    let tar = if cfg!(windows) {
        std::path::PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()))
            .join("System32")
            .join("tar.exe")
    } else {
        std::path::PathBuf::from("tar")
    };
    let status = std::process::Command::new(&tar)
        .arg("-xf")
        .arg(archive)
        .arg("-C")
        .arg(&unpacked)
        .status()
        .with_context(|| format!("cannot run {}", tar.display()))?;
    if !status.success() {
        bail!("cannot unpack {}", archive.display());
    }

    let mut found = Vec::new();
    collect_app_files(&unpacked, &mut found, 0)?;
    let exe_name = if cfg!(windows) { "ostp-gui.exe" } else { "ostp-gui" };
    if !found.iter().any(|(name, _)| name == exe_name) {
        bail!("the archive has no {exe_name}");
    }

    // Stage every file next to its target first, so a full disk fails before
    // anything running was touched.
    let mut staged = Vec::new();
    for (name, src) in &found {
        let new = dir.join(format!("{name}.new"));
        std::fs::copy(src, &new).with_context(|| format!("cannot copy {name} into {}", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&new, std::fs::Permissions::from_mode(0o755))?;
        }
        staged.push((name.clone(), new));
    }
    let mut swapped: Vec<(std::path::PathBuf, Option<std::path::PathBuf>)> = Vec::new();
    for (name, new) in &staged {
        let target = dir.join(name);
        let old = dir.join(format!("{name}.old"));
        let result = (|| -> std::io::Result<Option<std::path::PathBuf>> {
            let moved = if target.exists() {
                let _ = std::fs::remove_file(&old);
                std::fs::rename(&target, &old)?;
                Some(old.clone())
            } else {
                None
            };
            if let Err(e) = std::fs::rename(new, &target) {
                if let Some(o) = &moved {
                    let _ = std::fs::rename(o, &target);
                }
                return Err(e);
            }
            Ok(moved)
        })();
        match result {
            Ok(moved) => swapped.push((target, moved)),
            Err(e) => {
                for (t, o) in swapped.into_iter().rev() {
                    let _ = std::fs::remove_file(&t);
                    if let Some(o) = o {
                        let _ = std::fs::rename(o, &t);
                    }
                }
                for (_, n) in &staged {
                    let _ = std::fs::remove_file(n);
                }
                return Err(anyhow::anyhow!("cannot replace {name}: {e}; the previous version was kept"));
            }
        }
    }
    let _ = std::fs::remove_dir_all(&unpacked);
    Ok(dir.join(exe_name))
}

fn collect_app_files(dir: &std::path::Path, out: &mut Vec<(String, std::path::PathBuf)>, depth: u32) -> Result<()> {
    if depth > 3 {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let path = entry.path();
        if kind.is_dir() {
            collect_app_files(&path, out, depth + 1)?;
        } else if kind.is_file() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if APP_FILES.contains(&name.as_str()) && !out.iter().any(|(n, _)| *n == name) {
                out.push((name, path));
            }
        }
    }
    Ok(())
}

/// Removes the `.old` files a previous update left next to the app (they
/// could not be deleted while they were running).
pub fn remove_update_leftovers() {
    if let Ok(dir) = app_dir() {
        for name in APP_FILES {
            let _ = std::fs::remove_file(dir.join(format!("{name}.old")));
        }
    }
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

    #[test]
    fn chunked_body_split_anywhere_decodes_the_same() {
        let wire = b"4\r\nWiki\r\n5;ext=1\r\npedia\r\n0\r\n\r\n";
        for cut in 0..wire.len() {
            let mut d = Dechunk::default();
            let mut out = d.feed(&wire[..cut]).unwrap();
            out.extend(d.feed(&wire[cut..]).unwrap());
            assert_eq!(out, b"Wikipedia", "cut at {cut}");
            assert!(d.done);
        }
        let mut d = Dechunk::default();
        assert!(d.feed(b"zz\r\n").is_err());
    }
}
