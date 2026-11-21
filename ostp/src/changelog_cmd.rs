//! `ostp changelog` (`ostp cl`): what changed, from CHANGELOG.md /
//! CHANGELOG.ru.md built into the binary, so it works offline and always
//! matches the build.

use anyhow::{bail, Result};
use colored::Colorize;

const EN: &str = include_str!("../../CHANGELOG.md");
const RU: &str = include_str!("../../CHANGELOG.ru.md");

/// One `## [...]` section.
#[derive(Debug, PartialEq)]
struct Release<'a> {
    /// The heading after `## `, e.g. `[0.4.6-beta.5] - 2026-09-27`.
    heading: &'a str,
    /// `0.4.6-beta.5`; `None` for the unreleased section.
    version: Option<&'a str>,
    body: &'a str,
}

fn parse(text: &str) -> Vec<Release<'_>> {
    let mut releases = Vec::new();
    let mut starts: Vec<(usize, usize)> = Vec::new(); // (heading start, body start)
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        if line.starts_with("## [") {
            starts.push((offset, offset + line.len()));
        }
        offset += line.len();
    }
    for (i, &(head, body)) in starts.iter().enumerate() {
        let end = starts.get(i + 1).map_or(text.len(), |&(next, _)| next);
        let heading = text[head + 3..body].trim();
        let name = heading
            .strip_prefix('[')
            .and_then(|h| h.split(']').next())
            .unwrap_or("");
        // A version starts with a digit; anything else ("Unreleased",
        // "Не выпущено") is the section of changes not released yet.
        let version = name.starts_with(|c: char| c.is_ascii_digit()).then_some(name);
        releases.push(Release { heading, version, body: text[body..end].trim() });
    }
    releases
}

/// `wanted` matches itself and, when it has no pre-release part, every
/// pre-release of it: `0.4.6` matches `0.4.6-beta.5`.
fn version_matches(version: &str, wanted: &str) -> bool {
    version == wanted || (!wanted.contains('-') && version.starts_with(&format!("{wanted}-")))
}

#[derive(Debug, Default)]
pub struct Options {
    pub all: bool,
    pub last: Option<usize>,
    pub version: Option<String>,
    pub lang: Option<String>,
}

fn select<'r, 'a>(releases: &'r [Release<'a>], installed: &str, opts: &Options) -> Result<Vec<&'r Release<'a>>> {
    let non_empty = |r: &&Release| !r.body.is_empty();
    if opts.all {
        return Ok(releases.iter().filter(non_empty).collect());
    }
    if let Some(n) = opts.last {
        return Ok(releases.iter().filter(non_empty).take(n.max(1)).collect());
    }
    if let Some(wanted) = &opts.version {
        let wanted = wanted.trim().trim_start_matches('v');
        let found: Vec<_> = releases
            .iter()
            .filter(|r| r.version.is_some_and(|v| version_matches(v, wanted)))
            .collect();
        if found.is_empty() {
            let known: Vec<_> = releases.iter().filter_map(|r| r.version).collect();
            bail!("no changelog entry for {wanted}; known versions: {}", known.join(", "));
        }
        return Ok(found);
    }
    // Default: what this build contains. `installed` is the build's own
    // version with its channel ("0.5.0-alpha.5"): its entry, or when the
    // changelog has none for that pre-release, every entry of X.Y.Z; plus
    // changes not released yet (the development branch).
    let core = installed.split('-').next().unwrap_or(installed);
    let has_own = releases.iter().any(|r| r.version.is_some_and(|v| version_matches(v, installed)));
    let wanted = if has_own { installed } else { core };
    let mut found: Vec<_> = releases
        .iter()
        .filter(|r| match r.version {
            Some(v) => version_matches(v, wanted),
            None => !r.body.is_empty(),
        })
        .collect();
    if found.iter().all(|r| r.version.is_none()) {
        // An older build than the newest entry, or a gap: show the latest release.
        found.extend(releases.iter().find(|r| r.version.is_some()));
    }
    Ok(found)
}

/// `ru` when the system language is Russian, `en` otherwise.
fn system_lang() -> &'static str {
    for var in ["LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE"] {
        if let Ok(value) = std::env::var(var) {
            if !value.is_empty() {
                return if value.to_ascii_lowercase().starts_with("ru") { "ru" } else { "en" };
            }
        }
    }
    #[cfg(windows)]
    {
        // Primary language id 0x19 is Russian.
        let lang = unsafe { winapi::um::winnls::GetUserDefaultUILanguage() };
        if lang & 0x3ff == 0x19 {
            return "ru";
        }
    }
    "en"
}

fn print_release(release: &Release) {
    println!("{}", format!("== {} ==", release.heading).bold().cyan());
    for line in release.body.lines() {
        if let Some(section) = line.strip_prefix("### ") {
            println!("{}", section.bold());
        } else {
            println!("{line}");
        }
    }
    println!();
}

pub fn run(opts: Options) -> Result<()> {
    let lang = match opts.lang.as_deref().map(str::to_ascii_lowercase) {
        Some(l) if l == "ru" => "ru",
        Some(l) if l == "en" => "en",
        Some(other) => bail!("unknown language {other:?}; use en or ru"),
        None => system_lang(),
    };
    let text = if lang == "ru" { RU } else { EN };
    let releases = parse(text);
    let installed = ostp_client::updates::version();
    for release in select(&releases, installed, &opts)? {
        print_release(release);
    }
    if !opts.all && opts.last.is_none() && opts.version.is_none() {
        let hint = if lang == "ru" {
            "Все версии: ostp cl --all · последние N: ostp cl --last N"
        } else {
            "Every version: ostp cl --all · the last N: ostp cl --last N"
        };
        println!("{}", hint.dimmed());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "# Changelog\n\nintro\n\n## [Unreleased]\n\n### Added\n- next\n\n\
        ## [0.4.6-beta.2] - 2026-09-24\n\n### Fixed\n- b2\n\n\
        ## [0.4.6-beta.1] - 2026-09-24\n\n- b1\n\n\
        ## [0.4.5] - 2026-09-23\n\n- old\n";

    fn versions(selected: &[&Release]) -> Vec<Option<String>> {
        selected.iter().map(|r| r.version.map(str::to_string)).collect()
    }

    #[test]
    fn parses_sections_and_versions() {
        let r = parse(SAMPLE);
        assert_eq!(r.len(), 4);
        assert_eq!(r[0].version, None);
        assert_eq!(r[0].body, "### Added\n- next");
        assert_eq!(r[1].version, Some("0.4.6-beta.2"));
        assert_eq!(r[1].heading, "[0.4.6-beta.2] - 2026-09-24");
        assert_eq!(r[3].body, "- old");
    }

    #[test]
    fn default_is_the_installed_version_and_unreleased_changes() {
        let r = parse(SAMPLE);
        let got = select(&r, "0.4.6", &Options::default()).unwrap();
        assert_eq!(
            versions(&got),
            vec![None, Some("0.4.6-beta.2".into()), Some("0.4.6-beta.1".into())]
        );
    }

    #[test]
    fn unknown_installed_version_falls_back_to_the_latest_release() {
        let r = parse(SAMPLE);
        let got = select(&r, "0.3.0", &Options::default()).unwrap();
        assert_eq!(versions(&got), vec![None, Some("0.4.6-beta.2".into())]);
    }

    #[test]
    fn version_last_and_all() {
        let r = parse(SAMPLE);
        let one = |v: &str| Options { version: Some(v.into()), ..Default::default() };
        assert_eq!(versions(&select(&r, "0.4.6", &one("v0.4.5")).unwrap()), vec![Some("0.4.5".into())]);
        assert_eq!(select(&r, "0.4.6", &one("0.4.6")).unwrap().len(), 2);
        assert_eq!(select(&r, "0.4.6", &one("0.4.6-beta.1")).unwrap().len(), 1);
        assert!(select(&r, "0.4.6", &one("9.9.9")).is_err());

        let last = Options { last: Some(2), ..Default::default() };
        assert_eq!(select(&r, "0.4.6", &last).unwrap().len(), 2);
        let all = Options { all: true, ..Default::default() };
        assert_eq!(select(&r, "0.4.6", &all).unwrap().len(), 4);
    }

    #[test]
    fn an_empty_unreleased_section_is_not_shown() {
        let text = SAMPLE.replace("### Added\n- next\n\n", "");
        let r = parse(&text);
        let got = select(&r, "0.4.6", &Options::default()).unwrap();
        assert_eq!(got[0].version, Some("0.4.6-beta.2"));
    }

    /// Both languages must list the same versions in the same order, or
    /// `ostp cl` would show different histories depending on the locale.
    #[test]
    fn english_and_russian_changelogs_have_the_same_versions() {
        let en: Vec<_> = parse(EN).into_iter().map(|r| r.version).collect();
        let ru: Vec<_> = parse(RU).into_iter().map(|r| r.version).collect();
        assert_eq!(en, ru);
        assert!(en.len() > 1);
    }
}
