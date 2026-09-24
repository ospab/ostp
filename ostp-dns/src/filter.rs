//! Block and allow rules: adblock-style DNS syntax and hosts files.
//!
//! Supported: `||example.org^` (the domain and its subdomains), `|example.org^`
//! (only that name), a bare `example.org` (with subdomains), `*` wildcards,
//! `@@` exceptions, `$important`, and hosts lines (`0.0.0.0 example.org`
//! blocks that name; a real address answers with it). Rules with other
//! modifiers and `/regex/` rules are counted as unsupported, not applied.

use serde::Serialize;
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Block,
    Allow,
    Important,
}

#[derive(Debug, Clone, Copy)]
struct Origin {
    source: u16,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Match {
    /// The rule as it matched, e.g. "||ads.example.org^".
    pub rule: String,
    /// The list it came from ("user rules" for your own).
    pub source: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Verdict {
    Blocked(Match),
    Allowed(Match),
    None,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct SourceStats {
    pub name: String,
    pub rules: usize,
    pub unsupported: usize,
}

#[derive(Default)]
pub struct Filter {
    suffix: [HashMap<String, Origin>; 3],
    exact: [HashMap<String, Origin>; 3],
    wild: [Vec<(String, bool, Origin)>; 3],
    /// Hosts lines with a real address: name -> addresses.
    pub host_answers: HashMap<String, Vec<IpAddr>>,
    pub sources: Vec<SourceStats>,
}

fn idx(k: Kind) -> usize {
    match k {
        Kind::Block => 0,
        Kind::Allow => 1,
        Kind::Important => 2,
    }
}

fn is_domain(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.contains('.')
        && !s.starts_with('.')
        && !s.ends_with('.')
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'))
}

/// `*` matches any run of characters.
fn glob(pattern: &str, text: &str) -> bool {
    let (p, t) = (pattern.as_bytes(), text.as_bytes());
    let (mut pi, mut ti, mut star, mut mark) = (0usize, 0usize, None::<usize>, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

const HOSTS_SKIP: &[&str] = &["localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost", "ip6-loopback", "0.0.0.0"];

impl Filter {
    pub fn new() -> Self {
        Self::default()
    }

    fn add(&mut self, kind: Kind, key: String, exact: bool, wildcard: bool, source: u16) {
        let o = Origin { source };
        let i = idx(kind);
        if wildcard {
            self.wild[i].push((key, exact, o));
        } else if exact {
            self.exact[i].insert(key, o);
        } else {
            self.suffix[i].insert(key, o);
        }
    }

    /// Adds every rule of one list; `force_allow` for allow lists.
    pub fn add_source(&mut self, name: &str, text: &str, force_allow: bool) {
        let source = self.sources.len() as u16;
        let mut stats = SourceStats { name: name.to_string(), ..Default::default() };
        for raw in text.lines() {
            match self.add_line(raw.trim(), source, force_allow) {
                Some(true) => stats.rules += 1,
                Some(false) => stats.unsupported += 1,
                None => {}
            }
        }
        self.sources.push(stats);
    }

    /// Some(true) added, Some(false) unsupported, None a comment or blank.
    fn add_line(&mut self, line: &str, source: u16, force_allow: bool) -> Option<bool> {
        if line.is_empty() || line.starts_with('!') || line.starts_with('#') || line.starts_with('[') {
            return None;
        }
        // Cosmetic (page) rules mean nothing to DNS.
        if line.contains("##") || line.contains("#@#") || line.contains("#?#") || line.contains("#$#") {
            return None;
        }
        let line = line.split(" #").next().unwrap_or(line).trim();

        // hosts format
        let mut parts = line.split_whitespace();
        if let Some(first) = parts.next() {
            if let Ok(ip) = first.parse::<IpAddr>() {
                let names: Vec<String> = parts.map(|n| n.to_ascii_lowercase()).filter(|n| !HOSTS_SKIP.contains(&n.as_str())).collect();
                if names.is_empty() {
                    return None;
                }
                let blackhole = ip.is_unspecified() || ip.is_loopback();
                for n in names {
                    if !is_domain(&n) && !n.ends_with(".ostp") && !n.ends_with(".lan") {
                        continue;
                    }
                    if blackhole && !force_allow {
                        self.add(Kind::Block, n, true, false, source);
                    } else if !blackhole {
                        self.host_answers.entry(n).or_default().push(ip);
                    }
                }
                return Some(true);
            }
        }

        let (allow, body) = match line.strip_prefix("@@") {
            Some(rest) => (true, rest),
            None => (force_allow, line),
        };
        let (pattern, modifiers) = match body.split_once('$') {
            Some((p, m)) => (p, Some(m)),
            None => (body, None),
        };
        let important = match modifiers {
            None => false,
            Some(m) if m.split(',').all(|x| x.trim() == "important") => true,
            Some(_) => return Some(false),
        };
        if pattern.starts_with('/') && pattern.ends_with('/') && pattern.len() > 1 {
            return Some(false);
        }
        let kind = if allow { Kind::Allow } else if important { Kind::Important } else { Kind::Block };
        let lower = pattern.to_ascii_lowercase();
        let (core, exact) = if let Some(rest) = lower.strip_prefix("||") {
            (rest.trim_end_matches('|').trim_end_matches('^'), false)
        } else if let Some(rest) = lower.strip_prefix('|') {
            (rest.trim_end_matches('|').trim_end_matches('^'), true)
        } else {
            (lower.trim_end_matches('^'), false)
        };
        if core.contains('*') {
            if core.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '*')) {
                self.add(kind, core.to_string(), exact, true, source);
                return Some(true);
            }
            return Some(false);
        }
        if is_domain(core) {
            self.add(kind, core.to_string(), exact, false, source);
            return Some(true);
        }
        Some(false)
    }

    fn find(&self, kind: Kind, name: &str) -> Option<(String, Origin)> {
        let i = idx(kind);
        if let Some(o) = self.exact[i].get(name) {
            return Some((format!("|{name}^"), *o));
        }
        let mut s = name;
        loop {
            if let Some(o) = self.suffix[i].get(s) {
                return Some((format!("||{s}^"), *o));
            }
            match s.find('.') {
                Some(p) => s = &s[p + 1..],
                None => break,
            }
        }
        for (pat, exact, o) in &self.wild[i] {
            let hit = if *exact {
                glob(pat, name)
            } else {
                // Anchored at a label start, like ||pattern^.
                let mut s = name;
                loop {
                    if glob(pat, s) {
                        break true;
                    }
                    match s.find('.') {
                        Some(p) => s = &s[p + 1..],
                        None => break false,
                    }
                }
            };
            if hit {
                return Some((if *exact { format!("|{pat}^") } else { format!("||{pat}^") }, *o));
            }
        }
        None
    }

    fn to_match(&self, (rule, o): (String, Origin), prefix: &str) -> Match {
        Match {
            rule: format!("{prefix}{rule}"),
            source: self.sources.get(o.source as usize).map(|s| s.name.clone()).unwrap_or_default(),
        }
    }

    /// `$important` blocks beat exceptions; exceptions beat blocks.
    pub fn check(&self, name: &str) -> Verdict {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        if let Some(m) = self.find(Kind::Important, &name) {
            let mut m = self.to_match(m, "");
            m.rule.push_str("$important");
            return Verdict::Blocked(m);
        }
        if let Some(m) = self.find(Kind::Allow, &name) {
            return Verdict::Allowed(self.to_match(m, "@@"));
        }
        if let Some(m) = self.find(Kind::Block, &name) {
            return Verdict::Blocked(self.to_match(m, ""));
        }
        Verdict::None
    }

    pub fn rule_count(&self) -> usize {
        self.sources.iter().map(|s| s.rules).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filter(text: &str) -> Filter {
        let mut f = Filter::new();
        f.add_source("test", text, false);
        f
    }

    fn blocked(f: &Filter, n: &str) -> bool {
        matches!(f.check(n), Verdict::Blocked(_))
    }

    #[test]
    fn adblock_syntax() {
        let f = filter("! comment\n||ads.example.org^\n|exact.example.org^\nplain.example.com\n@@||good.ads.example.org^\n||tracker*.example.net^\n##.banner\n/ads[0-9]+/\n||x.example$third-party\n");
        assert!(blocked(&f, "ads.example.org"));
        assert!(blocked(&f, "img.ads.example.org."));
        assert!(!blocked(&f, "good.ads.example.org"));
        assert!(matches!(f.check("good.ads.example.org"), Verdict::Allowed(ref m) if m.rule == "@@||good.ads.example.org^"));
        assert!(blocked(&f, "exact.example.org"));
        assert!(!blocked(&f, "sub.exact.example.org"));
        assert!(blocked(&f, "cdn.plain.example.com"));
        assert!(blocked(&f, "tracker42.example.net"));
        assert!(blocked(&f, "a.tracker7.example.net"));
        assert!(!blocked(&f, "example.net"));
        assert!(!blocked(&f, "x.example"), "rules with unknown modifiers are not applied");
        assert_eq!(f.sources[0].rules, 5);
        assert_eq!(f.sources[0].unsupported, 2);
        match f.check("img.ads.example.org") {
            Verdict::Blocked(m) => assert_eq!(m, Match { rule: "||ads.example.org^".into(), source: "test".into() }),
            v => panic!("{v:?}"),
        }
    }

    #[test]
    fn important_beats_exceptions() {
        let f = filter("@@||site.example^\n||site.example^$important\n");
        assert!(blocked(&f, "site.example"));
    }

    #[test]
    fn hosts_syntax_blocks_or_answers() {
        let f = filter("127.0.0.1 localhost\n0.0.0.0 bad.example.org\n0.0.0.0 x.example.org y.example.org # two\n192.168.1.5 nas.lan\n");
        assert!(blocked(&f, "bad.example.org"));
        assert!(!blocked(&f, "sub.bad.example.org"), "hosts lines are exact");
        assert!(blocked(&f, "y.example.org"));
        assert!(!blocked(&f, "localhost"));
        assert_eq!(f.host_answers.get("nas.lan"), Some(&vec!["192.168.1.5".parse().unwrap()]));
    }

    #[test]
    fn allow_lists_turn_everything_into_exceptions() {
        let mut f = Filter::new();
        f.add_source("block", "||example.com^\n", false);
        f.add_source("allow", "www.example.com\n", true);
        assert!(blocked(&f, "api.example.com"));
        assert!(!blocked(&f, "www.example.com"));
    }

    #[test]
    fn glob_matching() {
        assert!(glob("ad*.example.com", "ads1.example.com"));
        assert!(glob("*.example.com", "a.b.example.com"));
        assert!(!glob("ad*.example.com", "x.example.com"));
        assert!(glob("a*b*c", "axxbyyc"));
    }
}
