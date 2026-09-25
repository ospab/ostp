//! Filtering DNS resolver for OSTP servers.
//!
//! Clients never reach it from the internet: the server answers the port-53
//! queries its clients send through the tunnel (whatever resolver address
//! they use) with this resolver. What it does, in order: local rewrites
//! (your own names, e.g. panel.ostp), safe search, blocking the browsers'
//! own DNS-over-HTTPS, blocked services, block/allow lists and your rules,
//! then the cache and the upstream resolvers (DoH, DoT, TCP, UDP), checking
//! CNAME answers against the lists too. It keeps a query log and counters.

pub mod filter;
pub mod lists;
pub mod services;
pub mod settings;
pub mod upstream;

pub use filter::{Match, Verdict};
pub use lists::UpdateResult;
pub use settings::{BlockingMode, DnsSettings, FilterList, Rewrite, UpstreamMode, PRESET_LISTS};

use serde::Serialize;
use simple_dns::rdata::{RData, CNAME};
use simple_dns::{Name, Packet, PacketFlag, ResourceRecord, CLASS, QTYPE, RCODE};
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};

use filter::Filter;
use upstream::Upstreams;

#[derive(Debug, Clone)]
enum Answer {
    Ip(IpAddr),
    Name(String),
}

/// What happened to one query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Allowed,
    Cached,
    Blocked,
    BlockedService,
    SafeSearch,
    Rewritten,
    /// Filtering is off; answered only to keep queries in the tunnel.
    Forwarded,
    Failed,
}

#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    /// Unix time, milliseconds.
    pub time: u64,
    pub client: String,
    pub name: String,
    pub qtype: String,
    pub outcome: Outcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream: Option<String>,
    pub elapsed_ms: u64,
}

#[derive(Default)]
struct Counters {
    total: u64,
    blocked: u64,
    rewritten: u64,
    cached: u64,
    failed: u64,
    upstream_ms_sum: u64,
    upstream_count: u64,
    domains: HashMap<String, u64>,
    blocked_domains: HashMap<String, u64>,
    clients: HashMap<String, u64>,
}

const TOP_CAP: usize = 5000;

fn bump(map: &mut HashMap<String, u64>, key: &str) {
    if let Some(v) = map.get_mut(key) {
        *v += 1;
    } else if map.len() < TOP_CAP {
        map.insert(key.to_string(), 1);
    }
}

fn top(map: &HashMap<String, u64>, n: usize) -> Vec<(String, u64)> {
    let mut v: Vec<(String, u64)> = map.iter().map(|(k, c)| (k.clone(), *c)).collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v.truncate(n);
    v
}

#[derive(Debug, Clone, Serialize)]
pub struct Stats {
    pub enabled: bool,
    pub since_seconds: u64,
    pub total: u64,
    pub blocked: u64,
    pub rewritten: u64,
    pub cached: u64,
    pub failed: u64,
    pub avg_upstream_ms: Option<u64>,
    pub rules: usize,
    pub lists: Vec<filter::SourceStats>,
    pub upstreams: Vec<String>,
    pub top_domains: Vec<(String, u64)>,
    pub top_blocked: Vec<(String, u64)>,
    pub top_clients: Vec<(String, u64)>,
}

/// Why a name is (or is not) answered the way it is.
#[derive(Debug, Clone, Serialize)]
pub struct Explanation {
    pub name: String,
    pub outcome: Outcome,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

struct CacheEntry {
    answer: Vec<u8>,
    stored: Instant,
    ttl: u32,
}

pub struct Dns {
    settings: RwLock<Arc<DnsSettings>>,
    filter: RwLock<Arc<Filter>>,
    rewrites: RwLock<Arc<Vec<(String, Answer)>>>,
    upstreams: RwLock<Arc<Upstreams>>,
    cache: Mutex<HashMap<(String, u16), CacheEntry>>,
    counters: Mutex<Counters>,
    log: Mutex<VecDeque<LogEntry>>,
    data_dir: Option<PathBuf>,
    proxy: RwLock<Option<String>>,
    started: Instant,
}

fn qtype_code(q: QTYPE) -> u16 {
    q.into()
}

fn qtype_name(code: u16) -> String {
    match code {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        64 => "SVCB".into(),
        65 => "HTTPS".into(),
        255 => "ANY".into(),
        n => format!("TYPE{n}"),
    }
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn compile_rewrites(s: &DnsSettings) -> Vec<(String, Answer)> {
    s.rewrites
        .iter()
        .map(|r| {
            let answer = match r.answer.trim().parse::<IpAddr>() {
                Ok(ip) => Answer::Ip(ip),
                Err(_) => Answer::Name(r.answer.trim().trim_end_matches('.').to_ascii_lowercase()),
            };
            (r.domain.trim().trim_end_matches('.').to_ascii_lowercase(), answer)
        })
        .collect()
}

fn rewrite_matches(pattern: &str, name: &str) -> bool {
    match pattern.strip_prefix("*.") {
        Some(base) => name.len() > base.len() && name.ends_with(base) && name.as_bytes()[name.len() - base.len() - 1] == b'.',
        None => pattern == name,
    }
}

/// A reply to `q` with its question, flags copied, no answers yet.
fn reply<'a>(q: &Packet<'a>) -> Packet<'a> {
    let mut r = Packet::new_reply(q.id());
    r.questions = q.questions.clone();
    if q.has_flags(PacketFlag::RECURSION_DESIRED) {
        r.set_flags(PacketFlag::RECURSION_DESIRED);
    }
    r.set_flags(PacketFlag::RECURSION_AVAILABLE);
    r
}

fn with_rcode(q: &Packet, rcode: RCODE) -> Option<Vec<u8>> {
    let mut r = reply(q);
    *r.rcode_mut() = rcode;
    r.build_bytes_vec_compressed().ok()
}

fn addresses_reply(q: &Packet, name: &Name, ips: &[IpAddr], ttl: u32) -> Option<Vec<u8>> {
    let qtype = qtype_code(q.questions[0].qtype);
    let mut r = reply(q);
    for ip in ips {
        match (ip, qtype) {
            (IpAddr::V4(v4), 1) | (IpAddr::V4(v4), 255) => r.answers.push(ResourceRecord::new(name.clone(), CLASS::IN, ttl, RData::A((*v4).into()))),
            (IpAddr::V6(v6), 28) | (IpAddr::V6(v6), 255) => r.answers.push(ResourceRecord::new(name.clone(), CLASS::IN, ttl, RData::AAAA((*v6).into()))),
            _ => {}
        }
    }
    r.build_bytes_vec_compressed().ok()
}

fn min_ttl(answer: &[u8]) -> Option<u32> {
    let p = Packet::parse(answer).ok()?;
    p.answers.iter().chain(p.name_servers.iter()).map(|r| r.ttl).min()
}

fn answer_names(answer: &[u8]) -> Vec<String> {
    let Ok(p) = Packet::parse(answer) else { return Vec::new() };
    p.answers
        .iter()
        .filter_map(|r| match &r.rdata {
            RData::CNAME(CNAME(n)) => Some(n.to_string().trim_end_matches('.').to_ascii_lowercase()),
            _ => None,
        })
        .collect()
}

/// The cached answer with this query's id and the TTLs counted down.
fn refresh(answer: &[u8], id: u16, elapsed: u32) -> Vec<u8> {
    let rebuilt = Packet::parse(answer).ok().and_then(|mut p| {
        for r in p.answers.iter_mut().chain(p.name_servers.iter_mut()).chain(p.additional_records.iter_mut()) {
            r.ttl = r.ttl.saturating_sub(elapsed).max(1);
        }
        p.build_bytes_vec_compressed().ok()
    });
    let mut out = rebuilt.unwrap_or_else(|| answer.to_vec());
    out[..2].copy_from_slice(&id.to_be_bytes());
    out
}

impl Dns {
    /// A resolver for `settings`; `data_dir` holds downloaded lists.
    /// Nothing runs in the background until `start`.
    pub fn new(settings: DnsSettings, data_dir: Option<PathBuf>) -> Arc<Self> {
        let settings = settings.normalized();
        let upstreams = Upstreams::new(&settings.upstreams, settings.upstream_mode, None)
            .unwrap_or_else(|e| {
                tracing::error!("DNS upstreams: {e:#}");
                Upstreams::new(&[], settings.upstream_mode, None).expect("empty upstream list")
            });
        let filter = lists::build_filter(&settings, data_dir.as_deref());
        Arc::new(Self {
            rewrites: RwLock::new(Arc::new(compile_rewrites(&settings))),
            filter: RwLock::new(Arc::new(filter)),
            upstreams: RwLock::new(Arc::new(upstreams)),
            settings: RwLock::new(Arc::new(settings)),
            cache: Mutex::new(HashMap::new()),
            counters: Mutex::new(Counters::default()),
            log: Mutex::new(VecDeque::new()),
            data_dir,
            proxy: RwLock::new(None),
            started: Instant::now(),
        })
    }

    /// Keeps the lists fresh: downloads missing or outdated ones now and
    /// then every half hour checks again.
    pub fn start(self: &Arc<Self>) {
        let me = self.clone();
        tokio::spawn(async move {
            loop {
                let s = me.settings();
                if s.enabled {
                    if let Some(dir) = me.data_dir.clone() {
                        if lists::update_due(&s, &dir) {
                            me.update_lists().await;
                        }
                    }
                }
                tokio::time::sleep(Duration::from_secs(1800)).await;
            }
        });
    }

    pub fn settings(&self) -> Arc<DnsSettings> {
        self.settings.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn enabled(&self) -> bool {
        self.settings().enabled
    }

    /// Whether a client's connection (TCP or UDP) to `target` is encrypted DNS
    /// that would skip the filter: anything to port 853 (DoT, DoQ), and port
    /// 443 on a public resolver's address (DoH, DoH over QUIC). Refused while
    /// filtering is on and `block_doh_bypass` is set; DoH servers reached by
    /// name are blocked by the resolver itself.
    pub fn is_dns_bypass(&self, target: &str) -> bool {
        let s = self.settings();
        if !s.enabled || !s.block_doh_bypass {
            return false;
        }
        match target.parse::<std::net::SocketAddr>() {
            Ok(addr) => addr.port() == 853 || (addr.port() == 443 && services::is_public_resolver(addr.ip())),
            Err(_) => target.rsplit_once(':').is_some_and(|(_, p)| p == "853"),
        }
    }

    /// Whether the server should answer its clients' port-53 queries.
    pub fn intercepts(&self) -> bool {
        let s = self.settings();
        s.enabled || s.intercept_all_port53
    }

    /// DoH and list downloads through the outbound proxy (e.g. socks5h://).
    pub fn set_proxy(&self, proxy: Option<String>) {
        *self.proxy.write().unwrap_or_else(|e| e.into_inner()) = proxy.clone();
        let s = self.settings();
        if let Ok(u) = Upstreams::new(&s.upstreams, s.upstream_mode, proxy.as_deref()) {
            *self.upstreams.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(u);
        }
    }

    /// New settings, live: upstreams, rules and rewrites are rebuilt and the
    /// cache emptied. Lists that are not downloaded yet are fetched.
    pub fn apply(self: &Arc<Self>, settings: DnsSettings) -> anyhow::Result<()> {
        let settings = settings.normalized();
        settings.validate()?;
        let proxy = self.proxy.read().unwrap_or_else(|e| e.into_inner()).clone();
        let upstreams = Upstreams::new(&settings.upstreams, settings.upstream_mode, proxy.as_deref())?;
        let filter = lists::build_filter(&settings, self.data_dir.as_deref());
        *self.upstreams.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(upstreams);
        *self.filter.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(filter);
        *self.rewrites.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(compile_rewrites(&settings));
        let due = self.data_dir.as_ref().is_some_and(|d| settings.enabled && lists::update_due(&settings, d));
        *self.settings.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(settings);
        self.cache.lock().unwrap_or_else(|e| e.into_inner()).clear();
        if due {
            let me = self.clone();
            tokio::spawn(async move {
                me.update_lists().await;
            });
        }
        Ok(())
    }

    /// Downloads the lists now and rebuilds the filter.
    pub async fn update_lists(&self) -> Vec<lists::UpdateResult> {
        let Some(dir) = self.data_dir.clone() else { return Vec::new() };
        let s = self.settings();
        let proxy = self.proxy.read().unwrap_or_else(|e| e.into_inner()).clone();
        let results = lists::update_all(&s, &dir, proxy.as_deref()).await;
        let filter = tokio::task::spawn_blocking(move || lists::build_filter(&s, Some(&dir))).await.unwrap_or_default();
        tracing::info!("DNS: {} rules from {} lists", filter.rule_count(), filter.sources.len());
        *self.filter.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(filter);
        self.cache.lock().unwrap_or_else(|e| e.into_inner()).clear();
        results
    }

    fn record(&self, entry: LogEntry, upstream_ms: Option<u64>) {
        let size = self.settings().query_log_size;
        {
            let mut c = self.counters.lock().unwrap_or_else(|e| e.into_inner());
            c.total += 1;
            match entry.outcome {
                Outcome::Blocked | Outcome::BlockedService => {
                    c.blocked += 1;
                    bump(&mut c.blocked_domains, &entry.name);
                }
                Outcome::Rewritten | Outcome::SafeSearch => c.rewritten += 1,
                Outcome::Cached => c.cached += 1,
                Outcome::Failed => c.failed += 1,
                _ => {}
            }
            if let Some(ms) = upstream_ms {
                c.upstream_ms_sum += ms;
                c.upstream_count += 1;
            }
            bump(&mut c.domains, &entry.name);
            bump(&mut c.clients, &entry.client);
        }
        if size > 0 {
            let mut log = self.log.lock().unwrap_or_else(|e| e.into_inner());
            while log.len() >= size {
                log.pop_front();
            }
            log.push_back(entry);
        }
    }

    pub fn stats(&self) -> Stats {
        let c = self.counters.lock().unwrap_or_else(|e| e.into_inner());
        let f = self.filter.read().unwrap_or_else(|e| e.into_inner()).clone();
        Stats {
            enabled: self.enabled(),
            since_seconds: self.started.elapsed().as_secs(),
            total: c.total,
            blocked: c.blocked,
            rewritten: c.rewritten,
            cached: c.cached,
            failed: c.failed,
            avg_upstream_ms: (c.upstream_count > 0).then(|| c.upstream_ms_sum / c.upstream_count),
            rules: f.rule_count(),
            lists: f.sources.clone(),
            upstreams: self.upstreams.read().unwrap_or_else(|e| e.into_inner()).labels(),
            top_domains: top(&c.domains, 10),
            top_blocked: top(&c.blocked_domains, 10),
            top_clients: top(&c.clients, 10),
        }
    }

    /// Newest first; `filter` matches the name or the client.
    pub fn query_log(&self, limit: usize, filter: Option<&str>) -> Vec<LogEntry> {
        let log = self.log.lock().unwrap_or_else(|e| e.into_inner());
        log.iter()
            .rev()
            .filter(|e| filter.map_or(true, |f| e.name.contains(f) || e.client.contains(f)))
            .take(limit)
            .cloned()
            .collect()
    }

    pub fn clear_log(&self) {
        self.log.lock().unwrap_or_else(|e| e.into_inner()).clear();
        *self.counters.lock().unwrap_or_else(|e| e.into_inner()) = Counters::default();
    }

    fn rewrite_for(&self, name: &str) -> Vec<Answer> {
        let rw = self.rewrites.read().unwrap_or_else(|e| e.into_inner()).clone();
        let mut out: Vec<Answer> = rw.iter().filter(|(p, _)| rewrite_matches(p, name)).map(|(_, a)| a.clone()).collect();
        if out.is_empty() {
            if let Some(ips) = self.filter.read().unwrap_or_else(|e| e.into_inner()).host_answers.get(name) {
                out = ips.iter().map(|ip| Answer::Ip(*ip)).collect();
            }
        }
        out
    }

    /// Policy decision for a name, without resolving it.
    pub fn explain(&self, name: &str) -> Explanation {
        let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
        let s = self.settings();
        let ex = |outcome, detail: String, rule: Option<String>, source: Option<String>| Explanation { name: name.clone(), outcome, detail, rule, source };
        let rw = self.rewrite_for(&name);
        if !rw.is_empty() {
            let answers: Vec<String> = rw.iter().map(|a| match a { Answer::Ip(ip) => ip.to_string(), Answer::Name(n) => n.clone() }).collect();
            return ex(Outcome::Rewritten, format!("answered locally: {}", answers.join(", ")), None, None);
        }
        if name == "ostp" || name.ends_with(".ostp") {
            return ex(Outcome::Blocked, "a .ostp name without a rewrite: NXDOMAIN, never sent upstream".into(), None, None);
        }
        if s.safe_search {
            if let Some(t) = services::safe_search_target(&name) {
                return ex(Outcome::SafeSearch, format!("safe search: answered with {t}"), None, None);
            }
        }
        if s.block_doh_bypass && (name == services::DOH_CANARY || services::DOH_HOSTS.contains(&name.as_str())) {
            return ex(Outcome::Blocked, "a browser's own DNS over HTTPS: blocked so queries stay here".into(), None, Some("built-in".into()));
        }
        if let Some(svc) = services::service_of(&name, &s.blocked_services) {
            return ex(Outcome::BlockedService, format!("service {svc} is blocked"), None, Some("blocked services".into()));
        }
        match self.filter.read().unwrap_or_else(|e| e.into_inner()).check(&name) {
            Verdict::Blocked(m) => ex(Outcome::Blocked, "blocked by a rule".into(), Some(m.rule), Some(m.source)),
            Verdict::Allowed(m) => ex(Outcome::Allowed, "allowed by an exception".into(), Some(m.rule), Some(m.source)),
            Verdict::None => ex(Outcome::Allowed, "no rule matches: resolved upstream".into(), None, None),
        }
    }

    fn blocked_reply(&self, q: &Packet, s: &DnsSettings) -> Option<Vec<u8>> {
        match s.blocking_mode {
            BlockingMode::Nxdomain => with_rcode(q, RCODE::NameError),
            BlockingMode::Refused => with_rcode(q, RCODE::Refused),
            BlockingMode::NullIp => {
                let name = q.questions[0].qname.clone();
                addresses_reply(q, &name, &[IpAddr::V4(Ipv4Addr::UNSPECIFIED), IpAddr::V6(Ipv6Addr::UNSPECIFIED)], s.blocked_ttl)
            }
        }
    }

    async fn resolve_cached(&self, name: &str, qtype: u16, query: &[u8], id: u16) -> Result<(Vec<u8>, Option<String>, bool, Option<u64>), anyhow::Error> {
        let s = self.settings();
        if s.cache_size > 0 {
            let cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(e) = cache.get(&(name.to_string(), qtype)) {
                let age = e.stored.elapsed().as_secs() as u32;
                if age < e.ttl {
                    return Ok((refresh(&e.answer, id, age), None, true, None));
                }
            }
        }
        let started = Instant::now();
        let ups = self.upstreams.read().unwrap_or_else(|e| e.into_inner()).clone();
        let (answer, label) = ups.query(query).await?;
        let ms = started.elapsed().as_millis() as u64;
        if s.cache_size > 0 {
            let ttl = min_ttl(&answer).unwrap_or(s.cache_min_ttl).clamp(s.cache_min_ttl, s.cache_max_ttl);
            let rcode_ok = answer.len() > 3 && matches!(answer[3] & 0x0F, 0 | 3);
            if rcode_ok {
                let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
                if cache.len() >= s.cache_size {
                    cache.retain(|_, e| e.stored.elapsed().as_secs() < e.ttl as u64);
                    if cache.len() >= s.cache_size {
                        if let Some(k) = cache.keys().next().cloned() {
                            cache.remove(&k);
                        }
                    }
                }
                cache.insert((name.to_string(), qtype), CacheEntry { answer: answer.clone(), stored: Instant::now(), ttl });
            }
        }
        Ok((answer, Some(label), false, Some(ms)))
    }

    /// A CNAME to `target` followed by the target's own records.
    async fn cname_reply(&self, q: &Packet<'_>, target: &str) -> Option<Vec<u8>> {
        let qtype = q.questions[0].qtype;
        let mut sub = Packet::new_query(rand::random());
        sub.set_flags(PacketFlag::RECURSION_DESIRED);
        let tname = Name::new(target).ok()?;
        sub.questions.push(simple_dns::Question::new(tname.clone(), qtype, simple_dns::QCLASS::CLASS(CLASS::IN), false));
        let sub_bytes = sub.build_bytes_vec().ok()?;
        let (answer, _, _, _) = self.resolve_cached(target, qtype_code(qtype), &sub_bytes, sub.id()).await.ok()?;
        let parsed = Packet::parse(&answer).ok()?;
        let mut r = reply(q);
        r.answers.push(ResourceRecord::new(q.questions[0].qname.clone(), CLASS::IN, 300, RData::CNAME(CNAME(tname))));
        r.answers.extend(parsed.answers.into_iter());
        r.build_bytes_vec_compressed().ok()
    }

    /// For a connection to `host` by name (a SOCKS client sends names, not
    /// DNS queries): `Err` with the reason when the filter blocks it,
    /// `Ok(Some(ip))` with the address the resolver gives (rewrites
    /// included), `Ok(None)` when filtering is off or nothing resolved (the
    /// caller then connects by name as before).
    pub async fn resolve_host(&self, host: &str, client: IpAddr) -> Result<Option<IpAddr>, String> {
        if !self.enabled() || host.parse::<IpAddr>().is_ok() {
            return Ok(None);
        }
        let e = self.explain(host);
        if matches!(e.outcome, Outcome::Blocked | Outcome::BlockedService) {
            let mut q = Packet::new_query(rand::random());
            if let Ok(n) = Name::new(host) {
                q.questions.push(simple_dns::Question::new(n, QTYPE::TYPE(simple_dns::TYPE::A), simple_dns::QCLASS::CLASS(CLASS::IN), false));
                if let Ok(bytes) = q.build_bytes_vec() {
                    // Recorded in the log like any blocked query.
                    let _ = self.handle(&bytes, client).await;
                }
            }
            return Err(format!("blocked by DNS filtering{}", e.rule.map(|r| format!(" ({r})")).unwrap_or_default()));
        }
        for qtype in [simple_dns::TYPE::A, simple_dns::TYPE::AAAA] {
            let mut q = Packet::new_query(rand::random());
            q.set_flags(PacketFlag::RECURSION_DESIRED);
            let Ok(n) = Name::new(host) else { return Ok(None) };
            q.questions.push(simple_dns::Question::new(n, QTYPE::TYPE(qtype), simple_dns::QCLASS::CLASS(CLASS::IN), false));
            let Ok(bytes) = q.build_bytes_vec() else { return Ok(None) };
            let Some(answer) = self.handle(&bytes, client).await else { return Ok(None) };
            if let Ok(p) = Packet::parse(&answer) {
                let ip = p.answers.iter().find_map(|r| match &r.rdata {
                    RData::A(a) => Some(IpAddr::V4(Ipv4Addr::from(a.address))),
                    RData::AAAA(a) => Some(IpAddr::V6(Ipv6Addr::from(a.address))),
                    _ => None,
                });
                if ip.is_some() {
                    return Ok(ip);
                }
            }
        }
        Ok(None)
    }

    /// Answers one DNS query from a client; `None` means "not ours, let it
    /// through" (filtering and interception both off, or not a query).
    pub async fn handle(&self, query: &[u8], client: IpAddr) -> Option<Vec<u8>> {
        let s = self.settings();
        if !s.enabled && !s.intercept_all_port53 {
            return None;
        }
        let q = Packet::parse(query).ok()?;
        let question = q.questions.first()?;
        let name = question.qname.to_string().trim_end_matches('.').to_ascii_lowercase();
        let qtype = qtype_code(question.qtype);
        let started = Instant::now();
        let entry = |outcome, rule: Option<String>, source: Option<String>, upstream: Option<String>| LogEntry {
            time: now_ms(),
            client: client.to_string(),
            name: name.clone(),
            qtype: qtype_name(qtype),
            outcome,
            rule,
            source,
            upstream,
            elapsed_ms: started.elapsed().as_millis() as u64,
        };

        if !s.enabled {
            // Only keep the query inside: forwarded, unfiltered.
            return match self.resolve_cached(&name, qtype, query, q.id()).await {
                Ok((a, up, cached, ms)) => {
                    self.record(entry(if cached { Outcome::Cached } else { Outcome::Forwarded }, None, None, up), ms);
                    Some(a)
                }
                Err(e) => {
                    self.record(entry(Outcome::Failed, None, None, Some(format!("{e:#}"))), None);
                    with_rcode(&q, RCODE::ServerFailure)
                }
            };
        }

        // Local names.
        let rw = self.rewrite_for(&name);
        if !rw.is_empty() {
            let ips: Vec<IpAddr> = rw.iter().filter_map(|a| if let Answer::Ip(ip) = a { Some(*ip) } else { None }).collect();
            let reply = if ips.is_empty() {
                let target = rw.iter().find_map(|a| if let Answer::Name(n) = a { Some(n.clone()) } else { None })?;
                self.cname_reply(&q, &target).await
            } else {
                addresses_reply(&q, &question.qname, &ips, 60)
            };
            self.record(entry(Outcome::Rewritten, None, None, None), None);
            return reply;
        }
        if name == "ostp" || name.ends_with(".ostp") {
            self.record(entry(Outcome::Blocked, Some(".ostp without a rewrite".into()), None, None), None);
            return with_rcode(&q, RCODE::NameError);
        }
        if s.safe_search {
            if let Some(t) = services::safe_search_target(&name) {
                self.record(entry(Outcome::SafeSearch, None, None, None), None);
                return self.cname_reply(&q, t).await;
            }
        }
        if s.block_doh_bypass && (name == services::DOH_CANARY || services::DOH_HOSTS.contains(&name.as_str())) {
            self.record(entry(Outcome::Blocked, Some("browser DNS over HTTPS".into()), Some("built-in".into()), None), None);
            return with_rcode(&q, RCODE::NameError);
        }
        if let Some(svc) = services::service_of(&name, &s.blocked_services) {
            self.record(entry(Outcome::BlockedService, Some(svc.into()), Some("blocked services".into()), None), None);
            return self.blocked_reply(&q, &s);
        }
        let filter = self.filter.read().unwrap_or_else(|e| e.into_inner()).clone();
        if let Verdict::Blocked(m) = filter.check(&name) {
            self.record(entry(Outcome::Blocked, Some(m.rule), Some(m.source), None), None);
            return self.blocked_reply(&q, &s);
        }

        match self.resolve_cached(&name, qtype, query, q.id()).await {
            Ok((answer, upstream, cached, ms)) => {
                // CNAME cloaking: a clean name pointing at a blocked one.
                for target in answer_names(&answer) {
                    if let Verdict::Blocked(m) = filter.check(&target) {
                        self.record(entry(Outcome::Blocked, Some(format!("{} (CNAME {target})", m.rule)), Some(m.source), upstream), ms);
                        return self.blocked_reply(&q, &s);
                    }
                }
                self.record(entry(if cached { Outcome::Cached } else { Outcome::Allowed }, None, None, upstream), ms);
                Some(answer)
            }
            Err(e) => {
                tracing::debug!("DNS {name}: {e:#}");
                self.record(entry(Outcome::Failed, None, None, Some(format!("{e:#}"))), None);
                with_rcode(&q, RCODE::ServerFailure)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use simple_dns::TYPE;

    fn query(name: &str, qtype: TYPE) -> Vec<u8> {
        let mut p = Packet::new_query(0x4242);
        p.set_flags(PacketFlag::RECURSION_DESIRED);
        p.questions.push(simple_dns::Question::new(Name::new(name).unwrap(), QTYPE::TYPE(qtype), simple_dns::QCLASS::CLASS(CLASS::IN), false));
        p.build_bytes_vec().unwrap()
    }

    /// A fake upstream on loopback: answers every A query with 93.184.216.34,
    /// and cdn.clean.test with a CNAME to ads.tracker.test.
    async fn fake_upstream() -> String {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 1500];
            while let Ok((n, peer)) = sock.recv_from(&mut b).await {
                let data = b[..n].to_vec();
                let q = Packet::parse(&data).unwrap();
                let mut r = reply(&q);
                let qn = q.questions[0].qname.clone();
                if qn.to_string() == "cdn.clean.test" {
                    r.answers.push(ResourceRecord::new(qn, CLASS::IN, 30, RData::CNAME(CNAME(Name::new("ads.tracker.test").unwrap()))));
                } else {
                    r.answers.push(ResourceRecord::new(qn, CLASS::IN, 30, RData::A(Ipv4Addr::new(93, 184, 216, 34).into())));
                }
                let _ = sock.send_to(&r.build_bytes_vec().unwrap(), peer).await;
            }
        });
        format!("udp://{addr}")
    }

    fn settings(upstream: String) -> DnsSettings {
        DnsSettings {
            enabled: true,
            upstreams: vec![upstream],
            lists: Vec::new(),
            user_rules: vec!["||ads.tracker.test^".into(), "@@||ok.ads.tracker.test^".into(), "||blocked.test^".into()],
            rewrites: vec![Rewrite { domain: "panel.ostp".into(), answer: "10.1.0.1".into() }],
            blocked_services: vec!["tiktok".into()],
            ..Default::default()
        }
    }

    fn rcode(a: &[u8]) -> u8 {
        a[3] & 0x0F
    }

    fn first_a(a: &[u8]) -> Option<Ipv4Addr> {
        Packet::parse(a).ok()?.answers.iter().find_map(|r| match &r.rdata {
            RData::A(a) => Some(Ipv4Addr::from(a.address)),
            _ => None,
        })
    }

    #[tokio::test]
    async fn the_pipeline() {
        let dns = Dns::new(settings(fake_upstream().await), None);
        let me: IpAddr = "10.1.0.2".parse().unwrap();

        let a = dns.handle(&query("example.com", TYPE::A), me).await.unwrap();
        assert_eq!(rcode(&a), 0);
        assert_eq!(&a[..2], &[0x42, 0x42]);
        assert_eq!(first_a(&a), Some(Ipv4Addr::new(93, 184, 216, 34)));

        let a = dns.handle(&query("x.ads.tracker.test", TYPE::A), me).await.unwrap();
        assert_eq!(rcode(&a), 3, "blocked: NXDOMAIN");
        let a = dns.handle(&query("ok.ads.tracker.test", TYPE::A), me).await.unwrap();
        assert_eq!(rcode(&a), 0, "exception");

        let a = dns.handle(&query("panel.ostp", TYPE::A), me).await.unwrap();
        assert_eq!(first_a(&a), Some(Ipv4Addr::new(10, 1, 0, 1)));
        let a = dns.handle(&query("other.ostp", TYPE::A), me).await.unwrap();
        assert_eq!(rcode(&a), 3, ".ostp never goes upstream");

        let a = dns.handle(&query("v16.tiktokcdn.com", TYPE::A), me).await.unwrap();
        assert_eq!(rcode(&a), 3, "blocked service");
        let a = dns.handle(&query(services::DOH_CANARY, TYPE::A), me).await.unwrap();
        assert_eq!(rcode(&a), 3, "Firefox canary");

        let a = dns.handle(&query("cdn.clean.test", TYPE::A), me).await.unwrap();
        assert_eq!(rcode(&a), 3, "CNAME to a blocked name");

        // The second query for example.com comes from the cache.
        let _ = dns.handle(&query("example.com", TYPE::A), me).await.unwrap();
        let st = dns.stats();
        assert_eq!(st.total, 9);
        assert_eq!(st.cached, 1);
        assert!(st.blocked >= 5);
        let log = dns.query_log(3, None);
        assert_eq!(log[0].outcome, Outcome::Cached);
        assert_eq!(dns.query_log(50, Some("tiktok")).len(), 1);
    }

    #[tokio::test]
    async fn null_ip_mode_and_explain() {
        let mut s = settings(fake_upstream().await);
        s.blocking_mode = BlockingMode::NullIp;
        let dns = Dns::new(s, None);
        let a = dns.handle(&query("blocked.test", TYPE::A), "10.1.0.2".parse().unwrap()).await.unwrap();
        assert_eq!(first_a(&a), Some(Ipv4Addr::UNSPECIFIED));
        let e = dns.explain("x.blocked.test");
        assert_eq!(e.outcome, Outcome::Blocked);
        assert_eq!(e.rule.as_deref(), Some("||blocked.test^"));
        assert_eq!(e.source.as_deref(), Some("user rules"));
        assert_eq!(dns.explain("panel.ostp").outcome, Outcome::Rewritten);
        assert_eq!(dns.explain("example.com").outcome, Outcome::Allowed);
    }

    #[tokio::test]
    async fn off_means_hands_off() {
        let dns = Dns::new(DnsSettings::default(), None);
        assert!(dns.handle(&query("example.com", TYPE::A), "10.1.0.2".parse().unwrap()).await.is_none());
    }

    #[tokio::test]
    async fn connections_by_name() {
        let dns = Dns::new(settings(fake_upstream().await), None);
        let me: IpAddr = "10.1.0.2".parse().unwrap();
        assert_eq!(dns.resolve_host("panel.ostp", me).await, Ok(Some("10.1.0.1".parse().unwrap())));
        assert_eq!(dns.resolve_host("example.com", me).await, Ok(Some("93.184.216.34".parse().unwrap())));
        assert!(dns.resolve_host("x.blocked.test", me).await.unwrap_err().contains("||blocked.test^"));
        assert_eq!(dns.resolve_host("1.2.3.4", me).await, Ok(None));
        assert_eq!(dns.query_log(10, Some("blocked.test")).len(), 1);
    }

    #[test]
    fn encrypted_dns_to_public_resolvers() {
        let mut s = DnsSettings::default();
        let dns = Dns::new(s.clone(), None);
        assert!(!dns.is_dns_bypass("1.1.1.1:853"), "filter off: nothing refused");
        s.enabled = true;
        let dns = Dns::new(s.clone(), None);
        assert!(dns.is_dns_bypass("1.1.1.1:853"));
        assert!(dns.is_dns_bypass("8.8.8.8:443"));
        assert!(dns.is_dns_bypass("[2001:4860:4860::8888]:443"));
        assert!(dns.is_dns_bypass("[::ffff:1.1.1.1]:443"));
        assert!(dns.is_dns_bypass("dns.example:853"));
        assert!(!dns.is_dns_bypass("93.184.216.34:443"));
        assert!(!dns.is_dns_bypass("1.1.1.1:80"));
        assert!(!dns.is_dns_bypass("example.com:443"));
        s.block_doh_bypass = false;
        let dns = Dns::new(s, None);
        assert!(!dns.is_dns_bypass("8.8.8.8:443"));
    }

    #[test]
    fn wildcard_rewrites() {
        assert!(rewrite_matches("*.lan", "nas.lan"));
        assert!(!rewrite_matches("*.lan", "lan"));
        assert!(!rewrite_matches("*.lan", "xlan"));
        assert!(rewrite_matches("panel.ostp", "panel.ostp"));
    }
}
