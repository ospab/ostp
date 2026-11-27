//! Names this server has seen for addresses, so `outbound.rules` with
//! `domain_suffix` also match a connection or a datagram that names only an
//! address.
//!
//! A client in TUN mode sends what the program sent: an address. Its TCP
//! connections carry the name when the client finds one in the TLS
//! ClientHello (SNI), but UDP (QUIC to Google and YouTube, UDP/443) never
//! does, and without a name only `ip_cidr` rules could match it. So the
//! server remembers, for a while, which name an address was given for:
//!
//! - the addresses its own DNS answers to a client (`Router::route_dns`),
//! - plain DNS answers a client gets through the tunnel from another
//!   resolver (UDP from port 53),
//! - the address it resolved for a client's connection by name
//!   (`Router::route_tcp`).
//!
//! Entries belong to the client's address: what one client's DNS answers say
//! never changes how another client's traffic is routed (a name a user
//! controls could otherwise point at any address and pull it under that
//! name's rule for everyone). They expire after `TTL` and there are at most
//! `CAPACITY` of them; the oldest go first.
//!
//! An address serves many names (a CDN): the last one seen for it is the one
//! remembered. This is a hint for routing, never used to decide where to
//! connect.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How long a remembered name is used.
pub const TTL: Duration = Duration::from_secs(600);
/// Most entries kept over all clients.
pub const CAPACITY: usize = 50_000;
/// A name seen again for the same address this soon is not stored again
/// (it would only grow the eviction queue).
const REFRESH_AFTER: Duration = Duration::from_secs(60);
/// Addresses taken from one DNS answer at most.
const MAX_PER_ANSWER: usize = 32;

type Key = (IpAddr, IpAddr);

struct Entry {
    name: Arc<str>,
    stored: Instant,
}

#[derive(Default)]
struct Inner {
    map: HashMap<Key, Entry>,
    /// Insertion order with the time stored; an item whose time is not the
    /// entry's any more is a stale one left by a later store.
    order: VecDeque<(Key, Instant)>,
}

pub struct IpNames {
    inner: Mutex<Inner>,
    ttl: Duration,
    capacity: usize,
}

impl Default for IpNames {
    fn default() -> Self {
        Self::new(TTL, CAPACITY)
    }
}

/// `::ffff:a.b.c.d` is `a.b.c.d`: the same destination whichever form a
/// socket or a client gave.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

/// A DNS name fit to be matched against rules: letters, digits, `-`, `_`
/// and dots, with at least one dot. Lower case, without the final dot.
pub fn routable_name(name: &str) -> Option<String> {
    let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
    if name.is_empty() || name.len() > 253 || !name.contains('.') || name.parse::<IpAddr>().is_ok() {
        return None;
    }
    let ok = name.split('.').all(|label| {
        !label.is_empty() && label.len() <= 63 && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    });
    ok.then_some(name)
}

impl IpNames {
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        Self { inner: Mutex::new(Inner::default()), ttl, capacity: capacity.max(1) }
    }

    /// `client` was given `ip` for `name`.
    pub fn remember(&self, client: IpAddr, ip: IpAddr, name: &str) {
        self.remember_at(client, ip, name, Instant::now());
    }

    fn remember_at(&self, client: IpAddr, ip: IpAddr, name: &str, now: Instant) {
        let Some(name) = routable_name(name) else { return };
        let ip = canonical(ip);
        if ip.is_unspecified() || ip.is_loopback() {
            return; // a blocked name's 0.0.0.0, or this machine
        }
        let key = (canonical(client), ip);
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(e) = inner.map.get(&key) {
            if &*e.name == name.as_str() && now.saturating_duration_since(e.stored) < REFRESH_AFTER {
                return;
            }
        }
        inner.map.insert(key, Entry { name: name.into(), stored: now });
        inner.order.push_back((key, now));
        // Over capacity, or the queue full of stale items: the oldest go.
        while inner.map.len() > self.capacity || inner.order.len() > self.capacity * 2 {
            let Some((old, stamp)) = inner.order.pop_front() else { break };
            if inner.map.get(&old).is_some_and(|e| e.stored == stamp) {
                inner.map.remove(&old);
            }
        }
    }

    /// The name `client` was last given `ip` for, while it is fresh.
    pub fn name_of(&self, client: IpAddr, ip: IpAddr) -> Option<Arc<str>> {
        self.name_at(client, ip, Instant::now())
    }

    fn name_at(&self, client: IpAddr, ip: IpAddr, now: Instant) -> Option<Arc<str>> {
        let key = (canonical(client), canonical(ip));
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let e = inner.map.get(&key)?;
        (now.saturating_duration_since(e.stored) < self.ttl).then(|| e.name.clone())
    }

    /// The name for the host of `target` ("host:port"), when the host is an
    /// address with a remembered name.
    pub fn name_for_target(&self, client: IpAddr, target: &str) -> Option<Arc<str>> {
        let (host, _) = ostp_core::net::split_host_port(target)?;
        let ip = host.parse::<IpAddr>().ok()?;
        self.name_of(client, ip)
    }

    /// Remembers the addresses of a DNS answer (A and AAAA records) under the
    /// name that was asked.
    pub fn remember_dns_answer(&self, client: IpAddr, answer: &[u8]) {
        let Some((name, ips)) = dns_answer_addresses(answer) else { return };
        for ip in ips {
            self.remember(client, ip, &name);
        }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).map.len()
    }
}

/// The question name of a DNS response and the addresses in its answers.
fn dns_answer_addresses(answer: &[u8]) -> Option<(String, Vec<IpAddr>)> {
    use simple_dns::rdata::RData;
    let p = simple_dns::Packet::parse(answer).ok()?;
    if !p.has_flags(simple_dns::PacketFlag::RESPONSE) {
        return None;
    }
    let name = p.questions.first()?.qname.to_string();
    let ips: Vec<IpAddr> = p
        .answers
        .iter()
        .filter_map(|r| match &r.rdata {
            RData::A(a) => Some(IpAddr::V4(std::net::Ipv4Addr::from(a.address))),
            RData::AAAA(a) => Some(IpAddr::V6(std::net::Ipv6Addr::from(a.address))),
            _ => None,
        })
        .take(MAX_PER_ANSWER)
        .collect();
    (!ips.is_empty()).then_some((name, ips))
}

#[cfg(test)]
mod tests {
    use super::*;
    use simple_dns::rdata::{RData, A, AAAA, CNAME};
    use simple_dns::{Name, Packet, PacketFlag, Question, ResourceRecord, CLASS, QCLASS, QTYPE, TYPE};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    const ME: &str = "203.0.113.5";

    #[test]
    fn remembers_and_finds_a_name() {
        let m = IpNames::default();
        m.remember(ip(ME), ip("142.250.74.14"), "www.YouTube.com.");
        assert_eq!(m.name_of(ip(ME), ip("142.250.74.14")).as_deref(), Some("www.youtube.com"));
        assert_eq!(m.name_for_target(ip(ME), "142.250.74.14:443").as_deref(), Some("www.youtube.com"));
        assert_eq!(m.name_for_target(ip(ME), "[::ffff:142.250.74.14]:443").as_deref(), Some("www.youtube.com"));
        assert!(m.name_of(ip(ME), ip("142.250.74.15")).is_none());
        assert!(m.name_for_target(ip(ME), "youtube.com:443").is_none());
    }

    #[test]
    fn one_clients_names_do_not_apply_to_another() {
        let m = IpNames::default();
        m.remember(ip(ME), ip("198.51.100.7"), "googlevideo.com");
        assert!(m.name_of(ip("203.0.113.6"), ip("198.51.100.7")).is_none());
    }

    #[test]
    fn the_last_name_for_an_address_wins() {
        let m = IpNames::default();
        m.remember(ip(ME), ip("198.51.100.7"), "a.example");
        m.remember(ip(ME), ip("198.51.100.7"), "b.example");
        assert_eq!(m.name_of(ip(ME), ip("198.51.100.7")).as_deref(), Some("b.example"));
    }

    #[test]
    fn entries_expire() {
        let m = IpNames::new(Duration::from_secs(10), 100);
        let t0 = Instant::now();
        m.remember_at(ip(ME), ip("198.51.100.7"), "a.example", t0);
        assert!(m.name_at(ip(ME), ip("198.51.100.7"), t0 + Duration::from_secs(9)).is_some());
        assert!(m.name_at(ip(ME), ip("198.51.100.7"), t0 + Duration::from_secs(10)).is_none());
    }

    #[test]
    fn the_map_is_bounded_and_the_oldest_go_first() {
        let m = IpNames::new(TTL, 3);
        let t0 = Instant::now();
        for i in 1..=5u8 {
            m.remember_at(ip(ME), IpAddr::from([198, 51, 100, i]), "a.example", t0 + Duration::from_secs(i as u64));
        }
        assert_eq!(m.len(), 3);
        let now = t0 + Duration::from_secs(6);
        assert!(m.name_at(ip(ME), ip("198.51.100.1"), now).is_none());
        assert!(m.name_at(ip(ME), ip("198.51.100.2"), now).is_none());
        assert!(m.name_at(ip(ME), ip("198.51.100.5"), now).is_some());
        // Stores of the same key again and again keep the queue bounded too.
        for i in 0..100u64 {
            m.remember_at(ip(ME), ip("198.51.100.5"), if i % 2 == 0 { "b.example" } else { "c.example" }, now + Duration::from_secs(i));
        }
        let inner = m.inner.lock().unwrap();
        assert!(inner.order.len() <= 6, "{}", inner.order.len());
        assert!(inner.map.len() <= 3);
    }

    #[test]
    fn junk_and_special_addresses_are_not_stored() {
        let m = IpNames::default();
        m.remember(ip(ME), ip("0.0.0.0"), "blocked.example");
        m.remember(ip(ME), ip("127.0.0.1"), "local.example");
        m.remember(ip(ME), ip("198.51.100.7"), "no-dot");
        m.remember(ip(ME), ip("198.51.100.8"), "1.2.3.4");
        m.remember(ip(ME), ip("198.51.100.9"), "bad name.example");
        assert_eq!(m.len(), 0);
    }

    fn response(name: &str, records: Vec<RData<'static>>) -> Vec<u8> {
        let mut p = Packet::new_reply(7);
        let n = Name::new_unchecked(name).into_owned();
        p.questions.push(Question::new(n.clone(), QTYPE::TYPE(TYPE::A), QCLASS::CLASS(CLASS::IN), false));
        for r in records {
            p.answers.push(ResourceRecord::new(n.clone(), CLASS::IN, 300, r));
        }
        p.build_bytes_vec().unwrap()
    }

    #[test]
    fn dns_answers_fill_the_map_under_the_asked_name() {
        let m = IpNames::default();
        let a = response(
            "www.youtube.com",
            vec![
                RData::CNAME(CNAME(Name::new_unchecked("youtube-ui.l.google.com").into_owned())),
                RData::A(A { address: u32::from(std::net::Ipv4Addr::new(142, 250, 74, 14)) }),
                RData::AAAA(AAAA { address: u128::from("2a00:1450::200e".parse::<std::net::Ipv6Addr>().unwrap()) }),
            ],
        );
        m.remember_dns_answer(ip(ME), &a);
        assert_eq!(m.name_of(ip(ME), ip("142.250.74.14")).as_deref(), Some("www.youtube.com"));
        assert_eq!(m.name_of(ip(ME), ip("2a00:1450::200e")).as_deref(), Some("www.youtube.com"));
    }

    #[test]
    fn queries_and_junk_are_ignored() {
        let m = IpNames::default();
        let mut q = Packet::new_query(1);
        q.set_flags(PacketFlag::RECURSION_DESIRED);
        q.questions.push(Question::new(Name::new_unchecked("a.example"), QTYPE::TYPE(TYPE::A), QCLASS::CLASS(CLASS::IN), false));
        m.remember_dns_answer(ip(ME), &q.build_bytes_vec().unwrap());
        m.remember_dns_answer(ip(ME), b"not dns");
        assert_eq!(m.len(), 0);
    }
}
