//! The DNS queries the tunnel sends to resolve a name *inside* the tunnel:
//! plain UDP to a resolver that is reached through WARP, never the server's
//! own resolver.

use anyhow::{anyhow, Result};
use simple_dns::rdata::RData;
use simple_dns::{Name, Packet, PacketFlag, Question, CLASS, QCLASS, QTYPE, RCODE, TYPE};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    A,
    Aaaa,
}

pub fn build_query(id: u16, name: &str, kind: Kind) -> Result<Vec<u8>> {
    let mut p = Packet::new_query(id);
    p.set_flags(PacketFlag::RECURSION_DESIRED);
    let n = Name::new(name).map_err(|e| anyhow!("cannot resolve \"{name}\": not a valid name ({e})"))?;
    let t = match kind {
        Kind::A => TYPE::A,
        Kind::Aaaa => TYPE::AAAA,
    };
    p.questions.push(Question::new(n, QTYPE::TYPE(t), QCLASS::CLASS(CLASS::IN), false));
    p.build_bytes_vec().map_err(|e| anyhow!("cannot build the DNS query: {e}"))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Answer {
    pub id: u16,
    pub ips: Vec<IpAddr>,
    /// Smallest TTL among the address records, seconds.
    pub ttl: Option<u32>,
    pub nxdomain: bool,
    pub truncated: bool,
}

pub fn parse_answer(bytes: &[u8]) -> Result<Answer> {
    let p = Packet::parse(bytes).map_err(|e| anyhow!("unparsable DNS answer: {e}"))?;
    let mut ips = Vec::new();
    let mut ttl: Option<u32> = None;
    for rr in &p.answers {
        let ip = match &rr.rdata {
            RData::A(a) => IpAddr::V4(Ipv4Addr::from(a.address)),
            RData::AAAA(a) => IpAddr::V6(Ipv6Addr::from(a.address)),
            _ => continue,
        };
        ips.push(ip);
        ttl = Some(ttl.map_or(rr.ttl, |t| t.min(rr.ttl)));
    }
    Ok(Answer {
        id: p.id(),
        ips,
        ttl,
        nxdomain: matches!(p.rcode(), RCODE::NameError),
        truncated: p.has_flags(PacketFlag::TRUNCATION),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use simple_dns::ResourceRecord;

    #[test]
    fn query_asks_for_the_name_with_recursion() {
        let q = build_query(0x1234, "example.com", Kind::Aaaa).unwrap();
        let p = Packet::parse(&q).unwrap();
        assert_eq!(p.id(), 0x1234);
        assert!(p.has_flags(PacketFlag::RECURSION_DESIRED));
        assert_eq!(p.questions.len(), 1);
        assert_eq!(p.questions[0].qname.to_string(), "example.com");
        assert!(matches!(p.questions[0].qtype, QTYPE::TYPE(TYPE::AAAA)));
    }

    #[test]
    fn invalid_names_are_refused_before_anything_is_sent() {
        assert!(build_query(1, &"a".repeat(70), Kind::A).is_err(), "a label over 63 bytes");
    }

    #[test]
    fn answer_collects_both_families_and_the_smallest_ttl() {
        let mut p = Packet::new_reply(7);
        let n = Name::new("example.com").unwrap();
        p.answers.push(ResourceRecord::new(n.clone(), CLASS::IN, 300, RData::A(simple_dns::rdata::A { address: u32::from(Ipv4Addr::new(93, 184, 216, 34)) })));
        p.answers.push(ResourceRecord::new(
            n,
            CLASS::IN,
            60,
            RData::AAAA(simple_dns::rdata::AAAA { address: u128::from("2606:2800:220:1::1".parse::<Ipv6Addr>().unwrap()) }),
        ));
        let a = parse_answer(&p.build_bytes_vec().unwrap()).unwrap();
        assert_eq!(a.id, 7);
        assert_eq!(a.ips, vec!["93.184.216.34".parse::<IpAddr>().unwrap(), "2606:2800:220:1::1".parse().unwrap()]);
        assert_eq!(a.ttl, Some(60));
        assert!(!a.nxdomain);
    }

    #[test]
    fn nxdomain_and_garbage_are_told_apart() {
        let mut p = Packet::new_reply(9);
        *p.rcode_mut() = RCODE::NameError;
        let a = parse_answer(&p.build_bytes_vec().unwrap()).unwrap();
        assert!(a.nxdomain && a.ips.is_empty());
        assert!(parse_answer(&[1, 2, 3]).is_err());
    }
}
