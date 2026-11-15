//! `ostp://` share-link codec, shared by the CLI and the server's subscribe API.
//!
//! `ostp://KEY@HOST:PORT?type=uot&tls=1&sni=..&insecure=1&path=%2F..&tun=true&dns=..&owndns=true&dnsall=true&name=..&pk=..`
//!
//! `pk` is the server's public key (protocol v6, base64url); a link without it is a v5 profile.
//!
//! The Dart (Android) and JS (desktop GUI) ports must stay in step with this;
//! the vectors in the tests below are the shared reference.

use anyhow::{anyhow, bail, Result};
use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};

/// Everything except RFC 3986 unreserved characters.
const COMPONENT: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'.').remove(b'_').remove(b'~');

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkTransport {
    Udp,
    Uot,
}

impl LinkTransport {
    pub fn as_str(self) -> &'static str {
        match self {
            LinkTransport::Udp => "udp",
            LinkTransport::Uot => "uot",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareLink {
    pub key: String,
    pub host: String,
    pub port: u16,
    pub transport: LinkTransport,
    pub tls: bool,
    pub sni: Option<String>,
    pub insecure: bool,
    /// HTTP-upgrade path (e.g. through nginx on 443).
    pub path: Option<String>,
    pub tun: bool,
    pub dns: Option<String>,
    pub owndns: bool,
    /// The server answers every DNS query in the tunnel, whichever resolver it
    /// was sent to, and refuses encrypted DNS (the operator's choice, declared
    /// here so apps can say so before the first connection).
    pub dnsall: bool,
    pub name: Option<String>,
    /// The server's static public key (`pk=`, base64url, 32 bytes). With it
    /// the link is a protocol v6 profile and the client checks the server;
    /// without it, a v5 profile.
    pub pk: Option<[u8; 32]>,
}

impl ShareLink {
    pub fn new(key: impl Into<String>, host: impl Into<String>, port: u16) -> Self {
        Self {
            key: key.into(),
            host: host.into(),
            port,
            transport: LinkTransport::Udp,
            tls: false,
            sni: None,
            insecure: false,
            path: None,
            tun: false,
            dns: None,
            owndns: false,
            dnsall: false,
            name: None,
            pk: None,
        }
    }

    /// The same link as a v6 profile for the server with this public key.
    pub fn with_pk(mut self, pk: Option<[u8; 32]>) -> Self {
        self.pk = pk;
        self
    }

    /// Plain UDP link; `owndns` when the server runs its own resolver.
    pub fn udp_for(key: impl Into<String>, host: impl Into<String>, port: u16, owndns: bool) -> Self {
        let mut l = Self::new(key, host, port);
        l.owndns = owndns;
        l
    }

    /// TLS link (OSTP over TLS, optionally behind a web server's upgrade `path`).
    pub fn tls_for(key: impl Into<String>, host: impl Into<String>, port: u16, path: Option<String>, owndns: bool) -> Self {
        let mut l = Self::new(key, host, port);
        l.transport = LinkTransport::Uot;
        l.tls = true;
        l.path = path;
        l.owndns = owndns;
        l
    }

    /// `host:port`, bracketing IPv6 literals.
    pub fn server(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    pub fn parse(input: &str) -> Result<Self> {
        let input = input.trim();
        let rest = input
            .get(..7)
            .filter(|s| s.eq_ignore_ascii_case("ostp://"))
            .map(|_| &input[7..])
            .ok_or_else(|| anyhow!("not an ostp:// link"))?;
        let rest = rest.split('#').next().unwrap_or(rest);
        let (authority, query) = match rest.split_once('?') {
            Some((a, q)) => (a, q),
            None => (rest, ""),
        };
        let authority = authority.trim_end_matches('/');
        let (key, hostport) = authority
            .rsplit_once('@')
            .ok_or_else(|| anyhow!("link has no access key (expected KEY@HOST:PORT)"))?;
        let key = decode(key)?;
        if key.is_empty() {
            bail!("link has an empty access key");
        }

        let (host, port) = if let Some(v6) = hostport.strip_prefix('[') {
            let (h, p) = v6.split_once(']').ok_or_else(|| anyhow!("unterminated IPv6 address"))?;
            (h, p.strip_prefix(':').ok_or_else(|| anyhow!("link has no port"))?)
        } else {
            hostport.rsplit_once(':').ok_or_else(|| anyhow!("link has no port"))?
        };
        if host.is_empty() {
            bail!("link has no host");
        }
        let port: u16 = port.parse().map_err(|_| anyhow!("invalid port '{port}'"))?;

        let mut link = ShareLink::new(key, host, port);
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let v = decode(v)?;
            match k {
                "type" => {
                    link.transport = match v.to_ascii_lowercase().as_str() {
                        "uot" | "tcp" | "http" => LinkTransport::Uot,
                        _ => LinkTransport::Udp,
                    }
                }
                "tls" => link.tls = truthy(&v),
                "sni" => link.sni = non_empty(v),
                "insecure" => link.insecure = truthy(&v),
                "path" => link.path = non_empty(v),
                "tun" => link.tun = truthy(&v),
                "dns" => link.dns = non_empty(v),
                "owndns" => link.owndns = truthy(&v),
                "dnsall" => link.dnsall = truthy(&v),
                "name" => link.name = non_empty(v),
                // A damaged key is an error: quietly dropping it would turn a
                // v6 profile into a v5 one.
                "pk" => link.pk = Some(crate::server_key::decode_key(&v).map_err(|e| anyhow!("link has an invalid pk: {e}"))?),
                _ => {}
            }
        }
        // TLS and HTTP upgrade only exist on the TCP carrier.
        if link.tls || link.path.is_some() {
            link.transport = LinkTransport::Uot;
        }
        Ok(link)
    }

    pub fn to_uri(&self) -> String {
        let mut q: Vec<String> = vec![format!("type={}", self.transport.as_str())];
        if self.tls {
            q.push("tls=1".into());
        }
        if let Some(sni) = &self.sni {
            q.push(format!("sni={}", encode(sni)));
        }
        if self.insecure {
            q.push("insecure=1".into());
        }
        if let Some(path) = &self.path {
            q.push(format!("path={}", encode(path)));
        }
        if self.tun {
            q.push("tun=true".into());
        }
        if let Some(dns) = &self.dns {
            q.push(format!("dns={}", encode(dns)));
        }
        if self.owndns {
            q.push("owndns=true".into());
        }
        if self.dnsall {
            q.push("dnsall=true".into());
        }
        if let Some(name) = &self.name {
            q.push(format!("name={}", encode(name)));
        }
        if let Some(pk) = &self.pk {
            q.push(format!("pk={}", crate::server_key::encode_key(pk)));
        }
        format!("ostp://{}@{}?{}", encode(&self.key), self.server(), q.join("&"))
    }
}

fn encode(s: &str) -> String {
    utf8_percent_encode(s, COMPONENT).to_string()
}

fn decode(s: &str) -> Result<String> {
    let s = s.replace('+', " ");
    percent_decode_str(&s)
        .decode_utf8()
        .map(|c| c.into_owned())
        .map_err(|_| anyhow!("link contains invalid UTF-8"))
}

fn truthy(v: &str) -> bool {
    matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes")
}

fn non_empty(v: String) -> Option<String> {
    (!v.is_empty()).then_some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The hand-built forms the constructors replaced.
    #[test]
    fn constructors_match_the_old_hand_built_links() {
        for (key, host, port, path, owndns) in [
            ("0123456789abcdef0123456789abcdef", "vpn.example.com", 443u16, Some("/s3cr3t".to_string()), false),
            ("k e/y+1", "2001:db8::1", 8443, None, true),
            ("a%b", "1.2.3.4", 50000, Some("/p ath/\u{43f}".to_string()), true),
        ] {
            let mut old = ShareLink::new(key, host, port);
            old.transport = LinkTransport::Uot;
            old.tls = true;
            old.path = path.clone();
            old.owndns = owndns;
            assert_eq!(ShareLink::tls_for(key, host, port, path, owndns), old);

            let mut old = ShareLink::new(key, host, port);
            old.owndns = owndns;
            assert_eq!(ShareLink::udp_for(key, host, port, owndns), old);
        }
        assert_eq!(
            ShareLink::tls_for("k e", "2001:db8::1", 443, Some("/x".into()), true).to_uri(),
            "ostp://k%20e@[2001:db8::1]:443?type=uot&tls=1&path=%2Fx&owndns=true"
        );
    }

    #[test]
    fn legacy_link_defaults_to_udp() {
        let l = ShareLink::parse("ostp://abc123@1.2.3.4:50000").unwrap();
        assert_eq!((l.key.as_str(), l.host.as_str(), l.port), ("abc123", "1.2.3.4", 50000));
        assert_eq!(l.transport, LinkTransport::Udp);
        assert!(!l.tls);
        assert_eq!(l.to_uri(), "ostp://abc123@1.2.3.4:50000?type=udp");
    }

    #[test]
    fn full_tls_link_round_trips() {
        let uri = "ostp://k1@vpn.example.com:443?type=uot&tls=1&sni=cdn.example.com&insecure=1&path=%2Fs3cr3t&tun=true&dns=1.1.1.1&owndns=true&dnsall=true&name=My%20VPN";
        let l = ShareLink::parse(uri).unwrap();
        assert_eq!(l.transport, LinkTransport::Uot);
        assert!(l.tls && l.insecure && l.tun && l.owndns && l.dnsall);
        assert_eq!(l.sni.as_deref(), Some("cdn.example.com"));
        assert_eq!(l.path.as_deref(), Some("/s3cr3t"));
        assert_eq!(l.dns.as_deref(), Some("1.1.1.1"));
        assert_eq!(l.name.as_deref(), Some("My VPN"));
        assert_eq!(l.to_uri(), uri);
    }

    #[test]
    fn a_link_with_pk_is_a_v6_profile_and_round_trips() {
        let pk = [0xabu8; 32];
        let text = crate::server_key::encode_key(&pk);
        let uri = format!("ostp://k1@vpn.example.com:443?type=uot&tls=1&path=%2Fx&name=A&pk={text}");
        let l = ShareLink::parse(&uri).unwrap();
        assert_eq!(l.pk, Some(pk));
        assert_eq!(l.to_uri(), uri);
        // Without pk it is a v5 profile and the output has no pk.
        let v5 = ShareLink::parse("ostp://k1@h:1?type=udp").unwrap();
        assert_eq!(v5.pk, None);
        assert!(!v5.to_uri().contains("pk="));
        assert_eq!(ShareLink::new("k", "h", 1).with_pk(Some(pk)).to_uri(), format!("ostp://k@h:1?type=udp&pk={text}"));
    }

    #[test]
    fn a_malformed_pk_is_an_error_not_a_v5_profile() {
        let good = crate::server_key::encode_key(&[1u8; 32]);
        for bad in [
            good[..42].to_string(),
            format!("{good}A"),
            format!("{}!", &good[..42]),
            "%%%".to_string(),
            String::new(),
        ] {
            let uri = format!("ostp://k@h:1?pk={bad}");
            assert!(ShareLink::parse(&uri).is_err(), "pk={bad:?} should be refused");
        }
    }

    #[test]
    fn tcp_and_http_types_mean_uot() {
        for t in ["tcp", "http", "uot", "UOT"] {
            let l = ShareLink::parse(&format!("ostp://k@h:1?type={t}")).unwrap();
            assert_eq!(l.transport, LinkTransport::Uot, "type={t}");
        }
    }

    #[test]
    fn tls_or_path_without_type_forces_uot() {
        assert_eq!(ShareLink::parse("ostp://k@h:443?tls=true").unwrap().transport, LinkTransport::Uot);
        assert_eq!(ShareLink::parse("ostp://k@h:443?path=%2Fx").unwrap().transport, LinkTransport::Uot);
    }

    #[test]
    fn ipv6_host_and_slash_before_query() {
        let l = ShareLink::parse("ostp://k@[2001:db8::1]:50000/?type=udp").unwrap();
        assert_eq!(l.host, "2001:db8::1");
        assert_eq!(l.server(), "[2001:db8::1]:50000");
        assert_eq!(l.to_uri(), "ostp://k@[2001:db8::1]:50000?type=udp");
    }

    #[test]
    fn plus_in_query_is_a_space() {
        assert_eq!(ShareLink::parse("ostp://k@h:1?name=My+VPN").unwrap().name.as_deref(), Some("My VPN"));
    }

    #[test]
    fn rejects_malformed_links() {
        for bad in [
            "https://k@h:1",
            "ostp://h:1",
            "ostp://@h:1",
            "ostp://k@h",
            "ostp://k@:1",
            "ostp://k@h:99999",
            "ostp://k@[::1",
        ] {
            assert!(ShareLink::parse(bad).is_err(), "{bad} should not parse");
        }
    }
}
