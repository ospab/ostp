//! `ostp://` share-link codec, shared by the CLI and the server's subscribe API.
//!
//! `ostp://KEY@HOST:PORT?type=uot&tls=1&sni=..&insecure=1&path=%2F..&tun=true&dns=..&owndns=true&name=..`
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
    pub name: Option<String>,
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
            name: None,
        }
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
                "name" => link.name = non_empty(v),
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
        if let Some(name) = &self.name {
            q.push(format!("name={}", encode(name)));
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
        let uri = "ostp://k1@vpn.example.com:443?type=uot&tls=1&sni=cdn.example.com&insecure=1&path=%2Fs3cr3t&tun=true&dns=1.1.1.1&owndns=true&name=My%20VPN";
        let l = ShareLink::parse(uri).unwrap();
        assert_eq!(l.transport, LinkTransport::Uot);
        assert!(l.tls && l.insecure && l.tun && l.owndns);
        assert_eq!(l.sni.as_deref(), Some("cdn.example.com"));
        assert_eq!(l.path.as_deref(), Some("/s3cr3t"));
        assert_eq!(l.dns.as_deref(), Some("1.1.1.1"));
        assert_eq!(l.name.as_deref(), Some("My VPN"));
        assert_eq!(l.to_uri(), uri);
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
