//! From a share link or a subscription document to the server to dial.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use ostp_core::share_link::{LinkTransport, ShareLink};
use ostp_core::subscription::SubscriptionDoc;

use crate::Error;

/// How datagrams reach the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carrier {
    /// OSTP over UDP.
    Udp,
    /// UDP-over-TCP: the same datagrams with a 2-byte length prefix on one TCP connection.
    Uot,
}

impl Carrier {
    pub fn as_str(self) -> &'static str {
        match self {
            Carrier::Udp => "udp",
            Carrier::Uot => "uot",
        }
    }
}

/// A server this client can dial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server {
    pub key: String,
    pub host: String,
    pub port: u16,
    pub carrier: Carrier,
    /// The link's display name, if it has one.
    pub name: Option<String>,
}

impl Server {
    /// `host:port`, with brackets for an IPv6 literal.
    pub fn address(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// A parsed share link, if this client supports what it asks for. TLS and the HTTP
    /// upgrade (`tls=1`, `path=`) need a TLS client, which this one does not have.
    pub fn from_link(link: &ShareLink) -> Result<Server, Error> {
        if link.tls {
            return Err(Error::Link(String::from(
                "the link uses TLS, which this client does not support yet; use a UDP or plain UoT link",
            )));
        }
        if link.path.is_some() {
            return Err(Error::Link(String::from(
                "the link goes through a web server (path=), which needs TLS; use a UDP or plain UoT link",
            )));
        }
        if link.key.is_empty() {
            return Err(Error::Link(String::from("the link has no access key")));
        }
        Ok(Server {
            key: link.key.clone(),
            host: link.host.clone(),
            port: link.port,
            carrier: match link.transport {
                LinkTransport::Udp => Carrier::Udp,
                LinkTransport::Uot => Carrier::Uot,
            },
            name: link.name.clone(),
        })
    }

    /// Parse an `ostp://` share link.
    pub fn parse(link: &str) -> Result<Server, Error> {
        let l = ShareLink::parse(link.trim()).map_err(|e| Error::Link(format!("not a valid ostp:// link: {e}")))?;
        Server::from_link(&l)
    }
}

/// The servers of a subscription document this client can use, in the document's order
/// (best first), and for every link it skipped, why.
pub fn usable_servers(doc: &SubscriptionDoc) -> (Vec<Server>, Vec<String>) {
    let mut ok = Vec::new();
    let mut skipped = Vec::new();
    for (i, raw) in doc.links.iter().enumerate() {
        match ShareLink::parse(raw) {
            Ok(l) => match Server::from_link(&l) {
                Ok(s) => ok.push(s),
                Err(e) => skipped.push(format!("link {}: {}", i + 1, e)),
            },
            Err(e) => skipped.push(format!("link {}: not a valid link: {}", i + 1, e)),
        }
    }
    (ok, skipped)
}

/// Parse the body of a subscription response (JSON, a list of links, or base64 of one).
pub fn parse_subscription(body: &str) -> Result<SubscriptionDoc, Error> {
    SubscriptionDoc::parse(body).map_err(|e| Error::Link(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_and_uot_links_are_accepted() {
        let s = Server::parse("ostp://k1@10.0.2.2:50000?type=udp").unwrap();
        assert_eq!((s.host.as_str(), s.port, s.carrier), ("10.0.2.2", 50000, Carrier::Udp));
        let s = Server::parse("ostp://k1@vpn.example.com:443?type=uot").unwrap();
        assert_eq!(s.carrier, Carrier::Uot);
        assert_eq!(s.address(), "vpn.example.com:443");
    }

    #[test]
    fn tls_links_are_refused_with_a_reason() {
        let e = Server::parse("ostp://k1@vpn.example.com:443?type=uot&tls=1").unwrap_err();
        assert!(e.to_string().contains("TLS"));
    }

    #[test]
    fn subscription_keeps_order_and_reports_skipped_links() {
        let doc = parse_subscription(
            "ostp://k@a.example:443?type=uot&tls=1\nostp://k@b.example:50000?type=udp\nostp://k@c.example:443?type=uot\n",
        )
        .unwrap();
        let (ok, skipped) = usable_servers(&doc);
        assert_eq!(ok.iter().map(|s| s.host.as_str()).collect::<Vec<_>>(), ["b.example", "c.example"]);
        assert_eq!(skipped.len(), 1);
        assert!(skipped[0].starts_with("link 1:"));
    }
}
