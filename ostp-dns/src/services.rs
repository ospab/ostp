//! Built-in data: services that can be blocked as a whole, safe-search
//! rewrites, and the names browsers use to skip the system resolver.

/// (id, name, domains blocked with their subdomains).
pub const SERVICES: &[(&str, &str, &[&str])] = &[
    ("tiktok", "TikTok", &["tiktok.com", "tiktokv.com", "tiktokcdn.com", "tiktokcdn-us.com", "byteoversea.com", "ibytedtos.com", "musical.ly"]),
    ("facebook", "Facebook", &["facebook.com", "facebook.net", "fbcdn.net", "fb.com", "fb.me", "fbsbx.com", "messenger.com"]),
    ("instagram", "Instagram", &["instagram.com", "cdninstagram.com", "ig.me", "instagr.am"]),
    ("youtube", "YouTube", &["youtube.com", "youtu.be", "ytimg.com", "googlevideo.com", "youtube-nocookie.com", "youtubei.googleapis.com", "youtube.googleapis.com"]),
    ("twitter", "X (Twitter)", &["twitter.com", "x.com", "twimg.com", "t.co"]),
    ("vk", "VK", &["vk.com", "vk.ru", "userapi.com", "vk-cdn.net", "vkuser.net", "vk.me"]),
    ("telegram", "Telegram", &["telegram.org", "telegram.me", "t.me", "telesco.pe", "tdesktop.com"]),
    ("whatsapp", "WhatsApp", &["whatsapp.com", "whatsapp.net", "wa.me"]),
    ("discord", "Discord", &["discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media"]),
    ("reddit", "Reddit", &["reddit.com", "redd.it", "redditmedia.com", "redditstatic.com"]),
    ("twitch", "Twitch", &["twitch.tv", "twitchcdn.net", "ttvnw.net", "jtvnw.net"]),
    ("netflix", "Netflix", &["netflix.com", "nflxvideo.net", "nflximg.net", "nflxext.com", "nflxso.net"]),
    ("steam", "Steam", &["steampowered.com", "steamcommunity.com", "steamstatic.com", "steamcontent.com"]),
    ("roblox", "Roblox", &["roblox.com", "rbxcdn.com", "rbx.com"]),
];

/// Safe search: (name, CNAME target). Google's ccTLDs are matched by
/// prefix in `safe_search_target`.
const SAFE_SEARCH: &[(&str, &str)] = &[
    ("www.youtube.com", "restrict.youtube.com"),
    ("m.youtube.com", "restrict.youtube.com"),
    ("youtubei.googleapis.com", "restrict.youtube.com"),
    ("youtube.googleapis.com", "restrict.youtube.com"),
    ("www.youtube-nocookie.com", "restrict.youtube.com"),
    ("www.bing.com", "strict.bing.com"),
    ("bing.com", "strict.bing.com"),
    ("duckduckgo.com", "safe.duckduckgo.com"),
    ("www.duckduckgo.com", "safe.duckduckgo.com"),
    ("yandex.ru", "familysearch.yandex.ru"),
    ("www.yandex.ru", "familysearch.yandex.ru"),
    ("yandex.com", "familysearch.yandex.ru"),
    ("www.yandex.com", "familysearch.yandex.ru"),
    ("ya.ru", "familysearch.yandex.ru"),
    ("www.ya.ru", "familysearch.yandex.ru"),
];

pub fn safe_search_target(name: &str) -> Option<&'static str> {
    if let Some((_, t)) = SAFE_SEARCH.iter().find(|(n, _)| *n == name) {
        return Some(t);
    }
    // www.google.com, www.google.ru, google.co.uk ...
    let bare = name.strip_prefix("www.").unwrap_or(name);
    if let Some(rest) = bare.strip_prefix("google.") {
        if !rest.is_empty() && rest.split('.').all(|l| (2..=3).contains(&l.len()) && l.chars().all(|c| c.is_ascii_alphabetic())) {
            return Some("forcesafesearch.google.com");
        }
    }
    None
}

/// Firefox turns its own DNS over HTTPS off when this name does not resolve.
pub const DOH_CANARY: &str = "use-application-dns.net";

/// Public DNS-over-HTTPS endpoints browsers switch to on their own.
pub const DOH_HOSTS: &[&str] = &[
    "dns.google",
    "dns.google.com",
    "cloudflare-dns.com",
    "mozilla.cloudflare-dns.com",
    "chrome.cloudflare-dns.com",
    "one.one.one.one",
    "1dot1dot1dot1.cloudflare-dns.com",
    "dns.quad9.net",
    "dns9.quad9.net",
    "doh.opendns.com",
    "doh.cleanbrowsing.org",
    "dns.adguard-dns.com",
    "dns.adguard.com",
    "doh.dns.sb",
    "dns.nextdns.io",
    "doh.mullvad.net",
    "common.dot.dns.yandex.net",
];

/// Public resolvers that speak encrypted DNS on their own addresses. Android
/// ("Private DNS: automatic", DoT on 853 and on Android 13+ DoH over QUIC on
/// 443) and Chrome's secure DNS switch to it by themselves when the system
/// DNS is one of these, which is what the VPN hands out (1.1.1.1, 8.8.8.8).
/// Those queries would pass through the tunnel encrypted and never reach the
/// filter, so while it is on they are refused and the device falls back to
/// plain port 53, which the server answers.
pub const RESOLVER_IPS: &[&str] = &[
    // Cloudflare
    "1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2", "1.1.1.3", "1.0.0.3",
    "2606:4700:4700::1111", "2606:4700:4700::1001", "2606:4700:4700::1112", "2606:4700:4700::1002",
    "2606:4700:4700::1113", "2606:4700:4700::1003",
    // Google
    "8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844",
    // Quad9
    "9.9.9.9", "149.112.112.112", "9.9.9.10", "149.112.112.10", "9.9.9.11", "149.112.112.11",
    "2620:fe::fe", "2620:fe::9", "2620:fe::10", "2620:fe::fe:10", "2620:fe::11", "2620:fe::fe:11",
    // AdGuard
    "94.140.14.14", "94.140.15.15", "94.140.14.15", "94.140.15.16", "94.140.14.140", "94.140.14.141",
    "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff",
    // OpenDNS
    "208.67.222.222", "208.67.220.220", "208.67.222.123", "208.67.220.123",
    "2620:119:35::35", "2620:119:53::53",
    // CleanBrowsing, DNS.SB, Mullvad, NextDNS anycast, Yandex
    "185.228.168.9", "185.228.169.9", "185.228.168.168", "185.228.169.168",
    "185.222.222.222", "45.11.45.11", "194.242.2.2", "194.242.2.3", "194.242.2.4",
    "45.90.28.0", "45.90.30.0", "77.88.8.8", "77.88.8.1", "77.88.8.88", "77.88.8.2",
];

pub fn is_public_resolver(ip: std::net::IpAddr) -> bool {
    static PARSED: std::sync::OnceLock<Vec<std::net::IpAddr>> = std::sync::OnceLock::new();
    let ip = match ip {
        std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped().map(std::net::IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    };
    PARSED.get_or_init(|| RESOLVER_IPS.iter().filter_map(|s| s.parse().ok()).collect()).contains(&ip)
}

pub fn service_of(name: &str, blocked: &[String]) -> Option<&'static str> {
    for (id, label, domains) in SERVICES {
        if !blocked.iter().any(|b| b == id) {
            continue;
        }
        if domains.iter().any(|d| name == *d || name.ends_with(&format!(".{d}"))) {
            return Some(label);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_search_names() {
        assert_eq!(safe_search_target("www.google.com"), Some("forcesafesearch.google.com"));
        assert_eq!(safe_search_target("www.google.co.uk"), Some("forcesafesearch.google.com"));
        assert_eq!(safe_search_target("google.ru"), Some("forcesafesearch.google.com"));
        assert_eq!(safe_search_target("mail.google.com"), None);
        assert_eq!(safe_search_target("www.youtube.com"), Some("restrict.youtube.com"));
        assert_eq!(safe_search_target("example.com"), None);
    }

    #[test]
    fn services_match_subdomains() {
        let b = vec!["tiktok".to_string()];
        assert_eq!(service_of("v16.tiktokcdn.com", &b), Some("TikTok"));
        assert_eq!(service_of("tiktok.com", &b), Some("TikTok"));
        assert_eq!(service_of("youtube.com", &b), None);
        assert_eq!(service_of("nottiktok.com", &b), None);
    }
}
