use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::{RwLock, Mutex};
use simple_dns::{Packet, rdata::RData, ResourceRecord, CLASS, TYPE, QTYPE};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    pub enabled: bool,
    pub doh_upstream: String,
    pub adblock_urls: Vec<String>,
    pub custom_domains: HashMap<String, String>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            doh_upstream: "https://cloudflare-dns.com/dns-query".to_string(),
            adblock_urls: vec![],
            custom_domains: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsQueryLog {
    pub timestamp: u64,
    pub domain: String,
    pub client_ip: String,
    pub blocked: bool,
}

pub struct DnsServer {
    pub config: RwLock<DnsConfig>,
    adblock_trie: RwLock<HashSet<String>>, // Simplified to HashSet for now, or maybe a suffix tree
    query_log: Mutex<VecDeque<DnsQueryLog>>,
    reqwest_client: reqwest::Client,
}

impl DnsServer {
    pub fn new(config: DnsConfig) -> Arc<Self> {
        let server = Arc::new(Self {
            config: RwLock::new(config.clone()),
            adblock_trie: RwLock::new(HashSet::new()),
            query_log: Mutex::new(VecDeque::with_capacity(1000)),
            reqwest_client: reqwest::Client::builder()
                .build()
                .unwrap_or_default(),
        });

        // Spawn a background task to download blocklists
        if config.enabled && !config.adblock_urls.is_empty() {
            let server_clone = server.clone();
            tokio::spawn(async move {
                server_clone.update_blocklists().await;
            });
        }

        server
    }

    pub async fn update_blocklists(&self) {
        let urls = {
            let cfg = self.config.read().await;
            cfg.adblock_urls.clone()
        };

        let mut new_blocked = HashSet::new();
        
        for url in urls {
            if let Ok(resp) = self.reqwest_client.get(&url).send().await {
                if let Ok(text) = resp.text().await {
                    for line in text.lines() {
                        let line = line.trim();
                        if line.is_empty() || line.starts_with('#') {
                            continue;
                        }
                        // Support standard hosts format: "0.0.0.0 ads.google.com" or just "ads.google.com"
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        let domain = if parts.len() >= 2 && (parts[0] == "0.0.0.0" || parts[0] == "127.0.0.1") {
                            parts[1]
                        } else {
                            parts[0]
                        };
                        new_blocked.insert(domain.to_lowercase());
                    }
                }
            }
        }

        tracing::info!("Loaded {} domains into AdBlock engine", new_blocked.len());
        *self.adblock_trie.write().await = new_blocked;
    }

    pub async fn resolve(&self, payload: &[u8], client_ip: std::net::IpAddr) -> Option<Vec<u8>> {
        let cfg = self.config.read().await;
        if !cfg.enabled {
            return None; // If DNS is disabled, fallback to standard UDP proxying
        }

        // Parse DNS packet
        let packet = match Packet::parse(payload) {
            Ok(p) => p,
            Err(_) => return None,
        };

        if packet.questions.is_empty() {
            return None;
        }

        let question = &packet.questions[0];
        let qname = question.qname.to_string().to_lowercase();
        
        // Check Custom Domains
        if let Some(ip_str) = cfg.custom_domains.get(&qname) {
            if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                if question.qtype == QTYPE::TYPE(TYPE::A) {
                    let mut response = Packet::new_reply(packet.id());
                    response.questions.push(question.clone());
                    response.answers.push(ResourceRecord::new(
                        question.qname.clone(),
                        CLASS::IN,
                        60,
                        RData::A(ip.into()),
                    ));
                    self.log_query(qname, client_ip.to_string(), false).await;
                    return response.build_bytes_vec().ok();
                }
            }
        }

        // Check AdBlock (Suffix matching not implemented in this simple hashset, for full pi-hole we need suffix match)
        // Let's do a simple suffix check
        let blocked = {
            let blocked_domains = self.adblock_trie.read().await;
            let mut parts: Vec<&str> = qname.split('.').collect();
            let mut is_blocked = false;
            while !parts.is_empty() {
                let suffix = parts.join(".");
                if blocked_domains.contains(&suffix) {
                    is_blocked = true;
                    break;
                }
                parts.remove(0);
            }
            is_blocked
        };

        if blocked {
            let mut response = Packet::new_reply(packet.id());
            response.questions.push(question.clone());
            self.log_query(qname, client_ip.to_string(), true).await;
            return response.build_bytes_vec().ok();
        }

        // Forward to DoH
        let doh_url = cfg.doh_upstream.clone();
        drop(cfg); // Release config lock before making network request
        
        if let Ok(resp) = self.reqwest_client.post(&doh_url)
            .header("Content-Type", "application/dns-message")
            .header("Accept", "application/dns-message")
            .body(payload.to_vec())
            .send()
            .await 
        {
            if resp.status().is_success() {
                if let Ok(bytes) = resp.bytes().await {
                    self.log_query(qname, client_ip.to_string(), false).await;
                    return Some(bytes.to_vec());
                }
            }
        }

        None
    }

    async fn log_query(&self, domain: String, client_ip: String, blocked: bool) {
        let mut log = self.query_log.lock().await;
        if log.len() >= 1000 {
            log.pop_front();
        }
        log.push_back(DnsQueryLog {
            timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            domain,
            client_ip,
            blocked,
        });
    }

    pub async fn get_queries(&self) -> Vec<DnsQueryLog> {
        let log = self.query_log.lock().await;
        log.iter().cloned().collect()
    }
}
