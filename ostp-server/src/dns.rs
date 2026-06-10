use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::{RwLock, Mutex};
use simple_dns::{Packet, rdata::RData, ResourceRecord, CLASS, TYPE, QTYPE};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    /// Включить полный DNS: кастомные домены + AdBlock списки + DoH форвардинг
    pub enabled: bool,
    /// Перехватывать весь UDP-трафик к порту :53 и резолвить через DoH,
    /// даже если `enabled = false`. Это предотвращает DNS-утечки через сервер.
    #[serde(default)]
    pub intercept_all_port53: bool,
    /// Порт на котором встроенный DNS-сервер слушает UDP-запросы (по умолчанию 50053).
    /// Клиенты могут указать <server_ip>:50053 в качестве DNS-сервера.
    #[serde(default = "default_dns_local_port")]
    pub local_port: u16,
    pub doh_upstream: String,
    pub adblock_urls: Vec<String>,
    pub custom_domains: HashMap<String, String>,
}

fn default_dns_local_port() -> u16 { 50053 }

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            intercept_all_port53: false,
            local_port: 50053,
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
    adblock_trie: RwLock<HashSet<String>>,
    query_log: Mutex<VecDeque<DnsQueryLog>>,
    reqwest_client: RwLock<reqwest::Client>,
}

impl DnsServer {
    pub fn new(config: DnsConfig) -> Arc<Self> {
        let server = Arc::new(Self {
            config: RwLock::new(config.clone()),
            adblock_trie: RwLock::new(HashSet::new()),
            query_log: Mutex::new(VecDeque::with_capacity(1000)),
            reqwest_client: RwLock::new(reqwest::Client::builder().build().unwrap_or_default()),
        });

        // Загружаем блок-листы при старте если DNS включён
        if config.enabled && !config.adblock_urls.is_empty() {
            let server_clone = server.clone();
            tokio::spawn(async move {
                server_clone.update_blocklists().await;
            });
        }

        server
    }

    pub async fn update_proxy(&self, outbound: Option<&crate::outbound::OutboundConfig>) {
        let mut builder = reqwest::Client::builder();
        if let Some(outbound) = outbound {
            if outbound.enabled {
                // Determine if DoH upstream domain matches any proxy rules
                // We simplify by just setting the proxy for the client if outbound is globally enabled
                // But we should check if the DoH URL domain matches Proxy.
                // Since DoH usually goes to 1.1.1.1 or cloudflare-dns.com, if proxy is enabled, we route it.
                // Better: just route if proxy is enabled and protocol is socks5/http.
                let proxy_url = match outbound.protocol.as_str() {
                    "socks5" => Some(format!("socks5h://{}:{}", outbound.address, outbound.port)),
                    "http" => Some(format!("http://{}:{}", outbound.address, outbound.port)),
                    _ => None,
                };
                if let Some(url) = proxy_url {
                    if let Ok(proxy) = reqwest::Proxy::all(&url) {
                        builder = builder.proxy(proxy);
                    }
                }
            }
        }
        if let Ok(client) = builder.build() {
            *self.reqwest_client.write().await = client;
        }
    }


    /// Скачать и обновить все AdBlock-листы.
    pub async fn update_blocklists(&self) {
        let urls = {
            let cfg = self.config.read().await;
            cfg.adblock_urls.clone()
        };

        let mut new_blocked = HashSet::new();

        for url in &urls {
            tracing::info!("DNS: downloading AdBlock list from {url}");
            let client = self.reqwest_client.read().await.clone();
            match client.get(url).send().await {
                Ok(resp) => {
                    match resp.text().await {
                        Ok(text) => {
                            for line in text.lines() {
                                let line = line.trim();
                                if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
                                    continue;
                                }
                                // Формат hosts: "0.0.0.0 ads.google.com" или просто "ads.google.com"
                                // Формат adblock: "||ads.google.com^" или "ads.google.com"
                                let domain = if line.starts_with("||") && line.ends_with('^') {
                                    line.trim_start_matches("||").trim_end_matches('^')
                                } else {
                                    let parts: Vec<&str> = line.split_whitespace().collect();
                                    if parts.len() >= 2 && (parts[0] == "0.0.0.0" || parts[0] == "127.0.0.1") {
                                        parts[1]
                                    } else if parts.len() == 1 {
                                        parts[0]
                                    } else {
                                        continue;
                                    }
                                };
                                // Пропускаем localhost и wildcard-мусор
                                if domain == "localhost" || domain.contains('*') || domain.contains(' ') {
                                    continue;
                                }
                                new_blocked.insert(domain.to_lowercase());
                            }
                        }
                        Err(e) => tracing::warn!("DNS: failed to read AdBlock list {url}: {e}"),
                    }
                }
                Err(e) => tracing::warn!("DNS: failed to fetch AdBlock list {url}: {e}"),
            }
        }

        tracing::info!("DNS: loaded {} domains into AdBlock engine from {} lists", new_blocked.len(), urls.len());
        *self.adblock_trie.write().await = new_blocked;
    }

    /// Резолвить DNS-запрос.
    ///
    /// Поведение зависит от конфигурации:
    /// - `enabled=true`:  кастомные домены → AdBlock → DoH
    /// - `intercept_all_port53=true`: минуя AdBlock/custom, всегда форвардит через DoH
    /// - оба `false`: возвращает `None` (трафик идёт напрямую к целевому DNS-серверу)
    pub async fn resolve(&self, payload: &[u8], client_ip: std::net::IpAddr) -> Option<Vec<u8>> {
        let cfg = self.config.read().await;

        // Если оба флага выключены — не вмешиваемся
        if !cfg.enabled && !cfg.intercept_all_port53 {
            return None;
        }

        let enabled = cfg.enabled;
        let intercept = cfg.intercept_all_port53;
        let doh_url = cfg.doh_upstream.clone();
        drop(cfg); // Освобождаем блокировку до IO

        // Парсим DNS-пакет
        let packet = match Packet::parse(payload) {
            Ok(p) => p,
            Err(_) => return None,
        };
        if packet.questions.is_empty() {
            return None;
        }

        let question = &packet.questions[0];
        let qname = question.qname.to_string().to_lowercase();

        // ── Полный DNS-режим (enabled=true) ───────────────────────────────────
        if enabled {
            // 1. Кастомные домены (прямой ответ из конфига)
            {
                let cfg = self.config.read().await;
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
                            return response.build_bytes_vec().ok();
                        }
                    }
                }
            }

            // 2. AdBlock (suffix matching)
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
                // Возвращаем пустой NXDOMAIN-ответ
                let mut response = Packet::new_reply(packet.id());
                response.questions.push(question.clone());
                tracing::debug!("DNS AdBlock: blocked {qname} for {client_ip}");
                return response.build_bytes_vec().ok();
            }
        }

        // ── Форвардинг через DoH ──────────────────────────────────────────────
        // Работает и при enabled=true и при intercept_all_port53=true
        tracing::debug!("DNS: resolving {qname} via DoH for {client_ip}");
        let client = self.reqwest_client.read().await.clone();
        match client
            .post(&doh_url)
            .header("Content-Type", "application/dns-message")
            .header("Accept", "application/dns-message")
            .body(payload.to_vec())
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(bytes) = resp.bytes().await {
                    return Some(bytes.to_vec());
                }
            }
            Ok(resp) => {
                tracing::warn!("DNS DoH upstream returned {}: {qname}", resp.status());
            }
            Err(e) => {
                tracing::warn!("DNS DoH upstream error for {qname}: {e}");
            }
        }

        // Если DoH упал и мы в режиме перехвата — возвращаем SERVFAIL
        // чтобы не пустить запрос напрямую к 8.8.8.8 с IP сервера
        if intercept && !enabled {
            let mut response = Packet::new_reply(packet.id());
            response.questions.push(question.clone());
            // Устанавливаем RCODE=2 (SERVFAIL) вручную в raw байтах
            if let Ok(mut bytes) = response.build_bytes_vec() {
                if bytes.len() >= 4 {
                    bytes[3] = (bytes[3] & 0xF0) | 0x02; // RCODE=SERVFAIL
                }
                return Some(bytes);
            }
        }

        None
    }

    /// Запустить встроенный UDP DNS-сервер на порту `config.local_port`.
    ///
    /// Клиент может явно указать `<server_ip>:<local_port>` как DNS-сервер
    /// в настройках — тогда все DNS-запросы туннелируются и резолвятся здесь.
    pub async fn run_local_udp_listener(self: Arc<Self>) {
        let port = self.config.read().await.local_port;
        let bind_addr = format!("0.0.0.0:{port}");

        let socket = match tokio::net::UdpSocket::bind(&bind_addr).await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                tracing::error!("Built-in DNS server failed to bind on {bind_addr}: {e}");
                return;
            }
        };
        tracing::info!("Built-in DNS server listening on UDP {bind_addr}");

        let mut buf = vec![0u8; 4096];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((n, peer)) => {
                    let query = buf[..n].to_vec();
                    let srv = self.clone();
                    let sock = socket.clone();
                    let client_ip = peer.ip();
                    tokio::spawn(async move {
                        if let Some(response) = srv.resolve(&query, client_ip).await {
                            let _ = sock.send_to(&response, peer).await;
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!("Built-in DNS listener recv error: {e}");
                }
            }
        }
    }

    async fn log_query(&self, domain: String, client_ip: String, blocked: bool) {
        let mut log = self.query_log.lock().await;
        if log.len() >= 1000 {
            log.pop_front();
        }
        log.push_back(DnsQueryLog {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
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
