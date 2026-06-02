//! Authenticated Relay Node
//!
//! Принимает входящие UDP/TCP (UoT) соединения от клиентов,
//! валидирует HMAC-подпись клиента, используя ключи синхронизированные с upstream-сервера,
//! и слепо пробрасывает авторизованный трафик к целевому upstream-серверу.
//!
//! Архитектура цепочек:
//!   Клиент -> [Relay 1] -> [Relay 2] -> ... -> [Target Server]
//! Каждый Relay скачивает access_keys напрямую с Target Server API.

use anyhow::Result;
use bytes::Bytes;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;

/// Конфигурация Relay-узла.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Адрес(а) для прослушивания входящих соединений (UDP + TCP).
    pub listen_addrs: Vec<String>,
    /// Адрес upstream TCP для пересылки (обычно тот же порт, что и у target-сервера).
    pub upstream_tcp: String,
    /// Адрес upstream UDP.
    pub upstream_udp: String,
    /// URL API target-сервера для получения access_keys.
    /// Пример: "http://127.0.0.1:9090"
    pub upstream_api_url: String,
    /// Bearer-токен для аутентификации на API target-сервера.
    pub upstream_api_token: String,
    /// Интервал синхронизации ключей (секунды).
    pub sync_interval_secs: u64,
}

type SharedKeys = Arc<RwLock<Vec<String>>>;

/// Точка входа Relay-узла.
pub async fn run_relay_node(cfg: RelayConfig) -> Result<()> {
    let shared_keys: SharedKeys = Arc::new(RwLock::new(Vec::new()));

    // Первоначальная синхронизация ключей
    if let Err(e) = sync_keys(&cfg, &shared_keys).await {
        tracing::warn!("Relay: initial key sync failed: {}. Will retry.", e);
    } else {
        let count = shared_keys.read().unwrap_or_else(|e| e.into_inner()).len();
        tracing::info!("Relay: synced {} access key(s) from upstream API", count);
    }

    // Фоновый синхронизатор ключей
    let cfg_clone = cfg.clone();
    let keys_clone = shared_keys.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(cfg_clone.sync_interval_secs)).await;
            match sync_keys(&cfg_clone, &keys_clone).await {
                Ok(count) => tracing::debug!("Relay: refreshed {} access key(s)", count),
                Err(e) => tracing::warn!("Relay: key sync error: {}", e),
            }
        }
    });

    // Запуск UDP relay
    {
        let cfg_udp = cfg.clone();
        let keys_udp = shared_keys.clone();
        tokio::spawn(async move {
            if let Err(e) = run_udp_relay(cfg_udp, keys_udp).await {
                tracing::error!("Relay UDP loop error: {}", e);
            }
        });
    }

    // Запуск TCP (UoT) relay
    run_tcp_relay(cfg, shared_keys).await
}

/// Синхронизация access_keys с upstream API.
async fn sync_keys(cfg: &RelayConfig, shared_keys: &SharedKeys) -> Result<usize> {
    let url = format!("{}/api/users", cfg.upstream_api_url.trim_end_matches('/'));

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    let mut req = client.get(&url);
    if !cfg.upstream_api_token.is_empty() {
        req = req.header("Authorization", format!("Bearer {}", cfg.upstream_api_token));
    }

    let resp = req.send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("API returned HTTP {}", resp.status());
    }

    #[derive(serde::Deserialize)]
    struct UserStatsSnapshot {
        access_key: String,
    }

    #[derive(serde::Deserialize)]
    struct ApiResponse {
        ok: bool,
        data: Option<Vec<UserStatsSnapshot>>,
    }

    let body: ApiResponse = resp.json().await?;
    if !body.ok {
        anyhow::bail!("API returned error ok=false");
    }

    let keys: Vec<String> = body.data.unwrap_or_default().into_iter().map(|u| u.access_key).collect();
    let count = keys.len();
    {
        let mut lock = shared_keys.write().unwrap();
        *lock = keys;
    }
    Ok(count)
}

/// Проверяет HMAC-подпись клиента по набору ключей.
/// Возвращает true если хотя бы один ключ подходит.
fn verify_hmac(ts_bytes: &[u8; 8], provided_mac: &[u8], keys: &[String]) -> bool {
    let client_ts = u64::from_be_bytes(*ts_bytes);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Защита от replay: ±60 секунд
    if client_ts > now + 30 || client_ts < now.saturating_sub(60) {
        return false;
    }

    for key in keys {
        if let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(key.as_bytes()) {
            mac.update(ts_bytes);
            if mac.verify_slice(provided_mac).is_ok() {
                return true;
            }
        }
    }
    false
}

// ── UDP Relay ────────────────────────────────────────────────────────────────

async fn run_udp_relay(cfg: RelayConfig, shared_keys: SharedKeys) -> Result<()> {
    // NAT-таблица: client_addr -> (upstream_socket, last_seen)
    let nat_table: Arc<Mutex<HashMap<SocketAddr, (Arc<UdpSocket>, Instant)>>> =
        Arc::new(Mutex::new(HashMap::new()));

    for bind_addr in &cfg.listen_addrs {
        let sock = UdpSocket::bind(bind_addr).await?;
        tracing::info!("Relay UDP listening on {}", bind_addr);
        let sock = Arc::new(sock);
        let upstream_udp = cfg.upstream_udp.clone();
        let keys = shared_keys.clone();
        let nat = nat_table.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let (n, peer) = match sock.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                let packet = Bytes::copy_from_slice(&buf[..n]);

                // Быстрая проверка: первый UDP-пакет от нового клиента содержит Noise handshake.
                // Мы берём из него первые 8 байт как timestamp + 32 байта MAC.
                // Если пакет достаточно длинный, проверяем подпись.
                // Для уже авторизованных клиентов (есть в NAT) — пропускаем проверку.
                {
                    let nat_lock = nat.lock().await;
                    if !nat_lock.contains_key(&peer) {
                        drop(nat_lock);

                        // Пакет должен быть >= 40 байт (8 ts + 32 hmac) для первичной проверки
                        if packet.len() < 40 {
                            tracing::debug!("Relay UDP: dropping short packet from {}", peer);
                            continue;
                        }

                        let ts_bytes: [u8; 8] = packet[0..8].try_into().unwrap();
                        let provided_mac = &packet[8..40];
                        let keys_guard = keys.read().unwrap_or_else(|e| e.into_inner());

                        if !verify_hmac(&ts_bytes, provided_mac, &keys_guard) {
                            tracing::debug!("Relay UDP: unauthorized probe from {}, dropped", peer);
                            continue;
                        }
                        tracing::debug!("Relay UDP: authorized new client {}", peer);
                    }
                }

                // Находим или создаём upstream socket для этого клиента
                let upstream_sock = {
                    let mut nat_lock = nat.lock().await;
                    if let Some(entry) = nat_lock.get_mut(&peer) {
                        entry.1 = Instant::now();
                        entry.0.clone()
                    } else {
                        // Новый upstream socket для этого клиента
                        let usock = match UdpSocket::bind("0.0.0.0:0").await {
                            Ok(s) => Arc::new(s),
                            Err(e) => {
                                tracing::warn!("Relay UDP: failed to bind upstream socket: {}", e);
                                continue;
                            }
                        };
                        if usock.connect(&upstream_udp).await.is_err() {
                            tracing::warn!("Relay UDP: failed to connect to upstream {}", upstream_udp);
                            continue;
                        }

                        nat_lock.insert(peer, (usock.clone(), Instant::now()));

                        // Задача: читаем ответы от upstream и отправляем клиенту
                        let usock_rx = usock.clone();
                        let client_sock = sock.clone();
                        let peer_addr = peer;
                        tokio::spawn(async move {
                            let mut rbuf = vec![0u8; 65535];
                            loop {
                                match usock_rx.recv(&mut rbuf).await {
                                    Ok(n) => {
                                        let _ = client_sock.send_to(&rbuf[..n], peer_addr).await;
                                    }
                                    Err(_) => break,
                                }
                            }
                        });

                        usock
                    }
                };

                // Пересылаем пакет в upstream
                let _ = upstream_sock.send(&packet).await;
            }
        });
    }

    // Периодически чистим устаревшие NAT записи (timeout 120 сек)
    loop {
        tokio::time::sleep(Duration::from_secs(30)).await;
        let mut nat_lock = nat_table.lock().await;
        let now = Instant::now();
        nat_lock.retain(|_, (_, last)| now.duration_since(*last) < Duration::from_secs(120));
    }
}

// ── TCP (UoT) Relay ──────────────────────────────────────────────────────────

async fn run_tcp_relay(cfg: RelayConfig, shared_keys: SharedKeys) -> Result<()> {
    for bind_addr in &cfg.listen_addrs {
        let listener = TcpListener::bind(bind_addr).await?;
        tracing::info!("Relay TCP (UoT) listening on {}", bind_addr);

        let upstream_tcp = cfg.upstream_tcp.clone();
        let keys = shared_keys.clone();

        tokio::spawn(async move {
            loop {
                let (stream, peer_addr) = match listener.accept().await {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!("Relay TCP accept error: {}", e);
                        continue;
                    }
                };

                let upstream = upstream_tcp.clone();
                let keys_clone = keys.clone();

                tokio::spawn(async move {
                    if let Err(e) = handle_tcp_client(stream, peer_addr, upstream, keys_clone).await {
                        tracing::debug!("Relay TCP client {} closed: {}", peer_addr, e);
                    }
                });
            }
        });
    }

    // Держим поток живым
    futures_util::future::pending::<()>().await;
    Ok(())
}

/// Обработка одного TCP (UoT) соединения.
///
/// Алгоритм:
/// 1. Читаем HTTP-заголовки (фейковый WebSocket upgrade).
/// 2. Извлекаем HMAC-подпись из Authorization: Bearer.
/// 3. Проверяем подпись по синхронизированным ключам.
/// 4. Если авторизован — открываем соединение к upstream и пайпим потоки.
async fn handle_tcp_client(
    mut client: TcpStream,
    peer_addr: SocketAddr,
    upstream_addr: String,
    shared_keys: SharedKeys,
) -> Result<()> {
    // Читаем HTTP-заголовки (до \r\n\r\n)
    let mut header_buf = vec![0u8; 4096];
    let mut header_len = 0usize;

    loop {
        let n = client.read(&mut header_buf[header_len..]).await?;
        if n == 0 {
            anyhow::bail!("connection closed before handshake");
        }
        header_len += n;
        if header_buf[..header_len].windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if header_len >= header_buf.len() {
            anyhow::bail!("headers too large");
        }
    }

    let headers_str = String::from_utf8_lossy(&header_buf[..header_len]);

    // Быстрая проверка: должен быть GET /stream
    if !headers_str.starts_with("GET /stream HTTP/1.1\r\n") {
        // Возвращаем 404 как обычный сервер (anti-scan)
        let _ = client.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\nConnection: close\r\n\r\nNot Found").await;
        anyhow::bail!("invalid request from {}", peer_addr);
    }

    // Извлекаем HMAC-подпись
    let mut sig_b64 = None;
    for line in headers_str.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("authorization: bearer ") {
            sig_b64 = Some(line[22..].trim().to_string());
        } else if lower.starts_with("cookie: ostp_token=") {
            sig_b64 = Some(line[19..].trim().to_string());
        }
    }

    let sig_b64 = match sig_b64 {
        Some(s) => s,
        None => {
            let _ = client.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\nConnection: close\r\n\r\nNot Found").await;
            anyhow::bail!("missing authorization from {}", peer_addr);
        }
    };

    let sig_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        &sig_b64,
    )
    .map_err(|_| anyhow::anyhow!("invalid base64 from {}", peer_addr))?;

    if sig_bytes.len() < 40 {
        let _ = client.write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 12\r\nConnection: close\r\n\r\nUnauthorized").await;
        anyhow::bail!("signature too short from {}", peer_addr);
    }

    let ts_bytes: [u8; 8] = sig_bytes[0..8].try_into().unwrap();
    let provided_mac = &sig_bytes[8..];

    // Проверяем по синхронизированным ключам
    let authorized = {
        let keys = shared_keys.read().unwrap_or_else(|e| e.into_inner());
        verify_hmac(&ts_bytes, provided_mac, &keys)
    };

    if !authorized {
        let _ = client.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\nConnection: close\r\n\r\nNot Found").await;
        anyhow::bail!("unauthorized client {}", peer_addr);
    }

    tracing::info!("Relay TCP: authorized client {}, forwarding to {}", peer_addr, upstream_addr);

    // Подключаемся к upstream
    let mut upstream = TcpStream::connect(&upstream_addr).await
        .map_err(|e| anyhow::anyhow!("failed to connect to upstream {}: {}", upstream_addr, e))?;

    // Пересылаем upstream заголовки AS-IS (он сам проверит подпись)
    upstream.write_all(&header_buf[..header_len]).await?;

    // Пайпим оба потока: client <-> upstream
    let (mut cr, mut cw) = client.into_split();
    let (mut ur, mut uw) = upstream.into_split();

    let c2u = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut cr, &mut uw).await;
    });
    let u2c = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut ur, &mut cw).await;
    });

    let _ = tokio::join!(c2u, u2c);
    Ok(())
}
