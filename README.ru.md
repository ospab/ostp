# OSTP — Ospab Stealth Transport Protocol

[English](README.md) · [Contributing](CONTRIBUTING.ru.md)

![GitHub Release](https://img.shields.io/github/v/release/ospab/ostp?style=for-the-badge&color=blue)
![License: BSL 1.1](https://img.shields.io/badge/License-BSL%201.1-orange.svg?style=for-the-badge)
![Platform: Windows | Linux | macOS | Android](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS%20%7C%20Android-green.svg?style=for-the-badge)
![Crypto](https://img.shields.io/badge/Crypto-Noise__NNpsk0-blueviolet?style=for-the-badge)
![Transport](https://img.shields.io/badge/Transport-UDP%20ARQ-informational?style=for-the-badge)

**OSTP** (Ospab Stealth Transport Protocol) — высокопроизводительный транспортный протокол, устойчивый к цензуре. Туннелирует TCP-трафик поверх UDP с полной обфускацией. Устойчив к Deep Packet Inspection (DPI), активному зондированию и статистическому анализу трафика.

---

## Возможности

| Возможность | Описание |
|-------------|----------|
| **Обфускация трафика** | Каждый пакет, включая заголовки, неотличим от случайного шума. Session ID и nonce маскируются HMAC-ключами, уникальными для каждого пакета. |
| **Noise Protocol** | `Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s` — аутентификация через PSK, forward secrecy, без раскрытия идентичности. |
| **Reliable UDP (ARQ)** | Selective ACK/NACK с rate-limited ретрансмиссией, настраиваемым reorder-буфером и exponential backoff. Разработан для 10 Гбит/с. |
| **Мультиплексирование** | Несколько логических TCP-потоков поверх одной зашифрованной UDP-сессии с per-stream flow control. |
| **Бесшовный роуминг** | Клиент может менять сети (WiFi ↔ 4G) без разрыва сессии — сервер отслеживает session-ID, а не IP-адрес. |
| **TUN-режим** | Полносистемный VPN через интеграцию с `tun2socks` на Windows и Linux. |
| **xHTTP Стелс (UoT)** | Туннель UDP-over-TCP, замаскированный под обычный HTTP/1.1 или TLS трафик для обхода белых списков ТСПУ (DPI). |
| **XTLS-Reality** | Собственная реализация протокола Reality (без зависимостей) с использованием ChaCha20Poly1305 и X25519 для идеальной маскировки под TLS 1.3. |
| **TURN Relay** | RFC 5766 TURN для окружений, где прямой UDP заблокирован. |
| **Hot-Reload** | Перезагрузка конфига в рантайме без перезапуска (ключи, исключения, mux, TURN). |
| **Кросс-платформа** | Windows, Linux, macOS, Android. Один бинарник, без зависимостей. |

---

## Архитектура

```mermaid
graph TD
    subgraph Client ["Клиент"]
        A[Браузер / Прил.] -->|SOCKS5 / HTTP| B(Bridge Multiplexer)
        TUN[TUN Интерфейс] -->|IP Пакеты| B
        
        subgraph OSTPCoreClient ["OSTP Core Протокол"]
            B --> C{Protocol Machine}
            C -->|Noise Handshake| D[ChaCha20Poly1305 AEAD]
            D -->|Обфусцированный UDP| E((UDP Сокет))
        end
    end

    E <==>|Зашифрованный UDP Туннель| F

    subgraph Server ["Сервер"]
        F((UDP Сокет)) --> G{Dispatcher}
        
        subgraph OSTPCoreServer ["OSTP Core Backend"]
            G -->|Auth & Decrypt| H[Session & State Guard]
            H -->|TCP Поток| I[Relay Loop]
        end
        
        G -->|Active Probing / Unauth| FB[TCP Fallback Proxy]
        FB -->|Перенаправление| NGINX[nginx / Caddy]
        
        I -->|Outbound| WWW((Интернет))
    end
```

---

## Установка

### Linux
```bash
bash <(curl -Ls https://raw.githubusercontent.com/ospab/ostp/master/scripts/install.sh)
```

### Windows (PowerShell от Администратора)
```powershell
irm https://raw.githubusercontent.com/ospab/ostp/master/scripts/install.ps1 | iex
```

---

## Конфигурация

Создать конфиг по умолчанию:
```bash
./ostp --init server   # VPS
./ostp --init client   # Локальная машина
```

### Сервер (`config.json`)
```jsonc
{
  "mode": "server",
  "listen": "0.0.0.0:50000",
  "access_keys": ["ВАШ_КЛЮЧ"],
  "debug": false,
  // Опционально: проксировать трафик через upstream
  "outbound": {
    "enabled": false,
    "protocol": "socks5",
    "address": "127.0.0.1",
    "port": 9050,
    "default_action": "proxy"
  }
}
```

### Клиент (`config.json`)
```jsonc
{
  "mode": "client",
  "server": "IP_СЕРВЕРА:50000",
  "access_key": "ВАШ_КЛЮЧ",
  "socks5_bind": "127.0.0.1:1088",
  "debug": false,
  // Настройки транспорта (udp или uot)
  "transport": {
    "mode": "udp",
    "stealth_sni": "vk.com",
    "stealth_port": 443
  },
  // TUN-режим (полносистемный VPN)
  "tun": {
    "enable": false,
    "dns": "1.1.1.1"
  },
  // Мультиплексирование: несколько UDP-сессий
  "mux": {
    "enabled": false,
    "sessions": 2
  },
  // TURN-реле для заблокированных сетей
  "turn": {
    "enabled": false,
    "server_addr": "turn.example.com:3478",
    "username": "user",
    "access_key": "pass"
  },
  // Исключения (идут напрямую, минуя туннель)
  "exclude": {
    "domains": ["example.local"],
    "ips": ["192.168.0.0/16"]
  }
}
```

---

## Использование

```bash
# Запуск с конфигом
./ostp --config config.json

# Или просто (ищет config.json рядом с бинарником)
./ostp
```

### TUN-режим (Windows)
Требуется `tun2socks.exe` в той же директории. Автоматически запрашивает права Администратора.

### TUN-режим (Linux)
Требуется root. Нужен бинарник `tun2socks` (рядом или в `$PATH`).

---

## Спецификация протокола

| Уровень | Механизм |
|---------|----------|
| XTLS-Reality | Поддельный TLS 1.3 ClientHello, X25519 обмен ключами, ChaCha20-Poly1305 AEAD |
| Обмен ключами | Noise NNpsk0 (X25519 + ChaChaPoly + BLAKE2s) |
| Шифрование | ChaCha20-Poly1305 AEAD на каждый пакет |
| Обфускация заголовков | HMAC-SHA256 маска session_id + nonce, уникальная для каждого пакета |
| Надёжность | Selective ACK с cumulative + SACK диапазонами |
| Ретрансмиссия | Rate-limited NACK (30мс cooldown) + exponential backoff RTO |
| Flow Control | Окно in-flight (только retransmittable фреймы) |
| Keepalive | Ping/Pong с измерением RTT каждые 5с |
| Таймаут сессии | 60с на клиенте, 300с на сервере |

---

## Сборка из исходников

```bash
# Требования: Rust toolchain (1.75+)
cargo build --release

# Кросс-компиляция для Linux
cross build --release --target x86_64-unknown-linux-gnu
```

---

## Документация

- [Архитектура](docs/ru/architecture.md)
- [Спецификация протокола](docs/ru/specification.md)
- [Дизайн обфускации](docs/ru/obfuscation.md)
- [Администрирование сервера](docs/ru/server.md)
- [Настройка клиента](docs/ru/client.md)
- [Интеграции](docs/ru/integrations.md)

---

## Лицензия

Business Source License 1.1. Бесплатно для личного и некоммерческого использования.
Переходит в MIT License 14 мая 2030 года.
