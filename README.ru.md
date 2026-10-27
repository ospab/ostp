# OSTP - Ospab Stealth Transport Protocol

[English](README.md) · [Документация](docs/README.md) · [Журнал изменений](CHANGELOG.ru.md) · [Releases](https://github.com/ospab/ostp/releases) · [Wiki](https://github.com/ospab/ostp/wiki) · [Участие в разработке](CONTRIBUTING.ru.md)

![GitHub Release](https://img.shields.io/github/v/release/ospab/ostp?style=for-the-badge&color=blue)
![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg?style=for-the-badge)

OSTP — зашифрованный туннель на Rust для сетей, где трафик фильтруют (DPI). Клиент на компьютере или телефоне отправляет весь трафик,
или только выбранные приложения и сайты, через ваш собственный сервер. Протокол, сервер, утилита командной строки, десктопное и
Android-приложения лежат в этом репозитории.

Как это выглядит на проводе, зависит от выбранного транспорта:

- **UDP**: каждый байт, включая заголовки, неотличим от случайных данных; надёжность своя (выборочные ACK/NACK, контроль перегрузки).
- **UoT** (UDP поверх TCP): те же пакеты внутри обычного TCP-соединения — для сетей, где незнакомый UDP блокируют или режут.
- **TLS**: UoT внутри настоящего TLS с настоящим сертификатом на вашем домене, на порту 443, напрямую или за nginx, Apache или Caddy по
  секретному пути. Для всех остальных сервер выглядит обычным сайтом.

---

## Установка

**Сервер или клиент командной строки, Linux:**
```bash
bash <(curl -Ls https://raw.githubusercontent.com/ospab/ostp/master/scripts/install.sh)
```

**Windows (PowerShell от имени администратора):**
```powershell
irm https://raw.githubusercontent.com/ospab/ostp/master/scripts/install.ps1 | iex
```

**Приложения:** десктопный клиент (Windows, Linux, macOS) и Android-приложение (arm64, armv7) — на странице [Releases](https://github.com/ospab/ostp/releases),
там же готовые бинарники `ostp` для Windows, Linux (x86, x64, ARM, MIPS, RISC-V), macOS и FreeBSD.

---

## Быстрый старт

**Не знакомы с Linux?** Установите десктопное приложение и на первом экране выберите «I have a server» (или позже: *Settings → Server management*).
Введите адрес VPS, логин SSH и пароль или приватный ключ: приложение само поставит OSTP по SSH, добавит себе подключение,
а дальше управляет сервером: пользователи, трафик, TLS-сертификат, подписки, обновления, логи и веб-панель через то же SSH-соединение.
Пароль или ключ SSH сохраняется, только если вы попросите, и зашифрован ключом из системного хранилища; ключ хоста сервера запоминается при первом подключении.

**Вручную. 1. На сервере** запустите мастер настройки и выведите ссылки для подключения:

```bash
ostp setup           # режим сервера, порт, ключи доступа
ostp links           # ссылки ostp://... для каждого пользователя
ostp links qr        # то же QR-кодами, по одному пользователю
```

**2. На клиенте** вставьте ссылку в десктопное или Android-приложение либо используйте командную строку:

```bash
ostp connect "ostp://ACCESS_KEY@server.example.com:50000?..."   # подключиться один раз
ostp import  "ostp://..."                                      # сохранить в конфиг
```

Ссылку берите в кавычки, иначе оболочка обрежет её на `&` или `?`.

**3. По желанию, на сервере с доменом:**

```bash
ostp cert issue --domain vpn.example.com   # HTTPS и сертификат Let's Encrypt, транспорт TLS на 443
ostp sub enable                            # персональные ссылки подписки, приложения обновляют их сами
ostp panel enable                          # веб-панель и API управления
ostp dns enable                            # фильтрующий DNS для подключённых клиентов
```

Подробнее: [Домены и TLS](docs/ru/tls.md), [Сервер](docs/ru/server.md), [Клиент](docs/ru/client.md).

---

## Что внутри

- Три транспорта: UDP, UoT (UDP поверх TCP) и TLS на 443 с настоящим сертификатом, напрямую или за веб-сервером.
- Всё, что не является настоящим клиентом, получает запасной сайт или ответ-приманку.
- Локальный SOCKS5/HTTP-прокси (и системный прокси Windows) или TUN-адаптер с kill switch.
- Домены, диапазоны IP и, на Windows и Linux, процессы можно исключить из туннеля.
- При смене сети или зависшем пути сессия переходит на новый сокет без нового рукопожатия.
- Персональные ссылки подписки, веб-панель с REST API и фильтрующий DNS для подключённых клиентов.
- Пробер сети: пробует все транспорты до вашего сервера и находит оборудование фильтрации по TTL.
- Исходящий трафик сервера можно пустить через SOCKS5-прокси по правилам или с выбранного адреса.
- По желанию сайты `.ov` через [overnet](https://github.com/ospab/overnet); по умолчанию выключено.

Набор шифров — `Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s`, ChaCha20-Poly1305 на каждый пакет; см. [спецификацию](docs/ru/specification.md).

---

## Как это устроено

```mermaid
flowchart LR
    subgraph Client["Устройство клиента"]
        Apps["Приложения и браузер"] --> In["SOCKS5 / HTTP-прокси<br/>или TUN"]
        In --> CEngine["Клиент OSTP<br/>Noise, ChaCha20, ARQ"]
    end

    subgraph Net["Сеть с фильтрацией"]
        Wire{{"UDP, UoT или TLS 443"}}
    end

    subgraph Server["Ваш сервер"]
        Front["Порт 443 или порт OSTP<br/>(при желании nginx / Apache / Caddy)"]
        SEngine["Сервер OSTP<br/>сессии, выход в интернет"]
        Site["Запасной сайт"]
        Out["Интернет"]
        Front -->|настоящий клиент| SEngine
        Front -->|всё остальное| Site
        SEngine --> Out
    end

    CEngine <--> Wire <--> Front
```

---

## Команды

```
ostp [--config ПУТЬ] [КОМАНДА]
```

| Команда | Что делает |
|---|---|
| *(без команды)* | Запуск клиентом или сервером, как указано в конфиге |
| `setup` | Мастер настройки |
| `init server\|client\|relay` | Записать шаблон конфига |
| `check` | Проверить конфиг и вывести сводку |
| `connect <URL>` | Подключиться один раз по ссылке `ostp://` |
| `import <URL>` | Сохранить в конфиг ссылку `ostp://` или ссылку подписки |
| `links [qr]` | Вывести ссылки `ostp://` пользователей или показать их QR-кодами |
| `gk` | Создать ключ доступа (`--format hex\|base64`, `-n` количество) |
| `cert issue\|status\|renew` | Домен, HTTPS и сертификат Let's Encrypt (сервер) |
| `sub status\|enable\|disable\|set\|urls` | Ссылки подписки (сервер) |
| `panel status\|enable\|disable\|set\|passwd\|token` | Веб-панель и API управления (сервер) |
| `dns status\|enable\|disable\|...` | Фильтрующий DNS для клиентов (сервер) |
| `overnet status\|install\|enable\|disable\|exit` | Сайты `.ov` для клиентов через overnet (сервер) |
| `hash-password` | Хэш пароля для конфига панели |
| `migrate [--dry-run]` | Обновить конфиг до текущего формата; сама программа этого никогда не делает |
| `update [-b stable\|beta\|alpha] [-v ВЕРСИЯ]` | Установить другой выпуск |
| `changelog`, `cl` | Что изменилось в этой версии (`--all`, `--last N`, `--version X`, `--lang en\|ru`) |
| `proxy-env`, `proxy-env-clear` | Команды export для локального прокси |
| `uninstall` | Остановить службу, удалить бинарник и конфиг |

Конфиг — `/etc/ostp/config.json` на Linux и `config.json` в текущей папке на Windows; другой файл задаётся через `--config`. У каждой
команды есть `--help`.

---

## Документация

Оглавление: [docs/README.md](docs/README.md). Чаще всего нужны:

- [Клиент](docs/ru/client.md) и [Сервер](docs/ru/server.md)
- [Домены и TLS](docs/ru/tls.md)
- [Спецификация протокола](docs/ru/specification.md), [Обфускация](docs/ru/obfuscation.md), [Архитектура](docs/ru/architecture.md)
- [Интеграции и API управления](docs/ru/integrations.md)
- [Протокол тестирования](docs/ru/testing.md) перед каждым выпуском
- [Журнал изменений](CHANGELOG.ru.md)

---

## Сборка из исходников

```bash
cargo build --release     # бинарник ostp: target/release/ostp
cargo test --workspace
```

Нужна актуальная стабильная версия Rust. У десктопного и Android-приложений свои шаги: [ostp-gui](ostp-gui/README.md), [ostp-flutter](ostp-flutter/README.md).
Как устроен репозиторий и как присылать изменения: [CONTRIBUTING.ru.md](CONTRIBUTING.ru.md).

---

## Безопасность

О уязвимостях сообщайте закрыто, не в публичном issue: см. [SECURITY.ru.md](SECURITY.ru.md).

## Лицензия

GNU Affero General Public License v3.0 (AGPL-3.0), см. [LICENSE](LICENSE).

## Контакты

- Telegram: [@ospab0](https://t.me/ospab0)
- Email: gvoprgrg@gmail.com
