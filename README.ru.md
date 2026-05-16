# OSTP (Ospab Stealth Transport Protocol)

[🇺🇸 English](README.md)

![GitHub Release](https://img.shields.io/github/v/release/ospab/ostp?style=flat-square&color=blue)
![License: BSL 1.1](https://img.shields.io/badge/License-BSL%201.1-orange.svg?style=flat-square)
![Platform: Windows | Linux | macOS | Android](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS%20%7C%20Android-green.svg?style=flat-square)

OSTP — это быстрый и безопасный транспортный протокол для обхода DPI и сетевых ограничений. Он маскирует трафик под высокоэнтропийные данные, что делает его труднообнаружимым для систем блокировки.

---

## Возможности

- **Обфускация трафика**: Скрывает сигнатуры VPN и прокси от сетевого анализа.
- **Высокая производительность**: Написан на Rust с использованием сетевого стека gVisor.
- **Стабильность**: Встроенный механизм keep-alive для надежной работы в мобильных сетях.
- **Гибкость**: Поддержка проксирования SOCKS5/HTTP и полнофункционального TUN (VPN) режима.
- **Кроссплатформенность**: Работает на Windows, Linux, macOS и Android.

---

## Установка

### Linux
Используйте скрипт для автоматической установки и настройки сервиса:
```bash
bash <(curl -Ls https://raw.githubusercontent.com/ospab/ostp/master/scripts/install.sh)
```

### Windows
Запустите в PowerShell от имени администратора:
```powershell
irm https://raw.githubusercontent.com/ospab/ostp/master/scripts/install.ps1 | iex
```

---

## Настройка

Создайте файл конфигурации по умолчанию:
```bash
./ostp --init server # Для сервера (VPS)
./ostp --init client # Для клиента (ПК)
```

### Сервер (config.json)
```json
{
  "_comment": "OSTP Server Configuration",
  "mode": "server",
  "listen": "0.0.0.0:50000",
  "access_keys": ["ВАШ_КЛЮЧ"],
  "outbound": {
    "enabled": false,
    "protocol": "socks5",
    "address": "127.0.0.1",
    "port": 9050,
    "default_action": "proxy"
  }
}
```

### Клиент (config.json)
```json
{
  "_comment": "OSTP Client Configuration",
  "mode": "client",
  "server": "IP_СЕРВЕРА:50000",
  "access_key": "ВАШ_КЛЮЧ",
  "socks5_bind": "127.0.0.1:1088",
  "tun": {
    "enable": false,
    "wintun_path": "./wintun.dll",
    "ipv4_address": "10.1.0.2/24",
    "dns": "1.1.1.1"
  }
}
```

---

## Использование

Запустите программу с вашим конфигом:
```bash
./ostp --config config.json
```

Для работы TUN режима в Windows файлы `tun2socks.exe` и `wintun.dll` должны находиться в одной папке с бинарным файлом.

---

## Лицензия

Business Source License 1.1. Бесплатно для личного и некоммерческого использования. Переходит в MIT License 14 мая 2030 года.
