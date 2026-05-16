# OSTP (Ospab Stealth Transport Protocol)

[🇷🇺 Русский язык](README.ru.md)

![GitHub Release](https://img.shields.io/github/v/release/ospab/ostp?style=flat-square&color=blue)
![License: BSL 1.1](https://img.shields.io/badge/License-BSL%201.1-orange.svg?style=flat-square)
![Platform: Windows | Linux | macOS | Android](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS%20%7C%20Android-green.svg?style=flat-square)

OSTP is a fast and secure transport protocol designed to bypass DPI and network restrictions. It masks traffic as high-entropy data, making it difficult to detect or block.

---

## Features

- **Traffic Obfuscation**: Hides VPN/proxy signatures from network analysis.
- **High Performance**: Written in Rust using the gVisor network stack for low latency.
- **Reliable Connectivity**: Built-in keep-alive mechanism for stable operation on mobile networks.
- **Flexible Modes**: Supports SOCKS5/HTTP proxying and full-system TUN (VPN) mode.
- **Multi-platform**: Compatible with Windows, Linux, macOS, and Android.

---

## Installation

### Linux
Run the installer script to set up OSTP as a system service:
```bash
bash <(curl -Ls https://raw.githubusercontent.com/ospab/ostp/master/scripts/install.sh)
```

### Windows
Run the following in PowerShell as Administrator:
```powershell
irm https://raw.githubusercontent.com/ospab/ostp/master/scripts/install.ps1 | iex
```

---

## Configuration

Initialize a default config file:
```bash
./ostp --init server # For VPS
./ostp --init client # For local machine
```

### Server (config.json)
```json
{
  "_comment": "OSTP Server Configuration",
  "mode": "server",
  "listen": "0.0.0.0:50000",
  "access_keys": ["YOUR_KEY"],
  "outbound": {
    "enabled": false,
    "protocol": "socks5",
    "address": "127.0.0.1",
    "port": 9050,
    "default_action": "proxy"
  }
}
```

### Client (config.json)
```json
{
  "_comment": "OSTP Client Configuration",
  "mode": "client",
  "server": "SERVER_IP:50000",
  "access_key": "YOUR_KEY",
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

## Usage

Start the node with your configuration:
```bash
./ostp --config config.json
```

For TUN mode on Windows, ensure `tun2socks.exe` and `wintun.dll` are in the same directory.

---

## License

Business Source License 1.1. Free for personal and non-commercial use. Converts to MIT License on May 14, 2030.
