# OSTP (Ospab Stealth Transport Protocol)

OSTP is a simple and fast tunnel protocol designed to bypass network restrictions. It hides your traffic and makes it look like random noise, making it hard to block.

---

## Main Features

- **Traffic Masking**: Hides your data so it doesn't look like a VPN or proxy.
- **Fast & Reliable**: Works well on unstable networks (like mobile data).
- **Easy Setup**: Simple config files and one-click installers.
- **Universal**: Works on Windows, Linux, and Android.
- **SOCKS5/HTTP**: Supports standard proxy modes.
- **TUN Mode**: Can act as a full VPN for your entire system.

---

## Quick Install

### Linux (Server or Client)
Run this command to install OSTP and set it up as a service:
```bash
bash <(curl -Ls https://raw.githubusercontent.com/ospab/ostp/master/scripts/install.sh)
```

### Windows (Client)
Run this in **PowerShell as Administrator**:
```powershell
irm https://raw.githubusercontent.com/ospab/ostp/master/scripts/install.ps1 | iex
```

---

## How to Use

The `ostp` program can work in two modes: **Server** (on your VPS) and **Client** (on your local computer).

### 1. Create a Config File
Run the program with the `--init` flag to generate a template:

**On Server:**
```bash
./ostp --init server
```

**On Client:**
```bash
./ostp --init client
```

### 2. Configure

#### Server (`config.json`)
```json
{
  "mode": "server",
  "listen": "0.0.0.0:50000",
  "access_keys": [
    "your-secret-key-here"
  ]
}
```

#### Client (`config.json`)
```json
{
  "mode": "client",
  "server": "YOUR_SERVER_IP:50000",
  "access_key": "your-secret-key-here",
  "socks5_bind": "127.0.0.1:1088",
  "tun": {
    "enable": false
  }
}
```

### 3. Start
Run the program using your config:
```bash
./ostp --config config.json
```

---

## TUN Mode (VPN for whole system)
To route all your traffic through OSTP, set `"enable": true` in the `tun` section of your client config.
- **Windows**: Requires Administrator rights.
- **Linux**: Requires Root rights.

---

## License
OSTP is licensed under the Business Source License 1.1. It is free for personal and non-commercial use. It becomes MIT License on May 14, 2030.
