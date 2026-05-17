#!/bin/bash
set -e

GITHUB_REPO="ospab/ostp"
INSTALL_DIR="/opt/ostp"
BIN_LINK="/usr/local/bin/ostp"
CONFIG_DIR="/etc/ostp"
CONFIG_FILE="$CONFIG_DIR/config.json"

# Legacy paths to check for migration
LEGACY_PATHS=(
    "$HOME/ostp"
    "/root/ostp"
    "/usr/local/ostp"
    "/usr/share/ostp"
)

echo "========================================================"
echo " OSTP Installer v2"
echo "========================================================"

# Verify root
if [ "$EUID" -ne 0 ]; then
    echo "[error] Root privileges required. Run with sudo."
    exit 1
fi

mkdir -p "$INSTALL_DIR"
mkdir -p "$CONFIG_DIR"

# ── Migration from legacy installations ──────────────────────────────

migrate_legacy() {
    local old_dir="$1"
    echo "[migrate] Found legacy installation at $old_dir"

    # Migrate config if exists and new one doesn't
    if [ -f "$old_dir/config.json" ] && [ ! -f "$CONFIG_FILE" ]; then
        echo "[migrate] Moving config: $old_dir/config.json -> $CONFIG_FILE"
        cp "$old_dir/config.json" "$CONFIG_FILE"
    fi

    # Migrate binary if no new binary yet
    if [ -f "$old_dir/ostp" ] && [ ! -f "$INSTALL_DIR/ostp" ]; then
        echo "[migrate] Moving binary: $old_dir/ostp -> $INSTALL_DIR/ostp"
        cp "$old_dir/ostp" "$INSTALL_DIR/ostp"
    fi

    # Migrate tun2socks if present
    if [ -f "$old_dir/tun2socks" ] && [ ! -f "$INSTALL_DIR/tun2socks" ]; then
        cp "$old_dir/tun2socks" "$INSTALL_DIR/tun2socks"
    fi

    echo "[migrate] Legacy files preserved at $old_dir (remove manually if no longer needed)"
}

# Check for legacy /opt/ostp/config.json (old layout: config in install dir)
if [ -f "$INSTALL_DIR/config.json" ] && [ ! -f "$CONFIG_FILE" ]; then
    echo "[migrate] Moving config from $INSTALL_DIR/config.json -> $CONFIG_FILE"
    cp "$INSTALL_DIR/config.json" "$CONFIG_FILE"
    # Keep old file as backup
    mv "$INSTALL_DIR/config.json" "$INSTALL_DIR/config.json.bak"
fi

# Check legacy paths
for lpath in "${LEGACY_PATHS[@]}"; do
    if [ -d "$lpath" ] && [ -f "$lpath/ostp" ]; then
        migrate_legacy "$lpath"
    fi
done

# Remove stale symlinks
if [ -L "$BIN_LINK" ] && [ ! -e "$BIN_LINK" ]; then
    rm -f "$BIN_LINK"
fi

# ── Architecture detection ───────────────────────────────────────────

ARCH=$(uname -m)
case "$ARCH" in
    x86_64)       ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    i386|i686)    ARCH="386" ;;
    armv7l)       ARCH="armv7" ;;
    mips|mipsel)  ARCH="$ARCH" ;;
    *)
        echo "[warn] Unknown architecture $ARCH, defaulting to amd64."
        ARCH="amd64"
        ;;
esac

echo "Platform: linux/$ARCH"

# ── Download binary ──────────────────────────────────────────────────

echo "Fetching latest release..."
LATEST_RELEASE=$(curl -s "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "$LATEST_RELEASE" ] || [[ "$LATEST_RELEASE" == *"null"* ]]; then
    echo "[notice] Could not determine latest release automatically."
    echo "Enter a direct URL to the .tar.gz archive,"
    echo "or press Enter if the binary is already in $INSTALL_DIR/ostp."
    read -p "URL: " DIRECT_URL
    if [ -n "$DIRECT_URL" ]; then
        TEMP_TAR="/tmp/ostp_temp.tar.gz"
        curl -L "$DIRECT_URL" -o "$TEMP_TAR"
        tar -xzf "$TEMP_TAR" -C "$INSTALL_DIR" ostp 2>/dev/null || tar -xzf "$TEMP_TAR" -C "$INSTALL_DIR"
        rm -f "$TEMP_TAR"
    fi
else
    ARCHIVE_NAME="ostp-linux-${ARCH}.tar.gz"
    DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/${LATEST_RELEASE}/${ARCHIVE_NAME}"
    echo "Downloading: $ARCHIVE_NAME ($LATEST_RELEASE)"

    TEMP_TAR="/tmp/ostp_temp.tar.gz"
    HTTP_CODE=$(curl -sL -w "%{http_code}" "$DOWNLOAD_URL" -o "$TEMP_TAR")

    if [ "$HTTP_CODE" -eq 200 ]; then
        tar -xzf "$TEMP_TAR" -C "$INSTALL_DIR" ostp 2>/dev/null || tar -xzf "$TEMP_TAR" -C "$INSTALL_DIR"
        rm -f "$TEMP_TAR"
    else
        echo "[error] Download failed (HTTP $HTTP_CODE)."
        echo "Verify that $LATEST_RELEASE is published at:"
        echo "  https://github.com/$GITHUB_REPO/releases"
        rm -f "$TEMP_TAR"
        exit 1
    fi
fi

if [ -f "$INSTALL_DIR/ostp" ]; then
    chmod +x "$INSTALL_DIR/ostp"
    echo "Binary installed: $INSTALL_DIR/ostp"
else
    echo "[error] Binary not found at $INSTALL_DIR/ostp."
    exit 1
fi

# ── Create global symlink ────────────────────────────────────────────

ln -sf "$INSTALL_DIR/ostp" "$BIN_LINK"
echo "Symlink created: $BIN_LINK -> $INSTALL_DIR/ostp"
echo "You can now run 'ostp' from anywhere."

# ── Update detection ─────────────────────────────────────────────────

if [ -f "$CONFIG_FILE" ]; then
    echo "--------------------------------------------------------"
    echo "Existing configuration found at $CONFIG_FILE."
    echo "Binary updated to ${LATEST_RELEASE:-latest}."

    # Update systemd service to use new paths
    if [ -f "/etc/systemd/system/ostp.service" ]; then
        # Check if service points to old path
        if grep -q "WorkingDirectory=$INSTALL_DIR" /etc/systemd/system/ostp.service && \
           grep -q "$CONFIG_FILE" /etc/systemd/system/ostp.service; then
            : # Service already uses correct paths
        else
            echo "Updating systemd service to use new paths..."
            cat <<EOF > /etc/systemd/system/ostp.service
[Unit]
Description=OSTP Stealth Transport Protocol
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/ostp --config $CONFIG_FILE
Restart=always
RestartSec=5
LimitNOFILE=65535
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
EOF
            systemctl daemon-reload
        fi
    fi

    if systemctl is-active --quiet ostp.service 2>/dev/null; then
        echo "Restarting ostp service..."
        systemctl restart ostp.service
        echo "Service restarted."
    elif systemctl is-enabled --quiet ostp.service 2>/dev/null; then
        echo "Service registered but not running."
        echo "Start manually: systemctl start ostp"
    fi
    echo "--------------------------------------------------------"
    echo "Update complete."
    exit 0
fi

# ── Interactive setup (first install) ────────────────────────────────

echo "--------------------------------------------------------"
echo "Select mode:"
echo "  1) Server"
echo "  2) Client"
echo "--------------------------------------------------------"
read -p "Choice [1-2]: " NODE_MODE

cd "$INSTALL_DIR"

if [ "$NODE_MODE" == "1" ]; then
    echo "Initializing server configuration..."
    ./ostp --init server --config "$CONFIG_FILE"

    read -p "Listen address [default: 0.0.0.0:50000]: " LISTEN_ADDR
    if [ -n "$LISTEN_ADDR" ]; then
        sed -i "s/\"listen\": \".*\"/\"listen\": \"$LISTEN_ADDR\"/g" "$CONFIG_FILE"
    fi

    read -p "Number of access keys [default: 1]: " KEYS_COUNT
    KEYS_COUNT=${KEYS_COUNT:-1}

    if [ "$KEYS_COUNT" -gt 1 ]; then
        echo "Generating $KEYS_COUNT access keys..."
        NEW_KEYS=$(./ostp -g -c "$KEYS_COUNT" | sed 's/^/      "/;s/$/"/' | paste -sd ',' | sed 's/,/,\n/g')
        # Replace the access_keys array
        python3 -c "
import json, subprocess, sys
with open('$CONFIG_FILE') as f:
    content = f.read()
    # Strip comments for parsing
    lines = [l for l in content.split('\n') if not l.strip().startswith('//')]
    cfg = json.loads('\n'.join(lines))
keys = subprocess.check_output(['$INSTALL_DIR/ostp', '-g', '-c', '$KEYS_COUNT']).decode().strip().split('\n')
cfg['access_keys'] = keys
with open('$CONFIG_FILE', 'w') as f:
    json.dump(cfg, f, indent=2)
" 2>/dev/null || echo "[warn] Key injection via python3 failed. Edit config manually."
    fi

    echo ""
    echo "Server access key(s):"
    grep -oP '"[0-9a-f]{32}"' "$CONFIG_FILE" | tr -d '"' | while read key; do
        echo "  $key"
    done
    echo ""
    echo "Server configuration saved: $CONFIG_FILE"

elif [ "$NODE_MODE" == "2" ]; then
    echo "Initializing client configuration..."
    ./ostp --init client --config "$CONFIG_FILE"

    read -p "Server address (host:port): " REMOTE_SERVER
    if [ -n "$REMOTE_SERVER" ]; then
        sed -i "s/\"server\": \"127.0.0.1:50000\"/\"server\": \"$REMOTE_SERVER\"/g" "$CONFIG_FILE"
    else
        echo "[warn] No server address provided. Using default (127.0.0.1:50000)."
    fi

    read -p "Access key: " ACCESS_KEY
    if [ -z "$ACCESS_KEY" ]; then
        ACCESS_KEY=$(./ostp -g)
        echo "Generated key: $ACCESS_KEY"
    fi
    sed -i "s/\"access_key\": \"[^\"]*\"/\"access_key\": \"$ACCESS_KEY\"/g" "$CONFIG_FILE"

    read -p "Local proxy address [default: 127.0.0.1:1088]: " SOCKS_BIND
    if [ -n "$SOCKS_BIND" ]; then
        sed -i "s/\"socks5_bind\": \"127.0.0.1:1088\"/\"socks5_bind\": \"$SOCKS_BIND\"/g" "$CONFIG_FILE"
    fi
    echo "Client configuration saved: $CONFIG_FILE"

else
    echo "[error] Invalid selection."
    exit 1
fi

# ── Register systemd service ─────────────────────────────────────────

echo "Registering systemd service..."
cat <<EOF > /etc/systemd/system/ostp.service
[Unit]
Description=OSTP Stealth Transport Protocol
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/ostp --config $CONFIG_FILE
Restart=always
RestartSec=5
LimitNOFILE=65535
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable ostp.service >/dev/null 2>&1

echo ""
echo "========================================================"
echo " Installation complete"
echo "========================================================"
echo ""
echo "  Binary:  $INSTALL_DIR/ostp"
echo "  Command: ostp (available globally)"
echo "  Config:  $CONFIG_FILE"
echo "  Service: systemctl start ostp"
echo "  Logs:    journalctl -u ostp -f"
echo ""
echo "  Quick commands:"
echo "    ostp --check              Validate configuration"
echo "    ostp --generate-key       Generate access key"
echo "    ostp --links              Print client share links"
echo "    systemctl status ostp     Service status"
echo ""
