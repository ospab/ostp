#!/bin/bash
set -e

GITHUB_REPO="ospab/ostp"
INSTALL_DIR="/opt/ostp"

echo "========================================================"
echo " OSTP Installer"
echo "========================================================"

# Verify root
if [ "$EUID" -ne 0 ]; then
  echo "[error] Root privileges required. Run with sudo."
  exit 1
fi

mkdir -p "$INSTALL_DIR"

# Architecture detection
ARCH=$(uname -m)
case "$ARCH" in
    x86_64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    i386|i686) ARCH="386" ;;
    armv7l) ARCH="armv7" ;;
    *)
        echo "[warn] Unknown architecture $ARCH, defaulting to amd64."
        ARCH="amd64"
        ;;
esac

# Fetch latest release
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
      tar -xzf "$TEMP_TAR" -C "$INSTALL_DIR" ostp
      rm -f "$TEMP_TAR"
   fi
else
   ARCHIVE_NAME="ostp-linux-${ARCH}.tar.gz"
   DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/${LATEST_RELEASE}/${ARCHIVE_NAME}"
   echo "Downloading: $ARCHIVE_NAME ($LATEST_RELEASE)"

   TEMP_TAR="/tmp/ostp_temp.tar.gz"
   HTTP_CODE=$(curl -sL -w "%{http_code}" "$DOWNLOAD_URL" -o "$TEMP_TAR")

   if [ "$HTTP_CODE" -eq 200 ]; then
      tar -xzf "$TEMP_TAR" -C "$INSTALL_DIR" ostp
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

# Update detection
if [ -f "$INSTALL_DIR/config.json" ]; then
   echo "--------------------------------------------------------"
   echo "Existing configuration found. Binary updated to ${LATEST_RELEASE:-latest}."

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

# Interactive setup
echo "--------------------------------------------------------"
echo "Select mode:"
echo "  1) Server"
echo "  2) Client"
echo "--------------------------------------------------------"
read -p "Choice [1-2]: " NODE_MODE

cd "$INSTALL_DIR"

if [ "$NODE_MODE" == "1" ]; then
  echo "Initializing server configuration..."
  ./ostp --init server --config config.json

  read -p "Listen address [default: 0.0.0.0:50000]: " LISTEN_ADDR
  if [ -n "$LISTEN_ADDR" ]; then
     sed -i "s/\"listen\": \".*\"/\"listen\": \"$LISTEN_ADDR\"/g" config.json
  fi

  read -p "Number of access keys [default: 1]: " KEYS_COUNT
  KEYS_COUNT=${KEYS_COUNT:-1}

  if [ "$KEYS_COUNT" -gt 1 ]; then
     echo "Generating $KEYS_COUNT access keys..."
     NEW_KEYS=$(./ostp -g -c "$KEYS_COUNT" | sed 's/^/      "/;s/$/",/' | sed '$ s/,$//')
     sed -i '/\"access_keys\": \[/,/\]/c\  "access_keys": [\n'"$NEW_KEYS"'\n  ],' config.json
  fi
  echo "Server configuration saved: $INSTALL_DIR/config.json"

elif [ "$NODE_MODE" == "2" ]; then
  echo "Initializing client configuration..."
  ./ostp --init client --config config.json

  read -p "Server address (host:port): " REMOTE_SERVER
  if [ -n "$REMOTE_SERVER" ]; then
     sed -i "s/\"server\": \"127.0.0.1:50000\"/\"server\": \"$REMOTE_SERVER\"/g" config.json
  else
     echo "[warn] No server address provided. Using default (127.0.0.1:50000)."
  fi

  read -p "Access key (blank to generate): " ACCESS_KEY
  if [ -z "$ACCESS_KEY" ]; then
     ACCESS_KEY=$(./ostp -g)
     echo "Generated key: $ACCESS_KEY"
  fi
  sed -i "s/\"access_key\": \"[^\"]*\"/\"access_key\": \"$ACCESS_KEY\"/g" config.json

  read -p "Local proxy address [default: 127.0.0.1:1088]: " SOCKS_BIND
  if [ -n "$SOCKS_BIND" ]; then
     sed -i "s/\"socks5_bind\": \"127.0.0.1:1088\"/\"socks5_bind\": \"$SOCKS_BIND\"/g" config.json
  fi
  echo "Client configuration saved: $INSTALL_DIR/config.json"

else
  echo "[error] Invalid selection."
  exit 1
fi

# Register systemd service
echo "Registering systemd service..."
cat <<EOF > /etc/systemd/system/ostp.service
[Unit]
Description=OSTP Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/ostp --config $INSTALL_DIR/config.json
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable ostp.service >/dev/null 2>&1

echo "--------------------------------------------------------"
echo "Installation complete."
echo "  Config: $INSTALL_DIR/config.json"
echo "  Start:  systemctl start ostp"
echo "--------------------------------------------------------"
