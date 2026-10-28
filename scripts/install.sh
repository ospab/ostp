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
echo " OSTP Installer v3"
echo "========================================================"

# Verify root
if [ "$EUID" -ne 0 ]; then
    echo "[error] Root privileges required. Run with sudo."
    exit 1
fi

mkdir -p "$INSTALL_DIR"
mkdir -p "$CONFIG_DIR"
# The config holds every access key and the panel credentials: root only, or any
# local user could read the keys and use the VPN as its owner.
chmod 700 "$CONFIG_DIR"

# Private download directory: a fixed name in /tmp lets a local user pre-create
# it as a symlink and make this root script overwrite any file, or swap the
# archive between download and extraction.
WORK_DIR=$(mktemp -d) || { echo "[error] Cannot create a temporary directory."; exit 1; }
trap 'rm -rf "$WORK_DIR"' EXIT

# -- Migration from legacy installations ------------------------------

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

    echo "[migrate] Legacy files preserved at $old_dir (remove manually if no longer needed)"
}

# Check for legacy /opt/ostp/config.json (old layout: config in install dir)
if [ -f "$INSTALL_DIR/config.json" ] && [ ! -f "$CONFIG_FILE" ]; then
    echo "[migrate] Moving config from $INSTALL_DIR/config.json -> $CONFIG_FILE"
    cp "$INSTALL_DIR/config.json" "$CONFIG_FILE"
    mv "$INSTALL_DIR/config.json" "$INSTALL_DIR/config.json.bak"
fi

# Check legacy paths
for lpath in "${LEGACY_PATHS[@]}"; do
    if [ -d "$lpath" ] && [ -f "$lpath/ostp" ]; then
        migrate_legacy "$lpath"
    fi
done

if [ -f "$CONFIG_FILE" ]; then
    chmod 600 "$CONFIG_FILE"
fi

# Remove stale symlinks
if [ -L "$BIN_LINK" ] && [ ! -e "$BIN_LINK" ]; then
    rm -f "$BIN_LINK"
fi

# -- Architecture detection -------------------------------------------

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

# -- Parse arguments ----------------------------------------------------
TARGET_VERSION=""
TARGET_BRANCH="stable"
# -y: no questions at all, for the desktop app installing over SSH. A first
# install then runs `ostp manage install`, which prints one JSON line.
ASSUME_YES=0
MANAGE_ARGS=()
while [[ $# -gt 0 ]]; do
  case $1 in
    -y|--yes)
      ASSUME_YES=1
      shift
      ;;
    --port|--host|--user)
      MANAGE_ARGS+=("$1" "$2")
      shift 2
      ;;
    -v|--version)
      TARGET_VERSION="$2"
      shift 2
      ;;
    -b|--branch)
      TARGET_BRANCH="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

# -- Release integrity ------------------------------------------------

# SHA-256 of a file, whichever tool the system has.
sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | cut -d' ' -f1
    elif command -v sha256 >/dev/null 2>&1; then
        sha256 -q "$1"
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 "$1" | sed 's/.*= *//'
    else
        return 1
    fi
}

# The digest GitHub computed for one asset of one release, taken from the API
# response for exactly that tag ("digest": "sha256:<hex>" next to the asset name).
release_digest() {
    curl -s --proto '=https' "https://api.github.com/repos/${GITHUB_REPO}/releases/tags/$1" \
        | tr ',' '\n' \
        | awk -v n="\"$2\"" '
            /"name": *"/ { in_asset = (index($0, n) > 0) }
            in_asset && /"digest": *"sha256:[0-9a-fA-F]+"/ {
                s = $0; sub(/.*sha256:/, "", s); sub(/".*/, "", s); print s; exit
            }'
}

# verify_sha256 FILE EXPECTED: fails (and says why) unless the file matches.
verify_sha256() {
    local actual
    if ! actual=$(sha256_of "$1") || [ -z "$actual" ]; then
        echo "[error] No SHA-256 tool (sha256sum, shasum, sha256 or openssl) to verify the download. Nothing was installed."
        return 1
    fi
    actual=$(printf '%s' "$actual" | tr 'A-F' 'a-f')
    if [ "$actual" != "$(printf '%s' "$2" | tr 'A-F' 'a-f')" ]; then
        echo "[error] SHA-256 mismatch: expected $2, got $actual. The file was not installed."
        return 1
    fi
    echo "SHA-256 verified: $actual"
}

# fetch_verified TAG ASSET OUT: downloads the release asset and checks it against
# the digest GitHub publishes for it; on any failure OUT is removed and nothing
# gets extracted.
fetch_verified() {
    local tag="$1" asset="$2" out="$3" expected code
    expected=$(release_digest "$tag" "$asset")
    if ! [[ "$expected" =~ ^[0-9a-fA-F]{64}$ ]]; then
        echo "[error] GitHub published no SHA-256 for $asset in release $tag. Nothing was installed."
        return 1
    fi
    echo "Downloading: $asset ($tag)"
    code=$(curl -sL --proto '=https' --proto-redir '=https' -w "%{http_code}" \
        "https://github.com/${GITHUB_REPO}/releases/download/${tag}/${asset}" -o "$out") || code=000
    if [ "$code" != "200" ]; then
        echo "[error] Download failed (HTTP $code)."
        echo "Verify that $tag is published at:"
        echo "  https://github.com/$GITHUB_REPO/releases"
        rm -f "$out"
        return 1
    fi
    verify_sha256 "$out" "$expected" || { rm -f "$out"; return 1; }
}

# -- Download binary --------------------------------------------------

if [ -n "$TARGET_VERSION" ]; then
    LATEST_RELEASE="$TARGET_VERSION"
    # Ensure it starts with 'v' if it's supposed to (only for real stable
    # semver tags - the alpha/pre-release channels use bare tag names).
    if [[ ! "$LATEST_RELEASE" =~ ^v ]] && [ "$TARGET_BRANCH" == "stable" ]; then
        LATEST_RELEASE="v$LATEST_RELEASE"
    fi
    echo "Fetching requested release $LATEST_RELEASE..."
else
    if [ "$TARGET_BRANCH" == "alpha" ] || [ "$TARGET_BRANCH" == "beta" ]; then
        # There is no floating "alpha"/"beta" GitHub Release - gha.ps1 cuts a
        # fresh versioned tag every time (v0.4.2-beta.4, v0.4.2-alpha.7, ...).
        # /releases/latest only ever returns the newest NON-prerelease
        # (stable) tag, so it can't find these. Query the releases list and
        # take the highest version among the tags containing "-$TARGET_BRANCH".
        # Not the first one listed: the API does not order by version
        # (it listed v0.4.6-beta.9 before v0.4.6-beta.10).
        echo "Fetching latest ${TARGET_BRANCH} release..."
        CHANNEL_TAGS=$(curl -s "https://api.github.com/repos/${GITHUB_REPO}/releases?per_page=100" \
            | grep '"tag_name":' \
            | grep -- "-${TARGET_BRANCH}\." \
            | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')
        LATEST_RELEASE=$(printf '%s\n' "$CHANNEL_TAGS" | sort -V 2>/dev/null | tail -1)
        # sort without -V (a minimal system): the API's own order, as before.
        [ -n "$LATEST_RELEASE" ] || LATEST_RELEASE=$(printf '%s\n' "$CHANNEL_TAGS" | head -1)
    else
        echo "Fetching latest stable release..."
        LATEST_RELEASE=$(curl -s "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    fi
fi

if { [ -z "$LATEST_RELEASE" ] || [[ "$LATEST_RELEASE" == *"null"* ]]; } && [ "$ASSUME_YES" -eq 1 ]; then
    echo "[error] Could not determine the latest ${TARGET_BRANCH} release (is GitHub reachable from this server?)."
    exit 1
fi

if [ -z "$LATEST_RELEASE" ] || [[ "$LATEST_RELEASE" == *"null"* ]]; then
    echo "[notice] Could not determine latest release automatically."
    echo "Enter a direct URL to the .tar.gz archive,"
    echo "or press Enter if the binary is already in $INSTALL_DIR/ostp."
    read -p "URL: " DIRECT_URL
    if [ -n "$DIRECT_URL" ]; then
        # No API to ask here, so the checksum comes from the person installing.
        read -p "Expected SHA-256 of the archive: " DIRECT_SHA
        TEMP_TAR="$WORK_DIR/ostp.tar.gz"
        curl -fL --proto '=https' "$DIRECT_URL" -o "$TEMP_TAR"
        verify_sha256 "$TEMP_TAR" "$DIRECT_SHA" || exit 1
        tar -xzf "$TEMP_TAR" -C "$INSTALL_DIR" ostp 2>/dev/null || tar -xzf "$TEMP_TAR" -C "$INSTALL_DIR"
        rm -f "$TEMP_TAR"
    fi
else
    ARCHIVE_NAME="ostp-linux-${ARCH}.tar.gz"
    TEMP_TAR="$WORK_DIR/ostp.tar.gz"
    fetch_verified "$LATEST_RELEASE" "$ARCHIVE_NAME" "$TEMP_TAR" || exit 1
    tar -xzf "$TEMP_TAR" -C "$INSTALL_DIR" ostp 2>/dev/null || tar -xzf "$TEMP_TAR" -C "$INSTALL_DIR"
    rm -f "$TEMP_TAR"
fi

if [ -f "$INSTALL_DIR/ostp" ]; then
    chmod +x "$INSTALL_DIR/ostp"
    echo "Binary installed: $INSTALL_DIR/ostp"
else
    echo "[error] Binary not found at $INSTALL_DIR/ostp."
    exit 1
fi

# -- Create global symlink --------------------------------------------

ln -sf "$INSTALL_DIR/ostp" "$BIN_LINK"
echo "Symlink created: $BIN_LINK -> $INSTALL_DIR/ostp"

# -- Update detection -------------------------------------------------

if [ -f "$CONFIG_FILE" ]; then
    echo "--------------------------------------------------------"
    echo "Existing configuration found at $CONFIG_FILE."
    echo "Binary updated to ${LATEST_RELEASE:-latest}."

    # Config SCHEMA migration does NOT happen here (or anywhere automatic) -
    # it used to be an ad-hoc Python snippet embedded right in this script,
    # silently rewriting config.json on every update. That's exactly the kind
    # of surprise this project no longer does: the ONE place a config's shape
    # is ever changed is the explicit `ostp migrate` command (see
    # ostp-client::migrate), which backs up the original file first and
    # prints exactly what it changed. If your config predates this install,
    # run it yourself:
    echo "If this config is from an older OSTP version, run 'ostp migrate' to upgrade it."

    # Update systemd service to use new paths
    if [ -f "/etc/systemd/system/ostp.service" ]; then
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

# -- First install: delegate to the built-in setup wizard -------------

echo ""
echo "No configuration found. Launching setup wizard..."
echo ""

cd "$INSTALL_DIR"
# Files the wizard creates (config, keys, certificates) are root's alone.
umask 077
if [ "$ASSUME_YES" -eq 1 ]; then
    exec ./ostp manage install --config "$CONFIG_FILE" "${MANAGE_ARGS[@]}"
fi
exec ./ostp setup --config "$CONFIG_FILE"
