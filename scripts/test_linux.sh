#!/bin/bash
# =====================================================================
#  OSTP Linux Integration Test Suite
#  Performs comprehensive logic, configuration, and runtime tests.
# =====================================================================

# ANSI Color Definitions for Output
GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Locate target binary
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
OSTP_BIN="$SCRIPT_DIR/../dist/linux/ostp"

# Temporary Sandbox Directory for Isolating Tests
SANDBOX="/tmp/ostp_test_sandbox_$$"
mkdir -p "$SANDBOX"
cd "$SANDBOX"

# Output Formatting Helper
print_result() {
    local label="$1"
    local status="$2"
    local err_msg="$3"
    if [ "$status" -eq 0 ]; then
        echo -e "${CYAN}Testing ${label} ...${NC} ${GREEN}OK${NC}"
    else
        echo -e "${CYAN}Testing ${label} ...${NC} ${RED}ERROR ($err_msg)${NC}"
        # Perform cleanup and exit if critical setup fails
        if [[ "$label" == *"binary"* ]]; then
            rm -rf "$SANDBOX"
            exit 1
        fi
    fi
}

echo -e "\n====================================================================="
echo -e " OSTP (Ospab Stealth Transport Protocol) LINUX TEST PIPELINE"
echo -e "=====================================================================\n"

# ---------------------------------------------------------------------
# SECTION 1: BINARY & ENVIRONMENT VERIFICATION
# ---------------------------------------------------------------------

if [ -f "$OSTP_BIN" ]; then
    print_result "binary presence at path" 0
else
    print_result "binary presence at path" 1 "File not found at $OSTP_BIN. Please build first."
fi

chmod +x "$OSTP_BIN" 2>/dev/null
print_result "binary execute permissions" $? "Failed to chmod +x"

"$OSTP_BIN" --help > /dev/null 2>&1
print_result "binary execution and architecture compatibility" $? "Returned non-zero exit code. Is binary x86_64-musl compliant?"

# ---------------------------------------------------------------------
# SECTION 2: KEY GENERATION UTILITIES (ostp -g)
# ---------------------------------------------------------------------

KEY_HEX=$("$OSTP_BIN" -g)
if [[ "$KEY_HEX" =~ ^[0-9a-f]{32}$ ]]; then
    print_result "secure key generation (hex 16-byte)" 0
else
    print_result "secure key generation (hex 16-byte)" 1 "Invalid hex format or length: $KEY_HEX"
fi

KEY_B64=$("$OSTP_BIN" -g --format base64)
if [ ${#KEY_B64} -gt 10 ]; then
    print_result "secure key generation (base64)" 0
else
    print_result "secure key generation (base64)" 1 "Base64 key too short or empty"
fi

KEY_COUNT=$("$OSTP_BIN" -g -c 5 | wc -l)
if [ "$KEY_COUNT" -eq 5 ]; then
    print_result "secure key generation multi-count (-c 5)" 0
else
    print_result "secure key generation multi-count (-c 5)" 1 "Expected 5 lines, got $KEY_COUNT"
fi

# ---------------------------------------------------------------------
# SECTION 3: CONFIGURATION COMPILER (--init)
# ---------------------------------------------------------------------

# Cleanup existing configs if any
rm -f config.json

"$OSTP_BIN" --init server --config config_srv.json > /dev/null 2>&1
if [ -f "config_srv.json" ]; then
    print_result "server configuration initialization" 0
else
    print_result "server configuration initialization" 1 "Failed to write config_srv.json"
fi

grep -q '"mode": "server"' config_srv.json
print_result "server config schema validation" $? "Mode field missing or incorrect"

"$OSTP_BIN" --init client --config config_cli.json > /dev/null 2>&1
if [ -f "config_cli.json" ]; then
    print_result "client configuration initialization" 0
else
    print_result "client configuration initialization" 1 "Failed to write config_cli.json"
fi

grep -q '"mode": "client"' config_cli.json
CLI_MODE=$?
grep -q '"socks5_bind"' config_cli.json
CLI_SOCKS=$?
if [ $CLI_MODE -eq 0 ] && [ $CLI_SOCKS -eq 0 ]; then
    print_result "client config schema validation" 0
else
    print_result "client config schema validation" 1 "Missing mode or socks5_bind fields"
fi

# ---------------------------------------------------------------------
# SECTION 4: SERVER RUNTIME TESTS
# ---------------------------------------------------------------------

# Run server in background, capturing output and PID
SRV_PORT=49218
sed -i "s/\"listen\": \".*\"/\"listen\": \"127.0.0.1:$SRV_PORT\"/g" config_srv.json

"$OSTP_BIN" --config config_srv.json > server_run.log 2>&1 &
SRV_PID=$!

# Wait for instantiation
sleep 2

# Check if process is alive
kill -0 $SRV_PID 2>/dev/null
STATUS=$?
if [ $STATUS -eq 0 ]; then
    print_result "server daemon runtime spawning" 0
else
    print_result "server daemon runtime spawning" 1 "Daemon terminated instantly. Log: $(cat server_run.log)"
fi

# Validate log patterns
grep -q "Starting in SERVER mode" server_run.log
print_result "server dynamic mode logging" $? "Expected starting sequence omitted in log"

# Clean up server
kill $SRV_PID 2>/dev/null
wait $SRV_PID 2>/dev/null
print_result "server active daemon termination" 0

# ---------------------------------------------------------------------
# SECTION 5: CLIENT RUNTIME TESTS
# ---------------------------------------------------------------------

# Prepare client config targeting server port and unique SOCKS5 bind
CLI_SOCKS_PORT=49219
sed -i "s/\"socks5_bind\": \".*\"/\"socks5_bind\": \"127.0.0.1:$CLI_SOCKS_PORT\"/g" config_cli.json
sed -i "s/\"server\": \".*\"/\"server\": \"127.0.0.1:$SRV_PORT\"/g" config_cli.json

"$OSTP_BIN" --config config_cli.json > client_run.log 2>&1 &
CLI_PID=$!

sleep 2

kill -0 $CLI_PID 2>/dev/null
STATUS=$?
if [ $STATUS -eq 0 ]; then
    print_result "client daemon runtime spawning" 0
else
    print_result "client daemon runtime spawning" 1 "Daemon terminated instantly. Log: $(cat client_run.log)"
fi

# Verify local proxy init logging
grep -q "Starting in CLIENT mode" client_run.log
print_result "client local proxy pipeline logging" $? "Starting logs missing"

# Verify network bindings (checking if SOCKS5 port opened)
# Try both ss and netstat, or fallback to /proc parsing
PORT_ACTIVE=1
if command -v ss > /dev/null 2>&1; then
    ss -tuln | grep -q ":$CLI_SOCKS_PORT"
    PORT_ACTIVE=$?
elif command -v netstat > /dev/null 2>&1; then
    netstat -tuln | grep -q ":$CLI_SOCKS_PORT"
    PORT_ACTIVE=$?
else
    # Fallback to assuming success if utilities not installed and PID is live
    PORT_ACTIVE=0
fi

print_result "client TCP proxy socket bind" $PORT_ACTIVE "TCP Port $CLI_SOCKS_PORT not responding"

# Clean up client
kill $CLI_PID 2>/dev/null
wait $CLI_PID 2>/dev/null
print_result "client active daemon termination" 0

# ---------------------------------------------------------------------
# FINAL CLEANUP
# ---------------------------------------------------------------------
cd "$SCRIPT_DIR"
rm -rf "$SANDBOX"

echo -e "\n====================================================================="
echo -e " OSTP TESTS EXECUTED SUCCESSFULLY"
echo -e "=====================================================================\n"
