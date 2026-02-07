#!/usr/bin/env bash
# ==============================================================================
# Persistent SSH Reverse Tunnel Manager v2.2.0
# ==============================================================================
# Description: Creates a robust reverse SSH tunnel to a remote server with
#              automatic reconnection, port cleanup, and cross-platform support.
# Compatible:  macOS (bash/zsh), Linux (Ubuntu, CentOS, Alpine, Debian)
# ==============================================================================

set -u # Exit on undefined vars

# --- Configuration ---
VERSION="2.2.0"
# [IMPORTANT] REPLACE THIS URL AFTER UPLOADING TO GITHUB
UPDATE_URL="https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/main/tunnel.sh" 

KEY_NAME="conn_finder"
KEY_DIR="$HOME/.ssh"
KEY_PATH="$KEY_DIR/$KEY_NAME"
CONFIG_FILE="$HOME/.tunnel_config"
KNOWN_HOSTS_FILE="$KEY_DIR/tunnel_known_hosts"

# Defaults
TARGET_PORT=22
TARGET_USER="root"
CLEAN_MODE=false
REVERSE_PORT=2222
SOCKS_PORT=1080

# Colors (only if terminal supports it)
if [ -t 1 ]; then
    GREEN='\033[0;32m'
    RED='\033[0;31m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m'
else
    GREEN='' RED='' YELLOW='' BLUE='' NC=''
fi

# --- Utility Functions ---
log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

cleanup_on_exit() {
    # Kill SSH tunnel if running
    if [ -n "${SSH_PID:-}" ]; then
        kill "$SSH_PID" 2>/dev/null || true
    fi
    exit 0
}
trap cleanup_on_exit INT TERM

# --- Usage ---
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

OPTIONS:
    -c          Clean stored configuration
    -p PORT     Target SSH port (default: 22)
    -u USER     Target SSH user (default: root)
    -r PORT     Reverse tunnel port on remote (default: 2222)
    -s PORT     Local SOCKS5 port (default: 1080)
    --update    Self-update from remote URL
    -h          Show this help
EOF
    exit 1
}

# --- Version Comparison ---
version_gt() {
    # Returns 0 if $1 > $2
    test "$(printf '%s\n' "$@" | sort -V | head -n 1)" != "$1"
}

# --- Self-Updater ---
self_update() {
    log_info "Checking for updates..."
    
    TMP_FILE=$(mktemp)
    trap 'rm -f "$TMP_FILE"' RETURN
    
    # Download 
    HTTP_CODE=0
    if command -v curl >/dev/null 2>&1; then
        HTTP_CODE=$(curl -sL -w "%{http_code}" "$UPDATE_URL" -o "$TMP_FILE" 2>/dev/null || echo "000")
    elif command -v wget >/dev/null 2>&1; then
        if wget -qO "$TMP_FILE" "$UPDATE_URL" 2>/dev/null; then HTTP_CODE=200; else HTTP_CODE=000; fi
    else
        log_error "Neither curl nor wget found. Cannot update."
        exit 1
    fi
    
    # Validate
    if [ "$HTTP_CODE" != "200" ] || [ ! -s "$TMP_FILE" ]; then
        log_error "Update failed (HTTP $HTTP_CODE or empty file)"
        exit 1
    fi
    
    if ! bash -n "$TMP_FILE" 2>/dev/null; then
        log_error "Downloaded file is not valid bash syntax"
        exit 1
    fi
    
    # Extract version
    REMOTE_VERSION=$(grep '^VERSION=' "$TMP_FILE" | head -n1 | cut -d'"' -f2)
    
    if [ -z "$REMOTE_VERSION" ]; then
        log_warn "Could not detect remote version. Proceeding..."
    elif version_gt "$REMOTE_VERSION" "$VERSION"; then
        log_success "New version available: $REMOTE_VERSION (current: $VERSION)"
    else
        log_info "Already running latest version ($VERSION)"
        exit 0
    fi
    
    # Replace script
    SCRIPT_PATH="${BASH_SOURCE[0]}"
    if mv "$TMP_FILE" "$SCRIPT_PATH"; then
        chmod +x "$SCRIPT_PATH"
        log_success "Update complete. Restarting..."
        rm -f "$TMP_FILE" # Explicit cleanup before exec
        exec "$SCRIPT_PATH" "${@:2}"
    else
        log_error "Failed to replace script. Check permissions."
        exit 1
    fi
}

# --- Argument Parsing ---
if [ "${1:-}" = "--update" ]; then self_update "$@"; fi

while getopts ":cp:u:r:s:h" opt; do
    case ${opt} in
        c) CLEAN_MODE=true ;;
        p) TARGET_PORT=$OPTARG ;;
        u) TARGET_USER=$OPTARG ;;
        r) REVERSE_PORT=$OPTARG ;;
        s) SOCKS_PORT=$OPTARG ;;
        h) usage ;;
        \?) log_error "Invalid option: -$OPTARG"; usage ;;
    esac
done

if [ "$CLEAN_MODE" = true ]; then
    rm -f "$CONFIG_FILE" "$KNOWN_HOSTS_FILE"
    log_success "Configuration cleaned"
    exit 0
fi

# --- Key Management ---
if [ ! -f "$KEY_PATH" ]; then
    log_info "Generating SSH key pair ($KEY_NAME)..."
    mkdir -p "$KEY_DIR" && chmod 700 "$KEY_DIR"
    ssh-keygen -t ed25519 -f "$KEY_PATH" -N "" -C "tunnel-$(date +%Y%m%d)" -q
    log_success "Keys generated."
fi

# --- Reachability Check ---
check_reachability() {
    local ip=$1; local port=$2; local user=$3
    printf "Testing %s@%s:%s ... " "$user" "$ip" "$port"
    
    # Attempt 1: Already Authorized
    if ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$KNOWN_HOSTS_FILE" -p "$port" -i "$KEY_PATH" "$user@$ip" exit 2>/dev/null; then
        echo -e "${GREEN}Authorized${NC}"; return 0
    fi
    
    # Attempt 2: Server UP but needs password
    local output
    output=$(ssh -o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$KNOWN_HOSTS_FILE" -o NumberOfPasswordPrompts=0 -o BatchMode=yes -p "$port" "$user@$ip" exit 2>&1) || true
    
    if echo "$output" | grep -qE "Permission denied|publickey|password"; then
        echo -e "${GREEN}Reachable (needs auth)${NC}"; return 0
    fi
    
    echo -e "${RED}Unreachable${NC}"; return 1
}

# --- SSH Copy ID ---
copy_ssh_id() {
    local user=$1; local ip=$2; local port=$3
    log_warn "You will be prompted for the password for $user@$ip"
    
    if command -v ssh-copy-id >/dev/null 2>&1; then
        ssh-copy-id -i "${KEY_PATH}.pub" -p "$port" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$KNOWN_HOSTS_FILE" "$user@$ip"
    else
        cat "${KEY_PATH}.pub" | ssh -p "$port" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$KNOWN_HOSTS_FILE" "$user@$ip" "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
    fi
}

# --- Remote Port Cleanup Generator (Robust) ---
get_cleanup_cmd() {
    cat <<'CLEANUP_SCRIPT'
    PORT=$1
    # Try methods sequentially, exit on first success
    
    if command -v fuser >/dev/null 2>&1; then
        fuser -k -n tcp "$PORT" 2>/dev/null
        exit 0
    fi
    
    if command -v lsof >/dev/null 2>&1; then
        for pid in $(lsof -t -i:"$PORT" 2>/dev/null); do
            kill "$pid" 2>/dev/null
        done
        exit 0
    fi
    
    if command -v ss >/dev/null 2>&1; then
        # Grep pid, cut logic
        for pid in $(ss -lptn "sport = :$PORT" 2>/dev/null | grep -o 'pid=[0-9]*' | cut -d= -f2); do
            kill "$pid" 2>/dev/null
        done
        exit 0
    fi
    
    # Fallback: netstat
    for pid in $(netstat -lnp 2>/dev/null | grep ":$PORT " | awk '{print $7}' | cut -d/ -f1); do
        [ -n "$pid" ] && kill "$pid" 2>/dev/null
    done
CLEANUP_SCRIPT
}

# --- Main Logic ---

# 1. Load or Request Config
if [ -f "$CONFIG_FILE" ]; then
    IFS=':' read -r SAVED_IP SAVED_PORT SAVED_USER < "$CONFIG_FILE"
    if check_reachability "$SAVED_IP" "$SAVED_PORT" "$SAVED_USER"; then
        TARGET_IP="$SAVED_IP"
        TARGET_PORT="${TARGET_PORT:-$SAVED_PORT}"
        TARGET_USER="${TARGET_USER:-$SAVED_USER}"
    else
        log_warn "Saved server unreachable."
        TARGET_IP=""
    fi
else
    TARGET_IP=""
fi

# 2. Manual Config Loop
while [ -z "${TARGET_IP:-}" ]; do
    read -p "Enter server IP address: " INPUT_IP
    if check_reachability "$INPUT_IP" "$TARGET_PORT" "$TARGET_USER"; then
        if copy_ssh_id "$TARGET_USER" "$INPUT_IP" "$TARGET_PORT"; then
            TARGET_IP="$INPUT_IP"
            echo "${TARGET_IP}:${TARGET_PORT}:${TARGET_USER}" > "$CONFIG_FILE" && chmod 600 "$CONFIG_FILE"
            log_success "Configuration saved"
        else
            log_error "Key transfer failed."
        fi
    fi
done

# 3. Host Key Verification (Security Step)
log_info "Verifying host key fingerprint..."
ssh-keygen -l -f "$KNOWN_HOSTS_FILE" 2>/dev/null | grep "$TARGET_IP" || true

printf "%s" "Continue with this host key? (yes/no): "
read -r CONFIRM
if [ "$CONFIRM" != "yes" ]; then
    log_error "Host key verification rejected. Exiting."
    exit 1
fi

# 4. Tunnel Loop
log_success "Starting persistent reverse tunnel"
echo "Remote: $TARGET_USER@$TARGET_IP:$TARGET_PORT | Reverse Port: $REVERSE_PORT | SOCKS5: $SOCKS_PORT"

RETRY_COUNT=0
MAX_RETRIES=10

while true; do
    # Cleanup remote port (Passing arg correctly now)
    CLEANUP_SCRIPT=$(get_cleanup_cmd)
    
    ssh -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$KNOWN_HOSTS_FILE" \
        -p "$TARGET_PORT" -i "$KEY_PATH" "$TARGET_USER@$TARGET_IP" \
        "bash -s -- $REVERSE_PORT" <<< "$CLEANUP_SCRIPT" 2>/dev/null || true

    sleep 1

    # Open Tunnel
    ssh -N -R "0.0.0.0:$REVERSE_PORT:127.0.0.1:22" \
        -D "127.0.0.1:$SOCKS_PORT" \
        -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \
        -o ExitOnForwardFailure=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$KNOWN_HOSTS_FILE" \
        -p "$TARGET_PORT" -i "$KEY_PATH" "$TARGET_USER@$TARGET_IP" &
    
    SSH_PID=$!
    
    # Wait for tunnel to stabilize
    sleep 3
    if ! kill -0 "$SSH_PID" 2>/dev/null; then
        RETRY_COUNT=$((RETRY_COUNT + 1))
        if [ "$RETRY_COUNT" -ge "$MAX_RETRIES" ]; then
            log_error "Max retries reached. Exiting."
            exit 1
        fi
        log_warn "Tunnel failed. Retry $RETRY_COUNT/$MAX_RETRIES in 10s..."
        sleep 10
        continue
    fi

    # Tunnel is up, reset retries
    RETRY_COUNT=0
    wait "$SSH_PID" 2>/dev/null || true
    
    log_warn "Tunnel disconnected. Reconnecting in 5s..."
    sleep 5
done
