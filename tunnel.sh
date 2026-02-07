#!/usr/bin/env bash
# ==============================================================================
# Persistent SSH Reverse Tunnel Manager v2.3.0-DEBUG
# ==============================================================================

set -u

# --- Configuration ---
VERSION="2.3.0-DEBUG"
# REPLACE THIS URL
UPDATE_URL="https://raw.githubusercontent.com/dazaiop853-afk/tunnel-tool/main/tunnel.sh" 

KEY_NAME="conn_finder"
KEY_DIR="$HOME/.ssh"
KEY_PATH="$KEY_DIR/$KEY_NAME"
CONFIG_FILE="$HOME/.tunnel_config"
KNOWN_HOSTS_FILE="$KEY_DIR/tunnel_known_hosts"
SSH_LOG=$(mktemp) # Temp file for debug logs

# Defaults
TARGET_PORT=22
TARGET_USER="root"
CLEAN_MODE=false
REVERSE_PORT=2222
SOCKS_PORT=1080

# Colors
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
    if [ -n "${SSH_PID:-}" ]; then kill "$SSH_PID" 2>/dev/null || true; fi
    rm -f "$SSH_LOG"
    exit 0
}
trap cleanup_on_exit INT TERM

# --- Usage ---
usage() {
    echo "Usage: $0 [-c] [-p port] [-u user] [-r reverse_port] [-s socks_port] [--update]"
    exit 1
}

# --- Self-Updater ---
self_update() {
    log_info "Checking for updates..."
    TMP_FILE=$(mktemp)
    trap 'rm -f "$TMP_FILE"' RETURN
    if curl -sL "$UPDATE_URL" -o "$TMP_FILE"; then
        if bash -n "$TMP_FILE"; then
            mv "$TMP_FILE" "${BASH_SOURCE[0]}"
            chmod +x "${BASH_SOURCE[0]}"
            log_success "Updated. Restarting..."
            exec "${BASH_SOURCE[0]}" "${@:2}"
        fi
    fi
    log_error "Update failed."
    exit 1
}

# --- Arguments ---
if [ "${1:-}" = "--update" ]; then self_update "$@"; fi
while getopts ":cp:u:r:s:h" opt; do
    case ${opt} in
        c) CLEAN_MODE=true ;;
        p) TARGET_PORT=$OPTARG ;;
        u) TARGET_USER=$OPTARG ;;
        r) REVERSE_PORT=$OPTARG ;;
        s) SOCKS_PORT=$OPTARG ;;
        h) usage ;;
    esac
done

if [ "$CLEAN_MODE" = true ]; then
    rm -f "$CONFIG_FILE" "$KNOWN_HOSTS_FILE"
    log_success "Config cleaned."
    exit 0
fi

# --- Keys ---
if [ ! -f "$KEY_PATH" ]; then
    log_info "Generating Keys..."
    mkdir -p "$KEY_DIR" && chmod 700 "$KEY_DIR"
    ssh-keygen -t ed25519 -f "$KEY_PATH" -N "" -q
    log_success "Keys generated."
fi

# --- Reachability ---
check_reachability() {
    local ip=$1; local port=$2; local user=$3
    printf "Testing %s@%s:%s ... " "$user" "$ip" "$port"
    if ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$KNOWN_HOSTS_FILE" -p "$port" -i "$KEY_PATH" "$user@$ip" exit 2>/dev/null; then
        echo -e "${GREEN}Authorized${NC}"; return 0
    fi
    local output
    output=$(ssh -o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$KNOWN_HOSTS_FILE" -o BatchMode=yes -p "$port" "$user@$ip" exit 2>&1) || true
    if echo "$output" | grep -qE "Permission denied|publickey|password"; then
        echo -e "${GREEN}Reachable (needs auth)${NC}"; return 0
    fi
    echo -e "${RED}Unreachable${NC}"; return 1
}

copy_ssh_id() {
    local user=$1; local ip=$2; local port=$3
    log_warn "Prompting for password to copy keys..."
    ssh-copy-id -i "${KEY_PATH}.pub" -p "$port" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$KNOWN_HOSTS_FILE" "$user@$ip"
}

# --- Config Loop ---
if [ -f "$CONFIG_FILE" ]; then
    IFS=':' read -r SAVED_IP SAVED_PORT SAVED_USER < "$CONFIG_FILE"
    if check_reachability "$SAVED_IP" "$SAVED_PORT" "$SAVED_USER"; then
        TARGET_IP="$SAVED_IP"; TARGET_PORT="${TARGET_PORT:-$SAVED_PORT}"; TARGET_USER="${TARGET_USER:-$SAVED_USER}"
    else
        TARGET_IP=""
    fi
else
    TARGET_IP=""
fi

while [ -z "${TARGET_IP:-}" ]; do
    read -p "Enter server IP: " INPUT_IP
    if check_reachability "$INPUT_IP" "$TARGET_PORT" "$TARGET_USER"; then
        copy_ssh_id "$TARGET_USER" "$INPUT_IP" "$TARGET_PORT" && TARGET_IP="$INPUT_IP"
        echo "${TARGET_IP}:${TARGET_PORT}:${TARGET_USER}" > "$CONFIG_FILE"
    fi
done

# --- Cleanup Generator ---
get_cleanup_cmd() {
    cat <<'CLEANUP_SCRIPT'
    PORT=$1
    if command -v fuser >/dev/null 2>&1; then fuser -k -n tcp "$PORT"; exit 0; fi
    if command -v lsof >/dev/null 2>&1; then lsof -t -i:"$PORT" | xargs -r kill 2>/dev/null; exit 0; fi
    if command -v ss >/dev/null 2>&1; then
        for pid in $(ss -lptn "sport = :$PORT" 2>/dev/null | grep -o 'pid=[0-9]*' | cut -d= -f2); do kill "$pid" 2>/dev/null; done
        exit 0
    fi
CLEANUP_SCRIPT
}

# --- Tunnel Loop (DEBUG ENABLED) ---
log_success "Starting Tunnel to $TARGET_IP"
log_info "Debug Log: $SSH_LOG"

while true; do
    # 1. Cleanup
    CLEANUP_SCRIPT=$(get_cleanup_cmd)
    ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$KNOWN_HOSTS_FILE" \
        -p "$TARGET_PORT" -i "$KEY_PATH" "$TARGET_USER@$TARGET_IP" \
        "bash -s -- $REVERSE_PORT" <<< "$CLEANUP_SCRIPT" >/dev/null 2>/dev/null

    sleep 1

    # 2. Start Tunnel (With Verbose Logging to File)
    # Added -v to ssh for debug info
    # Redirecting both stdout and stderr to log file
    ssh -v -N -R "0.0.0.0:$REVERSE_PORT:127.0.0.1:22" \
        -D "127.0.0.1:$SOCKS_PORT" \
        -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \
        -o ExitOnForwardFailure=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$KNOWN_HOSTS_FILE" \
        -p "$TARGET_PORT" -i "$KEY_PATH" "$TARGET_USER@$TARGET_IP" > "$SSH_LOG" 2>&1 &
    
    SSH_PID=$!
    
    # 3. Monitor for immediate failure
    sleep 3
    if ! kill -0 "$SSH_PID" 2>/dev/null; then
        log_error "Tunnel process died immediately!"
        echo "---------------- SSH ERROR LOG ----------------"
        cat "$SSH_LOG"
        echo "-----------------------------------------------"
        
        # Check specific errors
        if grep -q "remote port forwarding failed" "$SSH_LOG"; then
            log_error "Server failed to bind port $REVERSE_PORT."
            log_warn "FIX: Check if port is in use or GatewayPorts is 'no' on server."
        fi
        
        exit 1
    fi
    
    log_success "Tunnel Stable (PID: $SSH_PID)"
    wait "$SSH_PID"
    log_warn "Tunnel disconnected. Retrying..."
    sleep 5
done
