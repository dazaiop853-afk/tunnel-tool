#!/usr/bin/env bash
# ==============================================================================
# Persistent SSH Reverse Tunnel Manager v2.6.0
# ==============================================================================
set -u

VERSION="2.6.0"
# [IMPORTANT] REPLACE WITH YOUR RAW GITHUB URL
UPDATE_URL="https://raw.githubusercontent.com/dazaiop853-afk/tunnel-tool/main/tunnel.sh"

KEY_NAME="conn_finder"
KEY_DIR="$HOME/.ssh"
KEY_PATH="$KEY_DIR/$KEY_NAME"
CONFIG_FILE="$HOME/.tunnel_config"
KNOWN_HOSTS_FILE="$KEY_DIR/tunnel_known_hosts"

TARGET_PORT=22
TARGET_USER="root"
CLEAN_MODE=false
REVERSE_PORT=2222
SOCKS_PORT=1080

# --- Standardized SSH Options (The Fix for Multiplexing) ---
# We disable ControlMaster to prevent the script from hijacking existing sessions
SSH_BASE_OPTS="-o ControlMaster=no -o ControlPath=none -o ConnectTimeout=10 -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$KNOWN_HOSTS_FILE"

if [ -t 1 ]; then
    GREEN='\033[0;32m'
    RED='\033[0;31m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m'
else
    GREEN='' RED='' YELLOW='' BLUE='' NC=''
fi

log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

cleanup_on_exit() {
    if [ -n "${SSH_PID:-}" ]; then
        kill "$SSH_PID" 2>/dev/null || true
    fi
    exit 0
}
trap cleanup_on_exit INT TERM

usage() {
    cat << EOF
Usage: $0 [OPTIONS]
  -c          Clean configuration
  -p PORT     SSH port (default: 22)
  -u USER     SSH user (default: root)
  -r PORT     Reverse port (default: 2222)
  -s PORT     SOCKS5 port (default: 1080)
  --update    Self-update
  -h          Help
EOF
    exit 1
}

# --- Self-Updater ---
self_update() {
    log_info "Checking for updates..."
    TMP_FILE=$(mktemp)
    if curl -sL "$UPDATE_URL" -o "$TMP_FILE"; then
        if bash -n "$TMP_FILE"; then
            mv "$TMP_FILE" "${BASH_SOURCE[0]}"
            chmod +x "${BASH_SOURCE[0]}"
            log_success "Updated. Restarting..."
            exec "${BASH_SOURCE[0]}" "${@:2}"
        fi
    fi
    log_error "Update failed."
    rm -f "$TMP_FILE"
    exit 1
}

if [ "${1:-}" = "--update" ]; then self_update "$@"; fi

while getopts ":cp:u:r:s:h" opt; do
    case ${opt} in
        c) CLEAN_MODE=true ;;
        p) TARGET_PORT=$OPTARG ;;
        u) TARGET_USER=$OPTARG ;;
        r) REVERSE_PORT=$OPTARG ;;
        s) SOCKS_PORT=$OPTARG ;;
        h) usage ;;
        *) usage ;;
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
    ssh-keygen -t ed25519 -f "$KEY_PATH" -N "" -C "tunnel-$(date +%Y%m%d)" -q
    log_success "Keys created."
fi

# --- Reachability ---
check_reachability() {
    local ip=$1; local port=$2; local user=$3
    printf "Testing %s@%s:%s ... " "$user" "$ip" "$port"
    
    # 1. Try with existing key
    if ssh $SSH_BASE_OPTS -o BatchMode=yes -p "$port" -i "$KEY_PATH" "$user@$ip" exit 2>/dev/null; then
        echo -e "${GREEN}Authorized${NC}"; return 0
    fi
    
    # 2. Try auth check
    local output
    output=$(ssh $SSH_BASE_OPTS -o BatchMode=yes -o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive -o StrictHostKeyChecking=accept-new -o NumberOfPasswordPrompts=0 -p "$port" "$user@$ip" exit 2>&1) || true
    
    if echo "$output" | grep -qE "Permission denied|publickey|password"; then
        echo -e "${GREEN}Reachable${NC}"; return 0
    fi
    echo -e "${RED}Unreachable${NC}"; return 1
}

copy_ssh_id() {
    local user=$1; local ip=$2; local port=$3
    log_info "Transferring key..."
    # We deliberately do NOT use SSH_BASE_OPTS here as ssh-copy-id is a script
    if command -v ssh-copy-id >/dev/null 2>&1; then
        ssh-copy-id -i "${KEY_PATH}.pub" -p "$port" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$KNOWN_HOSTS_FILE" "$user@$ip"
    else
        cat "${KEY_PATH}.pub" | ssh -p "$port" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$KNOWN_HOSTS_FILE" "$user@$ip" "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
    fi
}

# --- Config Loop ---
if [ -f "$CONFIG_FILE" ]; then
    IFS=':' read -r SAVED_IP SAVED_PORT SAVED_USER < "$CONFIG_FILE"
    if check_reachability "$SAVED_IP" "$SAVED_PORT" "$SAVED_USER"; then
        TARGET_IP="$SAVED_IP"; TARGET_PORT="$SAVED_PORT"; TARGET_USER="$SAVED_USER"
        log_success "Using saved: $TARGET_USER@$TARGET_IP"
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
        chmod 600 "$CONFIG_FILE"
    fi
done

# --- Security Check ---
log_info "Verifying host key..."
ssh-keygen -l -f "$KNOWN_HOSTS_FILE" 2>/dev/null | grep "$TARGET_IP" || true
read -p "Continue? (yes/no): " CONFIRM
[ "$CONFIRM" != "yes" ] && exit 1

# --- Remote Cleanup Function (Robust) ---
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

# --- Main Tunnel Loop ---
echo ""
echo "=============================================="
echo "  Remote:        $TARGET_USER@$TARGET_IP:$TARGET_PORT"
echo "  Reverse Port:  127.0.0.1:$REVERSE_PORT"
echo "=============================================="

RETRY_COUNT=0
MAX_RETRIES=10

while true; do
    # 1. Cleanup Remote Port
    log_info "Cleaning remote port $REVERSE_PORT..."
    CLEANUP_SCRIPT=$(get_cleanup_cmd)
    
    # We use SSH_BASE_OPTS here to ensure we don't hit the mux socket
    ssh $SSH_BASE_OPTS -p "$TARGET_PORT" -i "$KEY_PATH" "$TARGET_USER@$TARGET_IP" \
        "bash -s -- $REVERSE_PORT" <<< "$CLEANUP_SCRIPT" 2>/dev/null || true
        
    sleep 1

    # 2. Start Tunnel
    log_info "Starting tunnel..."
    
    # We use SSH_BASE_OPTS + -N (no command) + -R (Reverse) + -D (Socks)
    ssh $SSH_BASE_OPTS \
        -N \
        -R "127.0.0.1:$REVERSE_PORT:127.0.0.1:22" \
        -D "127.0.0.1:$SOCKS_PORT" \
        -o ServerAliveInterval=15 \
        -o ServerAliveCountMax=3 \
        -o ExitOnForwardFailure=yes \
        -p "$TARGET_PORT" \
        -i "$KEY_PATH" \
        "$TARGET_USER@$TARGET_IP" &
    
    SSH_PID=$!
    
    # 3. Monitor
    sleep 3
    if ! kill -0 "$SSH_PID" 2>/dev/null; then
        RETRY_COUNT=$((RETRY_COUNT + 1))
        log_error "Tunnel failed immediately (Check if port $REVERSE_PORT is free on remote)."
        
        if [ "$RETRY_COUNT" -ge "$MAX_RETRIES" ]; then
            log_error "Max retries reached. Exiting."
            exit 1
        fi
        
        sleep 5
        continue
    fi
    
    log_success "Tunnel Established (PID: $SSH_PID)"
    RETRY_COUNT=0
    
    wait "$SSH_PID" 2>/dev/null || true
    
    log_warn "Tunnel disconnected. Reconnecting in 5s..."
    sleep 5
done
