#!/usr/bin/env bash
# ==============================================================================
# Persistent SSH Reverse Tunnel Manager v3.2.0 (Auto-Clean & Smart Auth)
# ==============================================================================
set -u

VERSION="3.2.0"
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

# --- NUCLEAR SSH OPTIONS ---
SSH_OPTS="-F /dev/null -S none -o ControlMaster=no -o ConnectTimeout=10 -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$KNOWN_HOSTS_FILE -o IdentitiesOnly=yes"

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

log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

cleanup_on_exit() {
    if [ -n "${SSH_PID:-}" ]; then kill "$SSH_PID" 2>/dev/null || true; fi
    exit 0
}
trap cleanup_on_exit INT TERM

# --- Self-Updater ---
if [ "${1:-}" = "--update" ]; then
    log_info "Updating..."
    TMP=$(mktemp)
    curl -sL "$UPDATE_URL?t=$(date +%s)" -o "$TMP"
    if bash -n "$TMP"; then
        mv "$TMP" "${BASH_SOURCE[0]}"
        chmod +x "${BASH_SOURCE[0]}"
        log_success "Updated to $(grep '^VERSION=' "${BASH_SOURCE[0]}" | cut -d'"' -f2). Restarting..."
        exec "${BASH_SOURCE[0]}" "${@:2}"
    else
        log_error "Update failed."
        exit 1
    fi
fi

# --- Args ---
while getopts ":cp:u:r:s:h" opt; do
    case ${opt} in
        c) CLEAN_MODE=true ;;
        p) TARGET_PORT=$OPTARG ;;
        u) TARGET_USER=$OPTARG ;;
        r) REVERSE_PORT=$OPTARG ;;
        s) SOCKS_PORT=$OPTARG ;;
        *) echo "Usage: $0 [-c] [-p port] [-u user] [-r rev_port] [-s socks_port]"; exit 1 ;;
    esac
done

if [ "$CLEAN_MODE" = true ]; then rm -f "$CONFIG_FILE" "$KNOWN_HOSTS_FILE"; log_success "Cleaned."; exit 0; fi

# --- Keys ---
if [ ! -f "$KEY_PATH" ]; then
    log_info "Generating Keys..."
    mkdir -p "$KEY_DIR" && chmod 700 "$KEY_DIR"
    ssh-keygen -t ed25519 -f "$KEY_PATH" -N "" -C "tunnel-$(date +%Y%m%d)" -q
fi

# --- Smart Reachability Check ---
check_status() {
    local ip=$1; local port=$2; local user=$3
    printf "Testing %s@%s:%s ... " "$user" "$ip" "$port"
    
    # 1. Try with Key (Success case)
    if ssh $SSH_OPTS -o BatchMode=yes -p "$port" -i "$KEY_PATH" "$user@$ip" exit 2>/dev/null; then
        echo -e "${GREEN}Authorized${NC}"; return 0
    fi
    
    # 2. Try Password Auth (Repair case)
    local output
    output=$(ssh -F /dev/null -o UserKnownHostsFile=$KNOWN_HOSTS_FILE -o StrictHostKeyChecking=accept-new -o BatchMode=yes -o ConnectTimeout=5 -o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive -p "$port" "$user@$ip" exit 2>&1) || true
    
    if echo "$output" | grep -qE "Permission denied|publickey|password"; then
        echo -e "${YELLOW}Needs Auth${NC}"; return 2
    fi
    
    echo -e "${RED}Unreachable${NC}"; return 1
}

copy_ssh_id() {
    local user=$1; local ip=$2; local port=$3
    log_warn "Access denied. Attempting to repair keys..."
    log_info "Please enter the server password:"
    cat "${KEY_PATH}.pub" | ssh -F /dev/null -o UserKnownHostsFile=$KNOWN_HOSTS_FILE -o StrictHostKeyChecking=accept-new -p "$port" "$user@$ip" "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
    return $?
}

# --- 1. Load Config & Auto-Repair ---
TARGET_IP=""
if [ -f "$CONFIG_FILE" ]; then
    IFS=':' read -r SIP SPORT SUSER < "$CONFIG_FILE"
    check_status "$SIP" "$SPORT" "$SUSER"
    STATUS=$?
    
    if [ $STATUS -eq 0 ]; then
        TARGET_IP="$SIP"; TARGET_PORT="$SPORT"; TARGET_USER="$SUSER"
        log_success "Loaded from config: $TARGET_IP"
    elif [ $STATUS -eq 2 ]; then
        if copy_ssh_id "$SUSER" "$SIP" "$SPORT"; then
            TARGET_IP="$SIP"; TARGET_PORT="$SPORT"; TARGET_USER="$SUSER"
            log_success "Access repaired."
        else
            log_error "Failed to repair access."
            TARGET_IP=""
        fi
    else
        log_warn "Saved IP unreachable. Switch to manual."
        TARGET_IP=""
    fi
fi

# --- 2. Manual Entry Loop ---
while [ -z "${TARGET_IP:-}" ]; do
    read -p "Enter server IP: " INPUT_IP
    check_status "$INPUT_IP" "$TARGET_PORT" "$TARGET_USER"
    STATUS=$?
    if [ $STATUS -eq 0 ]; then
        TARGET_IP="$INPUT_IP"
    elif [ $STATUS -eq 2 ]; then
        if copy_ssh_id "$TARGET_USER" "$INPUT_IP" "$TARGET_PORT"; then
            TARGET_IP="$INPUT_IP"
        fi
    fi
    
    if [ -n "$TARGET_IP" ]; then
        echo "${TARGET_IP}:${TARGET_PORT}:${TARGET_USER}" > "$CONFIG_FILE"
        log_success "Configuration saved."
    fi
done

# --- Cleanup Generator (Now with Auto-Wipe!) ---
get_cleanup_cmd() {
    cat <<'CLEANUP_SCRIPT'
    PORT=$1
    [ -z "$PORT" ] && exit 1
    
    # 1. Clean Known Hosts (The Fix)
    # This prevents the "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!" error
    if command -v ssh-keygen >/dev/null 2>&1; then
        ssh-keygen -f "$HOME/.ssh/known_hosts" -R "[127.0.0.1]:$PORT" >/dev/null 2>&1
    fi
    
    # 2. Kill Zombie Ports
    if command -v fuser >/dev/null 2>&1; then fuser -k -n tcp "$PORT"; exit 0; fi
    if command -v lsof >/dev/null 2>&1; then lsof -t -i:"$PORT" | xargs -r kill 2>/dev/null; exit 0; fi
    if command -v ss >/dev/null 2>&1; then
        for pid in $(ss -lptn "sport = :$PORT" 2>/dev/null | grep -o 'pid=[0-9]*' | cut -d= -f2); do kill "$pid" 2>/dev/null; done
        exit 0
    fi
CLEANUP_SCRIPT
}

# --- Host Key Check ---
log_info "Security Check..."
ssh-keygen -l -f "$KNOWN_HOSTS_FILE" 2>/dev/null | grep "$TARGET_IP" || true
read -p "Continue? (yes/no): " C; [ "$C" != "yes" ] && exit 1

# --- Tunnel Loop ---
echo "=============================================="
echo "  Remote: $TARGET_USER@$TARGET_IP:$TARGET_PORT"
echo "  Version: $VERSION (Auto-Clean & Smart Auth)"
echo "=============================================="

while true; do
    log_info "Cleaning remote port $REVERSE_PORT..."
    # 1. Clean Port (Executes the Auto-Wipe)
    ssh $SSH_OPTS -p "$TARGET_PORT" -i "$KEY_PATH" "$TARGET_USER@$TARGET_IP" \
        "bash -s -- $REVERSE_PORT" <<< "$(get_cleanup_cmd)" 2>/dev/null || true
    
    sleep 1
    
    # 2. Start Tunnel
    log_info "Starting Tunnel..."
    ssh $SSH_OPTS \
        -N -R "0.0.0.0:$REVERSE_PORT:127.0.0.1:22" \
        -D "127.0.0.1:$SOCKS_PORT" \
        -o ServerAliveInterval=15 \
        -o ServerAliveCountMax=3 \
        -o ExitOnForwardFailure=yes \
        -p "$TARGET_PORT" \
        -i "$KEY_PATH" \
        "$TARGET_USER@$TARGET_IP" &
    
    SSH_PID=$!
    
    sleep 3
    if ! kill -0 "$SSH_PID" 2>/dev/null; then
        log_error "Tunnel failed immediately."
        log_warn "If you see 'remote port forwarding failed', the server port is stuck."
        log_warn "Wait 10s and retry..."
        sleep 10
        continue
    fi
    
    log_success "Tunnel Established (PID: $SSH_PID)"
    wait "$SSH_PID" 2>/dev/null
    log_warn "Disconnected. Reconnecting..."
    sleep 5
done
