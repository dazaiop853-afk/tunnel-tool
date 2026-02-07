#!/usr/bin/env bash
# ==============================================================================
# Persistent SSH Reverse Tunnel Manager v2.4.0
# ==============================================================================
set -u

VERSION="2.4.0"
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
log_debug() { echo -e "${BLUE}[DEBUG]${NC} $*"; }

cleanup_on_exit() {
    log_info "Cleaning up..."
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

self_update() {
    log_info "Checking for updates..."
    TMP_FILE=$(mktemp)
    
    if command -v curl >/dev/null 2>&1; then
        HTTP_CODE=$(curl -sL -w "%{http_code}" "$UPDATE_URL" -o "$TMP_FILE" 2>/dev/null || echo "000")
    elif command -v wget >/dev/null 2>&1; then
        if wget -qO "$TMP_FILE" "$UPDATE_URL" 2>/dev/null; then
            HTTP_CODE=200
        else
            HTTP_CODE=000
        fi
    else
        log_error "curl or wget required"
        rm -f "$TMP_FILE"
        exit 1
    fi
    
    if [ "$HTTP_CODE" != "200" ] || [ ! -s "$TMP_FILE" ]; then
        log_error "Download failed (HTTP: $HTTP_CODE)"
        rm -f "$TMP_FILE"
        exit 1
    fi
    
    if ! bash -n "$TMP_FILE" 2>/dev/null; then
        log_error "Invalid bash syntax in update"
        rm -f "$TMP_FILE"
        exit 1
    fi
    
    REMOTE_VERSION=$(grep '^VERSION=' "$TMP_FILE" | head -n1 | cut -d'"' -f2)
    log_info "Remote version: $REMOTE_VERSION | Current: $VERSION"
    
    mv "$TMP_FILE" "${BASH_SOURCE[0]}"
    chmod +x "${BASH_SOURCE[0]}"
    log_success "Updated. Restarting..."
    exec "${BASH_SOURCE[0]}" "${@:2}"
}

if [ "${1:-}" = "--update" ]; then
    self_update "$@"
fi

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
    log_info "Cleaning configuration..."
    rm -f "$CONFIG_FILE" "$KNOWN_HOSTS_FILE"
    log_success "Done"
    exit 0
fi

if [ ! -f "$KEY_PATH" ]; then
    log_info "Generating SSH keys..."
    mkdir -p "$KEY_DIR" && chmod 700 "$KEY_DIR"
    ssh-keygen -t ed25519 -f "$KEY_PATH" -N "" -C "tunnel-$(date +%Y%m%d)" -q
    log_success "Keys created at $KEY_PATH"
fi

check_reachability() {
    local ip=$1
    local port=$2
    local user=$3
    
    log_debug "Checking reachability: $user@$ip:$port"
    
    if ssh -o BatchMode=yes \
           -o ConnectTimeout=5 \
           -o StrictHostKeyChecking=yes \
           -o UserKnownHostsFile="$KNOWN_HOSTS_FILE" \
           -p "$port" \
           -i "$KEY_PATH" \
           "$user@$ip" exit 2>/dev/null; then
        log_debug "Server authorized (key already installed)"
        return 0
    fi
    
    local output
    output=$(ssh -o PubkeyAuthentication=no \
                 -o PreferredAuthentications=password,keyboard-interactive \
                 -o ConnectTimeout=5 \
                 -o StrictHostKeyChecking=accept-new \
                 -o UserKnownHostsFile="$KNOWN_HOSTS_FILE" \
                 -o NumberOfPasswordPrompts=0 \
                 -o BatchMode=yes \
                 -p "$port" \
                 "$user@$ip" exit 2>&1) || true
    
    log_debug "SSH probe output: $output"
    
    if echo "$output" | grep -qE "Permission denied|publickey|password|keyboard-interactive"; then
        log_debug "Server reachable but needs authentication"
        return 0
    fi
    
    log_debug "Server unreachable or connection failed"
    return 1
}

copy_ssh_id() {
    local user=$1
    local ip=$2
    local port=$3
    
    log_info "Transferring public key to $user@$ip:$port"
    log_warn "You will be prompted for password"
    
    if command -v ssh-copy-id >/dev/null 2>&1; then
        ssh-copy-id -i "${KEY_PATH}.pub" \
                    -p "$port" \
                    -o StrictHostKeyChecking=accept-new \
                    -o UserKnownHostsFile="$KNOWN_HOSTS_FILE" \
                    "$user@$ip"
    else
        cat "${KEY_PATH}.pub" | ssh -p "$port" \
                                    -o StrictHostKeyChecking=accept-new \
                                    -o UserKnownHostsFile="$KNOWN_HOSTS_FILE" \
                                    "$user@$ip" \
                                    "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
    fi
    
    return $?
}

if [ -f "$CONFIG_FILE" ]; then
    log_debug "Loading saved configuration from $CONFIG_FILE"
    IFS=':' read -r SAVED_IP SAVED_PORT SAVED_USER < "$CONFIG_FILE"
    log_debug "Saved: $SAVED_USER@$SAVED_IP:$SAVED_PORT"
    
    if check_reachability "$SAVED_IP" "$SAVED_PORT" "$SAVED_USER"; then
        TARGET_IP="$SAVED_IP"
        TARGET_PORT="$SAVED_PORT"
        TARGET_USER="$SAVED_USER"
        log_success "Using saved server: $TARGET_USER@$TARGET_IP:$TARGET_PORT"
    else
        log_warn "Saved server unreachable"
        TARGET_IP=""
    fi
else
    log_debug "No saved configuration found"
    TARGET_IP=""
fi

while [ -z "${TARGET_IP:-}" ]; do
    printf "Enter server IP: "
    read -r INPUT_IP
    
    log_debug "User entered IP: $INPUT_IP"
    
    if ! echo "$INPUT_IP" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$|^[a-zA-Z0-9.-]+$'; then
        log_error "Invalid IP/hostname format"
        continue
    fi
    
    if check_reachability "$INPUT_IP" "$TARGET_PORT" "$TARGET_USER"; then
        log_info "Server is reachable"
        
        if copy_ssh_id "$TARGET_USER" "$INPUT_IP" "$TARGET_PORT"; then
            TARGET_IP="$INPUT_IP"
            echo "${TARGET_IP}:${TARGET_PORT}:${TARGET_USER}" > "$CONFIG_FILE"
            chmod 600 "$CONFIG_FILE"
            log_success "Configuration saved"
        else
            log_error "Key transfer failed"
        fi
    else
        log_error "Server unreachable. Try again."
    fi
done

log_info "Verifying host key fingerprint..."
ssh-keygen -l -f "$KNOWN_HOSTS_FILE" 2>/dev/null | grep "$TARGET_IP" || log_warn "No fingerprint found"

printf "Continue with this host key? (yes/no): "
read -r CONFIRM

if [ "$CONFIRM" != "yes" ]; then
    log_error "Host key verification rejected"
    exit 1
fi

log_success "Starting persistent reverse tunnel"
echo ""
echo "=============================================="
echo "  Remote:        $TARGET_USER@$TARGET_IP:$TARGET_PORT"
echo "  Reverse Port:  127.0.0.1:$REVERSE_PORT (on remote)"
echo "  SOCKS5 Port:   127.0.0.1:$SOCKS_PORT (local)"
echo "  Ctrl+C to stop"
echo "=============================================="
echo ""

RETRY_COUNT=0
MAX_RETRIES=10

while true; do
    log_debug "Cleaning remote port $REVERSE_PORT..."
    
    CLEANUP_SCRIPT='
PORT=$1
log() { echo "[CLEANUP] $*"; }

log "Attempting to free port $PORT"

if command -v fuser >/dev/null 2>&1; then
    log "Using fuser..."
    fuser -k -n tcp "$PORT" 2>/dev/null
    log "fuser completed"
    exit 0
fi

if command -v lsof >/dev/null 2>&1; then
    log "Using lsof..."
    PIDS=$(lsof -t -i:"$PORT" 2>/dev/null)
    if [ -n "$PIDS" ]; then
        echo "$PIDS" | while read -r pid; do
            log "Killing PID: $pid"
            kill "$pid" 2>/dev/null
        done
    fi
    log "lsof completed"
    exit 0
fi

if command -v ss >/dev/null 2>&1; then
    log "Using ss..."
    PIDS=$(ss -lptn "sport = :$PORT" 2>/dev/null | grep -o "pid=[0-9]*" | cut -d= -f2)
    if [ -n "$PIDS" ]; then
        echo "$PIDS" | while read -r pid; do
            log "Killing PID: $pid"
            kill "$pid" 2>/dev/null
        done
    fi
    log "ss completed"
    exit 0
fi

if command -v netstat >/dev/null 2>&1; then
    log "Using netstat..."
    PIDS=$(netstat -lnp 2>/dev/null | grep ":$PORT " | awk "{print \$7}" | cut -d/ -f1)
    if [ -n "$PIDS" ]; then
        echo "$PIDS" | while read -r pid; do
            [ -n "$pid" ] && log "Killing PID: $pid" && kill "$pid" 2>/dev/null
        done
    fi
    log "netstat completed"
    exit 0
fi

log "No cleanup tools available"
'
    
    ssh -o BatchMode=yes \
        -o ConnectTimeout=10 \
        -o StrictHostKeyChecking=yes \
        -o UserKnownHostsFile="$KNOWN_HOSTS_FILE" \
        -p "$TARGET_PORT" \
        -i "$KEY_PATH" \
        "$TARGET_USER@$TARGET_IP" \
        "bash -s -- $REVERSE_PORT" <<< "$CLEANUP_SCRIPT" 2>&1 | while read -r line; do
            log_debug "Remote cleanup: $line"
        done
    
    sleep 2
    
    log_info "Establishing tunnel (attempt $((RETRY_COUNT + 1))/$MAX_RETRIES)..."
    log_debug "Command: ssh -N -R 127.0.0.1:$REVERSE_PORT:127.0.0.1:22 -D 127.0.0.1:$SOCKS_PORT"
    
    ssh -N \
        -R "127.0.0.1:$REVERSE_PORT:127.0.0.1:22" \
        -D "127.0.0.1:$SOCKS_PORT" \
        -o ServerAliveInterval=15 \
        -o ServerAliveCountMax=3 \
        -o ExitOnForwardFailure=yes \
        -o StrictHostKeyChecking=yes \
        -o UserKnownHostsFile="$KNOWN_HOSTS_FILE" \
        -o TCPKeepAlive=yes \
        -p "$TARGET_PORT" \
        -i "$KEY_PATH" \
        "$TARGET_USER@$TARGET_IP" &
    
    SSH_PID=$!
    log_debug "SSH tunnel started with PID: $SSH_PID"
    
    sleep 5
    
    if ! kill -0 "$SSH_PID" 2>/dev/null; then
        RETRY_COUNT=$((RETRY_COUNT + 1))
        log_error "Tunnel process died immediately (PID $SSH_PID no longer exists)"
        
        if [ "$RETRY_COUNT" -ge "$MAX_RETRIES" ]; then
            log_error "Max retries ($MAX_RETRIES) reached. Giving up."
            log_error "Possible causes:"
            log_error "  1. Port $REVERSE_PORT already in use on remote"
            log_error "  2. GatewayPorts disabled in sshd_config"
            log_error "  3. Network connectivity issues"
            exit 1
        fi
        
        log_warn "Retrying in 10 seconds... ($RETRY_COUNT/$MAX_RETRIES)"
        sleep 10
        continue
    fi
    
    log_success "Tunnel established successfully (PID: $SSH_PID)"
    RETRY_COUNT=0
    
    wait "$SSH_PID" 2>/dev/null || {
        EXIT_CODE=$?
        log_debug "SSH process exited with code: $EXIT_CODE"
    }
    
    log_warn "Tunnel disconnected. Reconnecting in 5 seconds..."
    sleep 5
done
