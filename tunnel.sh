#!/usr/bin/env bash
# ==============================================================================
# Persistent SSH Reverse Tunnel Manager v2.5.0
# ==============================================================================
set -u

VERSION="2.5.0"
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
    log_success "Keys created"
fi

check_reachability() {
    local ip=$1
    local port=$2
    local user=$3
    
    printf "Testing %s@%s:%s ... " "$user" "$ip" "$port"
    
    if ssh -o BatchMode=yes \
           -o ConnectTimeout=5 \
           -o StrictHostKeyChecking=yes \
           -o UserKnownHostsFile="$KNOWN_HOSTS_FILE" \
           -p "$port" \
           -i "$KEY_PATH" \
           "$user@$ip" exit 2>/dev/null; then
        echo -e "${GREEN}Authorized${NC}"
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
    
    if echo "$output" | grep -qE "Permission denied|publickey|password|keyboard-interactive"; then
        echo -e "${GREEN}Reachable${NC}"
        return 0
    fi
    
    echo -e "${RED}Unreachable${NC}"
    return 1
}

copy_ssh_id() {
    local user=$1
    local ip=$2
    local port=$3
    
    log_info "Transferring key to $user@$ip:$port"
    
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
}

if [ -f "$CONFIG_FILE" ]; then
    IFS=':' read -r SAVED_IP SAVED_PORT SAVED_USER < "$CONFIG_FILE"
    
    if check_reachability "$SAVED_IP" "$SAVED_PORT" "$SAVED_USER"; then
        TARGET_IP="$SAVED_IP"
        TARGET_PORT="$SAVED_PORT"
        TARGET_USER="$SAVED_USER"
        log_success "Using saved: $TARGET_USER@$TARGET_IP:$TARGET_PORT"
    else
        TARGET_IP=""
    fi
else
    TARGET_IP=""
fi

while [ -z "${TARGET_IP:-}" ]; do
    printf "Enter server IP: "
    read -r INPUT_IP
    
    if check_reachability "$INPUT_IP" "$TARGET_PORT" "$TARGET_USER"; then
        if copy_ssh_id "$TARGET_USER" "$INPUT_IP" "$TARGET_PORT"; then
            TARGET_IP="$INPUT_IP"
            echo "${TARGET_IP}:${TARGET_PORT}:${TARGET_USER}" > "$CONFIG_FILE"
            chmod 600 "$CONFIG_FILE"
            log_success "Configuration saved"
        fi
    fi
done

log_info "Verifying host key fingerprint..."
ssh-keygen -l -f "$KNOWN_HOSTS_FILE" 2>/dev/null | grep "$TARGET_IP" || true

printf "Continue? (yes/no): "
read -r CONFIRM

if [ "$CONFIRM" != "yes" ]; then
    exit 1
fi

echo ""
echo "=============================================="
echo "  Remote:        $TARGET_USER@$TARGET_IP:$TARGET_PORT"
echo "  Reverse Port:  127.0.0.1:$REVERSE_PORT"
echo "  SOCKS5:        127.0.0.1:$SOCKS_PORT"
echo "=============================================="
echo ""

# PRE-FLIGHT CHECKS
log_info "Running pre-flight diagnostics..."

log_info "1. Testing basic SSH connection..."
if ssh -o BatchMode=yes \
       -o ConnectTimeout=10 \
       -o StrictHostKeyChecking=yes \
       -o UserKnownHostsFile="$KNOWN_HOSTS_FILE" \
       -p "$TARGET_PORT" \
       -i "$KEY_PATH" \
       "$TARGET_USER@$TARGET_IP" "echo 'SSH OK'" 2>/dev/null; then
    log_success "SSH connection works"
else
    log_error "Basic SSH connection failed"
    exit 1
fi

log_info "2. Checking if port $REVERSE_PORT is available on remote..."
PORT_CHECK=$(ssh -o BatchMode=yes \
                 -o StrictHostKeyChecking=yes \
                 -o UserKnownHostsFile="$KNOWN_HOSTS_FILE" \
                 -p "$TARGET_PORT" \
                 -i "$KEY_PATH" \
                 "$TARGET_USER@$TARGET_IP" \
                 "netstat -ln 2>/dev/null | grep ':$REVERSE_PORT ' || ss -ln 2>/dev/null | grep ':$REVERSE_PORT ' || echo 'AVAILABLE'" 2>/dev/null)

if echo "$PORT_CHECK" | grep -q "AVAILABLE"; then
    log_success "Port $REVERSE_PORT is available"
elif echo "$PORT_CHECK" | grep -q ":$REVERSE_PORT"; then
    log_error "Port $REVERSE_PORT is ALREADY IN USE on remote server!"
    log_error "Output: $PORT_CHECK"
    log_info "Attempting to kill processes..."
    
    ssh -o BatchMode=yes \
        -o StrictHostKeyChecking=yes \
        -o UserKnownHostsFile="$KNOWN_HOSTS_FILE" \
        -p "$TARGET_PORT" \
        -i "$KEY_PATH" \
        "$TARGET_USER@$TARGET_IP" \
        "fuser -k $REVERSE_PORT/tcp 2>/dev/null || lsof -ti:$REVERSE_PORT | xargs kill -9 2>/dev/null || true" 2>/dev/null
    
    sleep 2
else
    log_warn "Could not determine port status (assuming available)"
fi

log_info "3. Checking GatewayPorts setting..."
GATEWAY_PORTS=$(ssh -o BatchMode=yes \
                    -o StrictHostKeyChecking=yes \
                    -o UserKnownHostsFile="$KNOWN_HOSTS_FILE" \
                    -p "$TARGET_PORT" \
                    -i "$KEY_PATH" \
                    "$TARGET_USER@$TARGET_IP" \
                    "grep -i '^GatewayPorts' /etc/ssh/sshd_config 2>/dev/null || echo 'NOT_SET'" 2>/dev/null)

log_debug "GatewayPorts config: $GATEWAY_PORTS"

if echo "$GATEWAY_PORTS" | grep -qi "yes\|clientspecified"; then
    log_success "GatewayPorts is enabled"
elif echo "$GATEWAY_PORTS" | grep -qi "NOT_SET"; then
    log_warn "GatewayPorts not explicitly set (defaults to 'no')"
    log_warn "Binding to 127.0.0.1 only (localhost)"
else
    log_warn "GatewayPorts may be disabled"
fi

log_info "4. Testing reverse tunnel with verbose output..."
log_warn "Starting SSH with -v flag for 10 seconds..."

VERBOSE_LOG=$(mktemp)
timeout 10 ssh -v -N \
    -R "127.0.0.1:$REVERSE_PORT:127.0.0.1:22" \
    -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile="$KNOWN_HOSTS_FILE" \
    -p "$TARGET_PORT" \
    -i "$KEY_PATH" \
    "$TARGET_USER@$TARGET_IP" > "$VERBOSE_LOG" 2>&1 || true

echo ""
echo "========== SSH VERBOSE OUTPUT =========="
cat "$VERBOSE_LOG"
echo "========================================"
echo ""

if grep -qi "remote port forwarding failed\|cannot listen to port\|bind.*failed" "$VERBOSE_LOG"; then
    log_error "Port binding failed on remote server!"
    log_error "Possible causes:"
    log_error "  1. Port $REVERSE_PORT already in use"
    log_error "  2. GatewayPorts disabled (edit /etc/ssh/sshd_config)"
    log_error "  3. Firewall blocking the port"
    rm -f "$VERBOSE_LOG"
    exit 1
fi

if grep -qi "forwarding.*bound" "$VERBOSE_LOG"; then
    log_success "Tunnel CAN be established!"
else
    log_warn "Could not confirm tunnel establishment from logs"
fi

rm -f "$VERBOSE_LOG"

log_info "Diagnostics complete. Starting persistent tunnel..."
sleep 2

RETRY_COUNT=0
MAX_RETRIES=10

while true; do
    log_info "Establishing tunnel (attempt $((RETRY_COUNT + 1))/$MAX_RETRIES)..."
    
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
    
    sleep 5
    
    if ! kill -0 "$SSH_PID" 2>/dev/null; then
        RETRY_COUNT=$((RETRY_COUNT + 1))
        log_error "Tunnel failed (PID $SSH_PID died)"
        
        if [ "$RETRY_COUNT" -ge "$MAX_RETRIES" ]; then
            log_error "Max retries reached. Exiting."
            exit 1
        fi
        
        log_warn "Retrying in 10 seconds..."
        sleep 10
        continue
    fi
    
    log_success "Tunnel established (PID: $SSH_PID)"
    RETRY_COUNT=0
    
    wait "$SSH_PID" 2>/dev/null || true
    
    log_warn "Tunnel disconnected. Reconnecting in 5 seconds..."
    sleep 5
done
