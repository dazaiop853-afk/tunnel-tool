#!/bin/bash
set -e

# 1. Ensure root privileges
if [ "$EUID" -ne 0 ]; then
  echo "[!] Please run as root (sudo)"
  exit 1
fi

echo "[*] Updating package lists and installing dependencies..."
apt-get update -qq >/dev/null 2>&1 || yum check-update -q >/dev/null 2>&1 || true
apt-get install -y -qq curl wget iproute2 iptables libpcap-dev >/dev/null 2>&1 || \
yum install -y -q curl wget iproute iptables libpcap-devel >/dev/null 2>&1

# 2. Download latest paqet binary
echo "[*] Fetching the latest paqet release..."
LATEST_URL=$(curl -s https://api.github.com/repos/hanselime/paqet/releases/latest | grep "browser_download_url.*linux_amd64" | cut -d '"' -f 4)
if [ -z "$LATEST_URL" ]; then
    echo "[!] Failed to find latest release URL."
    exit 1
fi
curl -sL -o paqet "$LATEST_URL"
chmod +x paqet

# 3. Network Discovery
echo "[*] Discovering network configuration..."
PUBLIC_IP=$(curl -s --max-time 5 ifconfig.me || curl -s --max-time 5 api.ipify.org)
IFACE=$(ip route | awk '/default/ {print $5}' | head -n1)
LOCAL_IP=$(ip -4 addr show "$IFACE" | awk '/inet / {print $2}' | cut -d/ -f1 | head -n1)
GW_IP=$(ip route | awk '/default/ {print $3}' | head -n1)

# Ping gateway to populate ARP table, then extract MAC
ping -c 1 -W 1 "$GW_IP" >/dev/null 2>&1
GW_MAC=$(ip neigh show "$GW_IP" | grep -ioE '([a-f0-9]{2}:){5}[a-f0-9]{2}' | head -n1)

if [ -z "$GW_MAC" ]; then
    echo "[!] Could not resolve gateway MAC address for $GW_IP on $IFACE."
    exit 1
fi

PORT=$(shuf -i 10000-60000 -n 1)
SECRET=$(./paqet secret)

# 4. Generate Server Configuration
cat > server_config.yaml <<EOF
role: "server"
log:
  level: "info"
listen:
  addr: ":$PORT"
network:
  interface: "$IFACE"
  ipv4:
    addr: "$LOCAL_IP:$PORT"
    router_mac: "$GW_MAC"
transport:
  protocol: "kcp"
  kcp:
    mode: "fast3"
    mtu: 1350
    block: "aes-128-gcm"
    key: "$SECRET"
    dshard: 10
    pshard: 3
EOF

# 5. Output Client Configuration
echo ""
echo "=================================================================="
echo "🎯 SUCCESS: SERVER CONFIGURED. COPY THE CLIENT CONFIG BELOW:"
echo "=================================================================="
cat <<EOF
role: "client"
log:
  level: "info"
socks5:
  - listen: "127.0.0.1:1080"
network:
  interface: "REPLACE_WITH_CLIENT_INTERFACE"
  ipv4:
    addr: "REPLACE_WITH_CLIENT_LOCAL_IP:0"
    router_mac: "REPLACE_WITH_CLIENT_GATEWAY_MAC"
server:
  addr: "$PUBLIC_IP:$PORT"
transport:
  protocol: "kcp"
  kcp:
    mode: "fast3"
    mtu: 1350
    block: "aes-128-gcm"
    key: "$SECRET"
    dshard: 10
    pshard: 3
EOF
echo "=================================================================="
echo ""

# 6. Apply Firewall Rules & Setup Trap
echo "[*] Applying iptables bypass rules to hide from kernel tracking..."
iptables -t raw -A PREROUTING -p tcp --dport "$PORT" -j NOTRACK
iptables -t raw -A OUTPUT -p tcp --sport "$PORT" -j NOTRACK
iptables -t mangle -A OUTPUT -p tcp --sport "$PORT" --tcp-flags RST RST -j DROP

cleanup() {
    echo -e "\n[*] Caught exit signal. Cleaning up iptables rules..."
    iptables -t raw -D PREROUTING -p tcp --dport "$PORT" -j NOTRACK 2>/dev/null || true
    iptables -t raw -D OUTPUT -p tcp --sport "$PORT" -j NOTRACK 2>/dev/null || true
    iptables -t mangle -D OUTPUT -p tcp --sport "$PORT" --tcp-flags RST RST -j DROP 2>/dev/null || true
    echo "[*] Cleanup complete. Exiting."
    exit 0
}
trap cleanup SIGINT SIGTERM EXIT

# 7. Run Server
echo "[*] Starting paqet server in the foreground. Press Ctrl+C to stop."
./paqet run -c server_config.yaml
