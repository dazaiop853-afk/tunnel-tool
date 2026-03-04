#!/bin/bash
# Exit on any error, but print commands as they run so we can see what's happening
set -e

echo "[*] Ensuring root privileges..."
if [ "$EUID" -ne 0 ]; then
  echo "[!] Please run as root (sudo)"
  exit 1
fi

echo "[*] Updating package lists and installing dependencies..."
if command -v apt-get >/dev/null; then
    apt-get update
    apt-get install -y curl wget iproute2 iptables libpcap-dev tar
elif command -v yum >/dev/null; then
    yum check-update || true
    yum install -y curl wget iproute iptables libpcap-devel tar
else
    echo "[!] Unsupported package manager. Need apt or yum."
    exit 1
fi

echo "[*] Fetching the latest paqet release URL..."
# Query all releases (because alphas don't show in /latest), search for linux-amd64 and .tar.gz
LATEST_URL=$(curl -s https://api.github.com/repos/hanselime/paqet/releases | grep "browser_download_url.*linux-amd64.*\.tar\.gz" | head -n 1 | cut -d '"' -f 4)

if [ -z "$LATEST_URL" ]; then
    echo "[!] Failed to find release URL. Here is what GitHub returned for browser_download_urls:"
    curl -s https://api.github.com/repos/hanselime/paqet/releases | grep "browser_download_url" || echo "No URLs found at all."
    exit 1
fi

echo "[*] Found URL: $LATEST_URL"
echo "[*] Downloading archive..."
wget -O paqet.tar.gz "$LATEST_URL"

echo "[*] Extracting archive..."
# -v makes tar verbose so we can see exactly what files come out
tar -xzvf paqet.tar.gz

# If the binary extracts with a different name, let's ensure it's just called 'paqet'
if [ -f "paqet-linux-amd64" ]; then
    mv paqet-linux-amd64 paqet
fi
chmod +x paqet

echo "[*] Discovering network configuration..."
PUBLIC_IP=$(curl -s --max-time 5 ifconfig.me || curl -s --max-time 5 api.ipify.org)
IFACE=$(ip route | awk '/default/ {print $5}' | head -n1)
LOCAL_IP=$(ip -4 addr show "$IFACE" | awk '/inet / {print $2}' | cut -d/ -f1 | head -n1)
GW_IP=$(ip route | awk '/default/ {print $3}' | head -n1)

echo "[*] IFACE: $IFACE | LOCAL IP: $LOCAL_IP | GATEWAY: $GW_IP"

echo "[*] Pinging gateway to populate ARP table..."
ping -c 1 -W 1 "$GW_IP" || true
GW_MAC=$(ip neigh show "$GW_IP" | grep -ioE '([a-f0-9]{2}:){5}[a-f0-9]{2}' | head -n1)

if [ -z "$GW_MAC" ]; then
    echo "[!] Could not resolve gateway MAC address. Dumping ARP table for debugging:"
    ip neigh show
    exit 1
fi
echo "[*] Gateway MAC resolved to: $GW_MAC"

PORT=$(shuf -i 10000-60000 -n 1)
SECRET=$(./paqet secret)

echo "[*] Generating server_config.yaml..."
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

echo "[*] Starting paqet server. Press Ctrl+C to safely stop."
./paqet run -c server_config.yaml
