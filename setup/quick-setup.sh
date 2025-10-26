#!/bin/bash
# quick-setup.sh - Non-interactive setup with defaults

set -e

# Default configuration (edit these)
export WG_SERVER="vpn.twn.company.com:51820"
export WG_PUBKEY="YOUR_SERVER_PUBLIC_KEY_HERE"
export WG_CLIENT_IP="10.8.0.2/32"
export MESH_URL="wss://mesh.twn.company.com"
export OTEL_ENDPOINT="otel.twn.company.com:4317"
export WAZUH_MANAGER=""  # Leave empty to skip

# Generate WireGuard keys
wg genkey | tee /etc/wireguard/privatekey | wg pubkey > /etc/wireguard/publickey
WG_PRIVATE_KEY=$(cat /etc/wireguard/privatekey)

# Install
apt-get update
apt-get install -y wireguard curl jq

# Configure WireGuard
cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
PrivateKey = $WG_PRIVATE_KEY
Address = $WG_CLIENT_IP

[Peer]
PublicKey = $WG_PUBKEY
Endpoint = $WG_SERVER
AllowedIPs = 10.8.0.0/16
PersistentKeepalive = 25
EOF

# Start WireGuard
systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0

echo "✅ Quick setup complete!"
echo "🔑 Your public key: $(cat /etc/wireguard/publickey)"
echo "   Add this to your WireGuard server"
