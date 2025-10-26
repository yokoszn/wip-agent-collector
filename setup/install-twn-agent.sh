#!/bin/bash
# install-twn-agent.sh - Simple installer for TWN agent

set -e

echo "================================================"
echo "  TWN Agent Installer"
echo "  Linux-first eBPF endpoint monitoring"
echo "================================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "❌ Please run as root (sudo)"
    exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo "❌ Cannot detect OS"
    exit 1
fi

echo "✅ Detected OS: $OS"
echo ""

# ============================================
# CONFIGURATION - Ask for backend services
# ============================================

echo "📝 Backend Service Configuration"
echo "================================"
echo ""

# WireGuard VPN
read -p "WireGuard server endpoint (IP:PORT): " WG_SERVER
read -p "WireGuard server public key: " WG_PUBKEY
read -p "WireGuard client IP (e.g., 10.8.0.2/32): " WG_CLIENT_IP

echo ""

# MeshCentral
read -p "MeshCentral server URL (wss://mesh.example.com): " MESH_URL

echo ""

# SigNoz/OTel
read -p "OTel/SigNoz endpoint (otel.example.com:4317): " OTEL_ENDPOINT

echo ""

# Optional: Wazuh
read -p "Wazuh manager (leave empty to skip): " WAZUH_MANAGER

echo ""
echo "================================================"
echo "  Configuration Summary"
echo "================================================"
echo "WireGuard Server: $WG_SERVER"
echo "WireGuard Client IP: $WG_CLIENT_IP"
echo "MeshCentral: $MESH_URL"
echo "OTel Endpoint: $OTEL_ENDPOINT"
if [ ! -z "$WAZUH_MANAGER" ]; then
    echo "Wazuh Manager: $WAZUH_MANAGER"
fi
echo ""
read -p "Continue with installation? (y/n): " CONFIRM

if [ "$CONFIRM" != "y" ]; then
    echo "❌ Installation cancelled"
    exit 0
fi

echo ""
echo "🚀 Starting installation..."
echo ""

# ============================================
# INSTALL DEPENDENCIES
# ============================================

echo "📦 Installing dependencies..."

if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
    apt-get update
    apt-get install -y \
        curl \
        wireguard \
        wireguard-tools \
        clang \
        llvm \
        libelf-dev \
        linux-headers-$(uname -r) \
        build-essential \
        xrdp \
        x11vnc \
        jq
        
elif [ "$OS" = "rhel" ] || [ "$OS" = "centos" ] || [ "$OS" = "fedora" ]; then
    dnf install -y \
        curl \
        wireguard-tools \
        clang \
        llvm \
        elfutils-libelf-devel \
        kernel-headers-$(uname -r) \
        xrdp \
        x11vnc \
        jq
else
    echo "⚠️  Unsupported OS. Please install dependencies manually."
fi

echo "✅ Dependencies installed"
echo ""

# ============================================
# WIREGUARD SETUP
# ============================================

echo "🔐 Setting up WireGuard..."

# Generate client keys if they don't exist
if [ ! -f /etc/wireguard/privatekey ]; then
    wg genkey | tee /etc/wireguard/privatekey | wg pubkey > /etc/wireguard/publickey
fi

WG_PRIVATE_KEY=$(cat /etc/wireguard/privatekey)
WG_CLIENT_PUBKEY=$(cat /etc/wireguard/publickey)

echo ""
echo "🔑 Your WireGuard public key (add this to server):"
echo "$WG_CLIENT_PUBKEY"
echo ""
read -p "Press Enter after adding this key to your WireGuard server..."

# Create WireGuard config
cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
PrivateKey = $WG_PRIVATE_KEY
Address = $WG_CLIENT_IP
DNS = 1.1.1.1, 8.8.8.8

# Monitoring traffic routes through tunnel
PostUp = ip rule add to 10.8.0.0/16 table 88
PostUp = ip route add 10.8.0.0/16 dev %i table 88
PreDown = ip rule del to 10.8.0.0/16 table 88
PreDown = ip route del 10.8.0.0/16 dev %i table 88

[Peer]
PublicKey = $WG_PUBKEY
Endpoint = $WG_SERVER
AllowedIPs = 10.8.0.0/16
PersistentKeepalive = 25
EOF

chmod 600 /etc/wireguard/wg0.conf

# Enable and start WireGuard
systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0

# Test connection
if ping -c 1 -W 2 ${WG_CLIENT_IP%%/*} &> /dev/null; then
    echo "✅ WireGuard connected"
else
    echo "⚠️  WireGuard started but connectivity test failed"
    echo "   Check server configuration"
fi

echo ""

# ============================================
# DOWNLOAD TWN AGENT BINARY
# ============================================

echo "📥 Downloading TWN agent..."

# Create directories
mkdir -p /opt/twn-agent
mkdir -p /etc/twn-agent
mkdir -p /var/lib/twn-agent
mkdir -p /var/log/twn-agent

# Download binary (or copy from local build)
if [ -f "./target/release/twn-agent" ]; then
    echo "📦 Using local build"
    cp ./target/release/twn-agent /opt/twn-agent/twn-agent
else
    echo "📦 Downloading from releases..."
    # TODO: Replace with your actual release URL
    # curl -L https://releases.twn.company.com/twn-agent-latest-linux-amd64 \
    #     -o /opt/twn-agent/twn-agent
    
    echo "⚠️  Binary download not yet available"
    echo "   Please build locally: cd twn-agent && cargo build --release"
    exit 1
fi

chmod +x /opt/twn-agent/twn-agent

echo "✅ Agent binary installed"
echo ""

# ============================================
# CONFIGURE AGENT
# ============================================

echo "⚙️  Configuring agent..."

# Generate agent ID from machine-id
AGENT_ID=$(cat /etc/machine-id)

# Create configuration file
cat > /etc/twn-agent/config.yaml <<EOF
# TWN Agent Configuration
agent:
  id: "$AGENT_ID"
  hostname: "$(hostname)"
  tags:
    - "$(hostname)"
    - "$OS"

# Control plane (gRPC)
control_plane:
  # Use WireGuard tunnel for control
  endpoint: "10.8.0.1:50051"  # Adjust if your control plane uses different IP
  tls_enabled: true
  tls_ca: "/etc/twn-agent/certs/ca.pem"
  tls_cert: "/etc/twn-agent/certs/client.pem"
  tls_key: "/etc/twn-agent/certs/client-key.pem"
  
# WireGuard (managed by systemd)
wireguard:
  interface: "wg0"
  auto_isolation: true  # Auto-isolate on critical threats

# MeshCentral integration
meshcentral:
  enabled: true
  url: "$MESH_URL"
  device_group: "default"
  auto_install: false  # Install MeshCentral agent separately

# OpenTelemetry / SigNoz
otel:
  endpoint: "$OTEL_ENDPOINT"
  insecure: false
  compression: "gzip"
  batch_timeout: "10s"
  
# Wazuh integration (optional)
wazuh:
  enabled: $([ ! -z "$WAZUH_MANAGER" ] && echo "true" || echo "false")
  manager: "$WAZUH_MANAGER"

# eBPF monitoring
ebpf:
  enabled: true
  programs:
    - process_monitor
    - network_monitor
    - file_monitor
  
# Remote access
remote:
  rdp_enabled: true
  rdp_port: 3389
  vnc_enabled: true
  vnc_port: 5900
  ssh_enabled: true

# Logging
logging:
  level: "info"
  file: "/var/log/twn-agent/agent.log"
  max_size: "100MB"
  max_backups: 5
EOF

echo "✅ Configuration created"
echo ""

# ============================================
# INSTALL SYSTEMD SERVICE
# ============================================

echo "🔧 Installing systemd service..."

cat > /etc/systemd/system/twn-agent.service <<EOF
[Unit]
Description=TWN Security Agent
Documentation=https://github.com/yourusername/twn-agent
After=network.target wg-quick@wg0.service
Wants=wg-quick@wg0.service

[Service]
Type=simple
User=root
Group=root
ExecStart=/opt/twn-agent/twn-agent --config /etc/twn-agent/config.yaml
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/twn-agent /var/log/twn-agent
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_NET_ADMIN CAP_SYS_RESOURCE

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable twn-agent

echo "✅ Systemd service installed"
echo ""

# ============================================
# OPTIONAL: INSTALL MESHCENTRAL AGENT
# ============================================

if [ "$MESH_URL" != "" ]; then
    echo "📱 MeshCentral Agent Setup"
    echo "=========================="
    echo ""
    echo "To install MeshCentral agent:"
    echo "1. Go to: $MESH_URL"
    echo "2. Login to your admin panel"
    echo "3. Add new device group (if needed)"
    echo "4. Download the Linux agent installer"
    echo "5. Run: wget <mesh-agent-url> -O meshagent && chmod +x meshagent && ./meshagent -install"
    echo ""
    read -p "Install MeshCentral agent now? (y/n): " INSTALL_MESH
    
    if [ "$INSTALL_MESH" = "y" ]; then
        read -p "Paste the MeshCentral agent download URL: " MESH_AGENT_URL
        
        if [ ! -z "$MESH_AGENT_URL" ]; then
            wget "$MESH_AGENT_URL" -O /tmp/meshagent
            chmod +x /tmp/meshagent
            /tmp/meshagent -install
            echo "✅ MeshCentral agent installed"
        fi
    fi
    echo ""
fi

# ============================================
# OPTIONAL: INSTALL WAZUH AGENT
# ============================================

if [ ! -z "$WAZUH_MANAGER" ]; then
    echo "🔐 Wazuh Agent Setup"
    echo "==================="
    echo ""
    read -p "Install Wazuh agent? (y/n): " INSTALL_WAZUH
    
    if [ "$INSTALL_WAZUH" = "y" ]; then
        read -p "Wazuh registration password: " WAZUH_PASSWORD
        
        if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
            curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
            echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
            apt-get update
            WAZUH_MANAGER="$WAZUH_MANAGER" WAZUH_REGISTRATION_PASSWORD="$WAZUH_PASSWORD" apt-get install -y wazuh-agent
        elif [ "$OS" = "rhel" ] || [ "$OS" = "centos" ] || [ "$OS" = "fedora" ]; then
            rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
            cat > /etc/yum.repos.d/wazuh.repo <<WAZUH_REPO
[wazuh]
name=Wazuh repository
baseurl=https://packages.wazuh.com/4.x/yum/
enabled=1
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
WAZUH_REPO
            WAZUH_MANAGER="$WAZUH_MANAGER" WAZUH_REGISTRATION_PASSWORD="$WAZUH_PASSWORD" dnf install -y wazuh-agent
        fi
        
        systemctl enable wazuh-agent
        systemctl start wazuh-agent
        echo "✅ Wazuh agent installed"
    fi
    echo ""
fi

# ============================================
# START AGENT
# ============================================

echo "🚀 Starting TWN agent..."
systemctl start twn-agent

# Wait a moment for startup
sleep 2

# Check status
if systemctl is-active --quiet twn-agent; then
    echo "✅ TWN agent is running"
else
    echo "❌ TWN agent failed to start"
    echo "   Check logs: journalctl -u twn-agent -f"
    exit 1
fi

echo ""

# ============================================
# SUMMARY
# ============================================

echo "================================================"
echo "  ✅ TWN Agent Installation Complete!"
echo "================================================"
echo ""
echo "Configuration:"
echo "  • Agent ID: $AGENT_ID"
echo "  • Hostname: $(hostname)"
echo "  • WireGuard: wg0 ($WG_CLIENT_IP)"
echo "  • OTel Endpoint: $OTEL_ENDPOINT"
if [ ! -z "$WAZUH_MANAGER" ]; then
    echo "  • Wazuh Manager: $WAZUH_MANAGER"
fi
echo ""
echo "Services:"
echo "  • TWN Agent: systemctl status twn-agent"
echo "  • WireGuard: systemctl status wg-quick@wg0"
if [ ! -z "$WAZUH_MANAGER" ]; then
    echo "  • Wazuh Agent: systemctl status wazuh-agent"
fi
echo ""
echo "Logs:"
echo "  • Agent: journalctl -u twn-agent -f"
echo "  • Config: /etc/twn-agent/config.yaml"
echo "  • Data: /var/lib/twn-agent/"
echo ""
echo "Remote Access:"
echo "  • RDP: Port 3389 (on-demand via control plane)"
echo "  • VNC: Port 5900 (on-demand via control plane)"
echo "  • SSH: Standard port 22"
echo ""
echo "Next Steps:"
echo "  1. Verify connectivity: wg show"
echo "  2. Check agent status: systemctl status twn-agent"
echo "  3. View telemetry in SigNoz dashboard"
echo "  4. Send test command from control plane"
echo ""
echo "================================================"
echo ""
echo "🎉 Your endpoint is now monitored and manageable!"
echo ""
