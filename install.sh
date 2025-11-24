#!/bin/bash
#
# Installation Script for Penetration Testing Automation Tool
# Run with: sudo bash install.sh
#

set -e

echo "=========================================="
echo "Penetration Testing Automation Tool"
echo "Installation Script for Kali Linux"
echo "=========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "⚠️  This script should be run as root (use sudo)"
    echo "Some package installations require root privileges"
    echo ""
    read -p "Continue without root? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo "[1/5] Updating package lists..."
apt update || echo "⚠️  Could not update package lists (may require sudo)"

echo ""
echo "[2/5] Installing required tools..."

# Core penetration testing tools
TOOLS=(
    "nmap"
    "nikto"
    "gobuster"
    "whatweb"
    "sslscan"
    "dnsutils"
    "whois"
    "python3"
    "python3-tk"
)

MISSING_TOOLS=()

for tool in "${TOOLS[@]}"; do
    if dpkg -l | grep -q "^ii  $tool "; then
        echo "  ✓ $tool already installed"
    else
        echo "  → Installing $tool..."
        apt install -y "$tool" 2>/dev/null || MISSING_TOOLS+=("$tool")
    fi
done

if [ ${#MISSING_TOOLS[@]} -ne 0 ]; then
    echo ""
    echo "⚠️  Failed to install: ${MISSING_TOOLS[*]}"
    echo "You may need to install these manually:"
    echo "  sudo apt install ${MISSING_TOOLS[*]}"
fi

echo ""
echo "[3/5] Installing wordlists..."

# Check for wordlists
if [ ! -d "/usr/share/wordlists/dirb" ]; then
    echo "  → Installing dirb wordlists..."
    apt install -y dirb 2>/dev/null || echo "⚠️  Failed to install dirb"
else
    echo "  ✓ dirb wordlists already installed"
fi

if [ ! -d "/usr/share/wordlists/dirbuster" ]; then
    echo "  → Installing dirbuster wordlists..."
    apt install -y dirbuster 2>/dev/null || echo "⚠️  Failed to install dirbuster"
else
    echo "  ✓ dirbuster wordlists already installed"
fi

# Extract rockyou if needed
if [ -f "/usr/share/wordlists/rockyou.txt.gz" ] && [ ! -f "/usr/share/wordlists/rockyou.txt" ]; then
    echo "  → Extracting rockyou.txt..."
    gunzip /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || echo "⚠️  Could not extract rockyou.txt"
fi

echo ""
echo "[4/5] Setting up application..."

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
echo "  Installation directory: $SCRIPT_DIR"

# Make main script executable
chmod +x "$SCRIPT_DIR/pentest_automation.py"
echo "  ✓ Made pentest_automation.py executable"

# Create output directories
echo "  → Creating output directories..."
mkdir -p ~/pentest/{recon,web,proxmox,reports}
echo "  ✓ Created ~/pentest directory structure"

echo ""
echo "[5/5] Verifying installation..."

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | grep -oP '\d+\.\d+')
echo "  ✓ Python version: $PYTHON_VERSION"

# Verify tools
echo ""
echo "  Tool verification:"
for tool in nmap nikto gobuster whatweb sslscan dig whois; do
    if command -v "$tool" &> /dev/null; then
        echo "    ✓ $tool"
    else
        echo "    ✗ $tool (NOT FOUND)"
    fi
done

echo ""
echo "=========================================="
echo "✅ Installation Complete!"
echo "=========================================="
echo ""
echo "To run the tool:"
echo "  cd $SCRIPT_DIR"
echo "  python3 pentest_automation.py"
echo ""
echo "Or create a desktop launcher:"
echo "  $SCRIPT_DIR/create_launcher.sh"
echo ""
echo "⚠️  LEGAL WARNING:"
echo "Only use this tool on systems you own or have"
echo "explicit written permission to test."
echo ""
echo "For help and documentation, see README.md"
echo "=========================================="
