#!/bin/bash
#
# Create Desktop Launcher for Penetration Testing Automation Tool
#

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
DESKTOP_FILE="$HOME/Desktop/PentestTool.desktop"

echo "Creating desktop launcher..."

cat > "$DESKTOP_FILE" << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Pentest Automation Tool
Comment=Automated Penetration Testing Tool for Kali Linux
Exec=python3 $SCRIPT_DIR/pentest_automation.py
Icon=security-high
Terminal=false
Categories=Security;Network;
Keywords=pentest;security;hacking;nmap;nikto;
EOF

chmod +x "$DESKTOP_FILE"

echo "✓ Desktop launcher created: $DESKTOP_FILE"
echo ""
echo "You can now launch the tool from your desktop or applications menu."
