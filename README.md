# Penetration Testing Automation Tool

A comprehensive GUI-based penetration testing automation tool for Kali Linux that streamlines reconnaissance, web application testing, and Proxmox server security assessment.

![Version](https://img.shields.io/badge/version-1.0-blue)
![Platform](https://img.shields.io/badge/platform-Kali%20Linux-red)
![Python](https://img.shields.io/badge/python-3.8%2B-green)
![License](https://img.shields.io/badge/license-Educational%20Use-orange)

---

## ⚠️ LEGAL WARNING

**THIS TOOL IS FOR AUTHORIZED TESTING ONLY**

- Only use on systems you own or have explicit written permission to test
- Unauthorized access to computer systems is ILLEGAL
- Users are responsible for complying with all applicable laws
- The developers assume NO liability for misuse

---

## Features

### 🔍 Reconnaissance
- **Quick Nmap Scan** - Fast scan of common ports (1-1000)
- **Full Nmap Scan** - Comprehensive scan of all 65535 ports with vulnerability scripts
- **UDP Scan** - Top 100 UDP ports
- **DNS Enumeration** - DNS record lookups and zone transfer attempts
- **WHOIS Lookup** - Domain and IP registration information

### 🌐 Web Application Testing
- **WhatWeb** - Technology fingerprinting and version detection
- **Nikto** - Web vulnerability scanning
- **Gobuster** - Directory and file enumeration
- **SSLScan** - SSL/TLS configuration testing

### 🖥️ Proxmox Server Testing
- **Port Scanning** - Proxmox-specific ports (22, 111, 8006, VNC ranges)
- **Web Interface Testing** - Security assessment of Proxmox web GUI

### 📊 Reporting
- **Automated Report Generation** - Comprehensive markdown reports
- **Parsed Findings** - Extracted vulnerabilities, open ports, and technologies
- **Timestamped Outputs** - All scan results saved with timestamps
- **Organized File Structure** - Separate directories for different test types

---

## Installation

### Prerequisites

**Operating System:**
- Kali Linux (recommended) or any Debian-based Linux distribution
- Python 3.8 or higher (pre-installed on Kali)

**Required Tools:**

Most tools are pre-installed on Kali Linux. If needed, install with:

```bash
sudo apt update
sudo apt install -y nmap nikto gobuster whatweb sslscan dnsutils whois python3-tk
```

### Setup

1. **Clone or Download the Tool:**

```bash
cd /opt
sudo git clone <repository-url> pentest-tool
# OR if you have the files:
sudo mkdir /opt/pentest-tool
sudo cp -r /path/to/files/* /opt/pentest-tool/
```

2. **Set Permissions:**

```bash
sudo chmod +x /opt/pentest-tool/pentest_automation.py
```

3. **Install Python Dependencies (if any):**

```bash
cd /opt/pentest-tool
pip3 install -r requirements.txt
```

4. **Verify Tool Installation:**

Run the tool and click "Check Tools" to verify all required tools are installed.

---

## Usage

### Starting the Application

```bash
cd /opt/pentest-tool
python3 pentest_automation.py
```

Or make it executable:

```bash
chmod +x pentest_automation.py
./pentest_automation.py
```

### Quick Start Guide

1. **Enter Target**
   - Enter target IP address or domain name
   - Examples: `192.168.1.100`, `example.com`, `proxmox.local`

2. **Select Scan Preset**
   - **Quick Scan** - Fast reconnaissance and basic tests (~5-10 minutes)
   - **Full Scan** - Comprehensive testing (~30-60 minutes)
   - **Web Application Focus** - Web-specific tests
   - **Proxmox Server Focus** - Proxmox-specific tests
   - **Custom Selection** - Choose individual tests

3. **Start Scan**
   - Click "▶ Start Scan"
   - Confirm authorization
   - Monitor progress in real-time

4. **Generate Report**
   - After scan completes, click "📄 Generate Report"
   - Report saved to `~/pentest/reports/`

---

## File Structure

### Application Files

```
pentest_tool/
├── pentest_automation.py    # Main GUI application
├── scanner_engine.py         # Backend scanning engine
├── report_generator.py       # Report generation module
├── config.py                 # Configuration and settings
├── requirements.txt          # Python dependencies
└── README.md                 # This file
```

### Output Directory Structure

```
~/pentest/
├── recon/                    # Reconnaissance results
│   ├── nmap_quick_target_timestamp.txt
│   ├── nmap_full_target_timestamp.txt
│   ├── dns_enum_target_timestamp.txt
│   └── whois_target_timestamp.txt
├── web/                      # Web testing results
│   ├── whatweb_target_timestamp.txt
│   ├── nikto_target_timestamp.txt
│   ├── gobuster_target_timestamp.txt
│   └── sslscan_target_timestamp.txt
├── proxmox/                  # Proxmox testing results
│   ├── proxmox_ports_target_timestamp.txt
│   └── proxmox_web_target_timestamp.txt
└── reports/                  # Generated reports
    └── report_target_timestamp.md
```

---

## Configuration

Edit `config.py` to customize:

### Tool Paths
```python
TOOL_PATHS = {
    "nmap": "nmap",
    "nikto": "nikto",
    # ... customize paths if tools are in non-standard locations
}
```

### Timeouts
```python
TIMEOUTS = {
    "nmap_quick": 300,      # 5 minutes
    "nmap_full": 1800,      # 30 minutes
    # ... adjust based on your needs
}
```

### Wordlists
```python
WORDLISTS = {
    "dirb_common": "/usr/share/wordlists/dirb/common.txt",
    # ... add custom wordlist paths
}
```

---

## GUI Interface Guide

### Main Window Sections

1. **Target Configuration**
   - Input field for target IP/domain
   - Format validation

2. **Scan Presets**
   - Radio buttons for quick preset selection
   - Automatically selects appropriate tests

3. **Test Selection**
   - Three categories: Reconnaissance, Web Testing, Proxmox Testing
   - Checkboxes for granular control
   - Tooltips explain each test

4. **Control Buttons**
   - **Start Scan** - Begin testing
   - **Stop Scan** - Cancel running scan
   - **Generate Report** - Create summary report
   - **Open Output Folder** - View raw scan files
   - **Check Tools** - Verify tool availability
   - **About** - Application information

5. **Progress Bar**
   - Shows scan activity
   - Indeterminate mode during execution

6. **Output Log**
   - Real-time command execution output
   - Color-coded messages (errors in red)
   - Scrollable text area

7. **Status Bar**
   - Current application status

---

## Example Workflows

### Workflow 1: Basic Network Reconnaissance

```
1. Target: 192.168.1.100
2. Preset: Quick Scan
3. Tests: Quick Nmap, DNS Enum, WHOIS
4. Duration: ~5 minutes
5. Output: Port list, services, DNS records
```

### Workflow 2: Web Application Assessment

```
1. Target: webapp.company.com
2. Preset: Web Application Focus
3. Tests: Nmap, WhatWeb, Nikto, Gobuster, SSLScan
4. Duration: ~15-30 minutes
5. Output: Technologies, vulnerabilities, hidden directories, SSL issues
```

### Workflow 3: Proxmox Server Security Check

```
1. Target: proxmox.internal.net
2. Preset: Proxmox Server Focus
3. Tests: Nmap, Proxmox Ports, Proxmox Web, SSLScan
4. Duration: ~10-15 minutes
5. Output: Open services, web interface vulns, SSL configuration
```

### Workflow 4: Comprehensive Full Scan

```
1. Target: target-system.com
2. Preset: Full Scan
3. Tests: All available tests
4. Duration: 30-60+ minutes
5. Output: Complete security assessment
```

---

## Report Format

Generated reports include:

### Sections

1. **Executive Summary**
   - Finding counts by severity
   - Quick statistics

2. **Scope and Methodology**
   - Target information
   - Tests performed
   - Tools used

3. **Key Findings**
   - Open ports and services
   - Detected technologies
   - Potential vulnerabilities

4. **Detailed Scan Results**
   - Links to raw output files
   - Status of each test

5. **Remediation Recommendations**
   - Prioritized action items
   - Immediate, short-term, and long-term actions

6. **Appendix**
   - File locations
   - Raw scan data references

### Example Report Excerpt

```markdown
# Penetration Test Report

**Target:** 192.168.1.100
**Test Date:** 2025-11-24 14:30:00

## Executive Summary
- **Critical Findings:** 0
- **High Findings:** 2
- **Medium Findings:** 5
- **Open Ports:** 8

## Key Findings

### Open Ports and Services
- 22/tcp (SSH - OpenSSH 8.2)
- 80/tcp (HTTP - Apache 2.4.41)
- 443/tcp (HTTPS - Apache 2.4.41)
- 8006/tcp (Proxmox Web Interface)

### Potential Vulnerabilities
1. Outdated Apache version detected
2. Missing security headers (X-Frame-Options, CSP)
3. Weak SSL/TLS ciphers enabled
...
```

---

## Troubleshooting

### Common Issues

**Issue: "Tool not found" errors**
```bash
# Check if tools are installed
which nmap nikto gobuster whatweb sslscan

# Install missing tools
sudo apt install -y <tool-name>
```

**Issue: "Permission denied" errors**
```bash
# Some scans require root (like SYN scan, UDP scan)
# Run the tool with sudo if needed
sudo python3 pentest_automation.py

# Or add sudo to specific commands in config.py
```

**Issue: Wordlist not found**
```bash
# Check wordlist locations
ls -la /usr/share/wordlists/dirb/

# Install wordlists if missing
sudo apt install -y wordlists dirb seclists
```

**Issue: Slow scans**
```bash
# Reduce timeout values in config.py
# Use Quick Scan preset instead of Full Scan
# Limit the number of concurrent tests
```

**Issue: GUI doesn't appear**
```bash
# Install tkinter if missing
sudo apt install -y python3-tk

# Check DISPLAY variable (if using SSH)
echo $DISPLAY
export DISPLAY=:0
```

---

## Advanced Usage

### Command-Line Arguments (Future Enhancement)

```bash
# Run in headless mode (planned feature)
python3 pentest_automation.py --target 192.168.1.100 --preset quick --headless

# Generate report only
python3 pentest_automation.py --report-only --scan-dir ~/pentest/recon
```

### Integration with Other Tools

**Import Nmap XML into Metasploit:**
```bash
msfconsole
db_import ~/pentest/recon/nmap_full_target_timestamp.xml
```

**Parse with Custom Scripts:**
```python
from report_generator import ReportGenerator
results = {...}  # Your scan results
report = ReportGenerator("target", results)
report.generate_report("custom_report.md")
```

---

## Safety Features

- **Legal Warning** - Displays on every startup
- **Target Validation** - Checks IP/domain format
- **Confirmation Dialogs** - Requires confirmation before scanning
- **Cancellation** - Stop button to abort running scans
- **Timeout Protection** - Commands timeout to prevent hanging
- **Error Handling** - Graceful failure handling
- **Read-only Operations** - Tool only reads/scans, never modifies targets

---

## Best Practices

### Before Testing
1. ✅ Obtain written authorization
2. ✅ Define scope clearly
3. ✅ Schedule downtime if needed
4. ✅ Backup target systems
5. ✅ Inform stakeholders

### During Testing
1. 📊 Monitor scan progress
2. 📝 Take notes on findings
3. 🚫 Don't run destructive tests
4. ⏱️ Be mindful of scan intensity
5. 📸 Capture screenshots of findings

### After Testing
1. 📄 Generate comprehensive report
2. 🔐 Secure scan data (contains sensitive info)
3. 📧 Communicate findings
4. ✔️ Verify remediation
5. 🗑️ Securely delete scan data when no longer needed

---

## Contributing

This tool is designed for educational purposes. Improvements are welcome:

- Bug fixes
- Additional scan modules
- Enhanced parsing
- UI improvements
- Documentation updates

---

## License

Educational and Authorized Testing Use Only

This tool is provided for educational purposes and authorized penetration testing only. Users must comply with all applicable laws and regulations. The developers assume no liability for misuse.

---

## Changelog

### Version 1.0 (2025-11-24)
- Initial release
- GUI interface with tkinter
- Reconnaissance module (Nmap, DNS, WHOIS)
- Web testing module (Nikto, Gobuster, WhatWeb, SSLScan)
- Proxmox testing module
- Automated report generation
- Real-time output monitoring
- Preset scan profiles

---

## Acknowledgments

Built using industry-standard penetration testing tools:
- **Nmap** - Network mapper
- **Nikto** - Web server scanner
- **Gobuster** - Directory enumeration
- **WhatWeb** - Web fingerprinting
- **SSLScan** - SSL/TLS testing

Inspired by the PTES (Penetration Testing Execution Standard) and OWASP Testing Guide.

---

## Support

For issues, questions, or suggestions:
- Review this README thoroughly
- Check the troubleshooting section
- Verify tool installation with "Check Tools" button
- Consult tool-specific documentation (e.g., `man nmap`)

---

## Disclaimer

**USE AT YOUR OWN RISK**

This tool performs security testing that may:
- Generate significant network traffic
- Trigger security alarms/IDS
- Cause service disruption if misconfigured
- Expose sensitive information in logs

Always test in controlled environments with proper authorization.

---

**Made for Kali Linux | Penetration Testing Automation Tool v1.0**
