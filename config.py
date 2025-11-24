"""
Configuration file for Penetration Testing Automation Tool
Contains tool paths, timeouts, and wordlist locations
"""

import os
from pathlib import Path

# Output directory structure
OUTPUT_BASE = str(Path.home() / "pentest")
OUTPUT_DIRS = {
    "base": OUTPUT_BASE,
    "recon": os.path.join(OUTPUT_BASE, "recon"),
    "web": os.path.join(OUTPUT_BASE, "web"),
    "proxmox": os.path.join(OUTPUT_BASE, "proxmox"),
    "reports": os.path.join(OUTPUT_BASE, "reports"),
}

# Tool paths (most Kali tools are in PATH, but can be customized)
TOOL_PATHS = {
    "nmap": "nmap",
    "nikto": "nikto",
    "gobuster": "gobuster",
    "whatweb": "whatweb",
    "sslscan": "sslscan",
    "dig": "dig",
    "whois": "whois",
    "sqlmap": "sqlmap",
    "hydra": "hydra",
    "masscan": "masscan",
}

# Timeout settings (in seconds)
TIMEOUTS = {
    "nmap_quick": 300,      # 5 minutes
    "nmap_full": 1800,      # 30 minutes
    "nikto": 600,           # 10 minutes
    "gobuster": 900,        # 15 minutes
    "whatweb": 60,          # 1 minute
    "sslscan": 120,         # 2 minutes
    "dns": 60,              # 1 minute
    "whois": 30,            # 30 seconds
    "sqlmap": 1800,         # 30 minutes
    "hydra": 3600,          # 1 hour
}

# Wordlist locations (standard Kali locations)
WORDLISTS = {
    "dirb_common": "/usr/share/wordlists/dirb/common.txt",
    "dirb_big": "/usr/share/wordlists/dirb/big.txt",
    "dirbuster_medium": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "dirbuster_small": "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    "rockyou": "/usr/share/wordlists/rockyou.txt",
    "seclists_discovery": "/usr/share/seclists/Discovery/Web-Content/common.txt",
}

# Scan profiles
SCAN_PROFILES = {
    "quick": {
        "nmap_flags": "-sV -T4",
        "nmap_ports": "1-1000",
        "gobuster_wordlist": "dirb_common",
        "aggressive": False,
    },
    "full": {
        "nmap_flags": "-sS -sV -sC -O -T4 --script=vuln",
        "nmap_ports": "-p-",
        "gobuster_wordlist": "dirbuster_medium",
        "aggressive": True,
    },
}

# File extensions for web enumeration
WEB_EXTENSIONS = "php,html,txt,js,bak,old,zip,tar,gz,sql,conf,config,xml,json"

# Proxmox specific settings
PROXMOX_PORTS = "22,111,8006,3128,5900-5999"
PROXMOX_DEFAULT_USERS = ["root", "admin", "administrator", "proxmox", "pve"]

# Web application testing settings
WEB_PORTS = "80,443,8080,8443,8000,8888"

# Nmap scan types
NMAP_SCAN_TYPES = {
    "quick": "-sV -T4",
    "full_tcp": "-sS -sV -sC -p-",
    "udp_top": "-sU --top-ports 100",
    "vulnerability": "-sV --script=vuln",
    "os_detection": "-sV -O",
}

# Legal warning text
LEGAL_WARNING = """
⚠️  LEGAL WARNING ⚠️

This tool is designed for AUTHORIZED penetration testing ONLY.

You MUST have:
- Explicit written permission to test target systems
- Documented scope and authorization
- Understanding of legal consequences

Unauthorized access to computer systems is ILLEGAL and may result in:
- Criminal prosecution
- Civil liability
- Imprisonment

By proceeding, you confirm that you have proper authorization
to test the specified target systems.

USE AT YOUR OWN RISK. The developers assume no liability.
"""

# Tool availability checks
def check_tool_availability():
    """Check which penetration testing tools are installed"""
    import shutil

    available_tools = {}
    for tool_name, tool_path in TOOL_PATHS.items():
        available_tools[tool_name] = shutil.which(tool_path) is not None

    return available_tools

# Wordlist availability checks
def check_wordlist_availability():
    """Check which wordlists are available"""
    available_wordlists = {}
    for name, path in WORDLISTS.items():
        available_wordlists[name] = os.path.exists(path)

    return available_wordlists

# Create output directories
def create_output_directories():
    """Create all required output directories"""
    for dir_name, dir_path in OUTPUT_DIRS.items():
        os.makedirs(dir_path, exist_ok=True)
    return True
