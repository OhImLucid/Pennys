"""
Scanner Engine - Backend for executing penetration testing tools
Handles subprocess execution, output capture, and command generation
"""

import subprocess
import os
import threading
import queue
import re
from datetime import datetime
from typing import Dict, List, Optional, Callable
import config


class ScannerEngine:
    """Core scanning engine that executes penetration testing tools"""

    def __init__(self, output_callback: Optional[Callable] = None):
        """
        Initialize the scanner engine

        Args:
            output_callback: Function to call with output updates (line, is_error)
        """
        self.output_callback = output_callback
        self.current_process = None
        self.is_cancelled = False
        self.results = {}

    def log(self, message: str, is_error: bool = False):
        """Send log message to callback"""
        if self.output_callback:
            self.output_callback(message, is_error)

    def validate_target(self, target: str) -> tuple[bool, str]:
        """
        Validate target IP or domain

        Returns:
            (is_valid, error_message)
        """
        # Remove protocol if present
        target = re.sub(r'^https?://', '', target)
        target = target.split('/')[0]  # Remove path

        # Check if it's an IP address
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ip_pattern, target):
            octets = target.split('.')
            if all(0 <= int(octet) <= 255 for octet in octets):
                return True, ""
            else:
                return False, "Invalid IP address (octets must be 0-255)"

        # Check if it's a valid domain
        domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        if re.match(domain_pattern, target):
            return True, ""

        # Check if it's localhost or hostname
        if target in ['localhost', '127.0.0.1'] or re.match(r'^[a-zA-Z0-9\-]+$', target):
            return True, ""

        return False, "Invalid target format. Use IP (e.g., 192.168.1.1) or domain (e.g., example.com)"

    def execute_command(self, command: List[str], timeout: int = None) -> tuple[bool, str, str]:
        """
        Execute a shell command and capture output

        Args:
            command: Command as list of arguments
            timeout: Timeout in seconds

        Returns:
            (success, stdout, stderr)
        """
        if self.is_cancelled:
            return False, "", "Operation cancelled"

        try:
            self.log(f"[CMD] {' '.join(command)}")

            self.current_process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )

            stdout_lines = []
            stderr_lines = []

            # Read output in real-time
            def read_stream(stream, output_list, is_error=False):
                for line in iter(stream.readline, ''):
                    if self.is_cancelled:
                        break
                    line = line.rstrip()
                    if line:
                        output_list.append(line)
                        self.log(line, is_error)

            stdout_thread = threading.Thread(
                target=read_stream,
                args=(self.current_process.stdout, stdout_lines, False)
            )
            stderr_thread = threading.Thread(
                target=read_stream,
                args=(self.current_process.stderr, stderr_lines, True)
            )

            stdout_thread.start()
            stderr_thread.start()

            # Wait for process to complete
            try:
                self.current_process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.log(f"[TIMEOUT] Command exceeded {timeout}s timeout", True)
                self.current_process.kill()
                return False, '\n'.join(stdout_lines), "Timeout expired"

            stdout_thread.join()
            stderr_thread.join()

            stdout = '\n'.join(stdout_lines)
            stderr = '\n'.join(stderr_lines)

            success = self.current_process.returncode == 0
            return success, stdout, stderr

        except FileNotFoundError:
            error_msg = f"Tool not found: {command[0]}. Please install it on Kali Linux."
            self.log(f"[ERROR] {error_msg}", True)
            return False, "", error_msg

        except Exception as e:
            error_msg = f"Execution error: {str(e)}"
            self.log(f"[ERROR] {error_msg}", True)
            return False, "", error_msg

        finally:
            self.current_process = None

    def cancel(self):
        """Cancel the current operation"""
        self.is_cancelled = True
        if self.current_process:
            try:
                self.current_process.kill()
                self.log("[CANCELLED] Operation cancelled by user")
            except:
                pass

    def reset_cancel(self):
        """Reset cancellation flag"""
        self.is_cancelled = False

    # ============= RECONNAISSANCE SCANS =============

    def nmap_quick_scan(self, target: str, output_file: str) -> bool:
        """Quick Nmap scan (common ports)"""
        self.log("\n=== Starting Quick Nmap Scan ===")
        command = [
            config.TOOL_PATHS["nmap"],
            "-sV", "-T4",
            "-p", "1-1000",
            "-oN", output_file,
            target
        ]
        success, stdout, stderr = self.execute_command(command, config.TIMEOUTS["nmap_quick"])
        self.results['nmap_quick'] = {'success': success, 'output_file': output_file}
        return success

    def nmap_full_scan(self, target: str, output_file: str) -> bool:
        """Comprehensive Nmap scan (all ports with scripts)"""
        self.log("\n=== Starting Full Nmap Scan (This will take a while) ===")
        command = [
            config.TOOL_PATHS["nmap"],
            "-sS", "-sV", "-sC", "-O",
            "-p-", "-T4",
            "--script=vuln",
            "-oN", output_file,
            target
        ]
        success, stdout, stderr = self.execute_command(command, config.TIMEOUTS["nmap_full"])
        self.results['nmap_full'] = {'success': success, 'output_file': output_file}
        return success

    def nmap_udp_scan(self, target: str, output_file: str) -> bool:
        """UDP port scan (top 100 ports)"""
        self.log("\n=== Starting UDP Scan ===")
        command = [
            "sudo",
            config.TOOL_PATHS["nmap"],
            "-sU", "--top-ports", "100",
            "-oN", output_file,
            target
        ]
        success, stdout, stderr = self.execute_command(command, config.TIMEOUTS["nmap_quick"])
        self.results['nmap_udp'] = {'success': success, 'output_file': output_file}
        return success

    def dns_enumeration(self, target: str, output_file: str) -> bool:
        """DNS enumeration using dig"""
        self.log("\n=== Starting DNS Enumeration ===")

        # Remove protocol and path, get domain only
        domain = re.sub(r'^https?://', '', target).split('/')[0]

        with open(output_file, 'w') as f:
            # Basic DNS lookup
            self.log("[DNS] Performing ANY record lookup")
            command = [config.TOOL_PATHS["dig"], domain, "ANY"]
            success1, stdout, stderr = self.execute_command(command, config.TIMEOUTS["dns"])
            f.write("=== DNS ANY Records ===\n")
            f.write(stdout + "\n\n")

            # Reverse DNS
            self.log("[DNS] Attempting reverse DNS lookup")
            command = [config.TOOL_PATHS["dig"], "-x", target]
            success2, stdout, stderr = self.execute_command(command, config.TIMEOUTS["dns"])
            f.write("=== Reverse DNS ===\n")
            f.write(stdout + "\n\n")

        self.results['dns'] = {'success': success1 or success2, 'output_file': output_file}
        return success1 or success2

    def whois_lookup(self, target: str, output_file: str) -> bool:
        """WHOIS information lookup"""
        self.log("\n=== Starting WHOIS Lookup ===")
        command = [config.TOOL_PATHS["whois"], target]
        success, stdout, stderr = self.execute_command(command, config.TIMEOUTS["whois"])

        with open(output_file, 'w') as f:
            f.write(stdout)

        self.results['whois'] = {'success': success, 'output_file': output_file}
        return success

    # ============= WEB APPLICATION TESTING =============

    def whatweb_scan(self, target: str, output_file: str) -> bool:
        """Technology fingerprinting with WhatWeb"""
        self.log("\n=== Starting WhatWeb Technology Scan ===")

        # Ensure target has protocol
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"

        command = [
            config.TOOL_PATHS["whatweb"],
            "-v",
            target
        ]
        success, stdout, stderr = self.execute_command(command, config.TIMEOUTS["whatweb"])

        with open(output_file, 'w') as f:
            f.write(stdout)
            if stderr:
                f.write("\n\n=== Errors ===\n")
                f.write(stderr)

        self.results['whatweb'] = {'success': success, 'output_file': output_file}
        return success

    def nikto_scan(self, target: str, output_file: str) -> bool:
        """Web vulnerability scan with Nikto"""
        self.log("\n=== Starting Nikto Web Vulnerability Scan ===")

        # Ensure target has protocol
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"

        command = [
            config.TOOL_PATHS["nikto"],
            "-h", target,
            "-o", output_file,
            "-Format", "txt"
        ]
        success, stdout, stderr = self.execute_command(command, config.TIMEOUTS["nikto"])
        self.results['nikto'] = {'success': success, 'output_file': output_file}
        return success

    def gobuster_scan(self, target: str, output_file: str, wordlist: str = None) -> bool:
        """Directory enumeration with Gobuster"""
        self.log("\n=== Starting Gobuster Directory Enumeration ===")

        # Ensure target has protocol
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"

        # Select wordlist
        if not wordlist:
            wordlist = config.WORDLISTS.get("dirb_common")

        if not os.path.exists(wordlist):
            self.log(f"[WARNING] Wordlist not found: {wordlist}", True)
            # Try alternative wordlist
            for wl_name, wl_path in config.WORDLISTS.items():
                if os.path.exists(wl_path):
                    wordlist = wl_path
                    self.log(f"[INFO] Using alternative wordlist: {wordlist}")
                    break
            else:
                self.log("[ERROR] No wordlists available", True)
                return False

        command = [
            config.TOOL_PATHS["gobuster"],
            "dir",
            "-u", target,
            "-w", wordlist,
            "-o", output_file,
            "-k",  # Skip SSL verification
            "-q",  # Quiet mode
            "-x", "php,html,txt,js,bak"
        ]
        success, stdout, stderr = self.execute_command(command, config.TIMEOUTS["gobuster"])
        self.results['gobuster'] = {'success': success, 'output_file': output_file}
        return success

    def sslscan(self, target: str, output_file: str) -> bool:
        """SSL/TLS configuration testing"""
        self.log("\n=== Starting SSL/TLS Scan ===")

        # Remove protocol if present
        target = re.sub(r'^https?://', '', target).split('/')[0]

        command = [
            config.TOOL_PATHS["sslscan"],
            target
        ]
        success, stdout, stderr = self.execute_command(command, config.TIMEOUTS["sslscan"])

        with open(output_file, 'w') as f:
            f.write(stdout)
            if stderr:
                f.write("\n\n=== Errors ===\n")
                f.write(stderr)

        self.results['sslscan'] = {'success': success, 'output_file': output_file}
        return success

    # ============= PROXMOX TESTING =============

    def proxmox_port_scan(self, target: str, output_file: str) -> bool:
        """Scan Proxmox-specific ports"""
        self.log("\n=== Starting Proxmox Port Scan ===")
        command = [
            config.TOOL_PATHS["nmap"],
            "-sV", "-sC",
            "-p", config.PROXMOX_PORTS,
            "-oN", output_file,
            target
        ]
        success, stdout, stderr = self.execute_command(command, config.TIMEOUTS["nmap_quick"])
        self.results['proxmox_ports'] = {'success': success, 'output_file': output_file}
        return success

    def proxmox_web_scan(self, target: str, output_file: str) -> bool:
        """Scan Proxmox web interface (port 8006)"""
        self.log("\n=== Starting Proxmox Web Interface Scan ===")

        # Proxmox uses HTTPS on port 8006
        target_url = f"https://{target}:8006"

        command = [
            config.TOOL_PATHS["nikto"],
            "-h", target_url,
            "-ssl",
            "-o", output_file,
            "-Format", "txt"
        ]
        success, stdout, stderr = self.execute_command(command, config.TIMEOUTS["nikto"])
        self.results['proxmox_web'] = {'success': success, 'output_file': output_file}
        return success

    # ============= UTILITY METHODS =============

    def get_timestamp(self) -> str:
        """Get formatted timestamp for file names"""
        return datetime.now().strftime("%Y%m%d_%H%M%S")

    def get_output_filename(self, target: str, test_type: str, extension: str = "txt") -> str:
        """Generate output filename"""
        # Sanitize target for filename
        safe_target = re.sub(r'[^\w\-\.]', '_', target)
        timestamp = self.get_timestamp()
        return f"{test_type}_{safe_target}_{timestamp}.{extension}"

    def check_tool_installed(self, tool_name: str) -> bool:
        """Check if a tool is installed"""
        import shutil
        tool_path = config.TOOL_PATHS.get(tool_name)
        if not tool_path:
            return False
        return shutil.which(tool_path) is not None

    def get_scan_summary(self) -> Dict:
        """Get summary of scan results"""
        return self.results.copy()
