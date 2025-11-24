"""
Report Generator - Creates markdown reports from scan results
Parses tool outputs and generates comprehensive findings reports
"""

import os
import re
from datetime import datetime
from typing import Dict, List, Optional
import config


class ReportGenerator:
    """Generate markdown reports from penetration testing results"""

    def __init__(self, target: str, scan_results: Dict):
        """
        Initialize report generator

        Args:
            target: Target IP or domain
            scan_results: Dictionary of scan results from scanner_engine
        """
        self.target = target
        self.scan_results = scan_results
        self.findings = []
        self.open_ports = []
        self.technologies = []
        self.vulnerabilities = []

    def parse_nmap_output(self, nmap_file: str) -> Dict:
        """Parse Nmap output for key findings"""
        if not os.path.exists(nmap_file):
            return {}

        findings = {
            'open_ports': [],
            'services': [],
            'os': None,
            'vulnerabilities': []
        }

        try:
            with open(nmap_file, 'r') as f:
                content = f.read()

            # Extract open ports
            port_pattern = r'(\d+/tcp)\s+open\s+(\S+)\s*(.*)'
            for match in re.finditer(port_pattern, content):
                port = match.group(1)
                service = match.group(2)
                version = match.group(3).strip()
                findings['open_ports'].append(port)
                findings['services'].append({
                    'port': port,
                    'service': service,
                    'version': version
                })

            # Extract OS detection
            os_pattern = r'OS details: (.+)'
            os_match = re.search(os_pattern, content)
            if os_match:
                findings['os'] = os_match.group(1)

            # Extract vulnerabilities from NSE scripts
            vuln_pattern = r'\|\s+(.+):\s*\n\|\s+State: VULNERABLE'
            for match in re.finditer(vuln_pattern, content):
                vuln_name = match.group(1).strip()
                findings['vulnerabilities'].append(vuln_name)

        except Exception as e:
            print(f"Error parsing Nmap output: {e}")

        return findings

    def parse_nikto_output(self, nikto_file: str) -> List[str]:
        """Parse Nikto output for vulnerabilities"""
        if not os.path.exists(nikto_file):
            return []

        vulnerabilities = []

        try:
            with open(nikto_file, 'r') as f:
                content = f.read()

            # Extract findings (lines starting with +)
            finding_pattern = r'\+ (.+)'
            for match in re.finditer(finding_pattern, content):
                finding = match.group(1).strip()
                if finding and not finding.startswith('Target IP:'):
                    vulnerabilities.append(finding)

        except Exception as e:
            print(f"Error parsing Nikto output: {e}")

        return vulnerabilities

    def parse_whatweb_output(self, whatweb_file: str) -> List[str]:
        """Parse WhatWeb output for technologies"""
        if not os.path.exists(whatweb_file):
            return []

        technologies = []

        try:
            with open(whatweb_file, 'r') as f:
                content = f.read()

            # Extract technology detections
            # WhatWeb format: [Technology][Version]
            tech_pattern = r'\[([\w\-\.]+)\]\[([^\]]+)\]'
            for match in re.finditer(tech_pattern, content):
                tech = match.group(1)
                version = match.group(2)
                technologies.append(f"{tech} {version}")

            # Also look for simpler format
            simple_pattern = r'\[([\w\-\.]+)\]'
            for match in re.finditer(simple_pattern, content):
                tech = match.group(1)
                if tech not in [t.split()[0] for t in technologies]:
                    technologies.append(tech)

        except Exception as e:
            print(f"Error parsing WhatWeb output: {e}")

        return technologies

    def parse_gobuster_output(self, gobuster_file: str) -> List[str]:
        """Parse Gobuster output for discovered directories"""
        if not os.path.exists(gobuster_file):
            return []

        directories = []

        try:
            with open(gobuster_file, 'r') as f:
                for line in f:
                    # Gobuster format: /path (Status: 200) [Size: 1234]
                    if '(Status:' in line:
                        path_match = re.search(r'^(\S+)', line.strip())
                        if path_match:
                            directories.append(line.strip())

        except Exception as e:
            print(f"Error parsing Gobuster output: {e}")

        return directories

    def parse_sslscan_output(self, sslscan_file: str) -> Dict:
        """Parse SSLScan output for SSL/TLS findings"""
        if not os.path.exists(sslscan_file):
            return {}

        findings = {
            'weak_ciphers': [],
            'protocols': [],
            'certificate_issues': []
        }

        try:
            with open(sslscan_file, 'r') as f:
                content = f.read()

            # Extract accepted ciphers
            cipher_pattern = r'Accepted\s+(\S+)\s+\d+\s+bits\s+(\S+)'
            for match in re.finditer(cipher_pattern, content):
                protocol = match.group(1)
                cipher = match.group(2)
                findings['protocols'].append(f"{protocol}: {cipher}")

            # Check for weak protocols (SSLv2, SSLv3, TLSv1.0)
            if re.search(r'SSLv[23]', content):
                findings['weak_ciphers'].append("Weak SSL protocols detected (SSLv2/SSLv3)")
            if re.search(r'TLSv1\.0', content):
                findings['weak_ciphers'].append("TLSv1.0 detected (deprecated)")

        except Exception as e:
            print(f"Error parsing SSLScan output: {e}")

        return findings

    def analyze_results(self):
        """Analyze all scan results and extract findings"""
        # Parse Nmap results
        if 'nmap_quick' in self.scan_results and self.scan_results['nmap_quick']['success']:
            nmap_data = self.parse_nmap_output(self.scan_results['nmap_quick']['output_file'])
            self.open_ports.extend(nmap_data.get('open_ports', []))
            self.vulnerabilities.extend(nmap_data.get('vulnerabilities', []))

        if 'nmap_full' in self.scan_results and self.scan_results['nmap_full']['success']:
            nmap_data = self.parse_nmap_output(self.scan_results['nmap_full']['output_file'])
            self.open_ports.extend(nmap_data.get('open_ports', []))
            self.vulnerabilities.extend(nmap_data.get('vulnerabilities', []))

        # Parse WhatWeb results
        if 'whatweb' in self.scan_results and self.scan_results['whatweb']['success']:
            self.technologies = self.parse_whatweb_output(
                self.scan_results['whatweb']['output_file']
            )

        # Parse Nikto results
        if 'nikto' in self.scan_results and self.scan_results['nikto']['success']:
            nikto_vulns = self.parse_nikto_output(self.scan_results['nikto']['output_file'])
            self.vulnerabilities.extend(nikto_vulns)

        # Deduplicate
        self.open_ports = list(set(self.open_ports))
        self.technologies = list(set(self.technologies))

    def generate_report(self, output_file: str) -> bool:
        """Generate comprehensive markdown report"""
        try:
            self.analyze_results()

            with open(output_file, 'w') as f:
                # Header
                f.write(f"# Penetration Test Report\n\n")
                f.write(f"**Target:** {self.target}\n\n")
                f.write(f"**Test Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                f.write(f"**Generated By:** Penetration Testing Automation Tool\n\n")
                f.write("---\n\n")

                # Executive Summary
                f.write("## Executive Summary\n\n")
                critical_count = len([v for v in self.vulnerabilities if any(
                    x in v.lower() for x in ['critical', 'remote code execution', 'rce']
                )])
                high_count = len([v for v in self.vulnerabilities if any(
                    x in v.lower() for x in ['high', 'sql injection', 'authentication']
                )])
                medium_count = len([v for v in self.vulnerabilities if any(
                    x in v.lower() for x in ['medium', 'xss', 'csrf']
                )])

                f.write(f"- **Critical Findings:** {critical_count}\n")
                f.write(f"- **High Findings:** {high_count}\n")
                f.write(f"- **Medium Findings:** {medium_count}\n")
                f.write(f"- **Open Ports:** {len(self.open_ports)}\n")
                f.write(f"- **Technologies Detected:** {len(self.technologies)}\n\n")
                f.write("---\n\n")

                # Scope and Methodology
                f.write("## Scope and Methodology\n\n")
                f.write("### Target System\n\n")
                f.write(f"- **Target:** {self.target}\n")
                f.write(f"- **Test Type:** Automated Penetration Testing\n\n")

                f.write("### Methodology\n\n")
                f.write("The following testing methodology was applied:\n\n")
                f.write("1. **Reconnaissance** - Network discovery and port scanning\n")
                f.write("2. **Enumeration** - Service and technology identification\n")
                f.write("3. **Vulnerability Assessment** - Automated scanning for known vulnerabilities\n")
                f.write("4. **Web Application Testing** - Directory enumeration and web vulnerability scanning\n")
                f.write("5. **Reporting** - Documentation of findings\n\n")

                f.write("### Tools Used\n\n")
                tools_used = []
                for scan_type, result in self.scan_results.items():
                    if result.get('success'):
                        tools_used.append(scan_type.replace('_', ' ').title())
                f.write(", ".join(tools_used) + "\n\n")
                f.write("---\n\n")

                # Key Findings
                f.write("## Key Findings\n\n")

                # Open Ports
                if self.open_ports:
                    f.write("### Open Ports and Services\n\n")
                    f.write("The following ports were found open:\n\n")
                    for port in sorted(self.open_ports):
                        f.write(f"- {port}\n")
                    f.write("\n")

                # Technologies
                if self.technologies:
                    f.write("### Technologies Detected\n\n")
                    f.write("The following technologies were identified:\n\n")
                    for tech in self.technologies[:20]:  # Limit to top 20
                        f.write(f"- {tech}\n")
                    f.write("\n")

                # Vulnerabilities
                if self.vulnerabilities:
                    f.write("### Potential Vulnerabilities\n\n")
                    f.write("The following potential vulnerabilities were identified:\n\n")
                    for i, vuln in enumerate(self.vulnerabilities, 1):
                        f.write(f"{i}. {vuln}\n")
                    f.write("\n")
                else:
                    f.write("### Potential Vulnerabilities\n\n")
                    f.write("No critical vulnerabilities detected by automated scans.\n\n")

                f.write("---\n\n")

                # Detailed Scan Results
                f.write("## Detailed Scan Results\n\n")

                for scan_type, result in self.scan_results.items():
                    f.write(f"### {scan_type.replace('_', ' ').title()}\n\n")
                    if result.get('success'):
                        f.write(f"- **Status:** Completed Successfully\n")
                        f.write(f"- **Output File:** `{result['output_file']}`\n\n")
                    else:
                        f.write(f"- **Status:** Failed or Incomplete\n\n")

                f.write("---\n\n")

                # Recommendations
                f.write("## Remediation Recommendations\n\n")

                f.write("### Immediate Actions (Critical/High Priority)\n\n")
                if critical_count > 0 or high_count > 0:
                    f.write("1. Review and remediate all critical and high-severity findings\n")
                    f.write("2. Apply security patches to identified vulnerable services\n")
                    f.write("3. Disable unnecessary services running on open ports\n")
                    f.write("4. Implement proper access controls and authentication\n\n")
                else:
                    f.write("No critical or high-priority findings require immediate action.\n\n")

                f.write("### Short-term Actions (Medium Priority)\n\n")
                f.write("1. Review medium-severity findings\n")
                f.write("2. Update security headers on web applications\n")
                f.write("3. Implement SSL/TLS best practices\n")
                f.write("4. Review and secure directory permissions\n\n")

                f.write("### Long-term Actions (Low Priority)\n\n")
                f.write("1. Implement regular vulnerability scanning\n")
                f.write("2. Establish security monitoring and logging\n")
                f.write("3. Conduct periodic penetration testing\n")
                f.write("4. Security awareness training for administrators\n\n")

                f.write("---\n\n")

                # Appendix
                f.write("## Appendix\n\n")

                f.write("### Raw Scan Data Locations\n\n")
                f.write(f"All detailed scan outputs are stored in:\n\n")
                f.write(f"- **Reconnaissance:** `{config.OUTPUT_DIRS['recon']}/`\n")
                f.write(f"- **Web Testing:** `{config.OUTPUT_DIRS['web']}/`\n")
                f.write(f"- **Proxmox Testing:** `{config.OUTPUT_DIRS['proxmox']}/`\n")
                f.write(f"- **Reports:** `{config.OUTPUT_DIRS['reports']}/`\n\n")

                f.write("### Scan Files\n\n")
                for scan_type, result in self.scan_results.items():
                    if result.get('output_file'):
                        f.write(f"- **{scan_type}:** `{result['output_file']}`\n")

                f.write("\n---\n\n")

                # Footer
                f.write("## Disclaimer\n\n")
                f.write("This report was generated by automated penetration testing tools. ")
                f.write("The findings should be verified manually before remediation. ")
                f.write("False positives may occur. Always test remediation in a ")
                f.write("non-production environment first.\n\n")

                f.write("**Report Generation Complete**\n\n")
                f.write("---\n\n")
                f.write(f"*Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n")

            return True

        except Exception as e:
            print(f"Error generating report: {e}")
            return False

    def generate_summary_text(self) -> str:
        """Generate a brief text summary of findings"""
        self.analyze_results()

        summary = []
        summary.append(f"Target: {self.target}")
        summary.append(f"Open Ports: {len(self.open_ports)}")
        summary.append(f"Technologies: {len(self.technologies)}")
        summary.append(f"Potential Issues: {len(self.vulnerabilities)}")

        return " | ".join(summary)
