# Quick Start Guide

## Installation (5 minutes)

### Step 1: Install Required Tools

```bash
sudo bash install.sh
```

This will install:
- nmap, nikto, gobuster, whatweb, sslscan
- Python3 and tkinter
- Wordlists (dirb, dirbuster, rockyou)

### Step 2: Run the Tool

```bash
python3 pentest_automation.py
```

Or make it easier with a desktop launcher:

```bash
bash create_launcher.sh
```

---

## Your First Scan (2 minutes)

### Example 1: Quick Scan of a Web Server

1. **Start the tool**
   ```bash
   python3 pentest_automation.py
   ```

2. **Enter target**
   ```
   Target: example.com
   ```

3. **Select preset**
   - Click "Quick Scan" radio button

4. **Start scan**
   - Click "▶ Start Scan"
   - Confirm authorization
   - Wait 5-10 minutes

5. **Generate report**
   - Click "📄 Generate Report"
   - View report in `~/pentest/reports/`

### Example 2: Proxmox Server Assessment

1. **Enter target**
   ```
   Target: 192.168.1.100
   ```

2. **Select preset**
   - Click "Proxmox Server Focus"

3. **Start scan**
   - Click "▶ Start Scan"

4. **Review findings**
   - Check for open ports (22, 8006)
   - Review web interface vulnerabilities
   - Check SSL/TLS configuration

---

## Understanding the Output

### Output Directory Structure

```
~/pentest/
├── recon/          # Nmap, DNS, WHOIS results
├── web/            # Web testing results
├── proxmox/        # Proxmox-specific tests
└── reports/        # Generated reports
```

### Key Files to Review

After a scan completes, check these files:

**Reconnaissance:**
- `recon/nmap_quick_*.txt` - Open ports and services
- `recon/dns_enum_*.txt` - DNS records

**Web Testing:**
- `web/whatweb_*.txt` - Technologies detected
- `web/nikto_*.txt` - Web vulnerabilities
- `web/gobuster_*.txt` - Hidden directories

**Reports:**
- `reports/report_*.md` - Comprehensive summary

---

## Common Workflows

### Workflow 1: Network Discovery

**Goal:** Find what's running on a target

**Steps:**
1. Target: `192.168.1.0/24` or specific IP
2. Tests: Quick Nmap Scan
3. Duration: ~5 minutes
4. Output: List of open ports and services

**What to look for:**
- Unnecessary open ports
- Outdated service versions
- Unusual services

---

### Workflow 2: Web Security Assessment

**Goal:** Identify web application vulnerabilities

**Steps:**
1. Target: `https://webapp.example.com`
2. Tests: Web Application Focus preset
3. Duration: ~15-20 minutes
4. Output: Technologies, directories, vulnerabilities

**What to look for:**
- Outdated software versions
- Missing security headers
- Accessible admin panels
- Backup files exposed
- Weak SSL/TLS configuration

---

### Workflow 3: Proxmox Security Check

**Goal:** Verify Proxmox server security

**Steps:**
1. Target: Proxmox server IP
2. Tests: Proxmox Server Focus
3. Duration: ~10 minutes
4. Output: Service status, web interface issues

**What to look for:**
- SSH configuration
- Web interface vulnerabilities
- Certificate validity
- Unnecessary services

---

## Reading the Report

### Executive Summary

```markdown
- **Critical Findings:** 0   ← Fix immediately
- **High Findings:** 2       ← Fix within 1 week
- **Medium Findings:** 5     ← Fix within 1 month
- **Open Ports:** 8          ← Review necessity
```

### Open Ports Section

```markdown
- 22/tcp (SSH)      ← Expected for remote access
- 80/tcp (HTTP)     ← Web server
- 443/tcp (HTTPS)   ← Secure web server
- 3306/tcp (MySQL)  ← ⚠️ Database exposed to network?
```

**Action:** Close unnecessary ports with firewall rules.

### Technologies Detected

```markdown
- Apache 2.4.41              ← Check for updates
- PHP 7.4.3                  ← Check for vulnerabilities
- WordPress 5.9              ← Keep updated
```

**Action:** Update outdated software.

### Vulnerabilities

```markdown
1. Missing X-Frame-Options header     ← Medium risk
2. Weak SSL cipher suites enabled     ← High risk
3. Directory listing enabled          ← Low risk
```

**Action:** Follow remediation recommendations.

---

## Remediation Priorities

### Priority 1: Critical/High (Fix Now)

- Remote code execution vulnerabilities
- SQL injection
- Authentication bypass
- Exposed databases
- Weak/default credentials

### Priority 2: Medium (Fix This Week)

- Cross-site scripting (XSS)
- Missing security headers
- Information disclosure
- Weak SSL/TLS configuration

### Priority 3: Low (Fix This Month)

- Version disclosure
- Directory listing
- Minor misconfigurations

---

## Troubleshooting

### "Tool not found" Error

**Solution:**
```bash
sudo apt install <tool-name>
# Example: sudo apt install nmap
```

### Slow Scans

**Solution:**
- Use "Quick Scan" instead of "Full Scan"
- Select fewer tests
- Reduce timeout values in `config.py`

### No Output in Log Window

**Solution:**
- Check if target is reachable: `ping target-ip`
- Verify tool is installed: `which nmap`
- Check firewall isn't blocking

### Permission Denied

**Solution:**
```bash
# Some scans need root privileges
sudo python3 pentest_automation.py
```

---

## Best Practices Checklist

**Before Scanning:**
- [ ] I have written authorization to test this target
- [ ] I understand what each test does
- [ ] Target is in a test environment (or I have approval for production)
- [ ] I've informed relevant stakeholders

**During Scanning:**
- [ ] Monitoring scan progress
- [ ] Not running aggressive tests on production
- [ ] Taking notes on interesting findings

**After Scanning:**
- [ ] Generated comprehensive report
- [ ] Securing scan data (contains sensitive info)
- [ ] Planning remediation based on priorities
- [ ] Will retest after fixes

---

## Next Steps

### Learn More

1. **Read the full README.md** - Detailed documentation
2. **Explore tool options** - Click "Check Tools" to see what's installed
3. **Review raw outputs** - Click "Open Output Folder" to see detailed results
4. **Customize config.py** - Adjust timeouts, wordlists, etc.

### Advanced Usage

1. **Customize wordlists** - Add your own in `config.py`
2. **Adjust timeouts** - Increase for slower networks
3. **Add custom tests** - Extend `scanner_engine.py`
4. **Integrate with Metasploit** - Import Nmap XML files

### Community Resources

- **OWASP Testing Guide** - https://owasp.org/www-project-web-security-testing-guide/
- **Kali Linux Docs** - https://www.kali.org/docs/
- **Nmap Reference** - https://nmap.org/book/man.html
- **HackTheBox** - https://hackthebox.com (practice labs)

---

## Quick Reference

### Most Useful Presets

**Quick Scan** - Fast overview (5-10 min)
- Use for: Initial reconnaissance
- Output: Open ports, basic info

**Web Application Focus** - Web security (15-20 min)
- Use for: Web app pentesting
- Output: Web vulns, directories, tech stack

**Full Scan** - Everything (30-60 min)
- Use for: Comprehensive assessment
- Output: Complete security posture

### Keyboard Shortcuts

- `Ctrl+C` in terminal - Stop the tool
- Click "Stop Scan" - Cancel running scan
- `Ctrl+A` in log window - Select all output

---

## Getting Help

1. **Check README.md** - Full documentation
2. **Click "Check Tools"** - Verify installation
3. **Review logs** - Output window shows what went wrong
4. **Test tools manually** - Run `nmap --version` etc.

---

**You're ready to start! Remember: Only test systems you own or have permission to test.**

**Legal Note:** Unauthorized access to computer systems is illegal. Always obtain proper authorization before testing.
