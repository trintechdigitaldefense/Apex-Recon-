# ApexRecon v2.1.0

> **TrinTech Digital Defense** — Enterprise-Grade Local Network, OSINT & Web Application Audit Framework

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Linux__%7C__Android__%7C__Termux-green.svg)
![License](https://img.shields.io/badge/License-All%20Rights%20Reserved-gray.svg)
![Version](https://img.shields.io/badge/version-2.1.0-red.svg)

---

## Overview

ApexRecon is a professional-grade network security audit framework optimized for **Termux-Ubuntu proot** (Android/Samsung A16) and desktop Linux environments. It combines external OSINT, SMB auditing, web application scanning, and structured reporting into a single CLI tool.

Built for **professional engagements** — every scan produces client-ready reports with risk classification, executive summaries, and remediation guidance.

## Features

### 🔍 Module 1: External OSINT
- **DNS Enumeration** — A, AAAA, MX, NS, TXT, CNAME, SOA, CAA records via `dig`
- **WHOIS Lookup** — Registrant, org, ASN, and creation date extraction
- **IP Geolocation** — City, region, country, ASN via ipinfo.io
- **External Port Scan** — nmap `-F` with banner grabbing
- All results logged to JSON for traceability

### 💻 Module 2: SMB Auditor
- **Auto subnet detection** — reads local interface via `ip route`, falls back to `socket.gethostbyname()`
- **nmap SMB scan** — 5-script suite: `smb-os-discovery`, `smb-enum-shares`, `smb-security-mode`, `smb-vuln-ms17-010`, `smb-vuln-ms10-054`
- **Vulnerability detection** — EternalBlue (MS17-010), SMB memory corruption (MS10-054)
- **SMB signing detection** — flags disabled signing as relay attack vector
- Structured output parsing — raw nmap → host objects with IP, hostname, OS, shares, vuln flags

### 🌐 Module 3: Web Application Scanner *(NEW in 2.1)*
- **SSL/TLS certificate analysis** — protocol, cipher, expiry, SAN, days remaining
- **Security headers audit** — HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and more
- **CMS fingerprinting** — WordPress, Joomla, Drupal, Magento, Shopify, Wix, Squarespace + common paths
- **Technology detection** — Server, X-Powered-By, React/Vue/Angular/jQuery signals
- **Nikto integration** (optional) — quick-mode web vulnerability scan when installed
- Findings fed into the same HTML report engine

### 📊 Reporting
- **Risk Classification Engine** — auto-assigns LOW / MEDIUM / HIGH / CRITICAL
- **HTML Report** — dark-themed, self-contained, client-ready
- **Optional email delivery** — configure SMTP in `~/.apexrecon/config.json`
- **Persistent audit log** — `apex_recon.log` with timestamped entries

### 🛠️ Engineering
- **Startup dependency checker** — validates nmap, whois, dig, curl, openssl (+ optional nikto)
- **Config file** — `~/.apexrecon/config.json` for email, timeouts, user-agent
- **Unified subprocess wrapper** — timeout handling, `FileNotFoundError` protection
- **ANSI color palette** — consistent risk badges across terminal output

## Installation

```bash
# Clone the repository
git clone https://github.com/trintechdigitaldefense/Apex-Recon-.git
cd Apex-Recon-

# Run the framework
python3 apex_recon_v2.py
```

**Dependencies are auto-checked on startup.** Missing tools get `apt-get install` hints.

Recommended packages:
```bash
apt-get install nmap whois dnsutils curl openssl
# optional for deeper web scans
apt-get install nikto
```

## Usage

```
ApexRecon v2.1.0
Enterprise-Grade Local Network, OSINT & Web Application Audit Framework
─────────────────────────────────────────────────

  Target Engagement Modules:

  [1] External Footprinting (OSINT)
       DNS · WHOIS · GeoIP · Open Ports · Banner grab
  [2] Local Network SMB Auditor
       Host discovery · Share enum · EternalBlue · HTML report
  [3] Web Application Scanner  NEW
       SSL/TLS · Headers · CMS fingerprint · Nikto

  [9] Exit Framework
─────────────────────────────────────────────────
Apex@TrinTech:~# 
```

## Configuration

On first run a config file is created at `~/.apexrecon/config.json`:

```json
{
  "email": {
    "enabled": false,
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "username": "",
    "password": "",
    "from_addr": "",
    "to_addrs": []
  },
  "timeouts": {
    "nmap": 180,
    "web": 15,
    "ssl": 10
  },
  "web": {
    "user_agent": "ApexRecon/2.1 (+https://trintechdigitaldefense.github.io)",
    "follow_redirects": true
  }
}
```

Enable email delivery by setting `"enabled": true` and filling SMTP credentials.

## Architecture

```
apex_recon_v2.py        # Main entry point, CLI menu, all modules
CHANGELOG.md            # Version history
LICENSE                 # Copyright notice
README.md               # This file
```

## Output

### Terminal
```
[*] Running external port scan...
[+] Port 22/tcp: SSH (OpenSSH 8.9) — MEDIUM severity
[+] Port 445/tcp: Microsoft-DS (Samba 4.15) — CRITICAL severity
    ├── Vulnerability: smb-vuln-ms17-010 (EternalBlue) — RISK_HIGH
    ├── Vulnerability: smb-vuln-ms10-054 (SMB corruption) — RISK_HIGH
    └── SMB Signing: disabled — relay attack vector
```

### HTML Report
Each scan produces `apex_report_YYYYMMDD_HHMMSS.html` — self-contained dark-themed report ready for client delivery.

## Roadmap

| Version | Status |
|---------|--------|
| **2.0.0** | ✅ Released — OSINT, SMB, reporting, risk classification |
| **2.1.0** | ✅ Released — Web Application Scanner, SSL/TLS, headers, CMS fingerprint, config, email delivery |
| **2.2.0** | 📋 Planned — PDF export, multi-target batch mode, improved Nikto parsing |
| **3.0.0** | 📋 Planned — Subdomain brute-force, API mode, Caribbean/LatAm compliance mapping |

## License

All Rights Reserved — TrinTech Digital Defense

## About

TrinTech Digital Defense is a Trinidad & Tobago cybersecurity consultancy.

- 🌐 [trintechdigitaldefense.github.io](https://trintechdigitaldefense.github.io)
- 📧 [trintechdigitaldefense@gmail.com](mailto:trintechdigitaldefense@gmail.com)
- 📱 +1 (868) 362-0679

---

*DEFEND. DETECT. DOMINATE. 🇹🇹*
