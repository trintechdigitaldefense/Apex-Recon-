# ApexRecon v2.0

> **TrinTech Digital Defense** — Enterprise-Grade Local Network & OSINT Audit Framework

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Linux__%7C__Android__%7C__Termux-green.svg)
![License](https://img.shields.io/badge/License-All%20Rights%20Reserved-gray.svg)

---

## Overview

ApexRecon is a professional-grade network security audit framework optimized for **Termux-Ubuntu proot** (Android/Samsung A16) and desktop Linux environments. It combines external OSINT, SMB auditing, and structured reporting into a single CLI tool.

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

### 📊 Reporting
- **Risk Classification Engine** — auto-assigns LOW / MEDIUM / HIGH / CRITICAL per host
- **HTML Report** — dark-themed, self-contained, client-ready:
  - Executive summary: total hosts, critical count, clean count
  - Per-host cards with full finding breakdown
  - Color-coded severity indicators with ANSI badges
  - No technical background required to read
- **Persistent audit log** — `apex_recon.log` with timestamped entries

### 🛠️ Engineering
- **Startup dependency checker** — validates nmap, whois, dig, curl with install commands
- **Unified subprocess wrapper** — timeout handling, `FileNotFoundError` protection
- **ANSI color palette** — RED, DARK_RED, WHITE, GREY for cross-platform terminal output
- **Module descriptions** — shown in interactive main menu

## Installation

```bash
# Clone the repository
git clone https://github.com/trintechdigitaldefense/Apex-Recon-.git
cd Apex-Recon-

# Run the framework
python3 apex_recon_v2.py
```

**Dependencies are auto-checked on startup.** Missing tools get `apt-get install` hints.

## Usage

```
ApexRecon v2.0
Enterprise-Grade Local Network & OSINT Audit Framework
─────────────────────────────────────────────────

  Main Menu
  ─────────
  1. [1] External OSINT & Network Recon    — DNS, WHOIS, IP, ports, banners
  2. [2] SMB Vulnerability Audit            — EternalBlue, MS10-054, signing

  0. [0] Quit                               — Exit with log entry
─────────────────────────────────────────────────
Enter choice:
```

## Architecture

```
apex_recon_v2.py        # Main entry point, CLI menu, module orchestrator
apex_report_generator.py # HTML report generation, risk classification
modules/osint.py        # External OSINT (DNS, WHOIS, geo, ports)
modules/smb_auditor.py  # SMB scanning, nmap wrapper, output parsing
lib/                     # Shared utilities (logging, colors, subprocess, parsing)
CHANGELOG.md             # Version history
LICENSE                  # Copyright notice
```

## Output

### Terminal Output
```
[*] Running external port scan...
[+] Port 22/tcp: SSH (OpenSSH 8.9) — MEDIUM severity
[+] Port 445/tcp: Microsoft-DS (Samba 4.15) — CRITICAL severity
    ├── Vulnerability: smb-vuln-ms17-010 (EternalBlue) — RISK_HIGH
    ├── Vulnerability: smb-vuln-ms10-054 (SMB corruption) — RISK_HIGH
    └── SMB Signing: disabled — relay attack vector
```

### HTML Report
Each SMB scan produces `apex_report_YYYYMMDD_HHMMSS.html` — a self-contained, dark-themed report ready for client delivery.

## Roadmap

| Version | Status |
|---------|--------|
| **2.0.0** | ✅ Released — OSINT, SMB, reporting, risk classification |
| **2.1.0** | 🚧 In progress — Web application scanner (Nikto), SSL/TLS audit, CMS fingerprinting, PDF export, email delivery |
| **3.0.0** | 📋 Planned — Subdomain brute-force, API mode, Caribbean/LatAm compliance mapping, multi-target batch scanning |

## License

All Rights Reserved — TrinTech Digital Defense

## About

TrinTech Digital Defense is a Trinidad & Tobago cybersecurity consultancy.

- 🌐 [trintechdigitaldefense.github.io](https://trintechdigitaldefense.github.io)
- 📧 [trintechdigitaldefense@gmail.com](mailto:trintechdigitaldefense@gmail.com)
- 📱 +1 (868) 362-0679

---

*DEFEND. DETECT. DOMINATE. 🇹🇹*
