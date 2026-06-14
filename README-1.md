<div align="center">

```
    █████╗ ██████╗ ███████╗██╗  ██╗
   ██╔══██╗██╔══██╗██╔════╝╚██╗██╔╝
   ███████║██████╔╝█████╗   ╚███╔╝ 
   ██╔══██║██╔═══╝ ██╔══╝   ██╔██╗ 
   ██║  ██║██║     ███████╗██╔╝ ██╗
   ╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
```

# ApexRecon v2.0

**Mobile-First. Zero-Infrastructure. Enterprise-Grade.**

[![Version](https://img.shields.io/badge/version-2.0-red?style=flat-square)](https://github.com/trintechdigitaldefense/apexrecon)
[![Python](https://img.shields.io/badge/python-3.8%2B-white?style=flat-square&logo=python)](https://python.org)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Android%20%7C%20Termux-grey?style=flat-square)](https://termux.dev)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Author](https://img.shields.io/badge/by-TrinTech%20Digital%20Defense-red?style=flat-square)](https://trintechdigitaldefense.github.io)

*The only professional network audit framework built to run from a phone.*

</div>

---

## The Problem

Every enterprise security audit tool on the market assumes the same thing: **a dedicated laptop, a corporate network, and a $10,000/year license.**

That assumption leaves out field auditors, lean security teams, small and mid-sized businesses, and entire regions of the world where cybersecurity infrastructure is underfunded but the threats are real.

**ApexRecon was built to change that.**

---

## What It Does

ApexRecon is a unified network reconnaissance and audit framework. It runs a full professional-grade security assessment — OSINT footprinting, SMB enumeration, vulnerability detection, and client-ready HTML reporting — from a single Python file, on any Linux-capable device, including Android via Termux.

No agents. No cloud dependency. No enterprise license required to do enterprise-level work.

---

## Feature Overview

| Capability | Details |
|---|---|
| **External OSINT** | DNS enumeration (A/MX/NS/TXT/CNAME), WHOIS extraction, IP geolocation, open port scan with banner grabbing |
| **SMB Network Audit** | Host discovery, share enumeration, OS fingerprinting, SMB signing check |
| **Vulnerability Detection** | MS17-010 (EternalBlue), MS10-054 SMB memory corruption |
| **Auto Subnet Detection** | Reads local interface — no manual IP entry required |
| **Risk Classification** | Automatic LOW / MEDIUM / HIGH / CRITICAL scoring per host |
| **HTML Report Generation** | Dark-themed, client-ready audit report generated after every scan |
| **Compliance Logging** | Every action timestamped and written to persistent audit log |
| **Dependency Checker** | Startup validation with exact install commands for missing tools |
| **Mobile-First Design** | Full operation on Android (Samsung, Pixel, etc.) via Termux-Ubuntu |

---

## Who This Is For

- **Freelance security auditors** who need professional output without enterprise overhead
- **SMB-focused MSPs** running lean without dedicated hardware per site
- **Field security teams** auditing remote locations, branch offices, or client premises
- **Security companies** looking for a lightweight, embeddable audit engine
- **Developing-market practitioners** where enterprise tooling costs are prohibitive

---

## Why This Is Different

Most network audit tools in this class are:

- Desktop-only (Nessus, Qualys, OpenVAS require dedicated infrastructure)
- Cloud-dependent (no air-gapped or offline operation)
- Opaque in output (raw terminal dumps, no client-ready deliverables)
- Expensive to license for small engagements

ApexRecon is **none of those things.**

It runs offline. It runs on a phone. It produces a professional HTML report your client can read without a security background. And it's built by a practitioner who audits real networks, not a product team shipping features from a conference room.

---

## Quickstart

### Requirements

```bash
# Debian / Ubuntu / Termux-Ubuntu
apt-get install nmap whois dnsutils curl python3
```

### Run

```bash
git clone https://github.com/trintechdigitaldefense/apexrecon.git
cd apexrecon
python3 apex_recon_v2.py
```

### Menu

```
Target Engagement Modules:

  [1] External Footprinting (OSINT)
       DNS · WHOIS · GeoIP · Open Ports · Banner grab

  [2] Local Network SMB Auditor
       Host discovery · Share enum · EternalBlue check · HTML report

  [9] Exit Framework
```

---

## Output

Every SMB audit produces a timestamped `apex_report_YYYYMMDD_HHMMSS.html` — a self-contained dark-themed report with:

- Executive summary (hosts found, critical risk count)
- Per-host breakdown: IP, hostname, OS, SMB signing status
- Vulnerability flags with severity labeling
- Discovered shares with permission notes
- Actionable findings and recommendations

Open it in any browser. Send it directly to a client.

---

## Modules

### Module 1 — External Footprinting (OSINT)

Passive and active reconnaissance against a domain target:

- Full DNS record resolution (A, MX, NS, TXT, CNAME)
- WHOIS with key field extraction (registrar, dates, nameservers)
- IP geolocation via ipinfo.io (city, region, country, ASN)
- External port scan (top 20 ports, banner grabbing via nmap)
- All results logged to JSON for report integration

### Module 2 — SMB Network Auditor

Internal network SMB sweep with vulnerability detection:

- Auto-detects local subnet from `ip route` — no manual entry
- Runs `smb-os-discovery`, `smb-enum-shares`, `smb-security-mode`
- Checks for **MS17-010 (EternalBlue)** — the vulnerability behind WannaCry
- Checks for **MS10-054** SMB memory corruption
- Flags SMB signing disabled (relay attack vector)
- Parses all nmap output into structured host objects
- Generates full HTML audit report automatically

---

## Tested Environments

| Environment | Status |
|---|---|
| Ubuntu 22.04 / 24.04 (native) | ✅ Full support |
| Termux + Ubuntu proot (Android) | ✅ Full support |
| Samsung Galaxy A16 (4GB RAM) | ✅ Confirmed working |
| Kali Linux | ✅ Full support |
| Debian 11/12 | ✅ Full support |
| macOS (via Homebrew tools) | ⚠ Partial (nmap scripts may vary) |

---

## Roadmap

- [ ] Module 3 — Web Application Scanner (Nikto + SSL + headers)
- [ ] Module 4 — Subdomain brute-force with wildcard detection
- [ ] PDF report export
- [ ] Email delivery of completed reports
- [ ] API mode for integration into third-party platforms
- [ ] Caribbean & LatAm compliance mapping (local regulatory frameworks)

---

## Architecture

```
apex_recon_v2.py
│
├── Startup dependency check
├── Auto subnet detection (ip route / socket fallback)
│
├── Module 1: OSINT
│   ├── dig (DNS)
│   ├── whois
│   ├── curl → ipinfo.io (GeoIP)
│   └── nmap -F --script banner (ports)
│
└── Module 2: SMB Auditor
    ├── nmap -p 139,445 --script smb-*
    ├── parse_smb_output() → structured host objects
    ├── Risk classification engine
    └── generate_html_report() → apex_report_*.html
```

---

## Security & Ethics

ApexRecon is built exclusively for **authorized security auditing**.

- Always obtain written authorization before scanning any network you do not own
- This tool is designed for professional penetration testers, MSPs, and security auditors operating within legal scope
- All activity is logged with timestamps for compliance documentation
- The author and TrinTech Digital Defense accept no liability for unauthorized use

---

## License

MIT License — see [LICENSE](LICENSE) for full terms.

Free to use, modify, and integrate. Attribution appreciated.

---

## Author

**TrinTech Digital Defense**
Cybersecurity audit consultancy — Trinidad and Tobago

> *Built in the field. Tested on real networks. Designed for practitioners who work with what they have.*

[![GitHub](https://img.shields.io/badge/GitHub-trintechdigitaldefense-red?style=flat-square&logo=github)](https://github.com/trintechdigitaldefense)
[![Website](https://img.shields.io/badge/Web-trintechdigitaldefense.github.io-white?style=flat-square)](https://trintechdigitaldefense.github.io)

---

<div align="center">
<sub>ApexRecon v2.0 — TrinTech Digital Defense — Built for the field, not the boardroom.</sub>
</div>
