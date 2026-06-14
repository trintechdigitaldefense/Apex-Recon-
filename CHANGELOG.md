# Changelog

All notable changes to ApexRecon are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [2.0.0] — 2026-06-14

### The Enterprise Rebuild

v2.0 is a ground-up upgrade focused on three things: structured output,
vulnerability detection, and client-ready reporting. This is the version
built for professional engagements.

### Added
- **Module 1: External OSINT** — fully implemented
  - DNS enumeration (A, MX, NS, TXT, CNAME records via `dig`)
  - WHOIS lookup with key field extraction
  - IP geolocation via ipinfo.io (city, region, country, ASN)
  - External port scan with banner grabbing (nmap `-F --script banner`)
  - All results logged to JSON for traceability
- **Auto subnet detection** — reads local interface via `ip route`,
  falls back to `socket.gethostbyname()` — no manual IP entry required
- **Vulnerability detection** — two critical SMB CVEs now checked:
  - `smb-vuln-ms17-010` — EternalBlue (WannaCry vector)
  - `smb-vuln-ms10-054` — SMB memory corruption
- **SMB signing detection** — flags disabled signing as relay attack vector
- **Output parser** (`parse_smb_output()`) — converts raw nmap stdout into
  structured host objects: IP, hostname, OS, shares, signing, vuln flags
- **Risk classification engine** — auto-assigns LOW / MEDIUM / HIGH / CRITICAL
  per host based on detected findings
- **HTML report generator** — dark-themed, self-contained
  `apex_report_YYYYMMDD_HHMMSS.html` produced after every SMB scan
  - Executive summary: total hosts, critical count, clean count
  - Per-host cards with full finding breakdown
  - Color-coded severity indicators
  - Client-ready — no technical background required to read
- **Startup dependency checker** — validates nmap, whois, dig, curl on launch
  with exact `apt-get` install commands for anything missing
- **`run_cmd()` utility** — unified subprocess wrapper with timeout handling
  and `FileNotFoundError` protection across all modules
- **ANSI risk badges** — `RISK_HIGH`, `RISK_MED`, `RISK_LOW`, `RISK_INFO`
  applied consistently across terminal output

### Changed
- SMB nmap command upgraded from 2-script to 5-script suite
  (`smb-os-discovery`, `smb-enum-shares`, `smb-security-mode`,
  `smb-vuln-ms17-010`, `smb-vuln-ms10-054`)
- Main menu now shows module descriptions beneath each option
- All subprocess calls use `-T4` timing for faster field scans
- Log entries now include structured JSON data alongside raw output

### Fixed
- Module 1 was previously a stub — now fully operational
- Raw nmap output no longer dumped unfiltered to terminal;
  parsed and displayed as structured findings

---

## [1.0.0] — 2026-05-01

### Initial Release

First working build of ApexRecon. Proof of concept for a mobile-first
network audit framework running entirely within Termux-Ubuntu proot
on Android hardware.

### Added
- ASCII banner with TrinTech Digital Defense branding
- ANSI color palette (RED, DARK_RED, WHITE, GREY)
- `log_activity()` — timestamped persistent audit log (`apex_recon.log`)
- `print_banner()` — cross-platform terminal clear + banner render
- **Module 2: SMB Auditor** (initial build)
  - Manual IP / subnet input with blank-input validation
  - nmap scan: `-Pn --open -p 139,445`
  - Scripts: `smb-os-discovery`, `smb-enum-shares`
  - `--open` flag to filter inactive hosts
  - Raw stdout displayed to terminal
  - Full output written to audit log with scan duration
  - `FileNotFoundError` handling with install hint
- Interactive main menu with module selection loop
- Clean session exit with log entry on quit

### Known Limitations (resolved in v2.0)
- Module 1 (OSINT) listed in menu but not implemented
- No output parsing — raw nmap text only
- No HTML report generation
- No vulnerability detection (CVE checks)
- No subnet auto-detection — manual IP entry only
- No dependency validation on startup

---

## Upcoming — [2.1.0]

- Module 3: Web Application Scanner
  - Nikto integration
  - SSL/TLS certificate analysis
  - HTTP security header audit
  - CMS fingerprinting
- PDF export for HTML reports
- Email delivery of completed reports on scan finish

## Upcoming — [3.0.0]

- Module 4: Subdomain brute-force with wildcard detection
- API mode for third-party platform integration
- Caribbean & LatAm regulatory compliance mapping
- Multi-target batch scanning with consolidated report

---

*ApexRecon is actively maintained by TrinTech Digital Defense.*
*Trinidad and Tobago — https://trintechdigitaldefense.github.io*
