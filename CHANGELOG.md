# Changelog

All notable changes to ApexRecon are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [2.0.1-dev] — Unreleased (R1 Source Recovery and Stabilization)

### Recovered
- Restored the last complete executable v2.0 implementation from commit `086eb48` after confirming that the v2.1.0 entry point on `main` is truncated.
- Kept the restored baseline explicit: the v2.1 web scanner and SMTP/config features are not represented as available until their complete source can be recovered or rebuilt and tested.

### Security and reliability
- Added hostname/IP/CIDR validation and an explicit written-authorization confirmation gate before scanning.
- Bounded SMB scan ranges to 4,096 addresses.
- Hardened subprocess invocation with no shell, non-interactive stdin, and validated timeouts.
- Replaced guessed /24 subnet construction with actual route/interface prefix parsing.
- Escaped untrusted scan data in HTML reports.
- Reduced the default Nmap timing template to T3.

### Accuracy and reporting confidence
- Distinguish Nmap NSE vulnerability indicators from confirmed vulnerabilities; require independent verification before claiming exploitability.
- Represent potential indicators separately from positive indicators and explicit NOT VULNERABLE results.
- Mark hosts with missing SMB security or vulnerability-check results as UNASSESSED rather than LOW risk.
- Show missing vulnerability-script results as NOT TESTED / NO RESULT instead of Clean.
- Parse both IPv4 and IPv6 Nmap host labels.
- Use the actual local timezone offset in report timestamps.
- Rename the summary count from "Clean Hosts" to "Low-Risk Hosts".
- Support IPv4 and IPv6 address resolution for the OSINT geolocation lookup.
- Match the external quick-port-scan description to the actual Nmap scope by selecting the top 20 ports.
- Show unassessed hosts as a separate report summary count.

### Validation
- Added regression tests for evidence confidence, incomplete checks, potential indicators, IPv6 parsing, report wording and permissions.
- Added standard-library unit tests and GitHub Actions matrix validation for Python 3.10–3.12.

---

## [2.1.0] — 2026-09-29

### Web Application Scanner Release

v2.1 adds a full Web Application Scanner module while keeping the single-file, Termux-first design.

### Added
- **Module 3: Web Application Scanner**
  - SSL/TLS certificate inspection (protocol, cipher, expiry, days remaining, SAN, issuer)
  - Security headers audit (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-XSS-Protection, COOP, CORP)
  - CMS fingerprinting (WordPress, Joomla, Drupal, Magento, Shopify, Wix, Squarespace)
  - Technology detection (Server, X-Powered-By, React/Vue/Angular/jQuery)
  - Common CMS admin path probes
  - Optional Nikto integration (quick mode when installed)
- **Config system** — `~/.apexrecon/config.json` for email, timeouts, user-agent
- **Optional email delivery** of finished HTML reports via SMTP
- Enhanced HTML report with dedicated Web findings section
- Dependency checker now includes `openssl` and optional `nikto`
- Risk badges for CRITICAL findings

### Changed
- Main menu updated with Module 3 and "NEW" indicator
- Report generator accepts unified data structure (hosts + web)
- Version string and branding updated throughout

### Fixed
- Minor parsing edge cases in SMB output handling carried forward

---

## [2.0.0] — 2026-06-14

### The Enterprise Rebuild

v2.0 is a ground-up upgrade focused on structured output, vulnerability detection, and client-ready reporting.

### Added
- External OSINT — DNS, WHOIS, geolocation and external port scanning.
- SMB auditing — subnet discovery, SMB enumeration, signing and selected vulnerability checks.
- Structured output parsing, risk classification, HTML report generation and dependency checks.
- Unified subprocess wrapper with timeout and missing-dependency handling.

---

## [1.0.0] — 2026-05-01

### Initial Release
- Initial Termux-first SMB audit proof of concept.
- Interactive CLI, timestamped audit logging and basic Nmap SMB enumeration.
