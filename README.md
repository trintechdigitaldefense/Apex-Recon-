# ApexRecon — R1 Recovery and Phase 2 Development

**TrinTech Digital Defense** · Authorized one-time network and web security assessment framework

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)

## Current development status

The R1 branches restore and stabilize the last complete executable v2.0 baseline. The historical v2.1.0 entry point on `main` was incomplete; this development branch is rebuilding web-assessment capabilities in separately tested stages rather than claiming the missing v2.1 features are operational.

## Available recovered modules

### 1. External OSINT
- DNS lookups using `dig`
- WHOIS collection
- IP geolocation via ipinfo.io
- Quick external port and banner scan using `nmap`

### 2. Local network SMB auditor
- Local subnet discovery using actual route/interface prefix information
- SMB host and share enumeration using Nmap scripts
- SMB signing and selected legacy SMB vulnerability checks
- Structured host findings and HTML reporting

## Phase 2 — Web assessment reconstruction

### Milestone 2A: HTTP security assessment (in development)
A separate standard-library engine in `apex_web.py` performs up to two read-only GET requests against one supplied hostname/path to assess:
- HTTP-to-HTTPS redirect behavior
- HSTS, CSP, MIME-sniffing, clickjacking, Referrer-Policy and Permissions-Policy headers
- Secure, HttpOnly and SameSite attributes on observed cookies
- Server and X-Powered-By disclosure

Milestone 2A is integrated into the interactive CLI as menu option 3 and writes a dedicated, self-contained HTML assessment report. The engine does not crawl, fuzz, submit forms, authenticate, exploit, or perform background monitoring. TLS certificate/protocol checks and CMS identification are later milestones. The integration is under review in the Phase 2B draft PR.

See [Phase 2 HTTP assessment scope and limitations](docs/PHASE2_HTTP_ASSESSMENT.md).

## R1 stabilization and privacy

- Input validation for hostnames, IP addresses, and bounded IP/CIDR ranges.
- Explicit operator confirmation of written authorization for each existing scan scope.
- Subprocess execution uses argument lists, no shell, non-interactive stdin, and finite timeouts.
- Untrusted scan data is escaped before insertion into HTML reports.
- OSINT geolocation sends the resolved target IP to ipinfo.io; do not use that module where disclosure is prohibited.
- Logs and generated HTML reports use owner-only permissions (0600) on supported POSIX filesystems.

## Requirements

- Python 3.10 or newer
- Linux or Termux environment
- Existing recovered modules require `nmap`, `whois`, `dig` (dnsutils), and `curl`.
- The new HTTP assessment engine uses only the Python standard library.

## Run recovered CLI

```bash
python3 apex_recon_v2.py
```

## Test without scanning

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q apex_recon_v2.py apex_web.py tests
```

The test suite uses synthetic Nmap output, synthetic HTTP headers, and mocked network calls. It does not contact real targets.

## Authorized use and operational boundaries

ApexRecon is an operator-initiated, one-time assessment tool for assets owned by the operator or covered by explicit written permission. Confirm authorization for the exact target and scope before any live assessment. Do not use against third-party systems without permission.

No recurring scans, background agents, unattended monitoring, or 24-hour operation are introduced. CI and unit tests do not establish live accuracy, platform compatibility, client readiness, or release approval.

## Current limitations

- The v2.1 web assessment engine is being reconstructed in stages; only the isolated HTTP-header milestone is present in this branch.
- The HTTP integration/report work is in a separate draft PR and has not been merged or phone-validated.
- TLS certificate, protocol and cipher assessment is not included yet.
- CMS fingerprinting and technology identification are not included yet.
- Native PDF export is not implemented; the current recovered report is HTML.
- Legacy SMB vulnerability checks are indicators and require independent verification.
- No multi-tenant service, scheduling, continuous monitoring, or unattended 24-hour operation is provided.

## Validation references

- [Phone-only validation procedure](docs/PHONE_ONLY_VALIDATION.md)
- [R1 source review and known limitations](docs/R1_SOURCE_REVIEW.md)
- [Phase 2 HTTP assessment scope](docs/PHASE2_HTTP_ASSESSMENT.md)

No merge, production release, or client deployment is authorized by this development branch.
