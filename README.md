# ApexRecon — R1 Recovery and Phase 2 Development

**TrinTech Digital Defense** · Authorized one-time network and web security assessment framework

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)

## Current development status

The R1 branches restore and stabilize the last complete executable v2.0 baseline. The historical v2.1.0 entry point on `main` was incomplete; the development branches are rebuilding web-assessment capabilities in separately tested stages rather than claiming missing features are operational.

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

### Milestone 2A/2B: HTTP security assessment and CLI/report integration (draft PR)
A separate standard-library engine in `apex_web.py` performs up to two read-only GET requests against one supplied hostname/path to assess:
- HTTP-to-HTTPS redirect behavior
- HSTS, CSP, MIME-sniffing, clickjacking, Referrer-Policy and Permissions-Policy headers
- Secure, HttpOnly and SameSite attributes on observed cookies
- Server and X-Powered-By disclosure

Phase 2A provides the bounded HTTP engine and Phase 2B integrates it as menu option 3 with a dedicated HTML report. Phase 2C adds menu option 4 for one verified TLS handshake on TCP/443, certificate expiry/identity observations, and negotiated protocol/cipher reporting. Phase 2D extends menu option 3 with passive CMS and frontend technology fingerprints from response headers and at most 16 KiB of HTML across the existing two-request limit. Fingerprints include evidence markers and confidence; versions are reported only from an explicit numeric CMS generator tag. No extra paths or requests are introduced. The modules do not crawl, fuzz, submit forms, authenticate, exploit, or perform background monitoring. The HTTP, TLS and fingerprinting changes remain stacked development drafts until reviewed and validated.

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
- The HTTP and TLS assessment engines use only the Python standard library.

## Run recovered CLI

```bash
python3 apex_recon_v2.py
```

## Test without scanning

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q apex_recon_v2.py apex_web.py apex_tls.py tests
```

The test suite uses synthetic Nmap output, synthetic HTTP headers, and mocked network calls. It does not contact real targets.

## Authorized use and operational boundaries

ApexRecon is an operator-initiated, one-time assessment tool for assets owned by the operator or covered by explicit written permission. Confirm authorization for the exact target and scope before any live assessment. Do not use against third-party systems without permission.

No recurring scans, background agents, unattended monitoring, or 24-hour operation are introduced. CI and unit tests do not establish live accuracy, platform compatibility, client readiness, or release approval.

## Current limitations

- The v2.1 web assessment engine is being reconstructed in stages; HTTP headers, a single verified TLS handshake, and bounded passive CMS/technology fingerprinting are implemented in separate development milestones.
- The HTTP, TLS and fingerprinting CLI/report work is in stacked draft PRs; Phase 2C has passed local phone validation, while Phase 2D still requires CI and phone validation.
- TLS assessment is a one-handshake observation only; it does not enumerate all server-supported protocol versions or ciphers.
- CMS and frontend technology fingerprinting is heuristic and limited to markers in the bounded HTML sample and response headers; it is not a complete software inventory.
- Native PDF export is not implemented; the current recovered report is HTML.
- Legacy SMB vulnerability checks are indicators and require independent verification.
- No multi-tenant service, scheduling, continuous monitoring, or unattended 24-hour operation is provided.

## Validation references

- [Phone-only validation procedure](docs/PHONE_ONLY_VALIDATION.md)
- [R1 source review and known limitations](docs/R1_SOURCE_REVIEW.md)
- [Phase 2 HTTP assessment scope](docs/PHASE2_HTTP_ASSESSMENT.md)

No merge, production release, or client deployment is authorized by this development branch.

- [Phase 2C verified TLS assessment scope](docs/PHASE2C_TLS_ASSESSMENT.md)

- [Phase 2D passive CMS and technology fingerprinting](docs/PHASE2D_CMS_TECHNOLOGY_FINGERPRINTING.md)
