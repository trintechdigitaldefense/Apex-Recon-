# ApexRecon R1 — source recovery review

**Review scope:** recovered v2.0 executable baseline and R1 stabilization changes  
**Development branch:** r1-source-recovery-stabilization  
**Release status:** Not client-release ready; no merge or deployment approval is implied by this review.

## Findings addressed in the R1 source

| Area | Review result |
|---|---|
| Target validation | OSINT accepts a hostname/IP; SMB accepts IP/CIDR targets and caps ranges at 4,096 addresses. |
| Authorization | Each assessment requires the operator to type the exact confirmation YES for the displayed scope. This is an operator attestation, not independent verification of a written authorization document. |
| Command execution | Commands are passed as argument arrays with shell execution disabled, stdin closed, and finite validated timeouts capped at 600 seconds. |
| Network discovery | The subnet helper uses actual route/interface prefix data rather than assuming a /24. Current automatic interface discovery is IPv4-focused. |
| SMB evidence parsing | Explicit NOT VULNERABLE, potential indicators, positive NSE indicators and missing results are distinct states. Missing required checks do not produce a LOW-risk classification. |
| Address parsing | Nmap host labels support IPv4 and IPv6, including bare addresses and hostname-plus-address output. |
| Report timestamps | HTML report timestamps include the system's local UTC offset rather than a hard-coded UTC label. |
| Report language | NSE output is described as an indicator requiring independent verification; the report no longer claims that an NSE indicator proves remote code execution. |
| Summary/reporting | Low-risk and unassessed hosts are counted separately. A completed SMB command that returns parseable output but no open SMB hosts still produces an HTML record. |
| Report safety | Scan-derived text is HTML-escaped. Reports and audit logs use owner-only POSIX permissions (0600) where supported. Remote web fonts have been removed. |
| OSINT consistency | Geolocation resolution supports IPv4/IPv6; the external quick scan now uses an explicit top-20-port selection matching its description. |

## Data disclosure

The OSINT geolocation step sends the resolved target IP address to the third-party ipinfo.io API. The current implementation does not provide an independent toggle for this lookup. Do not use this option where third-party disclosure is prohibited; obtain client approval and document the data flow.

## Existing capabilities in the recovered baseline

- DNS queries for A, AAAA, MX, NS, TXT, CNAME, SOA and CAA records.
- WHOIS collection.
- IP geolocation via ipinfo.io.
- A bounded Nmap external quick port/banner scan.
- Local SMB enumeration and selected SMB security/vulnerability script checks.
- Responsive, self-contained HTML reporting and local audit logging.

## Residual limitations

1. The recovered source is based on the last complete v2.0 implementation. The v2.1 web application scanner, TLS assessment module, CMS fingerprinting, configuration system and SMTP delivery are not restored in this baseline.
2. Native PDF report generation is not implemented. Browser print-to-PDF is a browser function, not an ApexRecon PDF export engine.
3. Automatic subnet discovery is IPv4-focused. Explicit IPv6 network inputs and parser output are supported, but broader IPv6 route/interface discovery needs separate validation.
4. SMB checks are limited to the selected Nmap scripts and evidence they return. They are not a comprehensive vulnerability assessment, and an NSE indicator is not independent exploit confirmation.
5. The tool does not yet produce a complete machine-readable assessment package with immutable evidence provenance and report-to-report comparison.
6. OSINT lookups and port scanning are separate network actions. Operators must understand the third-party GeoIP disclosure and obtain permission for active network probing.
7. If Nmap returns no output (for example, command failure or timeout), the current flow reports the problem in the terminal and does not create a completed assessment report. A normal parsed result with no open SMB hosts does create a report.
8. The HTML report is responsive, but the current operator interface is CLI-based rather than a dedicated mobile web application.

## Validation boundary

- Unit tests and GitHub Actions validate local behavior using synthetic data and mocked subprocess calls.
- The Linux dependency smoke test validates dependency detection/import behavior.
- Phone-only validation must be performed by the operator using the documented procedure.
- None of these checks establishes live-network scan accuracy, performance on all devices, client readiness or 24-hour availability.

## Release gates still required

- Execute the phone-only procedure on the supported Android/Ubuntu environment and record the exact commit and output.
- Conduct separate, authorized and controlled network validation for each supported assessment module.
- Review third-party data handling, report integrity, logging and failure cases.
- Reconstruct and test the missing v2.1 modules in separate pull requests.
- Complete an independent security and client-readiness review.

ApexRecon remains a technician-operated, one-time assessment platform. No background scanning, recurring unattended assessments or always-on agent is part of this R1 scope.
