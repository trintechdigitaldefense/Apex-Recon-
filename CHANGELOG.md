# Changelog

## [2.0.1-dev] — Phase 2I unified engagement reporting

### Added
- Added an offline engagement builder combining the four supported ApexRecon module result types under one UUID.
- Added per-module status, target scope, timestamps, duration, finding counts and limitations, including explicit NOT_RUN and FAILED states.
- Consolidated normalized findings and transparent severity counts without calculating a composite risk score.
- Added canonical SHA-256 integrity verification and exclusive JSON/PDF export with owner-only POSIX permissions.
- Added optional native PDF generation through the existing ReportLab dependency.
- Added offline tests for completeness, module status, validation, checksum tampering, export exclusivity and PDF rendering.

### Boundaries
- This phase adds the aggregation and export API; it does not yet orchestrate all four interactive CLI modules in one run.
- No scan commands, network requests, authorization gates or target interaction changed.
- No live targets contacted; no digital signature, immutable vault, central storage, recurring scans or background monitoring.
- Draft development only; no merge, release or client deployment.

# [2.0.1-dev] — Phase 2H SMB and OSINT finding integration

### Added
- Adapted existing SMB parser results to the shared finding schema while preserving legacy host fields and risk presentation.
- Added explicit UNKNOWN / UNASSESSED records for missing or unrecognized required SMB checks.
- Adapted collected OSINT DNS, WHOIS metadata, geolocation-provider metadata and top-20 TCP port observations to common-schema INFO records.
- Kept OSINT data as observations; no vulnerability claims are inferred from collection output.
- Added offline adapter and parser-integration tests.

### Boundaries
- No scan commands, request counts, target scope, authorization gates or network behavior changed.
- No live targets contacted; no new OSINT export, combined engagement report, risk scoring, recurring scans or background monitoring.
- Draft development only; no merge, release or client deployment.


## [2.0.1-dev] — Phase 2G common finding schema

### Added
- Shared versioned finding normalization for HTTP and TLS assessment observations.
- Stable finding identifiers and explicit source module, confidence, and evidence-type fields.
- Evidence JSON export preserves the normalized finding metadata.
- Conservative normalization: unsupported severity/confidence/evidence-type values become UNKNOWN rather than being promoted.
- Offline tests for schema validation, stable identifiers, metadata preservation and module integration.

### Boundaries
- SMB free-text findings and OSINT raw collection are not yet migrated to the common finding schema.
- No new network requests, scan scope, or target interaction.
- No combined engagement report, automatic risk scoring, recurring scans, or background monitoring.
- Draft PR only; no merge, release or client deployment.


## [2.0.1-dev] — Phase 2F evidence quality and export reliability

### Added
- Evidence-record checksum verification before JSON export and PDF rendering.
- Strict UUID validation for assessment evidence IDs.
- URL sanitization that removes embedded user information, query strings and fragments, including relative URL query data; malformed URLs fail closed.
- Graceful PDF-generation and PDF-write failure handling that preserves the JSON evidence artifact and reports the PDF error.
- Offline tests for checksum tampering, URL secret redaction, invalid UUIDs and partial export recovery.

### Boundaries
- No network behavior or scan scope changes; no live targets contacted.
- No merge, release or client deployment.

## [2.0.1-dev] — Phase 2E professional reporting and evidence

### Added
- Versioned JSON evidence records for HTTP and TLS assessments with UUID, scope, timestamps, duration, findings, fingerprints, provenance and limitations.
- SHA-256 checksum over the canonical assessment record, explicitly documented as a checksum rather than a signature or immutable-storage guarantee.
- Native PDF report generation through optional ReportLab support; JSON export remains standard-library-only.
- Exclusive artifact creation and owner-only file permissions (0600) on supported POSIX systems.
- CLI integration that writes JSON evidence and attempts native PDF output after HTTP/TLS HTML reports.
- Offline tests for evidence schema, checksum, query-secret exclusion, exclusive creation and permissions.

### Boundaries
- No changes to network request behavior; no live targets contacted.
- Phase 2E packages HTTP and TLS results separately; it does not merge separate runs or add comparison, signing, central storage, scheduling or background monitoring.
- Native PDF requires the optional `requirements-pdf.txt` dependency.
- Draft development only; no merge, release or client deployment.


All notable changes to ApexRecon are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [2.0.1-dev] — Phase 2D development

### Added
- Passive CMS fingerprints for WordPress, Joomla, Drupal, Shopify, Wix and Squarespace.
- Frontend technology fingerprints for React, Vue.js, Angular, jQuery and Bootstrap.
- Evidence markers, confidence labels and optional CMS version only when an explicit generator meta tag provides a numeric version.
- Bounded HTML sampling from existing HTTP responses: 8 KiB per response, at most 16 KiB total across no more than two GET requests.
- Fingerprint section in the escaped standalone HTTP HTML report.
- Offline tests for fingerprint evidence, confidence, body-size bounds and report escaping.

### Boundaries
- No extra requests, URL paths, crawling, admin-path probes, fuzzing, authentication, exploitation or background monitoring.
- Fingerprints are heuristic observations, not proof of installed components or a complete software inventory.
- Phase 2D remains a draft and requires CI and phone validation; no live target testing is included.

## [2.0.1-dev] — Unreleased (R1 Source Recovery and Stabilization)

### Phase 2 — HTTP assessment milestone 2A
- Add a standalone standard-library HTTP assessment engine for HTTP-to-HTTPS behavior, common security headers, observed cookie flags, and server-header disclosure.
- Bound the module to two read-only GET requests, standard ports, finite timeouts, query-string removal, and same-host redirects.
- Add isolated synthetic/mocked regression coverage and document current scope and limitations.
- Keep the engine separate from the interactive CLI until the evidence model is reviewed; no live scan or client-readiness claim is made.

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
- Preserve an HTML report when a completed SMB command returns output but no hosts with open SMB ports are parsed.

### Phase 1 validation and review
- Expanded the standard-library regression suite to cover IPv4/IPv6 OSINT resolution, bounded quick-port selection, multiple-host parser isolation, empty SMB results, and unassessed reporting.
- Added a phone-only validation procedure for Android using the existing Ubuntu/Termux environment.
- Added a documented R1 source review with remaining limitations and release gates.
- Extended pull-request CI to validate changes targeting the R1 development branch.
- Retained the distinction between mocked tests, platform validation, and authorized live-network accuracy testing.

### Validation
- Added regression tests for evidence confidence, incomplete checks, potential indicators, IPv6 parsing, report wording, time zone offsets and permissions.
- GitHub Actions validates Python 3.10–3.12 and Linux dependency detection. These checks do not prove live scan accuracy or client readiness.

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


## Phase 2B — HTTP CLI and report integration (development)
- Add HTTP Security Assessment as interactive menu option 3.
- Require the existing exact-scope written-authorization attestation before network requests.
- Add a dedicated responsive HTML report with escaped evidence, severity counts, remediation guidance, scope notes and explicit limitations.
- Preserve the legacy SMB report path and existing OSINT/SMB menu behavior.
- Add mocked regression tests for authorization gating, CLI integration, report escaping and private report permissions.
- No live target scans, merge, release or deployment are included.


## Phase 2C — Verified TLS assessment (development)
- Add a separate TLS assessment module using one TCP/443 connection and one certificate-verified TLS handshake.
- Preserve system trust-chain and hostname verification; do not use an unverified fallback.
- Report certificate subject/issuer, returned SANs, validity/expiry and negotiated protocol/cipher.
- Classify certificate expiry within 7 days as HIGH and within 30 days as MEDIUM.
- Add an operator authorization gate for the exact host:443 scope and a separate escaped, owner-only HTML report.
- Explicitly limit interpretation to the one negotiated client/server session; do not claim a complete server protocol/cipher inventory.
- Add offline mocked socket/SSL and CLI integration tests. No live target was contacted.
