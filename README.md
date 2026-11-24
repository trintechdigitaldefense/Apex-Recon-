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

Phase 2A provides the bounded HTTP engine and Phase 2B integrates it as menu option 3 with a dedicated HTML report. Phase 2C adds menu option 4 for one verified TLS handshake on TCP/443, certificate expiry/identity observations, and negotiated protocol/cipher reporting. Phase 2D extends menu option 3 with passive CMS and frontend technology fingerprints from response headers and at most 16 KiB of HTML across the existing two-request limit. Fingerprints include evidence markers and confidence; versions are reported only from an explicit numeric CMS generator tag. No extra paths or requests are introduced. The modules do not crawl, fuzz, submit forms, authenticate, exploit, or perform background monitoring. The HTTP, TLS and fingerprinting changes are implemented in the stacked development branches. They remain outside `main` and are not a production or client-ready release.

### Milestone 2E: professional reporting and evidence (draft PR)
HTTP and TLS assessment runs now produce a versioned JSON evidence record with a unique assessment ID, scope, timestamps, duration, findings, fingerprint confidence, provenance, limitations and a SHA-256 assessment checksum. When optional ReportLab support is installed, ApexRecon also creates a native PDF report. Artifacts use exclusive file creation and owner-only permissions on POSIX systems. The checksum is not a digital signature or immutable storage guarantee. See [Phase 2E reporting and evidence](docs/PHASE2E_PROFESSIONAL_REPORTING_EVIDENCE.md).

### Milestone 2F: evidence quality and export reliability (draft PR)
Phase 2F adds checksum verification before evidence is exported or rendered, stricter assessment UUID validation, URL credential/query/fragment redaction, and graceful handling of PDF-generation failures so a valid JSON evidence artifact remains available. The work is offline-testable and does not add scan requests or alter target interaction.

See [Phase 2F evidence reliability](docs/PHASE2F_EVIDENCE_RELIABILITY.md).


### Milestone 2G: common finding schema (draft PR)
Phase 2G introduces a shared, versioned finding structure for the HTTP and TLS modules. Findings now carry a stable identifier, source module, severity, status, confidence, evidence type, evidence text and remediation recommendation. Unknown values remain UNKNOWN; the normalizer does not promote severity or infer exploitability. JSON evidence exports preserve the normalized metadata. The existing SMB parser still uses legacy free-text findings and OSINT remains a raw collection workflow, so neither is represented as fully migrated by this milestone. See [Phase 2G cross-module finding consistency](docs/PHASE2G_CROSS_MODULE_FINDINGS.md).

### Milestone 2H: SMB and OSINT finding integration (draft PR)
Phase 2H adapts existing SMB parser fields and already-collected OSINT datasets into the Phase 2G common finding schema. SMB signing, share and Nmap NSE status records retain conservative classifications; missing checks remain UNKNOWN / UNASSESSED. OSINT DNS, WHOIS metadata, geolocation-provider metadata and observed top-20 TCP ports are represented as INFO observations, not vulnerability claims. Existing scan commands and authorization gates are unchanged. See [Phase 2H SMB and OSINT finding integration](docs/PHASE2H_SMB_OSINT_FINDINGS.md).


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

## Check installation and run ApexRecon

Run the local dependency diagnostic before the first assessment:

```bash
python3 apex_doctor.py
```

For machine-readable output use `python3 apex_doctor.py --json`. Use `--strict` to require every listed external and optional dependency.

Then start the recovered CLI:

```bash
python3 apex_recon_v2.py
```

## Test without scanning

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q apex_storage.py apex_doctor.py apex_recon_v2.py apex_web.py apex_tls.py apex_fingerprint.py apex_evidence.py apex_findings.py apex_finding_adapters.py apex_engagement.py apex_engagement_cli.py apex_signing.py apex_audit.py tests
```

The test suite uses synthetic Nmap output, synthetic HTTP headers, and mocked network calls. It does not contact real targets.

## Authorized use and operational boundaries

ApexRecon is an operator-initiated, one-time assessment tool for assets owned by the operator or covered by explicit written permission. Confirm authorization for the exact target and scope before any live assessment. Do not use against third-party systems without permission.

No recurring scans, background agents, unattended monitoring, or 24-hour operation are introduced. CI and unit tests do not establish live accuracy, platform compatibility, client readiness, or release approval.

## Current limitations

- The v2.1 web assessment engine is being reconstructed in stages; HTTP headers, a single verified TLS handshake, and bounded passive CMS/technology fingerprinting are implemented in separate development milestones.
- Phase 2A through Phase 2S have been merged into their respective development branches. They remain outside `main` and have not been released or deployed. Phase 2T improved HTTP header-value accuracy and response classification. Phase 2U improved HTTP evidence traceability and report consistency. Phase 2V adds conservative finding triage metadata and recommendation-presence reporting. Phase 2W calibrates passive fingerprint confidence and improves CMS generator metadata parsing. Phase 2X distinguishes unavailable assessment results from security findings.
- TLS assessment is a one-handshake observation only; it does not enumerate all server-supported protocol versions or ciphers.
- CMS and frontend technology fingerprinting is heuristic and limited to markers in the bounded HTML sample and response headers; it is not a complete software inventory.
- Native PDF export for HTTP/TLS assessments is optional and requires ReportLab; the legacy SMB report remains HTML.
- Legacy SMB vulnerability checks are indicators and require independent verification.
- No multi-tenant service, scheduling, continuous monitoring, or unattended 24-hour operation is provided.

## Validation references

- [Phone-only validation procedure](docs/PHONE_ONLY_VALIDATION.md)
- [R1 source review and known limitations](docs/R1_SOURCE_REVIEW.md)
- [Phase 2 HTTP assessment scope](docs/PHASE2_HTTP_ASSESSMENT.md)

No merge into `main`, production release, or client deployment is authorized by this development branch.

- [Phase 2C verified TLS assessment scope](docs/PHASE2C_TLS_ASSESSMENT.md)

- [Phase 2D passive CMS and technology fingerprinting](docs/PHASE2D_CMS_TECHNOLOGY_FINGERPRINTING.md)


### Milestone 2I: unified engagement reporting (draft PR)
Phase 2I adds a standalone engagement packaging layer that combines supplied OSINT, SMB, HTTP and TLS module results under one engagement UUID. It tracks each module as COMPLETED, PARTIAL, FAILED or NOT_RUN, preserves per-module target scope and limitations, consolidates normalized findings, and reports severity counts without inventing a composite risk score. JSON and optional ReportLab PDF exports use exclusive file creation and owner-only POSIX permissions. The builder remains an offline aggregation API; Phase 2J connects it to an operator-driven CLI workflow. See [Phase 2I unified engagement reporting](docs/PHASE2I_UNIFIED_ENGAGEMENT_REPORTING.md).


### Milestone 2J: unified CLI engagement integration (draft PR)
Phase 2J connects the Phase 2I report builder to main-menu option 5. Operators can select all or a subset of OSINT, SMB, HTTP and TLS modules. Each selected module retains its existing target validation and written-authorization prompt. The workflow records unselected and selected-but-not-run modules as NOT_RUN, preserves module findings and limitations, and exports one combined JSON report plus an optional PDF. Individual module menu options remain available. See [Phase 2J unified CLI engagement integration](docs/PHASE2J_UNIFIED_CLI_ENGAGEMENT.md).


### Milestone 2K: unified engagement reliability (draft PR)
Phase 2K hardens the unified engagement workflow so a failure in one selected module does not prevent later selected modules from running or discard valid results from other modules. Module outputs are validated independently for status, scope, findings, duration, limitations and timestamps. Invalid outputs are represented as FAILED with an explicit limitation; unselected and selected-but-not-run modules remain distinct. The work does not change scan commands, authorization gates, target scope or network behavior. See [Phase 2K engagement reliability](docs/PHASE2K_ENGAGEMENT_RELIABILITY.md).


### Milestone 2L: unified engagement report quality (draft PR)
Phase 2L makes operator feedback callbacks non-blocking and expands the unified PDF to show engagement and per-module scope, timestamps, limitations, status counts, and finding evidence metadata. The PDF remains a presentation of supplied assessment outputs and does not independently verify scan completeness or accuracy. See [Phase 2L engagement report quality](docs/PHASE2L_ENGAGEMENT_REPORT_QUALITY.md).


### Milestone 2M: assessment evidence integrity and report verification (draft PR)
Phase 2M verifies engagement structure and internal count consistency in addition to the canonical SHA-256 checksum. It rejects duplicate finding IDs, malformed or incomplete module records, mismatched summaries and findings attributed to NOT_RUN modules. PDF metadata carries the engagement UUID and JSON checksum to help correlate the two artifacts; it does not sign or checksum the PDF. See [Phase 2M evidence integrity and report verification](docs/PHASE2M_EVIDENCE_INTEGRITY_VERIFICATION.md).


### Milestone 2N: cryptographic evidence signing and verification (draft PR)
Phase 2N adds optional detached Ed25519 signatures for verified engagement JSON records. Operators can generate encrypted private/public key pairs, sign an existing engagement export, and verify signatures offline from the main menu. Private keys are encrypted and owner-only; public-key fingerprints must be trusted out of band. Signatures cover the canonical JSON record, not the PDF bytes, and do not prove assessment accuracy or authorization. See [Phase 2N cryptographic evidence signing](docs/PHASE2N_CRYPTOGRAPHIC_EVIDENCE_SIGNING.md).

### Milestone 2O: evidence verification workflow and audit trail (draft PR)
Phase 2O records key-pair creation, engagement signing and signature verification outcomes in a local JSONL audit trail. Events are hash-chained, sequentially numbered, timezone-aware and written with owner-only permissions on POSIX systems. The CLI can verify the complete chain and refuses to extend a damaged trail. This is tamper-evident local logging, not immutable storage; preserve chain-head checkpoints independently for stronger assurance. No scan behavior or target interaction changes. See [Phase 2O evidence verification and audit trail](docs/PHASE2O_EVIDENCE_VERIFICATION_AUDIT_TRAIL.md).


### Milestone 2P: audit backup, independent checkpoints and recovery (draft PR)
Phase 2P adds offline export of the Phase 2O audit trail into a portable JSON backup, a detached SHA-256 checkpoint, complete backup verification, and create-only restore with post-write verification. Store the checkpoint separately from the backup for recovery assurance. The checkpoint is unkeyed and is not immutable or a digital signature. No scan behavior, network requests or background work are introduced. See [Phase 2P audit backup and recovery](docs/PHASE2P_AUDIT_BACKUP_RECOVERY.md).

### Milestone 2Q: signed audit backup checkpoints (draft PR)
Phase 2Q adds detached Ed25519 signatures over the exact canonical Phase 2P checkpoint bytes. Signing first verifies the backup/checkpoint pair; verification checks the backup chain, signature, public-key fingerprint and caller-supplied independently trusted fingerprint. Operators can use the encrypted Ed25519 private key from Phase 2N. A signature authenticates possession of the corresponding key, not a person, organization, event truthfulness or assessment accuracy. See [Phase 2Q signed audit backup checkpoints](docs/PHASE2Q_SIGNED_AUDIT_BACKUPS.md).


### Milestone 2R: HTTP redirect scope hardening (draft PR)
Phase 2R hardens the bounded HTTP-to-HTTPS redirect handler. Redirects containing embedded credentials, fragments, malformed ports, invalid hostnames, cross-host destinations, path/query changes or unsupported ports are rejected. The existing same-host HTTP-to-HTTPS upgrade and two-request maximum remain unchanged. See [Phase 2R HTTP redirect scope hardening](docs/PHASE2R_HTTP_REDIRECT_HARDENING.md).


### Milestone 2S: CSP policy quality observations (draft PR)
Phase 2S extends the existing HTTP response-header review with conservative static Content-Security-Policy hardening observations. It flags selected risky source expressions (`unsafe-inline`, `unsafe-eval`, and wildcard sources), and reviews object-src and base-uri restrictions. These are review indicators, not proof of exploitability or a browser-policy verdict. The existing two-request, read-only HTTP scope is unchanged. See [Phase 2S CSP policy quality](docs/PHASE2S_CSP_POLICY_QUALITY.md).


### Milestone 2U: HTTP evidence quality and report consistency (development)
Phase 2U attaches bounded response provenance and the relevant observed header values to HTTP findings, while redacting Set-Cookie values and CSP nonce/hash tokens. It adds regression coverage for conflicting header combinations, response evidence, and HTML/JSON/optional PDF generation. It does not add requests, expand scope, or alter authorization gates. See [Phase 2U HTTP evidence quality and report consistency](docs/PHASE2U_HTTP_EVIDENCE_REPORT_QUALITY.md).



### Milestone 2V: finding quality and remediation triage (development)
Phase 2V adds explicit severity provenance, a conservative review-priority tier derived only from the existing module-assigned severity, and a recommendation-presence indicator. Unknown severities remain UNRANKED; missing recommendations remain visible rather than being filled with invented advice. Review priority is a triage aid, not a composite risk score, confirmation of exploitability, or an automatic remediation instruction. JSON evidence and PDF/HTML report paths expose the additional metadata. No scan behavior, network requests, authorization gates or target scope are changed. See [Phase 2V finding quality and remediation triage](docs/PHASE2V_FINDING_QUALITY_REMEDIATION.md).


### Milestone 2W: assessment accuracy and fingerprint confidence calibration (development)
Phase 2W calibrates passive CMS fingerprint confidence so a self-declared generator meta tag alone is not treated as high-confidence identification. It also accepts valid HTML meta-attribute ordering and labels server/application response banners as low-confidence technology attribution because headers can be changed or spoofed. The bounded response sample and existing request limits are unchanged. See [Phase 2W assessment accuracy and false-positive reduction](docs/PHASE2W_ASSESSMENT_ACCURACY_FALSE_POSITIVES.md).


### Milestone 2X: unavailable-result classification (development)
Phase 2X keeps transport failures and unreachable endpoints unranked rather than assigning a security severity when the relevant security control could not be assessed. Reports explicitly count UNKNOWN findings. See [Phase 2X evidence-confidence calibration](docs/PHASE2X_EVIDENCE_CONFIDENCE_CALIBRATION.md).


### Milestone 2Y: assessment report consistency (development)
Phase 2Y aligns individual assessment PDF severity summaries with the existing HTTP HTML and unified engagement summaries by explicitly counting UNKNOWN findings. Unavailable checks remain visible as unranked results rather than disappearing from the executive count. This is a reporting and offline-test change only; assessment scope, request limits, authorization gates and network behavior are unchanged. See [Phase 2Y assessment report consistency](docs/PHASE2Y_ASSESSMENT_REPORT_CONSISTENCY.md).

### Milestone 2Z: installation preflight and environment diagnostics (development)
Phase 2Z adds an offline diagnostic for Python support, external command availability, optional PDF/signing dependencies, and the ApexRecon capabilities each enables. It provides Termux/Linux installation guidance and text/JSON output without installing packages or running assessment commands. HTTP/TLS assessment remains usable when unrelated OSINT/SMB tools are absent. No scan behavior or authorization gates change. See [Phase 2Z installation preflight](docs/PHASE2Z_INSTALLATION_PREFLIGHT.md).


### Milestone 2AA: capability-aware startup (development)
Phase 2AA makes startup dependency reporting feature-specific. Missing Nmap prevents SMB assessment from running and records the module as UNAVAILABLE in unified engagements; missing unrelated tools do not block HTTP/TLS. OSINT is labelled PARTIAL when individual collection tools are missing, and signing is clearly disabled when cryptography is unavailable. No scan scope, request behavior, or authorization gates change. See [Phase 2AA capability-aware startup](docs/PHASE2AA_CAPABILITY_AWARE_STARTUP.md).


### Milestone 2AB: installation and operational reliability (development)
Phase 2AB expands the offline preflight to check the required project files, actual artifact-output-directory write access, the active Python interpreter, virtual-environment state, and pip/venv availability. It adds isolated-environment guidance and recovery steps for common Termux/proot and externally-managed Python issues. The diagnostic creates and removes one temporary local file; it does not install packages, alter permissions, or contact targets. No assessment behavior or authorization gates change. See [Phase 2AB installation and operational reliability](docs/PHASE2AB_INSTALLATION_OPERATIONAL_RELIABILITY.md).

### Milestone 2AC: crash-safe assessment artifact publication (development)
Phase 2AC stages HTTP/TLS evidence and unified engagement JSON/PDF outputs in hidden temporary files, flushes them, and publishes complete artifacts atomically without overwriting existing evidence. If interrupted before publication, a final report file is not exposed; a hidden staging file may require manual cleanup. The change is local storage behavior only and does not alter assessment scope or network behavior. See [Phase 2AC crash-safe artifact publication](docs/PHASE2AC_CRASH_SAFE_ARTIFACT_PUBLICATION.md).

### Milestone 2AD: assessment execution recovery and evidence checkpoints (development)
Phase 2AD adds a private hash-chained execution journal to unified engagements. Each selected module is checkpointed before execution and its returned outcome is saved as an atomic private sidecar before the finish event. Operators can inspect interrupted/incomplete runs and verify recovered module evidence without automatically resuming network activity. Existing target prompts, authorization gates and assessment scope remain unchanged. See [Phase 2AD assessment execution recovery](docs/PHASE2AD_ASSESSMENT_EXECUTION_RECOVERY.md).
