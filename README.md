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


### Milestone 2AE: recovered evidence and execution-state consistency (development)
Phase 2AE rejects a recovered module artifact when the outcome's own status conflicts with the terminal status recorded in the execution journal. The same consistency check runs before a sidecar is written, preventing contradictory recovery evidence from being published. A mismatch leaves the module unresolved and the engagement incomplete. No assessment scope, target interaction, authorization gate, or automatic recovery behavior changes. See [Phase 2AE recovered evidence consistency](docs/PHASE2AE_RECOVERY_EVIDENCE_CONSISTENCY.md).


### Milestone 2AF: audit journal integrity diagnostics (development)
Phase 2AF improves offline verification of the local JSONL audit trail. Verification reports the original file's byte count and SHA-256, the number and byte length of the verified prefix, the prefix SHA-256, and a structured failure code/sequence when corruption is found. Duplicate records and broken sequence/hash-chain conditions are identified; an incomplete final write can be distinguished from corruption in an earlier event. Verification never truncates, repairs, rewrites or appends to the source trail, and append continues to fail closed for any invalid trail. Prefix metadata is diagnostic evidence, not authorization to discard the unverified tail. See [Phase 2AF audit integrity diagnostics](docs/PHASE2AF_AUDIT_INTEGRITY_DIAGNOSTICS.md).


### Milestone 2AG: audit backup restoration assurance (development)
Phase 2AG makes restoration use one captured backup/checkpoint byte pair: the exact backup bytes validated against the detached checkpoint are the source of the restored audit payload. Post-write checks compare byte length, SHA-256, event count and hash-chain head with the verified snapshot. Existing destinations remain create-only. This closes a verification/reopen gap but does not make backup/checkpoint creation a cross-file atomic transaction or prove audit-event truthfulness. See [Phase 2AG audit restore assurance](docs/PHASE2AG_AUDIT_RESTORE_ASSURANCE.md).


### Milestone 2AH: atomic audit backup and restore publication (development)
Phase 2AH routes each audit backup, detached checkpoint and restored audit trail through the existing same-directory atomic create-only publisher. Files are staged and synchronized before the final path is published, preventing partial final-path artifacts during an interrupted individual write. Fault-injection tests cover synchronization failures and interruption between the two separate backup/checkpoint publications. The pair is still not a cross-file transaction; an interruption between publications can leave an incomplete pair that fails verification and requires manual handling. See [Phase 2AH atomic audit backup publication](docs/PHASE2AH_ATOMIC_AUDIT_BACKUP_PUBLICATION.md).


### Milestone 2AI: controlled operational recovery drill runbooks (development)
Phase 2AI defines controlled, offline drill procedures for process interruption, backup/checkpoint separation, synchronization failures, existing destinations, permissions, bounded storage exhaustion, unsupported hard links, interrupted restore, and disposable-VM power-loss testing. It establishes evidence and pass/fail criteria across Termux, proot and Linux. These are operator runbooks, not proof that physical drills have passed. Use disposable synthetic data only; never fill a primary device or interrupt a production system. See [Phase 2AI controlled recovery drill runbooks](docs/PHASE2AI_CONTROLLED_RECOVERY_DRILL_RUNBOOKS.md).


### Milestone 2AJ: atomic storage edge-case regression coverage (development)
Phase 2AJ expands offline fault-injection coverage for the create-only atomic artifact publisher. Tests verify fail-closed behavior when same-directory hard links are unsupported, preservation of symlink destinations and their targets, and inode-specific cleanup when a destination is replaced during a directory-sync failure. The replacement test exposed and fixed an inode-reuse race: the publisher now pins the original inode until cleanup finishes and uses lstat for identity comparison. Permission-mode validation is also tightened. These are deterministic temporary-directory tests, not physical power-loss validation. No assessment behavior or network scope changes. See [Phase 2AJ atomic storage edge-case tests](docs/PHASE2AJ_ATOMIC_STORAGE_EDGE_CASE_TESTS.md).


### Milestone 2AK: subprocess process-crash recovery tests (development)
Phase 2AK adds isolated child-process termination tests at three publication boundaries: before artifact publication, between audit backup and checkpoint publication, and during restore staging. The tests use synthetic audit data, temporary directories and `os._exit` in child interpreters to bypass Python cleanup handlers. They verify no partial final artifact, fail-closed backup/checkpoint verification, and unchanged restore sources. They do not simulate power loss, kernel crashes, or storage-controller behavior. See [Phase 2AK process-crash recovery tests](docs/PHASE2AK_PROCESS_CRASH_RECOVERY_TESTS.md).


### Milestone 2AL: local filesystem capability probe (development)
Phase 2AL adds a non-destructive local probe for same-directory hard links, directory fsync, private file mode, and ApexRecon atomic artifact publication. It uses a small temporary workspace beneath an existing selected directory, reports available space where supported, and removes its own workspace. It does not consume storage, modify existing files, access networks, or establish power-loss durability. See [Phase 2AL filesystem capability probe](docs/PHASE2AL_FILESYSTEM_CAPABILITY_PROBE.md).


### Milestone 2AM: controlled power-loss validation protocol (development)
Phase 2AM turns the recovery drill guidance into a structured, repeatable protocol for actual guest-VM power interruption. It defines staging, post-publication, backup/checkpoint, restore and completed-artifact scenarios; requires disposable VM snapshots, synthetic data, guest-only power-off, at least three runs per scenario, and recorded filesystem/hash evidence. The protocol is not a claim that physical drills have passed. CI, process termination tests and filesystem capability probes are not substitutes for actual power-loss observations. See [Phase 2AM controlled power-loss validation](docs/PHASE2AM_CONTROLLED_POWER_LOSS_VALIDATION.md).


### Milestone 2AO: storage-aware operational readiness (development)
Phase 2AO makes `apex_doctor.py` run the non-destructive atomic-storage capability probe against the actual artifact output directory. Ordinary write access is no longer treated as sufficient evidence-storage readiness: missing hard-link support, failed atomic publication, directory sync, private mode, or cleanup causes a non-zero readiness result. The atomic publisher remains fail-closed with no direct-write fallback. See [Phase 2AO storage-aware readiness](docs/PHASE2AO_STORAGE_AWARE_READINESS.md).


### Milestone 2AP: assessment preflight enforcement
Phase 2AP runs a fresh local readiness check before the operator can start OSINT, SMB, HTTP, TLS, or a unified engagement. The check requires a supported Python runtime, the expected project files, a writable current artifact directory, and a successful atomic evidence-storage probe in that directory. If diagnostics fail, are unavailable, or report unsupported storage, the selected assessment module is not invoked and no target prompt or target interaction occurs. Evidence signing and offline verification remain available independently. The preflight does not install dependencies, change permissions, or contact targets. See [Phase 2AP assessment preflight enforcement](docs/PHASE2AP_ASSESSMENT_PREFLIGHT_ENFORCEMENT.md).


### Milestone 2AQ: unified execution stop on checkpoint failure (development)
Phase 2AQ makes the unified engagement stop starting additional selected assessment modules if a module's durable start or completion checkpoint fails. The current module is not started when its start checkpoint fails; a completion-checkpoint failure downgrades its result to FAILED. Modules not reached are recorded as NOT_RUN in the assembled report, while the execution journal remains incomplete and is not force-finalized. Ordinary assessment runner failures can still be isolated when durable checkpoints succeed. The change does not resume or replay assessments, alter target scope, or change authorization prompts. See [Phase 2AQ checkpoint failure stop](docs/PHASE2AQ_CHECKPOINT_FAILURE_STOP.md).

### Milestone 2AR: execution journal recovery diagnostics (development)
Phase 2AR extends read-only execution-journal verification with the original file digest and size, verified-prefix digest and byte count, and structured failure code/sequence. Incomplete final writes are distinguished from corruption in earlier complete events, while the module state recovered from the verified prefix remains diagnostic only. Verification never repairs or truncates the journal, and append continues to fail closed for invalid journals. No assessment is resumed or replayed, and target scope, authorization prompts and network behavior are unchanged. See [Phase 2AR execution journal recovery diagnostics](docs/PHASE2AR_EXECUTION_JOURNAL_RECOVERY_DIAGNOSTICS.md).

### Milestone 2AS: recovery workflow integrity diagnostics (development)
Phase 2AS adds a read-only recovery assessment that correlates verified execution-journal module states with their referenced outcome sidecars. It reports interrupted and not-started modules, missing or invalid sidecars, and verified artifact references without repairing, deleting, reconstructing, resuming, or replaying an assessment. Checksums establish byte consistency, not the truth or completeness of assessment observations. See [Phase 2AS recovery workflow integrity](docs/PHASE2AS_RECOVERY_WORKFLOW_INTEGRITY.md).


### Milestone 2AT: operator-facing recovery inspection (development)
Phase 2AT exposes the Phase 2AS consistency diagnostic through a read-only CLI command: `python3 apex_execution.py /path/to/execution-journal.jsonl --recovery`. It reports journal integrity, execution state, and each module's journal and artifact status. Exit code 0 means all applicable artifacts are verified, 1 means the journal cannot be trusted or safely inspected, and 2 means operator review is required. It does not print raw findings or target details, contact targets, resume modules, repair journals, or reconstruct missing artifacts. Existing journal-inspection and artifact-verification modes remain available. See [Phase 2AT operator recovery inspection](docs/PHASE2AT_OPERATOR_RECOVERY_INSPECTION.md).


### Milestone 2AU: recovery CLI process validation (development)
Phase 2AU exercises the operator recovery command through a real child process rather than only calling its Python entry-point function in-process. Synthetic journals and outcome sidecars are created in temporary directories using `ExecutionJournal`. Subprocess tests verify exit code 0 for fully verified evidence and exit code 2 for interrupted modules and missing sidecars. They snapshot journal and sidecar state to prove that inspection does not modify existing evidence or recreate missing artifacts. Tests are offline and do not invoke assessment modules or contact targets. See [Phase 2AU recovery CLI process validation](docs/PHASE2AU_RECOVERY_CLI_PROCESS_VALIDATION.md).
