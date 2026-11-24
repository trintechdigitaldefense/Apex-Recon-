# Phase 2I — Unified Engagement Reporting

## Purpose

Phase 2I introduces an offline packaging layer for combining results already collected by ApexRecon's four modules into one engagement record.

## Supported modules

- External Footprinting (OSINT)
- SMB Network Auditor
- HTTP Security Assessment
- TLS Security Assessment

Each engagement contains exactly one entry for each module. Operators can represent unrun work as NOT_RUN rather than allowing missing data to look like a clean result.

## Module states

- COMPLETED: the module reports that its supplied work completed.
- PARTIAL: the supplied result is incomplete or only partially completed.
- FAILED: the module did not complete successfully.
- NOT_RUN: the module was not run and must not contain findings.

These statuses describe supplied module metadata. The engagement builder does not independently verify scan execution or completeness.

## Included in the engagement record

- One UUID engagement identifier.
- Overall engagement status and top-level target scope.
- Per-module target scope, status, timestamps, duration, finding count and limitations.
- Consolidated Phase 2G normalized findings.
- Severity counts and module status counts.
- Explicit statement that no composite risk score is calculated.
- SHA-256 checksum over the canonical record.

The checksum detects content changes but is not a digital signature, proof of origin, or immutable storage guarantee.

## Exports

- JSON export uses the Python standard library.
- Optional native PDF export uses ReportLab from requirements-pdf.txt.
- Both outputs use exclusive file creation to avoid overwriting an existing artifact.
- Files use mode 0600 on supported POSIX systems.

## Current integration boundary

This phase supplies `build_engagement_record()`, `verify_engagement_record()`, JSON export and PDF rendering as an offline API. It does not yet refactor the interactive OSINT and SMB functions to return structured results or guide the operator through a multi-module engagement. Existing HTTP/TLS exports remain separate. CLI orchestration is a later integration step.

No scan behavior, target scope, authorization prompt, request count, or network activity changes in this phase. Tests use synthetic data only.

## Validation

Run:

```bash
python3 -m compileall -q apex_recon_v2.py apex_web.py apex_tls.py apex_fingerprint.py apex_evidence.py apex_findings.py apex_finding_adapters.py apex_engagement.py tests
python3 -m unittest discover -s tests -v
```

CI additionally imports the new module in its Linux dependency smoke job.

## Release boundaries

Phase 2I is a draft development milestone. CI and offline tests do not establish live accuracy, client readiness, or production readiness. No merge, release, deployment, live scan, continuous monitoring, or unattended 24-hour operation is authorized.
