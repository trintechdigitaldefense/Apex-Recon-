# Phase 2E — Professional Reporting and Evidence

## Scope

Phase 2E adds a versioned JSON evidence export and optional native PDF report for the existing HTTP and TLS assessment workflows. It does not change network behavior or add new assessment requests.

## Artifacts

Each successful HTTP or TLS assessment attempts to produce:

- The existing standalone HTML report.
- `apex_evidence_<assessment-id>.json`, a structured evidence record.
- `apex_report_<assessment-id>.pdf`, a native PDF report when the optional ReportLab dependency is installed.

The evidence record contains:
- Schema version and unique assessment UUID.
- Module, target scope, start/completion timestamps and duration.
- ApexRecon tool name/version.
- Findings with severity, status, observed evidence and recommended action.
- CMS/technology fingerprints and their confidence/evidence markers where available.
- Module-specific evidence provenance and interpretation notes.
- Assessment limitations.
- SHA-256 checksum of the canonical record before the integrity field is added.

## Integrity and privacy

- JSON and PDF artifacts are created with exclusive-create semantics. Existing files are never overwritten.
- On POSIX systems, files are created with owner-only permissions (0600).
- JSON is UTF-8, indented and key-sorted for practical review.
- Raw HTTP response bodies are not exported.
- HTTP URLs in the existing assessment model omit query strings; the evidence exporter does not add query parameters.
- The checksum detects changes to the canonical assessment record when independently recomputed. It is not a digital signature, proof of origin, immutable storage, or protection against an attacker who can replace both the artifact and checksum.
- Assessment records should be stored and transferred using the organisation's approved secure evidence-handling process.

## Native PDF dependency

JSON export requires only the Python standard library. Native PDF generation uses optional ReportLab support:

```bash
python3 -m pip install -r requirements-pdf.txt
```

Without ReportLab, the assessment and JSON export still complete. The CLI displays the installation instruction and does not mislabel the HTML print view as a native PDF.

## Validation

The automated tests use synthetic HTTP/TLS assessment dictionaries and temporary directories. They validate schema fields, timestamps, checksum calculation, query-secret exclusion, exclusive file creation and POSIX permissions. PDF tests verify a real PDF header when ReportLab is installed, or the clear optional-dependency error when it is absent.

No live targets are contacted by these tests.

## Boundaries and known limitations

- The export is currently integrated with HTTP and TLS assessments. Legacy OSINT and SMB report packaging is not unified in this milestone.
- A single assessment record represents one HTTP or TLS module run. It does not merge separate HTTP and TLS runs into a single combined engagement.
- ReportLab is optional, so a native PDF will not be created until the dependency is installed in the operator's Python environment.
- The checksum is a content-integrity aid, not a signature or immutable evidence vault.
- The feature does not add automatic comparisons between separate assessments, digital signing, a central evidence repository, client portal, recurring scans, or background monitoring.
- Phase 2E remains a draft development milestone pending CI and operator phone validation. No merge, release or client deployment is included.
