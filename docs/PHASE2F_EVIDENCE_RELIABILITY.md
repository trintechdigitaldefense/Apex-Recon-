# Phase 2F — Evidence Quality and Export Reliability

## Objective

Phase 2F hardens the evidence and reporting path introduced in Phase 2E. It focuses on record integrity, privacy-safe URL handling and predictable behavior when optional PDF generation fails.

## Changes

- Adds `verify_evidence_record()` to validate the schema version, canonical UUID and SHA-256 checksum.
- JSON export and PDF rendering reject records with malformed identifiers or a checksum mismatch.
- Assessment IDs are validated as UUIDs when evidence records are built.
- URL export removes embedded user information, query strings and fragments. This includes relative URL values; malformed URL syntax fails closed rather than being copied into evidence.
- PDF generation and file-write errors are captured separately from JSON export. If JSON creation succeeds but PDF creation fails, the JSON path is retained and the PDF error is returned for operator visibility.
- Adds offline regression tests for tamper detection, URL redaction, invalid UUID rejection and partial export recovery.

## Validation

The tests use synthetic assessment data and temporary directories. They do not contact targets or issue network requests.

Validation required for this milestone:
- GitHub Actions on Python 3.10, 3.11 and 3.12.
- Linux dependency/import smoke test.
- Operator validation in the existing Ubuntu/Termux environment.
- Confirm the complete unit-test count and compile check before considering the milestone complete.

## Security and operational boundaries

- No HTTP/TLS request behavior or scan scope changes.
- No live targets contacted as part of implementation or offline tests.
- Checksums provide tamper detection only when independently recomputed against a trusted copy. They are not signatures, proof of origin or immutable storage.
- A PDF failure does not invalidate a successfully created JSON evidence record.
- Phase 2F does not add signing, a central evidence vault, cross-run comparison, scheduling, background monitoring or unattended operation.
- This remains a development draft. No merge, release or client deployment is included.
