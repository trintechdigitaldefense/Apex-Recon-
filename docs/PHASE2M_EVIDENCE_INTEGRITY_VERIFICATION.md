# Phase 2M — Assessment Evidence Integrity and Report Verification

## Purpose

Phase 2M strengthens the offline engagement verifier so a valid checksum alone is not mistaken for a structurally consistent assessment record. It also makes the JSON record identity and checksum discoverable in PDF document metadata.

## Changes

- Verify the four-module set, supported module names and statuses, module scopes, timestamps, durations and limitations.
- Re-normalize every finding and reject malformed records, mismatched module ownership, duplicate finding IDs and findings attached to NOT_RUN modules.
- Recalculate per-module finding counts, total findings, severity counts and module status counts.
- Recalculate the expected overall engagement status and reject inconsistent summaries, even when a record's checksum has been recomputed.
- Validate the tool identity and the declared meaning of the SHA-256 field.
- Add PDF title, author and subject metadata carrying the engagement UUID and canonical JSON SHA-256.
- Add offline regression tests for inconsistent summaries, module counts, duplicate findings, incomplete module sets and PDF metadata.

## Validation

Run on the Phase 2M branch:

```bash
python3 -m compileall -q apex_recon_v2.py apex_engagement.py apex_engagement_cli.py tests
python3 -m unittest discover -s tests -v
```

Tests use synthetic engagement records. PDF metadata checks require the existing optional ReportLab dependency.

## Interpretation and boundaries

- The verifier checks internal consistency and detects changes against the stored checksum. It cannot prove who created a record or whether source scans were complete, accurate or authorized.
- Anyone able to edit a record and recompute its unkeyed SHA-256 checksum can create a new internally consistent record. This is not a digital signature.
- PDF metadata links the PDF to the engagement UUID and JSON checksum; it does not cryptographically sign or checksum the PDF bytes.
- No signing keys, immutable evidence vault, remote storage, scan probes, network requests, target expansion or authorization changes are introduced.
- No recurring scans, background work or 24-hour monitoring.
- This phase does not establish live accuracy, client readiness or production readiness.
- No merge, release, deployment or live scan is included.
