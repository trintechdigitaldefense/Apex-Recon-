# Phase 2AG — Audit backup restoration assurance

## Purpose

Strengthen offline audit-backup restoration so the bytes validated against the detached checkpoint are exactly the bytes used for restoration.

## Changes

- Capture the backup and checkpoint once for a restore operation.
- Validate the captured byte pair, canonical JSON, detached backup digest, embedded audit payload digest, event count and hash-chain head before creating the destination.
- Restore the audit payload extracted from that verified in-memory snapshot. Do not reopen the backup path between verification and restoration.
- After writing, read the destination and verify its exact byte length, SHA-256 digest, event count and hash-chain head against the verified snapshot.
- Preserve create-only destination behavior. Existing files are never overwritten.
- Keep the public backup-verification result backward-compatible; internal payload bytes are not returned to callers.

## Recovery boundaries

- A changed or replaced backup path after its bytes have been captured does not change the bytes restored in that operation.
- A failed verification does not create a destination.
- A post-write mismatch causes the newly created destination to be removed where possible and restoration to fail closed.
- This does not make the source backup/checkpoint immutable, protect against a compromised host, or prove the audit events were truthful.
- Backup and checkpoint creation are still two separate filesystem publications, not a cross-file atomic transaction. An interruption can leave an incomplete pair; it must fail verification and be handled manually without deleting original evidence.
- No automatic repair, truncation, replay, scan resumption, network request or target interaction is introduced.

## Validation

Tests use synthetic audit records and temporary local files. They exercise single-snapshot restoration, path mutation after capture, exact restored bytes, empty trails, overwrite refusal, and existing tamper/corruption cases.

Run from the repository root:

```bash
python3 -m compileall -q apex_audit_backup.py tests
python3 -m unittest discover -s tests -p 'test_audit_backup.py' -v
python3 -m unittest discover -s tests -v
```

CI and offline tests do not replace controlled filesystem interruption and recovery drills on each supported environment.
