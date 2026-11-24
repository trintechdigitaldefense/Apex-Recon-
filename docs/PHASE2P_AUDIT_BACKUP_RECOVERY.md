# Phase 2P: Evidence Export, Independent Checkpoints and Recovery

## Purpose
Phase 2P adds offline backup and recovery for the Phase 2O local JSONL audit trail. A portable JSON backup preserves the exact source bytes, event count, chain head and SHA-256 digest. A separate checkpoint records the backup digest and audit metadata.

## Operator workflow
From main menu option **6 — Evidence Signing / Verification**:
- **5 — Export audit backup and checkpoint:** create two separate output files. Existing files are never overwritten.
- **6 — Verify audit backup/checkpoint:** validate canonical JSON, detached backup digest, embedded payload digest, full audit chain, event count and chain head.
- **7 — Restore audit backup:** restore to a new path only, then verify the restored chain. Existing destinations are never overwritten.

Store the checkpoint on a different device or independently controlled storage from the backup. Keeping both only beside the original workstation does not provide recovery from workstation loss.

## Integrity and recovery limits
- The checkpoint is a detached SHA-256 reference, not a digital signature or immutable storage. An attacker able to replace both backup and checkpoint can rewrite both. Preserve checkpoints separately or authenticate them with a separately trusted key.
- A checkpoint proves the backup matches that checkpoint. It does not prove original events were truthful or complete before checkpoint creation.
- The hash chain detects edits within the retained sequence; it cannot prove an event was never omitted before the first trusted checkpoint.
- Restore is create-only and never overwrites the original audit file.
- Backups contain audit metadata including engagement UUIDs and signer fingerprints. Protect them as sensitive operational records.
- No private keys, passphrases, findings or target data are added. No network access, scans, scheduling or background monitoring.

## Validation
Tests use synthetic audit events and temporary local files only.
```bash
python3 -m compileall -q apex_recon_v2.py apex_signing.py apex_audit.py apex_audit_backup.py apex_engagement.py apex_engagement_cli.py tests
python3 -m unittest discover -s tests -v
```
