# Phase 2AE: Crash-safe audit artifact publication

## Purpose

Use the shared Phase 2AC atomic publisher for audit backups, detached checkpoints, restored audit trails and signed checkpoint envelopes. The final destination is create-only and is not visible with partial contents.

## Changes

- Replace direct file writes in audit backup and signature helpers with same-directory staged writes and atomic hard-link publication.
- Preserve owner-only POSIX permissions and existing create-only behavior.
- Restore audit trails through the same atomic publisher, then verify the restored chain.
- If a backup is published but checkpoint publication fails, preserve the complete backup and report that the pair is incomplete. Do not delete a published artifact by pathname during error cleanup.
- Add regression tests for first-stage publication failure, checkpoint publication interruption, orphan-backup preservation and signature publication failure.
- Keep the existing backup/checkpoint/signature schemas and cryptographic verification behavior unchanged.

## Operator handling

A complete backup without its detached checkpoint is an incomplete backup pair. Preserve it for investigation. Do not treat it as verified, sign it, or restore it until a valid checkpoint has been created through a separately reviewed process. A later retry must use new output paths; existing artifacts are never overwritten.

The atomic publisher can leave a hidden `.apexrecon-tmp-*` staging file if the process is forcibly interrupted before publication. Review such files manually and remove only after confirming no ApexRecon process is using them.

## Safety and limitations

- No audit event contents, hash-chain rules, backup schemas, signature schemas, key handling, target prompts, authorization gates, scan methods or assessment scope are changed.
- No network requests, target scans, background agents, recurring scans or automatic recovery are introduced.
- Atomic publication protects each individual file. The backup and checkpoint are still two separate files, not one multi-file transaction.
- A detached unsigned checkpoint remains an unkeyed SHA-256 reference. Signed checkpoints still require an independently trusted public-key fingerprint.
- SHA-256 checksums and hash chains are tamper-evident, not immutable storage.
- No live targets are contacted.

## Validation

Tests use synthetic audit events, generated local keys and temporary files only.

```bash
python3 -m compileall -q apex_storage.py apex_audit_backup.py apex_audit_backup_signing.py tests
python3 -m unittest discover -s tests -v
```
