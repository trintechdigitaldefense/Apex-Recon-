# Phase 2AH — Atomic audit backup and restore publication

## Purpose

Prevent a process or storage interruption during an individual audit backup, checkpoint, or restored-trail write from exposing a partially written final-path file.

## Changes

- Route backup, detached checkpoint, and restored audit-trail publication through the existing same-directory staging and atomic create-only publisher in `apex_storage.py`.
- Keep owner-only POSIX permissions and refuse to replace existing evidence.
- Preserve post-restore byte-count, SHA-256, event-count, and hash-chain verification.
- Add fault-injection tests for file-sync failures during backup and restore publication.
- Add an interruption test between the two separate backup/checkpoint publications.

## Recovery boundaries

- A failed individual publication must not expose a partial final-path file; temporary staging files are cleaned on handled failures.
- A hard interruption after the backup is published but before the checkpoint is published can still leave a complete backup without its checkpoint. Verification fails closed; no automatic cleanup or reconstruction is attempted.
- Backup and checkpoint remain two independent publications, not one atomic multi-file transaction.
- Atomic publication depends on same-directory hard-link support. Unsupported filesystems fail closed rather than falling back to a weaker write.
- A hard power loss cannot be fully simulated by unit tests. The tests inject failures at filesystem synchronization boundaries; controlled Termux/proot and Linux drills remain necessary.
- No network requests, assessment commands, target scope, authorization gates, automatic scan resumption, or audit-event semantics change.
- SHA-256 and the local hash chain remain tamper-evident, not immutable or proof that recorded events are truthful.

## Validation

Run from the repository root:

```bash
python3 -m compileall -q apex_storage.py apex_audit_backup.py tests
python3 -m unittest discover -s tests -p 'test_audit_backup.py' -v
python3 -m unittest discover -s tests -v
```
