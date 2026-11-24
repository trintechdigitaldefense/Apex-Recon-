# Phase 2Q: Signed Audit Backup Checkpoints

## Purpose
Phase 2Q authenticates the detached checkpoint created by Phase 2P. The checkpoint binds the portable backup's SHA-256 digest to the audit payload digest, event count and hash-chain head. An Ed25519 signature over the exact canonical checkpoint bytes makes it possible to detect an attacker who replaces both the backup and its unsigned checkpoint.

## Operator workflow
From main menu option **6 — Evidence Signing / Verification**:
- **8 — Sign audit backup checkpoint:** supply the backup, checkpoint, encrypted Ed25519 private key and signature output path. The tool verifies the backup/checkpoint pair before signing. It never overwrites an existing signature file.
- **9 — Verify signed audit backup:** supply the backup, checkpoint, detached signature, public key and the independently trusted public-key SHA-256 fingerprint. Verification fails if the supplied fingerprint does not match both the signature envelope and the actual public key.

Use the encrypted Ed25519 key pair generated through Phase 2N. Transfer the public key and signature envelope with the backup as needed, but establish the expected public-key fingerprint through a separate trusted channel. Do not trust a public key merely because it arrived beside the backup.

## What the signature proves
- The supplied public key verifies an Ed25519 signature over the exact canonical checkpoint bytes.
- The signed checkpoint binds the backup digest, audit payload digest, event count and chain-head hash.
- The verifier independently checks the backup, embedded audit JSONL chain, checkpoint and signature before returning valid.

## Limitations and security boundaries
- A valid signature proves possession of the private key corresponding to the supplied public key. It does not identify a person or organization; the fingerprint must be trusted out of band.
- The signature does not prove that original audit events were truthful, complete, authorized or created at the claimed time.
- `signed_at` is descriptive envelope metadata and is not covered by the checkpoint signature; it is local system time, not a trusted timestamp.
- Protect the encrypted private key and passphrase. Private-key input rejects symlinks, non-regular files and permissive POSIX file modes.
- Signature output uses exclusive creation and owner-only POSIX permissions.
- The signature authenticates the checkpoint, not a PDF or a separate report.
- Backup signing and verification are offline. They do not contact targets, alter scan behavior, change authorization gates or introduce background monitoring.
- Signing a backup does not mutate the source audit trail. This avoids changing the audit data immediately after creating the backup being signed.

## Validation
Tests use generated local Ed25519 keys, synthetic audit events and temporary files only.
```bash
python3 -m compileall -q apex_recon_v2.py apex_signing.py apex_audit.py apex_audit_backup.py apex_audit_backup_signing.py tests
python3 -m unittest discover -s tests -v
```
