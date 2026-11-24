# Phase 2O: Evidence Verification Workflow and Audit Trail

## Purpose

Phase 2O connects Phase 2N signature operations to a local, operator-reviewable audit trail. It records key-pair creation, engagement signing, successful signature verification and rejected signatures. The trail contains event metadata only, not target data, findings, private keys, passphrases or report contents.

## Operator workflow

From the ApexRecon main menu, choose **6 — Evidence Signing / Verification**.

- Generate a key pair: records a `KEYPAIR_CREATED` event and public-key fingerprint.
- Sign an engagement JSON: records `ENGAGEMENT_SIGNED` only after the detached signature file has been written successfully.
- Verify a signature: records either `SIGNATURE_VERIFIED` or `SIGNATURE_REJECTED`.
- Verify the audit trail: checks the complete JSONL hash chain and reports the event count and current head hash.

The default audit file is `apexrecon_audit.jsonl` in the current working directory. It is created with owner-only permissions on POSIX systems. Events are appended under an exclusive file lock. New events are refused if the existing trail is malformed or its hash chain does not verify.

## Audit event fields

Each event records a schema version, sequential event number, timezone-aware timestamp, event type, engagement UUID when applicable, operation result, signer public-key fingerprint when applicable, previous event hash and current event hash. No private-key material or passphrases are recorded.

## Integrity limits

- The SHA-256 chain detects accidental or unauthorized edits to existing entries when the chain is checked.
- A local hash chain is not immutable storage. An attacker with write access to the file can rewrite the entire chain. Preserve periodic head-hash checkpoints outside the workstation or use an independently controlled audit repository for stronger assurance.
- File permissions and advisory locking reduce accidental access and concurrent-write problems; they do not provide protection against a privileged local attacker.
- Audit timestamps come from the local system clock and are not trusted timestamps.
- A valid Ed25519 signature proves possession of the matching private key, not a human or organizational identity. Public-key trust must be established out of band.
- A signature covers the canonical engagement JSON, not PDF bytes, and does not prove assessment accuracy, completeness or authorization.
- Audit logging is best-effort relative to the primary operation: if the audit file cannot be written, the CLI reports that limitation rather than misrepresenting the cryptographic operation's result.

## Validation

Tests use temporary files and synthetic UUIDs and fingerprints. No network requests, scans, target interaction, scheduling or background monitoring are introduced.

```bash
python3 -m compileall -q apex_recon_v2.py apex_signing.py apex_audit.py apex_engagement.py apex_engagement_cli.py tests
python3 -m unittest discover -s tests -v
```
