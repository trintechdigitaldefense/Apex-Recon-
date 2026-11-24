# Phase 2AF — Audit journal integrity diagnostics

## Purpose

Improve offline diagnosis of damaged local audit JSONL trails without changing or repairing the original evidence.

## Changes

- Verification now reports the original file byte count and SHA-256 digest.
- Verification reports the number of fully verified records, the verified-prefix byte length and the SHA-256 digest of that exact prefix.
- Invalid trails include a structured failure code and the sequence number where verification stopped.
- Duplicate record hashes, sequence errors, broken hash-chain links, invalid event hashes, malformed JSON and incomplete final writes are distinguished.
- A complete verified prefix is retained as diagnostic metadata even when a later event is corrupt or the final write is incomplete.
- Existing callers retain the `valid`, `entries`, `head_hash` and `error` fields.

## Preservation and recovery boundaries

- Verification is read-only. It does not truncate, repair, rewrite, reorder or append to the original trail.
- Appending remains fail-closed for any invalid trail.
- A verified prefix is not a replacement for the original audit file and does not authorize deletion of an unverified tail.
- Preserve the original file and its independently retained signed checkpoint. Use the prefix digest only to identify the bytes that passed local chain validation.
- SHA-256 and a locally stored hash chain are tamper-evident, not immutable. An attacker able to replace both the trail and all trusted checkpoints may be able to forge a consistent history.
- Duplicate semantic actions are not automatically rejected: repeated signature verification or signing events can be legitimate. The verifier identifies repeated record hashes and invalid sequence/chain structure instead of guessing intent.

## Safety and scope

- No network requests, assessment commands, target scope, authorization prompts or module selection behavior change.
- No live targets are contacted.
- Tests use synthetic audit events and temporary local files.
- No automatic truncation, reconstruction, replay or network assessment resumption is introduced.

## Validation

```bash
python3 -m compileall -q apex_audit.py apex_audit_backup.py apex_audit_backup_signing.py tests
python3 -m unittest tests.test_audit -v
python3 -m unittest discover -s tests -v
```
