# Phase 2AR: execution journal recovery diagnostics

Phase 2AR improves offline diagnosis of interrupted or damaged unified-engagement execution journals.

## Behavior

The execution-journal verifier now reports:
- Original journal byte count and SHA-256 digest.
- Number of complete, verified events.
- Exact verified-prefix byte count and SHA-256 digest.
- A structured failure code and event sequence when verification fails.
- The module states and artifact references established by the verified prefix.

An incomplete final write is distinguished from malformed UTF-8, invalid JSON, event-hash mismatch, broken hash-chain links, and other invalid events. A valid journal reports the complete file as its verified prefix.

## Safety boundaries

- Verification is read-only. It never truncates, repairs, rewrites, reorders, or appends to the journal.
- A verified prefix is diagnostic evidence only. It does not authorize discarding the unverified tail or continuing the engagement.
- Journal append remains fail-closed whenever the complete journal is invalid.
- Recovered module sidecars remain available only when the complete journal and referenced artifacts verify.
- No assessment module is resumed, replayed, or re-contacted.
- No network, target scope, authorization prompt, or assessment behavior changes.

## Validation scope

Tests use synthetic JSONL events and temporary directories. They cover incomplete final records, earlier event corruption, invalid UTF-8, preservation of the original journal, and exact prefix digests. These tests do not simulate physical power loss or prove storage durability.

See also [Phase 2AM controlled power-loss validation](PHASE2AM_CONTROLLED_POWER_LOSS_VALIDATION.md). That protocol still requires execution in a disposable VM; CI and local unit tests are not substitutes.
