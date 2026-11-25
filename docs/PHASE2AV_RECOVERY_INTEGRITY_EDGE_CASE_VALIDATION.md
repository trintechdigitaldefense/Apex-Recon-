# Phase 2AV: Recovery Integrity Edge-Case Validation

## Purpose

Phase 2AV validates how read-only recovery inspection handles malformed but internally re-hashed journal transitions and unsafe or unavailable evidence sidecars. All fixtures are synthetic and local.

## Coverage

- Duplicate module-start events with a valid event hash and hash-chain link are rejected as invalid state transitions.
- Conflicting duplicate module-finish events are rejected.
- Parent-directory traversal in an artifact reference is rejected during journal verification.
- Windows-style backslash separators are rejected on POSIX as well as Windows, preventing a journal from carrying a path that changes meaning across operating systems.
- Permission-denied sidecars are reported as invalid evidence requiring operator review.
- Symlinked sidecars are rejected when no-follow file opening is supported; the symlink target is not modified.
- Tests snapshot journal, sidecar, and external target bytes to verify inspection is read-only.

Existing tests continue to cover incomplete/truncated journal tails, event-hash corruption, sidecar checksum mismatch, missing sidecars, and subprocess exit-code behavior.

## Run locally

From the ApexRecon repository root:

```bash
python3 -m unittest discover -s tests -p 'test_recovery_integrity_edge_cases.py' -v
python3 -m unittest discover -s tests -v
```

## Safety boundaries

- No assessment modules are invoked.
- No target names, IP addresses, DNS lookups, HTTP requests, port scans, or other target interactions are used.
- All files are created under temporary test directories.
- No journal repair, truncation, replay, resume, artifact reconstruction, or deletion is added to the recovery CLI.
- A passing test demonstrates handling of the tested filesystem and journal fixtures only. It does not establish physical power-loss durability, storage-controller behavior, assessment accuracy, or client deployment readiness.
