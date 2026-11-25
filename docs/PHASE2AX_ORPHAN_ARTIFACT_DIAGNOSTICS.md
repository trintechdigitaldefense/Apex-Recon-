# Phase 2AX — Orphaned execution artifact diagnostics

## Purpose

Phase 2AX makes an existing recovery diagnostic explicitly identify an expected module sidecar that exists without a corresponding artifact reference in the verified execution journal. This situation can occur when a process stops after atomic sidecar publication but before the journal completion event is appended.

## Diagnostic behavior

For each selected module without a journal artifact reference, recovery inspection checks only the conventional sidecar path derived from the journal filename and module position. It uses filesystem metadata lookup (`lstat`) and reports one of:

- `ABSENT`: no object exists at the expected path.
- `PRESENT`: an object exists, with its type classified as `REGULAR_FILE`, `DIRECTORY`, `SYMLINK`, or `OTHER`.
- `INSPECTION_ERROR`: metadata could not be safely obtained; the error is limited to its exception type.

The diagnostic does not open the object, follow symlinks, calculate a digest, parse its contents, adopt it as evidence, delete it, or attempt repair. Existing journal-referenced sidecars continue to be opened only through the established no-follow, bounded-size, checksum and metadata verification path.

## Validation

Synthetic offline tests cover a regular-file orphan, a symlink orphan whose target bytes must remain unchanged, and an absent expected path. Tests also preserve journal and artifact bytes across inspection.

Run locally from the repository root:

```bash
python3 -m compileall -q apex_execution.py tests
python3 -m unittest discover -s tests -p 'test_recovery_integrity_edge_cases.py' -v
python3 -m unittest discover -s tests -v
```

## Safety boundaries

- Temporary directories and synthetic bytes only.
- No assessment modules, target validation, authorization prompts, or network requests.
- No sidecar adoption, deletion, cleanup, reconstruction, journal repair, resume, or replay.
- A file at the expected path is not evidence unless a valid journal completion event references it and the existing verifier validates it.
- Metadata inspection is diagnostic and does not prove the origin or truthfulness of a file.
- This phase does not establish physical power-loss or storage-device durability. The Phase 2AM disposable-VM protocol remains outstanding.
