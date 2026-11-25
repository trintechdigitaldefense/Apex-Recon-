# Phase 2BA — Filesystem and journal-lock portability

## Objective

Add an explicit, bounded check for the advisory file-lock semantics used by the append-only execution journal. The existing storage probe already checks hard links, directory `fsync`, private file permissions, atomic publication and cleanup; it did not test whether a lock held by one process actually blocks a second process on the selected filesystem.

## Probe behavior

`python3 tools/apex_storage_probe.py --parent /path/to/existing/test-directory` now reports `advisory_file_locking` separately from atomic publication:

- `exclusive_lock_blocks_other_process`: a second Python process cannot acquire an exclusive non-blocking lock while the parent process holds it.
- `lock_released_for_waiting_process`: the second process acquires the lock after the parent releases it.
- `supported`: true only when both observations succeed.
- `error`: bounded diagnostic text when the probe cannot establish the required behavior.

The probe uses only uniquely named files inside its own temporary workspace, applies an eight-second timeout to child-process coordination, and cleans up only that workspace. It does not contact targets, modify existing files, install dependencies, or change assessment behavior.

## Operator interpretation

- A successful result is evidence for the exact tested directory, filesystem, mount and runtime at that time.
- A failed or unavailable lock probe means execution-journal concurrency safety is not established for that location. Do not use that location for concurrent or recoverable unified engagements until investigated.
- The journal continues to fail closed when `flock()` raises an error. This probe also detects filesystems where lock calls appear to succeed but do not exclude another process.
- This does not establish distributed locking, network-filesystem correctness, physical power-loss durability, or behavior on untested Android storage providers.
- Native Termux and Ubuntu/proot are separate environments and must be probed independently. Do not assume a result transfers between them.

## Validation

Run from the repository root:

```bash
python3 -m compileall -q apex_storage.py apex_execution.py apex_doctor.py tools tests
python3 -m unittest discover -s tests -p 'test_apex_storage_lock_probe.py' -v
python3 -m unittest discover -s tests -p 'test_execution_journal_concurrency.py' -v
python3 -m unittest discover -s tests -v
python3 tools/apex_storage_probe.py --parent "$HOME"
python3 tools/apex_storage_probe.py --parent "$PWD"
python3 apex_doctor.py
python3 apex_doctor.py --json
git diff --check
git status --short
```

The doctor reports execution-journal locking as a separate capability. A locking failure does not disable unrelated HTTP/TLS checks, but it must be treated as a blocker for relying on journal concurrency in that storage location.

## Scope and safety boundaries

- Probe and tests use synthetic files and subprocesses in temporary directories only.
- No production journal algorithm, lock ordering, assessment scope, authorization gate, network behavior, or recovery behavior is changed.
- No lock fallback is introduced.
- No destructive filesystem tests or real client data are used.
- Phase 2AM disposable-VM power-loss validation remains a separate outstanding gate.
