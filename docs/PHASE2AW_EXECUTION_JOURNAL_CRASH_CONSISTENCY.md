# Phase 2AW — Execution journal crash-consistency validation

## Purpose

Validate the ordering and failure boundaries between the unified-engagement execution journal and its per-module outcome sidecars. Phase 2AW uses deterministic process termination at controlled local write boundaries. It does not claim to simulate kernel failure, power loss, storage-controller cache loss, or filesystem recovery.

## Controlled scenarios

The new offline subprocess tests use synthetic module outcomes and temporary directories:

1. **Crash during sidecar staging, before final-path publication.** The child exits after writing the hidden staging file but before file synchronization and atomic link publication. The final sidecar path must not exist. The journal must remain a valid STARTED state. A hidden staging file may remain and is not evidence.
2. **Crash after sidecar publication, before the journal completion event.** The child exits after the sidecar is atomically published but before MODULE_FINISHED is appended. The journal remains STARTED; the sidecar is an unreferenced orphan and must not be promoted to verified evidence.
3. **Crash during journal append.** The child writes only part of a completion event and exits before the append completes. The journal must be rejected as incomplete_final_event; the verified prefix is diagnostic only and the source file must remain byte-for-byte unchanged during inspection.

The tests assert process exit codes, journal validity or failure classification, expected artifact presence/absence, and preservation of source bytes after read-only inspection.

## Run locally

From the repository root:

```bash
python3 -m compileall -q apex_execution.py apex_storage.py tests
python3 -m unittest discover -s tests -p 'test_execution_crash_consistency.py' -v
python3 -m unittest discover -s tests -v
```

A focused test command is a pass only when the runner reports tests executed and all pass.

## Safety boundaries

- All inputs and outputs are synthetic and confined to a temporary directory.
- The subprocesses call only ExecutionJournal and local filesystem functions.
- No OSINT, SMB, HTTP, TLS, target validation, authorization prompt, or network operation is invoked.
- The tests do not fill real storage, alter mount state, kill the host, reboot a device, or perform power-loss testing.
- Recovery inspection remains read-only. It does not truncate, repair, delete, reconstruct, resume, or replay.
- Hidden staging files and unreferenced sidecars are retained by the test until the temporary directory is cleaned up; production recovery must not silently adopt or delete them.

## Interpretation limits

A deterministic process exit tests application-level ordering and visible filesystem state after a child process terminates. It does not establish that data survives sudden power loss or that a particular filesystem/device honors every durability guarantee. Existing controlled VM power-loss scenarios in Phase 2AM remain separate and must be executed and recorded on the exact environment under test. A passing CI suite is not a physical durability result.

## Exit gate

Phase 2AW is complete when the focused and full test suites pass in CI and in the operator's Ubuntu-proot environment, with the exact commit recorded. Physical power-loss validation remains NOT RUN unless the separate Phase 2AM VM protocol is actually performed.
