# Phase 2AY — Recovery lifecycle consistency

## Objective

Validate that the append-only execution journal, module sidecars, and read-only recovery report remain consistent across normal lifecycle transitions and the interruption window between sidecar publication and journal completion.

## Scope

- Exercise the supported lifecycle: engagement creation, module start, module completion, and engagement finalization.
- Reject invalid transitions, including completion without a start and finalization while a module remains unresolved.
- Reproduce the crash window after atomic sidecar publication but before the corresponding `MODULE_FINISHED` event is appended.
- Confirm that this orphan remains untrusted and is reported as an interrupted module with an unreferenced sidecar.
- Repeat recovery inspection and compare results while checking that journal and sidecar bytes remain unchanged.

## Safety boundaries

- Synthetic temporary directories and synthetic outcome data only.
- No network access, target assessment, credentials, or real client evidence.
- Recovery inspection remains read-only.
- No orphan adoption, deletion, cleanup, reconstruction, journal repair, resume, or replay.
- A sidecar without a valid journal completion reference is not trusted evidence.
- These tests do not establish physical power-loss or storage-device durability. The Phase 2AM disposable-VM protocol remains outstanding.

## Validation

Run from the repository root:

```bash
python3 -m compileall -q apex_execution.py tests
python3 -m unittest discover -s tests -p 'test_recovery_lifecycle_consistency.py' -v
python3 -m unittest discover -s tests -v
git diff --check
git status --short
```

The focused and full regression results must be recorded before this phase is proposed for merge.
