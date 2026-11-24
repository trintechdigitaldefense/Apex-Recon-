# Phase 2AJ — Atomic storage edge-case regression coverage

## Purpose

Extend deterministic, offline regression coverage around the existing create-only atomic artifact publisher. Phase 2AI defined the operator drill plan; this phase closes several test gaps that can be exercised safely with temporary directories and fault injection.

## Added regression cases

- Unsupported same-directory hard-link operation fails closed. No direct-write fallback or final artifact is allowed.
- A destination symlink is treated as an existing destination. Neither the link nor its protected target is replaced.
- If directory synchronization fails after publication, cleanup removes only the inode ApexRecon published.
- If another process replaces the destination before failure cleanup, the replacement inode is preserved.
- Boolean, negative and out-of-range permission modes are rejected.
- Existing success, overwrite protection, staging synchronization failure, publication failure and cleanup checks remain covered.

## Safety and scope

All tests use Python temporary directories and mocked failure conditions. They do not fill storage, terminate a process, interrupt power, contact a network, run a target assessment, or touch normal evidence directories. The tests do not simulate kernel crash consistency or real filesystem power-loss behavior.

No production storage implementation is changed in this phase. The tests assert the existing fail-closed and inode-specific cleanup contract.

## Validation

From the repository root:

```bash
python3 -m compileall -q apex_storage.py tests
python3 -m unittest discover -s tests -p 'test_atomic_storage.py' -v
python3 -m unittest discover -s tests -v
```

A passing mocked test is not evidence that every Termux, proot, removable-storage or Linux filesystem supports hard links or provides identical crash durability.

## Exit gate

The phase is complete when the focused tests and full CI matrix pass. The Phase 2AI operator drills remain separately outstanding, including real filesystem-specific validation and disposable-VM power-loss testing.
