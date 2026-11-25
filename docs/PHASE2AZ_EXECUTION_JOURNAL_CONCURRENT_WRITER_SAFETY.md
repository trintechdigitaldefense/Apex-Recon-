# Phase 2AZ — Execution journal concurrent-writer safety

## Objective

Validate that independent processes appending to one execution journal are serialized safely by the existing advisory file lock. This phase adds offline tests only; it does not change journal or assessment behavior.

## Scenarios

- Two processes attempt to start the same selected module at the same time. Exactly one transition must succeed; the other must be rejected, and the journal must remain valid.
- Two processes start different selected modules at the same time. Both transitions must be retained in the append-only journal, with no lost event or hash-chain corruption.
- Two processes attempt to finish the same started module at the same time while publishing equivalent synthetic outcomes. Exactly one completion must succeed, one artifact reference must be recorded, and recovery inspection must verify the resulting artifact.

Each child process waits at a filesystem barrier so the parent can release competing operations together. Tests use subprocesses and temporary directories only.

## Run locally

From the repository root:

```bash
python3 -m compileall -q apex_execution.py tests
python3 -m unittest discover -s tests -p 'test_execution_journal_concurrency.py' -v
python3 -m unittest discover -s tests -v
git diff --check
git status --short
```

## Safety boundaries

- Synthetic execution identifiers, module names, and outcome data only.
- No assessment modules, target validation, DNS, HTTP, TLS, SMB, OSINT, or network activity.
- No real client evidence or credentials.
- No journal repair, truncation, replay, resume, sidecar adoption, or cleanup.
- No production execution code is modified by this phase.
- Tests exercise process-level advisory locking on the test filesystem. They do not prove behavior on every filesystem, network mount, Android storage provider, or under physical power loss.
- The separate Phase 2AM disposable-VM power-loss protocol remains outstanding.

## Interpretation

Passing these tests demonstrates the tested concurrent transitions remain serialized and verifiable in the tested environment. It is not a general guarantee of distributed locking or storage durability.
