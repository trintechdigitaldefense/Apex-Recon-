# Phase 2AI — Controlled operational recovery drill runbooks

## Purpose

Define repeatable, evidence-based operational drills for the local evidence-storage and audit-backup paths hardened in Phases 2AC–2AH. These procedures are for disposable test data and isolated test directories only. They do not authorize scans, production-data experiments, or changes to `main`.

This phase documents and standardizes operator-executed drills. A passing unit test or CI run is not a substitute for a physical interruption test on the intended filesystem.

## Safety rules

- Use a disposable checkout or isolated test environment and synthetic audit data.
- Never point a drill at a real client engagement, live audit trail, private signing key, or normal evidence directory.
- Do not fill the phone's or workstation's real storage to trigger ENOSPC. Use a bounded disposable filesystem/VM disk with a known size and a snapshot.
- Do not deliberately remove power from a primary phone or workstation. Power-loss testing belongs on a disposable VM or dedicated lab device with recoverable test data.
- Record OS, kernel, Python version, filesystem/mount type, Termux/proot status, available space, and exact commit SHA.
- Stop immediately if a command resolves outside the disposable drill directory or if any unexpected real artifact is touched.
- Do not run target scans during these drills. No network access is required.

## Drill matrix

| ID | Scenario | Expected safe outcome | Evidence to retain |
|---|---|---|---|
| D1 | Process exits before atomic publication | No partial final-path artifact; a hidden staging file may remain after an uncatchable exit | Directory listing, process exit point, artifact hashes |
| D2 | Process exits after backup publication but before checkpoint publication | Incomplete pair is detected; verification fails closed; no automatic reconstruction | Backup/checkpoint listing and verifier result |
| D3 | File or directory synchronization fails | Publication fails; no partial final artifact remains after handled failure | Test output and directory listing |
| D4 | Destination already exists | Existing evidence is not overwritten | Before/after hashes and error |
| D5 | Destination directory is not writable | Operation fails without publishing a final artifact | Permissions, error, directory listing |
| D6 | Storage exhaustion on bounded disposable filesystem | Operation fails closed; no partial final artifact; any staging residue is identified | Filesystem capacity, error, directory listing |
| D7 | Same-directory hard links are unsupported | Atomic publisher fails closed; no weaker fallback is used | Filesystem type and error |
| D8 | Interrupted restore | No partial final restore destination; source backup/checkpoint remain unchanged | Source hashes, destination listing |
| D9 | Restore to an existing destination | Existing destination remains byte-for-byte unchanged | Before/after destination hash |
| D10 | Controlled VM power cut/restart | Recovery is manual; incomplete backup/checkpoint pair is rejected; valid completed artifacts verify | VM snapshot IDs, logs, hashes, verifier output |

## Baseline validation

From the repository root, first record the commit and environment, then run:

```bash
git rev-parse HEAD
python3 --version
python3 -m compileall -q apex_storage.py apex_audit.py apex_audit_backup.py tests
python3 -m unittest discover -s tests -v
```

For the focused storage and audit-backup regression tests:

```bash
python3 -m unittest discover -s tests -p 'test_*storage*.py' -v
python3 -m unittest discover -s tests -p 'test_audit_backup.py' -v
```

A filename pattern that matches no tests is not a passing drill. Confirm that the test runner reports at least one test executed.

## Execution procedure

1. Create a new disposable directory on the filesystem being evaluated. Keep all synthetic inputs and outputs beneath it.
2. Confirm the resolved absolute path and available space. Do not reuse a directory containing client evidence.
3. Generate a synthetic audit trail using the repository's existing audit test fixtures or test helpers. Do not copy a real audit log.
4. Run baseline validation and retain the complete output.
5. Execute only the scenarios supported by the current test helpers or a purpose-built disposable harness. Do not improvise destructive shell commands against the host filesystem.
6. For every scenario, record the expected result, actual result, exit code, final directory listing, and SHA-256 hashes of all files that should remain.
7. Verify source backup and checkpoint hashes before and after restore drills. A restore must not mutate either source file.
8. Repeat on each supported environment separately: Termux native storage, Termux/proot Linux storage, and a conventional Linux filesystem. Record unsupported environments rather than guessing.
9. For power-loss testing, use a disposable VM with a snapshot and a bounded virtual disk. Force-stop the VM only at a documented test point, restart from the snapshot, then inspect artifacts offline. Never do this on a user's primary device.
10. Preserve raw logs and results. Do not label a scenario PASS unless its expected invariants were checked.

## Pass/fail criteria

A scenario passes only when all applicable invariants hold:

- No existing evidence file is overwritten.
- No final-path file is exposed with partial contents.
- A missing or mismatched checkpoint causes verification to fail closed.
- A successful restore is byte-identical to the captured verified audit payload and has matching event count and hash-chain head.
- A failed restore does not leave a partial destination.
- Source backup/checkpoint bytes remain unchanged during verification and restoration.
- Unsupported atomic-publication capabilities fail closed, without silently falling back to direct writes.
- Recovery is manual and offline. No scan is automatically resumed, replayed, or re-contacted.

Any unexpected file mutation, successful verification of a mismatched pair, partial final artifact, overwritten destination, or unplanned network activity is a FAIL and blocks progression.

## Results record template

For each drill, record:

- Drill ID and date/time (with timezone)
- Operator and test-environment identifier
- ApexRecon commit SHA
- OS, kernel, Python version, filesystem/mount type
- Termux native / proot / Linux VM
- Exact synthetic test setup and commands
- Expected result and observed result
- Exit code and complete relevant output
- Before/after file listing, sizes, permissions, and SHA-256 hashes
- PASS / FAIL / NOT RUN, with reason
- Any cleanup performed and confirmation that cleanup stayed inside the disposable directory

## Known limitations

- Unit fault injection does not reproduce every kernel, filesystem, device-cache, or power-loss behavior.
- Atomic publication relies on same-directory hard-link support and filesystem semantics. Validate each target filesystem independently.
- Backup and checkpoint are separate publications, not a multi-file atomic transaction. A hard interruption between them can leave an incomplete pair that must fail verification and be handled manually.
- A process killed before temporary-file cleanup can leave a hidden `.apexrecon-tmp-*` file. Inspect and handle it manually only after confirming it is inside the disposable drill directory and is not an active writer's file.
- SHA-256 and hash chaining are tamper-evident checks, not immutable storage, trusted timestamps, proof of event truthfulness, or a substitute for independent backup custody.
- These runbooks do not establish client readiness, production reliability, or 24-hour monitoring capability.

## Exit gate

Phase 2AI is complete only when the runbooks are reviewed and the drill results are recorded for each available environment. Any scenario that cannot safely be executed is marked NOT RUN with a reason; it is not silently treated as passed. Physical power-loss and filesystem-specific results remain outstanding until actually observed.
