# Phase 2AM — Controlled power-loss validation protocol

## Purpose

Turn the generic recovery procedures from Phase 2AI into a repeatable, evidence-led protocol for validating ApexRecon artifact publication and audit backup recovery after an actual virtual-machine power interruption.

This phase defines the controlled test plan and the evidence required to make a defensible result. It does not claim that power-loss testing has already been performed. GitHub Actions, unit tests, `os._exit`, and a successful filesystem capability probe are not substitutes for removing power from a disposable VM and inspecting the recovered filesystem.

## Scope

Test only the local storage and recovery paths already implemented:

- `apex_storage.write_exclusive_atomic()`
- HTTP/TLS and engagement artifact publication paths that use the atomic publisher
- Audit backup and detached checkpoint publication
- Offline backup verification and restore

No target scans, network requests, package installation, production evidence, or client data are part of this phase.

## Mandatory safety controls

1. Use a disposable Linux VM with a bounded virtual disk and a snapshot that can be restored.
2. Use synthetic audit events and uniquely named test artifacts only.
3. Keep the VM disconnected from external networks during the drill. No assessment targets are needed.
4. Do not run the drill on a primary phone, daily workstation, production server, shared VM, or any filesystem containing client evidence.
5. Do not use host-level power controls. The interruption must affect only the disposable guest VM.
6. Record the VM snapshot ID, virtual-disk size, filesystem and mount options before each run.
7. Restore the clean snapshot between independent scenarios. Do not reuse a damaged guest state as the baseline for another scenario.
8. If the test touches a path outside the dedicated drill workspace, stop and mark the run FAIL.
9. Do not run destructive filesystem repair, discard, trim, or journal manipulation commands during evidence collection.
10. A scenario that was not actually interrupted and recovered is NOT RUN, not PASS.

## Environment record

Record before each run:

- Date/time with timezone and operator
- ApexRecon commit SHA
- Hypervisor and VM identifier
- Snapshot identifier and virtual-disk size
- Guest OS, kernel, architecture and Python version
- Filesystem type, mount options and storage backend
- Free space before the drill
- Exact workspace path
- Scenario identifier and interruption point

## Scenario matrix

| ID | Interruption point | Expected recovery result | Required evidence |
|---|---|---|---|
| AM-1 | During staging, before final hard-link publication | No partial final-path artifact. A hidden staging file may exist and must be identified manually | Guest/host timestamps, workspace listing, file sizes, hashes and permissions |
| AM-2 | After final hard-link publication but before directory fsync completes | The final artifact may be absent or present after recovery. If present, it must contain the complete expected bytes; partial contents are a FAIL | Expected and recovered hashes, file length, mode, directory listing |
| AM-3 | After audit backup publication but before checkpoint publication | The backup/checkpoint pair is incomplete and verification must fail closed. No automatic repair or checkpoint reconstruction | Backup/checkpoint listing, backup hash, verifier output |
| AM-4 | During restore staging, before restore destination publication | No partial final restore destination. Original backup and checkpoint must remain unchanged and continue to verify | Source hashes before/after, destination listing, verifier output |
| AM-5 | After a completed restore and its successful verification | Restored bytes, event count and hash-chain head must match the captured verified source | Source and restored hashes, byte counts, event counts, chain heads |
| AM-6 | After a completed artifact publication and successful return | A fully completed artifact must remain byte-identical after reboot, or the run must explain a filesystem durability limitation | Pre-interruption and post-recovery hashes, file metadata, application output |

## Execution protocol

### 1. Prepare a clean guest

1. Restore the designated clean VM snapshot.
2. Confirm the guest is disconnected from external networks.
3. Create a new, dedicated drill workspace on the filesystem under test.
4. Confirm the workspace's absolute path and verify it is empty.
5. Record the environment and ApexRecon commit SHA.
6. Run the filesystem capability probe against the workspace parent:

```bash
python3 tools/apex_storage_probe.py --parent /absolute/path/to/drill-parent
```

A failed capability probe blocks the atomic-publication scenarios on that filesystem. Preserve the report; do not weaken the publisher or use a direct-write fallback to force a pass.

### 2. Establish a verified synthetic baseline

1. Create a synthetic audit trail using the existing local audit helper and test-only identifiers.
2. Verify the audit trail before creating a backup.
3. Create a backup and detached checkpoint in the drill workspace.
4. Verify the backup/checkpoint pair.
5. Record SHA-256 hashes, sizes, permissions, event count and chain head.
6. Confirm all paths resolve inside the dedicated workspace.

### 3. Execute each interruption scenario

1. Restore the clean snapshot before each independent scenario.
2. Recreate the synthetic baseline.
3. Arrange the interruption at the exact publication boundary named in the scenario matrix. Record how that boundary was reached.
4. Use the hypervisor's guest-only **Power Off** operation. Do not use guest shutdown, reboot, suspend, host shutdown, or a process kill as a substitute.
5. Restart the guest from the same virtual disk without restoring the clean snapshot.
6. Do not open or modify recovered artifacts before recording the initial directory listing and hashes.
7. Verify each artifact offline using the applicable ApexRecon verifier.
8. Record the observed result as PASS, FAIL, or NOT RUN. Explain any difference from the expected result.

If an exact interruption point cannot be reached deterministically with the available test setup, mark that scenario NOT RUN. Do not describe a random interruption as a precisely controlled checkpoint.

### 4. Repeatability

- Run each scenario at least three times from a clean snapshot.
- Preserve each run's output separately.
- Do not combine results from different filesystems or VM storage backends.
- Repeat on another filesystem only after completing and recording the first environment.
- Report intermittent outcomes as intermittent failures, not as a majority PASS.

## Pass/fail criteria

A scenario is PASS only when all applicable conditions are met:

- No pre-existing file is overwritten.
- No final-path artifact contains partial or malformed data.
- A missing or mismatched backup checkpoint is rejected.
- A completed backup/checkpoint pair verifies against its embedded audit chain.
- A successful restore is byte-identical to the verified captured audit payload.
- Restored event count and hash-chain head match the verified source.
- Source backup and checkpoint hashes remain unchanged during restore.
- Any staging residue is confined to the drill workspace and is explicitly recorded.
- No scan, external network request, package installation, or out-of-scope file access occurred.

Any partial final artifact, overwritten destination, successful verification of a mismatched pair, modified source backup, or unexplained filesystem mutation is a FAIL and blocks progression.

## Results record

Create one record per scenario run containing:

- Scenario ID, run number and date/time with timezone
- Operator and VM identifier
- ApexRecon commit SHA and snapshot ID
- Guest OS, kernel, filesystem, mount options and virtual-disk backend
- Exact interruption point and hypervisor action
- Expected and observed outcome
- Exit code and relevant complete output
- Initial and recovered file listings
- File sizes, modes and SHA-256 hashes
- Backup/checkpoint verification result
- Restore byte count, event count and chain head where applicable
- PASS / FAIL / NOT RUN and reason
- Confirmation that no client evidence or external targets were involved

## Interpretation limits

- A result applies only to the tested guest OS, filesystem, mount options, hypervisor, virtual-disk backend and storage configuration.
- A successful VM drill does not prove durability on Android flash storage, Termux native storage, proot bind mounts, other filesystems, or physical devices.
- A VM power cut does not necessarily reproduce sudden physical power loss, controller-cache loss, device firmware behavior, or every kernel/filesystem failure mode.
- The backup and checkpoint remain two separate publications, not a cross-file atomic transaction. An interrupted pair must fail closed and be handled manually.
- SHA-256 checksums and hash chains are tamper-evident integrity mechanisms, not immutable storage, trusted timestamps, proof of event truthfulness, or independent backup custody.
- Passing this phase does not by itself establish client readiness, production reliability, or 24-hour monitoring capability.

## Exit gate

Phase 2AM is complete only when the controlled VM scenarios are actually executed, each available scenario has at least three recorded runs, all required invariants pass, and the results are reviewed against the exact tested commit and environment.

Any scenario not safely executable remains NOT RUN and must be carried into the readiness assessment. No physical power-loss result may be inferred from CI or process-crash tests.
