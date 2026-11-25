# Phase 2AT — Operator-Facing Recovery Inspection

## Purpose

Phase 2AT exposes the existing Phase 2AS recovery-consistency diagnostic through a dedicated operator command. The command inspects an existing execution journal and its referenced module outcome sidecars without initiating or continuing an assessment.

## Usage

From the ApexRecon project directory:

```bash
python3 apex_execution.py /path/to/apex_execution_<UUID>.jsonl --recovery
```

The output shows journal integrity, execution status, per-module journal state, sidecar verification status, and any verification error. It deliberately omits raw assessment findings and target details.

## Exit codes

- `0`: journal is valid and every applicable recorded artifact is verified.
- `1`: journal is invalid or could not be safely inspected.
- `2`: journal is valid, but operator review is required because a module is interrupted, not started, missing an artifact reference, or has an invalid artifact.

A non-zero result is not an instruction to resume or repair the engagement.

## Safety properties

- Read-only journal and sidecar access.
- No target prompt, authorization prompt, network request, module runner, or retry.
- No journal truncation, repair, artifact reconstruction, deletion, or overwrite.
- Invalid journals do not expose verified-prefix module state as trusted recovery state.
- Raw findings and target scope are not printed.
- Existing default journal inspection and `--verify-artifacts` JSON behavior remain available.

## Validation

The test suite uses temporary directories and synthetic journal/artifact fixtures. It does not contact assessment targets. Local Ubuntu-proot validation remains required before treating this phase as locally verified.
