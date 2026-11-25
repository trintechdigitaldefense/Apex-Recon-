# Phase 2AS: recovery workflow integrity

Phase 2AS adds a read-only assessment of the consistency between an execution journal and its referenced module outcome sidecars.

## Recovery assessment

`inspect_execution_recovery(path)` reports:
- The complete execution-journal verification result, including original and verified-prefix digests.
- Each selected module's journal state.
- `NOT_STARTED` and `INTERRUPTED` module states.
- Whether a terminal module has no sidecar reference, a verified sidecar, or an invalid/unavailable sidecar.
- The sidecar filename and SHA-256 only when a reference exists.
- A conservative aggregate status: `JOURNAL_INVALID`, `REVIEW_REQUIRED`, or `EVIDENCE_VERIFIED`.

Sidecars are checked against the journal-bound filename, digest, execution identifier, module, terminal status, schema version and outcome status. A missing or malformed sidecar is reported as invalid evidence; it is not reconstructed.

## Safety boundaries

- Inspection is read-only and does not alter the journal or sidecars.
- An invalid journal produces no module recovery list. Its verified prefix remains diagnostic only.
- `NOT_STARTED` and `STARTED` modules are never resumed or replayed.
- A terminal journal state without a sidecar reference is reported as `NO_ARTIFACT_RECORDED`; it is not treated as verified recovery evidence.
- A referenced sidecar that cannot be opened, parsed, or matched is reported as `INVALID`.
- The assessment does not repair, truncate, delete, rename, reorder, or append evidence.
- Checksums establish byte consistency, not assessment truth, completeness, or immutability.
- No network access, target interaction, assessment scope, authorization prompt, or scan behavior changes.

## Validation scope

Tests use synthetic journal events and temporary directories. They cover valid sidecars, missing sidecars, tampered sidecars, interrupted modules, not-started modules, and invalid journals. These tests do not simulate physical power loss or prove filesystem durability.

The Phase 2AM controlled power-loss protocol remains outstanding and must be executed in a disposable VM with synthetic data.
