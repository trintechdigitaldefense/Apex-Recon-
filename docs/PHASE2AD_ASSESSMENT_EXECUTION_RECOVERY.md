# Phase 2AD — Assessment execution recovery and evidence checkpoints

## Purpose

Record which selected modules started and finished, preserve each returned module result as a separate local evidence artifact, and identify engagements that did not reach final export. Recovery is inspection and manual reconstruction only. ApexRecon never resumes a network assessment automatically.

## Execution journal

At the start of a unified engagement, ApexRecon creates a private, create-only apex_execution_UUID.jsonl file. It records:
- Engagement execution identifier and selected module names.
- A hash-chained MODULE_STARTED event before invoking each selected module.
- A hash-chained MODULE_FINISHED event after the module returns or is converted to a failure result.
- Finalization success or failure after the consolidated JSON report is written.

The journal stores module names, state, timestamps, artifact filenames and SHA-256 checksums. It does not store target addresses, credentials, findings or scan instructions.

## Completed module evidence

Each module outcome returned by the runner is serialized to a separate owner-only JSON sidecar before its terminal journal event is appended. This means results from modules that finished before a later process crash remain available even if the unified engagement JSON was never generated.

The sidecar is referenced by its filename and SHA-256 digest in the journal. load_completed_module_artifacts() verifies the journal, file type, sidecar checksum and metadata before returning the saved outcome objects.

If the process stops after writing a sidecar but before appending its MODULE_FINISHED event, the sidecar is an unreferenced orphan. Do not treat it as verified recovery evidence; preserve it for manual inspection.

## Recovery states

- READY: journal created, no selected module has started.
- INCOMPLETE: one or more selected modules remain unstarted or started without a terminal event. After confirming the original process has exited, treat this as interrupted.
- AWAITING_FINALIZATION: all selected modules have terminal states, but the unified report finalization event is absent.
- FINALIZED: the unified JSON report was written and the journal finalization event was recorded.
- FINALIZATION_FAILED: all modules reached terminal states, but unified report export failed.
- INVALID: journal framing, schema, transition, or hash-chain validation failed.

A module state can be NOT_STARTED, STARTED, COMPLETED, PARTIAL, FAILED, or NOT_RUN. A STARTED state after process exit is interrupted, not a completed assessment.

## Operator inspection

Inspect a journal without changing it:

```bash
python3 apex_execution.py apex_execution_UUID.jsonl --verify-artifacts
```

Use the Python helper load_completed_module_artifacts(path) to load only the verified module sidecars. Rebuild or export a report manually after reviewing the recovered module states and evidence. Never re-run a module merely because its journal state is incomplete without a new operator decision and fresh scope/authorization confirmation.

## Safety and limitations

- Existing module target prompts and written-authorization gates remain in place.
- A journal start event is fsynced before the selected module callable is invoked.
- Module outcome sidecars are written atomically and privately before the corresponding finish event.
- A failed checkpoint prevents a module from starting or downgrades its result to FAILED; an unfinished journal is not finalized.
- No automatic resume, retry, replay, scheduling, background monitoring, or target re-contact is implemented.
- The journal and sidecars are local, tamper-evident through SHA-256 chaining/checksums, but are not immutable or digitally signed. Protect and back them up separately.
- Sidecars can contain target and finding evidence. Keep the output directory private and follow client retention requirements.
- A crash during append can leave an incomplete final journal line. The journal then fails closed; do not truncate or repair it automatically.
- No assessment methods, request counts, paths, ports, probes, redirects, or target scope are changed.
- No live targets contacted during development or tests.

## Validation

```bash
python3 -m compileall -q apex_execution.py apex_engagement_cli.py apex_recon_v2.py apex_doctor.py tests
python3 -m unittest discover -s tests -v
```

Tests use temporary local files and synthetic module outcomes. They cover valid state transitions, incomplete recovery, no automatic resume, outcome sidecar recovery, tamper detection, torn journal tails, and strict checkpoint failure behavior.
