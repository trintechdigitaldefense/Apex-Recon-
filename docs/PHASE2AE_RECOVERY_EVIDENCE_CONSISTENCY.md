# Phase 2AE — Recovered evidence and execution-state consistency

## Purpose

Ensure that a module outcome's own status agrees with the terminal status recorded in its Phase 2AD execution journal. A checksum proves that the saved bytes match the journal reference; it does not by itself prove that the fields inside those bytes agree with the journal's state transition.

## Changes

- Before writing a module sidecar, `finish_module()` requires the outcome object's `status` to match the requested journal terminal status.
- During recovery, `load_completed_module_artifacts()` independently checks the embedded outcome status against both the sidecar metadata and the journal module state.
- A mismatch is rejected. It is not silently normalized or rewritten.
- If the pre-publication check fails, no sidecar is created and the module remains STARTED, so the engagement remains INCOMPLETE until an operator resolves it manually.
- Regression coverage verifies that a contradictory outcome is rejected without publishing a sidecar or changing the journal state.

## Safety and scope

- No network requests, assessment commands, target scope, authorization prompts or module selection behavior change.
- Recovery remains offline inspection and manual reconstruction only. No automatic resume, retry, replay or target re-contact is introduced.
- No live targets are contacted by these tests.
- SHA-256 remains tamper-evident integrity checking, not immutable storage, a digital signature or proof that assessment observations are truthful.
- A status match establishes internal consistency only; it does not establish that a module actually completed all intended checks.

## Validation

```bash
python3 -m compileall -q apex_execution.py apex_engagement_cli.py apex_recon_v2.py apex_doctor.py tests
python3 -m unittest discover -s tests -v
```

Tests use temporary local files and synthetic module outcomes.
