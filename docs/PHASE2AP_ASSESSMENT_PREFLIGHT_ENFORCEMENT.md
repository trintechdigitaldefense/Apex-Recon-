# Phase 2AP — Assessment preflight enforcement

## Purpose

Prevent an assessment module from starting when the current local environment cannot safely publish its evidence artifacts.

## Enforcement point

The main menu now runs a fresh preflight immediately before starting any of these workflows:

- External Footprinting (OSINT)
- Local Network SMB Auditor
- HTTP Security Assessment
- TLS Security Assessment
- Unified Engagement

The preflight happens before the module's target prompt and before its assessment runner is invoked. A failed or unavailable diagnostic blocks that module for the current attempt. The operator can correct the local environment and retry.

## Required checks

The preflight requires all of the following:

- Python runtime meets the project's supported minimum.
- Required ApexRecon project files are present.
- The current working directory, which is where the assessment modules publish their relative-path artifacts, is writable.
- The storage capability probe has actually run against that directory and reports atomic evidence storage as compatible.

A missing diagnostic, exception, unverified probe, or incompatible result fails closed. The operator receives a concise reason and a message that no assessment module was started and no target was contacted.

## Scope and behavior

- This phase gates the five assessment workflows listed above.
- Evidence signing and offline verification remain independent and are not blocked by assessment-storage preflight.
- No assessment target is resolved, prompted for, or contacted before the gate passes.
- The check uses the existing local doctor and storage probe. It does not install packages, change permissions, modify existing files, or make network requests.
- The gate is point-in-time. It does not guarantee that storage remains available throughout a later assessment, and publication operations continue to fail closed if storage changes or fails.
- The preflight uses the current working directory because the legacy assessment modules write their reports and evidence artifacts using relative paths. Changing directories changes the tested destination.

## Validation

Run from the repository directory using the same Python interpreter used to launch ApexRecon:

```bash
python3 -m compileall -q apex_storage.py tools tests apex_recon_v2.py
python3 -m unittest discover -s tests -v
python3 apex_doctor.py
python3 tools/apex_storage_probe.py --parent "$PWD"
```

The new tests cover compatible storage, unsupported or unverified storage, incomplete project files, an unwritable artifact directory, unsupported Python, diagnostic exceptions, and confirmation that the assessment runner is never invoked after a failed preflight.

## Limitations

- This is a local readiness gate, not a live-target validation.
- A successful preflight does not prove assessment accuracy, authorization, report completeness, or power-loss durability.
- The Phase 2AM controlled power-loss protocol remains outstanding.
- Native Termux remains unsuitable for evidence-producing assessments on the previously tested runtime because its `os.link` capability is absent. Ubuntu/proot compatibility is limited to the specific tested environment and paths.
- This phase does not approve client deployment, unattended operation, or a production release.