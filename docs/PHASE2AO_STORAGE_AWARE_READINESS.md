# Phase 2AO — Storage-aware operational readiness

## Purpose

Make the local environment doctor distinguish ordinary directory write access from the stronger filesystem capabilities required to publish ApexRecon evidence safely.

## Behavior

- `apex_doctor.py` invokes the existing non-destructive filesystem capability probe against the configured artifact output directory.
- The result is compatible only when the probe reports `overall_atomic_storage_compatible: true` and confirms its temporary artifacts were removed.
- A missing probe, probe exception, unsupported hard-link API, failed atomic publication, failed directory synchronization, incorrect private mode, or incomplete cleanup is reported as unsupported/not verified.
- The doctor exits non-zero when atomic evidence storage is not verified. This is an environment readiness gate, not a claim that every other capability is unavailable.
- The diagnostic includes the probe result in JSON output and identifies the exact artifact directory tested.

## Operational interpretation

Native Termux previously reported that `os.link` is absent in its Python 3.14.6 environment. Its filesystem probe returned `overall_atomic_storage_compatible: false`; its full test suite also recorded failures/errors in code paths that require atomic publication. Native Termux must therefore be treated as unsuitable for evidence-producing assessments unless a future runtime/filesystem combination passes the actual probe.

Ubuntu/proot passed the capability probe in both the user's home directory and the ApexRecon repository directory, and passed 277 unit tests on the tested checkout. This is evidence for those observed paths and that environment only. It does not establish physical power-loss durability or universal compatibility across other mounts.

## Safety boundaries

- The existing `write_exclusive_atomic` implementation remains fail-closed. No direct-write fallback is introduced.
- The probe uses disposable temporary files under the selected artifact directory; it does not scan targets, make network requests, install packages, or change permissions on existing files.
- A successful probe is a point-in-time capability observation. Re-run it if the artifact directory or mount changes.
- This phase does not execute the Phase 2AM power-loss drills and does not approve client deployment.

## Validation

Run from the ApexRecon repository using the same Python interpreter used to launch the tool:

```bash
python3 -m compileall -q apex_storage.py tools tests
python3 -m unittest discover -s tests -v
python3 apex_doctor.py
python3 apex_doctor.py --json
python3 tools/apex_storage_probe.py --parent "$HOME"
python3 tools/apex_storage_probe.py --parent "$PWD"
```

A supported environment should show `Atomic evidence storage: COMPATIBLE` and the JSON field `capabilities.atomic_evidence_storage: true`. The standalone probe should return `overall_atomic_storage_compatible: true` for the actual artifact directory.

## Scope exclusions

No assessment execution, network behavior, target authorization logic, finding semantics, evidence format, audit behavior, or storage publication primitive is changed. CI and unit tests do not substitute for native Termux or device-specific manual validation.
