# Phase 2K — Unified Engagement Reliability

## Purpose

Phase 2K hardens the Phase 2J operator-driven unified engagement workflow. The objective is to preserve valid module results and continue the selected sequence when an individual module fails or returns malformed output.

## Changes

- Selected modules execute in a stable, sequential order.
- An unexpected exception or missing runner is isolated to that module and recorded as FAILED.
- A selected module that returns no result remains NOT_RUN / SELECTED_BUT_NOT_RUN. This preserves the distinction between declined authorization or rejected target input and a completed assessment.
- Each module result is independently validated for status, findings, target scope, duration, limitations and optional timezone-aware timestamps.
- Invalid module output is represented as FAILED with an explicit limitation. It does not discard valid results from other modules.
- Unselected modules remain NOT_RUN / NOT_SELECTED.
- Existing module-specific target validation and exact-scope written-authorization prompts remain unchanged.

## Validation

Run the offline test suite:

```bash
python3 -m compileall -q apex_recon_v2.py apex_engagement_cli.py tests
python3 -m unittest discover -s tests -v
```

Tests use synthetic module data and injected runner functions. They do not execute assessment modules or contact live targets.

## Boundaries

- No scan commands, probes, paths, ports, request counts, target expansion or network behavior are added.
- No authorization gate is removed or bypassed.
- No background execution, scheduling, recurring scanning or 24-hour monitoring is introduced.
- Invalid results are not silently treated as clean or complete.
- This draft phase does not establish live accuracy, platform compatibility, client readiness or production readiness.
- No merge, release or deployment is included.
