# Phase 2AU — Recovery CLI Process Validation

## Purpose

Phase 2AU validates the operator recovery command through the same operating-system process boundary used in normal terminal operation. Existing tests that call `main()` directly remain useful unit tests, but they do not prove that the executable script, argument parsing, process exit status, and output work together as invoked by an operator.

## Controlled test design

The integration tests create all inputs in temporary directories using `ExecutionJournal` and synthetic module outcomes. They do not run assessment modules or contact targets.

The subprocess tests cover:

1. **Verified evidence:** create a journal, start and complete a selected module, persist its synthetic outcome sidecar, finalize the journal, then run `apex_execution.py <journal> --recovery`. The CLI must exit with code `0` and report `EVIDENCE_VERIFIED`.
2. **Interrupted module:** create a journal and record a module start without a completion event or sidecar. The CLI must exit with code `2` and report `REVIEW_REQUIRED` / `INTERRUPTED`.
3. **Missing sidecar:** create a completed synthetic module outcome, remove its sidecar before inspection to model missing evidence, and run the CLI. The CLI must exit with code `2` and report `REVIEW_REQUIRED` / `INVALID`.

For each case, the tests snapshot the journal and any relevant sidecar state before invoking the subprocess. They verify that inspection leaves existing journal and sidecar bytes unchanged and does not recreate a missing sidecar.

The subprocess is launched with the current Python interpreter, the repository's actual `apex_execution.py` entry point, and the temporary fixture directory as its working directory. A timeout prevents a hung CLI test from blocking the suite.

## Run locally

From the ApexRecon repository root:

```bash
python3 -m unittest discover -s tests -p 'test_recovery_cli.py' -v
```

Run the complete suite with:

```bash
python3 -m unittest discover -s tests -v
```

## Safety boundaries

- All journals and sidecars are synthetic and confined to temporary test directories.
- No live assessment modules, target prompts, DNS lookups, HTTP requests, port scans, or other target interactions are invoked.
- The missing-sidecar test removes only its synthetic fixture sidecar before inspection; the recovery CLI itself must not recreate it.
- The CLI is expected to be read-only. These tests verify byte-for-byte preservation of the journal and present sidecars, plus continued absence of the deliberately missing sidecar.
- A passing test demonstrates process-level CLI behavior for these controlled fixtures. It does not prove physical power-loss durability, storage-controller behavior, assessment accuracy, or client deployment readiness.

## Phase 2AT exit-code contract

- `0`: journal and applicable evidence artifacts verify.
- `1`: journal is invalid or cannot be safely inspected.
- `2`: journal is valid but operator review is required.

No test or command in this phase resumes, replays, repairs, truncates, or reconstructs an engagement.
