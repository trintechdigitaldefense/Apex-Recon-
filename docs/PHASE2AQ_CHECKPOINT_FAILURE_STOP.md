# Phase 2AQ — Stop-on-checkpoint-failure execution integrity

## Purpose

Prevent a unified engagement from starting additional assessment modules after a durable execution-journal checkpoint fails.

## Behavior

The shared `run_selected_modules` helper now supports an opt-in `abort_on_checkpoint_error` mode. The unified engagement CLI enables it.

When enabled:

- If a module's pre-run journal checkpoint fails, that module is not invoked and no later selected module is started.
- If a module returns but its completion outcome cannot be durably checkpointed, its result is downgraded to FAILED and no later selected module is started.
- Modules not reached after the checkpoint failure are represented as selected-but-not-run in the engagement report.
- The execution journal remains incomplete when selected module states are unresolved. Finalization is not forced or repaired.
- No assessment is automatically resumed, retried, replayed, or re-contacted.

Ordinary assessment runner failures retain the existing behavior: the failure is recorded and later selected modules may continue, provided the required start and completion checkpoints succeed. Operator display/log callbacks remain observational and do not control assessment execution.

The default for other callers of `run_selected_modules` remains unchanged. The new fail-stop behavior is explicitly enabled by the unified engagement workflow.

## Why this matters

A failed durable checkpoint means ApexRecon may no longer be able to prove which module ran or preserve its outcome consistently. Continuing with additional assessment modules could create more untracked activity. Stopping is safer than pretending the journal failure is merely another module error.

## Validation

The offline regression tests cover:

- Start-checkpoint failure blocks the current module and all later selected modules.
- Completion-checkpoint failure downgrades the current result and blocks all later selected modules.
- Later modules are represented as NOT_RUN in assembled engagement results.
- Default helper behavior remains backward compatible when the new flag is not enabled.
- Existing ordinary runner-failure isolation remains intact.

Run:

```bash
python3 -m compileall -q apex_engagement_cli.py apex_recon_v2.py tests
python3 -m unittest discover -s tests -p 'test_engagement_cli.py' -v
python3 -m unittest discover -s tests -v
```

Tests use synthetic outcomes and callbacks. No live target, network request, package installation, or destructive storage operation is involved.

## Limitations

This phase adds a fail-stop policy around the existing unified execution journal. It does not make journal append and artifact publication a multi-file transaction, guarantee physical power-loss durability, or prove assessment accuracy. The controlled VM power-loss drills remain outstanding. It does not approve client deployment or production release.
