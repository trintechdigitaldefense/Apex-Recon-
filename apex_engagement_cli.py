"""Pure, fail-closed helpers for Phase 2J/2K unified engagement orchestration."""
import math
from datetime import datetime

from apex_findings import FindingSchemaError, normalize_findings

MODULE_NAMES = (
    "External Footprinting (OSINT)",
    "SMB Network Auditor",
    "HTTP Security Assessment",
    "TLS Security Assessment",
)
VALID_STATUSES = {"COMPLETED", "PARTIAL", "FAILED", "NOT_RUN"}
MAX_FINDINGS = 2000


def parse_module_selection(value):
    """Parse ALL or a comma-separated set of module numbers (1-4)."""
    if not isinstance(value, str):
        raise ValueError("Enter ALL or one or more module numbers from 1 to 4")
    raw = value.strip().upper()
    if raw == "ALL":
        return set(MODULE_NAMES)
    if not raw:
        raise ValueError("Select at least one module")
    parts = [part.strip() for part in raw.split(",")]
    if any(not part.isdigit() for part in parts):
        raise ValueError("Use ALL or comma-separated module numbers from 1 to 4")
    numbers = [int(part) for part in parts]
    if any(number < 1 or number > len(MODULE_NAMES) for number in numbers):
        raise ValueError("Module numbers must be between 1 and 4")
    if len(set(numbers)) != len(numbers):
        raise ValueError("Duplicate module selections are not allowed")
    return {MODULE_NAMES[number - 1] for number in numbers}


def _failure_entry(name, reason):
    return {
        "module": name, "status": "FAILED",
        "target_scope": {"module": name, "scope": "module result rejected"},
        "findings": [], "duration_seconds": 0,
        "limitations": [reason],
    }


def _valid_scope(scope):
    if not isinstance(scope, dict) or not scope:
        return False
    for key, value in scope.items():
        if not isinstance(key, (str, int, float)) or not str(key).strip():
            return False
        if isinstance(value, (str, int, float)):
            continue
        if isinstance(value, list) and len(value) <= 50:
            if all(isinstance(part, (str, int, float)) for part in value):
                continue
        return False
    return True


def _valid_timestamp(value):
    if not isinstance(value, str):
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _validate_outcome(name, outcome):
    if not isinstance(outcome, dict):
        raise ValueError("module result must be an object")
    status = str(outcome.get("status", "")).strip().upper()
    if status not in VALID_STATUSES:
        raise ValueError("module status is missing or unsupported")
    findings = outcome.get("findings", [])
    if not isinstance(findings, list):
        raise ValueError("findings must be a list")
    if len(findings) > MAX_FINDINGS:
        raise ValueError("module exceeds the engagement finding limit")
    if status == "NOT_RUN" and findings:
        raise ValueError("NOT_RUN module cannot contain findings")
    if not _valid_scope(outcome.get("target_scope")):
        raise ValueError("target scope must be a non-empty scalar/list object")
    duration = outcome.get("duration_seconds", 0)
    if (isinstance(duration, bool) or not isinstance(duration, (int, float))
            or not math.isfinite(duration) or duration < 0 or duration > 86400):
        raise ValueError("duration must be finite and between 0 and 86400 seconds")
    limitations = outcome.get("limitations", [])
    if (not isinstance(limitations, list) or len(limitations) > 100
            or any(not isinstance(item, (str, int, float)) or not str(item).strip()
                   for item in limitations)):
        raise ValueError("limitations must contain at most 100 non-empty scalar items")
    for field in ("started_at", "completed_at"):
        if field in outcome and not _valid_timestamp(outcome[field]):
            raise ValueError(f"{field} must be a timezone-aware ISO-8601 timestamp")
    try:
        normalize_findings(findings, name, default_confidence="UNKNOWN",
                           default_evidence_type="UNKNOWN")
    except FindingSchemaError as exc:
        raise ValueError("finding data failed common-schema validation") from exc
    result = {
        "module": name, "status": status, "target_scope": outcome["target_scope"],
        "findings": findings, "duration_seconds": duration, "limitations": limitations,
    }
    for field in ("started_at", "completed_at"):
        if field in outcome:
            result[field] = outcome[field]
    return result


def run_selected_modules(selected, runners, on_start=None, on_error=None,
                         before_run=None, on_finish=None,
                         abort_on_checkpoint_error=False):
    """Run selected callables with optional durable before/after checkpoints.

    on_start remains observational. before_run is a strict gate: if it fails,
    the module is not invoked. on_finish runs after a callable returns or is
    converted to a failure result; if it fails, the result is downgraded to
    FAILED so an unrecorded completion cannot look successful.

    When abort_on_checkpoint_error is true, a before_run or on_finish failure
    stops the remaining selected modules. This is intended for durable
    execution journals where continuing after a storage/checkpoint failure
    could create untracked assessment activity. Ordinary runner failures keep
    the existing continue-to-next-module behavior.
    """
    if isinstance(selected, (str, bytes)):
        raise ValueError("selected must be a collection of module names")
    selected = set(selected)
    if not selected or not selected.issubset(set(MODULE_NAMES)):
        raise ValueError("selected must contain one or more supported modules")
    if not isinstance(runners, dict):
        raise ValueError("runners must be a mapping")
    outcomes = {}
    for name in MODULE_NAMES:
        if name not in selected:
            continue
        if callable(before_run):
            try:
                before_run(name)
            except Exception as exc:
                if callable(on_error):
                    try:
                        on_error(name, exc)
                    except Exception:
                        pass
                outcomes[name] = _failure_entry(
                    name, f"Module was not started because its execution checkpoint failed ({type(exc).__name__})."
                )
                if abort_on_checkpoint_error:
                    break
                continue
        # Operator callbacks are observational only. A broken console/logging
        # callback must never prevent an authorized module runner from executing.
        if callable(on_start):
            try:
                on_start(name)
            except Exception:
                pass
        runner = runners.get(name)
        try:
            if not callable(runner):
                raise RuntimeError("No callable runner is registered")
            outcomes[name] = runner()
        except Exception as exc:
            if callable(on_error):
                try:
                    on_error(name, exc)
                except Exception:
                    pass
            outcomes[name] = _failure_entry(
                name, f"Module stopped unexpectedly ({type(exc).__name__}); inspect the operator log."
            )
        if callable(on_finish):
            try:
                on_finish(name, outcomes[name])
            except Exception as exc:
                if callable(on_error):
                    try:
                        on_error(name, exc)
                    except Exception:
                        pass
                outcomes[name] = _failure_entry(
                    name, f"Module result could not be checkpointed ({type(exc).__name__}); treat execution as incomplete."
                )
                if abort_on_checkpoint_error:
                    break
    return outcomes


def assemble_module_results(selected, outcomes):
    """Create all four entries; isolate invalid output to its originating module."""
    if isinstance(selected, (str, bytes)):
        raise ValueError("selected must be a collection of module names")
    selected = set(selected)
    if not selected.issubset(set(MODULE_NAMES)):
        raise ValueError("Unsupported selected module")
    if not isinstance(outcomes, dict):
        raise ValueError("outcomes must be a mapping")
    entries = []
    total_findings = 0
    for name in MODULE_NAMES:
        if name not in selected:
            entries.append({
                "module": name, "status": "NOT_RUN",
                "target_scope": {"selection": "NOT_SELECTED"},
                "findings": [], "duration_seconds": 0,
                "limitations": ["Operator did not select this module for the engagement."],
            })
            continue
        outcome = outcomes.get(name)
        if outcome is None:
            entries.append({
                "module": name, "status": "NOT_RUN",
                "target_scope": {"selection": "SELECTED_BUT_NOT_RUN"},
                "findings": [], "duration_seconds": 0,
                "limitations": ["Module did not proceed, for example because target validation or authorization was not completed."],
            })
            continue
        try:
            validated = _validate_outcome(name, outcome)
            if total_findings + len(validated["findings"]) > MAX_FINDINGS:
                raise ValueError("combined engagement exceeds the finding limit")
            total_findings += len(validated["findings"])
            entries.append(validated)
        except (TypeError, ValueError, OverflowError):
            entries.append(_failure_entry(
                name, "Module output failed engagement validation or exceeded the engagement finding limit; inspect the operator log."
            ))
    return entries
