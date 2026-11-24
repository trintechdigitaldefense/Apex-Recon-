"""Pure selection and result-assembly helpers for Phase 2J CLI orchestration."""

MODULE_NAMES = (
    "External Footprinting (OSINT)",
    "SMB Network Auditor",
    "HTTP Security Assessment",
    "TLS Security Assessment",
)
VALID_STATUSES = {"COMPLETED", "PARTIAL", "FAILED", "NOT_RUN"}


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


def assemble_module_results(selected, outcomes):
    """Create all four required entries, explicitly marking skipped work."""
    selected = set(selected)
    if not selected.issubset(set(MODULE_NAMES)):
        raise ValueError("Unsupported selected module")
    if not isinstance(outcomes, dict):
        raise ValueError("outcomes must be a mapping")
    entries = []
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
        if not isinstance(outcome, dict):
            raise ValueError(f"Outcome for {name} must be an object or None")
        status = str(outcome.get("status", "")).strip().upper()
        if status not in VALID_STATUSES:
            raise ValueError(f"Invalid status for {name}")
        findings = outcome.get("findings", [])
        if not isinstance(findings, list):
            raise ValueError(f"Findings for {name} must be a list")
        if status == "NOT_RUN" and findings:
            raise ValueError(f"NOT_RUN module {name} cannot contain findings")
        scope = outcome.get("target_scope")
        if not isinstance(scope, dict) or not scope:
            raise ValueError(f"Target scope for {name} must be a non-empty object")
        entries.append({
            "module": name, "status": status, "target_scope": scope,
            "findings": findings,
            "duration_seconds": outcome.get("duration_seconds", 0),
            "limitations": outcome.get("limitations", []),
        })
    return entries
