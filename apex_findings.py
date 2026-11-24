"""Shared, conservative finding schema for ApexRecon assessment modules.

The schema standardizes how evidence is represented. It does not calculate
risk, infer exploitability, or upgrade a module's severity decisions.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any


FINDING_SCHEMA_VERSION = "1.1"
SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"}
CONFIDENCE_LEVELS = {"HIGH", "MEDIUM", "LOW", "UNKNOWN"}
EVIDENCE_TYPES = {"OBSERVATION", "INDICATOR", "INFERENCE", "UNKNOWN"}
REVIEW_PRIORITIES = {"P1", "P2", "P3", "INFO", "UNRANKED"}

_PRIORITY_BY_SEVERITY = {
    "CRITICAL": "P1",
    "HIGH": "P1",
    "MEDIUM": "P2",
    "LOW": "P3",
    "INFO": "INFO",
    "UNKNOWN": "UNRANKED",
}

_SEVERITY_ALIASES = {"CRIT": "CRITICAL", "MED": "MEDIUM", "NOT_ASSESSED": "UNKNOWN"}
_CONFIDENCE_ALIASES = {"CERTAIN": "HIGH", "MODERATE": "MEDIUM", "WEAK": "LOW"}
_TEXT_LIMITS = {
    "module": 100,
    "check": 200,
    "status": 100,
    "evidence": 4000,
    "recommendation": 4000,
}


class FindingSchemaError(ValueError):
    """Raised when a finding cannot be safely normalized."""


def _text(value: Any, field: str, *, required: bool = False) -> str:
    limit = _TEXT_LIMITS[field]
    if value is None:
        value = ""
    if not isinstance(value, (str, int, float)):
        raise FindingSchemaError(f"finding {field} must be scalar text")
    result = str(value).strip()[:limit]
    if required and not result:
        raise FindingSchemaError(f"finding {field} is required")
    return result


def _level(value: Any, allowed: set[str], aliases: dict[str, str]) -> str:
    if not isinstance(value, str):
        return "UNKNOWN"
    normalized = re.sub(r"[\s-]+", "_", value.strip().upper())
    normalized = aliases.get(normalized, normalized)
    return normalized if normalized in allowed else "UNKNOWN"


def normalize_finding(
    finding: dict,
    module: str,
    *,
    default_confidence: str = "UNKNOWN",
    default_evidence_type: str = "UNKNOWN",
) -> dict:
    """Return a stable, bounded finding record without changing its risk rating."""
    if not isinstance(finding, dict):
        raise FindingSchemaError("each finding must be an object")
    source_module = _text(module, "module", required=True)
    check = _text(finding.get("check", "UNKNOWN"), "check", required=True)
    status = _text(finding.get("status", "UNKNOWN"), "status") or "UNKNOWN"
    evidence = _text(finding.get("evidence", ""), "evidence")
    recommendation = _text(finding.get("recommendation", ""), "recommendation")
    severity = _level(finding.get("severity"), SEVERITIES, _SEVERITY_ALIASES)
    review_priority = _PRIORITY_BY_SEVERITY[severity]
    confidence = _level(
        finding.get("confidence", default_confidence),
        CONFIDENCE_LEVELS,
        _CONFIDENCE_ALIASES,
    )
    evidence_type = _level(
        finding.get("evidence_type", default_evidence_type),
        EVIDENCE_TYPES,
        {},
    )
    identity = {
        "module": source_module,
        "check": check,
        "status": status,
        "evidence": evidence,
    }
    digest = hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()[:20]
    return {
        "schema_version": FINDING_SCHEMA_VERSION,
        "finding_id": f"ARF-{digest}",
        "module": source_module,
        "check": check,
        "severity": severity,
        "status": status,
        "confidence": confidence,
        "evidence_type": evidence_type,
        "evidence": evidence,
        "recommendation": recommendation,
        "severity_basis": "MODULE_ASSIGNED" if severity != "UNKNOWN" else "UNASSESSED",
        "review_priority": review_priority,
        "review_priority_note": (
            "Triage ordering derived from the module-assigned severity only; it is not a composite risk score or proof of exploitability."
        ),
        "recommendation_status": "PRESENT" if recommendation else "MISSING",
    }


def normalize_findings(
    findings: list,
    module: str,
    *,
    default_confidence: str = "UNKNOWN",
    default_evidence_type: str = "UNKNOWN",
) -> list[dict]:
    """Normalize a complete finding list or fail without silently dropping items."""
    if not isinstance(findings, list):
        raise FindingSchemaError("findings must be a list")
    return [
        normalize_finding(
            item,
            module,
            default_confidence=default_confidence,
            default_evidence_type=default_evidence_type,
        )
        for item in findings
    ]
