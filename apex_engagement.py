"""Unified engagement packaging for ApexRecon Phase 2I.

This layer combines already-collected module results. It never initiates scans,
infers exploitability, or computes a composite risk score.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from apex_findings import FindingSchemaError, normalize_findings
from apex_storage import write_exclusive_atomic

SCHEMA_VERSION = "1.0"
MODULES = {
    "External Footprinting (OSINT)",
    "SMB Network Auditor",
    "HTTP Security Assessment",
    "TLS Security Assessment",
}
MODULE_STATUSES = {"COMPLETED", "PARTIAL", "FAILED", "NOT_RUN"}
MAX_MODULES = 4
MAX_FINDINGS = 2000


class EngagementError(ValueError):
    """Raised when engagement data cannot be represented safely."""


class EngagementPDFDependencyError(RuntimeError):
    """Raised when PDF output is requested without ReportLab."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(value: Any, field: str) -> str:
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise EngagementError(f"{field} must be an ISO-8601 timestamp") from exc
    elif isinstance(value, datetime):
        parsed = value
    else:
        raise EngagementError(f"{field} must be a datetime or ISO-8601 string")
    if parsed.tzinfo is None:
        raise EngagementError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _text(value: Any, field: str, limit: int = 1000) -> str:
    if not isinstance(value, (str, int, float)):
        raise EngagementError(f"{field} must be scalar text")
    result = str(value).strip()[:limit]
    if not result:
        raise EngagementError(f"{field} is required")
    return result


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _safe_scope(value: Any) -> dict:
    if not isinstance(value, dict) or not value:
        raise EngagementError("target_scope must be a non-empty object")
    scope = {}
    for key, item in value.items():
        name = _text(key, "scope key", 80)
        if isinstance(item, (str, int, float)):
            scope[name] = str(item)[:500]
        elif isinstance(item, list):
            scope[name] = [str(part)[:200] for part in item[:50]]
        else:
            raise EngagementError("target_scope values must be scalar or lists")
    return scope


def build_engagement_record(
    target_scope: dict,
    module_results: list[dict],
    *,
    engagement_id: str | None = None,
    generated_at: datetime | None = None,
) -> dict:
    """Build a combined record from up to four already-collected module results.

    Every module must be represented, including NOT_RUN modules, so report
    readers can distinguish an unassessed area from a negative result.
    """
    if not isinstance(module_results, list) or len(module_results) != MAX_MODULES:
        raise EngagementError("module_results must contain exactly four module entries")
    now = generated_at or _now()
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise EngagementError("generated_at must be timezone-aware")
    try:
        eid = str(uuid.UUID(str(engagement_id or uuid.uuid4())))
    except (ValueError, TypeError, AttributeError) as exc:
        raise EngagementError("engagement_id must be a valid UUID") from exc

    seen = set()
    modules = []
    all_findings = []
    started_values = []
    completed_values = []
    for item in module_results:
        if not isinstance(item, dict):
            raise EngagementError("each module result must be an object")
        name = _text(item.get("module"), "module", 100)
        if name not in MODULES or name in seen:
            raise EngagementError("module names must be supported and unique")
        seen.add(name)
        status = str(item.get("status", "NOT_RUN")).strip().upper()
        if status not in MODULE_STATUSES:
            raise EngagementError(f"unsupported module status for {name}")
        findings = item.get("findings", [])
        if not isinstance(findings, list):
            raise EngagementError(f"findings for {name} must be a list")
        if status == "NOT_RUN" and findings:
            raise EngagementError(f"NOT_RUN module {name} cannot contain findings")
        if len(all_findings) + len(findings) > MAX_FINDINGS:
            raise EngagementError("engagement exceeds the 2000-finding limit")
        try:
            normalized = normalize_findings(
                findings, name, default_confidence="UNKNOWN",
                default_evidence_type="UNKNOWN",
            )
        except FindingSchemaError as exc:
            raise EngagementError(f"invalid findings for {name}: {exc}") from exc
        duration = item.get("duration_seconds", 0)
        if isinstance(duration, bool) or not isinstance(duration, (int, float)) or not 0 <= duration <= 86400:
            raise EngagementError(f"duration_seconds for {name} must be between 0 and 86400")
        started = _timestamp(item.get("started_at", now), f"{name}.started_at")
        completed = _timestamp(item.get("completed_at", now), f"{name}.completed_at")
        started_values.append(started)
        completed_values.append(completed)
        module_scope = _safe_scope(item.get("target_scope", target_scope))
        limitations = item.get("limitations", [])
        if not isinstance(limitations, list) or len(limitations) > 100:
            raise EngagementError(f"limitations for {name} must be a list of at most 100 items")
        clean_limitations = [_text(value, "limitation", 1000) for value in limitations]
        modules.append({
            "module": name,
            "status": status,
            "target_scope": module_scope,
            "started_at": started,
            "completed_at": completed,
            "duration_seconds": round(float(duration), 3),
            "finding_count": len(normalized),
            "limitations": clean_limitations,
        })
        all_findings.extend(normalized)

    missing = MODULES - seen
    if missing:
        raise EngagementError("missing module entries: " + ", ".join(sorted(missing)))
    modules.sort(key=lambda value: value["module"])
    counts = {level: sum(1 for f in all_findings if f["severity"] == level)
              for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN")}
    status_counts = {status: sum(1 for m in modules if m["status"] == status)
                     for status in sorted(MODULE_STATUSES)}
    payload = {
        "schema_version": SCHEMA_VERSION,
        "engagement": {
            "id": eid,
            "status": "COMPLETED" if all(m["status"] in {"COMPLETED", "NOT_RUN"} for m in modules)
                      and any(m["status"] == "COMPLETED" for m in modules) else "PARTIAL",
            "target_scope": _safe_scope(target_scope),
            "generated_at": _timestamp(now, "generated_at"),
            "module_count": len(modules),
        },
        "tool": {"name": "ApexRecon", "version": "2.0.1-dev", "publisher": "TrinTech Digital Defense"},
        "modules": modules,
        "summary": {
            "module_status_counts": status_counts,
            "finding_severity_counts": counts,
            "total_findings": len(all_findings),
            "risk_score": None,
            "risk_score_note": "No composite risk score is calculated; module severities retain their original meaning.",
        },
        "evidence": {"findings": all_findings},
        "limitations": [
            "This report combines supplied module outputs; it does not verify that scans were complete or accurate.",
            "NOT_RUN and PARTIAL modules are not negative security results.",
            "Findings are observations or indicators according to their evidence_type; they are not proof of exploitation.",
            "The SHA-256 checksum detects accidental or unauthorized content changes but is not a digital signature or immutable storage guarantee.",
        ],
    }
    payload["integrity"] = {
        "algorithm": "SHA-256",
        "engagement_sha256": hashlib.sha256(_canonical(payload)).hexdigest(),
        "meaning": "Checksum of the canonical engagement record before the integrity field; not a digital signature.",
    }
    return payload


def _record_structure_valid(record: dict) -> bool:
    """Check internal record consistency independently of its checksum."""
    try:
        engagement = record["engagement"]
        modules = record["modules"]
        summary = record["summary"]
        evidence = record["evidence"]
        if record.get("tool") != {
            "name": "ApexRecon", "version": "2.0.1-dev",
            "publisher": "TrinTech Digital Defense",
        }:
            return False
        limitations = record.get("limitations")
        if not isinstance(limitations, list) or any(
            not isinstance(item, str) or not item.strip() for item in limitations
        ):
            return False
        if not isinstance(engagement, dict) or not isinstance(modules, list) or len(modules) != MAX_MODULES:
            return False
        if not isinstance(summary, dict) or not isinstance(evidence, dict):
            return False
        if engagement.get("module_count") != MAX_MODULES:
            return False
        if _safe_scope(engagement.get("target_scope")) != engagement.get("target_scope"):
            return False
        if _timestamp(engagement.get("generated_at"), "generated_at") != engagement.get("generated_at"):
            return False

        module_by_name = {}
        for module in modules:
            if not isinstance(module, dict):
                return False
            name = module.get("module")
            if name not in MODULES or name in module_by_name:
                return False
            if module.get("status") not in MODULE_STATUSES:
                return False
            if _safe_scope(module.get("target_scope")) != module.get("target_scope"):
                return False
            if _timestamp(module.get("started_at"), "started_at") != module.get("started_at"):
                return False
            if _timestamp(module.get("completed_at"), "completed_at") != module.get("completed_at"):
                return False
            duration = module.get("duration_seconds")
            if isinstance(duration, bool) or not isinstance(duration, (int, float)) or not 0 <= duration <= 86400:
                return False
            if not isinstance(module.get("limitations"), list):
                return False
            if any(not isinstance(item, str) or not item.strip() for item in module["limitations"]):
                return False
            count = module.get("finding_count")
            if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                return False
            module_by_name[name] = module

        if set(module_by_name) != MODULES:
            return False
        findings = evidence.get("findings")
        if not isinstance(findings, list) or len(findings) > MAX_FINDINGS:
            return False
        per_module = {name: 0 for name in MODULES}
        severity_counts = {level: 0 for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN")}
        finding_ids = set()
        for finding in findings:
            if not isinstance(finding, dict):
                return False
            name = finding.get("module")
            if name not in module_by_name or module_by_name[name]["status"] == "NOT_RUN":
                return False
            normalized = normalize_findings([finding], name)[0]
            if normalized != finding:
                return False
            finding_id = finding.get("finding_id")
            if finding_id in finding_ids:
                return False
            finding_ids.add(finding_id)
            per_module[name] += 1
            severity_counts[finding["severity"]] += 1

        for name, module in module_by_name.items():
            if module["finding_count"] != per_module[name]:
                return False
        expected_status_counts = {
            status: sum(1 for module in modules if module["status"] == status)
            for status in sorted(MODULE_STATUSES)
        }
        if summary.get("total_findings") != len(findings):
            return False
        if summary.get("finding_severity_counts") != severity_counts:
            return False
        if summary.get("module_status_counts") != expected_status_counts:
            return False
        if summary.get("risk_score") is not None:
            return False
        expected_status = (
            "COMPLETED"
            if all(module["status"] in {"COMPLETED", "NOT_RUN"} for module in modules)
            and any(module["status"] == "COMPLETED" for module in modules)
            else "PARTIAL"
        )
        return engagement.get("status") == expected_status
    except (KeyError, TypeError, ValueError, EngagementError, FindingSchemaError):
        return False


def verify_engagement_record(record: Any) -> bool:
    """Verify schema consistency and the canonical SHA-256 checksum."""
    if not isinstance(record, dict) or record.get("schema_version") != SCHEMA_VERSION:
        return False
    if not _record_structure_valid(record):
        return False
    integrity = record.get("integrity")
    engagement = record.get("engagement")
    if not isinstance(integrity, dict) or not isinstance(engagement, dict):
        return False
    try:
        parsed = uuid.UUID(str(engagement.get("id", "")))
    except (ValueError, TypeError, AttributeError):
        return False
    if str(parsed) != str(engagement.get("id", "")).lower():
        return False
    digest = integrity.get("engagement_sha256")
    if integrity.get("algorithm") != "SHA-256" or not isinstance(digest, str) or len(digest) != 64:
        return False
    if integrity.get("meaning") != (
        "Checksum of the canonical engagement record before the integrity field; not a digital signature."
    ):
        return False
    if any(char not in "0123456789abcdef" for char in digest.lower()):
        return False
    unsigned = dict(record)
    unsigned.pop("integrity", None)
    try:
        expected = hashlib.sha256(_canonical(unsigned)).hexdigest()
    except (TypeError, ValueError):
        return False
    return hmac.compare_digest(expected, digest.lower())


def _require_valid(record: dict) -> None:
    if not verify_engagement_record(record):
        raise EngagementError("invalid or checksum-mismatched engagement record")


def _write_exclusive(path: Path, data: bytes) -> str:
    """Publish complete engagement bytes atomically without overwriting."""
    return write_exclusive_atomic(path, data)


def export_engagement_json(record: dict, directory: str | os.PathLike[str] = ".") -> str:
    _require_valid(record)
    path = Path(directory) / f"apex_engagement_{record['engagement']['id']}.json"
    data = json.dumps(record, indent=2, ensure_ascii=False, sort_keys=True).encode("utf-8") + b"\n"
    return _write_exclusive(path, data)


def generate_engagement_pdf_bytes(record: dict) -> bytes:
    """Render the verified engagement record with scope and evidence detail."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        )
    except ImportError as exc:
        raise EngagementPDFDependencyError("PDF export requires ReportLab") from exc
    _require_valid(record)
    from xml.sax.saxutils import escape

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="EngagementTitle", parent=styles["Title"],
        textColor=colors.HexColor("#8f1728"),
    ))
    styles.add(ParagraphStyle(
        name="EngagementSmall", parent=styles["BodyText"],
        fontSize=6.5, leading=8, wordWrap="CJK",
    ))
    styles.add(ParagraphStyle(
        name="EngagementBody", parent=styles["BodyText"],
        fontSize=8, leading=10, wordWrap="CJK",
    ))

    def p(value: Any, style: str = "EngagementBody") -> Any:
        text = str(value if value is not None else "")
        return Paragraph(escape(text[:8000]).replace("\\n", "<br/>"), styles[style])

    story = [
        p("APEXRECON", "EngagementTitle"),
        p("TRINTECH DIGITAL DEFENSE | CONFIDENTIAL SECURITY ASSESSMENT"),
        Spacer(1, 4 * mm),
        p("Unified Engagement Report", "Heading1"),
        p("Engagement ID: " + record["engagement"]["id"]),
        p("Generated: " + record["engagement"]["generated_at"]),
        p("Overall status: " + record["engagement"]["status"]),
        p("Target scope: " + json.dumps(record["engagement"]["target_scope"], ensure_ascii=False)),
        p("Executive Summary", "Heading2"),
        p("Modules: " + str(record["engagement"]["module_count"]) +
          " | Findings: " + str(record["summary"]["total_findings"])),
        p("Module status counts: " + json.dumps(record["summary"]["module_status_counts"], sort_keys=True)),
        p("Severity counts: " + json.dumps(record["summary"]["finding_severity_counts"], sort_keys=True)),
        p("No composite risk score is calculated.", "Italic"),
        p("Engagement record SHA-256: " + record["integrity"]["engagement_sha256"]),
        p("This checksum covers the canonical JSON engagement record, not the PDF file.", "EngagementSmall"),
        p("Module Coverage and Scope", "Heading2"),
    ]

    module_rows = [[
        p("Module", "EngagementSmall"), p("Status", "EngagementSmall"),
        p("Findings", "EngagementSmall"), p("Duration (s)", "EngagementSmall"),
    ]]
    for module in record["modules"]:
        module_rows.append([
            p(module["module"], "EngagementSmall"),
            p(module["status"], "EngagementSmall"),
            p(module["finding_count"], "EngagementSmall"),
            p(module["duration_seconds"], "EngagementSmall"),
        ])
    module_table = Table(module_rows, colWidths=[105 * mm, 30 * mm, 25 * mm, 35 * mm], repeatRows=1)
    module_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#253449")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#c8d0d9")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.extend([module_table, Spacer(1, 3 * mm)])

    for module in record["modules"]:
        scope_text = json.dumps(module["target_scope"], ensure_ascii=False, sort_keys=True)
        details = [
            p(module["module"] + " | " + module["status"], "Heading3"),
            p("Target scope: " + scope_text),
            p("Started: " + module["started_at"] + " | Completed: " + module["completed_at"]),
        ]
        if module["limitations"]:
            details.extend(p("Limitation: " + item, "EngagementSmall")
                           for item in module["limitations"])
        else:
            details.append(p("Module limitations: none reported.", "EngagementSmall"))
        story.extend(details)

    story.extend([
        p("Consolidated Findings", "Heading2"),
        p("Review priority is derived from module-assigned severity alone. It is a triage aid, not a composite risk score or proof of exploitability.", "EngagementSmall"),
    ])
    finding_rows = [[
        p("Module", "EngagementSmall"), p("Severity", "EngagementSmall"),
        p("Check / Status", "EngagementSmall"), p("Confidence", "EngagementSmall"),
        p("Evidence type", "EngagementSmall"), p("Evidence", "EngagementSmall"),
        p("Recommendation", "EngagementSmall"),
    ]]
    for finding in record["evidence"]["findings"]:
        finding_rows.append([
            p(finding.get("module", ""), "EngagementSmall"),
            p(str(finding.get("severity", "")) + " / " + str(finding.get("review_priority", "UNRANKED")), "EngagementSmall"),
            p(finding.get("check", "") + " / " + finding.get("status", ""), "EngagementSmall"),
            p(finding.get("confidence", "UNKNOWN"), "EngagementSmall"),
            p(finding.get("evidence_type", "UNKNOWN"), "EngagementSmall"),
            p(finding.get("evidence", ""), "EngagementSmall"),
            p(str(finding.get("recommendation_status", "MISSING")) + ": " + str(finding.get("recommendation", "")), "EngagementSmall"),
        ])
    if len(finding_rows) == 1:
        finding_rows.append([p("No findings were supplied.", "EngagementSmall")] + [""] * 6)
    finding_table = Table(
        finding_rows,
        colWidths=[31 * mm, 19 * mm, 39 * mm, 22 * mm, 27 * mm, 55 * mm, 55 * mm],
        repeatRows=1,
    )
    finding_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#253449")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#c8d0d9")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.extend([finding_table, p("Assessment Limitations", "Heading2")])
    for limitation in record["limitations"]:
        story.append(p("• " + limitation, "EngagementSmall"))

    import io
    output = io.BytesIO()
    SimpleDocTemplate(
        output, pagesize=landscape(A4), rightMargin=12 * mm,
        leftMargin=12 * mm, topMargin=12 * mm, bottomMargin=12 * mm,
        title="ApexRecon Engagement " + record["engagement"]["id"],
        author="TrinTech Digital Defense",
        subject="SHA-256 " + record["integrity"]["engagement_sha256"],
    ).build(story)
    return output.getvalue()


def export_engagement_pdf(record: dict, directory: str | os.PathLike[str] = ".") -> str:
    _require_valid(record)
    path = Path(directory) / f"apex_engagement_{record['engagement']['id']}.pdf"
    return _write_exclusive(path, generate_engagement_pdf_bytes(record))
