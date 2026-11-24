"""Phase 2E evidence packaging and native report generation.

JSON evidence export uses only the Python standard library. Native PDF
rendering is optional and uses ReportLab when installed. Artifacts are
created exclusively with owner-only permissions on POSIX systems.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from typing import Any


SCHEMA_VERSION = "1.0"
TOOL_NAME = "ApexRecon"
TOOL_VERSION = "2.0.1-dev"
SUPPORTED_MODULES = {"HTTP Security Assessment", "TLS Security Assessment"}


class EvidenceExportError(ValueError):
    """Raised when an assessment cannot be represented safely as evidence."""


class PDFDependencyError(RuntimeError):
    """Raised when native PDF export is requested without ReportLab."""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _clean_text(value: Any, limit: int = 4000) -> str:
    text = str(value if value is not None else "")
    return text[:limit]


def _safe_url(value: Any) -> str:
    """Remove URL queries, fragments, and embedded credentials before export."""
    raw = _clean_text(value, 2000)
    try:
        parsed = urlsplit(raw)
        hostname = parsed.hostname
        safe_netloc = ""
        if hostname:
            host = f"[{hostname}]" if ":" in hostname else hostname
            try:
                port = parsed.port
            except ValueError:
                # An invalid port is malformed URL syntax; do not preserve any
                # portion of the original value in exported evidence.
                return "[REDACTED_INVALID_URL]"
            safe_netloc = host + (f":{port}" if port is not None else "")
        return urlunsplit((parsed.scheme.lower(), safe_netloc, parsed.path, "", ""))
    except ValueError:
        # Fail closed for malformed URL syntax: never retain query/fragment data.
        return "[REDACTED_INVALID_URL]"




def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_evidence_record(record: Any) -> bool:
    """Return True only when a versioned record has a valid UUID and checksum."""
    if not isinstance(record, dict) or record.get("schema_version") != SCHEMA_VERSION:
        return False
    assessment = record.get("assessment")
    integrity = record.get("integrity")
    if not isinstance(assessment, dict) or not isinstance(integrity, dict):
        return False
    try:
        parsed_id = uuid.UUID(str(assessment.get("id", "")))
    except (ValueError, TypeError, AttributeError):
        return False
    if str(parsed_id) != str(assessment.get("id", "")).lower():
        return False
    if integrity.get("algorithm") != "SHA-256":
        return False
    supplied = integrity.get("assessment_sha256")
    if not isinstance(supplied, str) or len(supplied) != 64:
        return False
    if any(char not in "0123456789abcdef" for char in supplied.lower()):
        return False
    unsigned = dict(record)
    unsigned.pop("integrity", None)
    try:
        expected = hashlib.sha256(_canonical_json(unsigned)).hexdigest()
    except (TypeError, ValueError):
        return False
    return hmac.compare_digest(expected, supplied.lower())


def _require_valid_evidence_record(record: Any) -> None:
    if not verify_evidence_record(record):
        raise EvidenceExportError("invalid or checksum-mismatched ApexRecon evidence record")


def build_evidence_record(
    result: dict,
    duration_seconds: float,
    assessment_id: str | None = None,
    generated_at: datetime | None = None,
) -> dict:
    """Build a versioned, secret-conscious evidence record from HTTP or TLS results."""
    if not isinstance(result, dict) or result.get("module") not in SUPPORTED_MODULES:
        raise EvidenceExportError("unsupported ApexRecon assessment payload")
    try:
        duration = float(duration_seconds)
    except (TypeError, ValueError) as exc:
        raise EvidenceExportError("duration must be numeric") from exc
    if not 0 <= duration <= 86400:
        raise EvidenceExportError("duration must be between 0 and 86400 seconds")
    target = _clean_text(result.get("target", "")).strip()
    if not target:
        raise EvidenceExportError("assessment target is required")
    findings = result.get("findings")
    limitations = result.get("limitations")
    if not isinstance(findings, list) or not isinstance(limitations, list):
        raise EvidenceExportError("assessment findings and limitations must be lists")
    if any(not isinstance(item, dict) for item in findings):
        raise EvidenceExportError("each finding must be an object")

    now = generated_at or _utc_now()
    if now.tzinfo is None:
        raise EvidenceExportError("generated_at must be timezone-aware")
    raw_assessment_id = assessment_id or result.get("assessment_id") or str(uuid.uuid4())
    try:
        normalized_assessment_id = str(uuid.UUID(str(raw_assessment_id)))
    except (ValueError, TypeError, AttributeError) as exc:
        raise EvidenceExportError("assessment ID must be a valid UUID") from exc
    completed = _iso(now)
    started = _iso(now - timedelta(seconds=duration))
    scope = {"target": target}
    for key in ("path", "port"):
        if result.get(key) is not None:
            scope[key] = _clean_text(result[key], 1000)

    finding_records = []
    for item in findings:
        finding_records.append({
            "check": _clean_text(item.get("check", "UNKNOWN"), 200),
            "severity": _clean_text(item.get("severity", "INFO"), 40).upper(),
            "status": _clean_text(item.get("status", "UNKNOWN"), 100),
            "evidence": _clean_text(item.get("evidence", "")),
            "recommendation": _clean_text(item.get("recommendation", "")),
        })

    fingerprints = []
    raw_fingerprints = result.get("fingerprints", [])
    if raw_fingerprints is not None and not isinstance(raw_fingerprints, list):
        raise EvidenceExportError("fingerprints must be a list")
    for item in raw_fingerprints or []:
        if not isinstance(item, dict):
            continue
        fingerprints.append({
            "category": _clean_text(item.get("category", "Technology"), 100),
            "name": _clean_text(item.get("name", "Unknown"), 200),
            "version": _clean_text(item.get("version"), 100) if item.get("version") is not None else None,
            "confidence": _clean_text(item.get("confidence", "unknown"), 40).lower(),
            "evidence": [_clean_text(v, 300) for v in item.get("evidence", [])[:20]]
            if isinstance(item.get("evidence", []), list) else [],
            "source": _clean_text(item.get("source", ""), 200),
        })

    if result["module"] == "HTTP Security Assessment":
        provenance = {
            "method": "Direct observation of bounded HTTP response status, headers, and capped HTML sample",
            "request_limit": "At most two read-only GET requests; at most 16 KiB of HTML read in total",
            "interpretation": "Header observations and heuristic fingerprints do not prove exploitability or a complete technology inventory",
        }
    else:
        provenance = {
            "method": "One TCP/443 connection and one certificate-verified TLS handshake",
            "verification": "System trust-chain and hostname verification enabled; no insecure fallback",
            "interpretation": "Protocol and cipher are the negotiated values for this client session, not a server-wide inventory",
        }

    payload = {
        "schema_version": SCHEMA_VERSION,
        "assessment": {
            "id": normalized_assessment_id,
            "module": _clean_text(result["module"], 100),
            "target_scope": scope,
            "status": _clean_text(result.get("status", "COMPLETED"), 100),
            "started_at": started,
            "completed_at": completed,
            "duration_seconds": round(duration, 3),
        },
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION, "publisher": "TrinTech Digital Defense"},
        "evidence": {
            "findings": finding_records,
            "fingerprints": fingerprints,
            "technical_details": {
                key: (_safe_url(result.get(key)) if key in ("http_final_url", "https_final_url") else result.get(key))
                for key in (
                    "http_status", "http_final_scheme", "http_redirected_to_https",
                    "https_status", "http_final_url", "https_final_url", "port",
                    "verified", "protocol", "cipher", "certificate", "error_type",
                ) if key in result
            },
            "provenance": provenance,
        },
        "limitations": [_clean_text(item, 1000) for item in limitations[:100]],
    }
    payload["integrity"] = {
        "algorithm": "SHA-256",
        "assessment_sha256": hashlib.sha256(_canonical_json(payload)).hexdigest(),
        "meaning": "Checksum of the canonical assessment record before the integrity field; not a digital signature or immutable storage guarantee.",
    }
    return payload


def _write_exclusive(path: Path, data: bytes) -> str:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(str(path), flags, 0o600)
    try:
        if os.name == "posix":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            fd = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        if fd >= 0:
            os.close(fd)
        try:
            path.unlink()
        except OSError:
            pass
        raise
    return str(path)


def export_json(record: dict, directory: str | os.PathLike[str] = ".") -> str:
    _require_valid_evidence_record(record)
    assessment_id = str(record["assessment"]["id"])
    path = Path(directory) / f"apex_evidence_{assessment_id}.json"
    data = json.dumps(record, indent=2, ensure_ascii=False, sort_keys=True).encode("utf-8") + b"\n"
    return _write_exclusive(path, data)


def generate_pdf_bytes(record: dict) -> bytes:
    """Render a self-contained PDF in memory; requires optional ReportLab."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_LEFT
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            PageBreak, KeepTogether,
        )
    except ImportError as exc:
        raise PDFDependencyError("Native PDF export requires ReportLab. Install with: python3 -m pip install reportlab") from exc

    _require_valid_evidence_record(record)
    assessment = record.get("assessment", {})
    evidence = record.get("evidence", {})
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="ApexTitle", parent=styles["Title"], textColor=colors.HexColor("#8f1728"), alignment=TA_LEFT, fontSize=21, leading=25, spaceAfter=5))
    styles.add(ParagraphStyle(name="ApexSub", parent=styles["Normal"], textColor=colors.HexColor("#455468"), fontSize=9, leading=13))
    styles.add(ParagraphStyle(name="ApexHead", parent=styles["Heading2"], textColor=colors.HexColor("#8f1728"), fontSize=13, leading=16, spaceBefore=12, spaceAfter=7))
    styles.add(ParagraphStyle(name="ApexBody", parent=styles["BodyText"], fontSize=8, leading=11, wordWrap="CJK"))
    styles.add(ParagraphStyle(name="ApexSmall", parent=styles["BodyText"], fontSize=7, leading=9, textColor=colors.HexColor("#455468"), wordWrap="CJK"))

    def p(value: Any, style: str = "ApexBody") -> Any:
        from xml.sax.saxutils import escape
        return Paragraph(escape(_clean_text(value)).replace("\\n", "<br/>"), styles[style])

    story = [
        Paragraph("APEXRECON", styles["ApexTitle"]),
        Paragraph("TRINTECH DIGITAL DEFENSE | CONFIDENTIAL SECURITY ASSESSMENT", styles["ApexSub"]),
        Spacer(1, 5 * mm),
        Paragraph("Assessment Report", styles["Heading1"]),
    ]
    meta = [
        [p("Assessment ID"), p(assessment.get("id", ""))],
        [p("Module"), p(assessment.get("module", ""))],
        [p("Target scope"), p(json.dumps(assessment.get("target_scope", {}), ensure_ascii=False))],
        [p("Started (UTC)"), p(assessment.get("started_at", ""))],
        [p("Completed (UTC)"), p(assessment.get("completed_at", ""))],
        [p("Duration"), p(f"{assessment.get('duration_seconds', 0)} seconds")],
        [p("Tool version"), p(record.get("tool", {}).get("version", ""))],
    ]
    table = Table(meta, colWidths=[38 * mm, 135 * mm], repeatRows=0)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#edf1f5")),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#c8d0d9")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.extend([table, Paragraph("Executive Summary", styles["ApexHead"])])
    findings = evidence.get("findings", [])
    counts = {level: sum(1 for item in findings if str(item.get("severity", "")).upper() == level)
              for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
    story.append(p("Finding counts: " + " | ".join(f"{key}: {value}" for key, value in counts.items())))
    story.append(Paragraph("Observed Findings", styles["ApexHead"]))
    rows = [[p("Severity", "ApexSmall"), p("Check / Status", "ApexSmall"), p("Evidence", "ApexSmall"), p("Recommended action", "ApexSmall")]]
    for item in findings:
        rows.append([
            p(item.get("severity", "INFO"), "ApexSmall"),
            p(str(item.get("check", "")) + " / " + str(item.get("status", "")), "ApexSmall"),
            p(item.get("evidence", ""), "ApexSmall"),
            p(item.get("recommendation", ""), "ApexSmall"),
        ])
    findings_table = Table(rows, colWidths=[19 * mm, 34 * mm, 60 * mm, 60 * mm], repeatRows=1)
    findings_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#253449")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#c8d0d9")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(findings_table)
    fingerprints = evidence.get("fingerprints", [])
    if fingerprints:
        story.append(Paragraph("CMS and Technology Fingerprints", styles["ApexHead"]))
        fp_rows = [[p("Category", "ApexSmall"), p("Technology", "ApexSmall"), p("Confidence", "ApexSmall"), p("Evidence markers", "ApexSmall")]]
        for item in fingerprints:
            fp_rows.append([p(item.get("category", ""), "ApexSmall"), p(item.get("name", ""), "ApexSmall"),
                            p(item.get("confidence", ""), "ApexSmall"), p(", ".join(item.get("evidence", [])), "ApexSmall")])
        fp_table = Table(fp_rows, colWidths=[28 * mm, 38 * mm, 25 * mm, 82 * mm], repeatRows=1)
        fp_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#253449")),
                                      ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                                      ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#c8d0d9")),
                                      ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        story.append(fp_table)
    story.append(Paragraph("Evidence Provenance and Interpretation", styles["ApexHead"]))
    provenance = evidence.get("provenance", {})
    for key, value in provenance.items():
        story.append(p(f"{key.replace('_', ' ').title()}: {value}", "ApexSmall"))
    story.append(Paragraph("Technical Details", styles["ApexHead"]))
    technical = evidence.get("technical_details", {})
    story.append(p(json.dumps(technical, indent=2, ensure_ascii=False)[:12000], "ApexSmall"))
    story.append(Paragraph("Limitations", styles["ApexHead"]))
    for item in record.get("limitations", []):
        story.append(p("• " + item, "ApexSmall"))
    integrity = record.get("integrity", {})
    story.append(Paragraph("Integrity", styles["ApexHead"]))
    story.append(p(f"SHA-256 assessment checksum: {integrity.get('assessment_sha256', '')}", "ApexSmall"))
    story.append(p(integrity.get("meaning", ""), "ApexSmall"))
    story.append(Spacer(1, 5 * mm))
    story.append(p("CONFIDENTIAL. Distribute only to personnel authorized to receive this assessment. A checksum is not a digital signature and does not guarantee immutable storage.", "ApexSmall"))

    from io import BytesIO
    buffer = BytesIO()
    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#667085"))
        canvas.drawString(18 * mm, 10 * mm, "ApexRecon | TrinTech Digital Defense | Confidential")
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {doc.page}")
        canvas.restoreState()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=18 * mm, leftMargin=18 * mm, topMargin=16 * mm, bottomMargin=18 * mm, title="ApexRecon Assessment Report", author="TrinTech Digital Defense")
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()


def export_pdf(record: dict, directory: str | os.PathLike[str] = ".") -> str:
    _require_valid_evidence_record(record)
    assessment_id = str(record["assessment"]["id"])
    pdf_data = generate_pdf_bytes(record)
    path = Path(directory) / f"apex_report_{assessment_id}.pdf"
    return _write_exclusive(path, pdf_data)


def export_artifacts(result: dict, duration_seconds: float, directory: str | os.PathLike[str] = ".") -> dict:
    record = build_evidence_record(result, duration_seconds)
    json_path = export_json(record, directory)
    try:
        pdf_path = export_pdf(record, directory)
        pdf_error = None
    except Exception as exc:
        # JSON is the primary structured artifact. A PDF renderer or file-system
        # failure must not discard its path or abort the completed assessment.
        pdf_path = None
        pdf_error = f"{type(exc).__name__}: {_clean_text(exc, 300)}"
    return {"record": record, "json_path": json_path, "pdf_path": pdf_path, "pdf_error": pdf_error}
