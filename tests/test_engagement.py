"""Offline tests for unified engagement reporting."""
import json
import tempfile
import unittest
import uuid
from pathlib import Path

from apex_engagement import (
    EngagementError, build_engagement_record, export_engagement_json,
    generate_engagement_pdf_bytes, verify_engagement_record,
)

MODULES = [
    "External Footprinting (OSINT)",
    "SMB Network Auditor",
    "HTTP Security Assessment",
    "TLS Security Assessment",
]


def sample_modules():
    return [
        {
            "module": MODULES[0], "status": "COMPLETED",
            "target_scope": {"target": "example.com"},
            "findings": [{"check": "DNS_A", "severity": "INFO", "status": "RECORDS_COLLECTED",
                          "evidence": "192.0.2.10", "confidence": "HIGH", "evidence_type": "OBSERVATION"}],
            "duration_seconds": 1.2,
        },
        {"module": MODULES[1], "status": "NOT_RUN", "target_scope": {"target": "192.0.2.0/24"}, "findings": []},
        {"module": MODULES[2], "status": "COMPLETED", "target_scope": {"target": "https://example.com"},
         "findings": [{"check": "HSTS", "severity": "MEDIUM", "status": "MISSING", "evidence": "Header absent"}]},
        {"module": MODULES[3], "status": "FAILED", "target_scope": {"target": "example.com:443"},
         "findings": [], "limitations": ["TLS handshake did not complete"]},
    ]


class EngagementTests(unittest.TestCase):
    def test_builds_all_modules_and_marks_not_run(self):
        record = build_engagement_record({"engagement": "example engagement"}, sample_modules())
        self.assertEqual(record["engagement"]["module_count"], 4)
        smb = next(item for item in record["modules"] if item["module"] == MODULES[1])
        self.assertEqual(smb["status"], "NOT_RUN")
        self.assertEqual(record["summary"]["total_findings"], 2)
        self.assertIsNone(record["summary"]["risk_score"])
        self.assertTrue(verify_engagement_record(record))

    def test_checksum_detects_tampering(self):
        record = build_engagement_record({"target": "example.com"}, sample_modules())
        record["evidence"]["findings"][0]["evidence"] = "tampered"
        self.assertFalse(verify_engagement_record(record))

    def test_requires_exact_four_unique_modules(self):
        with self.assertRaises(EngagementError):
            build_engagement_record({"target": "example.com"}, sample_modules()[:3])
        data = sample_modules()
        data[3]["module"] = MODULES[2]
        with self.assertRaises(EngagementError):
            build_engagement_record({"target": "example.com"}, data)

    def test_not_run_cannot_have_findings(self):
        data = sample_modules()
        data[0]["status"] = "NOT_RUN"
        with self.assertRaises(EngagementError):
            build_engagement_record({"target": "example.com"}, data)

    def test_rejects_unknown_status_and_naive_time(self):
        data = sample_modules()
        data[0]["status"] = "SKIPPED"
        with self.assertRaises(EngagementError):
            build_engagement_record({"target": "example.com"}, data)
        with self.assertRaises(EngagementError):
            build_engagement_record({"target": "example.com"}, sample_modules(),
                                    generated_at=__import__("datetime").datetime(2026, 1, 1))

    def test_json_export_is_exclusive_and_private(self):
        record = build_engagement_record({"target": "example.com"}, sample_modules())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(export_engagement_json(record, directory))
            self.assertTrue(path.exists())
            self.assertEqual(json.loads(path.read_text())["engagement"]["id"], record["engagement"]["id"])
            if __import__("os").name == "posix":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                export_engagement_json(record, directory)

    def test_pdf_rendering_handles_empty_findings_and_preserves_pdf_structure(self):
        data = sample_modules()
        for module in data:
            module["findings"] = []
        record = build_engagement_record({"target": "example.com"}, data)
        try:
            pdf = generate_engagement_pdf_bytes(record)
        except Exception as exc:
            if "ReportLab" in str(exc):
                self.skipTest("ReportLab not installed")
            raise
        self.assertTrue(pdf.startswith(b"%PDF-"))
        self.assertTrue(pdf.rstrip().endswith(b"%%EOF"))

    def test_pdf_renders_when_reportlab_available(self):
        record = build_engagement_record({"target": "example.com"}, sample_modules())
        try:
            pdf = generate_engagement_pdf_bytes(record)
        except Exception as exc:
            if "ReportLab" in str(exc):
                self.skipTest("ReportLab not installed")
            raise
        self.assertTrue(pdf.startswith(b"%PDF-"))
