import hashlib
import json
import os
import stat
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import apex_evidence as evidence


class EvidenceExportTests(unittest.TestCase):
    def sample(self):
        return {
            "schema_version": "1.0",
            "module": "HTTP Security Assessment",
            "target": "example.test",
            "path": "/login",
            "http_final_url": "https://example.test/login",
            "findings": [{
                "check": "CSP", "severity": "MEDIUM", "status": "MISSING",
                "evidence": "Content-Security-Policy response header was not present.",
                "recommendation": "Configure a restrictive policy.",
            }],
            "fingerprints": [{
                "category": "CMS", "name": "WordPress", "version": None,
                "confidence": "medium", "evidence": ["generator meta"],
                "source": "bounded HTML sample",
            }],
            "limitations": ["One URL path only.", "No exploitation performed."],
        }

    def test_record_has_stable_schema_metadata_and_checksum(self):
        now = datetime(2026, 11, 23, 12, 0, tzinfo=timezone.utc)
        record = evidence.build_evidence_record(self.sample(), 2.5, assessment_id="11111111-1111-4111-8111-111111111111", generated_at=now)
        self.assertEqual(record["schema_version"], "1.0")
        self.assertEqual(record["assessment"]["duration_seconds"], 2.5)
        self.assertEqual(record["assessment"]["started_at"], "2026-11-23T11:59:57Z")
        self.assertEqual(record["assessment"]["completed_at"], "2026-11-23T12:00:00Z")
        self.assertEqual(record["evidence"]["findings"][0]["check"], "CSP")
        self.assertEqual(record["evidence"]["findings"][0]["module"], "HTTP Security Assessment")
        self.assertEqual(record["evidence"]["findings"][0]["confidence"], "UNKNOWN")
        self.assertEqual(record["evidence"]["findings"][0]["evidence_type"], "UNKNOWN")
        self.assertTrue(record["evidence"]["findings"][0]["finding_id"].startswith("ARF-"))
        self.assertEqual(record["evidence"]["fingerprints"][0]["confidence"], "medium")
        checksum = record["integrity"]["assessment_sha256"]
        unsigned = dict(record)
        unsigned.pop("integrity")
        expected = hashlib.sha256(evidence._canonical_json(unsigned)).hexdigest()
        self.assertEqual(checksum, expected)

    def test_record_preserves_normalized_finding_metadata(self):
        result = self.sample()
        result["findings"][0]["confidence"] = "MEDIUM"
        result["findings"][0]["evidence_type"] = "INDICATOR"
        record = evidence.build_evidence_record(result, 0.1)
        finding = record["evidence"]["findings"][0]
        self.assertEqual(finding["confidence"], "MEDIUM")
        self.assertEqual(finding["evidence_type"], "INDICATOR")
        self.assertEqual(finding["severity"], "MEDIUM")

    def test_record_does_not_include_url_query_or_raw_response(self):
        result = self.sample()
        result["assessment_id"] = "33333333-3333-4333-8333-333333333333"
        result["http_final_url"] = "https://example.test/login?token=do-not-export"
        record = evidence.build_evidence_record(result, 0.1)
        rendered = json.dumps(record)
        self.assertNotIn("do-not-export", rendered)
        self.assertNotIn("body", record["evidence"])
        self.assertEqual(record["assessment"]["id"], result["assessment_id"])
        self.assertEqual(record["evidence"]["technical_details"]["http_final_url"], "https://example.test/login")

    def test_rejects_invalid_assessment_and_duration(self):
        with self.assertRaises(evidence.EvidenceExportError):
            evidence.build_evidence_record({}, 1)
        with self.assertRaises(evidence.EvidenceExportError):
            evidence.build_evidence_record(self.sample(), -1)
        invalid = self.sample()
        invalid["findings"] = ["not-an-object"]
        with self.assertRaises(evidence.EvidenceExportError):
            evidence.build_evidence_record(invalid, 1)

    def test_json_export_is_private_and_does_not_overwrite(self):
        record = evidence.build_evidence_record(
            self.sample(), 1, assessment_id="22222222-2222-4222-8222-222222222222"
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(evidence.export_json(record, tmp))
            self.assertTrue(path.exists())
            loaded = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(loaded["assessment"]["id"], record["assessment"]["id"])
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                evidence.export_json(record, tmp)

    def test_checksum_verification_detects_tampering(self):
        record = evidence.build_evidence_record(
            self.sample(), 1, assessment_id="44444444-4444-4444-8444-444444444444"
        )
        self.assertTrue(evidence.verify_evidence_record(record))
        changed = json.loads(json.dumps(record))
        changed["evidence"]["findings"][0]["severity"] = "LOW"
        self.assertFalse(evidence.verify_evidence_record(changed))
        with self.assertRaises(evidence.EvidenceExportError):
            evidence.export_json(changed)

    def test_url_sanitization_removes_credentials_queries_and_fragments(self):
        self.assertEqual(
            evidence._safe_url("https://user:secret@example.test:8443/a?token=hidden#section"),
            "https://example.test:8443/a",
        )
        self.assertEqual(
            evidence._safe_url("/health?api_key=hidden#fragment"),
            "/health",
        )
        self.assertEqual(
            evidence._safe_url("https://[2001:db8::1]:443/status?secret=x"),
            "https://[2001:db8::1]:443/status",
        )
        self.assertEqual(
            evidence._safe_url("https://example.test:99999/path?token=hidden"),
            "[REDACTED_INVALID_URL]",
        )

    def test_invalid_assessment_uuid_is_rejected(self):
        with self.assertRaises(evidence.EvidenceExportError):
            evidence.build_evidence_record(self.sample(), 1, assessment_id="not-a-uuid")

    @patch("apex_evidence.export_pdf", side_effect=OSError("simulated PDF storage failure"))
    def test_pdf_failure_preserves_json_artifact(self, _mock_pdf):
        with tempfile.TemporaryDirectory() as tmp:
            artifacts = evidence.export_artifacts(self.sample(), 1, tmp)
            self.assertTrue(Path(artifacts["json_path"]).is_file())
            self.assertIsNone(artifacts["pdf_path"])
            self.assertIn("simulated PDF storage failure", artifacts["pdf_error"])

    def test_pdf_summary_counts_unavailable_findings_as_unknown(self):
        try:
            import reportlab.platypus
        except ImportError:
            self.skipTest("ReportLab is optional")

        result = self.sample()
        result["findings"].append({
            "check": "HTTPS_ENDPOINT",
            "severity": "UNKNOWN",
            "status": "UNAVAILABLE",
            "evidence": "HTTPS endpoint could not be assessed.",
            "recommendation": "Confirm reachability before drawing conclusions.",
        })
        record = evidence.build_evidence_record(result, 0.25)
        captured = {}

        def capture_build(_document, flowables, *args, **kwargs):
            captured["paragraphs"] = [
                item.getPlainText() for item in flowables
                if hasattr(item, "getPlainText")
            ]

        with patch(
            "reportlab.platypus.SimpleDocTemplate.build",
            autospec=True,
            side_effect=capture_build,
        ):
            evidence.generate_pdf_bytes(record)

        summary = next(
            text for text in captured["paragraphs"]
            if text.startswith("Finding counts:")
        )
        self.assertIn("UNKNOWN: 1", summary)
        self.assertIn("MEDIUM: 1", summary)

    def test_pdf_generation_or_clear_optional_dependency_error(self):
        record = evidence.build_evidence_record(self.sample(), 0.25)
        try:
            pdf = evidence.generate_pdf_bytes(record)
        except evidence.PDFDependencyError as exc:
            self.assertIn("reportlab", str(exc).lower())
        else:
            self.assertTrue(pdf.startswith(b"%PDF-"))
            self.assertGreater(len(pdf), 1000)
            with tempfile.TemporaryDirectory() as tmp:
                pdf_path = Path(evidence.export_pdf(record, tmp))
                self.assertTrue(pdf_path.read_bytes().startswith(b"%PDF-"))
                if os.name == "posix":
                    self.assertEqual(stat.S_IMODE(pdf_path.stat().st_mode), 0o600)
                with self.assertRaises(FileExistsError):
                    evidence.export_pdf(record, tmp)


if __name__ == "__main__":
    unittest.main()
