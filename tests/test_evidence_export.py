import hashlib
import json
import os
import stat
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

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
        self.assertEqual(record["evidence"]["fingerprints"][0]["confidence"], "medium")
        checksum = record["integrity"]["assessment_sha256"]
        unsigned = dict(record)
        unsigned.pop("integrity")
        expected = hashlib.sha256(evidence._canonical_json(unsigned)).hexdigest()
        self.assertEqual(checksum, expected)

    def test_record_does_not_include_url_query_or_raw_response(self):
        result = self.sample()
        result["http_final_url"] = "https://example.test/login?token=do-not-export"
        record = evidence.build_evidence_record(result, 0.1)
        rendered = json.dumps(record)
        self.assertNotIn("do-not-export", rendered)
        self.assertNotIn("body", record["evidence"])

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

    def test_pdf_generation_or_clear_optional_dependency_error(self):
        record = evidence.build_evidence_record(self.sample(), 0.25)
        try:
            pdf = evidence.generate_pdf_bytes(record)
        except evidence.PDFDependencyError as exc:
            self.assertIn("reportlab", str(exc).lower())
        else:
            self.assertTrue(pdf.startswith(b"%PDF-"))
            self.assertGreater(len(pdf), 1000)


if __name__ == "__main__":
    unittest.main()
