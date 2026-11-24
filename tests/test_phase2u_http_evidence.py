import importlib.util
import io
import json
import tempfile
import unittest
import urllib.parse
from email.message import Message
from pathlib import Path
from unittest.mock import patch

import apex_evidence as evidence

MODULE_PATH = Path(__file__).resolve().parents[1] / "apex_web.py"
SPEC = importlib.util.spec_from_file_location("apex_web_phase2u", MODULE_PATH)
web = importlib.util.module_from_spec(SPEC)
import sys
sys.modules[SPEC.name] = web
SPEC.loader.exec_module(web)


class Phase2UResponseEvidenceTests(unittest.TestCase):
    def headers(self, values=(), cookies=()):
        result = Message()
        for name, value in values:
            result.add_header(name, value)
        for cookie in cookies:
            result.add_header("Set-Cookie", cookie)
        return result

    def response(self, status, headers):
        return web.FetchResult(status, headers, "https://example.test/login?token=must-not-export")

    @patch.object(web, "_fetch")
    def test_assessment_findings_include_exact_header_observations(self, mocked_fetch):
        headers = self.headers([
            ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
            ("Content-Security-Policy", "default-src 'self'; object-src 'none'; base-uri 'self'"),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "strict-origin"),
            ("Permissions-Policy", "camera=()"),
            ("X-Frame-Options", "DENY"),
        ])
        mocked_fetch.return_value = self.response(200, headers)
        result = web.assess_url("https://example.test/login")
        hsts = next(item for item in result["findings"] if item["check"] == "HSTS")
        self.assertIn("Strict-Transport-Security", hsts["evidence"])
        self.assertIn("max-age=31536000", hsts["evidence"])
        self.assertIn("HTTPS status 200", hsts["evidence"])
        self.assertIn("https://example.test/login", hsts["evidence"])
        self.assertNotIn("token=", json.dumps(result))
        self.assertEqual(mocked_fetch.call_count, 2)

    @patch.object(web, "_fetch")
    def test_cookie_evidence_redacts_cookie_values_but_keeps_attributes(self, mocked_fetch):
        headers = self.headers(
            [("Content-Security-Policy", "default-src 'self'")],
            ["session=highly-sensitive-cookie-value; Secure; HttpOnly; SameSite=Lax"],
        )
        mocked_fetch.side_effect = [
            self.response(200, headers),
            self.response(200, headers),
        ]
        result = web.assess_url("example.test")
        cookie = next(item for item in result["findings"] if item["check"] == "COOKIE_FLAGS")
        self.assertIn("cookie-name=session", cookie["evidence"])
        self.assertIn("samesite=Lax", cookie["evidence"])
        self.assertNotIn("highly-sensitive-cookie-value", json.dumps(result))

    @patch.object(web, "_fetch")
    def test_csp_nonce_and_hash_tokens_are_redacted_from_evidence(self, mocked_fetch):
        headers = self.headers([
            ("Content-Security-Policy", "script-src 'self' 'nonce-secret123' 'sha256-secret456'"),
        ])
        mocked_fetch.side_effect = [
            self.response(200, headers),
            self.response(200, headers),
        ]
        result = web.assess_url("example.test")
        rendered = json.dumps(result)
        self.assertNotIn("secret123", rendered)
        self.assertNotIn("secret456", rendered)
        self.assertIn("[REDACTED_TOKEN]", rendered)

    @patch.object(web, "_fetch")
    def test_conflicting_header_combinations_keep_ambiguous_statuses_and_evidence(self, mocked_fetch):
        headers = self.headers([
            ("Strict-Transport-Security", "max-age=31536000"),
            ("Strict-Transport-Security", "max-age=0"),
            ("X-Content-Type-Options", "nosniff"),
            ("X-Content-Type-Options", "invalid"),
            ("Content-Security-Policy-Report-Only", "default-src 'none'"),
        ])
        mocked_fetch.side_effect = [
            self.response(200, headers),
            self.response(200, headers),
        ]
        result = web.assess_url("example.test")
        checks = {item["check"]: item for item in result["findings"]}
        self.assertEqual(checks["HSTS"]["status"], "AMBIGUOUS")
        self.assertEqual(checks["MIME_SNIFFING"]["status"], "AMBIGUOUS")
        self.assertEqual(checks["CSP"]["status"], "MISSING")
        self.assertEqual(checks["CSP_REPORT_ONLY"]["status"], "REPORT_ONLY_NOT_ENFORCED")
        self.assertIn("max-age=0", checks["HSTS"]["evidence"])
        self.assertIn("invalid", checks["MIME_SNIFFING"]["evidence"])

    @patch.object(web, "_fetch")
    def test_http_assessment_evidence_survives_html_json_and_pdf_generation(self, mocked_fetch):
        headers = self.headers([
            ("Content-Security-Policy", "default-src 'self'; object-src 'none'; base-uri 'self'"),
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
        ])
        mocked_fetch.side_effect = [
            self.response(200, headers),
            self.response(200, headers),
        ]
        result = web.assess_url("example.test")
        expected = next(item for item in result["findings"] if item["check"] == "MIME_SNIFFING")["evidence"]
        record = evidence.build_evidence_record(result, 1.0)
        self.assertTrue(evidence.verify_evidence_record(record))
        exported = json.dumps(record["evidence"]["findings"])
        self.assertIn(expected, exported)

        with tempfile.TemporaryDirectory() as tmp:
            original = __import__("os").getcwd()
            try:
                __import__("os").chdir(tmp)
                html_path = web.generate_html_report(result, 1.0)
                html = Path(html_path).read_text(encoding="utf-8")
                self.assertIn("X-Content-Type-Options", html)
                self.assertIn("nosniff", html)
            finally:
                __import__("os").chdir(original)

        try:
            pdf = evidence.generate_pdf_bytes(record)
        except evidence.PDFDependencyError:
            self.skipTest("ReportLab is not installed in this environment")
        self.assertTrue(pdf.startswith(b"%PDF-"))
        self.assertGreater(len(pdf), 1000)


if __name__ == "__main__":
    unittest.main()
