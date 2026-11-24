import importlib.util
import os
import stat
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "apex_web.py"
SPEC = importlib.util.spec_from_file_location("apex_web_report_tests", MODULE_PATH)
web = importlib.util.module_from_spec(SPEC)
import sys
sys.modules[SPEC.name] = web
SPEC.loader.exec_module(web)


class HTTPReportTests(unittest.TestCase):
    def test_report_escapes_untrusted_values_and_records_limitations(self):
        result = {
            "module": "HTTP Security Assessment",
            "target": "<script>alert(1)</script>",
            "assessment_id": "test-assessment-123",
            "path": "/<img src=x>",
            "findings": [{
                "check": "HEADER",
                "severity": "MEDIUM",
                "status": "MISSING",
                "evidence": "<svg onload=alert(1)>",
                "recommendation": "Use a safe policy.",
            }],
            "limitations": ["No exploitation performed."],
        }
        with tempfile.TemporaryDirectory() as tmp:
            original = os.getcwd()
            try:
                os.chdir(tmp)
                path = web.generate_html_report(result, 1.25)
                content = Path(path).read_text(encoding="utf-8")
                self.assertIn("&lt;script&gt;", content)
                self.assertIn("&lt;img", content)
                self.assertIn("&lt;svg", content)
                self.assertIn("No exploitation performed.", content)
                self.assertIn("test-assessment-123", content)
                self.assertNotIn("<script>alert(1)</script>", content)
                mode = stat.S_IMODE(Path(path).stat().st_mode)
                if os.name == "posix":
                    self.assertEqual(mode, 0o600)
            finally:
                os.chdir(original)

    def test_rejects_non_assessment_payload(self):
        with self.assertRaises(ValueError):
            web.generate_html_report({}, 0)


if __name__ == "__main__":
    unittest.main()
