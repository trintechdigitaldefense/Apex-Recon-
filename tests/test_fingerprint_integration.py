import importlib.util
import os
import stat
import tempfile
import unittest
from email.message import Message
from pathlib import Path
from unittest.mock import patch

MODULE_PATH = Path(__file__).resolve().parents[1] / "apex_web.py"
SPEC = importlib.util.spec_from_file_location("apex_web_fingerprint_integration", MODULE_PATH)
web = importlib.util.module_from_spec(SPEC)
import sys
sys.modules[SPEC.name] = web
SPEC.loader.exec_module(web)


class FakeResponse:
    def __init__(self, body):
        self.headers = Message()
        self.headers["Content-Type"] = "text/html; charset=utf-8"
        self.body = body
        self.read_limit = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def getcode(self):
        return 200

    def geturl(self):
        return "https://example.test/"

    def read(self, limit):
        self.read_limit = limit
        return self.body[:limit]


class FakeOpener:
    def __init__(self, response):
        self.response = response

    def open(self, request, timeout):
        return self.response


class FingerprintIntegrationTests(unittest.TestCase):
    def test_fetch_reads_only_capped_html_sample(self):
        response = FakeResponse(b"x" * (web.MAX_RESPONSE_BYTES + 500))
        with patch.object(web.urllib.request, "build_opener", return_value=FakeOpener(response)):
            result = web._fetch("https://example.test/")
        self.assertEqual(response.read_limit, web.MAX_RESPONSE_BYTES)
        self.assertEqual(len(result.body), web.MAX_RESPONSE_BYTES)

    def test_report_escapes_fingerprint_fields(self):
        result = {
            "module": "HTTP Security Assessment",
            "target": "example.test",
            "path": "/",
            "findings": [],
            "fingerprints": [{
                "category": "CMS",
                "name": "<script>alert(1)</script>",
                "confidence": "high",
                "version": None,
                "evidence": ["<img src=x onerror=alert(1)>"],
                "source": "bounded HTML sample",
            }],
            "limitations": ["Bounded sample only."],
        }
        with tempfile.TemporaryDirectory() as tmp:
            original = os.getcwd()
            try:
                os.chdir(tmp)
                path = web.generate_html_report(result, 0.1)
                html = Path(path).read_text(encoding="utf-8")
                self.assertIn("&lt;script&gt;", html)
                self.assertIn("&lt;img", html)
                self.assertNotIn("<script>alert(1)</script>", html)
                if os.name == "posix":
                    self.assertEqual(stat.S_IMODE(Path(path).stat().st_mode), 0o600)
            finally:
                os.chdir(original)


if __name__ == "__main__":
    unittest.main()
