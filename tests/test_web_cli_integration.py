import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    import sys
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


cli = load_module("apex_recon_cli_integration", ROOT / "apex_recon_v2.py")


class HTTPCLIIntegrationTests(unittest.TestCase):
    def test_invalid_target_stops_before_authorization_or_network(self):
        with patch("builtins.input", return_value="https://user:pass@example.com"), \
             patch.object(cli, "confirm_authorized_scope") as authorization, \
             patch("apex_web.assess_url") as assess:
            cli.http_assessment_module()
        authorization.assert_not_called()
        assess.assert_not_called()

    def test_declined_authorization_makes_no_http_request(self):
        with patch("builtins.input", return_value="example.com"), \
             patch.object(cli, "confirm_authorized_scope", return_value=False), \
             patch("apex_web.assess_url") as assess:
            cli.http_assessment_module()
        assess.assert_not_called()

    def test_authorized_assessment_calls_engine_and_writes_report(self):
        fake_result = {
            "module": "HTTP Security Assessment",
            "target": "example.com",
            "path": "/",
            "findings": [{
                "check": "CSP", "severity": "MEDIUM", "status": "MISSING",
                "evidence": "No CSP header observed.",
                "recommendation": "Configure a suitable CSP.",
            }],
            "limitations": ["One path only."],
        }
        with tempfile.TemporaryDirectory() as tmp, \
             patch("builtins.input", side_effect=["example.com", ""]), \
             patch.object(cli, "confirm_authorized_scope", return_value=True), \
             patch("apex_web.assess_url", return_value=fake_result) as assess:
            original = os.getcwd()
            try:
                os.chdir(tmp)
                cli.http_assessment_module()
                reports = list(Path(tmp).glob("apex_http_report_*.html"))
                self.assertEqual(len(reports), 1)
                self.assertIn("HTTP Security Assessment Report", reports[0].read_text(encoding="utf-8"))
                assess.assert_called_once_with("https://example.com/")
            finally:
                os.chdir(original)


if __name__ == "__main__":
    unittest.main()
