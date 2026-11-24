import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("apex_recon_cli_tls", ROOT / "apex_recon_v2.py")
cli = importlib.util.module_from_spec(SPEC)
import sys
sys.modules[SPEC.name] = cli
SPEC.loader.exec_module(cli)


class TLSCLIIntegrationTests(unittest.TestCase):
    def test_declined_authorization_makes_no_tls_connection(self):
        with patch("builtins.input", return_value="example.com"), \
             patch.object(cli, "confirm_authorized_scope", return_value=False), \
             patch("apex_tls.assess_tls") as assess:
            cli.tls_assessment_module()
        assess.assert_not_called()

    def test_authorized_scope_is_port_443_and_report_is_written(self):
        fake = {
            "module": "TLS Security Assessment", "target": "example.com", "port": 443,
            "status": "VERIFIED", "verified": True, "protocol": "TLSv1.3",
            "cipher": {"name": "TEST"}, "certificate": {},
            "findings": [{"check": "TLS", "severity": "INFO", "status": "OK",
                          "evidence": "verified", "recommendation": "maintain"}],
            "limitations": ["one handshake"],
        }
        with tempfile.TemporaryDirectory() as tmp, \
             patch("builtins.input", side_effect=["https://example.com/path", ""]), \
             patch.object(cli, "confirm_authorized_scope", return_value=True) as auth, \
             patch("apex_tls.assess_tls", return_value=fake) as assess:
            import os
            old = os.getcwd()
            try:
                os.chdir(tmp)
                cli.tls_assessment_module()
                auth.assert_called_once_with("example.com:443")
                assess.assert_called_once_with("example.com")
                self.assertEqual(len(list(Path(tmp).glob("apex_tls_report_*.html"))), 1)
            finally:
                os.chdir(old)


if __name__ == "__main__":
    unittest.main()
