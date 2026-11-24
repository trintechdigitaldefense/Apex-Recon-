import contextlib
import io
import unittest
from unittest.mock import patch

import apex_recon_v2 as apex


class MissingOSINTDependencyTests(unittest.TestCase):
    def test_missing_tools_are_not_reported_as_empty_dns_or_clean_osint(self):
        output = io.StringIO()
        with patch.object(apex, "print_banner"), \
             patch.object(apex, "validate_osint_target", return_value=True), \
             patch.object(apex, "confirm_authorized_scope", return_value=True), \
             patch.object(apex.shutil, "which", return_value=None), \
             patch.object(apex, "run_cmd", side_effect=AssertionError("missing tool must not run")), \
             patch.object(apex, "resolve_target_ip", side_effect=AssertionError("GeoIP must be skipped")), \
             patch.object(apex, "osint_result_observations", return_value=[]), \
             patch.object(apex, "log"), \
             patch.object(apex.time, "time", side_effect=[10.0, 11.0]), \
             patch("builtins.input", return_value=""), \
             contextlib.redirect_stdout(output):
            result = apex.osint_module(engagement_mode=True)

        rendered = output.getvalue()
        self.assertIn("NOT ASSESSED: dig is not installed", rendered)
        self.assertIn("NOT ASSESSED: whois is not installed", rendered)
        self.assertIn("NOT ASSESSED: curl is not installed", rendered)
        self.assertIn("NOT ASSESSED: nmap is not installed", rendered)
        self.assertNotIn("No record", rendered)
        self.assertEqual(result["status"], "PARTIAL")
        self.assertTrue(any("dig (DNS records)" in item for item in result["limitations"]))
        self.assertEqual(result["findings"], [])


if __name__ == "__main__":
    unittest.main()
