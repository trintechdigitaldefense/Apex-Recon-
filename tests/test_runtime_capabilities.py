import contextlib
import io
import unittest
from unittest.mock import patch

import apex_recon_v2 as apex


class RuntimeCapabilityTests(unittest.TestCase):
    def _status(self, available=(), signing=False):
        available = set(available)
        with patch.object(apex.shutil, "which",
                          side_effect=lambda name: f"/usr/bin/{name}" if name in available else None), \
             patch.object(apex.importlib.util, "find_spec",
                          return_value=object() if signing else None):
            return apex.dependency_status()

    def test_http_and_tls_remain_available_without_external_tools(self):
        status = self._status()
        self.assertTrue(status["capabilities"]["http"])
        self.assertTrue(status["capabilities"]["tls"])
        self.assertFalse(status["capabilities"]["smb"])
        self.assertFalse(status["capabilities"]["osint_dns"])

    def test_nmap_enables_smb_and_osint_port_checks(self):
        status = self._status(("nmap",))
        self.assertTrue(status["capabilities"]["smb"])
        self.assertTrue(status["capabilities"]["osint_ports"])

    def test_missing_nmap_blocks_smb_before_target_prompt(self):
        with patch.object(apex, "dependency_status", return_value=self._status()), \
             patch.object(apex, "print_banner") as banner, \
             patch("builtins.input", side_effect=AssertionError("must not prompt")):
            result = apex.smb_auditor_module()
        self.assertIsNone(result)
        banner.assert_not_called()

    def test_unified_smb_missing_result_is_explicitly_unavailable(self):
        result = apex._engagement_module_result(
            "SMB Network Auditor", "UNAVAILABLE", {}, [], 0,
            ["Nmap is missing; SMB checks were not executed."],
        )
        self.assertEqual(result["status"], "UNAVAILABLE")
        self.assertEqual(result["findings"], [])
        self.assertIn("Nmap is missing", result["limitations"][0])

    def test_menu_marks_partial_osint_and_unavailable_smb(self):
        status = self._status(("dig", "whois"))
        output = io.StringIO()
        with patch.object(apex, "print_banner"), \
             patch("builtins.input", return_value="9"), \
             contextlib.redirect_stdout(output):
            apex.main_menu(status)
        rendered = output.getvalue()
        self.assertIn("External Footprinting (OSINT) [PARTIAL]", rendered)
        self.assertIn("Local Network SMB Auditor [UNAVAILABLE]", rendered)
        self.assertIn("HTTP Security Assessment [AVAILABLE]", rendered)

    def test_signing_status_tracks_cryptography_dependency(self):
        self.assertFalse(self._status()["capabilities"]["signing"])
        self.assertTrue(self._status(signing=True)["capabilities"]["signing"])

    def test_check_deps_returns_false_when_external_tools_are_missing(self):
        status = self._status()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(apex.check_deps(status))

    def test_check_deps_returns_true_when_all_external_tools_are_present(self):
        status = self._status(("nmap", "whois", "dig", "curl", "ip"))
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(apex.check_deps(status))


if __name__ == "__main__":
    unittest.main()
